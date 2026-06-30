// qt_hider.cpp - selectively hides Qt5 windows + auto-fills the login form
//
// Login strategy: QApplication::allWidgets() returns every QWidget in the
// process across all threads. We scan it for QLineEdit children, identify
// username/password by order (first = username, second = password), then
// call QLineEdit::setText() via QMetaObject::invokeMethod with
// Qt::QueuedConnection so the call is marshalled onto Qt's main thread.
//
// Chrome strategy:
//   - The OS-level Win32 titlebar (WS_CAPTION etc.) is LEFT INTACT.
//   - The INTERNAL Roblox Studio topbar (QtitanRibbon + all docked panels)
//     is hidden via HideStudioChromeWidgets() in qt_widget_hider.cpp.
//   - Context menu / popup shadow artifacts: after hiding a visible Qt
//     popup HWND we call RedrawWindow on the desktop HWND to force DWM
//     to flush the composited shadow tile immediately.
//
// FIX NOTES:
//   1. The 'running' re-entrancy guard is now properly reset on ALL exit
//      paths, including the "not ready yet" early-return path. Previously
//      a "not ready" return from HideStudioChromeWidgets left running=true
//      permanently, silently blocking all future hide passes.
//   2. HideStudioChromeWidgets now returns a tri-state via outReady.
//      When outReady==false the pass was a "not ready" failure and we
//      schedule another retry. When outReady==true we stop retrying.
//   3. The retry cadence uses a separate "successfulHide" flag: once the
//      pass succeeds we stop posting new hide messages entirely, since
//      undocked widgets stay undocked across layout passes.
//   4. kSuccessPassesNeeded raised to 8: qt_widget_hider now only counts a
//      pass as successful when every chrome widget has ChromeBlockerWndProc
//      actually installed (noHwnd==0). Extra passes cover late-init HWNDs.

#include "qt_hider.h"
#include "qt_widget_hider.h"
#include <cwctype>
#include <cwchar>

#define LOGIN_USERNAME  L"LocalUser"
#define LOGIN_PASSWORD  L"LocalPass"

namespace RobloxStudioPatcher
{
    static constexpr int kPollsBeforeAction = 30;
    static constexpr int kPollsBetweenHides = 3;   // retry every 300ms
    static constexpr int kLoginAttemptDelay = 15;
    static constexpr int kLoginWindowDelay = 10;
    // Raised from 5 to 8: qt_widget_hider only declares success when every
    // chrome widget has a real HWND blocker (noHwnd==0). Extra passes ensure
    // any widgets whose HWNDs are created after the first successful pass
    // also get ChromeBlockerWndProc installed before we stop retrying.
    static constexpr int kSuccessPassesNeeded = 8;
    // After the app (re)gains the foreground we wait this many ~100ms polls
    // before touching Qt again, so the widget tree is never traversed while it
    // is still settling from a minimize / focus-change transition (that
    // transition window is exactly when the Qt deref used to crash).
    static constexpr int kFgSettlePolls = 3;
    // Steady re-hide cadence while focused (catches keybind-opened panels).
    static constexpr int kPollsBetweenRehide = 6;   // ~600ms

    static bool s_loginAutoFilled = false;
    static bool s_hideHardFailed = false;
    static int  s_successfulHides = 0;
    static int  s_chromeHidesRun = 0;
    static int  s_lastHidePollSnapshot = 0;
    static int  s_mainStableCount = 0;
    static int  s_loginStableCount = 0;
    static int  s_fgStable = 0;         // consecutive polls app is foreground+ready
    static HWND s_lastMain = nullptr;   // last-found main window (for the iconic test)

    struct HiderState
    {
        DWORD selfPid;
        HWND  mainWindow;
        int   mainArea;    // area of the chosen mainWindow (largest-wins)
        HWND  loginWindow;
        bool  active;   // true = safe to hide this pass (foreground + not minimized)
    };

    // Our app owns the foreground window? (Used to gate all hiding so we only
    // act when the app is actually in front and responsive.)
    static bool ProcessIsForeground()
    {
        HWND fg = GetForegroundWindow();
        if (!fg) return false;
        DWORD pid = 0;
        GetWindowThreadProcessId(fg, &pid);
        return pid == GetCurrentProcessId();
    }

#ifdef _WIN64
#define QT_MEMBER_CC __cdecl
#else
#define QT_MEMBER_CC __thiscall
#endif

    static constexpr int kQueuedConnection = 2;

    struct QGenericArgument
    {
        const char* _name = nullptr;
        const void* _data = nullptr;
    };
    using QGenericReturnArgument = QGenericArgument;

    using FnAllWidgets = void(__cdecl*)(void* sretList);
    using FnSetText = void (QT_MEMBER_CC*)(void* lineEdit, const void* qstring);
    using FnQStringCtorW = void (QT_MEMBER_CC*)(void* self, const wchar_t* chars, int size);
    using FnQStringDtor = void (QT_MEMBER_CC*)(void* self);
    using FnChildren = const void* (QT_MEMBER_CC*)(const void* qobj);
    using FnClassName = const char* (QT_MEMBER_CC*)(const void* meta);
    using FnWidgetFind = void* (__cdecl*)(uintptr_t wid);
    using FnInvokeMethod = bool(__cdecl*)(
        void* obj,
        const char* member,
        int                    type,
        QGenericReturnArgument ret,
        QGenericArgument       val0,
        QGenericArgument       val1,
        QGenericArgument       val2,
        QGenericArgument       val3,
        QGenericArgument       val4,
        QGenericArgument       val5,
        QGenericArgument       val6,
        QGenericArgument       val7,
        QGenericArgument       val8,
        QGenericArgument       val9);

    struct LoginSymbols
    {
        bool             resolved = false;
        FnAllWidgets     allWidgets = nullptr;
        FnSetText        setText = nullptr;
        FnQStringCtorW   qstrCtor = nullptr;
        FnQStringDtor    qstrDtor = nullptr;
        FnChildren       children = nullptr;
        FnClassName      className = nullptr;
        FnWidgetFind     widgetFind = nullptr;
        FnInvokeMethod   invokeMethod = nullptr;
        const void* metaQLineEdit = nullptr;
        const void* metaQWidget = nullptr;
    };
    static LoginSymbols g_login;

    static FARPROC TryGet(HMODULE m, const char* a, const char* b = nullptr)
    {
        FARPROC f = GetProcAddress(m, a);
        if (!f && b) f = GetProcAddress(m, b);
        return f;
    }

    static bool ResolveLoginSymbols()
    {
        if (g_login.resolved) return true;

        HMODULE core = GetModuleHandleW(L"Qt5Core.dll");
        HMODULE widgets = GetModuleHandleW(L"Qt5Widgets.dll");
        if (!core || !widgets)
        {
            //LOG(L"[qt_hider] Qt5Core/Qt5Widgets not loaded yet\n");
            return false;
        }

        g_login.allWidgets = (FnAllWidgets)TryGet(widgets,
            "?allWidgets@QApplication@@SA?AV?$QList@PEAVQWidget@@@@XZ",
            "?allWidgets@QApplication@@SA?AV?$QList@PAVQWidget@@@@XZ");

        g_login.setText = (FnSetText)TryGet(widgets,
            "?setText@QLineEdit@@QEAAXAEBVQString@@@Z",
            "?setText@QLineEdit@@QAEXABVQString@@@Z");

        g_login.qstrCtor = (FnQStringCtorW)TryGet(core,
            "??0QString@@QEAA@PEBVQChar@@H@Z",
            "??0QString@@QAE@PBVQChar@@H@Z");

        g_login.qstrDtor = (FnQStringDtor)TryGet(core,
            "??1QString@@QEAA@XZ",
            "??1QString@@QAE@XZ");

        g_login.children = (FnChildren)TryGet(core,
            "?children@QObject@@QEBAAEBV?$QList@PEAVQObject@@@@XZ",
            "?children@QObject@@QBEABV?$QList@PAVQObject@@@@XZ");

        g_login.className = (FnClassName)TryGet(core,
            "?className@QMetaObject@@QEBAPEBDXZ",
            "?className@QMetaObject@@QBEPBDXZ");

        g_login.widgetFind = (FnWidgetFind)TryGet(widgets,
            "?find@QWidget@@SAPEAV1@_K@Z",
            "?find@QWidget@@SAPAV1@I@Z");

        g_login.invokeMethod = (FnInvokeMethod)TryGet(core,
            "?invokeMethod@QMetaObject@@SA_NPEAVQObject@@PEBDVQt@@ConnectionType@@"
            "VQGenericReturnArgument@@VQGenericArgument@@1111111111@Z",
            "?invokeMethod@QMetaObject@@SA_NPAVQObject@@PBDVQt@@ConnectionType@@"
            "VQGenericReturnArgument@@VQGenericArgument@@1111111111@Z");

        g_login.metaQLineEdit = (const void*)GetProcAddress(widgets,
            "?staticMetaObject@QLineEdit@@2UQMetaObject@@B");
        g_login.metaQWidget = (const void*)GetProcAddress(widgets,
            "?staticMetaObject@QWidget@@2UQMetaObject@@B");

        bool ok = g_login.allWidgets
            && g_login.qstrCtor
            && g_login.qstrDtor
            && g_login.children
            && g_login.className
            && g_login.invokeMethod
            && g_login.metaQLineEdit;

       // LOG(L"[qt_hider] login symbols: allWidgets=%p setText=%p "
         //   L"qstrCtor=%p qstrDtor=%p invokeMethod=%p metaQLineEdit=%p -> %s\n",
         //   g_login.allWidgets, g_login.setText,
         //   g_login.qstrCtor, g_login.qstrDtor,
         //   g_login.invokeMethod, g_login.metaQLineEdit,
         //   ok ? L"OK" : L"FAIL");

        g_login.resolved = ok;
        return ok;
    }

    static const void* GetMetaObject(const void* qobj)
    {
        if (!qobj) return nullptr;
        using FnMeta = const void* (__cdecl*)(const void*);
        const void* const* vt = *reinterpret_cast<const void* const* const*>(qobj);
        return reinterpret_cast<FnMeta>(vt[0])(qobj);
    }

    template<typename Visitor>
    static void ForEachWidget(void* listStorage, Visitor v)
    {
        const void* d = *reinterpret_cast<const void**>(listStorage);
        if (!d) return;
        const int* hdr = reinterpret_cast<const int*>(d);
        int begin = hdr[2], end = hdr[3];
        if (begin < 0 || end < begin || end > 200000) return;
        auto items = reinterpret_cast<const void* const*>(
            reinterpret_cast<const char*>(d) + 16);
        for (int i = begin; i < end; ++i)
            if (items[i]) v(items[i]);
    }

    static void SetLineEditTextQueued(void* lineEdit, const wchar_t* text)
    {
        if (!g_login.invokeMethod || !g_login.qstrCtor || !g_login.qstrDtor)
        {
           // LOG(L"[qt_hider] SetLineEditTextQueued: missing symbols\n");
            return;
        }

        void* qstr = ::operator new(sizeof(void*) * 4);
        memset(qstr, 0, sizeof(void*) * 4);

        __try
        {
            g_login.qstrCtor(qstr, text, static_cast<int>(wcslen(text)));

            QGenericArgument       arg = { "QString", qstr };
            QGenericReturnArgument noRet = {};
            QGenericArgument       noArg = {};

            bool ok = g_login.invokeMethod(
                lineEdit, "setText",
                kQueuedConnection,
                noRet,
                arg,
                noArg, noArg, noArg, noArg,
                noArg, noArg, noArg, noArg, noArg);

           // LOG(L"[qt_hider] invokeMethod setText -> %d\n", (int)ok);

            Sleep(100);
            g_login.qstrDtor(qstr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
          //  LOG(L"[qt_hider] SEH in SetLineEditTextQueued\n");
        }

        ::operator delete(qstr);
    }

    static constexpr int kMaxLoginLineEdits = 2;

    struct LoginFields
    {
        void* username = nullptr;
        void* password = nullptr;
        bool  valid = false;
    };

    static LoginFields FindLoginLineEdits()
    {
        alignas(8) char listBuf[16] = {};
        g_login.allWidgets(listBuf);

        void* lineEdits[kMaxLoginLineEdits + 1] = {};
        int   found = 0;

        ForEachWidget(listBuf, [&](const void* widget)
            {
                if (found > kMaxLoginLineEdits) return;
                const void* meta = GetMetaObject(widget);
                if (!meta) return;
                const char* cls = g_login.className(meta);
                if (!cls || strcmp(cls, "QLineEdit") != 0) return;
                if (found <= kMaxLoginLineEdits)
                    lineEdits[found] = const_cast<void*>(widget);
                ++found;
            });

       // LOG(L"[qt_hider] FindLoginLineEdits: found %d QLineEdit(s)\n", found);

        if (found != 2)
            return { nullptr, nullptr, false };

        return { lineEdits[0], lineEdits[1], true };
    }

    static void AutoFillLogin(HWND loginOwnDc)
    {
        //LOG(L"[qt_hider] AutoFillLogin entry, loginOwnDc=%p\n", loginOwnDc);

        if (!ResolveLoginSymbols())
        {
         //   LOG(L"[qt_hider] symbols not ready, will retry\n");
            s_loginAutoFilled = false;
            return;
        }

        LoginFields fields = FindLoginLineEdits();
        if (!fields.valid)
        {
        //    LOG(L"[qt_hider] login fields not found yet, will retry\n");
            s_loginAutoFilled = false;
            return;
        }

       // LOG(L"[qt_hider] setting username on %p\n", fields.username);
        SetLineEditTextQueued(fields.username, LOGIN_USERNAME);

       // LOG(L"[qt_hider] setting password on %p\n", fields.password);
        SetLineEditTextQueued(fields.password, LOGIN_PASSWORD);

       // LOG(L"[qt_hider] sending VK_RETURN to login OwnDC %p\n", loginOwnDc);
        SendMessageW(loginOwnDc, WM_KEYDOWN, VK_RETURN, 0x001C0001);
        Sleep(30);
        SendMessageW(loginOwnDc, WM_KEYUP, VK_RETURN, 0xC01C0001);

       // LOG(L"[qt_hider] AutoFillLogin complete\n");
    }

    // ----- Window classification -------------------------------------------

    static bool ClassNameStartsWithQt5(HWND hwnd, wchar_t* outCls, int cap)
    {
        int n = GetClassNameW(hwnd, outCls, cap);
        if (n <= 0) return false;
        return outCls[0] == L'Q' && outCls[1] == L't' && outCls[2] == L'5';
    }

    static bool ClassEndsWith(const wchar_t* cls, const wchar_t* suffix)
    {
        size_t cl = wcslen(cls);
        size_t sl = wcslen(suffix);
        if (cl < sl) return false;
        return wcscmp(cls + (cl - sl), suffix) == 0;
    }

    static bool IsQt5IconClass(const wchar_t* cls)
    {
        if (!(cls[0] == L'Q' && cls[1] == L't' && cls[2] == L'5')) return false;
        if (wcsstr(cls, L"OwnDC") != nullptr) return false;
        return ClassEndsWith(cls, L"QWindowIcon");
    }

    static bool TitleContainsAnyOf(HWND hwnd,
        const wchar_t* a,
        const wchar_t* b = nullptr,
        const wchar_t* c = nullptr)
    {
        wchar_t title[256] = {};
        if (GetWindowTextW(hwnd, title, _countof(title)) <= 0) return false;
        if (a && wcsstr(title, a)) return true;
        if (b && wcsstr(title, b)) return true;
        if (c && wcsstr(title, c)) return true;
        return false;
    }

    static void GetWindowSize(HWND hwnd, int* w, int* h)
    {
        RECT r{};
        if (GetWindowRect(hwnd, &r))
        {
            *w = r.right - r.left; *h = r.bottom - r.top;
        }
        else { *w = *h = 0; }
    }

    static bool IsMainWindowToKeepVisible(HWND hwnd, const wchar_t* cls)
    {
        if (wcsstr(cls, L"OwnDC") != nullptr) return true;
        if (!IsQt5IconClass(cls)) return false;
        if (TitleContainsAnyOf(hwnd, L"Roblox", L"Studio", L"Player") || TitleContainsAnyOf(hwnd, L"OffBlox", L"Studio", L"Player"))
            return true;
        int w = 0, h = 0;
        GetWindowSize(hwnd, &w, &h);
        return w >= 800 && h >= 600;
    }

    static void ClearPopupShadow(HWND hwnd)
    {
        RECT old{};
        GetWindowRect(hwnd, &old);

        SetWindowPos(hwnd, nullptr, -32000, -32000, 0, 0,
            SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);

        old.left -= 8;
        old.top -= 8;
        old.right += 8;
        old.bottom += 8;

        HWND desktop = GetDesktopWindow();
        RedrawWindow(desktop, &old, nullptr,
            RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    }

    static BOOL CALLBACK EnumProc(HWND hwnd, LPARAM lParam)
    {
        auto* state = reinterpret_cast<HiderState*>(lParam);

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid != state->selfPid) return TRUE;

        wchar_t cls[64] = {};
        if (!ClassNameStartsWithQt5(hwnd, cls, _countof(cls)))
            return TRUE;

        if (wcsstr(cls, L"OwnDC") && state->loginWindow == nullptr)
        {
            wchar_t title[64] = {};
            GetWindowTextW(hwnd, title, _countof(title));
            if (title[0] == L'\0' && IsWindowVisible(hwnd))
            {
                state->loginWindow = hwnd;
                LOG(L"[qt_hider] detected login OwnDC %p\n", hwnd);
            }
        }

        if (IsMainWindowToKeepVisible(hwnd, cls))
        {
            // LARGEST-wins, not first-wins. Studio has more than one top-level
            // Qt window with a QEngineWidget (the real editor window plus a
            // smaller secondary render window). First-wins would flip onto the
            // small one after the first pass and then never block chrome that
            // appears on the REAL window later (e.g. the bottom playtest/status
            // bar - the "dead strip"). Picking the biggest window keeps us
            // locked on the real Studio window every pass.
            if (IsQt5IconClass(cls))
            {
                int w = 0, h = 0;
                GetWindowSize(hwnd, &w, &h);
                int area = w * h;
                if (area > state->mainArea)
                {
                    state->mainArea = area;
                    state->mainWindow = hwnd;
                }
            }
            return TRUE;
        }

        // Only ever hide while the app is foreground + not minimized. When it
        // isn't, we just detect the main/login windows and touch nothing -
        // this is what keeps a minimize / unfocus / refocus from hiding the
        // whole window or crashing on a half-recreated Qt window.
        if (!state->active) return TRUE;

        if (!IsWindowVisible(hwnd)) return TRUE;

        LONG_PTR ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        if (!(ex & WS_EX_LAYERED))
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, ex | WS_EX_LAYERED);
        SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);

        ClearPopupShadow(hwnd);
        ShowWindow(hwnd, SW_HIDE);
      //  LOG(L"[qt_hider] hid %p class=%s\n", hwnd, cls);
        return TRUE;
    }

    // ----- GUI-thread marshaling for the chrome hide -----------------------
    //
    // HideStudioChromeWidgets() mutates the Qt widget tree (setParent /
    // hide / resize). Qt widgets MUST only be touched on the GUI thread.
    // We subclass the main window's WndProc (which always runs on the GUI
    // thread) and PostMessage a private message from the background thread.
    // PostMessage itself is thread-safe.

    static UINT    s_hideChromeMsg = 0;
    static WNDPROC s_origMainWndProc = nullptr;
    static HWND    s_subclassedHwnd = nullptr;
    static volatile LONG s_hidePassQueued = 0;

    static LRESULT CALLBACK HiderWndProc(HWND hwnd, UINT msg,
        WPARAM wParam, LPARAM lParam)
    {
        // Pin the client window caption to "Roblox" regardless of what Studio
        // tries to set it to. This WndProc is only installed on a StartClient
        // launch, so the editor/server window keeps its real title.
        if (msg == WM_SETTEXT)
        {
            if (s_origMainWndProc)
                return CallWindowProcW(s_origMainWndProc, hwnd, WM_SETTEXT,
                    wParam, reinterpret_cast<LPARAM>(L"OffBlox"));
            return DefWindowProcW(hwnd, WM_SETTEXT, wParam,
                reinterpret_cast<LPARAM>(L"OffBlox"));
        }

        if (msg == s_hideChromeMsg && s_hideChromeMsg != 0)
        {
            // Running on the GUI thread - Qt widget calls are safe here.
            InterlockedExchange(&s_hidePassQueued, 0);

            // Focus can change between the background thread posting this and
            // us processing it. Re-check here so the Qt traversal only ever
            // runs while we're actually foreground + not minimized.
            if (!ProcessIsForeground() || IsIconic(hwnd))
            {
            //    LOG(L"[qt_hider] hide pass skipped (not foreground/minimized)\n");
                goto call_orig;
            }

            // Re-entrancy guard: setFloating() pumps events which can
            // re-dispatch into this WndProc. Only reset to 0 on exit.
            static volatile LONG running = 0;
            if (InterlockedCompareExchange(&running, 1, 0) != 0)
            {
              //  LOG(L"[qt_hider] HiderWndProc re-entrant call; skipping\n");
                goto call_orig;
            }

            {
                bool ready = false;
                bool success = HideStudioChromeWidgets(hwnd, &ready);

                if (success)
                {
                    s_successfulHides++;
                 //   LOG(L"[qt_hider] chrome hide pass succeeded (%d/%d)\n",
                      //  s_successfulHides, kSuccessPassesNeeded);
                }
                else if (ready)
                {
                    // Don't permanently disable hiding on a single transient
                    // fault - the foreground gate makes faults rare, and we want
                    // a later (settled, foreground) pass to recover.
                  //  LOG(L"[qt_hider] chrome hide pass faulted - will retry later\n");
                }
                else
                {
                   //LOG(L"[qt_hider] chrome hide: not ready, will retry\n");
                }
            }

            InterlockedExchange(&running, 0);
            return 0;
        }

    call_orig:
        if (s_origMainWndProc)
            return CallWindowProcW(s_origMainWndProc, hwnd, msg, wParam, lParam);
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    static void EnsureMainWindowSubclassed(HWND mainHwnd)
    {
        if (s_subclassedHwnd == mainHwnd) return;
        if (s_hideChromeMsg == 0)
            s_hideChromeMsg =
            RegisterWindowMessageW(L"RobloxStudioPatcher_HideChrome_v1");

        LONG_PTR prev = SetWindowLongPtrW(
            mainHwnd, GWLP_WNDPROC,
            reinterpret_cast<LONG_PTR>(&HiderWndProc));
        if (prev != 0)
        {
            s_origMainWndProc = reinterpret_cast<WNDPROC>(prev);
            s_subclassedHwnd = mainHwnd;
            //LOG(L"[qt_hider] subclassed main window %p (orig WndProc=%p msg=%u)\n",
              //  mainHwnd, s_origMainWndProc, s_hideChromeMsg);
            // Set "Roblox" now; the WM_SETTEXT hook keeps it pinned afterward.
            SetWindowTextW(mainHwnd, L"OffBlox");
        }
        else
        {
            //LOG(L"[qt_hider] SetWindowLongPtr(GWLP_WNDPROC) failed on %p\n",
             //   mainHwnd);
        }
    }

    static void HideChrome(HWND mainHwnd)
    {
        // No permanent stop: passes are gated to the foreground-stable state by
        // the caller, and we keep re-hiding so panels opened later (e.g. the
        // Toolbox via a keybind) get caught and permanently blocked too.
      //  LOG(L"[qt_hider] queueing Qt widget hide pass on %p\n", mainHwnd);

        EnsureMainWindowSubclassed(mainHwnd);
        if (s_subclassedHwnd != mainHwnd)
        {
          //  LOG(L"[qt_hider] main window not subclassed; skipping hide pass\n");
            return;
        }

        if (InterlockedCompareExchange(&s_hidePassQueued, 1, 0) == 0)
            PostMessageW(mainHwnd, s_hideChromeMsg, 0, 0);
    }

    static DWORD WINAPI HiderThreadProc(LPVOID)
    {
        //LOG(L"[qt_hider] HiderThreadProc started\n");
        for (;;)
        {
            HiderState state = {};
            state.selfPid = GetCurrentProcessId();
            // Decide up front whether it's safe to hide this pass: our app must
            // own the foreground and the (last-known) main window must not be
            // minimized. EnumProc only HIDES when this is true; it always
            // detects the main/login windows.
            const bool notMinimized =
                !(s_lastMain && IsWindow(s_lastMain) && IsIconic(s_lastMain));
            state.active = ProcessIsForeground() && notMinimized;
            EnumWindows(EnumProc, reinterpret_cast<LPARAM>(&state));
            if (state.mainWindow) s_lastMain = state.mainWindow;

            if (state.loginWindow != nullptr && !s_loginAutoFilled)
            {
                s_loginStableCount++;
               // LOG(L"[qt_hider] login stable=%d loginWindow=%p\n",
                 //   s_loginStableCount, state.loginWindow);

                if (s_loginStableCount >= kLoginWindowDelay)
                {
                    s_loginAutoFilled = true;
                    AutoFillLogin(state.loginWindow);
                }
            }
            else if (state.loginWindow == nullptr)
            {
                s_loginStableCount = 0;
            }

            if (state.mainWindow != nullptr)
            {
                s_mainStableCount++;

                // Track how long we've been continuously foreground+ready. The
                // chrome pass (which traverses the Qt widget tree) only runs
                // once that count clears the settle threshold, so it never
                // touches Qt during a minimize/unfocus/refocus transition.
                if (state.active) s_fgStable++;
                else              s_fgStable = 0;

                const bool settled = state.active && s_fgStable >= kFgSettlePolls;
                const bool firstHideReady =
                    settled && s_chromeHidesRun == 0 &&
                    s_mainStableCount >= kPollsBeforeAction;
                const bool rehideReady =
                    settled && s_chromeHidesRun > 0 &&
                    (s_mainStableCount - s_lastHidePollSnapshot) >= kPollsBetweenRehide;

                if (firstHideReady || rehideReady)
                {
                    s_chromeHidesRun++;
                    s_lastHidePollSnapshot = s_mainStableCount;
                    HideChrome(state.mainWindow);
                }
            }
            else
            {
                s_mainStableCount = 0;
                s_fgStable = 0;
            }

            Sleep(100);
        }
    }

    void StartQtHider()
    {
        //LOG(L"[qt_hider] StartQtHider called\n");
        HANDLE h = CreateThread(nullptr, 0, HiderThreadProc, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    }
}