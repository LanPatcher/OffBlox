// qt_widget_hider.cpp - chrome hider for Roblox Studio.
//
// WHY THIS NEEDS Qt CLASS NAMES
// =============================
// Every child window of Studio's main window has the SAME Win32 class
// ("Qt5159QWindowIcon"), so window-class detection is useless. The only way
// to tell the 3D viewport apart from the ribbon / dock panels / toolbars is
// to ask Qt what each window's QWidget class is (QtitanRibbonBar,
// QtitanDockWidget, QToolBar, ... vs. the render widget).
//
// Reading the Qt object model (QWidget::find + QMetaObject::className) is a
// READ-ONLY operation and is SAFE here: qt_hider.cpp marshals this call onto
// the GUI thread via the main-window WndProc subclass. We never MUTATE the
// Qt widget tree (no setParent / hide), so there is no crash risk and no
// QtitanDocking invariant to break.
//
// HIDING MECHANISM (pure Win32, permanent)
// ----------------------------------------
//   * Each chrome window is subclassed with ChromeBlockerWndProc, which
//     intercepts WM_WINDOWPOSCHANGING and forces it hidden + zero-sized
//     forever.
//   * The viewport window (and the native containers between it and the
//     main window) is subclassed with ViewportExpanderWndProc, which forces
//     it to always fill its parent - so the 3D view covers the frame.
//
// This pass also LOGS every child window with its resolved QWidget class
// name, so the exact window tree is visible in Studio's Output panel.
//
// CURSOR-HIDE FIX (focus-from-load)
// ---------------------------------
// The viewport selector now ONLY ever accepts the editor's document viewport
// (an engine widget nested under a Qtitan DockDocument* container). The old
// "largest engine widget anywhere" / "largest non-chrome" fallbacks could
// select the full-window Start Page render (an engine widget parented
// directly to the main window, with QLabel children) during the brief load
// phase. Expanding/focusing that start-page widget makes the engine hide the
// OS cursor (SetCursor NULL), which is what randomly hid the pointer whenever
// the window was focused from the moment it loaded. We now exclude that
// widget outright and DEFER the pass (retry) until the docked document
// viewport exists, instead of ever expanding the start-page render.
#include "qt_widget_hider.h"
#include <cstdint>
#include <cstring>
#include <vector>
#ifdef _WIN64
#define QT_STATIC_CC __cdecl
#define QT_MEMBER_CC __cdecl
#else
#define QT_STATIC_CC __cdecl
#define QT_MEMBER_CC __thiscall
#endif
namespace RobloxStudioPatcher
{
    static const wchar_t* kOrigProcProp = L"RbxPatcher_OrigWndProc";
    // ----- Resolved Qt symbols (read-only use only) ------------------------
    struct QtSymbols
    {
        bool tried = false;
        bool ok = false;
        using FnFind = void* (QT_STATIC_CC*)(uintptr_t);
        using FnClassName = const char* (QT_MEMBER_CC*)(const void*);
        FnFind      widgetFind = nullptr;
        FnClassName metaClassName = nullptr;
    };
    static QtSymbols g_qt;
    static void* FindExportByPrefix(HMODULE mod, const char* prefix)
    {
        if (!mod) return nullptr;
        BYTE* base = reinterpret_cast<BYTE*>(mod);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        DWORD rva = nt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!rva) return nullptr;
        auto ed = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + rva);
        auto nrva = reinterpret_cast<DWORD*>(base + ed->AddressOfNames);
        auto ords = reinterpret_cast<WORD*>(base + ed->AddressOfNameOrdinals);
        auto frva = reinterpret_cast<DWORD*>(base + ed->AddressOfFunctions);
        size_t pl = std::strlen(prefix);
        for (DWORD i = 0; i < ed->NumberOfNames; ++i)
        {
            const char* nm = reinterpret_cast<const char*>(base + nrva[i]);
            if (std::strlen(nm) < pl) continue;
            if (std::memcmp(nm, prefix, pl) == 0)
                return base + frva[ords[i]];
        }
        return nullptr;
    }
    static bool ResolveQtSymbols()
    {
        if (g_qt.tried) return g_qt.ok;
        g_qt.tried = true;
        HMODULE core = GetModuleHandleW(L"Qt5Core.dll");
        HMODULE widgets = GetModuleHandleW(L"Qt5Widgets.dll");
        if (!core || !widgets)
        {
            // LogF(L"[hider] Qt5 DLLs not loaded yet (core=%p widgets=%p)\n",
             //     core, widgets);
            return false;
        }
        g_qt.widgetFind = (QtSymbols::FnFind)FindExportByPrefix(
            widgets, "?find@QWidget@@");
        g_qt.metaClassName = (QtSymbols::FnClassName)FindExportByPrefix(
            core, "?className@QMetaObject@@");
        g_qt.ok = g_qt.widgetFind && g_qt.metaClassName;
        LogF(L"[hider] Qt symbols: find=%p className=%p -> %s\n",
            g_qt.widgetFind, g_qt.metaClassName, g_qt.ok ? L"OK" : L"FAIL");
        return g_qt.ok;
    }
    // Resolve the QWidget class name behind a window handle. SEH-guarded
    // because it dereferences a Qt object through a vtable. Returns "" if
    // the HWND isn't a Qt widget or anything looks wrong.
    static const char* ClassNameOfHwndRaw(HWND hwnd)
    {
        void* widget = g_qt.widgetFind(reinterpret_cast<uintptr_t>(hwnd));
        if (!widget) return "";
        // QObject::metaObject() is the first vtable entry.
        const void* const* vtable =
            *reinterpret_cast<const void* const* const*>(widget);
        using FnMeta = const void* (__cdecl*)(const void*);
        const void* meta = reinterpret_cast<FnMeta>(vtable[0])(widget);
        if (!meta) return "";
        const char* cls = g_qt.metaClassName(meta);
        return cls ? cls : "";
    }
    static void ClassNameOfHwnd(HWND hwnd, char* out, int cap)
    {
        out[0] = '\0';
        __try
        {
            const char* c = ClassNameOfHwndRaw(hwnd);
            int i = 0;
            for (; c[i] && i < cap - 1; ++i) out[i] = c[i];
            out[i] = '\0';
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            out[0] = '\0';
        }
    }
    // Chrome = ribbon / dock panels / toolbars / menu / status / tabs.
    // Substring match against the QWidget class name. The 3D render widget
    // is never one of these.
    static bool IsChromeClassName(const char* cls)
    {
        if (!cls || !cls[0]) return false;
        static const char* const kChrome[] = {
            "Qtitan", "Ribbon",
            "QToolBar", "QToolButton",
            "QMenuBar", "QMenu",
            "QStatusBar", "QStatus",
            "QTabBar",
            "QScrollBar",
            "QHeaderView",
            "QSizeGrip",
            "QDockWidget",
        };
        for (const char* k : kChrome)
            if (std::strstr(cls, k)) return true;
        return false;
    }
    // ----- Blocker / expander WndProcs -------------------------------------
    static LRESULT CALLBACK ChromeBlockerWndProc(HWND h, UINT msg,
        WPARAM wp, LPARAM lp)
    {
        switch (msg)
        {
        case WM_WINDOWPOSCHANGING:
        {
            auto* p = reinterpret_cast<WINDOWPOS*>(lp);
            if (p)
            {
                p->flags &= ~SWP_SHOWWINDOW;
                p->flags |= SWP_HIDEWINDOW | SWP_NOREDRAW;
                p->x = -32000; p->y = -32000;
                p->cx = 0;     p->cy = 0;
            }
            break;
        }
        // Even if Qt re-shows this bar for a frame before our
        // WM_WINDOWPOSCHANGING fires (the cause of the "dead strip" at the
        // bottom of the window), make it invisible to the mouse: the cursor
        // and any click fall straight through to the viewport beneath.
        case WM_NCHITTEST:
            return HTTRANSPARENT;
        case WM_MOUSEACTIVATE:
            return MA_NOACTIVATE;
        }
        WNDPROC orig = reinterpret_cast<WNDPROC>(GetPropW(h, kOrigProcProp));
        if (orig) return CallWindowProcW(orig, h, msg, wp, lp);
        return DefWindowProcW(h, msg, wp, lp);
    }
    static LRESULT CALLBACK ViewportExpanderWndProc(HWND h, UINT msg,
        WPARAM wp, LPARAM lp)
    {
        // Let the ENGINE own the cursor. We pass WM_SETCURSOR straight through
        // to the original WndProc so the engine can hide the OS cursor
        // (SetCursor NULL) and draw its own in-engine cursor, and so its input
        // state stays consistent. The previous code forced IDC_ARROW here and
        // returned TRUE, which showed the external Windows cursor, suppressed the
        // internal one, and left the viewport unclickable. (Intentionally NOT
        // intercepting WM_SETCURSOR.)
        if (msg == WM_WINDOWPOSCHANGING)
        {
            auto* p = reinterpret_cast<WINDOWPOS*>(lp);
            HWND parent = GetParent(h);
            RECT pc{};
            if (p && parent && GetClientRect(parent, &pc))
            {
                int w = pc.right - pc.left, ht = pc.bottom - pc.top;
                if (w > 0 && ht > 0)
                {
                    p->x = 0; p->y = 0;
                    p->cx = w; p->cy = ht;
                    p->hwndInsertAfter = HWND_TOP;
                    p->flags &= ~(SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER
                        | SWP_HIDEWINDOW);
                    // SWP_NOACTIVATE: never let the constant re-raise of the
                    // viewport steal activation/focus. Without it, every layout
                    // pass bounces focus onto the engine widget, and the engine
                    // toggles the OS cursor each time - the drift that leaves
                    // the cursor stuck hidden while chrome is being hidden.
                    p->flags |= SWP_SHOWWINDOW | SWP_NOACTIVATE;
                }
            }
        }
        WNDPROC orig = reinterpret_cast<WNDPROC>(GetPropW(h, kOrigProcProp));
        if (orig) return CallWindowProcW(orig, h, msg, wp, lp);
        return DefWindowProcW(h, msg, wp, lp);
    }
    // Returns 1 = newly installed, 0 = already ours, -1 = failed.
    static int InstallWndProc(HWND hwnd, WNDPROC proc)
    {
        if (!hwnd || !IsWindow(hwnd)) return -1;
        LONG_PTR cur = GetWindowLongPtrW(hwnd, GWLP_WNDPROC);
        if (cur == reinterpret_cast<LONG_PTR>(proc)) return 0;
        SetLastError(0);
        LONG_PTR orig = SetWindowLongPtrW(hwnd, GWLP_WNDPROC,
            reinterpret_cast<LONG_PTR>(proc));
        if (orig == 0 && GetLastError() != 0) return -1;
        SetPropW(hwnd, kOrigProcProp, reinterpret_cast<HANDLE>(orig));
        return 1;
    }
    // ----- Child window enumeration ----------------------------------------
    struct WinInfo
    {
        HWND hwnd;
        HWND parent;
        int  area;
        bool visible;
        bool chrome;
        char cls[64];
    };
    static BOOL CALLBACK CollectProc(HWND child, LPARAM lp)
    {
        reinterpret_cast<std::vector<HWND>*>(lp)->push_back(child);
        return TRUE;
    }
    // ----- Hide pass -------------------------------------------------------
    //
    // Returns 1 = stable success, 0 = retry.
    static int HideChromeImpl(HWND mainHwnd)
    {
        if (!ResolveQtSymbols())
            return 0;   // Qt DLLs not ready - retry
        // Enumerate every child window and resolve its QWidget class.
        std::vector<HWND> raw;
        EnumChildWindows(mainHwnd, CollectProc, reinterpret_cast<LPARAM>(&raw));
        // Re-dump the full tree whenever the child-window count changes, so
        // chrome that appears AFTER the first pass (e.g. the bottom playtest /
        // status bar that shows up once a playtest starts) is logged too.
        static size_t s_lastDumpCount = (size_t)-1;
        bool doLog = (raw.size() != s_lastDumpCount);
        s_lastDumpCount = raw.size();
        std::vector<WinInfo> wins;
        wins.reserve(raw.size());
        for (HWND h : raw)
        {
            WinInfo w{};
            w.hwnd = h;
            w.parent = GetParent(h);
            RECT r{};
            GetClientRect(h, &r);
            w.area = (r.right - r.left) * (r.bottom - r.top);
            w.visible = IsWindowVisible(h) != 0;
            ClassNameOfHwnd(h, w.cls, sizeof(w.cls));
            w.chrome = IsChromeClassName(w.cls);
            wins.push_back(w);
            if (doLog)
                LogF(L"[hider]  hwnd=%p parent=%p vis=%d area=%d chrome=%d "
                    L"qclass=%hs\n",
                    h, w.parent, w.visible ? 1 : 0, w.area,
                    w.chrome ? 1 : 0, w.cls);
        }
        // Pick the viewport (the 3D render surface). Its QWidget class name is
        // DEFINITIVE, so match it regardless of the `visible` flag or current
        // size: on a play-test client the render window reports vis=0 for a
        // while during load, and requiring visible=1 made the hider loop
        // forever on "no viewport found". ViewportExpander forces it visible +
        // full-size once subclassed.
        //   2023 build: render widget class contained "Ogre" (Ogre engine).
        //   2026 build: it is "RBX::Studio::QEngineWidget".
        // Match either so the same patcher works across builds.
        //
        // There can be SEVERAL engine widgets in the tree:
        //   * the editor/play DOCUMENT viewport, nested inside a Qtitan
        //     DockDocument* container  <-- THIS is the only one we ever want;
        //   * the Start Page / Home render: a FULL-WINDOW engine widget
        //     parented DIRECTLY to the main window (it has QLabel/QFrame
        //     children). It is the LARGEST engine widget during load, so the
        //     old largest-area fallbacks selected it - and expanding/focusing
        //     it makes the engine hide the OS cursor (the random hidden-cursor
        //     bug when the window is focused from the moment it loads);
        //   * the CoreGui TopBar render and small docked previews.
        //
        // So: accept ONLY an engine widget that sits under a DockDocument*
        // container, and explicitly reject any engine widget parented directly
        // to the main window (the start-page render). If the document viewport
        // doesn't exist yet (start-page / still loading), DEFER the pass and
        // retry - never fall back to expanding the start-page render.
        auto classOf = [&](HWND h) -> const char*
            {
                for (const WinInfo& q : wins) if (q.hwnd == h) return q.cls;
                return "";
            };
        auto hasDocAncestor = [&](HWND h) -> bool
            {
                for (HWND a = GetParent(h); a && a != mainHwnd; a = GetParent(a))
                    if (std::strstr(classOf(a), "DockDocument")) return true;
                return false;
            };
        auto isEngine = [&](const WinInfo& w) -> bool
            {
                return std::strstr(w.cls, "EngineWidget") || std::strstr(w.cls, "Ogre");
            };
        // Start Page / Home render: an engine widget parented straight to the
        // main window. Never the editor viewport; must never be selected or
        // expanded (expanding it hides the OS cursor).
        auto isStartPageEngine = [&](const WinInfo& w) -> bool
            {
                return isEngine(w) && w.parent == mainHwnd;
            };
        // ONLY the docked document engine widget qualifies. Largest such wins
        // (covers a split editor where two document viewports exist).
        HWND viewport = nullptr;
        int  bestArea = -1;
        for (const WinInfo& w : wins)
        {
            if (!isEngine(w) || isStartPageEngine(w)) continue;
            if (!hasDocAncestor(w.hwnd)) continue;
            if (!viewport || w.area > bestArea) { viewport = w.hwnd; bestArea = w.area; }
        }
        if (!viewport)
        {
            // Document viewport not present yet (start-page / still loading).
            // DEFER rather than fall back to the start-page render: the old
            // fallbacks selected that full-window widget and expanding it is
            // what hid the cursor when focused from load. qt_hider will re-run
            // this pass until the editor document viewport appears.
            LogF(L"[hider] no docked document viewport yet - deferring (retry)\n");
            return 0;
        }
        // Only log the viewport when it first appears or changes - logging it on
        // every periodic pass is pure spam once it's stable.
        static HWND s_lastViewport = nullptr;
        const bool vpChanged = (viewport != s_lastViewport);
        s_lastViewport = viewport;
        if (doLog || vpChanged)
        {
            char vc[64] = {};
            for (const WinInfo& w : wins)
                if (w.hwnd == viewport)
                {
                    memcpy(vc, w.cls, sizeof(vc));
                    vc[sizeof(vc) - 1] = '\0';
                    break;
                }
            LogF(L"[hider] viewport = %p qclass=%hs\n", viewport, vc);
        }
        // Viewport HWND chain up to the main window - these are kept.
        std::vector<HWND> chain;
        for (HWND c = viewport; c; c = GetParent(c))
        {
            chain.push_back(c);
            if (c == mainHwnd) break;
            if (chain.size() > 64) break;
        }
        if (chain.empty() || chain.back() != mainHwnd)
        {
            LogF(L"[hider] viewport chain broken - retry\n");
            return 0;
        }
        // The qt hider must NEVER leave the cursor hidden. Our SetWindowPos /
        // hide calls below run the engine widget's window handlers synchronously
        // and can drive the OS ShowCursor counter negative (cursor stuck hidden).
        // After the pass we force the counter back to >= 0 (visible). The engine
        // still owns the cursor IMAGE via SetCursor (NULL == its in-engine
        // cursor), so this never reveals the external arrow during gameplay - it
        // only ensures the hider itself can never hide the pointer.
        auto PeekCursorCount = []() -> int
            {
                int v = ShowCursor(TRUE);   // returns count+1
                ShowCursor(FALSE);          // back to count
                return v - 1;
            };
        // Block every chrome-class window that is NOT on the viewport chain.
        // (Chain ancestors are kept even if they are chrome-classed, so we
        // never blank a container that physically holds the viewport.)
        int newlyBlocked = 0, alreadyBlocked = 0;
        for (const WinInfo& w : wins)
        {
            if (!w.chrome) continue;
            bool onChain = false;
            for (HWND c : chain)
                if (c == w.hwnd) { onChain = true; break; }
            if (onChain) continue;
            int r = InstallWndProc(w.hwnd, &ChromeBlockerWndProc);
            if (r == 1)
            {
                ++newlyBlocked;
                // WS_EX_TRANSPARENT: excluded from sibling hit-testing so the
                // bar is click-through (paired with the HTTRANSPARENT handler).
                LONG_PTR ex = GetWindowLongPtrW(w.hwnd, GWL_EXSTYLE);
                SetWindowLongPtrW(w.hwnd, GWL_EXSTYLE,
                    ex | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
                // Deliberately NOT EnableWindow(FALSE) / ShowWindow(SW_HIDE):
                // disabling or hiding a child that holds the keyboard focus
                // forces focus elsewhere, and the engine viewport reacts to
                // that focus change by hiding the OS cursor (ShowCursor drift)
                // - the "cursor disappears while chrome is hidden" bug. The
                // single SWP_HIDEWINDOW move below hides it without the extra
                // focus churn, and the exstyle above keeps it click-through.
                SetWindowPos(w.hwnd, nullptr, -32000, -32000, 0, 0,
                    SWP_NOZORDER | SWP_NOACTIVATE | SWP_HIDEWINDOW);
            }
            else if (r == 0)
            {
                ++alreadyBlocked;
            }
        }
        // Expand the viewport chain so the 3D view fills the whole frame.
        // Walk OUTERMOST -> INNERMOST (the window nearest the main window
        // first) so each parent is already full-size before we size its
        // child to fit it. chain[0] is the viewport, chain.back() is the
        // main window (never resized).
        for (int i = static_cast<int>(chain.size()) - 2; i >= 0; --i)
        {
            HWND h = chain[i], parent = chain[i + 1];
            InstallWndProc(h, &ViewportExpanderWndProc);   // idempotent
            RECT pc{};
            if (GetClientRect(parent, &pc))
            {
                int w = pc.right - pc.left;
                int ht = pc.bottom - pc.top;
                if (w < 1) w = 1;
                if (ht < 1) ht = 1;
                // Only reposition when the geometry is actually wrong. Poking
                // the engine widget with SetWindowPos every single pass (even
                // when it already fills the parent) is what drives the cursor
                // show-count down over time; the ViewportExpanderWndProc still
                // re-asserts size reactively whenever Qt tries to change it.
                RECT wr{};
                POINT org{ 0, 0 };
                GetWindowRect(h, &wr);
                ClientToScreen(parent, &org);
                int curX = wr.left - org.x, curY = wr.top - org.y;
                int curW = wr.right - wr.left, curH = wr.bottom - wr.top;
                if (curX != 0 || curY != 0 || curW != w || curH != ht)
                    SetWindowPos(h, HWND_TOP, 0, 0, w, ht,
                        SWP_NOACTIVATE | SWP_SHOWWINDOW);
            }
        }
        // Guarantee the cursor is never left hidden by the hider: bring the OS
        // show-count up to at least 0 (>= 0 == visible).
        int cursorAfter = PeekCursorCount();
        while (cursorAfter < 0)
            cursorAfter = ShowCursor(TRUE);
        // Log a pass only when it actually did something (blocked new windows)
        // or the tree/viewport changed. A steady "newlyBlocked=0" pass is noise.
        if (doLog || vpChanged || newlyBlocked > 0)
            LogF(L"[hider] pass: viewport=%p chainLen=%zu newlyBlocked=%d "
                L"alreadyBlocked=%d totalWins=%zu\n",
                viewport, chain.size(), newlyBlocked, alreadyBlocked,
                wins.size());
        // ----- Bottom-strip diagnostic --------------------------------------
        // The dead zone is at the bottom of the window. Log, for the first few
        // passes AFTER the tree is fully built, every child window whose screen
        // rect touches the bottom 80px of the main client area - that is the
        // window stealing the cursor. Flag whether it's chrome (should be
        // blocked) and whether it's on the viewport chain (kept on purpose).
        static int s_stripDiag = 0;
        if (s_stripDiag < 3)
        {
            ++s_stripDiag;
            RECT mc{};
            GetClientRect(mainHwnd, &mc);
            POINT tl{ mc.left, mc.top }, brp{ mc.right, mc.bottom };
            ClientToScreen(mainHwnd, &tl);
            ClientToScreen(mainHwnd, &brp);
            const int stripTop = brp.y - 80;
            {
                RECT vr{};
                GetWindowRect(viewport, &vr);
                LogF(L"[hider] strip-diag: mainClientBottom=%d viewport=[%d,%d,%d,%d] "
                    L"(coversBottom=%d)\n",
                    brp.y, vr.left, vr.top, vr.right, vr.bottom,
                    (vr.bottom >= brp.y - 2) ? 1 : 0);
            }
            for (const WinInfo& w : wins)
            {
                if (w.hwnd == viewport) continue;
                RECT wr{};
                if (!GetWindowRect(w.hwnd, &wr)) continue;
                if (wr.right <= wr.left || wr.bottom <= wr.top) continue;
                if (wr.bottom < stripTop || wr.top > brp.y) continue;     // not in strip
                if (wr.right < tl.x || wr.left > brp.x) continue;         // not horizontally over client
                bool onChain = false;
                for (HWND c : chain) if (c == w.hwnd) { onChain = true; break; }
                LogF(L"[hider] strip-occupant hwnd=%p rect=[%d,%d,%d,%d] vis=%d "
                    L"chrome=%d onChain=%d qclass=%hs\n",
                    w.hwnd, wr.left, wr.top, wr.right, wr.bottom,
                    IsWindowVisible(w.hwnd) ? 1 : 0,
                    w.chrome ? 1 : 0, onChain ? 1 : 0, w.cls);
            }
        }
        return (newlyBlocked == 0) ? 1 : 0;
    }
    // ----- Public entry point ----------------------------------------------
    bool HideStudioChromeWidgets(HWND mainHwnd, bool* outReady)
    {
        if (outReady) *outReady = false;
        // LogF(L"[hider] === HideStudioChromeWidgets(main=%p) ===\n", mainHwnd);
        if (!mainHwnd || !IsWindow(mainHwnd))
        {
            //  LogF(L"[hider] main window handle invalid - abort\n");
            return false;
        }
        int result = 0;
        __try
        {
            result = HideChromeImpl(mainHwnd);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // LogF(L"[hider] SEH fault in HideChromeImpl - hard fail\n");
            if (outReady) *outReady = true;
            return false;
        }
        return result == 1;
    }
}
