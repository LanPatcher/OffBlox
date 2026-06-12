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
        using FnFind      = void* (QT_STATIC_CC*)(uintptr_t);
        using FnClassName = const char* (QT_MEMBER_CC*)(const void*);
        FnFind      widgetFind    = nullptr;
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
        auto ed   = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + rva);
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
        HMODULE core    = GetModuleHandleW(L"Qt5Core.dll");
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
        if (msg == WM_WINDOWPOSCHANGING)
        {
            auto* p = reinterpret_cast<WINDOWPOS*>(lp);
            if (p)
            {
                p->flags &= ~SWP_SHOWWINDOW;
                p->flags |= SWP_HIDEWINDOW | SWP_NOREDRAW;
                p->x = -32000; p->y = -32000;
                p->cx = 0;     p->cy = 0;
            }
        }
        WNDPROC orig = reinterpret_cast<WNDPROC>(GetPropW(h, kOrigProcProp));
        if (orig) return CallWindowProcW(orig, h, msg, wp, lp);
        return DefWindowProcW(h, msg, wp, lp);
    }

    static LRESULT CALLBACK ViewportExpanderWndProc(HWND h, UINT msg,
                                                    WPARAM wp, LPARAM lp)
    {
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
                    p->flags |= SWP_SHOWWINDOW;
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

        static bool s_dumped = false;
        bool doLog = !s_dumped;
        s_dumped = true;

        // Enumerate every child window and resolve its QWidget class.
        std::vector<HWND> raw;
        EnumChildWindows(mainHwnd, CollectProc, reinterpret_cast<LPARAM>(&raw));

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

           // if (doLog)
              //  LogF(L"[hider]  hwnd=%p parent=%p vis=%d area=%d chrome=%d "
                 //    L"qclass=%hs\n",
                 //    h, w.parent, w.visible ? 1 : 0, w.area,
                 //    w.chrome ? 1 : 0, w.cls);
        }

        // Pick the viewport. The 3D render surface is a "QOgreWidget"
        // (Roblox renders the 3D scene through an Ogre-derived engine).
        // Its class name is DEFINITIVE, so match it regardless of the
        // `visible` flag or current size: on a play-test client the render
        // window can report vis=0 for a while during load, and requiring
        // visible=1 made the hider loop forever on "no viewport found".
        // ViewportExpander forces it visible + full-size once subclassed.
        HWND viewport = nullptr;
        int  bestArea = -1;
        for (const WinInfo& w : wins)
        {
            if (!std::strstr(w.cls, "Ogre")) continue;
            if (!viewport || w.area > bestArea)
            {
                viewport = w.hwnd;
                bestArea = w.area;
            }
        }
        if (!viewport)
        {
            // Fallback: largest visible non-chrome window (only used if no
            // QOgreWidget exists in the tree at all).
            bestArea = 0;
            for (const WinInfo& w : wins)
            {
                if (!w.visible || w.chrome || w.area < 10000) continue;
                if (w.area > bestArea) { bestArea = w.area; viewport = w.hwnd; }
            }
        }
        if (!viewport)
        {
          //  LogF(L"[hider] no viewport window found - retry\n");
            return 0;
        }
        {
            char vc[64] = {};
            for (const WinInfo& w : wins)
                if (w.hwnd == viewport)
                {
                    memcpy(vc, w.cls, sizeof(vc));
                    vc[sizeof(vc) - 1] = '\0';
                    break;
                }
          //  LogF(L"[hider] viewport = %p qclass=%hs\n", viewport, vc);
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
                ShowWindow(w.hwnd, SW_HIDE);
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
            InstallWndProc(h, &ViewportExpanderWndProc);
            RECT pc{};
            if (GetClientRect(parent, &pc))
            {
                int w  = pc.right - pc.left;
                int ht = pc.bottom - pc.top;
                if (w < 1) w = 1;
                if (ht < 1) ht = 1;
                SetWindowPos(h, HWND_TOP, 0, 0, w, ht,
                             SWP_NOACTIVATE | SWP_SHOWWINDOW);
            }
        }

       // LogF(L"[hider] pass: viewport=%p chainLen=%zu newlyBlocked=%d "
         //    L"alreadyBlocked=%d totalWins=%zu\n",
         ///    viewport, chain.size(), newlyBlocked, alreadyBlocked,
         //    wins.size());

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
