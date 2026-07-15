// server_console.cpp - see server_console.h.

#include "server_console.h"
#include "loadstring_console.h"
#include "patcher.h"

#include <shellapi.h>
#include <winhttp.h>
#include <string>
#include <mutex>
#include <cstdio>
#include <cwctype>

#pragma comment(lib, "winhttp.lib")

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();

    static bool        g_active  = false;
    static HANDLE      g_conOut  = nullptr;
    static std::mutex  g_writeMtx;

    bool ServerConsoleActive() { return g_active; }

    void ServerConsoleLog(const std::string& line)
    {
        if (!g_active || !g_conOut) return;
        std::lock_guard<std::mutex> lk(g_writeMtx);
        DWORD w = 0;
        if (!line.empty())
            WriteFile(g_conOut, line.data(), (DWORD)line.size(), &w, nullptr);
        if (line.empty() || line.back() != '\n')
        {
            const char nl = '\n';
            WriteFile(g_conOut, &nl, 1, &w, nullptr);
        }
    }

    void ServerConsolePlayerJoined(const std::string& displayName)
    {
        if (!g_active) return;
        ServerConsoleLog(std::string("[+] Player joined: ") + displayName);
    }

    void ServerConsolePlayerLeft(const std::string& username)
    {
        if (!g_active) return;
        ServerConsoleLog(std::string("[-] Player left: ") + username);
    }

    // ---- window hiding ---------------------------------------------------

    // Hide the visible top-level windows owned by THIS process, except the
    // console window. The server's 3D viewport / Studio chrome is one such
    // top-level window; the console belongs to conhost and/or is skipped
    // explicitly, so it stays visible.
    static BOOL CALLBACK HideEnumProc(HWND hwnd, LPARAM lparam)
    {
        HWND console = reinterpret_cast<HWND>(lparam);
        if (hwnd == console) return TRUE;
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid != GetCurrentProcessId()) return TRUE;
        if (!IsWindowVisible(hwnd)) return TRUE;
        // Keep the HookedWebserver cookie-login popup visible: it needs user
        // input (paste .ROBLOSECURITY, Log In / Skip), so even on a headless
        // StartServer instance it must NOT be hidden. Match by window class
        // (stable across the normal and "invalid cookie" retry titles).
        {
            wchar_t cls[64] = {};
            if (GetClassNameW(hwnd, cls, ARRAYSIZE(cls)) > 0 &&
                lstrcmpW(cls, L"OffBloxCookieLogin") == 0)
                return TRUE;
        }
        // Never hide the Auto-Recovery modal: hiding a modal leaves its input
        // grab active but invisible, freezing the UI (clicks ding). Leave it for
        // auto_recovery.cpp to close via WM_CLOSE.
        {
            wchar_t title[256] = {};
            if (GetWindowTextW(hwnd, title, ARRAYSIZE(title)) > 0)
            {
                for (wchar_t* p = title; *p; ++p) *p = (wchar_t)towlower(*p);
                if (wcsstr(title, L"recover") != nullptr) return TRUE;
            }
        }
        ShowWindow(hwnd, SW_HIDE);
        return TRUE;
    }

    static DWORD WINAPI HideThread(LPVOID)
    {
        // The main window may not exist yet at DllMain time and can be
        // re-created during startup, so sweep for a while.
        HWND console = GetConsoleWindow();
        for (int i = 0; i < 300; ++i)   // ~30s
        {
            EnumWindows(&HideEnumProc, reinterpret_cast<LPARAM>(console));
            Sleep(100);
        }
        return 0;
    }

    // ---- shutdown ---------------------------------------------------------

    static bool RunningUnderWine()
    {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        return nt != nullptr && GetProcAddress(nt, "wine_get_version") != nullptr;
    }

    // Ctrl+C / Ctrl+Break / console-close must actually kill the server. The
    // engine's GUI message loop never returns, so no normal exit path is ever
    // reached; force the process down. Registered on our console below.
    static BOOL WINAPI ServerCtrlHandler(DWORD type)
    {
        switch (type)
        {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            ServerConsoleLog("[server] shutting down");
            TerminateProcess(GetCurrentProcess(), 0);
            return TRUE;
        default:
            return FALSE;
        }
    }

    // ---- console input -> run Luau on the server -------------------------
    // Lines the host types are POSTed to the local webserver's /offblox/exec
    // queue; an in-engine poller (injected into the signed startup Lua) GETs
    // them and loadstring()s each on the server with the startup identity.
    // C++ can't call the Luau VM directly without engine RE, so this HTTP
    // hand-off + tiny poller is the bridge.

    static void PostExecScript(const std::string& code)
    {
        HINTERNET hS = WinHttpOpen(L"OffBloxConsole",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hS) return;
        HINTERNET hC = WinHttpConnect(hS, L"localhost", 80, 0);
        if (hC)
        {
            HINTERNET hR = WinHttpOpenRequest(hC, L"POST", L"/offblox/exec",
                nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (hR)
            {
                if (WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                        (LPVOID)code.data(), (DWORD)code.size(),
                        (DWORD)code.size(), 0))
                    WinHttpReceiveResponse(hR, nullptr);
                WinHttpCloseHandle(hR);
            }
            WinHttpCloseHandle(hC);
        }
        WinHttpCloseHandle(hS);
    }

    static DWORD WINAPI InputReaderThread(LPVOID)
    {
        // Let startup settle (and any headless cookie prompt finish reading
        // stdin) before we start consuming console input.
        Sleep(5000);

        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        if (!hIn || hIn == INVALID_HANDLE_VALUE)
            hIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_EXISTING, 0, nullptr);
        if (!hIn || hIn == INVALID_HANDLE_VALUE) return 0;

        ServerConsoleLog("[console] script input ready - type Luau and press "
                         "Enter to run it on the server (one line per script).");

        std::string line; char c; DWORD r = 0;
        for (;;)
        {
            if (!ReadFile(hIn, &c, 1, &r, nullptr) || r == 0) { Sleep(200); continue; }
            if (c == '\r') continue;
            if (c != '\n') { line.push_back(c); continue; }

            while (!line.empty() && (line.back() == ' ' || line.back() == '\t'))
                line.pop_back();
            if (!line.empty())
            {
                ServerConsoleLog(std::string("> ") + line);
                // Hand the line to the loadstring-hook queue; the in-engine
                // poller pulls it and runs it on the server. (PostExecScript /
                // the /offblox/exec HTTP path is left in place as a fallback.)
                EnqueueConsoleScript(line);
            }
            line.clear();
        }
        return 0;
    }

    void StartServerConsole()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        // Prefer an output that ALREADY exists so we don't spawn a separate
        // console window (a new console needs a display, which fails on a truly
        // headless Wine/Linux host). Order of preference:
        //   1. inherited stdout - launched from a shell / pipe / redirect
        //      (e.g. `wine OffBlox.exe ...` from a terminal). Write straight to it.
        //   2. an already-attached console -> open its CONOUT$.
        //   3. nothing -> AllocConsole() and make our own (desktop case).
        bool madeConsole = false;
        HANDLE inherited = GetStdHandle(STD_OUTPUT_HANDLE);
        const bool haveInherited =
            (inherited != nullptr && inherited != INVALID_HANDLE_VALUE);

        if (haveInherited)
        {
            g_conOut = inherited;
            LogF(L"[server_console] using inherited stdout %p (no new console)\n",
                 (void*)inherited);
        }
        else if (GetConsoleWindow() != nullptr)
        {
            g_conOut = CreateFileW(L"CONOUT$", GENERIC_WRITE,
                                   FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, 0, nullptr);
            if (g_conOut == INVALID_HANDLE_VALUE) g_conOut = nullptr;
            LogF(L"[server_console] using already-attached console (CONOUT$)\n");
        }
        else if (RunningUnderWine() && AttachConsole(ATTACH_PARENT_PROCESS))
        {
            // WINE ONLY. `wine OffBlox.exe` keeps the launching Linux terminal
            // BUSY for the whole run (wine is a console program the shell waits
            // on), so attaching to that parent console gives clean, exclusive
            // output there. On Windows we deliberately do NOT do this: a GUI exe
            // does NOT block PowerShell/cmd, so the shell returns to its prompt
            // and our output would interleave with a live "PS C:\...>" prompt
            // (and Ctrl+C would go to the shell, not us). Windows falls through
            // to AllocConsole() below to get its own dedicated console instead.
            g_conOut = CreateFileW(L"CONOUT$", GENERIC_WRITE,
                                   FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, 0, nullptr);
            if (g_conOut == INVALID_HANDLE_VALUE) g_conOut = nullptr;
            madeConsole = true;   // redirect C stdio to the terminal too
            LogF(L"[server_console] attached to parent console (wine terminal)\n");
        }
        else if (AllocConsole())
        {
            madeConsole = true;
            SetConsoleTitleW(L"Roblox Server");
            g_conOut = CreateFileW(L"CONOUT$", GENERIC_WRITE,
                                   FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, 0, nullptr);
            if (g_conOut == INVALID_HANDLE_VALUE) g_conOut = nullptr;
            LogF(L"[server_console] allocated a new console\n");
        }
        else
        {
            LogF(L"[server_console] no console and AllocConsole failed (err=%lu)\n",
                 GetLastError());
        }

        g_active = (g_conOut != nullptr);

        // Make Ctrl+C / Ctrl+Break / window-close terminate the server. Without
        // this the engine's GUI loop keeps the process alive and Ctrl+C is
        // swallowed. On our own (AllocConsole) window this is fully in effect;
        // when attached to the wine terminal it lets a terminal SIGINT bring us
        // down cleanly too.
        SetConsoleCtrlHandler(&ServerCtrlHandler, TRUE);

        // Only redirect C stdio when WE created the console. If stdout was
        // inherited it is already wired to the shell/pipe and must not be
        // clobbered (freopen CONOUT$ would point it at a console that may not
        // exist on a headless host).
        if (madeConsole)
        {
            FILE* f = nullptr;
            freopen_s(&f, "CONOUT$", "w", stdout);
            freopen_s(&f, "CONOUT$", "w", stderr);
        }

        if (g_active)
        {
            // Parse -port from the command line
            int port = 0;
            int argc = 0;
            LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
            if (argv)
            {
                for (int i = 1; i < argc - 1; ++i)
                {
                    if (_wcsicmp(argv[i], L"-port") == 0)
                    {
                        port = _wtoi(argv[i + 1]);
                        break;
                    }
                }
                LocalFree(argv);
            }

            char portBuf[64];
            int n = _snprintf_s(portBuf, sizeof(portBuf), _TRUNCATE,
                "RCCService running on port: %d", port);
            if (n > 0) ServerConsoleLog(std::string(portBuf, n));
        }

        // Hide the 3D/game window regardless (even if the console handle failed,
        // the user asked for the window gone on the server).
        CloseHandle(CreateThread(nullptr, 0, &HideThread, nullptr, 0, nullptr));

        // Start the console script-input reader once we have a usable console.
        if (g_active)
            CloseHandle(CreateThread(nullptr, 0, &InputReaderThread, nullptr, 0, nullptr));
    }
}
