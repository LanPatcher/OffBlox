// server_console.cpp - see server_console.h.

#include "server_console.h"
#include "patcher.h"

#include <shellapi.h>
#include <string>
#include <mutex>
#include <cstdio>

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

    void StartServerConsole()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        // AllocConsole fails if one already exists; either way try to open the
        // console output buffer.
        AllocConsole();
        SetConsoleTitleW(L"Roblox Server");

        g_conOut = CreateFileW(L"CONOUT$", GENERIC_WRITE,
                               FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (g_conOut == INVALID_HANDLE_VALUE) { g_conOut = nullptr; }
        g_active = (g_conOut != nullptr);

        // Also point C stdio at the console so any stray printf shows up.
        FILE* f = nullptr;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);

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
        else
        {
            LogF(L"[server_console] AllocConsole/CONOUT$ failed (err=%lu)\n",
                 GetLastError());
        }

        // Hide the 3D/game window regardless (even if the console handle failed,
        // the user asked for the window gone on the server).
        CloseHandle(CreateThread(nullptr, 0, &HideThread, nullptr, 0, nullptr));
    }
}
