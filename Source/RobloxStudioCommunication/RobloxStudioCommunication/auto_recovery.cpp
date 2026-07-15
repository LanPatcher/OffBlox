// auto_recovery.cpp - suppress Studio's Auto-Recovery modal (AutoSaveDialog).
//
// Two layers, because clearing files alone can lose the race with Studio's
// startup scan:
//   1. Keep <Documents>\ROBLOX\AutoSaves empty during startup (belt).
//   2. Intercept the modal itself: watch our own top-level windows for the
//      "Auto-Save Recovery" dialog (title contains "recover") and send WM_CLOSE,
//      which Qt treats as reject() - the modal loop ends, no file is recovered,
//      and input returns to the viewport. Hiding it (qt_hider) wasn't enough
//      because a modal keeps its input grab even while invisible.
//
// Default "Auto-Recovery Path" is %USERPROFILE%\Documents\ROBLOX\AutoSaves.

#include "auto_recovery.h"
#include "patcher.h"

#include <shlobj.h>
#include <string>
#include <cwctype>
#pragma comment(lib, "shell32.lib")

namespace RobloxStudioPatcher
{
    static std::wstring AutoSavesDir()
    {
        wchar_t docs[MAX_PATH] = {};
        if (SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr,
                             SHGFP_TYPE_CURRENT, docs) != S_OK)
            return {};
        return std::wstring(docs) + L"\\ROBLOX\\AutoSaves";
    }

    static int ClearAutoRecoveryDir()
    {
        std::wstring dir = AutoSavesDir();
        if (dir.empty()) return 0;
        std::wstring pattern = dir + L"\\*";
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return 0;
        int deleted = 0;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring full = dir + L"\\" + fd.cFileName;
            SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
            if (DeleteFileW(full.c_str())) ++deleted;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
        return deleted;
    }

    static std::wstring ToLowerW(std::wstring s)
    {
        for (auto& c : s) c = (wchar_t)towlower(c);
        return s;
    }

    struct DismissCtx { DWORD pid; int closed; };

    static BOOL CALLBACK DismissEnumProc(HWND hwnd, LPARAM lp)
    {
        auto* ctx = reinterpret_cast<DismissCtx*>(lp);
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid != ctx->pid) return TRUE;
        // NOTE: do NOT skip invisible windows. A window hider (qt_hider /
        // server_console) can ShowWindow(SW_HIDE) the modal before we reach it;
        // a hidden modal still holds its input grab, so the UI freezes (and a
        // click plays the system "ding"). We must still WM_CLOSE it even when
        // hidden - matching by title + our pid keeps that specific.

        wchar_t title[256] = {};
        if (GetWindowTextW(hwnd, title, _countof(title)) <= 0) return TRUE;
        std::wstring t = ToLowerW(title);

        // "Auto-Save Recovery" / "Auto-Recovery" / "...recovered file..." all
        // contain "recover". The main window title is "Roblox", login is handled
        // elsewhere, so this is specific enough in this build.
        if (t.find(L"recover") != std::wstring::npos)
        {
            LogF(L"[auto_recovery] dismissing recovery dialog hwnd=%p title='%ls'\n",
                 hwnd, title);
            // reject() the modal: WM_CLOSE ends the dialog's exec() loop and
            // returns control without recovering anything.
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
            ctx->closed++;
        }
        return TRUE;
    }

    static int DismissRecoveryDialog()
    {
        DismissCtx ctx{ GetCurrentProcessId(), 0 };
        EnumWindows(&DismissEnumProc, reinterpret_cast<LPARAM>(&ctx));
        return ctx.closed;
    }

    // One-shot diagnostic: log every visible top-level window title of our
    // process, so if the "recover" match misses (different localized title) we
    // can see the real title in the log and adjust without guessing.
    static BOOL CALLBACK DumpEnumProc(HWND hwnd, LPARAM)
    {
        DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
        if (pid != GetCurrentProcessId() || !IsWindowVisible(hwnd)) return TRUE;
        wchar_t title[256] = {};
        if (GetWindowTextW(hwnd, title, _countof(title)) > 0 && title[0])
            LogF(L"[auto_recovery] window hwnd=%p title='%ls'\n", hwnd, title);
        return TRUE;
    }

    // Run both layers across the startup window. The dialog appears once during
    // launch; polling catches it the instant it shows and closes it before the
    // user is stuck. Cheap, so we cover a generous window.
    static DWORD WINAPI AutoRecoveryKillerThread(LPVOID)
    {
        bool dumped = false;
        for (int i = 0; i < 160; ++i)   // 160 * 250ms = ~40s
        {
            int n = ClearAutoRecoveryDir();
            if (n > 0) LogF(L"[auto_recovery] cleared %d file(s)\n", n);
            // Dump titles once, a couple seconds in (after the window likely exists).
            if (!dumped && i == 8) { EnumWindows(&DumpEnumProc, 0); dumped = true; }
            DismissRecoveryDialog();      // logs per close
            Sleep(250);
        }
        LogF(L"[auto_recovery] killer thread finished\n");
        return 0;
    }

    void StartAutoRecoveryKiller()
    {
        int n = ClearAutoRecoveryDir();
        LogF(L"[auto_recovery] initial clear removed %d file(s) from '%ls'\n",
             n, AutoSavesDir().c_str());
        HANDLE h = CreateThread(nullptr, 0, &AutoRecoveryKillerThread,
                                nullptr, 0, nullptr);
        if (h) { CloseHandle(h); LogF(L"[auto_recovery] watcher started\n"); }
        else   { LogF(L"[auto_recovery] FAILED to start watcher thread\n"); }
    }
}
