// patcher.h - shared declarations & utilities for RobloxStudioPatcher
//
// This DLL is intended to be injected into RobloxStudioBeta.exe (2023 client)
// via stud_pe's "Add new import" feature. Once the host EXE loads the DLL,
// DllMain runs DLL_PROCESS_ATTACH, which:
//   1) Installs an IAT hook on kernel32!GetCommandLineW so Studio sees an
//      extra "-username <X>" appended (read from username.txt next to DLL).
//   2) Spawns a worker thread that polls top-level windows and hides every
//      Qt5* window (login screen, menus, toolbars, dock widgets, viewport...).
//
// Pure Win32 + STL. No external dependencies. Build with VS 2019/2023,
// PlatformToolset v143, /MT (static CRT) so the DLL has no runtime deps.

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>

namespace RobloxStudioPatcher
{
    // Filled in by DllMain. Used everywhere we need to read sidecar files
    // (username.txt) from the directory the DLL was loaded from.
    extern HMODULE g_hSelf;

    // ---- Logging --------------------------------------------------------
    // Lightweight OutputDebugStringW wrapper. View output in DbgView or by
    // attaching a debugger to RobloxStudioBeta.exe. Compiled out in Release
    // unless ROBLOX_PATCHER_LOG is defined.

#if defined(_DEBUG) || defined(ROBLOX_PATCHER_LOG)
    void LogImpl(const wchar_t* fmt, ...);
    #define LOG(...) ::RobloxStudioPatcher::LogImpl(__VA_ARGS__)
#else
    #define LOG(...) ((void)0)
#endif

    // ---- Always-on file logger ----------------------------------------
    // Writes to RobloxStudioPatcher.log next to the DLL, regardless of
    // build config. Use this for diagnostics that the user needs to see
    // in Release builds (where LOG() is compiled out).
    //
    // The file is opened, appended, and closed each call - slower than
    // a persistent handle but trivially safe across the DllMain timing
    // and crash recovery. Use sparingly.
    void LogF(const wchar_t* fmt, ...);

    // ---- Filesystem helpers --------------------------------------------

    // Absolute path of the directory the DLL was loaded from, ending in '\\'.
    // Used as the base location for sidecar files (username.txt, etc.).
    std::wstring GetDllDirectory();

    // Read a UTF-8 / UTF-16 / locale file fully into a wstring, trimming any
    // trailing CR/LF/whitespace. Returns empty string if the file doesn't
    // exist or can't be opened. Safe to call from DllMain.
    std::wstring ReadTextFileTrimmed(const std::wstring& path);
}
