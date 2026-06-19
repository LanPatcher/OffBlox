// dllmain.cpp - entry point for RobloxStudioPatcher.dll
//
// Loaded into RobloxStudioBeta.exe (2023 client) by adding an import to
// the EXE's PE import table via stud_pe.
//
// Sequence on DLL_PROCESS_ATTACH:
//   1. Disable thread library callbacks (we don't need them).
//   2. Check the command line for "-task StartClient". If absent we are
//      running as a server or Studio editor instance -- skip ALL Qt/network
//      hider work so the developer tools remain accessible.
//   3. Install the surgical name-patch (rewrites the push operand that
//      supplies the format string to the player-name sprintf).
//   4. Start the ws2_32 UDP relay (both client and server ends), the
//      server-only script-start + identity hooks, and the Qt5 window hider
//      (client only).
//
// We also export a single stub function "Patch" via RobloxStudioPatcher.def
// so that stud_pe has something concrete to import.

#include "patcher.h"
#include "qt_hider.h"
#include "name_patcher.h"
#include "identity_patch.h"
#include "udp_relay.h"
#include "studio_print.h"
#include "script_start_hook.h"
#include "rcc_patch.h"
#include "port_remap.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace RobloxStudioPatcher
{
    HMODULE g_hSelf = nullptr;

#if defined(_DEBUG) || defined(ROBLOX_PATCHER_LOG)
    void LogImpl(const wchar_t* fmt, ...)
    {
        wchar_t buf[1024];
        va_list ap;
        va_start(ap, fmt);
        _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
        va_end(ap);
        OutputDebugStringW(buf);
    }
#endif

    void LogF(const wchar_t* fmt, ...)
    {
        wchar_t buf[2048];
        va_list ap;
        va_start(ap, fmt);
        int n = _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
        va_end(ap);
        if (n <= 0) return;

        OutputDebugStringW(buf);

        // Surface the same line in Studio's Output panel via Roblox's
        // internal logger. RobloxPrintW is a no-op if the print fn
        // hasn't been resolved (early in startup before ws2_32 is loaded,
        // or in a build where the marker string isn't present).
        RobloxPrintW(buf);

        std::wstring path = GetDllDirectory() + L"RobloxStudioPatcher.log";
        HANDLE h = CreateFileW(path.c_str(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (h == INVALID_HANDLE_VALUE) return;

        char utf8[4096];
        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, buf, n,
            utf8, sizeof(utf8), nullptr, nullptr);
        if (utf8Len > 0)
        {
            DWORD written = 0;
            WriteFile(h, utf8, (DWORD)utf8Len, &written, nullptr);
        }
        CloseHandle(h);
    }

    std::wstring GetDllDirectory()
    {
        if (!g_hSelf) return {};
        wchar_t path[MAX_PATH] = {};
        DWORD n = GetModuleFileNameW(g_hSelf, path, _countof(path));
        if (n == 0 || n == _countof(path)) return {};
        std::wstring s(path, n);
        size_t slash = s.find_last_of(L"\\/");
        if (slash == std::wstring::npos) return {};
        return s.substr(0, slash + 1);
    }

    std::wstring ReadTextFileTrimmed(const std::wstring& path)
    {
        HANDLE h = CreateFileW(path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (h == INVALID_HANDLE_VALUE) return {};

        LARGE_INTEGER size{};
        if (!GetFileSizeEx(h, &size) || size.QuadPart > (1 << 20))
        {
            CloseHandle(h);
            return {};
        }

        std::vector<BYTE> bytes(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        ReadFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
        CloseHandle(h);
        if (read == 0) return {};
        bytes.resize(read);

        std::wstring out;
        if (bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            out.assign(reinterpret_cast<wchar_t*>(bytes.data() + 2),
                (bytes.size() - 2) / sizeof(wchar_t));
        }
        else if (bytes.size() >= 3
            && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            int wlen = MultiByteToWideChar(CP_UTF8, 0,
                reinterpret_cast<char*>(bytes.data() + 3),
                static_cast<int>(bytes.size() - 3),
                nullptr, 0);
            out.resize(wlen);
            MultiByteToWideChar(CP_UTF8, 0,
                reinterpret_cast<char*>(bytes.data() + 3),
                static_cast<int>(bytes.size() - 3),
                out.data(), wlen);
        }
        else
        {
            int wlen = MultiByteToWideChar(CP_UTF8, 0,
                reinterpret_cast<char*>(bytes.data()),
                static_cast<int>(bytes.size()),
                nullptr, 0);
            out.resize(wlen);
            MultiByteToWideChar(CP_UTF8, 0,
                reinterpret_cast<char*>(bytes.data()),
                static_cast<int>(bytes.size()),
                out.data(), wlen);
        }

        while (!out.empty() && (out.back() == L'\r' || out.back() == L'\n'
            || out.back() == L' ' || out.back() == L'\t'))
            out.pop_back();
        size_t firstNon = out.find_first_not_of(L" \t\r\n");
        if (firstNon == std::wstring::npos) return {};
        return out.substr(firstNon);
    }

    // Returns true if the process command line contains "-task StartClient".
    // Used to gate Qt hiding and network relay so that server and editor
    // instances retain full developer-tool access.
    static bool IsStartClientTask()
    {
        const wchar_t* cmdLine = GetCommandLineW();
        if (!cmdLine) return false;
        return wcsstr(cmdLine, L"-task StartClient") != nullptr;
    }

    static bool IsStartServerTask()
    {
        const wchar_t* cmdLine = GetCommandLineW();
        if (!cmdLine) return false;
        return wcsstr(cmdLine, L"-task StartServer") != nullptr;
    }

    // Public wrappers so udp_relay.cpp (separate TU) can query launch mode
    // without duplicating the command-line parse.
    bool IsStartClientTask_Pub() { return IsStartClientTask(); }
    bool IsStartServerTask_Pub() { return IsStartServerTask(); }
}

extern "C" __declspec(dllexport) void Patch()
{
    // Intentionally empty. Side effects happen in DllMain.
}

static void SafeInit()
{
#if !defined(ROBLOX_PATCHER_PROBE_ONLY)
    using namespace RobloxStudioPatcher;

    LogF(L"[dllmain] SafeInit pid=%lu\n", GetCurrentProcessId());

    // Phase 1: surgical name patch - safe in all launch modes.
    __try { PatchPlayerNameCallSite(); }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in PatchPlayerNameCallSite\n"); }

    // Phase 2: ws2_32 UDP relay (the magic-packet identity/appearance channel).
    // Must run on BOTH client and server ends.
    // Guarded independently: relay failure must NOT prevent the Qt hider.
    __try { StartUdpRelay(); }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartUdpRelay - continuing\n"); }

    // Phase 3: server-only script-start hook.
    // Hook VA 0x0101E380 on StartServer launches only. Blocks Lua execution
    // until AllowScriptStart() / the named event fires.
    // NOT installed in editor or client modes.
    __try
    {
        if (IsStartServerTask())
        {
            LogF(L"[dllmain] StartServer: installing script-start hook\n");
            InstallScriptStartHook();
            // Put the UserId/AccountAge getter detours in place now so they're
            // ready before the joining player reaches createServerPlayer; the
            // relay fills the values when the magic packet arrives.
            InstallIdentityPatch();
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in InstallScriptStartHook\n"); }

    // Phase 3b: server-only UDP listen-port remap. Swaps which UDP listener
    // owns -port: RbxTransport/DummyServer takes -port (forwardable), RakNet
    // moves to -port+1. See port_remap.h.
    __try
    {
        if (IsStartServerTask())
            StartPortRemap();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartPortRemap\n"); }

    // Phase 4: client-only LocalRcc join-IP patch.
    // Redirects the hardcoded "127.0.0.1" the client connects to -> -server <ip>.
    // (The port is set separately via the DebugLocalRccServerConnectionPort FInt
    // the webserver injects into PCStudioApp.)
    __try
    {
        if (IsStartClientTask())
            PatchLocalRccIp();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in PatchLocalRccIp\n"); }

    // Phase 5: Qt chrome hider - client only.
    // Running this inside the server/editor would hide the developer tools.
    __try
    {
        if (!IsStartClientTask())
        {
            LogF(L"[dllmain] not a StartClient launch - "
                L"skipping Qt hider (relay + username server already active)\n");
            return;
        }

        LogF(L"[dllmain] StartClient launch confirmed - activating Qt hider\n");
        StartQtHider();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in Qt hider phase\n"); }
#else
    OutputDebugStringW(L"[RobloxStudioPatcher] PROBE_ONLY build, no-op\n");
#endif
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/)
{
    using namespace RobloxStudioPatcher;
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        g_hSelf = hModule;
        DisableThreadLibraryCalls(hModule);
        LOG(L"[RobloxStudioPatcher] attached to pid %lu\n", GetCurrentProcessId());
        SafeInit();
        break;
    }
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}