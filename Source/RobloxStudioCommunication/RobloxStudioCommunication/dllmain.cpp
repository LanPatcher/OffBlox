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
#include "auto_recovery.h"
#include "output_dedupe.h"
#include "script_error_dedupe.h"
#include "server_console.h"
#include "render_disable.h"
#include "player_leave.h"
#include "player_join.h"
#include "render_nulldevice.h"
#include "headless_force.h"
#include "dialog_suppress.h"
#include "audio_disable.h"
#include "audio_silence.h"
#include "loadstring_console.h"
#include "plugin_disable.h"
#include "anr_disable.h"
#include "devconsole_lock.h"
#include "webview_skip.h"

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

// Force the engine's FilteringEnabled getter to return false. In this build the
// getter at base+0x6FF1D0 is hardcoded `mov al,1 ; ret` (B0 01 C3) - i.e. FE is
// ALWAYS on regardless of the Workspace.FilteringEnabled property (which is why
// setting the property to false does nothing). Every reader - including the ~120
// server replication-filter call sites - goes through this one getter, so
// flipping the immediate 1 -> 0 makes the whole engine treat FilteringEnabled as
// OFF: client (executor) changes replicate to the server and back out again,
// i.e. full-trust / classic "experimental mode". Applied on client AND server so
// the client sends and the server accepts.
static void ForceFilteringDisabled()
{
    using namespace RobloxStudioPatcher;   // LogF lives in this namespace
    const uintptr_t kGetterRva = 0x6FF1D0;
    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!base) return;
    unsigned char* p = reinterpret_cast<unsigned char*>(base + kGetterRva);
    if (!(p[0] == 0xB0 && p[1] == 0x01 && p[2] == 0xC3))
    {
        LogF(L"[dllmain] FilteringEnabled getter mismatch (%02X %02X %02X) - not patched\n",
             p[0], p[1], p[2]);
        return;
    }
    DWORD oldp = 0;
    if (VirtualProtect(p, 3, PAGE_EXECUTE_READWRITE, &oldp))
    {
        p[1] = 0x00;   // mov al,0 ; ret  -> getter now returns false everywhere
        VirtualProtect(p, 3, oldp, &oldp);
        FlushInstructionCache(GetCurrentProcess(), p, 3);
        LogF(L"[dllmain] FilteringEnabled forced OFF (getter -> return false)\n");
    }
}

// Make the SERVER ACCEPT client-originated replication. Flipping the FE getter
// alone is not enough: the enforced ServerReplicator gates every incoming client
// item behind four virtual RECEIVE filters that still reject non-whitelisted
// changes and, via the propSync rejection counter, can KICK the client. The four
// were resolved from the 2022L PDB (RobloxStudioBeta.pdb) and located in this
// binary via the "remotePlayer already exists" / "PlayerPropChange" strings and the
// ServerReplicator vtable (@ .rdata 0x8CB0098):
//   isLegalReceiveInstance        rva 0x2866A20  -> mov al,1 ; ret   (accept new instances)
//   isLegalReceiveProperty        rva 0x2866E10  -> mov al,1 ; ret   (accept property writes)
//   filterReceivedChangedProperty rva 0x286F340  -> xor eax,eax ; ret (FilterResult Accept=0)
//   filterReceivedParent          rva 0x286B670  -> xor eax,eax ; ret (FilterResult Accept=0)
// Returning accept at ENTRY also short-circuits propSync.onReceivedPropertyChanged,
// so the anti-exploit rejection counter never trips (no kick). This is orthogonal
// to the rbxsig / cookie / anti-impersonation systems, which are left untouched.
// Server-only in effect (the client uses ClientReplicator vtables); applied at
// VM-lock alongside the getter patch.
namespace RobloxStudioPatcher { void ServerConsoleLog(const std::string& line); }

static volatile long g_acceptDone = 0;   // apply-once guard (VM-lock + timer both call)

static void AcceptClientReplication()
{
    using namespace RobloxStudioPatcher;
    if (InterlockedCompareExchange(&g_acceptDone, 1, 0) != 0) return;   // already applied
    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!base) { InterlockedExchange(&g_acceptDone, 0); return; }
    ServerConsoleLog("[offblox] AcceptClientReplication running (server accept patches)");
    struct P { uintptr_t rva; unsigned char stub[3]; const wchar_t* name; };
    const P ps[4] = {
        { 0x2866A20, { 0xB0, 0x01, 0xC3 }, L"isLegalReceiveInstance" },        // return true
        { 0x2866E10, { 0xB0, 0x01, 0xC3 }, L"isLegalReceiveProperty" },        // return true
        { 0x286F340, { 0x31, 0xC0, 0xC3 }, L"filterReceivedChangedProperty" }, // return Accept(0)
        { 0x286B670, { 0x31, 0xC0, 0xC3 }, L"filterReceivedParent" },          // return Accept(0)
    };
    for (const P& e : ps)
    {
        unsigned char* p = reinterpret_cast<unsigned char*>(base + e.rva);
        // each entry begins `mov [rsp+8],rbx` (48 89 5C) or `mov [rsp+0x10],rbp` (48 89 6C)
        if (!(p[0] == 0x48 && p[1] == 0x89 && (p[2] == 0x5C || p[2] == 0x6C)))
        {
            LogF(L"[dllmain] %ls entry mismatch (%02X %02X %02X) - skipped\n", e.name, p[0], p[1], p[2]);
            continue;
        }
        DWORD oldp = 0;
        if (VirtualProtect(p, 3, PAGE_EXECUTE_READWRITE, &oldp))
        {
            p[0] = e.stub[0]; p[1] = e.stub[1]; p[2] = e.stub[2];
            VirtualProtect(p, 3, oldp, &oldp);
            FlushInstructionCache(GetCurrentProcess(), p, 3);
            LogF(L"[dllmain] server accepts client replication: %ls -> accept\n", e.name);
        }
    }

    // SCHEMA new-instance path: readInstanceNew (0x28D32F0) resolves the client's
    // class network id to a ClassInfo, then runs its OWN strictFilter class check
    // ([rep+0x2E50] -> call 0x14285C770) and, on Reject, throws the misleadingly-named
    // "invalid class network type for new class item" (0x28D401B) - THIS is what the
    // server logs when a client inserts a Part. It is a separate gate from
    // isLegalReceiveInstance above (the modern Mega/schema deserializer). NOP the
    // reject branch `je 0x28D401B` @ 0x28D36D7 (0F 84 3E 09 00 00) so control falls
    // through to the accept path (the `jmp 0x28D3714` at 0x28D36DD) - the server then
    // accepts client-created instances of any class.
    // readInstanceNew has TWO strictFilter class-check paths (gated by a global flag
    // @ 0x28D36B2); each ends `cmp eax,1; je <type-error>` (Reject -> throw). NOP BOTH
    // reject branches so control falls through to the accept path (0x28D3714):
    //   je 0x28D401B @ 0x28D36D7  (0F 84 3E 09 00 00)
    //   je 0x28D4092 @ 0x28D370E  (0F 84 7E 09 00 00)
    {
        const uintptr_t branches[2] = { 0x28D36D7, 0x28D370E };
        for (uintptr_t rva : branches)
        {
            unsigned char* p = reinterpret_cast<unsigned char*>(base + rva);
            if (p[0] == 0x0F && p[1] == 0x84)
            {
                DWORD oldp2 = 0;
                if (VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &oldp2))
                {
                    std::memset(p, 0x90, 6);
                    VirtualProtect(p, 6, oldp2, &oldp2);
                    FlushInstructionCache(GetCurrentProcess(), p, 6);
                    LogF(L"[dllmain] readInstanceNew class-filter reject @%p -> accept\n", (void*)rva);
                    char cb[96]; _snprintf_s(cb, sizeof(cb), _TRUNCATE, "[offblox] readInstanceNew class-filter @0x%llX -> accept", (unsigned long long)rva);
                    ServerConsoleLog(cb);
                }
            }
            else
            {
                LogF(L"[dllmain] readInstanceNew reject-branch @%p mismatch (%02X %02X)\n", (void*)rva, p[0], p[1]);
                char cb[112]; _snprintf_s(cb, sizeof(cb), _TRUNCATE, "[offblox] readInstanceNew @0x%llX MISMATCH %02X %02X (not patched)", (unsigned long long)rva, p[0], p[1]);
                ServerConsoleLog(cb);
            }
        }
    }
}

// Apply the accept patches on a timer, INDEPENDENT of the StartServer VM-lock
// trigger. That trigger (loadstring_console) only fires in headless StartServer
// tasks; Studio Team-Test / Play-server processes host the server DataModel but
// never hit it, so the patches were never applied there. These are byte patches on
// the replication receive path, safe to apply once the engine module is mapped
// (which it is by DLL-inject time). Idempotent via g_acceptDone. Retries a few
// times in case the module maps late.
static DWORD WINAPI AcceptReplThread(LPVOID)
{
    for (int i = 0; i < 8 && !g_acceptDone; ++i)
    {
        Sleep(3000);
        __try { AcceptClientReplication(); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    return 0;
}

// Public wrapper so the server console hook (separate TU) can trigger the patches
// once the DataModel is live. Idempotent (re-verifies the bytes).
//
// We no longer flip the FE getter here - it is redundant and riskier:
//   * AcceptClientReplication patches the four receive-gates directly, so the
//     server accepts client items regardless of the getter. The getter flip is no
//     longer needed for acceptance.
//   * getter=ON is the vanilla state (safer; getter=OFF previously destabilised
//     server startup, which is why it was moved to VM-lock).
//   * (Verified) the OffBlox CLIENT builds its whitelist filter UNCONDITIONALLY and
//     never resets it from the server join-bit, so the getter value does not change
//     client filtering either way. The client's clean join depends only on the
//     client DLL NOT nulling its own filter (born-null / runtime ForceClientFeOff -
//     all now disabled in OffBloxExec). If the client still floods at join, it is
//     running a stale OffBloxExec build.
// If a global "server reports FE off" is ever needed again, call
// ForceFilteringDisabled() explicitly; it is intentionally omitted here.
namespace RobloxStudioPatcher {
    // Baseline = clean join. Blanket-accepting arbitrary client replication at the
    // four receive-gates crashed the session, and flipping the FE getter tells
    // clients "FE off" (side effects). So the VM-lock hook now does NOTHING by
    // default -> vanilla FE server -> the client (whitelist intact) joins cleanly.
    // Re-enable acceptance deliberately (and, when we do, gated/toggleable) once a
    // clean join is confirmed:
    //   AcceptClientReplication();    // <- server accepts client items (was crashing)
    //   ForceFilteringDisabled();     // <- server reports FE off (join-bit side effect)
    // Now that the client joins clean and un-hooked (no flood, no send corruption),
    // re-enable ONLY the server-side accept. The client keeps its whitelist, so it
    // sends its legitimate whitelisted items (BasePart is whitelisted) - the server
    // now accepts+applies them instead of rejecting/kicking. The FE getter is left
    // ON (its flip is unrelated and telling clients "FE off" has side effects).
    // If this destabilises the session, revert to the no-op baseline below.
    void ForceFilteringDisabled_Pub() { AcceptClientReplication(); }
    void AcceptClientReplication_Pub() { AcceptClientReplication(); }
    void ForceFilteringDisabledGetter_Pub() { ForceFilteringDisabled(); }
}

static void SafeInit()
{
#if !defined(ROBLOX_PATCHER_PROBE_ONLY)
    using namespace RobloxStudioPatcher;

    LogF(L"[dllmain] SafeInit pid=%lu\n", GetCurrentProcessId());

    // Phase 0: client->server replication accept patches, on a timer, ALL launch
    // modes. The StartServer VM-lock trigger doesn't fire in Studio Team-Test/Play
    // server processes, so apply here too (idempotent; safe byte patches).
    { HANDLE t = CreateThread(nullptr, 0, AcceptReplThread, nullptr, 0, nullptr);
      if (t) CloseHandle(t); }

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

    // Phase 2b: WebView2 login skip - ALL launch modes (the login/auth happens
    // on the editor process). Installs IAT hooks on WebView2Loader so that, on
    // machines with no working WebView2 runtime (e.g. Wine), Studio's login is
    // driven straight to the OAuth redirect without ever opening the WebView2
    // window. Pass-through (no behaviour change) when a real runtime exists, so
    // it is safe on Windows. Must be installed before login fires (~1.4s in).
    __try { StartWebViewLoginSkip(); }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartWebViewLoginSkip - continuing\n"); }

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

    // Phase 4d: Auto-Recovery suppressor - ALL launch modes (client, server,
    // editor). The Auto-Recovery modal (AutoSaveDialog) grabs input on any
    // launch; clearing the AutoSaves folder + dismissing the dialog is safe
    // everywhere (it only ever rejects an unwanted recovery prompt, and does
    // not touch developer tools).
    __try
    {
        StartAutoRecoveryKiller();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartAutoRecoveryKiller\n"); }

    // Phase 4e: output dedupe - drop already-seen output/error strings in a
    // running game so error spam stops hammering the output model. No-op until
    // kSinkRva is set in output_dedupe.cpp; gates itself to non-editor modes.
    __try
    {
        StartOutputDedupe();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartOutputDedupe\n"); }

    // Phase 4f: script-error dedupe - redirects the script-error reporter's
    // single emit call site (0x34dc777 -> 0x32ccb30) through a dedup wrapper so
    // repeated script errors (which bypass StandardOut) stop spamming. Surgical
    // (one call site), so it avoids the crash from inline-hooking 0x32ccb30.
    __try
    {
        StartScriptErrorDedupe();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartScriptErrorDedupe\n"); }

    // Phase 4g: server console - StartServer launches only. Allocates a console
    // window, hides the 3D game window, and mirrors the deduped output + player
    // joins there. No-op on client/editor (gates on -task StartServer inside).
    __try
    {
        StartServerConsole();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartServerConsole\n"); }

    // Phase 4g2: console script execution - StartServer only. Inline-hooks the
    // engine's loadstring; on the first script compile it bootstraps an in-engine
    // Heartbeat driver that runs lines typed into the server console, all on the
    // Lua thread. Server-gated; all VM access is SEH-guarded inside.
    __try
    {
        InstallLoadstringConsoleHook();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in InstallLoadstringConsoleHook\n"); }

    // Phase 4h: engine-level 3D render disable - StartServer only. NOPs the
    // RenderJob's render-dispatch call so the server stops GPU/scene work
    // (physics/scripts/replication keep running). Server-gated inside.
    __try
    {
        StartRenderDisable();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartRenderDisable\n"); }

    // Phase 4i: player-leave detection - StartServer only. Hooks the engine's
    // player-removal so a leaving player's relay name is freed (clone-identity
    // fix). Server-gated inside; SEH-guarded name read.
    __try
    {
        StartPlayerLeaveHook();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartPlayerLeaveHook\n"); }

    // Phase 4i2: player-JOIN detection - StartServer only. Hooks createServerPlayer
    // so the anti-impersonation name lock is committed only when a player actually
    // joins (not when the join magic is received) - a client that announces but
    // never joins can no longer hold a username. Server-gated inside.
    __try
    {
        StartPlayerJoinHook();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartPlayerJoinHook\n"); }

    // Phase 4j: force NoGraphics null-device - StartServer only, EXPERIMENTAL.
    // Redirects the CreateGraphicsEngine factory call to always request mode 9
    // (NoGraphics). If a null backend exists, the server runs with no D3D11
    // device / shaders / VRAM; if not, it aborts at FailedCreateGameWindow.
    // Server-gated inside. Revert by deleting this block.
    __try
    {
        StartForceNullDevice();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartForceNullDevice\n"); }

    // Phase 4j2: headless instrument + forcing - StartServer only. Inline-hooks
    // kernel32!GetProcAddress / LoadLibraryExW and user32!CreateWindowExW to LOG
    // every display/GPU API the server touches at runtime (so a single headless
    // run reveals the exact remaining display dependency), and - via opt-in
    // sidecar toggles - to force the engine off the GPU/window path. Default is
    // log-only pass-through. Installed before the graphics engine is created so
    // the hooks see its resolution. Server-gated inside.
    __try
    {
        StartHeadlessForce();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartHeadlessForce\n"); }

    // Phase 4k: modal-dialog suppressor - StartServer only. Stops the NoGraphics
    // "incompatible GPU" QMessageBox (and any other modal) from showing/beeping
    // on the headless server. Server-gated inside.
    __try
    {
        StartDialogSuppress();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartDialogSuppress\n"); }

    // Phase 4l: audio disable - StartServer only. Neuters the audio device
    // enumerate/open so no output device, mixer or mic capture is set up on the
    // headless server. Server-gated inside.
    __try
    {
        StartAudioDisable();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartAudioDisable\n"); }

    // Phase 4l2: audio silence (build-independent) - StartServer only. The FMOD
    // NOSOUND patch above relies on a per-build RVA and silently aborts on a
    // build mismatch. This backstop IAT-hooks ole32!CoCreateInstance to fail the
    // WASAPI device enumerator (CLSID_MMDeviceEnumerator) - which every FMOD
    // output backend funnels through under Wine - so the server stays silent
    // regardless of engine version. Server-gated inside.
    __try
    {
        StartAudioSilence();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartAudioSilence\n"); }

    // Phase 4m: editor-plugin disable - StartServer only. Blocks the ~40
    // sabuiltin_*.rbxm Studio editor plugins from loading (fails their file
    // open); builtin_ plugins like SimulationStep are kept. Server-gated inside.
    __try
    {
        StartPluginDisable();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartPluginDisable\n"); }

    // Phase 4n: ANR watchdog disable - StartServer only. Neuters the
    // App-Not-Responding monitor (noise + a thread once 3D render is off).
    // Server-gated inside.
    __try
    {
        StartAnrDisable();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartAnrDisable\n"); }

    // Phase 4o: dev-console lock - client + server (game launches). Re-enables
    // the FastFlag-gated GetCanManageAsync request the Developer Console relies
    // on, so the (host-only) webserver canManage answer applies again and only
    // the host gets the dev console. Pure branch byte-patch; no CoreGui/Lua,
    // no FastFlag config. Editor left untouched (gated inside).
    __try
    {
        StartDevConsoleLock();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    { LogF(L"[dllmain] exception in StartDevConsoleLock\n"); }

    // NOTE: FilteringEnabled OFF is applied LATER, not here. The FE getter is read
    // during DataModel/service init; forcing it false this early (at DLL load,
    // before the DataModel exists) crashes server startup. It's applied once the
    // DataModel is live instead - see the server-VM-lock in loadstring_console.cpp
    // (server) and OffBloxExec's VM lock (client executor).

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

static DWORD WINAPI SafeInitThread(LPVOID) { SafeInit(); return 0; }

// True when the host is running under Wine (ntdll exports wine_get_version).
static bool RunningUnderWine()
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    return nt != nullptr && GetProcAddress(nt, "wine_get_version") != nullptr;
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

        // Wine's loader aborts loader_init with c0000005 if the heavy SafeInit
        // (inline hooks, IAT walks, memory patches) runs synchronously here under
        // the loader lock. So under Wine we spawn SafeInit on a high-priority
        // thread and return immediately - the DLL is already mapped, so the thread
        // runs the instant the loader lock releases (earliest possible without the
        // crash) and, unlike deferring the whole load, it actually produces a log.
        // On Windows we keep the original synchronous path so the early IAT hooks
        // are in place before the host reads its command line.
        if (RunningUnderWine())
        {
            LOG(L"[RobloxStudioPatcher] Wine detected - SafeInit on worker thread\n");
            HANDLE t = CreateThread(nullptr, 0, SafeInitThread, nullptr, 0, nullptr);
            if (t) { SetThreadPriority(t, THREAD_PRIORITY_HIGHEST); CloseHandle(t); }
            else   { SafeInit(); }
        }
        else
        {
            SafeInit();
        }
        break;
    }
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}