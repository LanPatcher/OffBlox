// output_dedupe.cpp - see output_dedupe.h.
//
// Drops already-seen output/error LINES while a game is running, so repeated
// script errors stop hammering the LogService / output model every frame
// (the real per-frame cost under spam; the hidden window itself doesn't paint).
//
// THE CHOKE POINT (found statically in OffBlox-82ca190a.exe, md5 e3dc264b...):
//
//   0x32ccb30  the LogService message-post that fires MessageOut. It is the
//   single function every output line funnels through:
//       * engine StandardOut:   0x32cc790 -> 0x32ccb30
//       * variadic printf:       0x32cce50 -> 0x32cc790 -> 0x32ccb30
//       * script-error reporter: 0x34dc777 -> 0x32ccb30   (this path BYPASSES
//                                StandardOut, which is why hooking 0x32cc790
//                                alone missed the script-error spam)
//   Signature: post(ecx = MessageType, rdx = std::string* msg, r8 = ctx,
//                   r9d = flags). Confirmed: it reads rdx as an MSVC
//                   std::string (cmp [rbx+0x18],0x10; mov r8,[rbx]).
//
//   Dropping a duplicate here returns BEFORE MessageOut fires, so the repeat
//   is neither displayed nor relayed over the network to the client.
//
// MSVC std::string layout: data/ptr@+0, size@+0x10, capacity@+0x18; the data
// lives in the inline buffer (+0) when capacity < 16, else at the heap ptr(+0).
//
// A first-N diagnostic dump (file-only, so it can't re-enter the hooked
// function) records the distinct lines actually carried, for verification.
//
// NOTE: RVA is for the 82ca build (the unpacked exe you run). The packed
// retail OffBlox.exe (94MB) can't be analyzed; re-capture for other builds.

#include "output_dedupe.h"
#include "patcher.h"
#include "iat_hook.h"
#include "server_console.h"

#include <string>
#include <unordered_set>
#include <mutex>
#include <cstdint>

namespace RobloxStudioPatcher
{
    extern bool IsStartClientTask_Pub();
    extern bool IsStartServerTask_Pub();

    // ---- CONFIGURE (per build) ------------------------------------------
    // StandardOut::printMessage (std::string message at rdx). STABLE target.
    // NOTE: the deeper universal post 0x32ccb30 (which this funnels into) would
    // also catch the ScriptContext-error path, but inline-hooking it CRASHES
    // (it is called from 16 sites incl. early/special contexts). 0x32cc790 is
    // safe and catches engine messages + Stack Begin/End; the script-error
    // message+location pair is emitted via 0x34dc777->0x32ccb30 directly and is
    // NOT covered here (see chat: needs a targeted reporter hook instead).
    static const uintptr_t kSinkB30 = 0x0032cc790;
    // ----------------------------------------------------------------------

    // Fixed 5-arg passthrough signature (the target is not variadic).
    using FnSink = void (*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
    static FnSink g_origB30 = nullptr;

    static bool                            g_suppress = false;
    static bool                            g_serverMode = false;
    static std::mutex                      g_seenMtx;
    static std::unordered_set<std::string> g_seen;
    static size_t                          g_diagCount = 0;   // first-N diag cap

    // Re-entrancy guard: the post fires LogService signals whose handlers can
    // log again on this thread; g_seenMtx is non-recursive.
    static thread_local bool t_inHook = false;

    // Read the MSVC std::string at `arg`. Bounded + SEH-guarded so a bad
    // pointer or unexpected layout just passes the message through.
    static bool CopyStdString(uintptr_t arg, std::string& out)
    {
        auto* s = reinterpret_cast<const unsigned char*>(arg);
        if (!s) return false;
        __try
        {
            size_t size = *reinterpret_cast<const size_t*>(s + 0x10);
            size_t cap  = *reinterpret_cast<const size_t*>(s + 0x18);
            if (size == 0 || size > 16384 || cap < 15) return false;
            const char* data = (cap >= 16)
                ? *reinterpret_cast<const char* const*>(s)
                : reinterpret_cast<const char*>(s);
            if (!data) return false;
            out.assign(data, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    // Collapse digit runs to a single '#' so the same error with a changing
    // number (line, id, "(x4)") dedupes to one key.
    static std::string NormalizeKey(const std::string& m)
    {
        std::string k; k.reserve(m.size());
        bool prevDigit = false;
        for (char c : m)
        {
            bool d = (c >= '0' && c <= '9');
            if (d) { if (!prevDigit) k.push_back('#'); }
            else   { k.push_back(c); }
            prevDigit = d;
        }
        return k;
    }

    // File-only log line (does NOT call RobloxPrint, so it can't re-enter the
    // hooked post). Used for the first-N diagnostic dump.
    static void DiagLine(const char* tag, const std::string& msg)
    {
        std::wstring path = GetDllDirectory() + L"RobloxStudioPatcher.log";
        HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return;
        std::string line = "[output_dedupe] ";
        line += tag; line += ": "; line += msg; line += "\n";
        DWORD w = 0;
        WriteFile(h, line.data(), (DWORD)line.size(), &w, nullptr);
        CloseHandle(h);
    }

    // Returns true if this line has already been shown (=> drop it).
    static bool SeenBefore(const std::string& m, const char* tag)
    {
        std::string key = NormalizeKey(m);
        bool firstTime;
        bool doDiag = false;
        {
            std::lock_guard<std::mutex> lk(g_seenMtx);
            firstTime = g_seen.insert(key).second;
            if (g_seen.size() > 20000) g_seen.clear();
            if (firstTime && g_diagCount < 80) { ++g_diagCount; doDiag = true; }
        }
        if (doDiag) DiagLine(tag, m);   // outside the lock
        return !firstTime;
    }

    static void SetColorForMessageType(HANDLE hCon, uintptr_t msgType)
    {
        WORD attr;
        switch (msgType)
        {
        case 0:  attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; break; // OUTPUT  -> white
        case 1:  attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; break; // INFO    -> white
        case 2:  attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break; // WARNING -> yellow
        case 3:  attr = FOREGROUND_RED | FOREGROUND_INTENSITY; break;                // ERROR   -> red
        default: attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; break;
        }
        SetConsoleTextAttribute(hCon, attr);
    }

    // Lines that must NEVER be de-duplicated, because the caller needs to see
    // EVERY occurrence (e.g. "Disconnect from <ip>|<port>" is used to detect a
    // player leaving - digit-normalisation would otherwise collapse different
    // peers into one key and only the first would ever show).
    static bool NeverSuppress(const std::string& m)
    {
        return m.find("Disconnect") != std::string::npos;
    }

    // Server-only: lines that are pure noise on a headless null-device server
    // and should be dropped outright (not just deduped). Forcing NoGraphics
    // makes the engine emit a "graphics card not compatible / minimum system
    // requirements" warning every boot - meaningless when there is no GPU in
    // use by design.
    static bool ServerSuppressLine(const std::string& m)
    {
        if (!g_serverMode) return false;
        return m.find("system requirements")  != std::string::npos
            || m.find("system-requirements")  != std::string::npos
            || m.find("not compatible with Roblox") != std::string::npos
            || m.find("graphics card is not compatible") != std::string::npos
            // Audio is intentionally disabled on the server; FMOD then has a
            // null system object and the engine polls it, spamming
            // "FMOD object: 0x0 ... fmodOperation: getVersion ...". Pure noise.
            || m.find("fmodOperation") != std::string::npos
            || m.find("FMOD object:")  != std::string::npos
            // Editor plugins are blocked on the server (plugin_disable); the
            // loader's "Failed to load plugin sabuiltin_..." lines are expected
            // noise, as is anything else mentioning the editor plugin token.
            || m.find("sabuiltin") != std::string::npos;
    }

    static void HookB30(uintptr_t a1, uintptr_t a2, uintptr_t a3,
        uintptr_t a4, uintptr_t a5)
    {
        // a1 = MessageType (0=Output/print, 1=Info, 2=Warning, 3=Error). Only
        // de-dup the non-print classes; ordinary print() output always passes
        // through so the user's own logging is never suppressed.
        // Server-only outright drop of known noise (any message type), checked
        // before the type gate so even Output-class emissions are caught.
        if (g_suppress && !t_inHook && g_serverMode)
        {
            t_inHook = true;
            std::string sm;
            bool drop = CopyStdString(a2, sm) && ServerSuppressLine(sm);
            t_inHook = false;
            if (drop) return;
        }

        if (g_suppress && !t_inHook && (unsigned)(a1 & 0xffffffffu) != 0)
        {
            t_inHook = true;
            std::string m;
            if (CopyStdString(a2, m) && !m.empty() && !NeverSuppress(m) && SeenBefore(m, "sinkB30"))
            {
                t_inHook = false;
                return;
            }
            if (g_origB30)
            {
                HANDLE hCon = ServerConsoleActive() ? GetStdHandle(STD_OUTPUT_HANDLE) : nullptr;
                if (hCon) SetColorForMessageType(hCon, a1);
                g_origB30(a1, a2, a3, a4, a5);
                if (hCon) SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            }
            t_inHook = false;
            return;
        }
        if (g_origB30) g_origB30(a1, a2, a3, a4, a5);
    }

    void StartOutputDedupe()
    {
        // Only suppress in a running game; the editor keeps full output.
        g_suppress = IsStartClientTask_Pub() || IsStartServerTask_Pub();
        g_serverMode = IsStartServerTask_Pub();
        if (!g_suppress)
        {
            LogF(L"[output_dedupe] editor mode - dedupe left off\n");
            return;
        }

        HMODULE host = GetModuleHandleW(nullptr);
        uintptr_t va = reinterpret_cast<uintptr_t>(host) + kSinkB30;
        void* tramp = nullptr;
        if (InlineHookVA(va, reinterpret_cast<void*>(&HookB30), &tramp) && tramp)
        {
            g_origB30 = reinterpret_cast<FnSink>(tramp);
            LogF(L"[output_dedupe] hooked StandardOut::printMessage @ %p (rva=0x%llx)\n",
                 (void*)va, (unsigned long long)kSinkB30);
        }
        else
        {
            LogF(L"[output_dedupe] FAILED to hook StandardOut @ %p\n", (void*)va);
        }
    }
}
