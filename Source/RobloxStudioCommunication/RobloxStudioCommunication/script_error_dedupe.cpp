// script_error_dedupe.cpp - see script_error_dedupe.h.
//
// Dedups repeated output that flows through the universal LogService post
// 0x32ccb30. Inline-hooking 0x32ccb30 crashes (it takes 7 args - rcx,rdx,r8,r9
// + 3 stack - and is called from 16 sites incl. early startup). Instead we
// redirect every DIRECT call site (E8 rel32 -> 0x32ccb30) to one shared stub:
//
//   caller --call--> stub:
//       save rcx/rdx/r8/r9 ; DecideDrop(rdx) ; restore
//       if drop -> ret              (skip the post; return to caller)
//       else    -> jmp 0x32ccb30    (tail-call: full stack/args intact)
//
// The tail-jmp means NO argument re-marshalling, so the 7-arg layout is
// preserved exactly - this is what makes it crash-free where the inline hook
// (which only forwarded 5 args) failed. Each call site is a clean 4-byte rel32
// rewrite; 0x32ccb30 itself is never modified.
//
// This catches engine messages, script-error lines, and the relayed runtime
// error - on whichever process emits them (the DLL runs in both).
//
// RVAs are for the 82ca build (the unpacked exe you run, md5 e3dc264b...).

#include "script_error_dedupe.h"
#include "patcher.h"
#include "server_console.h"
#include "udp_relay.h"

#include <string>
#include <unordered_set>
#include <mutex>
#include <cstdint>
#include <cstring>

namespace RobloxStudioPatcher
{
    extern bool IsStartClientTask_Pub();
    extern bool IsStartServerTask_Pub();

    // ---- CONFIGURE (per build) ------------------------------------------
    static const uintptr_t kPostRva = 0x0032ccb30;   // LogService message-post

    // Every direct `call 0x32ccb30` site found statically in the 82ca build.
    static const uintptr_t kCallSites[] = {
        0x00aa8055, 0x00daa379, 0x01210873, 0x012109ba, 0x01210afc,
        0x0121446f, 0x01214b33, 0x01214c82, 0x01214dcf, 0x01292c55,
        0x032cc82b, 0x034dc777, 0x034ddbe3, 0x034ddccb, 0x0359b57f,
        0x040a70e3,
    };
    // ----------------------------------------------------------------------

    static bool                            g_active = false;
    static std::mutex                      g_mtx;
    static std::unordered_set<std::string> g_seen;
    static size_t                          g_diagCount = 0;

    static bool ReadStdString(const void* arg, std::string& out)
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

    static std::string NormalizeKey(const std::string& m)
    {
        std::string k; k.reserve(m.size());
        bool pd = false;
        for (char c : m)
        {
            bool d = (c >= '0' && c <= '9');
            if (d) { if (!pd) k.push_back('#'); }
            else   { k.push_back(c); }
            pd = d;
        }
        return k;
    }

    static void DiagLine(const std::string& msg)
    {
        std::wstring path = GetDllDirectory() + L"RobloxStudioPatcher.log";
        HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return;
        std::string line = "[se_dedupe] saw: " + msg + "\n";
        DWORD w = 0;
        WriteFile(h, line.data(), (DWORD)line.size(), &w, nullptr);
        CloseHandle(h);
    }

    // Lines that must NEVER be de-duplicated - the caller needs every
    // occurrence (e.g. "Disconnect from <ip>|<port>" is used to detect a player
    // leaving; digit-normalisation would collapse different peers into one key).
    static bool NeverSuppress(const std::string& m)
    {
        return m.find("Disconnect") != std::string::npos;
    }

    // Called by the stub with rcx = MessageType, rdx = std::string* msg.
    // Returns 1 = DROP (already seen), 0 = keep.
    //
    // Roblox MessageType: 0 = Output (print), 1 = Info, 2 = Warning, 3 = Error.
    // ONLY the non-print classes are de-duplicated. Ordinary print() output
    // (MessageOutput == 0) ALWAYS passes through, so a script's own logging is
    // never eaten by the error suppressor. Only locks briefly (no post happens
    // under the lock), so it is safe under re-entrancy.
    static int DecideDrop(uintptr_t msgType, const void* msgStr)
    {
        unsigned t = (unsigned)(msgType & 0xffffffffu);
        std::string m;
        bool readable = ReadStdString(msgStr, m) && !m.empty();

        // Feed player-leave signals to the relay so it frees the leaving
        // player's name (clone-identity fix). Done for EVERY occurrence, before
        // any dedup/early-return, so it never gets swallowed. If it was the
        // internal PlayerRemoving tag, suppress the line entirely.
        if (readable && (m.find("OffBloxPlayerLeft:") != std::string::npos ||
                         m.find("Disconnect") != std::string::npos ||
                         m.find("is being removed") != std::string::npos))
        {
            if (OnServerOutputLine(m.c_str()))
                return 1;   // internal leave tag -> drop (don't display/mirror)
        }

        if (t == 0)   // MessageOutput / print -> never suppressed
        {
            if (readable) ServerConsoleLog(m);   // mirror every print to console
            return 0;
        }
        if (!readable) return 0;
        if (NeverSuppress(m)) { ServerConsoleLog(m); return 0; }   // every occurrence

        std::string key = NormalizeKey(m);
        bool first; bool diag = false;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            first = g_seen.insert(key).second;
            if (g_seen.size() > 20000) g_seen.clear();
            if (first && g_diagCount < 80) { ++g_diagCount; diag = true; }
        }
        if (diag) DiagLine("type=" + std::to_string(t) + " " + m);
        // Mirror the first occurrence of each error-class line to the console.
        if (first) ServerConsoleLog(m);
        return first ? 0 : 1;
    }

    static void* AllocNear(uintptr_t anchor, size_t size)
    {
        SYSTEM_INFO si; GetSystemInfo(&si);
        uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
        const uintptr_t span = 0x70000000ULL;   // ~1.75GB, safely under 2GB
        for (uintptr_t off = gran; off < span; off += gran)
        {
            if (anchor > off)
            {
                uintptr_t lo = (anchor - off) & ~(gran - 1);
                void* p = VirtualAlloc(reinterpret_cast<void*>(lo), size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (p) return p;
            }
            uintptr_t hi = (anchor + off) & ~(gran - 1);
            void* p2 = VirtualAlloc(reinterpret_cast<void*>(hi), size,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p2) return p2;
        }
        return nullptr;
    }

    // Build the shared redirect stub. On entry the stack is exactly as
    // 0x32ccb30 would see it (retaddr on top, args in regs + stack).
    static BYTE* BuildStub(uintptr_t anchor, void* decideFn, void* realPost)
    {
        BYTE* s = reinterpret_cast<BYTE*>(AllocNear(anchor, 64));
        if (!s) return nullptr;
        int i = 0;
        s[i++] = 0x51;                                  // push rcx
        s[i++] = 0x52;                                  // push rdx
        s[i++] = 0x41; s[i++] = 0x50;                   // push r8
        s[i++] = 0x41; s[i++] = 0x51;                   // push r9
        s[i++] = 0x48; s[i++] = 0x83; s[i++] = 0xEC; s[i++] = 0x28;   // sub rsp,0x28
        // rcx already = MessageType (arg1), rdx already = std::string* msg
        // (arg2) - exactly DecideDrop(type, msg). Do NOT clobber them.
        s[i++] = 0x48; s[i++] = 0xB8;                   // mov rax, imm64 (DecideDrop)
        std::memcpy(s + i, &decideFn, 8); i += 8;
        s[i++] = 0xFF; s[i++] = 0xD0;                   // call rax
        s[i++] = 0x48; s[i++] = 0x83; s[i++] = 0xC4; s[i++] = 0x28;   // add rsp,0x28
        s[i++] = 0x41; s[i++] = 0x59;                   // pop r9
        s[i++] = 0x41; s[i++] = 0x58;                   // pop r8
        s[i++] = 0x5A;                                  // pop rdx
        s[i++] = 0x59;                                  // pop rcx
        s[i++] = 0x84; s[i++] = 0xC0;                   // test al,al
        s[i++] = 0x75; s[i++] = 0x0C;                   // jnz .drop (+12)
        s[i++] = 0x48; s[i++] = 0xB8;                   // mov rax, imm64 (realPost)
        std::memcpy(s + i, &realPost, 8); i += 8;
        s[i++] = 0xFF; s[i++] = 0xE0;                   // jmp rax  (tail-call, stack intact)
        // .drop:
        s[i++] = 0x31; s[i++] = 0xC0;                   // xor eax,eax
        s[i++] = 0xC3;                                  // ret
        FlushInstructionCache(GetCurrentProcess(), s, i);
        return s;
    }

    void StartScriptErrorDedupe()
    {
        g_active = IsStartClientTask_Pub() || IsStartServerTask_Pub();
        if (!g_active)
        {
            LogF(L"[se_dedupe] editor mode - off\n");
            return;
        }

        HMODULE host = GetModuleHandleW(nullptr);
        uintptr_t base = reinterpret_cast<uintptr_t>(host);
        void* realPost = reinterpret_cast<void*>(base + kPostRva);

        // One shared stub near the post (all call sites are within ~15MB of it,
        // well inside rel32 range).
        BYTE* stub = BuildStub(base + kPostRva, reinterpret_cast<void*>(&DecideDrop), realPost);
        if (!stub)
        {
            LogF(L"[se_dedupe] BuildStub/AllocNear failed - aborting\n");
            return;
        }

        int patched = 0;
        const int n = (int)(sizeof(kCallSites) / sizeof(kCallSites[0]));
        for (int k = 0; k < n; ++k)
        {
            uintptr_t site = base + kCallSites[k];
            BYTE* p = reinterpret_cast<BYTE*>(site);
            if (p[0] != 0xE8) continue;                          // not a direct call
            int32_t rel = *reinterpret_cast<int32_t*>(p + 1);
            if (site + 5 + rel != base + kPostRva) continue;     // not our target
            int64_t newRel = (int64_t)reinterpret_cast<uintptr_t>(stub) - (int64_t)(site + 5);
            if (newRel < INT32_MIN || newRel > INT32_MAX) continue;
            DWORD oldP = 0;
            if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &oldP)) continue;
            *reinterpret_cast<int32_t*>(p + 1) = (int32_t)newRel;
            VirtualProtect(p, 5, oldP, &oldP);
            FlushInstructionCache(GetCurrentProcess(), p, 5);
            ++patched;
        }

        LogF(L"[se_dedupe] redirected %d/%d call sites -> stub %p (real post %p)\n",
             patched, n, (void*)stub, realPost);
    }
}
