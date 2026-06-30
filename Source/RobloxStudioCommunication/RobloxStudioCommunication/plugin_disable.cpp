// plugin_disable.cpp - see plugin_disable.h.
//
// The editor plugin list is manifest-driven and the .rbxm bytes are read from a
// content/hash store, so neither the friendly name nor a folder scan is visible
// at the filesystem layer. We therefore filter at the engine loader.
//
// openOrFetchPlugin (0x19539a0) is called once per plugin with rcx = the plugin
// descriptor object; that object holds the logical name ("sabuiltin_X.rbxm").
// Both call sites (0xef4e16, 0xaace05) ignore the return value, so for an editor
// plugin we just return immediately and it is never loaded.
//
// Rather than hard-code the (build-specific) name offset, the helper scans the
// descriptor for any pointer to a string beginning with "sabuiltin_" - SEH
// guarded, so bad pointers are skipped. "builtin_" (SimulationStep, draggers)
// does not match, so those still load.
//
// We patch the function's first instruction (mov [rsp+0x10],rbx = 48 89 5C 24
// 10) with a jmp to a stub: it calls the helper; skip -> ret; otherwise run the
// saved prologue and continue into the real function.
//
// RVAs are for the 82ca build (the unpacked exe you run, md5 e3dc264b...).

#include "plugin_disable.h"
#include "patcher.h"

#include <cstdint>
#include <cstring>

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();

    // ---- CONFIGURE (per build) ------------------------------------------
    static const uintptr_t kLoaderRva = 0x019539a0;        // openOrFetchPlugin(this)
    static const unsigned char kPrologue[5] =
        { 0x48, 0x89, 0x5C, 0x24, 0x10 };                   // mov [rsp+0x10], rbx
    static const uintptr_t kScanBytes = 0x200;             // descriptor scan window
    // ----------------------------------------------------------------------

    // Does the char* at `p` begin with "sabuiltin_" (case-insensitive)?
    // SEH-guarded; copies the full string into out on match.
    static int StrIsSabuiltin(const char* p, char* out, int outSz)
    {
        if (!p) return 0;
        static const char* needle = "sabuiltin_";
        __try
        {
            for (int i = 0; i < 10; ++i)
            {
                char c = p[i];
                if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                if (c != needle[i]) return 0;
            }
            int n = 0;
            while (n < outSz - 1 && p[n]) { out[n] = p[n]; ++n; }
            out[n] = '\0';
            return 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }

    // First-N diagnostic: dump the readable ASCII strings reachable at one and
    // two pointer levels from `self`, so we can see exactly where the plugin
    // name lives if the scan ever misses. File-logged, bounded.
    static void DiagDump(const unsigned char* base)
    {
        static int dumped = 0;
        if (dumped >= 3) return;
        ++dumped;
        for (uintptr_t off = 0; off <= 0x80; off += sizeof(void*))
        {
            __try
            {
                const char* p = *reinterpret_cast<const char* const*>(base + off);
                if (!p) continue;
                char buf[48]; int n = 0; bool ascii = true;
                for (; n < 40; ++n)
                {
                    char c = p[n];
                    if (c == 0) break;
                    if (c < 0x20 || c > 0x7e) { ascii = false; break; }
                    buf[n] = c;
                }
                if (ascii && n >= 4) { buf[n] = '\0'; LogF(L"[plugin_disable][diag] +0x%llx -> '%hs'\n", (unsigned long long)off, buf); }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    // Returns 1 if the descriptor (or an object one pointer deep) names a
    // "sabuiltin_*" plugin. POD-only, SEH-guarded throughout.
    static int ShouldSkipPlugin(void* self)
    {
        char nameBuf[80]; nameBuf[0] = '\0';
        int skip = 0;
        __try
        {
            if (self)
            {
                auto* base = reinterpret_cast<const unsigned char*>(self);
                DiagDump(base);
                // level 1: a member points straight at the name
                for (uintptr_t off = 0; off <= kScanBytes && !skip; off += sizeof(void*))
                {
                    const char* p = *reinterpret_cast<const char* const*>(base + off);
                    if (StrIsSabuiltin(p, nameBuf, (int)sizeof(nameBuf))) skip = 1;
                }
                // level 2: a member points at a sub-object whose member points at the name
                for (uintptr_t off = 0; off <= 0x100 && !skip; off += sizeof(void*))
                {
                    __try
                    {
                        auto* sub = *reinterpret_cast<const unsigned char* const*>(base + off);
                        if (!sub) continue;
                        for (uintptr_t o2 = 0; o2 <= 0x100 && !skip; o2 += sizeof(void*))
                        {
                            const char* p = *reinterpret_cast<const char* const*>(sub + o2);
                            if (StrIsSabuiltin(p, nameBuf, (int)sizeof(nameBuf))) skip = 1;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { skip = 0; }

        if (skip && nameBuf[0])
            LogF(L"[plugin_disable] skipped editor plugin '%hs'\n", nameBuf);
        return skip;
    }

    static void* AllocNear(uintptr_t anchor, size_t size)
    {
        SYSTEM_INFO si; GetSystemInfo(&si);
        uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
        const uintptr_t span = 0x70000000ULL;
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

    static BYTE* BuildStub(uintptr_t anchor, void* helper, uintptr_t contRva)
    {
        BYTE* s = reinterpret_cast<BYTE*>(AllocNear(anchor, 96));
        if (!s) return nullptr;
        int i = 0;
        s[i++] = 0x51;                                   // push rcx        (save this)
        s[i++] = 0x48; s[i++] = 0x83; s[i++] = 0xEC; s[i++] = 0x20;   // sub rsp,0x20 (shadow)
        s[i++] = 0x48; s[i++] = 0xB8;                    // mov rax, imm64 helper
        std::memcpy(s + i, &helper, 8); i += 8;
        s[i++] = 0xFF; s[i++] = 0xD0;                    // call rax  (ShouldSkipPlugin(rcx))
        s[i++] = 0x48; s[i++] = 0x83; s[i++] = 0xC4; s[i++] = 0x20;   // add rsp,0x20
        s[i++] = 0x59;                                   // pop rcx         (restore this)
        s[i++] = 0x85; s[i++] = 0xC0;                    // test eax,eax
        s[i++] = 0x75; s[i++] = 0x11;                    // jne skip (+17)
        // no match: run saved prologue, continue into real function
        s[i++] = 0x48; s[i++] = 0x89; s[i++] = 0x5C; s[i++] = 0x24; s[i++] = 0x10; // mov [rsp+0x10],rbx
        s[i++] = 0x48; s[i++] = 0xB8;                    // mov rax, imm64 (orig+5)
        uintptr_t cont = contRva;
        std::memcpy(s + i, &cont, 8); i += 8;
        s[i++] = 0xFF; s[i++] = 0xE0;                    // jmp rax
        // skip: return to caller (caller ignores the return value)
        s[i++] = 0x31; s[i++] = 0xC0;                    // xor eax,eax
        s[i++] = 0xC3;                                   // ret
        FlushInstructionCache(GetCurrentProcess(), s, i);
        return s;
    }

    void StartPluginDisable()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        HMODULE host = GetModuleHandleW(nullptr);
        uintptr_t base = reinterpret_cast<uintptr_t>(host);
        BYTE* p = reinterpret_cast<BYTE*>(base + kLoaderRva);

        if (std::memcmp(p, kPrologue, sizeof(kPrologue)) != 0)
        {
            LogF(L"[plugin_disable] loader prologue mismatch @ %p "
                 L"(%02X %02X %02X %02X %02X) - aborting (build mismatch?)\n",
                 (void*)p, p[0], p[1], p[2], p[3], p[4]);
            return;
        }

        BYTE* stub = BuildStub(reinterpret_cast<uintptr_t>(p),
                               reinterpret_cast<void*>(&ShouldSkipPlugin),
                               base + kLoaderRva + 5);
        if (!stub) { LogF(L"[plugin_disable] stub/AllocNear failed - aborting\n"); return; }

        int64_t rel = (int64_t)reinterpret_cast<uintptr_t>(stub)
                    - (int64_t)reinterpret_cast<uintptr_t>(p + 5);
        if (rel < INT32_MIN || rel > INT32_MAX)
        {
            LogF(L"[plugin_disable] stub out of rel32 range - aborting\n");
            return;
        }

        DWORD oldP = 0;
        if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &oldP))
        {
            LogF(L"[plugin_disable] VirtualProtect failed (err=%lu)\n", GetLastError());
            return;
        }
        p[0] = 0xE9;
        int32_t rel32 = (int32_t)rel;
        std::memcpy(p + 1, &rel32, 4);
        VirtualProtect(p, 5, oldP, &oldP);
        FlushInstructionCache(GetCurrentProcess(), p, 5);

        LogF(L"[plugin_disable] openOrFetchPlugin @ %p -> stub %p "
             L"(sabuiltin_ editor plugins skipped by name; builtin_ kept)\n",
             (void*)p, (void*)stub);
    }
}
