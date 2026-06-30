// player_leave.cpp - see player_leave.h.
//
// In the 82ca build the server removes a player in the function at 0x4a187c0
// (right after createServerPlayer @ 0x4a17a80). For each player being removed
// it sets the "is being removed" flag (player+0x11a1 = 1) and fires the
// per-player removal at:
//
//   0x4a1894b   call 0x49e09a0     ; rcx=&PlayerRemoving signal (Players+0x728),
//                                  ; rdx=&{player, refcount}, r8=&flag
//
// This is the engine equivalent of Players.PlayerRemoving:Connect(...). We
// redirect ONLY this call site to a small stub that reads the leaving player's
// name and frees it in the relay, then tail-calls the real function so the
// engine's removal behaviour is completely unchanged.
//
// The player object is *rdx; its Name is a std::string* at player+0xb0 (the
// engine reads it that way at 0x4a51282 / 0x4a512b2 to format player messages).
// The name read is POD-only + SEH-guarded, so a wrong offset or bad pointer
// degrades to "no name" instead of crashing.
//
// RVAs are for the 82ca build (the unpacked exe you run, md5 e3dc264b...).

#include "player_leave.h"
#include "patcher.h"
#include "udp_relay.h"

#include <cstdint>
#include <cstring>

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();

    // ---- CONFIGURE (per build) ------------------------------------------
    // Every PlayerRemoving fire site: `call 0x49e09a0` preceded by
    // `lea rcx,[Players+0x728]` (0x728 is the PlayerRemoving signal, per the
    // reflection registration at 0x4c8978). 0x4a1894b is in the batch-removal
    // 0x4a187c0; 0x4a252d8 / 0x4a253a7 are in 0x4a24f60 (the per-player removal
    // that runs on a disconnect). All call 0x49e09a0 with rdx = &{player,...}.
    static const uintptr_t kFireTgtRva   = 0x049e09a0;       // the signal-fire (sanity)
    static const uintptr_t kFireSites[]  = { 0x04a1894b, 0x04a252d8, 0x04a253a7 };
    static const uintptr_t kPlayerNameOff = 0xb0;            // Instance Name std::string*
    // ----------------------------------------------------------------------

    // Read the leaving player's name into nameBuf (POD-only so __try is legal;
    // a std::string here would need C++ unwinding and SEH would reject it).
    // player = *slot; name std::string* at player+0xb0; MSVC std::string =
    // {ptr/buf @ +0, size @ +0x10, capacity @ +0x18; heap iff cap >= 16}.
    static void OnPlayerRemoved(void* slot)
    {
        char  nameBuf[256]; nameBuf[0] = '\0';
        void* dbgPlayer = nullptr;
        __try
        {
            if (slot)
            {
                void* player = *reinterpret_cast<void**>(slot);
                dbgPlayer = player;
                if (player)
                {
                    auto* np = *reinterpret_cast<const unsigned char* const*>(
                        reinterpret_cast<const unsigned char*>(player) + kPlayerNameOff);
                    if (np)
                    {
                        size_t size = *reinterpret_cast<const size_t*>(np + 0x10);
                        size_t cap  = *reinterpret_cast<const size_t*>(np + 0x18);
                        if (size > 0 && size < sizeof(nameBuf))
                        {
                            const char* d = (cap >= 16)
                                ? *reinterpret_cast<const char* const*>(np)
                                : reinterpret_cast<const char*>(np);
                            if (d) { std::memcpy(nameBuf, d, size); nameBuf[size] = '\0'; }
                        }
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { nameBuf[0] = '\0'; }

        // DIAGNOSTIC: prove the stub fires and show what name we read.
        LogF(L"[player_leave] removal fired: player=%p name='%hs'\n",
             dbgPlayer, nameBuf[0] ? nameBuf : "(none)");

        if (nameBuf[0]) RelayFreePlayerName(nameBuf);   // std::string built here, outside __try
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

    // Stub reached via the redirected call (stack/regs exactly as 0x49e09a0
    // expects): save args, OnPlayerRemoved(rdx), restore, tail-jmp to real fn.
    static BYTE* BuildStub(uintptr_t anchor, void* helper, void* real)
    {
        BYTE* s = reinterpret_cast<BYTE*>(AllocNear(anchor, 64));
        if (!s) return nullptr;
        int i = 0;
        s[i++] = 0x51;                                  // push rcx
        s[i++] = 0x52;                                  // push rdx
        s[i++] = 0x41; s[i++] = 0x50;                   // push r8
        s[i++] = 0x41; s[i++] = 0x51;                   // push r9
        s[i++] = 0x48; s[i++] = 0x83; s[i++] = 0xEC; s[i++] = 0x28;   // sub rsp,0x28
        s[i++] = 0x48; s[i++] = 0x8B; s[i++] = 0xCA;    // mov rcx,rdx  (&player slot)
        s[i++] = 0x48; s[i++] = 0xB8;                   // mov rax, imm64 (helper)
        std::memcpy(s + i, &helper, 8); i += 8;
        s[i++] = 0xFF; s[i++] = 0xD0;                   // call rax
        s[i++] = 0x48; s[i++] = 0x83; s[i++] = 0xC4; s[i++] = 0x28;   // add rsp,0x28
        s[i++] = 0x41; s[i++] = 0x59;                   // pop r9
        s[i++] = 0x41; s[i++] = 0x58;                   // pop r8
        s[i++] = 0x5A;                                  // pop rdx
        s[i++] = 0x59;                                  // pop rcx
        s[i++] = 0x48; s[i++] = 0xB8;                   // mov rax, imm64 (real)
        std::memcpy(s + i, &real, 8); i += 8;
        s[i++] = 0xFF; s[i++] = 0xE0;                   // jmp rax  (tail-call)
        FlushInstructionCache(GetCurrentProcess(), s, i);
        return s;
    }

    void StartPlayerLeaveHook()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        HMODULE host = GetModuleHandleW(nullptr);
        uintptr_t base = reinterpret_cast<uintptr_t>(host);
        void* real = reinterpret_cast<void*>(base + kFireTgtRva);

        // One shared stub (all sites call the same 0x49e09a0 with the same args).
        BYTE* stub = BuildStub(base + kFireSites[0],
                               reinterpret_cast<void*>(&OnPlayerRemoved), real);
        if (!stub) { LogF(L"[player_leave] stub/AllocNear failed - aborting\n"); return; }

        int patched = 0;
        const int n = (int)(sizeof(kFireSites) / sizeof(kFireSites[0]));
        for (int k = 0; k < n; ++k)
        {
            uintptr_t site = base + kFireSites[k];
            BYTE* p = reinterpret_cast<BYTE*>(site);
            if (p[0] != 0xE8)
            {
                LogF(L"[player_leave] site rva=0x%llx not a call (%02X) - skip\n",
                     (unsigned long long)kFireSites[k], p[0]);
                continue;
            }
            int32_t rel = *reinterpret_cast<int32_t*>(p + 1);
            if (reinterpret_cast<uintptr_t>(p + 5) + rel != base + kFireTgtRva)
            {
                LogF(L"[player_leave] site rva=0x%llx target mismatch - skip\n",
                     (unsigned long long)kFireSites[k]);
                continue;
            }
            int64_t newRel = (int64_t)reinterpret_cast<uintptr_t>(stub) - (int64_t)(site + 5);
            if (newRel < INT32_MIN || newRel > INT32_MAX) continue;
            DWORD oldP = 0;
            if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &oldP)) continue;
            *reinterpret_cast<int32_t*>(p + 1) = (int32_t)newRel;
            VirtualProtect(p, 5, oldP, &oldP);
            FlushInstructionCache(GetCurrentProcess(), p, 5);
            ++patched;
        }

        LogF(L"[player_leave] redirected %d/%d PlayerRemoving fire sites -> stub %p "
             L"(real %p) - leave detection active\n", patched, n, stub, real);
    }
}
