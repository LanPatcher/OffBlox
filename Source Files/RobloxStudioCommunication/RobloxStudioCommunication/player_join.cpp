// player_join.cpp - see player_join.h.
//
// The anti-impersonation name lock used to be applied the moment the host
// received a client's join magic (in ClassifyJoin). That meant a client could
// send the magic, never actually join, and keep a username reserved. The lock
// is now DEFERRED: ClassifyJoin only records a PENDING peer, and the name is
// committed (RelayCommitPlayerName) only once the player ACTUALLY joins.
//
// "Actually joined" == the server ran createServerPlayer (0x4a17a80) and
// produced a Player. createServerPlayer returns a shared_ptr<Player> by hidden
// return pointer: rax -> { Player* @ +0, control @ +8 } (confirmed at the call
// sites, which do `mov rdx,[rax]; mov rcx,[rax+8]`). The Player's Name is a
// std::string* at player+0xb0 (same offset player_leave reads on removal).
//
// We redirect the 4 createServerPlayer call sites to a small RETURN-CAPTURING
// stub: it calls the real createServerPlayer (args untouched -> engine behaviour
// is identical), then reads the created Player's Name and commits it to the
// relay, then returns the real result unchanged. createServerPlayer takes 4
// register args and no stack args, so the wrap can't disturb the call.
//
// RVAs are for the 82ca build (the unpacked exe you run, md5 e3dc264b...).

#include "player_join.h"
#include "patcher.h"
#include "udp_relay.h"

#include <cstdint>
#include <cstring>
#include <string>

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();

    // ---- CONFIGURE (per build) ------------------------------------------
    static const uintptr_t kCreatePlayerRva = 0x04a17a80;     // createServerPlayer
    static const uintptr_t kCallSites[] =
        { 0x0286088f, 0x0286097b, 0x028625cd, 0x028626ad };   // its 4 callers
    static const uintptr_t kPlayerNameOff = 0xb0;             // Instance Name std::string*
    // ----------------------------------------------------------------------

    // player = the created Player* ([rax+0] of the returned shared_ptr). Read its
    // Name (POD-only + SEH-guarded; MSVC std::string: ptr/buf@+0, size@+0x10,
    // capacity@+0x18, heap iff cap>=16) and commit it to the relay table.
    static int ReadPlayerNameSEH(void* player, char* buf, size_t bufSize)
    {
        __try
        {
            if (!player) return 0;
            auto* np = *reinterpret_cast<const unsigned char* const*>(
                reinterpret_cast<const unsigned char*>(player) + kPlayerNameOff);
            if (!np) return 0;
            size_t size = *reinterpret_cast<const size_t*>(np + 0x10);
            size_t cap = *reinterpret_cast<const size_t*>(np + 0x18);
            if (size == 0 || size >= bufSize) return 0;
            const char* d = (cap >= 16)
                ? *reinterpret_cast<const char* const*>(np)
                : reinterpret_cast<const char*>(np);
            if (!d) return 0;
            std::memcpy(buf, d, size);
            buf[size] = '\0';
            return 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    }

    static void OnPlayerCreated(void* player)
    {
        char nameBuf[256]; nameBuf[0] = '\0';
        ReadPlayerNameSEH(player, nameBuf, sizeof(nameBuf));

        LogF(L"[player_join] createServerPlayer -> player=%p name='%hs'\n",
            player, nameBuf[0] ? nameBuf : "(none)");

        if (nameBuf[0]) RelayCommitPlayerName(std::string(nameBuf));
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

    // Return-capturing stub. Entered in place of `call createServerPlayer` with
    // its args in rcx/rdx/r8/r9 (no stack args). Calls the real function, reads
    // the created player from the returned shared_ptr ([rax+0]), notifies us, and
    // returns the real result unchanged. rbx is callee-saved (preserved by both
    // createServerPlayer and the C helper), so we use it to hold the result.
    static BYTE* BuildStub(uintptr_t anchor, void* helper, void* real)
    {
        BYTE* s = reinterpret_cast<BYTE*>(AllocNear(anchor, 64));
        if (!s) return nullptr;
        int i = 0;
        s[i++] = 0x53;                                              // push rbx
        s[i++] = 0x48; s[i++] = 0x83; s[i++] = 0xEC; s[i++] = 0x20; // sub rsp,0x20 (shadow)
        s[i++] = 0x48; s[i++] = 0xB8;                              // mov rax, imm64 real
        std::memcpy(s + i, &real, 8); i += 8;
        s[i++] = 0xFF; s[i++] = 0xD0;                              // call rax (real createServerPlayer)
        s[i++] = 0x48; s[i++] = 0x89; s[i++] = 0xC3;               // mov rbx, rax (save return struct)
        s[i++] = 0x48; s[i++] = 0x8B; s[i++] = 0x08;               // mov rcx, [rax] (player*)
        s[i++] = 0x48; s[i++] = 0xB8;                              // mov rax, imm64 helper
        std::memcpy(s + i, &helper, 8); i += 8;
        s[i++] = 0xFF; s[i++] = 0xD0;                              // call rax (OnPlayerCreated)
        s[i++] = 0x48; s[i++] = 0x89; s[i++] = 0xD8;               // mov rax, rbx (restore return)
        s[i++] = 0x48; s[i++] = 0x83; s[i++] = 0xC4; s[i++] = 0x20; // add rsp,0x20
        s[i++] = 0x5B;                                             // pop rbx
        s[i++] = 0xC3;                                             // ret
        FlushInstructionCache(GetCurrentProcess(), s, i);
        return s;
    }

    void StartPlayerJoinHook()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        HMODULE host = GetModuleHandleW(nullptr);
        uintptr_t base = reinterpret_cast<uintptr_t>(host);
        void* real = reinterpret_cast<void*>(base + kCreatePlayerRva);

        BYTE* stub = BuildStub(base + kCallSites[0],
                               reinterpret_cast<void*>(&OnPlayerCreated), real);
        if (!stub) { LogF(L"[player_join] stub/AllocNear failed - aborting\n"); return; }

        int patched = 0;
        const int n = (int)(sizeof(kCallSites) / sizeof(kCallSites[0]));
        for (int k = 0; k < n; ++k)
        {
            uintptr_t site = base + kCallSites[k];
            BYTE* p = reinterpret_cast<BYTE*>(site);
            if (p[0] != 0xE8)
            {
                LogF(L"[player_join] site rva=0x%llx not a call (%02X) - skip\n",
                     (unsigned long long)kCallSites[k], p[0]);
                continue;
            }
            int32_t rel = *reinterpret_cast<int32_t*>(p + 1);
            if (reinterpret_cast<uintptr_t>(p + 5) + rel != base + kCreatePlayerRva)
            {
                LogF(L"[player_join] site rva=0x%llx target mismatch - skip\n",
                     (unsigned long long)kCallSites[k]);
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

        LogF(L"[player_join] redirected %d/%d createServerPlayer call sites -> stub %p "
             L"(real %p) - name lock now commits on actual join\n", patched, n, stub, real);
    }
}
