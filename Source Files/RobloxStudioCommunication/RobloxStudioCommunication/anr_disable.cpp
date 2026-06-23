// anr_disable.cpp - see anr_disable.h.
//
// 0x841230 is the ANR detector's monitor routine (it logs "ANR Detector worker
// thread started" and "ANR In Progress"). Its prologue is:
//   4C 89 4C 24 20   mov [rsp+0x20], r9
//   4C 89 44 24 18   mov [rsp+0x18], r8
//   ...              (4 reg args spilled, then a big stack frame)
// We overwrite the first three bytes with `xor eax,eax ; ret` so it returns 0
// before establishing a frame (rsp untouched). The monitor never runs.
//
// RVAs are for the 82ca build (the unpacked exe you run, md5 e3dc264b...).

#include "anr_disable.h"
#include "patcher.h"

#include <cstdint>
#include <cstring>

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();

    // ---- CONFIGURE (per build) ------------------------------------------
    static const uintptr_t kAnrMonitorRva = 0x00841230;   // ANR monitor routine
    static const unsigned char kPrologue[5] =
        { 0x4C, 0x89, 0x4C, 0x24, 0x20 };                  // mov [rsp+0x20], r9
    // ----------------------------------------------------------------------

    void StartAnrDisable()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        HMODULE host = GetModuleHandleW(nullptr);
        uintptr_t base = reinterpret_cast<uintptr_t>(host);
        BYTE* p = reinterpret_cast<BYTE*>(base + kAnrMonitorRva);

        if (std::memcmp(p, kPrologue, sizeof(kPrologue)) != 0)
        {
            LogF(L"[anr_disable] prologue mismatch @ %p "
                 L"(%02X %02X %02X %02X %02X) - aborting (build mismatch?)\n",
                 (void*)p, p[0], p[1], p[2], p[3], p[4]);
            return;
        }

        const unsigned char patch[3] = { 0x31, 0xC0, 0xC3 };   // xor eax,eax ; ret
        DWORD oldP = 0;
        if (!VirtualProtect(p, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldP))
        {
            LogF(L"[anr_disable] VirtualProtect failed (err=%lu)\n", GetLastError());
            return;
        }
        std::memcpy(p, patch, sizeof(patch));
        VirtualProtect(p, sizeof(patch), oldP, &oldP);
        FlushInstructionCache(GetCurrentProcess(), p, sizeof(patch));

        LogF(L"[anr_disable] ANR monitor @ %p neutered (return 0) - "
             L"no watchdog thread / 'ANR In Progress' spam on server\n", (void*)p);
    }
}
