// audio_disable.cpp - see audio_disable.h.
//
// Force FMOD into NOSOUND output on the server. Roblox's default audio init
// calls FMOD System::setOutput (0x64a0920) with output = 0 (AUTODETECT), which
// picks WASAPI and opens the real "Speakers" device + mixer. We redirect THAT
// call site (0x640f153) through a stub that forces the output argument (edx) to
// 2 = FMOD_OUTPUTTYPE_NOSOUND. FMOD then initialises with the null output: a
// valid system object (so nothing polls-and-fails) but no audio device, no
// device mixer and no microphone capture. Server launches only.
//
//   0x640f151  xor edx,edx          ; output = AUTODETECT (overridden below)
//   0x640f153  call 0x64a0920       ; System::setOutput(rcx=system, edx=output)
//
// rcx (the FMOD system) is set up before the call and untouched by the stub.
//
// RVAs are for the 82ca build (the unpacked exe you run, md5 e3dc264b...).

#include "audio_disable.h"
#include "patcher.h"

#include <cstdint>
#include <cstring>

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();

    // ---- CONFIGURE (per build) ------------------------------------------
    static const uintptr_t kCallSiteRva  = 0x0640f153;     // call System::setOutput (AUTODETECT path)
    static const uintptr_t kSetOutputRva = 0x064a0920;     // System::setOutput impl
    static const unsigned char kCallBytes[5] =
        { 0xE8, 0xC8, 0x17, 0x09, 0x00 };                   // E8 + rel32 -> 0x64a0920
    static const unsigned int kNoSound = 2;                // FMOD_OUTPUTTYPE_NOSOUND
    // ----------------------------------------------------------------------

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

    // Build:  mov edx, NOSOUND ; jmp setOutput   (rcx already = the FMOD system)
    static BYTE* BuildStub(uintptr_t anchor, uintptr_t setOutput)
    {
        BYTE* s = reinterpret_cast<BYTE*>(AllocNear(anchor, 32));
        if (!s) return nullptr;
        int i = 0;
        s[i++] = 0xBA;                                   // mov edx, imm32
        std::memcpy(s + i, &kNoSound, 4); i += 4;        //   = 2 (NOSOUND)
        s[i++] = 0xE9;                                   // jmp rel32 -> setOutput
        int64_t rel = (int64_t)setOutput - (int64_t)reinterpret_cast<uintptr_t>(s + i + 4);
        if (rel < INT32_MIN || rel > INT32_MAX) return nullptr;
        int32_t rel32 = (int32_t)rel;
        std::memcpy(s + i, &rel32, 4); i += 4;
        FlushInstructionCache(GetCurrentProcess(), s, i);
        return s;
    }

    void StartAudioDisable()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        HMODULE host = GetModuleHandleW(nullptr);
        uintptr_t base = reinterpret_cast<uintptr_t>(host);
        BYTE* call = reinterpret_cast<BYTE*>(base + kCallSiteRva);

        if (std::memcmp(call, kCallBytes, sizeof(kCallBytes)) != 0)
        {
            LogF(L"[audio_disable] setOutput call-site mismatch @ %p "
                 L"(%02X %02X %02X %02X %02X) - aborting (build mismatch?)\n",
                 (void*)call, call[0], call[1], call[2], call[3], call[4]);
            return;
        }
        int32_t origRel = *reinterpret_cast<int32_t*>(call + 1);
        if (reinterpret_cast<uintptr_t>(call + 5) + origRel != base + kSetOutputRva)
        {
            LogF(L"[audio_disable] setOutput target mismatch @ %p - aborting\n", (void*)call);
            return;
        }

        BYTE* stub = BuildStub(reinterpret_cast<uintptr_t>(call), base + kSetOutputRva);
        if (!stub) { LogF(L"[audio_disable] stub/AllocNear failed - aborting\n"); return; }

        int64_t newRel = (int64_t)reinterpret_cast<uintptr_t>(stub)
                       - (int64_t)reinterpret_cast<uintptr_t>(call + 5);
        if (newRel < INT32_MIN || newRel > INT32_MAX)
        {
            LogF(L"[audio_disable] stub out of rel32 range - aborting\n");
            return;
        }

        DWORD oldP = 0;
        if (!VirtualProtect(call, 5, PAGE_EXECUTE_READWRITE, &oldP))
        {
            LogF(L"[audio_disable] VirtualProtect failed (err=%lu)\n", GetLastError());
            return;
        }
        *reinterpret_cast<int32_t*>(call + 1) = (int32_t)newRel;   // keep E8, repoint to stub
        VirtualProtect(call, 5, oldP, &oldP);
        FlushInstructionCache(GetCurrentProcess(), call, 5);

        LogF(L"[audio_disable] FMOD setOutput @ %p -> stub %p (forces NOSOUND) - "
             L"no audio device/mixer, valid FMOD system (no poll loop)\n",
             (void*)call, (void*)stub);
    }
}
