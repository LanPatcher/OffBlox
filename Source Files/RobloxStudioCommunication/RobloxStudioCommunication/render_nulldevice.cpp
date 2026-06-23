// render_nulldevice.cpp - see render_nulldevice.h.
//
// In the 82ca build, CreateGraphicsEngine (0x1e0fd40) builds a list of candidate
// graphics modes and tries each via the backend factory thunk at 0x58f8740:
//
//   0x1e1019c   mov ecx, ebx          ; ecx = candidate mode from the list
//   0x1e1019e   call 0x58f8740        ; engine = factory(mode, rdx, r8)
//   0x1e101a3   mov rbx, rax          ; test rax -> next mode on null
//
// The factory is a thunk (`mov rax,[rip+ptr]; jmp rax`) into the registered
// "create rendering engine" function, which switches on the mode arg (2=D3D11,
// 4=OpenGL, 6=Vulkan, 9=NoGraphics). The list-builder deliberately never emits
// mode 9 (case 9 returns an empty list) and the only runtime path that sees 9
// logs "NoGraphics not supported" and substitutes D3D11 - i.e. the headless
// path is gated off, not necessarily absent from the factory.
//
// We bypass all of that gating by redirecting THIS ONE call site (not the other
// factory call at 0x265982f) through a stub that forces ecx=9 and tail-jumps to
// the factory thunk. Every candidate the loop tries is therefore requested as
// NoGraphics. If the factory can still construct a null device, the engine is
// non-null (passes the mandatory check) but holds no D3D11 device / shaders /
// VRAM. If it cannot, factory(9) returns null and the engine aborts at
// RenderScheduler.FailedCreateGameWindow - the expected "iterate from here"
// failure, not silent corruption.
//
// RVAs are for the 82ca build (the unpacked exe you run, md5 e3dc264b...).

#include "render_nulldevice.h"
#include "patcher.h"

#include <cstdint>
#include <cstring>

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();

    // ---- CONFIGURE (per build) ------------------------------------------
    static const uintptr_t kCallSiteRva   = 0x01e1019e;   // call 0x58f8740 in CreateGraphicsEngine
    static const uintptr_t kFactoryRva    = 0x058f8740;   // backend factory thunk
    static const unsigned char kCallBytes[5] =
        { 0xE8, 0x9D, 0x85, 0xAE, 0x03 };                 // E8 + rel32 -> 0x58f8740
    static const unsigned int kForcedMode = 9;            // NoGraphics
    // ----------------------------------------------------------------------

    // Allocate executable memory within +/-2GB of `anchor` so a rel32 jmp/call
    // can reach it. (Same approach as player_leave.cpp.)
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

    // Build:  mov ecx, kForcedMode ; jmp factory
    // The original `call` pushes the return address (0x1e101a3); the factory's
    // own `ret` therefore returns straight back into the try-loop. We touch no
    // other register, so rdx/r8 (the factory's other args) are preserved.
    static BYTE* BuildModeStub(uintptr_t anchor, uintptr_t factory)
    {
        BYTE* s = reinterpret_cast<BYTE*>(AllocNear(anchor, 32));
        if (!s) return nullptr;
        int i = 0;
        s[i++] = 0xB9;                                   // mov ecx, imm32
        std::memcpy(s + i, &kForcedMode, 4); i += 4;     //   = 9
        s[i++] = 0xE9;                                   // jmp rel32 -> factory
        int64_t rel = (int64_t)factory - (int64_t)reinterpret_cast<uintptr_t>(s + i + 4);
        if (rel < INT32_MIN || rel > INT32_MAX) { return nullptr; }
        int32_t rel32 = (int32_t)rel;
        std::memcpy(s + i, &rel32, 4); i += 4;
        FlushInstructionCache(GetCurrentProcess(), s, i);
        return s;
    }

    void StartForceNullDevice()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        HMODULE host = GetModuleHandleW(nullptr);
        uintptr_t base = reinterpret_cast<uintptr_t>(host);
        BYTE* call = reinterpret_cast<BYTE*>(base + kCallSiteRva);

        // Build guard: bail if this isn't the exact call we mapped.
        if (std::memcmp(call, kCallBytes, sizeof(kCallBytes)) != 0)
        {
            LogF(L"[null_device] call-site mismatch @ %p "
                 L"(%02X %02X %02X %02X %02X) - aborting (build mismatch?)\n",
                 (void*)call, call[0], call[1], call[2], call[3], call[4]);
            return;
        }

        // Sanity: the rel32 must actually point at the factory thunk.
        int32_t origRel = *reinterpret_cast<int32_t*>(call + 1);
        if (reinterpret_cast<uintptr_t>(call + 5) + origRel != base + kFactoryRva)
        {
            LogF(L"[null_device] call target mismatch @ %p - aborting\n", (void*)call);
            return;
        }

        BYTE* stub = BuildModeStub(reinterpret_cast<uintptr_t>(call),
                                   base + kFactoryRva);
        if (!stub)
        {
            LogF(L"[null_device] stub/AllocNear failed - aborting\n");
            return;
        }

        int64_t newRel = (int64_t)reinterpret_cast<uintptr_t>(stub)
                       - (int64_t)reinterpret_cast<uintptr_t>(call + 5);
        if (newRel < INT32_MIN || newRel > INT32_MAX)
        {
            LogF(L"[null_device] stub out of rel32 range - aborting\n");
            return;
        }

        DWORD oldP = 0;
        if (!VirtualProtect(call, 5, PAGE_EXECUTE_READWRITE, &oldP))
        {
            LogF(L"[null_device] VirtualProtect failed (err=%lu)\n", GetLastError());
            return;
        }
        *reinterpret_cast<int32_t*>(call + 1) = (int32_t)newRel;   // keep E8, repoint
        VirtualProtect(call, 5, oldP, &oldP);
        FlushInstructionCache(GetCurrentProcess(), call, 5);

        LogF(L"[null_device] CreateGraphicsEngine factory call @ %p -> stub %p "
             L"(forces mode 9 / NoGraphics; factory thunk %p)\n",
             (void*)call, (void*)stub, (void*)(base + kFactoryRva));
    }
}
