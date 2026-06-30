// render_disable.cpp - see render_disable.h.
//
// Engine-level 3D render disable for StartServer instances, pure DLL.
//
// The RenderJob (constructed at 0x4193ce0, which sets the "RenderJob" name +
// vtable) has a per-frame step at 0x4194760. The scheduler calls that step; it
// pre-checks, then tail-calls the scheduler's job-step dispatcher 0x40ed740,
// which invokes the job's render virtual and returns a status the scheduler
// uses to reschedule. The dispatcher has the engine's OWN skip path: when the
// job's skip flag is set it does `mov eax,1; ret` (0x40ed788) - i.e. returning
// eax=1 means "skipped this frame, reschedule normally".
//
// So we neuter the RenderJob step by overwriting its prologue with
// `mov eax,1; ret`. The step returns the engine's sanctioned skip value every
// frame: no 3D render, and the scheduler / physics / scripts / replication are
// completely unaffected. (An earlier attempt NOPed a CONDITIONAL call inside
// the step - 0x6de6c80, gated by a predicate - which was usually not taken, so
// it did nothing. This neuters the whole step.)
//
// RVAs are for the 82ca build (the unpacked exe you run, md5 e3dc264b...).

#include "render_disable.h"
#include "patcher.h"

#include <cstdint>
#include <cstring>

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();

    // ---- CONFIGURE (per build) ------------------------------------------
    static const uintptr_t kRenderStepRva = 0x04194760;   // RenderJob per-frame step
    // Exact prologue we expect, so a different build is left untouched.
    static const unsigned char kStepPrologue[6] =
        { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57 };           // mov [rsp+8],rbx ; push rdi
    // ----------------------------------------------------------------------

    void StartRenderDisable()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        HMODULE host = GetModuleHandleW(nullptr);
        uintptr_t base = reinterpret_cast<uintptr_t>(host);
        BYTE* p = reinterpret_cast<BYTE*>(base + kRenderStepRva);

        if (std::memcmp(p, kStepPrologue, sizeof(kStepPrologue)) != 0)
        {
            LogF(L"[render_disable] RenderJob step prologue mismatch @ %p "
                 L"(%02X %02X %02X %02X %02X %02X) - aborting (build mismatch?)\n",
                 (void*)p, p[0], p[1], p[2], p[3], p[4], p[5]);
            return;
        }

        // mov eax,1 ; ret  -> the engine's own "skip this step" return value.
        const unsigned char patch[6] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
        DWORD oldP = 0;
        if (!VirtualProtect(p, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldP))
        {
            LogF(L"[render_disable] VirtualProtect failed (err=%lu)\n", GetLastError());
            return;
        }
        std::memcpy(p, patch, sizeof(patch));
        VirtualProtect(p, sizeof(patch), oldP, &oldP);
        FlushInstructionCache(GetCurrentProcess(), p, sizeof(patch));

        LogF(L"[render_disable] RenderJob step @ %p neutered (returns engine skip "
             L"value) - 3D rendering disabled on server\n", (void*)p);
    }
}
