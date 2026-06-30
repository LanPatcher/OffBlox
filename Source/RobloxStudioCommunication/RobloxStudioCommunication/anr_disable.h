// anr_disable.h - disable the ANR (App-Not-Responding) watchdog on StartServer.
//
// With 3D rendering forced off (null device), nothing pumps the main event loop
// the way the watchdog expects, so the ANR detector repeatedly flags "ANR In
// Progress" and runs its monitor thread. It is a pure watchdog (no functional
// role on a headless server), so we neuter its monitor routine to return
// immediately - the thread exits at once: no checks, no log spam, no growth.
// Server launches only.
#pragma once

namespace RobloxStudioPatcher
{
    void StartAnrDisable();
}
