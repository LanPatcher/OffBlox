// render_nulldevice.h - force the graphics backend factory to build a
// NoGraphics (null-device) engine on StartServer instances.
//
// EXPERIMENTAL / AGGRESSIVE. CreateGraphicsEngine's try-loop calls the backend
// factory once per candidate mode; we redirect THAT call so it is always asked
// for mode 9 (NoGraphics). If the build still contains a working null backend,
// the engine comes up with no D3D11 device, no shader pack and no VRAM budget,
// while still satisfying the caller's mandatory non-null engine check. If the
// null backend was compiled out, factory(9) returns null and the engine aborts
// at RenderScheduler.FailedCreateGameWindow - we then iterate from there.
//
// Server launches only. Easily reverted: remove the Phase-4j call in dllmain.
#pragma once

namespace RobloxStudioPatcher
{
    void StartForceNullDevice();
}
