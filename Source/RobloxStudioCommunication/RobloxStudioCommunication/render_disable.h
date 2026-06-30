// render_disable.h - engine-level 3D render disable for StartServer instances.
//
// Pure DLL: NOPs the single render-dispatch call inside the RenderJob's
// per-frame step, so the server stops doing 3D render work. Physics, network
// replication, scripts and the task scheduler are untouched (the step's
// predicate and base-step tail-call still run). Server launches only.
#pragma once

namespace RobloxStudioPatcher
{
    void StartRenderDisable();
}
