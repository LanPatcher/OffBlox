// script_error_dedupe.h - dedup the ScriptContext error-reporter output.
//
// The script-error reporter (0x34dbe20) emits its message via a single
// `call 0x32ccb30` at 0x34dc777. That universal LogService post is unsafe to
// inline-hook (it crashed - it's called from 16 sites incl. early contexts),
// so instead we redirect ONLY this one call site to a dedup wrapper via a
// near-allocated trampoline. All other callers of 0x32ccb30 are untouched.
#pragma once

namespace RobloxStudioPatcher
{
    // Patches the reporter's emit call site so repeated script errors are
    // dropped before they reach LogService. Safe to call from DllMain; no-op
    // (logs and returns) in editor mode or if the call site doesn't match.
    void StartScriptErrorDedupe();
}
