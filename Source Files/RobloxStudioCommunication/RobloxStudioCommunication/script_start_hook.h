// script_start_hook.h
//
// Call-through wrapper hook at VA 0x0178ED65 (NetworkServer::Start).
//
// Design rationale:
//   Both "Started network server" and script output appear on task thread
//   11b74, in that order. Scripts are launched by the code that runs in the
//   task body AFTER NetworkServer::Start() returns. Blocking inside Start()
//   (after the real Start() has run) holds up that task body and prevents
//   scripts from starting, without leaving NetworkServer uninitialised.
//
//   The previous hook at 0x0101E380 targeted the wrong thread (main/UI
//   thread 11b10), which is why Studio froze for 60s and scripts ran anyway.
//
// Hook strategy - call-through wrapper:
//   Entry JMP patch at 0x0178ED65 redirects to NetworkServerStartWrap.
//   The detour calls the real Start() via the trampoline (so Start() runs
//   fully and returns to us), then waits on the allow-event, then returns
//   to the task body. The task body proceeds to start Lua after AllowScriptStart().
//
// Signaling:
//   Manual-reset event "Local\RobloxStudioPatcher_ScriptStart".
//   AllowScriptStart() sets it. Once signaled, all future waits are instant.
//   The launcher can also signal it externally:
//     HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE,
//                           L"Local\\RobloxStudioPatcher_ScriptStart");
//     SetEvent(h);

#pragma once
#include "patcher.h"

namespace RobloxStudioPatcher
{
    // Install the call-through wrapper at VA 0x0178ED65.
    // No-op on second call. Only call when IsStartServerTask() is true.
    void InstallScriptStartHook();

    // Signal that coregui init is done and Lua may proceed.
    // Sets the manual-reset event. Idempotent.
    void AllowScriptStart();
}
