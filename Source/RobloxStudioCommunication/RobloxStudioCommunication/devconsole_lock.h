// devconsole_lock.h
//
// Locks the in-game Developer Console to the host only by repairing the
// canManage request the console already depends on (no CoreGui / Lua edit,
// no FastFlag config). See devconsole_lock.cpp for the full rationale.

#pragma once

namespace RobloxStudioPatcher
{
    // Flip the FastFlag-gated early-return in the GetCanManageAsync worker so
    // the canManage HTTP request fires again. Gated to game tasks (client or
    // server) inside; the editor is left untouched.
    void StartDevConsoleLock();
}
