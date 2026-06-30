// player_leave.h - detect a player leaving (connection drop) purely in C++ and
// free their relay name (clone-identity fix), so the same person reclaims their
// username on reconnect instead of being bumped to Player%d.
//
// Hooks the server's player-removal path (the engine fires its per-player
// removal here, equivalent to Players.PlayerRemoving). Server launches only.
#pragma once

namespace RobloxStudioPatcher
{
    void StartPlayerLeaveHook();
}
