// player_join.h
//
// Server-only. Detects an ACTUAL player join (createServerPlayer) and commits
// that player's name into the relay's anti-impersonation table at that point -
// NOT when the join magic is merely received. This prevents a client that
// announces a username but never actually joins from holding that name hostage.
// See player_join.cpp for the engine details.

#pragma once

namespace RobloxStudioPatcher
{
    void StartPlayerJoinHook();
}
