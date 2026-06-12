// identity_patch.h - inject a relayed UserId / AccountAge into createServerPlayer.
//
// createServerPlayer() (v8datamodel/src/Players.cpp) builds each joining
// Player from the join-data source by, for every property, pushing the
// property NAME and calling a generic getter then a generic setter, e.g.:
//
//   push "UserId"      ; int64
//   ...                ; build descriptor
//   call <getInt64>    ; eax:edx = UserId from join data (0 on a local server)
//   mov  ecx,[ebp-18]
//   push edx / push eax
//   call <setInt64>    ; Player.UserId = eax:edx
//
//   push "AccountAge"  ; int32
//   call <getInt32>    ; eax = AccountAge from join data (0)
//   mov  ecx,[ebp-14]
//   push eax
//   call <setInt32>
//
// We detour ONLY the getter CALL at the UserId site and the AccountAge site
// (located by their exact surrounding byte idiom, validated as a unique match)
// so they return the values relayed over the magic packet instead of 0. The
// generic getters keep their original behaviour at every other call site.
//
// x86 only. Fail-safe: if a site isn't found/unique the patch is a no-op.

#pragma once
#include "patcher.h"

namespace RobloxStudioPatcher
{
    // Locate + detour the two getter call sites. Idempotent; safe to call more
    // than once and before any values are known.
    void InstallIdentityPatch();

    // Store the values the detours hand back, and ensure the detours are
    // installed. Called by the relay when a v2 magic packet arrives.
    void SetRelayedIdentity(unsigned long long userId, unsigned int accountAge);
}
