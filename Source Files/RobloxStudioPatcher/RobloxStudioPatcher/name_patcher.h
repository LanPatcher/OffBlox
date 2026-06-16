// name_patcher.h - patches the "Player%d" string literal in the host EXE
//
// Roblox Studio / Player constructs the local player's display name from
// a printf-style format string. The disassembly that motivated this:
//
//     push 6                              ; length 6
//     push robloxplayerbeta.41CDEE4       ; "Player" - default name
//     push ecx
//     push eax
//     call ...
//     ...
//     push robloxplayerbeta.44BE328       ; "Player%d" - sprintf format
//
// We scan the main module's .rdata for the literal bytes of "Player%d\0"
// and overwrite them with "<username>%d\0" (read from username.txt next
// to the DLL). The replacement is constrained to fit in the same 9 bytes,
// so the username is truncated to 6 chars max - the rest of the slot is
// filled with the "%d" format specifier and a null terminator.
//
// Effect: the local player's auto-generated name becomes "<username>1",
// "<username>2", etc. instead of "Player1", "Player2".

#pragma once

#include "patcher.h"
#include <string>

namespace RobloxStudioPatcher
{
    // DISABLED. Overwrote the "Player%d" string literal in .rdata, which
    // also broke the launch-task ID system that references the same
    // string. Kept here for documentation; the implementation early-
    // returns false. Use PatchPlayerNameCallSite() instead.
    bool PatchLocalPlayerName();

    // Surgical patch: pattern-matches the specific `push "Player%d"`
    // instruction inside Studio's player-name formatting code path and
    // redirects ONLY that push to a custom format ("<username>%d\0")
    // we allocate in our DLL. Other uses of the original "Player%d"
    // string (notably the launch-task ID generator) keep their original
    // pointer and stay intact.
    //
    // x86 ONLY - the instruction pattern is 32-bit specific.
    // Reads the username from "username.txt" beside the DLL.
    // Returns true if at least one call site was patched.
    bool PatchPlayerNameCallSite();

    // Same as above but uses the supplied name directly instead of
    // reading username.txt. Used by the server-side relay when it
    // receives a magic packet - the name is already in memory.
    bool PatchPlayerNameCallSite(const std::string& username);

    // ---- Relayed UserId / AccountAge (server side) ----------------------
    //
    // Called from udp_relay when a v2 magic packet arrives. It captures the
    // two numeric fields (always - see getters below, and the log line) and
    // then performs the engine-side write so the joining Player gets the real
    // UserId / AccountAge instead of 0.
    //
    // The engine write is gated behind a validated pattern scan (same fail-
    // safe style as PatchPlayerNameCallSite): if the join-time write site
    // isn't found/verified it is a NO-OP and never touches the binary, so a
    // wrong/!matching build can't crash a join. Returns regardless.
    void ApplyReceivedIdentity(unsigned long long userId, unsigned int accountAge);

    // Last values received over the relay (0 until a v2 packet arrives).
    unsigned long long GetReceivedUserId();
    unsigned int       GetReceivedAccountAge();
}
