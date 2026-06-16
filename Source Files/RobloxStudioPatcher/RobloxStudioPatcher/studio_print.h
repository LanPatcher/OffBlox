// studio_print.h - call Roblox's internal logger from inside the patcher.
//
// Roblox's C++ code has a central logging entrypoint that ultimately
// feeds Studio's Output panel (and the player's diag log). The user
// identified one call site in x32dbg:
//
//   ...
//   push <addr-of "Video recording stopped">    ; second arg, const char*
//   push 1                                       ; first arg, int (level?)
//   call <print fn>
//   add esp, 8                                   ; cdecl cleanup -> 2x dword
//
// Signature deduced:   void __cdecl print(int level, const char* msg);
// On x64 the same signature lands as fastcall:  rcx = level, rdx = msg.
//
// RobloxPrint() is best-effort: it resolves the print function lazily
// (first via a signature scan that looks for the "Video recording stopped"
// marker string and the call site referencing it, then via a per-EXE
// hard-coded RVA fallback). If resolution fails it's a no-op - safe to
// sprinkle anywhere.

#pragma once

#include "patcher.h"

namespace RobloxStudioPatcher
{
    // ASCII / UTF-8 string. Crops to ~1900 chars internally.
    void RobloxPrint(const char* msg);

    // Wide variant - re-encoded to UTF-8 before being passed to Roblox.
    void RobloxPrintW(const wchar_t* msg);
}
