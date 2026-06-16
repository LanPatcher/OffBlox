// rcc_patch.h - LocalRcc join-IP patch (x64)
//
// FFlagDebugLocalRccServerConnection makes the 2026 client connect to a local
// RCC server. The PORT is set via the DebugLocalRccServerConnectionPort FInt
// (injected by HookedWebserver into PCStudioApp). The IP, however, has no FFlag
// on this build - it is a hardcoded "127.0.0.1" string the client copies into
// the connection endpoint. This patches that one specific string load to the
// "-server <ip>" value from the command line.
//
// x64, build-specific (validated before patching, so a wrong build is a no-op).

#pragma once

#include "patcher.h"

namespace RobloxStudioPatcher
{
    // Redirects the LocalRcc default IP "127.0.0.1" to the "-server <ip>" value
    // on the command line. Returns true if patched. No-op (and never crashes)
    // if -server is absent or the call site doesn't validate. Client only.
    bool PatchLocalRccIp();
}
