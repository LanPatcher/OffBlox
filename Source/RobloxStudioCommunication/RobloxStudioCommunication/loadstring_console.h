// loadstring_console.h - server console -> Luau execution via a loadstring hook.
//
// Lines the host types into the server console are queued here (from
// server_console.cpp) and run on the server by hooking the engine's loadstring
// C function: an injected startup poller calls loadstring(<sentinel number>)
// every tick on the server's Lua thread, and our hook swaps the sentinel for
// the next queued script before the real loadstring compiles it. The poller
// then runs the returned function - so it executes with the poller's (elevated
// startup) identity, exactly like a normal script calling loadstring.
//
// StartServer only, and OPT-IN: create "loadstring_console_on.txt" next to the
// DLL to enable. Guarded by SEH so a bad offset fault-skips instead of crashing.
#pragma once

#include <string>

namespace RobloxStudioPatcher
{
    // Queue a line of Luau to run on the server (called by the console reader).
    void EnqueueConsoleScript(const std::string& code);

    // Same, but runs WITHOUT echoing to the server console. Used by the v10 property
    // replication path (udp_relay) so replicated writes don't flood the console.
    void EnqueueConsoleScriptQuiet(const std::string& code);

    // Queue a pure-C++ property change {guid64, prop, variant} for main-thread apply
    // (guid resolve + setValue). Called from the network thread; thread-safe.
    void EnqueueGuidChange(unsigned long long guid, const char* prop, int plen,
                           const unsigned char* var, int vlen);

    // Install the loadstring entry hook (StartServer + sidecar-gated inside).
    void InstallLoadstringConsoleHook();
}
