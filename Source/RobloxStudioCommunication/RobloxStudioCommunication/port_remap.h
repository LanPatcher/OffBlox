// port_remap.h - server-only UDP listen-port remapper.
//
// Problem this solves
// -------------------
// On a `-task StartServer` launch the engine opens TWO UDP listeners:
//   * RakNet            -> binds to the value you pass with -port (e.g. 25565)
//   * RbxTransport      -> the new (QUIC/"sys") transport. In this build its
//     "DummyServer"        server socket binds to an EPHEMERAL port (port 0 ->
//                          the OS picks a random one, e.g. 62683), so it can't
//                          be forwarded through a tunnel.
//
// We forward exactly one fixed port (the -port value) through playit.gg, and
// the client connects over RbxTransport - so the RbxTransport/DummyServer
// listener is the one that has to sit on -port, not RakNet.
//
// What this module does (server side only)
// -----------------------------------------
// Hooks ws2_32!bind and, for the engine's UDP listeners:
//   1. RakNet's explicit bind to <-port>      -> rewritten to <-port + 1>.
//   2. The RbxTransport DummyServer's ephemeral (port 0) bind, the first such
//      bind seen AFTER RakNet's -> rewritten to <-port>.
//
// Net result: DummyServer/RbxTransport ends up on the forwarded -port, RakNet
// moves one above it. Both target ports are derived from -port at runtime, so
// nothing is hard-coded to a single setup.
//
// Tuning sidecars (next to the DLL, all optional)
// -----------------------------------------------
//   raknet_port.txt        absolute port for RakNet instead of (-port + 1).
//   dummy_bind_index.txt   which ephemeral UDP bind (1-based, after RakNet) is
//                          the DummyServer. Default 1 (first). Bump it if the
//                          log shows an unrelated ephemeral bind got grabbed.
//   port_remap_off.txt     if present, the whole remap is disabled (passthrough).
//
// Every bind() is logged to RobloxStudioPatcher.log with family/addr/port/type
// and the action taken, so the mapping can be verified and tuned without a
// rebuild.

#pragma once

namespace RobloxStudioPatcher
{
    // Installs the ws2_32!bind hook. Call ONLY on a StartServer launch, from
    // DllMain (early, before the engine opens its listeners). No-op and returns
    // false if -port is absent from the command line or the hook can't install.
    bool StartPortRemap();
}
