// udp_relay.h - relay the local username to the game server via Roblox's
// own UDP socket, no extra ports.
//
// Design:
//   * Client DLL: hooks ws2_32!sendto and ws2_32!WSASendTo via IAT. The
//     first time the host EXE sends a UDP datagram to a given non-loopback
//     (ip:port), we squeeze ONE extra datagram in front of it that carries
//     a "magic" header and the username from username.txt. Subsequent
//     traffic to that destination passes through untouched.
//
//   * Server DLL: hooks ws2_32!recvfrom, ws2_32!WSARecvFrom, AND
//     ws2_32!WSARecv (RakNet uses WSARecv on connected UDP sockets).
//     Every incoming datagram is sniffed for our magic prefix. If it
//     matches, we extract the username, stash it in an in-memory
//     `IP -> name` map keyed on the source address, and pretend we never
//     received anything (Roblox's RakNet never sees the packet).
//     WSARecv has no from/fromlen - source IP is obtained via getpeername.
//
//   * Lua bridge: see username_server.cpp - a loopback-only HTTP listener
//     (127.0.0.1:19999) exposes the IP->name map via GET /lookup?ip=...
//     so server-side scripts can rename the Player on PlayerAdded.
//
// Wire format of the magic datagram:
//     +-----+-----+-----+-----+---+----+--------------+
//     | C0  | DE  | 5A  | 45  | 1 | nL | name bytes...|
//     +-----+-----+-----+-----+---+----+--------------+
//     bytes  0..3                4   5    6..(6+nL-1)
//   * Magic   = 0xC0DE5A45 in network byte order (uniquely identifies us)
//   * Version = 1
//   * nL      = name length in bytes (max 255)

#pragma once

#include "patcher.h"
#include <string>

namespace RobloxStudioPatcher
{
    // Installs the IAT hooks on ws2_32!sendto, WSASendTo, recvfrom,
    // WSARecvFrom, and WSARecv in the host EXE. Safe to call from DllMain.
    // The same DLL works on both the client and server side - hooks are
    // bidirectional by design.
    bool StartUdpRelay();

    // Feed a server output line here so the relay can detect player LEAVES and
    // free that player's name (so the same human reclaims it on reconnect
    // instead of being bumped to Player%d). Recognises:
    //   * "OffBloxPlayerLeft:<name>"      - the injected PlayerRemoving handler
    //                                       (reliable; fires on every leave)
    //   * "Disconnect from <ip>|<port>"   - transport disconnect (by port)
    //   * "Player (<name>) is being removed"
    // Returns true if the line was the INTERNAL PlayerRemoving tag and should be
    // suppressed from visible output; false otherwise. Cheap; the caller should
    // only pass lines containing one of those trigger substrings.
    bool OnServerOutputLine(const char* msg);

    // Free a player's relay identity by name (clone-identity fix). Called by the
    // C++ player-removal hook (player_leave.cpp) when a player leaves, so the
    // same person reclaims their name on reconnect instead of getting Player%d.
    void RelayFreePlayerName(const char* name);
}
