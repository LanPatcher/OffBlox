// server_console.h - a real console window for -task StartServer instances.
//
// On a server launch we allocate a console, hide the (useless, GPU-wasting)
// 3D game window, and surface our own log lines there: the deduped engine /
// script output plus a "player joined" line with the username. Client and
// editor launches are unaffected (everything here no-ops unless the console
// was allocated, which only happens in StartServer mode).
#pragma once

#include <string>

namespace RobloxStudioPatcher
{
    // Allocates the console + starts the window-hider watcher. Server only.
    void StartServerConsole();

    // True once the server console is up (i.e. we are a StartServer instance
    // and AllocConsole succeeded). Used to gate the mirror/join calls so they
    // are free no-ops on client/editor launches.
    bool ServerConsoleActive();

    // Write one line to the console (a trailing newline is added if missing).
    void ServerConsoleLog(const std::string& line);

    // Convenience: "[+] Player joined: <name>" (pass the FORCED name, e.g.
    // "Player%d (...)", for a rejected/impersonating connection).
    void ServerConsolePlayerJoined(const std::string& displayName);

    // Convenience: "[-] Player left: <name>".
    void ServerConsolePlayerLeft(const std::string& username);
}
