// output_dedupe.h - drop duplicate output/error lines before they reach the
// Studio output model (which is what actually costs FPS under error spam -
// the hidden window doesn't paint, but every message is still formatted and
// appended on the main thread).
//
// This hooks the engine's StandardOut sink (the std::string output function
// that LogService broadcasts from). In a running game (client/server) any
// message string we've already shown is dropped; in the editor nothing is
// suppressed so developers still see everything.
//
// IMPORTANT: set kSinkRva in output_dedupe.cpp to the RVA of the sink in YOUR
// build (capture it once in x32dbg - see the chat notes). With kSinkRva == 0
// the module is a safe no-op.
#pragma once

namespace RobloxStudioPatcher
{
    // Installs the StandardOut sink hook + dedupe. Safe to call from DllMain.
    // No-op (logs and returns) if the sink RVA isn't configured or the hook
    // can't be installed. Only suppresses when NOT in editor mode.
    void StartOutputDedupe();
}
