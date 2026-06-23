// auto_recovery.h - suppress Studio's Auto-Recovery ("auto-recovered file
// detected") modal on client launches.
//
// Studio's AutoSaveDialog only appears at startup when auto-recovery files
// exist in the AutoSaves folder, and it is MODAL (it grabs input) - so the Qt
// hider can make it invisible but the viewport still won't accept input
// ("gets hidden but the player cannot interact with game"). The only real fix
// is to stop the dialog being constructed: keep the AutoSaves folder empty
// during the startup window so the recovery scan finds nothing.
#pragma once

namespace RobloxStudioPatcher
{
    // Clears <Documents>\ROBLOX\AutoSaves immediately, then keeps it empty for
    // the launch window on a worker thread. Safe to call from DllMain. Intended
    // for StartClient launches, where the modal blocks the hidden viewport.
    void StartAutoRecoveryKiller();
}
