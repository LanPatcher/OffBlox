// audio_disable.h - disable audio device init on StartServer instances.
//
// A headless server has no reason to open an audio output device, run a mixer
// or enumerate microphones. The engine's audio device enumerate/open routine
// (0x6420510 in the 82ca build - the function that logs "[FLog::Audio]
// OutputDevice ... Speakers" and the InputDevice list) is neutered to an
// immediate `return 0` so no device is opened and no mixer/capture is set up.
// The engine tolerates having no audio device (normal on machines without
// sound hardware). SoundService still exists for scripts/replication. Server
// launches only; revert by deleting the Phase-4l call in dllmain.
#pragma once

namespace RobloxStudioPatcher
{
    void StartAudioDisable();
}
