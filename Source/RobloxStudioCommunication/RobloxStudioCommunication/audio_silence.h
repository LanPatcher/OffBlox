// audio_silence.h - make StartServer instances run with no audio output.
//
// A headless game server has no reason to emit sound, but the engine still
// opens the default audio endpoint and plays Sound instances - audible and
// annoying when hosting under Wine. We make the WASAPI device enumerator fail
// to instantiate so the engine finds no output device and runs fully silent
// (the same graceful path taken on a machine with no audio hardware).
//
// Server launches only. Easily reverted: remove the Phase-4 call in dllmain.
#pragma once

namespace RobloxStudioPatcher
{
    void StartAudioSilence();
}
