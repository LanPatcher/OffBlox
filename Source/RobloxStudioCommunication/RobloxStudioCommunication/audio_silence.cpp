// audio_silence.cpp - see audio_silence.h.
//
// The engine reaches its audio output through WASAPI: it COM-creates the
// device enumerator (CLSID_MMDeviceEnumerator), asks it for the default render
// endpoint, activates an IAudioClient on it and streams samples. If the very
// first step - creating the enumerator - fails, the engine has no endpoint to
// play through and simply runs silent, exactly as it does on a box with no
// sound card. That is the graceful, well-trodden path, so it is far safer than
// trying to null out the mixer or hook the render buffer.
//
// Mechanism: IAT-hook ole32!CoCreateInstance (and CoCreateInstanceEx) in the
// host EXE. When the requested class is the audio device enumerator we return
// REGDB_E_CLASSNOTREG; every other COM class is passed straight through, so
// nothing else on the server is disturbed. Server launches only.

#include "audio_silence.h"
#include "iat_hook.h"
#include "patcher.h"

#include <objbase.h>
#include <cstring>
#include <cstdint>

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();
    void SilenceFmodLog();   // defined below

    // CLSID_MMDeviceEnumerator = {BCDE0395-E52F-467C-8E3D-C4579291692E}
    // (defined locally so we don't have to link the mmdevapi import lib).
    static const GUID kCLSID_MMDeviceEnumerator =
        { 0xBCDE0395, 0xE52F, 0x467C, { 0x8E,0x3D,0xC4,0x57,0x92,0x91,0x69,0x2E } };

    static bool IsAudioEnumerator(REFCLSID rclsid)
    {
        return std::memcmp(&rclsid, &kCLSID_MMDeviceEnumerator, sizeof(GUID)) == 0;
    }

    typedef HRESULT (WINAPI *CoCreateInstance_t)(
        REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
    typedef HRESULT (WINAPI *CoCreateInstanceEx_t)(
        REFCLSID, IUnknown*, DWORD, COSERVERINFO*, DWORD, MULTI_QI*);

    static CoCreateInstance_t   g_origCCI   = nullptr;
    static CoCreateInstanceEx_t g_origCCIEx = nullptr;

    static HRESULT WINAPI Hook_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN outer,
                                                DWORD ctx, REFIID riid, LPVOID* ppv)
    {
        if (IsAudioEnumerator(rclsid))
        {
            if (ppv) *ppv = nullptr;
            return REGDB_E_CLASSNOTREG;   // "no audio device" -> engine stays silent
        }
        CoCreateInstance_t fn = g_origCCI ? g_origCCI : &CoCreateInstance;
        return fn(rclsid, outer, ctx, riid, ppv);
    }

    static HRESULT WINAPI Hook_CoCreateInstanceEx(REFCLSID rclsid, IUnknown* outer,
                                                  DWORD ctx, COSERVERINFO* si,
                                                  DWORD cmq, MULTI_QI* mqi)
    {
        if (IsAudioEnumerator(rclsid))
        {
            for (DWORD i = 0; i < cmq && mqi; ++i)
            {
                mqi[i].pItf = nullptr;
                mqi[i].hr   = REGDB_E_CLASSNOTREG;
            }
            return REGDB_E_CLASSNOTREG;
        }
        CoCreateInstanceEx_t fn = g_origCCIEx ? g_origCCIEx : &CoCreateInstanceEx;
        return fn(rclsid, outer, ctx, si, cmq, mqi);
    }

    void StartAudioSilence()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        // Capture the real exports up front. IAT hooking leaves the export code
        // itself untouched, so calling these for non-audio classes does NOT
        // re-enter our hook (no recursion).
        HMODULE ole = GetModuleHandleW(L"ole32.dll");
        if (!ole) ole = LoadLibraryW(L"ole32.dll");
        if (ole)
        {
            g_origCCI   = reinterpret_cast<CoCreateInstance_t>(
                              GetProcAddress(ole, "CoCreateInstance"));
            g_origCCIEx = reinterpret_cast<CoCreateInstanceEx_t>(
                              GetProcAddress(ole, "CoCreateInstanceEx"));
        }

        // Prefer IAT hooking (no code patching, so g_origCCI stays the real,
        // un-patched export and calling it can't recurse). If the EXE doesn't
        // import the function by name, fall back to an inline export patch - in
        // which case we MUST call through the returned trampoline instead, since
        // the export code itself is now redirected to us.
        void* prev = nullptr;
        bool a = IatHook("ole32.dll", "CoCreateInstance",
                         reinterpret_cast<void*>(&Hook_CoCreateInstance), &prev);
        if (!a)
        {
            void* tramp = nullptr;
            if (InlineHook("ole32.dll", "CoCreateInstance",
                           reinterpret_cast<void*>(&Hook_CoCreateInstance), &tramp))
            { g_origCCI = reinterpret_cast<CoCreateInstance_t>(tramp); a = true; }
        }

        bool b = IatHook("ole32.dll", "CoCreateInstanceEx",
                         reinterpret_cast<void*>(&Hook_CoCreateInstanceEx), &prev);
        if (!b)
        {
            void* tramp = nullptr;
            if (InlineHook("ole32.dll", "CoCreateInstanceEx",
                           reinterpret_cast<void*>(&Hook_CoCreateInstanceEx), &tramp))
            { g_origCCIEx = reinterpret_cast<CoCreateInstanceEx_t>(tramp); b = true; }
        }

        LogF(L"[audio_silence] MMDeviceEnumerator block installed "
             L"(CoCreateInstance=%d CoCreateInstanceEx=%d, orig %p/%p)\n",
             (int)a, (int)b, (void*)g_origCCI, (void*)g_origCCIEx);

        SilenceFmodLog();
    }

    // Disable the FLog::FMOD channel so the "FMOD object 0x0 ... getVersion:
    // invalid object handle" spam (a side effect of running with no audio device)
    // stops. The channel level lives inline in the log-channel table immediately
    // before the "FMOD" name string; zeroing it disables the channel. Guarded so
    // we only touch it when the known default value is there.
    void SilenceFmodLog()
    {
        const uintptr_t kFmodChannelRva = 0xBE7A448;   // level qword before "FMOD" name
        const uint64_t  kExpect         = 0x306;

        uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        uint64_t* chan = reinterpret_cast<uint64_t*>(base + kFmodChannelRva);
        if (*chan != kExpect)
        {
            LogF(L"[audio_silence] FLog::FMOD channel value mismatch (%llX) - not patched\n",
                 (unsigned long long)*chan);
            return;
        }
        DWORD oldp = 0;
        if (VirtualProtect(chan, 8, PAGE_READWRITE, &oldp))
        {
            *chan = 0;                                  // 0 = channel disabled
            VirtualProtect(chan, 8, oldp, &oldp);
            LogF(L"[audio_silence] FLog::FMOD channel disabled (error spam suppressed)\n");
        }
    }
}
