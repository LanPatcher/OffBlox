// script_start_hook.cpp
//
// PLACEHOLDER - hook target not yet identified.
//
// The correct intercept point is the function that directly calls lua_resume
// (or equivalent) on task thread 11b74. Its VA must be found via x32dbg before
// this module does anything useful.
//
// NetworkServer::Start (0x0178ED65) is NOT the right place:
//   - Start runs on a separate thread from the Lua launcher
//   - Blocking or fake-returning there leaves NetworkServer uninitialised,
//     causing the task body after Start to hang, which the WatcherThread
//     detects at ~1s and kills with StartProcessException.

#include "script_start_hook.h"
#include "iat_hook.h"
#include <cstdint>

#ifndef _WIN64

namespace RobloxStudioPatcher
{
    static HANDLE s_allowEvent = nullptr;
    static LONG   s_eventOnce  = 0;

    static HANDLE GetOrCreateEvent()
    {
        if (InterlockedCompareExchange(&s_eventOnce, 1, 0) == 0)
        {
            s_allowEvent = CreateEventW(
                nullptr, TRUE, FALSE,
                L"Local\\RobloxStudioPatcher_ScriptStart");
            if (!s_allowEvent)
                LogF(L"[script_start_hook] CreateEventW failed (err=%lu)\n", GetLastError());
            else
                LogF(L"[script_start_hook] event %s\n",
                     GetLastError() == ERROR_ALREADY_EXISTS ? L"opened" : L"created");
        }
        else
        {
            for (int i = 0; !s_allowEvent && i < 10000; ++i) Sleep(0);
        }
        return s_allowEvent;
    }

    void InstallScriptStartHook()
    {
        // No-op until the correct Lua-launch VA is identified.
        // To find it:
        //   1. Run with this no-op build (scripts will start normally).
        //   2. In x32dbg, attach and set a breakpoint on lua_resume.
        //      Alternatively break on the Roblox print function (find via
        //      scanning for the "print" string xref in RobloxStudioBeta.exe).
        //   3. When the breakpoint hits, open the call stack panel.
        //   4. Walk up until you see a frame on thread 11b74 that is the
        //      topmost C++ function called from the task scheduler body
        //      (i.e. the function the task scheduler calls that eventually
        //      reaches lua_resume).
        //   5. Record that VA and replace kTargetVA below.
        LogF(L"[script_start_hook] no-op (Lua-launch VA not yet identified)\n");
        GetOrCreateEvent(); // create the event now so the launcher can open it early
    }

    void AllowScriptStart()
    {
        HANDLE ev = GetOrCreateEvent();
        if (ev) SetEvent(ev);
        LogF(L"[script_start_hook] AllowScriptStart() called\n");
    }

} // namespace RobloxStudioPatcher

#else

namespace RobloxStudioPatcher
{
    void InstallScriptStartHook() {}
    void AllowScriptStart() {}
}

#endif
