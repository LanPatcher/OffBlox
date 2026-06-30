// iat_hook.h - Import Address Table hooking
//
// IAT hooking replaces the function pointer the host EXE uses to call an
// imported API. It doesn't touch the original API's code, so it's much
// safer than inline detours and works the same on x86 and x64.
//
// Typical use:
//   PVOID original = nullptr;
//   IatHook("kernel32.dll", "GetCommandLineW", &MyHook, &original);
//   // From now on every call from RobloxStudioBeta.exe to GetCommandLineW
//   // jumps to MyHook instead. Call (LPWSTR(WINAPI*)())original() if you
//   // need the real one.

#pragma once

#include "patcher.h"

namespace RobloxStudioPatcher
{
    // Hooks the IAT entry for `funcName` imported from `dllName` in the
    // currently-running EXE (NOT all loaded modules - just the main module).
    //
    // On success returns true and stores the previous function pointer in
    // *outOriginal so the hook can call through to it. On failure returns
    // false and leaves *outOriginal untouched. Failures are usually:
    //   - The target EXE didn't import that function (most common)
    //   - VirtualProtect failed (very unusual)
    //
    // Thread-safety: not concurrent. Call once during DllMain before any
    // other threads run.
    bool IatHook(const char* dllName,
                 const char* funcName,
                 void* newFunction,
                 void** outOriginal);

    // Fallback for functions resolved via GetProcAddress (not in static IAT).
    // Writes an inline JMP trampoline directly on the ws2_32 export.
    // outOriginal receives an executable stub that calls through to the original.
    bool InlineHook(const char* dllName,
                    const char* funcName,
                    void*  newFunction,
                    void** outOriginal);

    // Raw-VA variant for hooking fixed addresses inside the host EXE itself.
    // Identical mechanics to InlineHook but resolves via a direct VA instead
    // of GetProcAddress. The VA must be within a PAGE_EXECUTE* region.
    //
    // Usage (x86 __thiscall example):
    //   void* trampoline = nullptr;
    //   InlineHookVA(0x0178ED65, &MyDetour, &trampoline);
    //   // real function now callable through trampoline
    //
    // On failure (VirtualProtect error, unrecognised prologue instruction)
    // returns false and writes a log line. outOriginal is untouched on fail.
    bool InlineHookVA(uintptr_t targetVA,
                      void*  newFunction,
                      void** outOriginal);
}
