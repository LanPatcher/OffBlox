# RobloxStudioPatcher

A native DLL that turns Roblox Studio 2022 (`RobloxStudioBeta.exe`) into a
silent game client. Same DLL also works against `RobloxPlayerBeta.exe`.
Injected once via stud_pe so the patch is permanent.

## Architecture: two DLLs

The solution builds **two** DLLs:

1. **`RbxInject.dll`** - a tiny pure-C injector (~5 KB). The ONLY thing it
   does is `LoadLibraryW("RobloxStudioPatcher.dll")` from its own folder.
   This is what stud_pe imports into Roblox's PE.
2. **`RobloxStudioPatcher.dll`** - the real mod. Loaded at runtime by the
   injector. Never touched by stud_pe.

Why split it up:

- **Smaller PE modification.** A short DLL name (`RbxInject.dll`) and a
  tiny target file are far less likely to trip stud_pe's import-table
  rewriting than a full 200 KB C++ DLL with a long name.
- **Iteration speed.** Once `RbxInject.dll` is wired into the EXE, you
  can rebuild and replace `RobloxStudioPatcher.dll` as many times as you
  want without re-running stud_pe.
- **Easy rollback.** Delete `RobloxStudioPatcher.dll` and the injector
  silently does nothing - the EXE still runs.

## What the mod does

1. **Hides every Qt5 window.** Login window, menubars, toolbars, dock
   widgets, and the 3D viewport host (`Qt5*` HWNDs) get `ShowWindow(SW_HIDE)`
   as soon as they appear.
2. **Dismisses the login window.** Any HWND whose title contains "Login",
   "Sign In", "Log In", or "Authenticate" gets a `WM_CLOSE` posted to it.
3. **Locally overrides the username.** Reads `username.txt` from beside
   the patcher DLL and appends `-username "X"` to Studio's command line
   via an IAT hook on `kernel32!GetCommandLineW`.

Pure Win32 + STL with the static CRT (`/MT`). No NuGet, no Detours, no
MinHook, no runtime to deploy.

## Build

Requirements: Visual Studio 2019 or 2022 with **Desktop development with C++**.

1. Open `RobloxStudioPatcher.sln`.
2. Pick the right config in the toolbar:
   - **`Release | x64`** for 64-bit Roblox builds
   - **`Release | Win32`** for 32-bit Roblox builds (most older clients)
3. Build → Build Solution. Both DLLs build at once.

Outputs (Release|x64 shown - swap `x64` for `Win32` if you built that):
- `RobloxStudioPatcher\x64\Release\RobloxStudioPatcher.dll`
- `RbxInject\x64\Release\RbxInject.dll`

## How to check bitness of your Roblox EXE

In stud_pe, open the EXE. The top header shows `Bitness 32` or `Bitness 64`.
Match the DLL build to that. An x64 DLL injected into a Win32 EXE causes
the exact "0xC0000005" error you saw.

## Install via stud_pe

1. Copy **both** DLLs into the same folder as `RobloxStudioBeta.exe`
   (e.g. `Clients\2022M\Studio\`):
   - `RbxInject.dll`
   - `RobloxStudioPatcher.dll`
2. Create `username.txt` next to the patcher DLL containing just the
   username, one line, no quotes. The launcher can write this file from
   `textBox1.Text` right before launching Studio.
3. Open stud_pe → File → Open → `RobloxStudioBeta.exe`.
4. Right-click the imports list → **Add new import**.
5. **Library name:** `RbxInject.dll` (the small one)
6. **New function:** `Patch`
7. Apply → Save the modified EXE.

That's it. Next launch:

- Windows loads `RbxInject.dll` because the EXE imports it.
- `RbxInject`'s `DllMain` immediately `LoadLibraryW`'s `RobloxStudioPatcher.dll`
  from the same folder.
- The patcher installs the GetCommandLineW IAT hook synchronously - before
  the host EXE's CRT init reads the command line.
- The patcher's Qt-hider thread starts polling 100ms later.

## Troubleshooting

### 0xC0000005 on launch

Run through these in order:

1. **Bitness mismatch.** Check the EXE's bitness in stud_pe and rebuild
   the DLLs for the matching platform. This is by far the most common
   cause.
2. **stud_pe corrupted the PE.** Test with a probe-only build to isolate:
   add `ROBLOX_PATCHER_PROBE_ONLY` to the `RobloxStudioPatcher` project's
   preprocessor definitions and rebuild. If the EXE still crashes with
   that probe attached, the modification is the problem, not our code.
   Try a fresh copy of the EXE and re-do the stud_pe step, making sure
   you only add ONE new import row and don't touch anything else.
3. **Missing patcher.** If `RobloxStudioPatcher.dll` isn't next to the
   EXE, the injector silently does nothing. That's safe (the EXE runs)
   but the mod won't work. Confirm both DLLs are in the EXE's folder.

### EXE icon disappears in Explorer

This is a known cosmetic side effect of stud_pe extending the PE's
section table - it can shift the resource directory. The EXE still runs
correctly; only the icon is gone. If that bothers you, use Resource Hacker
to re-inject the original icon after stud_pe is done.

### Verifying the mod is running

In the patcher's `RobloxStudioPatcher` project, add `ROBLOX_PATCHER_LOG`
to the preprocessor definitions and rebuild. Then run
[DbgView](https://learn.microsoft.com/sysinternals/downloads/debugview)
as administrator while launching the patched EXE. You should see:

```
[RobloxStudioPatcher] attached to pid 12345
[username_patch] hook installed (original at 0x...)
[username_patch] cmdline now: ... -username "PlayerName"
[qt_hider] hid HWND 0x...
[qt_hider] hid HWND 0x...
```

## File map

```
RobloxStudioPatcher.sln

RobloxStudioPatcher/                 the actual mod (C++, ~200 KB)
├── RobloxStudioPatcher.vcxproj
├── RobloxStudioPatcher.def
├── patcher.h
├── iat_hook.h / .cpp
├── qt_hider.h / .cpp
├── username_patch.h / .cpp
└── dllmain.cpp

RbxInject/                           the tiny injector (C, ~5 KB)
├── RbxInject.vcxproj
├── RbxInject.def
└── dllmain.c
```
