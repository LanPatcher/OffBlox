/*
 * RbxInject.dll - tiny injector for RobloxStudioPatcher.dll
 *
 * The whole point of this DLL is to be as small and structurally trivial as
 * possible so stud_pe can add an import for it to RobloxStudioBeta.exe /
 * RobloxPlayerBeta.exe without corrupting the PE.
 *
 * No CRT entry point, no STL, no statics. Just kernel32 imports and one
 * call to LoadLibraryW. Built as pure C with /MT static CRT and almost no
 * code in there, so the DLL on disk is a few KB.
 *
 * Behavior:
 *   1. On DLL_PROCESS_ATTACH, build the absolute path of
 *      "<dir-of-this-dll>\RobloxStudioPatcher.dll"
 *   2. LoadLibraryW that. The real patcher's DllMain then runs synchronously,
 *      installs the GetCommandLineW IAT hook, and spawns its window-hider
 *      thread - all BEFORE the host EXE's CRT init runs and asks for the
 *      command line.
 *   3. If the load fails (patcher missing, etc.) we silently return TRUE.
 *      The host EXE continues normally; the mod just doesn't take effect.
 *
 * Why the load happens inside DllMain (not on a thread):
 *   The patcher needs to install its IAT hook BEFORE the host EXE reads its
 *   command line for the first time. The EXE's CRT init runs immediately
 *   after our DllMain returns, so a delayed thread-based load would race
 *   and lose. LoadLibrary inside DllMain is technically discouraged because
 *   of loader-lock concerns, but kernel32 is already initialized at this
 *   point and the patcher only depends on kernel32 + user32 (also loaded),
 *   so there's no realistic deadlock risk here.
 */

#include <windows.h>

/* Exported so stud_pe has a concrete symbol to point its added import at.
 * The host EXE will end up calling Patch() once during startup; we do
 * nothing because all the work happens in DllMain.
 *
 * Also listed in RbxInject.def to ensure the export name isn't decorated. */
__declspec(dllexport) void Patch(void)
{
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    DisableThreadLibraryCalls(hModule);

    /* Resolve <our-dir>\RobloxStudioPatcher.dll
     *
     * We deliberately avoid CRT helpers (wcscat_s, wcsrchr, swprintf, etc.)
     * so this DLL has zero CRT footprint. Just plain index math. */
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(hModule, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return TRUE;

    /* Walk back to the last path separator so 'path' becomes the
     * directory portion (including the trailing backslash). */
    while (n > 0 && path[n - 1] != L'\\' && path[n - 1] != L'/')
        --n;

    /* Append "RobloxStudioPatcher.dll" without overrunning the buffer. */
    static const wchar_t kPatcherName[] = L"RobloxStudioPatcher.dll";
    DWORD i = 0;
    while (kPatcherName[i] != 0 && (n + i + 1) < MAX_PATH)
    {
        path[n + i] = kPatcherName[i];
        ++i;
    }
    path[n + i] = 0;

    /* Best-effort load. We don't check the return value - if it fails,
     * we just want the host EXE to continue running normally without
     * the mod features. */
    HMODULE patcher = LoadLibraryW(path);
    (void)patcher;






    wchar_t path2[MAX_PATH];
    DWORD n2 = GetModuleFileNameW(hModule, path2, MAX_PATH);
    if (n2 == 0 || n2 >= MAX_PATH)
        return TRUE;

    /* Walk back to the last path separator so 'path2' becomes the
     * directory portion (including the trailing backslash). */
    while (n2 > 0 && path2[n2 - 1] != L'\\' && path2[n2 - 1] != L'/')
        --n2;

    /* Append "HookedWebserver.dll" without overrunning the buffer. */
    static const wchar_t kPatcherName2[] = L"HookedWebserver.dll";
    DWORD i2 = 0;
    while (kPatcherName2[i2] != 0 && (n2 + i2 + 1) < MAX_PATH)
    {
        path2[n2 + i2] = kPatcherName2[i2];
        ++i2;
    }
    path2[n2 + i2] = 0;

    /* Best-effort load. We don't check the return value - if it fails,
     * we just want the host EXE to continue running normally without
     * the mod features. */
    HMODULE patcher2 = LoadLibraryW(path2);
    (void)patcher2;

    return TRUE;
}
