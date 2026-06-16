/*
 * RbxInject.dll - tiny injector for RobloxStudioPatcher.dll
 *
 * The whole point of this DLL is to be as small and structurally trivial as
 * possible so stud_pe can add an import for it to RobloxStudioBeta.exe /
 * RobloxPlayerBeta.exe without corrupting the PE.
 *
 * No CRT entry point, no STL, no statics. Just kernel32 imports and two
 * calls to LoadLibraryW. Built as pure C with /MT static CRT and almost no
 * code in there, so the DLL on disk is a few KB.
 *
 * IMPORTANT - must be compiled x64 (/MACHINE:X64) to match the 64-bit
 * RobloxStudioBeta.exe. An x86 DLL injected into an x64 process causes
 * "application was unable to start correctly (0xc000007b)".
 *
 * Behavior:
 *   1. On DLL_PROCESS_ATTACH, build the absolute path of
 *      "<dir-of-this-dll>\RobloxStudioPatcher.dll" and LoadLibraryW it.
 *   2. Do the same for HookedWebserver.dll.
 *   3. If either load fails (DLL missing, etc.) we silently continue.
 *      The host EXE runs normally without that feature.
 *
 * Why the load happens inside DllMain (not on a thread):
 *   The patcher needs to install its IAT hook BEFORE the host EXE reads its
 *   command line for the first time. The EXE's CRT init runs immediately
 *   after our DllMain returns, so a delayed thread-based load would race
 *   and lose. LoadLibrary inside DllMain is technically discouraged because
 *   of loader-lock concerns, but kernel32 is already initialized at this
 *   point and the patcher only depends on kernel32 + user32 (also loaded),
 *   so there's no realistic deadlock risk here.
 *
 * Imports: kernel32.lib ONLY. This is intentional - extra import DLLs
 * increase the IAT size and can corrupt adjacent PE sections when stud_pe
 * patches the import table.
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

    /* Get our own directory once; both DLLs live next to us. */
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(hModule, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return TRUE;

    /* Walk back to the last path separator so n points just after the
     * trailing backslash (directory portion only). */
    while (n > 0 && path[n - 1] != L'\\' && path[n - 1] != L'/')
        --n;

    /* --- Load RobloxStudioPatcher.dll --- */
    {
        static const wchar_t kName[] = L"RobloxStudioPatcher.dll";
        DWORD i = 0;
        while (kName[i] != 0 && (n + i + 1) < MAX_PATH)
        {
            path[n + i] = kName[i];
            ++i;
        }
        path[n + i] = 0;

        HMODULE h = LoadLibraryW(path);
        (void)h;
    }

    /* --- Load HookedWebserver.dll --- */
    {
        static const wchar_t kName[] = L"HookedWebserver.dll";
        DWORD i = 0;
        while (kName[i] != 0 && (n + i + 1) < MAX_PATH)
        {
            path[n + i] = kName[i];
            ++i;
        }
        path[n + i] = 0;

        HMODULE h = LoadLibraryW(path);
        (void)h;
    }

    return TRUE;
}