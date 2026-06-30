/*
 * StandaloneLoader.c
 * ==================
 * Tiny host process that loads HookedWebserver.dll directly.
 * Use this to test the server WITHOUT needing Stud_PE / Roblox Studio.
 *
 * Build (from HookedWebserver\ directory, using the same VS tools):
 *   cl /nologo /O1 /MT StandaloneLoader.c /link /OUT:StandaloneLoader.exe kernel32.lib user32.lib
 *
 * Or just double-click RunStandalone.bat which does this automatically.
 *
 * The DLL will auto-start its server in a background thread.
 * Keep this window open -- closing it shuts the server down.
 */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    char dllPath[MAX_PATH];
    GetModuleFileNameA(NULL, dllPath, MAX_PATH);
    /* strip exe name, append DLL name */
    char *slash = strrchr(dllPath, '\\');
    if (slash) strcpy(slash + 1, "HookedWebserver.dll");

    printf("[Loader] Loading: %s\n", dllPath);

    HMODULE hDll = LoadLibraryA(dllPath);
    if (!hDll) {
        DWORD err = GetLastError();
        printf("[Loader] FAILED to load DLL. Error: %lu\n", err);
        printf("[Loader] Common causes:\n");
        printf("         - DLL not compiled yet (run Build.bat first)\n");
        printf("         - Missing MSVC runtime (use /MT in build)\n");
        printf("         - Wrong architecture (must be x86 to match this loader)\n");
        printf("\nPress any key to exit...\n");
        getchar();
        return 1;
    }

    printf("[Loader] DLL loaded OK. Server starting in background...\n");
    printf("[Loader] Check HookedWebserver.log for startup status.\n");
    printf("[Loader] HTTP: http://localhost/ping\n");
    printf("[Loader] Press Enter to shut down.\n\n");

    /* Give the startup thread a moment to initialize */
    Sleep(1500);

    /* Read and tail the log */
    char logPath[MAX_PATH];
    GetModuleFileNameA(NULL, logPath, MAX_PATH);
    char *sl2 = strrchr(logPath, '\\');
    if (sl2) strcpy(sl2 + 1, "HookedWebserver.log");

    FILE *log = fopen(logPath, "rb");
    if (log) {
        fseek(log, 0, SEEK_END);
        long sz = ftell(log);
        if (sz > 2000) fseek(log, sz - 2000, SEEK_SET);
        else rewind(log);
        char buf[2100] = {0};
        fread(buf, 1, sizeof(buf)-1, log);
        fclose(log);
        printf("--- HookedWebserver.log (tail) ---\n%s\n---\n\n", buf);
    }

    getchar(); /* wait for Enter */

    printf("[Loader] Shutting down...\n");

    /* Call HWS_Stop if exported */
    typedef void (WINAPI *PFN_Stop)(void);
    PFN_Stop pfnStop = (PFN_Stop)GetProcAddress(hDll, "HWS_Stop");
    if (pfnStop) pfnStop();

    Sleep(500);
    FreeLibrary(hDll);
    printf("[Loader] Done.\n");
    return 0;
}
