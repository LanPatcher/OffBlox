/*
 * RbxInject.dll - tiny injector for RobloxStudioPatcher.dll
 *
 * Adds an import to OffBlox.exe (via stud_pe) so this DLL loads with the host.
 * It then loads HookedWebserver.dll and RobloxStudioCommunication.dll, which
 * live next to it.
 *
 * WINDOWS vs WINE:
 *   On Windows we LoadLibraryW inline in DllMain so the patcher's hooks are in
 *   place before the host reads its command line (original, tested timing).
 *
 *   Wine's loader crashes loader_init with c0000005 if we LoadLibraryW these
 *   (large, TLS/CRT-heavy) DLLs re-entrantly while the host's own loader_init
 *   is still running. So under Wine we defer the loads to a worker thread whose
 *   LoadLibraryW runs only AFTER the host finishes loader_init (the thread
 *   blocks on the loader lock until then) - a clean, non-re-entrant load.
 *   We load RobloxStudioCommunication.dll FIRST so its engine hooks apply as
 *   early as possible, then HookedWebserver.dll.
 *
 *   A small RbxInject.log (next to this DLL) records the Wine load path so we
 *   can confirm the thread ran and each DLL loaded.
 *
 * Wine is detected via ntdll!wine_get_version. Imports: kernel32 only.
 */

#include <windows.h>

__declspec(dllexport) void Patch(void) { }

static wchar_t g_dir[MAX_PATH];
static DWORD   g_dirLen = 0;

/* Minimal append logger (kernel32 only) -> "<dir>\RbxInject.log". */
static void Dbg(const char* msg)
{
    wchar_t path[MAX_PATH];
    DWORD i;
    HANDLE h;
    DWORD wrote = 0;
    static const wchar_t name[] = L"RbxInject.log";

    if (g_dirLen == 0 || g_dirLen >= MAX_PATH) return;
    for (i = 0; i < g_dirLen; ++i) path[i] = g_dir[i];
    { DWORD j = 0; while (name[j] && (i + 1) < MAX_PATH) { path[i++] = name[j++]; } path[i] = 0; }

    h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    WriteFile(h, msg, (DWORD)lstrlenA(msg), &wrote, NULL);
    CloseHandle(h);
}

/* Build "<dir><name>" and LoadLibraryW it; log the result handle. */
static void LoadOne(const wchar_t* name, const char* tag)
{
    wchar_t path[MAX_PATH];
    DWORD i = 0, j = 0;
    HMODULE m;
    char buf[64];

    if (g_dirLen == 0 || g_dirLen >= MAX_PATH) return;
    for (i = 0; i < g_dirLen; ++i) path[i] = g_dir[i];
    while (name[j] != 0 && (i + 1) < MAX_PATH) { path[i] = name[j]; ++i; ++j; }
    path[i] = 0;

    m = LoadLibraryW(path);
    { /* "  <tag> = 0x%p\n" without CRT */
        const char* p = tag; char* o = buf; DWORD_PTR v = (DWORD_PTR)m; int k;
        *o++ = ' '; *o++ = ' ';
        while (*p) *o++ = *p++;
        *o++ = '='; *o++ = '0'; *o++ = 'x';
        for (k = (int)(sizeof(void*) * 2) - 1; k >= 0; --k)
        { int nib = (int)((v >> (k * 4)) & 0xF); *o++ = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10); }
        *o++ = '\n'; *o = 0;
    }
    Dbg(buf);
}

static void LoadBoth(void)
{
    /* Load HookedWebserver FIRST. The engine fetches its FastFlags from
     * https://localhost/v2/settings/... within the first ~0.4s of startup and
     * FATALLY exits ("Trouble launching Studio") if that connection fails - so
     * the webserver must be bound before then. RobloxStudioCommunication's
     * SafeInit (especially server mode) is heavy and its hooks aren't needed
     * until the place/players load (seconds later), so it loads second. Under
     * Wine the deferred loader thread previously loaded comm first, which pushed
     * the webserver bind past the settings fetch and intermittently killed the
     * launch; webserver-first removes that race. */
    LoadOne(L"HookedWebserver.dll", "webserver");
    LoadOne(L"RobloxStudioCommunication.dll", "comm");
}

static DWORD WINAPI LoaderThread(LPVOID unused)
{
    (void)unused;
    Dbg("LoaderThread: start\n");
    LoadBoth();
    Dbg("LoaderThread: done\n");
    return 0;
}

static int RunningUnderWine(void)
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    return (nt != NULL) && (GetProcAddress(nt, "wine_get_version") != NULL);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    DisableThreadLibraryCalls(hModule);

    /* directory of this DLL (with trailing separator) */
    {
        wchar_t path[MAX_PATH];
        DWORD n = GetModuleFileNameW(hModule, path, MAX_PATH);
        DWORD k;
        if (n == 0 || n >= MAX_PATH) return TRUE;
        while (n > 0 && path[n - 1] != L'\\' && path[n - 1] != L'/') --n;
        for (k = 0; k < n; ++k) g_dir[k] = path[k];
        g_dir[n] = 0;
        g_dirLen = n;
    }

    if (RunningUnderWine())
    {
        HANDLE t;
        Dbg("DllMain: Wine - deferring loads to thread\n");
        t = CreateThread(NULL, 0, LoaderThread, NULL, 0, NULL);
        if (t) { SetThreadPriority(t, THREAD_PRIORITY_HIGHEST); CloseHandle(t); }
        else   { Dbg("DllMain: CreateThread failed - inline fallback\n"); LoadBoth(); }
    }
    else
    {
        LoadBoth();   /* Windows: inline, original timing */
    }

    return TRUE;
}
