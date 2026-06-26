// webview_skip.cpp - see webview_skip.h.
//
// Implements a minimal fake WebView2 COM tree (Environment -> Controller ->
// CoreWebView2 + event-arg objects) that, instead of rendering a browser,
// immediately fires Studio's NavigationStarting handler with the OAuth redirect
// URL carrying the hard-coded auth code and Studio's own per-login `state`.
//
// Vtable slot numbers below are the documented, ABI-stable WebView2 layouts.
// They were cross-checked against this exact Studio build (0.725.x): Studio's
// DOMContentLoaded handler calls ICoreWebView2::ExecuteScript at vtable slot 29
// (offset 0xE8), which matches the documented base-interface ordering used here.
//
// Everything is single-instance (one login per process) and intentionally
// leaks its tiny COM objects - simpler and safe for a process-lifetime shim.

#include "webview_skip.h"
#include "patcher.h"
#include "iat_hook.h"

#include <objbase.h>      // CoTaskMemAlloc
#include <string>
#include <cstring>
#include <cstdint>

#pragma comment(lib, "ole32.lib")

namespace RobloxStudioPatcher
{
    // ---- config ---------------------------------------------------------
    // The auth code HookedWebserver hands out at /oauth/v1/authorize and
    // accepts at /oauth/v1/token. Must match the webserver.
    static const wchar_t* kAuthCode = L"hardcoded_auth_code_2023";
    // Default redirect scheme Studio registers for the embedded login.
    static const wchar_t* kDefaultRedirect = L"roblox-studio-auth:/";

    // ---- documented WebView2 vtable slots -------------------------------
    enum {
        // IUnknown (every interface)
        S_QI = 0, S_AddRef = 1, S_Release = 2,
        // ICoreWebView2Environment
        ENV_CreateController = 3, ENV_BrowserVersion = 5,
        // ICoreWebView2Controller
        CTRL_put_IsVisible = 4, CTRL_put_Bounds = 6,
        CTRL_Close = 24, CTRL_get_CoreWebView2 = 25,
        // ICoreWebView2
        WV_get_Settings = 3, WV_Navigate = 5,
        WV_add_NavigationStarting = 7, WV_add_NavigationCompleted = 15,
        WV_AddScriptToExecuteOnDocumentCreated = 27, WV_ExecuteScript = 29,
        WV_add_WebMessageReceived = 34,
        // event-arg / completed-handler Invoke
        H_Invoke = 3,
        // ICoreWebView2NavigationStartingEventArgs
        NSA_get_Uri = 3, NSA_get_IsUserInitiated = 4, NSA_get_IsRedirected = 5,
        NSA_get_RequestHeaders = 6, NSA_get_Cancel = 7, NSA_put_Cancel = 8,
        NSA_get_NavigationId = 9,
        // ICoreWebView2NavigationCompletedEventArgs
        NCA_get_IsSuccess = 3, NCA_get_WebErrorStatus = 4, NCA_get_NavigationId = 5,
    };

    static const UINT WM_WV_ENVDONE  = WM_APP + 0x51;
    static const UINT WM_WV_CTRLDONE = WM_APP + 0x52;
    static const UINT WM_WV_NAVSTART = WM_APP + 0x53;
    static const UINT WM_WV_NAVDONE  = WM_APP + 0x54;

    // ---- a fake COM object is just a vtable pointer ---------------------
    struct ComObj { void** vtbl; };

    // Vtables (generously sized; unused slots -> a benign S_OK stub).
    static void* g_envVtbl[80];
    static void* g_ctrlVtbl[80];
    static void* g_wvVtbl[140];
    static void* g_setVtbl[80];
    static void* g_nsaVtbl[24];
    static void* g_ncaVtbl[24];
    static void* g_hdrVtbl[24];

    static ComObj g_env, g_ctrl, g_wv, g_settings, g_nsa, g_nca, g_hdr;

    // Captured Studio callbacks / state.
    static void*        g_envHandler   = nullptr;   // CreateEnvironment completed
    static void*        g_ctrlHandler  = nullptr;   // CreateController completed
    static void*        g_navStartCb   = nullptr;   // NavigationStarting handler
    static void*        g_navDoneCb    = nullptr;   // NavigationCompleted handler
    static std::wstring g_redirectUrl;              // roblox-studio-auth:/?code=...&state=...
    static HWND         g_pumpWnd      = nullptr;
    static volatile LONG g_built       = 0;

    // Hook trampolines (real exports, used for pass-through on Windows).
    typedef HRESULT (STDMETHODCALLTYPE *PFN_CreateEnv)(PCWSTR, PCWSTR, void*, void*);
    typedef HRESULT (STDMETHODCALLTYPE *PFN_GetAvail)(PCWSTR, LPWSTR*);
    static PFN_CreateEnv g_realCreateEnv = nullptr;
    static PFN_GetAvail  g_realGetAvail  = nullptr;

    // ---- helpers --------------------------------------------------------
    static LPWSTR DupCoTask(const wchar_t* s)
    {
        size_t n = (wcslen(s) + 1) * sizeof(wchar_t);
        void* p = CoTaskMemAlloc(n);
        if (p) memcpy(p, s, n);
        return (LPWSTR)p;
    }

    // Extract value of query param `key=` from a wide URL into out (raw,
    // un-decoded; OAuth state/redirect_uri are URL-safe for our purposes).
    static bool ExtractParam(const wchar_t* url, const wchar_t* key, std::wstring& out)
    {
        if (!url) return false;
        std::wstring u(url), k(key);
        size_t pos = 0;
        while ((pos = u.find(k, pos)) != std::wstring::npos)
        {
            // must be preceded by ? or & (or start) to be a real param
            if (pos == 0 || u[pos - 1] == L'?' || u[pos - 1] == L'&')
            {
                size_t v = pos + k.size();
                size_t e = u.find_first_of(L"&#", v);
                out = u.substr(v, (e == std::wstring::npos) ? std::wstring::npos : e - v);
                return true;
            }
            pos += k.size();
        }
        return false;
    }

    // Minimal %XX decode (for redirect_uri which Studio percent-encodes).
    static std::wstring UrlDecode(const std::wstring& s)
    {
        std::wstring o; o.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i)
        {
            if (s[i] == L'%' && i + 2 < s.size())
            {
                auto hex = [](wchar_t c)->int{
                    if (c >= L'0' && c <= L'9') return c - L'0';
                    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
                    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
                    return -1; };
                int hi = hex(s[i + 1]), lo = hex(s[i + 2]);
                if (hi >= 0 && lo >= 0) { o.push_back((wchar_t)((hi << 4) | lo)); i += 2; continue; }
            }
            o.push_back(s[i]);
        }
        return o;
    }

    static void CallHandlerInvoke3(void* handler, void* a2, void* a3)
    {
        if (!handler) return;
        void** vt = *(void***)handler;
        typedef HRESULT (STDMETHODCALLTYPE *Fn)(void*, void*, void*);
        __try { ((Fn)vt[H_Invoke])(handler, a2, a3); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        { LogF(L"[webview_skip] SEH in handler Invoke\n"); }
    }

    static void AddRefObj(void* o)
    { if (o) { void** vt = *(void***)o; typedef ULONG(STDMETHODCALLTYPE*Fn)(void*); ((Fn)vt[S_AddRef])(o); } }

    // ---- generic IUnknown shared by all fake objects --------------------
    static HRESULT STDMETHODCALLTYPE Gen_QI(void* self, void* /*riid*/, void** ppv)
    { if (ppv) *ppv = self; return S_OK; }              // promiscuous: same object
    static ULONG STDMETHODCALLTYPE Gen_AddRef(void* /*self*/) { return 2; }
    static ULONG STDMETHODCALLTYPE Gen_Release(void* /*self*/) { return 1; }

    // Benign default for every unimplemented slot: succeed, touch nothing.
    static HRESULT STDMETHODCALLTYPE Gen_Ok(void* /*self*/) { return S_OK; }

    // ---- ICoreWebView2NavigationStartingEventArgs -----------------------
    static HRESULT STDMETHODCALLTYPE NSA_Uri(void* /*self*/, LPWSTR* uri)
    { if (uri) *uri = DupCoTask(g_redirectUrl.c_str()); return S_OK; }
    static HRESULT STDMETHODCALLTYPE NSA_UserInit(void* /*self*/, BOOL* b){ if (b) *b = FALSE; return S_OK; }
    static HRESULT STDMETHODCALLTYPE NSA_Redirected(void* /*self*/, BOOL* b){ if (b) *b = TRUE; return S_OK; }
    static HRESULT STDMETHODCALLTYPE NSA_Headers(void* /*self*/, void** h){ if (h) *h = &g_hdr; return S_OK; }
    static HRESULT STDMETHODCALLTYPE NSA_GetCancel(void* /*self*/, BOOL* b){ if (b) *b = FALSE; return S_OK; }
    static HRESULT STDMETHODCALLTYPE NSA_PutCancel(void* /*self*/, BOOL /*b*/){ return S_OK; }
    static HRESULT STDMETHODCALLTYPE NSA_NavId(void* /*self*/, UINT64* id){ if (id) *id = 1; return S_OK; }

    // ---- ICoreWebView2NavigationCompletedEventArgs ----------------------
    static HRESULT STDMETHODCALLTYPE NCA_IsSuccess(void* /*self*/, BOOL* b){ if (b) *b = FALSE; return S_OK; }
    static HRESULT STDMETHODCALLTYPE NCA_ErrStatus(void* /*self*/, int* s){ if (s) *s = 0; return S_OK; }
    static HRESULT STDMETHODCALLTYPE NCA_NavId(void* /*self*/, UINT64* id){ if (id) *id = 1; return S_OK; }

    // ---- ICoreWebView2 (the fake browser) -------------------------------
    static HRESULT STDMETHODCALLTYPE WV_Settings(void* /*self*/, void** out){ if (out) *out = &g_settings; return S_OK; }

    static HRESULT STDMETHODCALLTYPE WV_AddNavStarting(void* /*self*/, void* handler, UINT64* token)
    { g_navStartCb = handler; AddRefObj(handler); if (token) *token = 1; return S_OK; }
    static HRESULT STDMETHODCALLTYPE WV_AddNavCompleted(void* /*self*/, void* handler, UINT64* token)
    { g_navDoneCb = handler; AddRefObj(handler); if (token) *token = 2; return S_OK; }
    static HRESULT STDMETHODCALLTYPE WV_AddWebMsg(void* /*self*/, void* /*handler*/, UINT64* token)
    { if (token) *token = 3; return S_OK; }

    static HRESULT STDMETHODCALLTYPE WV_AddScript(void* /*self*/, LPCWSTR /*js*/, void* completed)
    { if (completed) CallHandlerInvoke3(completed, (void*)(intptr_t)S_OK, (void*)L"1"); return S_OK; }
    static HRESULT STDMETHODCALLTYPE WV_Exec(void* /*self*/, LPCWSTR /*js*/, void* completed)
    { if (completed) CallHandlerInvoke3(completed, (void*)(intptr_t)S_OK, (void*)L"null"); return S_OK; }

    static HRESULT STDMETHODCALLTYPE WV_DoNavigate(void* /*self*/, LPCWSTR url)
    {
        // url = http://localhost/oauth/v1/authorize?...&state=XXX&redirect_uri=YYY
        // Build the redirect the real browser would have produced, echoing
        // Studio's own state so any state check passes.
        std::wstring state, redirect = kDefaultRedirect;
        std::wstring tmp;
        if (ExtractParam(url, L"redirect_uri=", tmp) && !tmp.empty())
            redirect = UrlDecode(tmp);
        ExtractParam(url, L"state=", state);

        std::wstring loc = redirect;
        loc += (loc.find(L'?') == std::wstring::npos) ? L"?" : L"&";
        loc += L"code="; loc += kAuthCode;
        if (!state.empty()) { loc += L"&state="; loc += state; }
        g_redirectUrl = loc;

        LogF(L"[webview_skip] Navigate intercepted; feeding redirect: %s\n", g_redirectUrl.c_str());
        if (g_pumpWnd) PostMessageW(g_pumpWnd, WM_WV_NAVSTART, 0, 0);
        return S_OK;
    }

    // ---- ICoreWebView2Controller ----------------------------------------
    static HRESULT STDMETHODCALLTYPE CTRL_GetWebView(void* /*self*/, void** out)
    { if (out) { *out = &g_wv; } return S_OK; }
    static HRESULT STDMETHODCALLTYPE CTRL_DoClose(void* /*self*/) { return S_OK; }

    // ---- ICoreWebView2Environment ---------------------------------------
    static HRESULT STDMETHODCALLTYPE ENV_CreateCtrl(void* /*self*/, HWND /*parent*/, void* completed)
    {
        g_ctrlHandler = completed; AddRefObj(completed);
        if (g_pumpWnd) PostMessageW(g_pumpWnd, WM_WV_CTRLDONE, 0, 0);
        return S_OK;
    }
    static HRESULT STDMETHODCALLTYPE ENV_Version(void* /*self*/, LPWSTR* out)
    { if (out) *out = DupCoTask(L"120.0.2210.91"); return S_OK; }

    // ---- message pump (mimics WebView2's async callbacks) ---------------
    static LRESULT CALLBACK PumpProc(HWND h, UINT m, WPARAM w, LPARAM l)
    {
        switch (m)
        {
        case WM_WV_ENVDONE:
            CallHandlerInvoke3(g_envHandler, (void*)(intptr_t)S_OK, &g_env);
            return 0;
        case WM_WV_CTRLDONE:
            CallHandlerInvoke3(g_ctrlHandler, (void*)(intptr_t)S_OK, &g_ctrl);
            return 0;
        case WM_WV_NAVSTART:
            // sender = ICoreWebView2*, args = NavigationStartingEventArgs*
            CallHandlerInvoke3(g_navStartCb, &g_wv, &g_nsa);
            PostMessageW(h, WM_WV_NAVDONE, 0, 0);
            return 0;
        case WM_WV_NAVDONE:
            CallHandlerInvoke3(g_navDoneCb, &g_wv, &g_nca);
            return 0;
        }
        return DefWindowProcW(h, m, w, l);
    }

    static void BuildVtables()
    {
        if (InterlockedCompareExchange(&g_built, 1, 0) != 0) return;

        // every slot defaults to a safe S_OK stub
        for (int i = 0; i < (int)(sizeof(g_envVtbl) / sizeof(void*)); ++i) g_envVtbl[i] = (void*)&Gen_Ok;
        for (int i = 0; i < (int)(sizeof(g_ctrlVtbl) / sizeof(void*)); ++i) g_ctrlVtbl[i] = (void*)&Gen_Ok;
        for (int i = 0; i < (int)(sizeof(g_wvVtbl) / sizeof(void*)); ++i) g_wvVtbl[i] = (void*)&Gen_Ok;
        for (int i = 0; i < (int)(sizeof(g_setVtbl) / sizeof(void*)); ++i) g_setVtbl[i] = (void*)&Gen_Ok;
        for (int i = 0; i < (int)(sizeof(g_nsaVtbl) / sizeof(void*)); ++i) g_nsaVtbl[i] = (void*)&Gen_Ok;
        for (int i = 0; i < (int)(sizeof(g_ncaVtbl) / sizeof(void*)); ++i) g_ncaVtbl[i] = (void*)&Gen_Ok;
        for (int i = 0; i < (int)(sizeof(g_hdrVtbl) / sizeof(void*)); ++i) g_hdrVtbl[i] = (void*)&Gen_Ok;

        void* vts[] = { g_envVtbl, g_ctrlVtbl, g_wvVtbl, g_setVtbl, g_nsaVtbl, g_ncaVtbl, g_hdrVtbl };
        for (void* vp : vts)
        {
            void** v = (void**)vp;
            v[S_QI] = (void*)&Gen_QI; v[S_AddRef] = (void*)&Gen_AddRef; v[S_Release] = (void*)&Gen_Release;
        }

        g_envVtbl[ENV_CreateController] = (void*)&ENV_CreateCtrl;
        g_envVtbl[ENV_BrowserVersion]   = (void*)&ENV_Version;

        g_ctrlVtbl[CTRL_get_CoreWebView2] = (void*)&CTRL_GetWebView;
        g_ctrlVtbl[CTRL_Close]            = (void*)&CTRL_DoClose;

        g_wvVtbl[WV_get_Settings]                        = (void*)&WV_Settings;
        g_wvVtbl[WV_Navigate]                            = (void*)&WV_DoNavigate;
        g_wvVtbl[WV_add_NavigationStarting]              = (void*)&WV_AddNavStarting;
        g_wvVtbl[WV_add_NavigationCompleted]             = (void*)&WV_AddNavCompleted;
        g_wvVtbl[WV_add_WebMessageReceived]              = (void*)&WV_AddWebMsg;
        g_wvVtbl[WV_AddScriptToExecuteOnDocumentCreated] = (void*)&WV_AddScript;
        g_wvVtbl[WV_ExecuteScript]                       = (void*)&WV_Exec;

        g_nsaVtbl[NSA_get_Uri]            = (void*)&NSA_Uri;
        g_nsaVtbl[NSA_get_IsUserInitiated]= (void*)&NSA_UserInit;
        g_nsaVtbl[NSA_get_IsRedirected]   = (void*)&NSA_Redirected;
        g_nsaVtbl[NSA_get_RequestHeaders] = (void*)&NSA_Headers;
        g_nsaVtbl[NSA_get_Cancel]         = (void*)&NSA_GetCancel;
        g_nsaVtbl[NSA_put_Cancel]         = (void*)&NSA_PutCancel;
        g_nsaVtbl[NSA_get_NavigationId]   = (void*)&NSA_NavId;

        g_ncaVtbl[NCA_get_IsSuccess]      = (void*)&NCA_IsSuccess;
        g_ncaVtbl[NCA_get_WebErrorStatus] = (void*)&NCA_ErrStatus;
        g_ncaVtbl[NCA_get_NavigationId]   = (void*)&NCA_NavId;

        g_env.vtbl = g_envVtbl;  g_ctrl.vtbl = g_ctrlVtbl; g_wv.vtbl = g_wvVtbl;
        g_settings.vtbl = g_setVtbl; g_nsa.vtbl = g_nsaVtbl; g_nca.vtbl = g_ncaVtbl;
        g_hdr.vtbl = g_hdrVtbl;
    }

    static void EnsurePump()
    {
        if (g_pumpWnd) return;
        WNDCLASSW wc = {};
        wc.lpfnWndProc = PumpProc;
        wc.hInstance = g_hSelf;
        wc.lpszClassName = L"OffBloxWV2Pump";
        RegisterClassW(&wc);   // ignore "already registered"
        g_pumpWnd = CreateWindowExW(0, L"OffBloxWV2Pump", L"", 0, 0, 0, 0, 0,
                                    HWND_MESSAGE, nullptr, g_hSelf, nullptr);
        if (!g_pumpWnd)
            LogF(L"[webview_skip] CreateWindowEx(message-only) failed err=%lu\n", GetLastError());
    }

    // ---- hooked exports -------------------------------------------------
    static HRESULT STDMETHODCALLTYPE Hook_GetAvail(PCWSTR folder, LPWSTR* version)
    {
        if (g_realGetAvail)
        {
            __try
            {
                HRESULT hr = g_realGetAvail(folder, version);
                if (SUCCEEDED(hr) && version && *version) return hr;  // real runtime
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        // No runtime: pretend a version exists so Studio proceeds to create the
        // environment (which we then shim).
        if (version) *version = DupCoTask(L"120.0.2210.91");
        return S_OK;
    }

    // Only the FIRST CreateCoreWebView2Environment call is the login dialog;
    // it is the one we shim. Studio opens further WebView2s after login (e.g.
    // the home/start page) which are real content browsers - those must NOT be
    // shimmed (hijacking them feeds the auth redirect to a content view and
    // crashes). Subsequent calls pass through to the real WebView2 runtime.
    static volatile LONG g_loginShimmed = 0;

    static HRESULT STDMETHODCALLTYPE Hook_CreateEnv(PCWSTR folder, PCWSTR dataFolder,
                                                    void* options, void* envHandler)
    {
        if (InterlockedCompareExchange(&g_loginShimmed, 1, 0) != 0)
        {
            // Not the login dialog - hand it to the real runtime untouched.
            LogF(L"[webview_skip] CreateCoreWebView2Environment (post-login) "
                 L"-> real runtime\n");
            if (g_realCreateEnv)
                return g_realCreateEnv(folder, dataFolder, options, envHandler);
            // No real runtime (e.g. Wine): report failure so Studio handles it
            // gracefully (blank content view) instead of us crashing it.
            return E_FAIL;
        }

        // First call = the login dialog. Shim it: never open a WebView window,
        // drive Studio's own login handlers straight to the OAuth redirect.
        LogF(L"[webview_skip] CreateCoreWebView2EnvironmentWithOptions shimmed (login)\n");
        BuildVtables();
        EnsurePump();
        g_envHandler = envHandler; AddRefObj(envHandler);
        if (g_pumpWnd) PostMessageW(g_pumpWnd, WM_WV_ENVDONE, 0, 0);
        return S_OK;
    }

    void StartWebViewLoginSkip()
    {
        bool a = IatHook("WebView2Loader.dll",
                         "CreateCoreWebView2EnvironmentWithOptions",
                         (void*)&Hook_CreateEnv, (void**)&g_realCreateEnv);
        bool b = IatHook("WebView2Loader.dll",
                         "GetAvailableCoreWebView2BrowserVersionString",
                         (void*)&Hook_GetAvail, (void**)&g_realGetAvail);
        LogF(L"[webview_skip] IAT hooks: CreateEnv=%d GetAvail=%d "
             L"(always-skip: WebView2 window never opens on any platform)\n", (int)a, (int)b);
    }
}
