// webview_skip.h - skip the WebView2 login window, feed the OAuth response.
//
// Some machines (notably Wine/Linux) have no working Edge WebView2 runtime, so
// Studio's WebView2-based login dialog never loads and authentication hangs.
//
// This module keeps Studio's own login *logic* intact and only replaces the
// WebView2 runtime with a tiny in-process shim. When Studio asks WebView2 to
// create an environment, we synthesize the exact navigation the real browser
// would have produced - a redirect to
//     roblox-studio-auth:/?code=<authcode>&state=<state>
// - and drive Studio's own NavigationStarting handler with it. Studio then
// exchanges the code at /oauth/v1/token (HookedWebserver) exactly as it does on
// Windows, reaching "Authenticated : YES" with no WebView2 window.
//
// ALWAYS SKIP: the WebView2 window is never opened, on ANY platform (Windows
// included). Studio's login is driven straight to the OAuth redirect every time.

#pragma once

namespace RobloxStudioPatcher
{
    // Installs IAT hooks on WebView2Loader.dll!CreateCoreWebView2EnvironmentWithOptions
    // and GetAvailableCoreWebView2BrowserVersionString. Safe to call on any
    // launch; it only does anything once Studio actually starts a WebView2
    // login and only shims when no real runtime exists.
    void StartWebViewLoginSkip();
}
