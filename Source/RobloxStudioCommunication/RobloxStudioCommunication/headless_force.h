// headless_force.h
//
// Server-only. Instruments and (optionally) forces the StartServer process onto
// a zero-display headless path so it can run under Wine on a headless Linux box.
//
// The host EXE resolves user32 / d3d11 / dxgi through its OWN loader (kernel32
// is not even in the static import table), so the only reliable interception
// point is the real system-DLL exports. This module inline-hooks:
//   kernel32!GetProcAddress   - logs every display/GPU API the server resolves
//   kernel32!LoadLibraryExW   - logs every graphics DLL the server loads
//   user32!CreateWindowExW    - logs every window the server creates
//
// DEFAULT = log only (pure pass-through; no behaviour change). Forcing is opt-in
// per run via sidecar files next to the DLL (no rebuild needed):
//   headless_block_gfx_dll.txt  -> LoadLibraryExW(d3d11/dxgi/opengl/vulkan) -> NULL
//   headless_stub_d3d.txt       -> GetProcAddress(D3D11CreateDevice/DXGI...) -> E_FAIL stub
//   headless_msgonly_windows.txt-> CreateWindowExW that fails -> retried as a
//                                  message-only window (HWND_MESSAGE; no display)
//
// Pairs with Phase 4j (render_nulldevice) which forces the graphics factory to
// mode 9 (NoGraphics); these hooks reveal/force whatever residual display work
// still happens after that.

#pragma once

namespace RobloxStudioPatcher
{
    void StartHeadlessForce();
}
