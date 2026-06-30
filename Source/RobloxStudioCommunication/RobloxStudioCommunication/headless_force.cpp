// headless_force.cpp - see headless_force.h.

#include "headless_force.h"
#include "iat_hook.h"     // InlineHook
#include "patcher.h"      // LogF, GetDllDirectory

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cwchar>

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();

    // ---- original (trampoline) function pointers -------------------------
    typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
    typedef HMODULE (WINAPI *LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
    typedef HWND    (WINAPI *CreateWindowExW_t)(DWORD, LPCWSTR, LPCWSTR, DWORD,
                                                int, int, int, int,
                                                HWND, HMENU, HINSTANCE, LPVOID);

    static GetProcAddress_t   o_GetProcAddress  = nullptr;
    static LoadLibraryExW_t   o_LoadLibraryExW  = nullptr;
    static CreateWindowExW_t  o_CreateWindowExW = nullptr;

    // Reentrancy guard: GetProcAddress is hot and our logging path must never
    // recurse back into the hook.
    static thread_local int s_inHook = 0;

    // ---- sidecar toggles (checked per call; cheap, lets the user flip forcing
    //      without a rebuild) -------------------------------------------------
    static bool Sidecar(const wchar_t* name)
    {
        std::wstring p = GetDllDirectory() + name;
        return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
    }

    static bool ContainsCI(const char* hay, const char* needle)
    {
        if (!hay || !needle) return false;
        size_t nl = std::strlen(needle);
        for (const char* p = hay; *p; ++p)
            if (_strnicmp(p, needle, nl) == 0) return true;
        return false;
    }
    static bool ContainsCIW(const wchar_t* hay, const wchar_t* needle)
    {
        if (!hay || !needle) return false;
        size_t nl = wcslen(needle);
        for (const wchar_t* p = hay; *p; ++p)
            if (_wcsnicmp(p, needle, nl) == 0) return true;
        return false;
    }

    // A proc name worth logging (display / GPU / window surface APIs).
    static bool IsDisplayProc(const char* n)
    {
        static const char* k[] = {
            "CreateWindowEx", "RegisterClass", "D3D11", "D3D12", "D3D10",
            "DXGI", "CreateDevice", "wglCreate", "wglMake", "vkCreate",
            "ChoosePixelFormat", "SetPixelFormat", "EnumDisplay",
            "GetDC", "OpenGL", "glX", "DwmFlush", "DCompositionCreate"
        };
        for (auto s : k) if (ContainsCI(n, s)) return true;
        return false;
    }
    // A proc whose resolution we should fail when headless_stub_d3d.txt is set.
    static bool IsD3DCreateProc(const char* n)
    {
        return ContainsCI(n, "D3D11CreateDevice")
            || ContainsCI(n, "D3D12CreateDevice")
            || ContainsCI(n, "CreateDXGIFactory")
            || ContainsCI(n, "D3D10CreateDevice");
    }
    static bool IsGfxDll(const wchar_t* n)
    {
        static const wchar_t* k[] = {
            L"d3d11", L"d3d12", L"d3d10", L"dxgi", L"opengl32",
            L"vulkan-1", L"vulkan", L"d3dcompiler", L"dcomp"
        };
        for (auto s : k) if (ContainsCIW(n, s)) return true;
        return false;
    }

    // Generic failing stub for D3D/DXGI creation entrypoints. In x64 the callee
    // never cleans the stack, so a no-arg stub safely stands in for any of them;
    // the engine sees E_FAIL (0x80004005) and treats the backend as unavailable.
    static HRESULT WINAPI Stub_FailHResult()
    {
        return (HRESULT)0x80004005L;   // E_FAIL
    }

    // ---- hooks -----------------------------------------------------------
    static FARPROC WINAPI Hk_GetProcAddress(HMODULE mod, LPCSTR name)
    {
        FARPROC real = o_GetProcAddress(mod, name);

        // Ordinal imports (name is a small integer) and reentrant calls: pass.
        if (s_inHook || !name || (((uintptr_t)name) >> 16) == 0)
            return real;

        if (IsDisplayProc(name))
        {
            ++s_inHook;
            wchar_t modPath[MAX_PATH]; modPath[0] = 0;
            GetModuleFileNameW(mod, modPath, MAX_PATH);
            LogF(L"[headless] GetProcAddress('%hs') from %s -> %p\n",
                 name, modPath[0] ? modPath : L"(module)", (void*)real);

            if (real && IsD3DCreateProc(name) && Sidecar(L"headless_stub_d3d.txt"))
            {
                LogF(L"[headless] FORCING '%hs' -> E_FAIL stub (headless_stub_d3d.txt)\n", name);
                --s_inHook;
                return reinterpret_cast<FARPROC>(&Stub_FailHResult);
            }
            --s_inHook;
        }
        return real;
    }

    static HMODULE WINAPI Hk_LoadLibraryExW(LPCWSTR file, HANDLE h, DWORD flags)
    {
        if (!s_inHook && file && IsGfxDll(file))
        {
            ++s_inHook;
            const bool block = Sidecar(L"headless_block_gfx_dll.txt");
            LogF(L"[headless] LoadLibraryExW('%s')%s\n",
                 file, block ? L"  -> BLOCKED (headless_block_gfx_dll.txt)" : L"");
            --s_inHook;
            if (block) { SetLastError(ERROR_MOD_NOT_FOUND); return nullptr; }
        }
        return o_LoadLibraryExW(file, h, flags);
    }

    static HWND WINAPI Hk_CreateWindowExW(DWORD exStyle, LPCWSTR cls, LPCWSTR title,
                                          DWORD style, int x, int y, int w, int hgt,
                                          HWND parent, HMENU menu, HINSTANCE inst,
                                          LPVOID param)
    {
        HWND r = o_CreateWindowExW(exStyle, cls, title, style, x, y, w, hgt,
                                   parent, menu, inst, param);

        if (!s_inHook)
        {
            ++s_inHook;
            // cls may be an atom (low integer) rather than a string pointer.
            const bool clsIsStr = cls && ((((uintptr_t)cls) >> 16) != 0);
            LogF(L"[headless] CreateWindowExW class='%s' title='%s' -> %p\n",
                 clsIsStr ? cls : L"(atom)",
                 (title && (((uintptr_t)title) >> 16)) ? title : L"",
                 (void*)r);

            // Forcing: if the real call failed (typical under a headless Wine
            // null display driver) retry as a message-only window, which needs
            // no display and still gives the engine a valid HWND to hold.
            if (!r && Sidecar(L"headless_msgonly_windows.txt"))
            {
                HWND r2 = o_CreateWindowExW(0, cls, title,
                                            style & ~(WS_VISIBLE | WS_CHILD),
                                            0, 0, 0, 0,
                                            HWND_MESSAGE, nullptr, inst, param);
                LogF(L"[headless] FORCING message-only window retry -> %p\n", (void*)r2);
                --s_inHook;
                return r2;
            }
            --s_inHook;
        }
        return r;
    }

    void StartHeadlessForce()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        // OFF by default. Inline-hooking kernel32!GetProcAddress / user32!
        // CreateWindowExW process-wide is risky (it regressed engine startup), so
        // these diagnostics only install when explicitly opted in via a sidecar
        // file next to the DLL. Without it, this module does nothing.
        if (!Sidecar(L"headless_diag_on.txt"))
        {
            LogF(L"[headless] StartHeadlessForce: disabled (create headless_diag_on.txt "
                 L"next to the DLL to enable the GetProcAddress/window diagnostics)\n");
            return;
        }

        int hooked = 0;
        if (InlineHook("kernel32.dll", "GetProcAddress",
                       reinterpret_cast<void*>(&Hk_GetProcAddress),
                       reinterpret_cast<void**>(&o_GetProcAddress)))
            ++hooked;
        else
            LogF(L"[headless] InlineHook kernel32!GetProcAddress FAILED\n");

        if (InlineHook("kernel32.dll", "LoadLibraryExW",
                       reinterpret_cast<void*>(&Hk_LoadLibraryExW),
                       reinterpret_cast<void**>(&o_LoadLibraryExW)))
            ++hooked;
        else
            LogF(L"[headless] InlineHook kernel32!LoadLibraryExW FAILED\n");

        // user32 is already loaded (Qt). If for some reason it isn't, skip.
        if (GetModuleHandleW(L"user32.dll"))
        {
            if (InlineHook("user32.dll", "CreateWindowExW",
                           reinterpret_cast<void*>(&Hk_CreateWindowExW),
                           reinterpret_cast<void**>(&o_CreateWindowExW)))
                ++hooked;
            else
                LogF(L"[headless] InlineHook user32!CreateWindowExW FAILED\n");
        }
        else
        {
            LogF(L"[headless] user32 not loaded yet - CreateWindowExW not hooked\n");
        }

        LogF(L"[headless] StartHeadlessForce: %d/3 hooks installed "
             L"(log-only unless sidecar toggles present: headless_block_gfx_dll.txt, "
             L"headless_stub_d3d.txt, headless_msgonly_windows.txt)\n", hooked);
    }
}
