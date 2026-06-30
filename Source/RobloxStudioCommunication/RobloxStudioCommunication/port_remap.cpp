// port_remap.cpp - see port_remap.h for the design overview.
//
// Server-only ws2_32!bind hook that swaps which UDP listener owns the -port:
//   * RakNet's bind to <-port>            -> rewritten to <-port + 1>
//   * the first ephemeral (port 0) UDP bind seen AFTER RakNet (the
//     RbxTransport "DummyServer" socket) -> rewritten to <-port>
//
// Only SOCK_DGRAM binds are touched (TCP listeners - HTTP, debugger, the
// RbxTransport control channel - pass through untouched). Every bind() is
// logged with family/addr/port/type and the action taken.

#include "port_remap.h"
#include "iat_hook.h"
#include "patcher.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

namespace RobloxStudioPatcher
{
    typedef int (WSAAPI *PFN_bind)(SOCKET, const sockaddr*, int);
    static PFN_bind s_orig_bind = nullptr;

    // We also intercept kernel32!GetProcAddress so the RbxTransport "sys"
    // backend (which resolves bind dynamically) receives our Hook_bind.
    typedef FARPROC (WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
    static PFN_GetProcAddress s_orig_GetProcAddress = nullptr;

    static std::mutex s_mutex;
    static bool       s_active      = false;   // -port present and remap enabled
    static int        s_basePort    = 0;       // the -port value (DummyServer target)
    static int        s_raknetPort  = 0;       // base+1, or raknet_port.txt override
    static int        s_dummyIndex  = 1;       // which post-RakNet ephemeral bind = DummyServer
    static bool       s_sawRaknet   = false;
    static bool       s_dummyDone   = false;
    static int        s_ephemSeen   = 0;       // ephemeral UDP binds seen after RakNet

    // ---- command-line / sidecar parsing ----------------------------------

    static int ParsePortArg()
    {
        const wchar_t* cmd = GetCommandLineW();
        if (!cmd) return 0;
        const wchar_t* p = wcsstr(cmd, L"-port ");
        if (!p) return 0;
        p += 6;                                  // skip "-port "
        while (*p == L' ') ++p;
        int v = (int)_wtoi(p);
        return (v > 0 && v < 65536) ? v : 0;
    }

    static int ReadPortSidecar(const wchar_t* file)
    {
        std::wstring dir = GetDllDirectory();
        if (dir.empty()) return 0;
        std::wstring w = ReadTextFileTrimmed(dir + file);
        if (w.empty()) return 0;
        int v = (int)_wtoi(w.c_str());
        return (v > 0 && v < 65536) ? v : 0;
    }

    static bool SidecarExists(const wchar_t* file)
    {
        std::wstring dir = GetDllDirectory();
        if (dir.empty()) return false;
        DWORD a = GetFileAttributesW((dir + file).c_str());
        return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
    }

    // ---- the hook --------------------------------------------------------

    static bool IsUdpSocket(SOCKET s)
    {
        int type = 0; int len = (int)sizeof(type);
        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&type, &len) != 0) return false;
        return type == SOCK_DGRAM;
    }

    static int WSAAPI Hook_bind(SOCKET s, const sockaddr* name, int namelen)
    {
        if (s_active && name && namelen >= (int)sizeof(sockaddr_in))
        {
            const unsigned short fam = name->sa_family;
            // sin_port / sin6_port both sit at offset 2, network byte order.
            const unsigned short netPort = *reinterpret_cast<const unsigned short*>(
                                               reinterpret_cast<const char*>(name) + 2);
            const unsigned short port = ntohs(netPort);

            if ((fam == AF_INET || fam == AF_INET6) && IsUdpSocket(s))
            {
                int         newPort = -1;
                const char* action  = "passthrough";

                std::lock_guard<std::mutex> lk(s_mutex);
                // Move ONLY RakNet off -port. RakNet binds -port FIRST; we send it
                // to raknetPort (-port+1). RbxTransport is pinned to -port by the
                // webserver's RbxTransport*Port FInt overrides and binds it on its
                // own AFTER RakNet has vacated - so we must NOT touch any other
                // bind (the old dummy/ephemeral redirect is gone: it could have
                // grabbed an unrelated ephemeral socket and collided on -port).
                if (!s_sawRaknet && port == s_basePort)
                {
                    newPort = s_raknetPort; s_sawRaknet = true; action = "RakNet -> raknetPort";
                }
                (void)s_dummyDone; (void)s_ephemSeen; (void)s_dummyIndex;

                LogF(L"[port_remap] bind fam=%u port=%u udp=1 -> %hs (newPort=%d)\n",
                     (unsigned)fam, (unsigned)port, action, newPort);

                if (newPort >= 0)
                {
                    char buf[sizeof(sockaddr_in6)] = {};
                    int clen = namelen;
                    if (clen > (int)sizeof(buf)) clen = (int)sizeof(buf);
                    memcpy(buf, name, clen);
                    *reinterpret_cast<unsigned short*>(buf + 2) =
                        htons((unsigned short)newPort);
                    return s_orig_bind(s, reinterpret_cast<sockaddr*>(buf), namelen);
                }
            }
        }
        return s_orig_bind(s, name, namelen);
    }

    // ---- public entry ----------------------------------------------------

    static FARPROC WINAPI Hook_GetProcAddress(HMODULE hMod, LPCSTR name)
    {
        FARPROC real = s_orig_GetProcAddress ? s_orig_GetProcAddress(hMod, name)
                                              : ::GetProcAddress(hMod, name);
        // Only swap the genuine ws2_32!bind (compare the resolved pointer so we
        // never touch some unrelated symbol that happens to be named "bind").
        if (s_active && real && s_orig_bind &&
            reinterpret_cast<void*>(real) == reinterpret_cast<void*>(s_orig_bind) &&
            reinterpret_cast<uintptr_t>(name) > 0xFFFF &&    // not an ordinal
            lstrcmpiA(name, "bind") == 0)
        {
            return reinterpret_cast<FARPROC>(&Hook_bind);
        }
        return real;
    }

    bool StartPortRemap()
    {
        if (SidecarExists(L"port_remap_off.txt"))
        {
            LogF(L"[port_remap] port_remap_off.txt present - disabled\n");
            return false;
        }

        s_basePort = ParsePortArg();
        if (s_basePort == 0)
        {
            LogF(L"[port_remap] no -port on command line - not installing\n");
            return false;
        }

        int rkOverride = ReadPortSidecar(L"raknet_port.txt");
        s_raknetPort = rkOverride ? rkOverride : (s_basePort + 1);

        int di = ReadPortSidecar(L"dummy_bind_index.txt");
        s_dummyIndex = di ? di : 1;

        // Resolve the genuine ws2_32!bind up front so both hooks call through to
        // it and the GetProcAddress hook can identity-match it.
        if (HMODULE hWs2 = GetModuleHandleW(L"ws2_32.dll"))
            s_orig_bind = reinterpret_cast<PFN_bind>(::GetProcAddress(hWs2, "bind"));

        // (a) IAT hook on bind - catches RakNet (static import). Stable; no
        //     inline trampoline (inline-patching bind destabilises startup).
        void* prevBind = nullptr;
        if (IatHook("ws2_32.dll", "bind",
                    reinterpret_cast<void*>(&Hook_bind), &prevBind))
        {
            if (prevBind) s_orig_bind = reinterpret_cast<PFN_bind>(prevBind);
            LogF(L"[port_remap] bind: IAT hook installed (orig=%p)\n", s_orig_bind);
        }
        else LogF(L"[port_remap] bind: IAT hook miss (RakNet may not be remapped)\n");

        // (b) GetProcAddress hook - catches RbxTransport/DummyServer (dynamic
        //     resolution). This is the path that owns the forwardable -port.
        if (!s_orig_bind)
        {
            LogF(L"[port_remap] could not resolve ws2_32!bind - aborting\n");
            return false;
        }
        if (!IatHook("kernel32.dll", "GetProcAddress",
                     reinterpret_cast<void*>(&Hook_GetProcAddress),
                     reinterpret_cast<void**>(&s_orig_GetProcAddress)))
        {
            LogF(L"[port_remap] GetProcAddress IAT hook FAILED - dummy bind "
                 L"won't be caught\n");
        }

        s_active = true;
        LogF(L"[port_remap] active: basePort=%d raknetPort=%d dummyIndex=%d "
             L"(DummyServer/RbxTransport -> %d, RakNet -> %d)\n",
             s_basePort, s_raknetPort, s_dummyIndex, s_basePort, s_raknetPort);
        return true;
    }
}
