// rcc_patch.cpp - patch the LocalRcc default IP "127.0.0.1" -> -server <ip>.
//
// In the x64 build the connection-setup function loads the literal "127.0.0.1"
// with a length of 9:
//
//     41 B8 09 00 00 00      mov  r8d, 9                 ; length
//     48 8D 15 <disp32>      lea  rdx, [rip+disp]        ; -> "127.0.0.1"
//     48 8D 4C 24 38         lea  rcx, [rsp+38]
//     E8 <rel32>             call std::string assign
//
// We target that exact site by RVA (build-specific), validate it really loads
// "127.0.0.1" with length 9, then point the LEA at a replacement IP string we
// allocate within +/-2GB and fix the length. ONLY this dedicated string is
// touched - the shared "127.0.0.1" used for the local webserver is a different
// literal and is left alone, so localhost traffic keeps working.

#include "rcc_patch.h"

#include <cstdint>
#include <cstring>
#include <string>

// patcher.h pulls in <Windows.h> with WIN32_LEAN_AND_MEAN, so the legacy
// winsock.h is NOT included and we can safely use winsock2 here. ws2_32 is
// already linked by udp_relay.cpp.
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

namespace RobloxStudioPatcher
{
    // RVAs of every `lea rdx,[rip->"127.0.0.1"]` connection-setup site we want
    // redirected to the -server IP (base 0x140000000). Build-specific; each is
    // validated at runtime before any write, so a stale RVA is skipped safely.
    //   0x4FA1DAE  - original LocalRcc site
    //   0x2793CDA / 0x2793DA7 / 0x2793E8B / 0x2793F2D - the connection-setup
    //     cluster. Roblox resolves a domain/playit.gg -server value to its real
    //     IP via a ping, but a sibling callsite in this cluster then resets the
    //     address to 127.0.0.1; redirecting the whole cluster stops that reset.
    //   (0x65D4798 is the local-webserver 127.0.0.1 and is deliberately NOT
    //    touched, so localhost traffic keeps working.)
    static const uintptr_t kLeaRvas[] = {
        0x4FA1DAE, 0x2793CDA, 0x2793DA7, 0x2793E8B, 0x2793F2D
    };

    // Pull "-server <host>" off the command line. Accepts a numeric IPv4 OR a
    // hostname/domain (letters, digits, '.', '-'). Stops at the optional
    // ":port" or whitespace so only the address is taken.
    static std::string GetServerArg()
    {
        const wchar_t* cl = GetCommandLineW();
        if (!cl) return "";
        std::wstring s(cl);
        size_t p = s.find(L"-server");
        if (p == std::wstring::npos) return "";
        size_t a = p + 7;
        while (a < s.size() && (s[a] == L' ' || s[a] == L'\t' || s[a] == L'"')) ++a;
        std::string host;
        while (a < s.size())
        {
            wchar_t c = s[a];
            bool ok = (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'z') ||
                      (c >= L'A' && c <= L'Z') || c == L'.' || c == L'-';
            if (!ok) break;            // stops at ':', space, quote, etc.
            host.push_back((char)c);
            ++a;
        }
        return host;
    }

    // Resolve a host to a numeric IPv4 string. A numeric IPv4 is returned as-is.
    // A domain/playit.gg name is resolved via DNS (getaddrinfo) to its real IP,
    // because the engine's connect path needs a numeric address - handed a bare
    // hostname it fails to parse and silently falls back to 127.0.0.1, which is
    // exactly the bug. Returns "" if it can't be resolved.
    static std::string ResolveToIpv4(const std::string& host)
    {
        if (host.empty()) return "";
        struct in_addr probe;
        if (InetPtonA(AF_INET, host.c_str(), &probe) == 1)
            return host;            // already a numeric IPv4

        WSADATA wsa;
        bool started = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);

        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;       // IPv4 only (engine connect is v4)
        hints.ai_socktype = SOCK_DGRAM;

        struct addrinfo* res = nullptr;
        std::string out;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res)
        {
            char buf[64] = {};
            auto* sin = reinterpret_cast<sockaddr_in*>(res->ai_addr);
            if (InetNtopA(AF_INET, &sin->sin_addr, buf, sizeof(buf)))
                out = buf;
            freeaddrinfo(res);
        }
        if (started) WSACleanup();
        return out;
    }

    // Allocate a page within +/-2GB of `anchor` so a RIP-relative disp32 reaches it.
    static void* AllocNear(uintptr_t anchor, size_t size)
    {
        SYSTEM_INFO si; GetSystemInfo(&si);
        uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
        for (uintptr_t delta = gran; delta < 0x7FFF0000ULL; delta += gran)
        {
            uintptr_t cands[2] = { anchor + delta, anchor - delta };
            for (int d = 0; d < 2; ++d)
            {
                void* mem = VirtualAlloc(reinterpret_cast<void*>(cands[d] & ~(gran - 1)),
                    size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!mem) continue;
                intptr_t off = (intptr_t)((uintptr_t)mem - anchor);
                if (off >= INT32_MIN && off <= INT32_MAX) return mem;
                VirtualFree(mem, 0, MEM_RELEASE);
            }
        }
        return nullptr;
    }

    // POD-only worker so the function can use __try/__except (no C++ unwinding).
    // Patches a single `lea rdx,[rip->"127.0.0.1"]` site at the given RVA.
    static bool PatchOneSite(uintptr_t leaRva, const char* ip, size_t iplen)
    {
        __try
        {
            BYTE* base = reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
            if (!base) return false;
            BYTE* lea = base + leaRva;

            if (lea[0] != 0x48 || lea[1] != 0x8D || lea[2] != 0x15)
            {
                LogF(L"[rcc_patch] LEA sig mismatch at %p rva=0x%llX (%02X %02X %02X)\n",
                     lea, (unsigned long long)leaRva, lea[0], lea[1], lea[2]);
                return false;
            }
            int32_t disp = *reinterpret_cast<int32_t*>(lea + 3);
            BYTE* tgt = lea + 7 + disp;
            if (std::memcmp(tgt, "127.0.0.1", 9) != 0)
            {
                LogF(L"[rcc_patch] LEA target is not '127.0.0.1' - skipping\n");
                return false;
            }

            // length mov: 41 B8 09 00 00 00 immediately before the lea.
            BYTE* lenmov = lea - 6;
            bool haveLen = (lenmov[0] == 0x41 && lenmov[1] == 0xB8 &&
                            *reinterpret_cast<uint32_t*>(lenmov + 2) == 9);

            char* buf = reinterpret_cast<char*>(AllocNear((uintptr_t)lea, 256));
            if (!buf) { LogF(L"[rcc_patch] AllocNear failed\n"); return false; }
            std::memcpy(buf, ip, iplen);
            buf[iplen] = '\0';

            intptr_t newDisp = (intptr_t)((uintptr_t)buf - (uintptr_t)(lea + 7));
            if (newDisp < INT32_MIN || newDisp > INT32_MAX)
            { LogF(L"[rcc_patch] replacement out of disp32 range\n"); return false; }

            DWORD op = 0;
            if (VirtualProtect(lea + 3, 4, PAGE_EXECUTE_READWRITE, &op))
            {
                *reinterpret_cast<int32_t*>(lea + 3) = (int32_t)newDisp;
                DWORD ig = 0; VirtualProtect(lea + 3, 4, op, &ig);
                FlushInstructionCache(GetCurrentProcess(), lea + 3, 4);
            }
            if (haveLen)
            {
                DWORD op2 = 0;
                if (VirtualProtect(lenmov + 2, 4, PAGE_EXECUTE_READWRITE, &op2))
                {
                    *reinterpret_cast<uint32_t*>(lenmov + 2) = (uint32_t)iplen;
                    DWORD ig = 0; VirtualProtect(lenmov + 2, 4, op2, &ig);
                    FlushInstructionCache(GetCurrentProcess(), lenmov + 2, 4);
                }
            }
            LogF(L"[rcc_patch] IP patched @rva=0x%llX -> '%hs' (len mov %ls)\n",
                 (unsigned long long)leaRva, ip, haveLen ? L"updated" : L"NOT FOUND");
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LogF(L"[rcc_patch] exception during IP patch @rva=0x%llX\n",
                 (unsigned long long)leaRva);
            return false;
        }
    }

    bool PatchLocalRccIp()
    {
        std::string host = GetServerArg();
        if (host.empty()) { LogF(L"[rcc_patch] no -server arg, skipping IP patch\n"); return false; }

        // Resolve domains/playit.gg names to a numeric IP; numeric IPs pass
        // through unchanged. Without this, a hostname reaches the connect path
        // un-parseable and the engine falls back to 127.0.0.1.
        std::string ip = ResolveToIpv4(host);
        if (ip.empty())
        {
            LogF(L"[rcc_patch] could not resolve -server host '%hs' - skipping\n", host.c_str());
            return false;
        }
        if (ip != host)
            LogF(L"[rcc_patch] resolved -server '%hs' -> '%hs'\n", host.c_str(), ip.c_str());
        if (ip.size() == 0 || ip.size() > 64) return false;

        bool any = false;
        for (uintptr_t rva : kLeaRvas)
            any |= PatchOneSite(rva, ip.c_str(), ip.size());
        return any;
    }
}
