// studio_print.cpp - locate and invoke Roblox's internal log entrypoint.
//
// RESOLUTION STRATEGY
// -------------------
// 1) Signature scan inside the host EXE for the marker string
//    "Video recording stopped" (chosen because the user already
//    identified it in x32dbg and it survives across recent Roblox
//    builds). Find the instruction that loads its address (PUSH imm32
//    on x86, LEA rdx, [rip+disp32] on x64), then look at the next
//    handful of bytes for a `call rel32` opcode (0xE8). The rel32
//    target is the print function.
//
// 2) If the scan fails (string renamed, layout shifted), fall back to a
//    per-EXE hard-coded RVA. The user can edit these constants to match
//    whatever build they ship. Determining the correct value:
//      - Load RobloxStudioBeta.exe in x32dbg / x64dbg.
//      - Search for the string "Video recording stopped".
//      - Follow its xref to the call site.
//      - Read the absolute address of the `call <target>` operand.
//      - Subtract the module's base address (Modules tab).
//      - That difference is the RVA.

#include "studio_print.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstring>

namespace RobloxStudioPatcher
{
#ifdef _WIN64
    using FnRobloxPrint = void(*)(int level, const char* msg);
#else
    using FnRobloxPrint = void(__cdecl*)(int level, const char* msg);
#endif

    // Per-EXE RVA fallbacks. Update these for YOUR build of Roblox.
    // The Player RVA below is derived from the user's x32dbg screenshot
    // (call target shown as `roblox.1964720`, default PE base 0x00400000):
    //     0x01964720 - 0x00400000 = 0x01564720.
    // Studio's address has not been captured yet - leave 0 to disable the
    // hard-coded fallback and rely on the signature scan.
    static const uintptr_t kPlayerPrintRva = 0x01564720;
    static const uintptr_t kStudioPrintRva = 0;

    // Resolved function pointer + one-shot resolution gate. Both are
    // touched from any thread that calls LogF, so guard with an InterlockedXX
    // for the gate; the pointer write is naturally atomic on aligned slots.
    static FnRobloxPrint g_printFn = nullptr;
    static LONG          g_resolveGate = 0;     // 0 = pending, 1 = done

    // Thread-local recursion guard. RobloxPrint may itself be reached from
    // a LogF call inside whatever Roblox's print does (e.g. assertion
    // failures or a console redirector). Block re-entry on the same thread
    // so we never recurse and blow the stack.
    static thread_local bool t_inPrint = false;

    // ---- Signature scan --------------------------------------------------

    static const char kMarker[] = "Video recording stopped";

    static const uint8_t* FindMarkerString(HMODULE host)
    {
        if (!host) return nullptr;
        auto base = reinterpret_cast<uint8_t*>(host);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        const size_t markerLen = sizeof(kMarker) - 1;
        auto sections = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            // Marker lives in a readable, non-executable section
            // (.rdata / .data on MSVC builds).
            DWORD chars = sections[i].Characteristics;
            if (!(chars & IMAGE_SCN_MEM_READ))    continue;
            if (chars & IMAGE_SCN_MEM_EXECUTE)    continue;

            uint8_t* secBase = base + sections[i].VirtualAddress;
            uint32_t secSize = sections[i].Misc.VirtualSize;
            if (secSize < markerLen + 1) continue;

            uint32_t lim = secSize - (uint32_t)markerLen - 1;
            for (uint32_t off = 0; off < lim; ++off)
            {
                if (secBase[off] != kMarker[0]) continue;
                if (std::memcmp(secBase + off, kMarker, markerLen) != 0) continue;
                if (secBase[off + markerLen] != '\0') continue;
                return secBase + off;
            }
        }
        return nullptr;
    }

    // Scan executable sections for an instruction that addresses
    // `markerAddr`, followed within `kCallWindow` bytes by a CALL rel32.
    // Returns the call target.
    static FnRobloxPrint FindPrintCallAddressingMarker(HMODULE host,
                                                       const uint8_t* markerAddr)
    {
        constexpr uint32_t kCallWindow = 40;
        if (!host || !markerAddr) return nullptr;
        auto base = reinterpret_cast<uint8_t*>(host);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        auto sections = IMAGE_FIRST_SECTION(nt);

        for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            DWORD chars = sections[i].Characteristics;
            if (!(chars & IMAGE_SCN_MEM_EXECUTE)) continue;
            uint8_t* secBase = base + sections[i].VirtualAddress;
            uint32_t secSize = sections[i].Misc.VirtualSize;
            if (secSize < kCallWindow + 8) continue;

            for (uint32_t off = 0; off + kCallWindow < secSize; ++off)
            {
                uint32_t loadInsnLen = 0;
                bool     hit         = false;

#ifdef _WIN64
                // LEA r64, [rip + disp32]: REX.W (48) 8D /r with ModRM mod=00, rm=101.
                if (secBase[off] == 0x48 && secBase[off + 1] == 0x8D &&
                    (secBase[off + 2] & 0xC7) == 0x05)
                {
                    int32_t disp = *reinterpret_cast<const int32_t*>(secBase + off + 3);
                    const uint8_t* tgt = secBase + off + 7 + disp;
                    if (tgt == markerAddr) { hit = true; loadInsnLen = 7; }
                }
#else
                // PUSH imm32: 68 [imm32].
                if (secBase[off] == 0x68)
                {
                    uint32_t imm = *reinterpret_cast<const uint32_t*>(secBase + off + 1);
                    if (imm == reinterpret_cast<uintptr_t>(markerAddr)) {
                        hit = true; loadInsnLen = 5;
                    }
                }
#endif
                if (!hit) continue;

                // Scan forward for a near CALL (E8 rel32) instruction.
                for (uint32_t j = loadInsnLen;
                     j < kCallWindow && (off + j + 5) < secSize;
                     ++j)
                {
                    if (secBase[off + j] != 0xE8) continue;
                    int32_t rel = *reinterpret_cast<const int32_t*>(secBase + off + j + 1);
                    const uint8_t* callTarget = secBase + off + j + 5 + rel;

                    // Sanity check: target must live inside one of the
                    // executable sections of the same module.
                    bool inExec = false;
                    for (int k = 0; k < nt->FileHeader.NumberOfSections; ++k)
                    {
                        if (!(sections[k].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                            continue;
                        uint8_t* sb = base + sections[k].VirtualAddress;
                        uint32_t sz = sections[k].Misc.VirtualSize;
                        if (callTarget >= sb && callTarget < sb + sz) {
                            inExec = true; break;
                        }
                    }
                    if (!inExec) continue;

                    return reinterpret_cast<FnRobloxPrint>(
                        const_cast<uint8_t*>(callTarget));
                }
            }
        }
        return nullptr;
    }

    static FnRobloxPrint ResolvePrintFunction()
    {
        HMODULE host = GetModuleHandleW(nullptr);
        if (!host) return nullptr;

        wchar_t hostPath[MAX_PATH] = {};
        GetModuleFileNameW(host, hostPath, _countof(hostPath));

        // 1. Signature scan.
        const uint8_t* marker = FindMarkerString(host);
        if (marker)
        {
            FnRobloxPrint scanned =
                FindPrintCallAddressingMarker(host, marker);
            if (scanned)
            {
                LOG(L"[print] scanned print fn at %p (marker=%p host=%s)\n",
                     scanned, marker, hostPath);
                return scanned;
            }
            LOG(L"[print] marker found at %p but no nearby call (host=%s)\n",
                 marker, hostPath);
        }
        else
        {
            LOG(L"[print] marker '%hs' not found in host %s\n",
                 kMarker, hostPath);
        }

        // 2. Hardcoded RVA fallback per host EXE.
        uintptr_t rva = 0;
        if (wcsstr(hostPath, L"RobloxPlayerBeta.exe"))      rva = kPlayerPrintRva;
        else if (wcsstr(hostPath, L"RobloxStudioBeta.exe")) rva = kStudioPrintRva;

        if (rva != 0)
        {
            auto fn = reinterpret_cast<FnRobloxPrint>(
                reinterpret_cast<uint8_t*>(host) + rva);
            LOG(L"[print] using hardcoded RVA print fn at %p (host=%s rva=0x%lx)\n",
                 fn, hostPath, (unsigned long)rva);
            return fn;
        }

        LOG(L"[print] no print fn resolved for host %s (logs file-only)\n",
             hostPath);
        return nullptr;
    }

    static FnRobloxPrint Resolve()
    {
        // Cheap fast-path: already resolved (or already known-failed).
        if (InterlockedCompareExchange(&g_resolveGate, 1, 1) == 1)
            return g_printFn;

        FnRobloxPrint fn = nullptr;
        __try { fn = ResolvePrintFunction(); }
        __except (EXCEPTION_EXECUTE_HANDLER) { fn = nullptr; }

        g_printFn = fn;
        InterlockedExchange(&g_resolveGate, 1);
        return fn;
    }

    void RobloxPrint(const char* msg)
    {
        if (!msg) return;
        if (t_inPrint) return;          // re-entrancy guard
        FnRobloxPrint fn = Resolve();
        if (!fn) return;

        t_inPrint = true;
        __try
        {
            fn(1, msg);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // If the call faulted, disable for the rest of the session so we
            // don't bring down the host EXE on every subsequent LogF.
            g_printFn = nullptr;
        }
        t_inPrint = false;
    }

    void RobloxPrintW(const wchar_t* msg)
    {
        if (!msg) return;
        char narrow[2048];
        int n = WideCharToMultiByte(CP_UTF8, 0, msg, -1,
                                    narrow, (int)sizeof(narrow) - 1,
                                    nullptr, nullptr);
        if (n <= 0) return;
        narrow[n] = '\0';
        // Strip trailing newline so Roblox's logger doesn't double-space.
        if (n >= 1 && narrow[n - 1] == '\n') narrow[n - 1] = '\0';
        if (n >= 2 && narrow[n - 2] == '\r') narrow[n - 2] = '\0';
        RobloxPrint(narrow);
    }
}
