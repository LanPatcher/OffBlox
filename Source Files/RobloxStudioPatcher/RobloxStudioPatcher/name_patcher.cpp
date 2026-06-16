// name_patcher.cpp
//
// PatchPlayerNameCallSite() - SURGICAL approach.
//   Pattern-matches the SPECIFIC `push "Player%d"` instruction inside the
//   player-name formatting code path and redirects only THAT push to a
//   new format string we own. Other uses of "Player%d" (task IDs, etc.)
//   keep their original pointer and stay intact.
//
//   Updated pattern (new EXE build, from x32dbg trace at 0x0272510F):
//
//     6A 00             push 0
//     6A 00             push 0
//     6A 00             push 0
//     6A 09             push 9
//     E8 ?? ?? ?? ??    call robloxstudiobeta.318E8A0   ; (push args)
//     8D 4D A8          lea ecx, dword ptr ss:[ebp-58]
//     E8 ?? ?? ?? ??    call robloxstudiobeta.318E8C0
//     FF 87 30010000    inc dword ptr ds:[edi+130]
//     8D 45 C8          lea eax, dword ptr ss:[ebp-38]
//     FF 87 3C010000    inc dword ptr ds:[edi+13C]      ; (second inc before push)
//     C6 45 FC 02       mov byte ptr ss:[ebp-4], 2
//     68 A8 AD 29 05    push robloxstudiobeta.529ADA8   <-- TARGET (Player%d)
//     50                push eax
//     E8 ?? ?? ?? ??    call robloxstudiobeta.34CB250
//     83 C4 0C          add esp, 0Ch
//
//   We pattern-match starting from the `C6 45 FC 02` that immediately
//   precedes the push, because the mov-byte + push-imm32 + push-eax +
//   call + add-esp sequence is unique in this build.
//
// Both functions read the desired name from "username.txt" next to the DLL.

#include "name_patcher.h"
#include "identity_patch.h"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

namespace RobloxStudioPatcher
{
    static const char   kPattern[] = "Player%d";
    static const size_t kPatternLen = sizeof(kPattern); // 9 incl. \0

    static std::string WStringToAscii(const std::wstring& s)
    {
        std::string out;
        out.reserve(s.size());
        for (wchar_t c : s)
        {
            if (c >= 32 && c <= 126)
                out.push_back(static_cast<char>(c));
        }
        return out;
    }

    static std::vector<BYTE*> FindBytesInMainModule(const BYTE* pattern,
        size_t patLen)
    {
        std::vector<BYTE*> matches;
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return matches;

        auto base = reinterpret_cast<BYTE*>(mod);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return matches;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return matches;

        auto section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
        {
            if (!(section->Characteristics & IMAGE_SCN_MEM_READ)) continue;

            BYTE* sectionStart = base + section->VirtualAddress;
            DWORD sectionSize = section->Misc.VirtualSize;
            if (sectionSize < patLen) continue;

            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(sectionStart, &mbi, sizeof(mbi)) == 0) continue;
            if (mbi.State != MEM_COMMIT) continue;

            for (DWORD off = 0; off + patLen <= sectionSize; ++off)
            {
                if (std::memcmp(sectionStart + off, pattern, patLen) == 0)
                    matches.push_back(sectionStart + off);
            }
        }
        return matches;
    }

    static bool WriteRdataBytes(BYTE* addr, const BYTE* data, size_t len)
    {
        DWORD oldProtect = 0;
        if (!VirtualProtect(addr, len, PAGE_READWRITE, &oldProtect))
            return false;
        std::memcpy(addr, data, len);
        DWORD ignored = 0;
        VirtualProtect(addr, len, oldProtect, &ignored);
        return true;
    }

    // DISABLED - kept as documentation.
    bool PatchLocalPlayerName()
    {
        LogF(L"[name_patcher] DISABLED - see comment in name_patcher.cpp\n");
        return false;
    }

    // ===================================================================
    //  SURGICAL CALL-SITE PATCH
    // ===================================================================
    //
    // NEW pattern for the updated EXE build (screenshot at 0x0272510F):
    //
    //   C6 45 FC 02           mov byte ptr [ebp-4], 2
    //   68 ?? ?? ?? ??        push imm32          <- target (Player%d ptr)
    //   50                    push eax
    //   E8 ?? ?? ?? ??        call rel32          (sprintf)
    //   83 C4 0C              add esp, 0Ch
    //   8B 0B                 mov ecx, [ebx]
    //   8D 55 C8              lea edx, [ebp-38]
    //
    // The `C6 45 FC 02` (mov byte [ebp-4],2) immediately before the push
    // is distinctive enough as an anchor. We validate the imm32 points to
    // "Player%d\0" before patching.
    //
    // x86 ONLY - the x64 build uses different opcodes and register args.

#ifndef _WIN64
    static bool MemoryEqualsAt(const void* addr, const char* expected, size_t len)
    {
        if (!addr) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;
        if (mbi.State != MEM_COMMIT) return false;
        const DWORD readable = PAGE_READONLY | PAGE_READWRITE
            | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
            | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
        if (!(mbi.Protect & readable)) return false;

        const BYTE* p = static_cast<const BYTE*>(addr);
        const BYTE* regionEnd =
            static_cast<const BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (p + len > regionEnd) return false;

        return std::memcmp(p, expected, len) == 0;
    }

    static char s_playerNameFormat[256] = {};

    // Core patch logic shared by both overloads.
    static bool PatchPlayerNameCallSiteImpl(const std::string& username)
    {
        if (username.empty()) {
            LogF(L"[name_patcher] username empty, skipping\n");
            return false;
        }
        int n = _snprintf_s(s_playerNameFormat, sizeof(s_playerNameFormat),
            _TRUNCATE, "%s", username.c_str());
        if (n <= 0) {
            LogF(L"[name_patcher] _snprintf_s failed (n=%d)\n", n);
            return false;
        }
        LogF(L"[name_patcher] new format='%hs' at %p\n",
            s_playerNameFormat, s_playerNameFormat);

        LogF(L"[name_patcher] surgical patch entry (new EXE build pattern)\n");


        // ---- Pattern (new EXE build) ------------------------------------
        //
        // Offset  Bytes                     Mnemonic
        //   0     C6 45 FC 02               mov byte [ebp-04], 2
        //   4     68 ?? ?? ?? ??            push imm32   <- we patch bytes 5..8
        //   9     50                        push eax
        //  10     E8 ?? ?? ?? ??            call rel32
        //  15     83 C4 0C                  add esp, 0Ch
        //  18     8B 0B                     mov ecx, [ebx]
        //  20     8D 55 C8                  lea edx, [ebp-38]
        //
        // Total pattern length: 23 bytes.
        // imm32 offset within pattern: 5 (the 4 bytes of the push operand).
        static const BYTE kPat[] = {
            0xC6, 0x45, 0xFC, 0x02,       // mov byte [ebp-4], 2
            0x68, 0x00, 0x00, 0x00, 0x00, // push imm32      <- target offset 4
            0x50,                          // push eax
            0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32
            0x83, 0xC4, 0x0C,             // add esp, 0Ch
            0x8B, 0x0B,                   // mov ecx, [ebx]
            0x8D, 0x55, 0xC8              // lea edx, [ebp-38]
        };
        static const BYTE kMask[] = {
            0xFF, 0xFF, 0xFF, 0xFF,       // exact
            0xFF, 0x00, 0x00, 0x00, 0x00, // opcode exact, imm32 wildcard
            0xFF,                          // exact
            0xFF, 0x00, 0x00, 0x00, 0x00, // opcode exact, rel32 wildcard
            0xFF, 0xFF, 0xFF,             // exact
            0xFF, 0xFF,                   // exact
            0xFF, 0xFF, 0xFF              // exact
        };
        constexpr size_t kPatLen = sizeof(kPat);
        constexpr size_t kImmOffset = 5; // byte offset of imm32 inside pattern

        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;
        BYTE* base = reinterpret_cast<BYTE*>(mod);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        int candidates = 0;
        int patched = 0;

        auto section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
        {
            if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            BYTE* secStart = base + section->VirtualAddress;
            DWORD secSize = section->Misc.VirtualSize;
            if (secSize < kPatLen) continue;

            for (DWORD off = 0; off + kPatLen <= secSize; ++off)
            {
                BYTE* p = secStart + off;

                bool match = true;
                for (size_t k = 0; k < kPatLen; ++k) {
                    if (kMask[k] != 0 && p[k] != kPat[k]) {
                        match = false;
                        break;
                    }
                }
                if (!match) continue;

                ++candidates;

                // Read the imm32 (4 bytes after the 0x68 opcode at offset 4).
                DWORD imm = *reinterpret_cast<DWORD*>(p + kImmOffset);
                const void* immPtr = reinterpret_cast<const void*>(
                    static_cast<uintptr_t>(imm));

                // Verify the imm32 actually points to "Player%d\0".
                if (!MemoryEqualsAt(immPtr, "Player%d", 9)) {
                    LogF(L"[name_patcher] candidate at %p imm=%08X does not "
                        L"point to 'Player%%d' - skipping\n", p, imm);
                    continue;
                }

                LogF(L"[name_patcher] candidate at %p imm=%08X -> 'Player%%d' MATCH\n",
                    p, imm);

                BYTE* immAddr = p + kImmOffset;
                DWORD newImm = static_cast<DWORD>(
                    reinterpret_cast<uintptr_t>(s_playerNameFormat));
                DWORD oldProtect = 0;
                if (!VirtualProtect(immAddr, sizeof(DWORD),
                    PAGE_EXECUTE_READWRITE, &oldProtect))
                {
                    LogF(L"[name_patcher] VirtualProtect failed at %p\n", immAddr);
                    continue;
                }
                *reinterpret_cast<DWORD*>(immAddr) = newImm;
                DWORD ignored = 0;
                VirtualProtect(immAddr, sizeof(DWORD), oldProtect, &ignored);
                FlushInstructionCache(GetCurrentProcess(), immAddr, sizeof(DWORD));

                LogF(L"[name_patcher] patched %p: imm %08X -> %08X\n",
                    immAddr, imm, newImm);
                ++patched;
            }
        }

        LogF(L"[name_patcher] surgical: candidates=%d patched=%d\n",
            candidates, patched);
        return patched > 0;
    } // end PatchPlayerNameCallSiteImpl

    // Public overload: read name from username.txt (client/server own instance).
    bool PatchPlayerNameCallSite()
    {
        std::wstring dir = GetDllDirectory();
        if (dir.empty()) { LogF(L"[name_patcher] no DLL dir\n"); return false; }
        std::wstring usernameW = ReadTextFileTrimmed(dir + L"username.txt");
        if (usernameW.empty()) { LogF(L"[name_patcher] username.txt missing/empty\n"); return false; }
        std::string username = WStringToAscii(usernameW);
        return PatchPlayerNameCallSiteImpl(username);
    }

    // Public overload: use a name received over the network (server-side relay).
    // Called from udp_relay.cpp when a magic packet arrives, replacing the
    // loopback HTTP server + Lua RenameOnJoin approach entirely.
    bool PatchPlayerNameCallSite(const std::string& username)
    {
        return PatchPlayerNameCallSiteImpl(username);
    }

#else  // ====================== x64 build ======================
    //
    // sprintf(dst, "Player%d", n) loads the format RIP-relative:
    //     45 8B 85 A0 02 00 00   mov  r8d, [r13+0x2A0]      ; the %d arg
    //     48 8D 15 EF C3 E9 04   lea  rdx, [rip -> "Player%d"]
    //     48 8D 4D 20            lea  rcx, [rbp+0x20]        ; dest buffer
    //     E8 <rel32>             call sprintf
    //
    // It's a NUL-terminated format (no length field), so we just repoint the LEA
    // at our own NUL-terminated format string. We target the LEA BY RVA
    // (build-specific, validated) rather than scanning the 127MB .text - doing
    // that scan inside DllMain (it VirtualQuery'd every RIP LEA) stalled Studio's
    // startup so the window never showed. The replacement buffer is allocated
    // within +/-2GB once and reused (later calls just rewrite it).

    static const uintptr_t kNameLeaRva = 0x4A18302; // file VA 0x144A18302
    static char*  s_nameBuf      = nullptr;        // near-allocated replacement
    static const size_t kNameBufSize = 256;
    static bool   s_dispPatched  = false;

    // Allocate a page within +/-2GB of `anchor` so a RIP-relative disp32 can
    // reach it. Searches outward from the anchor in allocation-granularity steps.
    static void* AllocNear(uintptr_t anchor, size_t size)
    {
        SYSTEM_INFO si; GetSystemInfo(&si);
        uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
        const uintptr_t limit = 0x7FFF0000ULL;     // stay comfortably under 2GB
        for (uintptr_t delta = gran; delta < limit; delta += gran)
        {
            uintptr_t cands[2] = { anchor + delta, anchor - delta };
            for (int d = 0; d < 2; ++d)
            {
                uintptr_t cand = cands[d] & ~(gran - 1);
                void* p = VirtualAlloc(reinterpret_cast<void*>(cand), size,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!p) continue;
                intptr_t off = (intptr_t)((uintptr_t)p - anchor);
                if (off >= INT32_MIN && off <= INT32_MAX) return p;
                VirtualFree(p, 0, MEM_RELEASE);
            }
        }
        return nullptr;
    }

    static void WriteNameToBuf(const std::string& name)
    {
        if (!s_nameBuf) return;
        size_t n = name.size();
        if (n >= kNameBufSize) n = kNameBufSize - 1;
        std::memcpy(s_nameBuf, name.data(), n);
        s_nameBuf[n] = '\0';
    }

    // POD-only worker (no C++ unwinding) so it can use __try/__except. Validates
    // the RVA site really loads "Player%d", then repoints its disp32 at s_nameBuf.
    static int PatchNameDispImpl()
    {
        __try
        {
            BYTE* base = reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
            if (!base) return 0;
            BYTE* lea = base + kNameLeaRva;
            if (lea[0] != 0x48 || lea[1] != 0x8D || lea[2] != 0x15)
            {
                LogF(L"[name_patcher] x64 LEA sig mismatch (%02X %02X %02X)\n",
                     lea[0], lea[1], lea[2]);
                return 0;
            }
            int32_t disp = *reinterpret_cast<int32_t*>(lea + 3);
            if (std::memcmp(lea + 7 + disp, "Player%d", 9) != 0)
            {
                LogF(L"[name_patcher] x64 target is not 'Player%%d' - skipping\n");
                return 0;
            }
            intptr_t nd = (intptr_t)((uintptr_t)s_nameBuf - (uintptr_t)(lea + 7));
            if (nd < INT32_MIN || nd > INT32_MAX) return 0;
            DWORD op = 0;
            if (!VirtualProtect(lea + 3, 4, PAGE_EXECUTE_READWRITE, &op)) return 0;
            *reinterpret_cast<int32_t*>(lea + 3) = (int32_t)nd;
            DWORD ig = 0; VirtualProtect(lea + 3, 4, op, &ig);
            FlushInstructionCache(GetCurrentProcess(), lea + 3, 4);
            return 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LogF(L"[name_patcher] x64 exception during patch\n");
            return 0;
        }
    }

    static bool PatchPlayerNameCallSiteImpl(const std::string& username)
    {
        if (username.empty()) { LogF(L"[name_patcher] username empty, skipping\n"); return false; }

        // Already redirected once -> just swap the buffer contents (cheap; this
        // is the hot path when many players join the server). No re-patch.
        if (s_dispPatched && s_nameBuf)
        {
            WriteNameToBuf(username);
            LogF(L"[name_patcher] x64 name updated to '%hs'\n", username.c_str());
            return true;
        }

        BYTE* base = reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
        if (!base) return false;
        s_nameBuf = static_cast<char*>(AllocNear((uintptr_t)(base + kNameLeaRva), kNameBufSize));
        if (!s_nameBuf) { LogF(L"[name_patcher] x64 AllocNear failed\n"); return false; }
        WriteNameToBuf(username);

        if (PatchNameDispImpl())
        {
            s_dispPatched = true;
            LogF(L"[name_patcher] x64 name patch OK -> '%hs' (buf %p)\n",
                 username.c_str(), s_nameBuf);
            return true;
        }
        return false;
    }

    bool PatchPlayerNameCallSite()
    {
        std::wstring dir = GetDllDirectory();
        if (dir.empty()) { LogF(L"[name_patcher] no DLL dir\n"); return false; }
        std::wstring uw = ReadTextFileTrimmed(dir + L"username.txt");
        if (uw.empty()) { LogF(L"[name_patcher] username.txt missing/empty\n"); return false; }
        return PatchPlayerNameCallSiteImpl(WStringToAscii(uw));
    }
    bool PatchPlayerNameCallSite(const std::string& username)
    {
        return PatchPlayerNameCallSiteImpl(username);
    }
#endif

    // ===================================================================
    //  Relayed UserId / AccountAge  (build-independent)
    // ===================================================================
    //
    // The relay (udp_relay.cpp) calls ApplyReceivedIdentity() when a v2 magic
    // packet arrives; it hands the values to the createServerPlayer getter
    // detours in identity_patch.cpp so the joining Player gets them instead
    // of 0. The values are also cached + logged here.

    static volatile unsigned long long s_recvUserId     = 0;
    static volatile unsigned int       s_recvAccountAge = 0;

    unsigned long long GetReceivedUserId()     { return s_recvUserId; }
    unsigned int       GetReceivedAccountAge() { return s_recvAccountAge; }

    void ApplyReceivedIdentity(unsigned long long userId, unsigned int accountAge)
    {
        s_recvUserId     = userId;
        s_recvAccountAge = accountAge;

        LogF(L"[name_patcher] relayed identity: userId=%llu accountAge=%u\n",
             userId, accountAge);

        SetRelayedIdentity(userId, accountAge);
    }
}