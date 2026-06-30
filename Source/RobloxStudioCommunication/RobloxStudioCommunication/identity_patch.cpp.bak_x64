// identity_patch.cpp - see identity_patch.h for the design.

#include "identity_patch.h"
#include <cstdint>
#include <cstring>

namespace RobloxStudioPatcher
{
#ifndef _WIN64

    // ---- values handed back by the detours (referenced ABSOLUTELY by the
    //      generated thunk code, so they must live at fixed addresses) --------
    static volatile uint32_t g_uidLo   = 0;
    static volatile uint32_t g_uidHi   = 0;
    static volatile uint8_t  g_haveUid = 0;
    static volatile uint32_t g_age     = 0;
    static volatile uint8_t  g_haveAge = 0;

    // Filled at install time with the absolute address of the ORIGINAL engine
    // getter, so each thunk can forward to it via `jmp dword ptr [slot]`.
    static void* g_origUidGetter = nullptr;
    static void* g_origAgeGetter = nullptr;

    // Per-detour saved return address (the real createServerPlayer call site).
    // Single-threaded join path, one call each -> no reentrancy concern.
    static void* g_realRetUid = nullptr;
    static void* g_realRetAge = nullptr;

    static bool  g_installed = false;

    // ---- pattern scan over the main module's executable sections -----------
    static bool MatchAt(const uint8_t* p, const uint8_t* pat,
                        const uint8_t* mask, size_t n)
    {
        for (size_t i = 0; i < n; ++i)
            if (mask[i] && p[i] != pat[i]) return false;
        return true;
    }

    // Return the single match of pat/mask, or nullptr if there are zero or
    // more than one (ambiguous -> refuse to patch).
    static uint8_t* FindUnique(const uint8_t* pat, const uint8_t* mask, size_t n)
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return nullptr;
        uint8_t* base = reinterpret_cast<uint8_t*>(mod);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        uint8_t* found = nullptr;
        int count = 0;
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
        {
            if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            uint8_t* s = base + sec->VirtualAddress;
            DWORD sz = sec->Misc.VirtualSize;
            if (sz < n) continue;
            for (DWORD off = 0; off + n <= sz; ++off)
                if (MatchAt(s + off, pat, mask, n))
                {
                    if (++count > 1) return nullptr;   // ambiguous
                    found = s + off;
                }
        }
        return (count == 1) ? found : nullptr;
    }

    static bool ProtectWrite(void* addr, const void* data, size_t len)
    {
        DWORD old = 0;
        if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)) return false;
        std::memcpy(addr, data, len);
        DWORD ign = 0;
        VirtualProtect(addr, len, old, &ign);
        FlushInstructionCache(GetCurrentProcess(), addr, len);
        return true;
    }

    // Point the `E8 rel32` at callSite to `thunk`; record the original target
    // in *origSlot FIRST (so the thunk can never call through a null slot).
    static bool RedirectCall(uint8_t* callSite, void* thunk, void** origSlot)
    {
        if (callSite[0] != 0xE8) return false;             // must be a near call
        int32_t rel = *reinterpret_cast<int32_t*>(callSite + 1);
        *origSlot = callSite + 5 + rel;                    // original target
        int32_t newRel = static_cast<int32_t>(
            reinterpret_cast<uint8_t*>(thunk) - (callSite + 5));
        return ProtectWrite(callSite + 1, &newRel, 4);
    }

    // Build a trampoline in RWX memory. The engine getters use a normal
    // `push ebp; mov ebp,esp` frame and read their args via [ebp+8]..[ebp+10]
    // (the property name they FNV-hash), and they `ret N`. So we must NOT add a
    // return address before forwarding - instead we forward with `jmp` (leaving
    // the stack EXACTLY as the original call site left it) and intercept only
    // the getter's RETURN by swapping the on-stack return address:
    //
    //   mov  eax,[esp]            ; eax = real return addr (the call site)
    //   mov  [realRet], eax       ; stash it
    //   mov  dword [esp], post    ; getter will now return into us
    //   jmp  [origSlot]           ; run getter with the original stack/args
    // post:
    //   cmp  byte [have], 0
    //   jz   done                 ; no relayed value -> keep engine's result
    //   mov  eax,[lo]             ; override (eax / eax:edx)
    //  [mov  edx,[hi]]            ; int64 only
    // done:
    //   jmp  [realRet]            ; return to the original call site
    static void* BuildThunk(void** origSlot, void** realRetSlot,
                            volatile uint8_t* haveFlag,
                            volatile uint32_t* lo, volatile uint32_t* hi)
    {
        uint8_t code[64];
        size_t n = 0;
        auto put   = [&](uint8_t b) { code[n++] = b; };
        auto put32 = [&](const void* p) {
            uint32_t v = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p));
            std::memcpy(code + n, &v, 4); n += 4;
        };

        put(0x8B); put(0x04); put(0x24);                       // mov eax,[esp]
        put(0xA3); put32((void*)realRetSlot);                  // mov [realRet],eax
        put(0xC7); put(0x04); put(0x24);                       // mov dword [esp],imm32
        size_t postOperand = n; put32(nullptr);                //   (post abs, fixed below)
        put(0xFF); put(0x25); put32(origSlot);                 // jmp [origSlot]
        size_t postOff = n;
        put(0x80); put(0x3D); put32((void*)haveFlag); put(0x00); // cmp byte [have],0
        put(0x74); size_t jzRel = n; put(0x00);                // jz done
        put(0xA1); put32((void*)lo);                           // mov eax,[lo]
        if (hi) { put(0x8B); put(0x15); put32((void*)hi); }    // mov edx,[hi]
        size_t doneOff = n;
        put(0xFF); put(0x25); put32((void*)realRetSlot);       // jmp [realRet]
        code[jzRel] = static_cast<uint8_t>(doneOff - (jzRel + 1));

        void* mem = VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
        if (!mem) return nullptr;
        uint32_t postAbs = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(mem) + postOff);
        std::memcpy(code + postOperand, &postAbs, 4);          // fix up `post`
        std::memcpy(mem, code, n);
        FlushInstructionCache(GetCurrentProcess(), mem, n);
        return mem;
    }

    void InstallIdentityPatch()
    {
        if (g_installed) return;
        g_installed = true;

        // UserId site (int64):
        //   mov eax,[ebp+C]; mov ecx,esi; mov [edx],eax; mov eax,[ebp+10];
        //   mov [edx+4],eax; CALL get; mov ecx,[ebp-18]; push edx; push eax; CALL set
        static const uint8_t uPat[] = {
            0x8B,0x45,0x0C, 0x8B,0xCE, 0x89,0x02, 0x8B,0x45,0x10, 0x89,0x42,0x04,
            0xE8,0,0,0,0, 0x8B,0x4D,0xE8, 0x52, 0x50, 0xE8,0,0,0,0 };
        static const uint8_t uMask[] = {
            1,1,1, 1,1, 1,1, 1,1,1, 1,1,1,
            1,0,0,0,0, 1,1,1, 1, 1, 1,0,0,0,0 };

        // AccountAge site (int32):  ... CALL get; mov ecx,[ebp-14]; push eax; CALL set
        static const uint8_t aPat[] = {
            0x8B,0x45,0x0C, 0x8B,0xCE, 0x89,0x02, 0x8B,0x45,0x10, 0x89,0x42,0x04,
            0xE8,0,0,0,0, 0x8B,0x4D,0xEC, 0x50, 0xE8,0,0,0,0 };
        static const uint8_t aMask[] = {
            1,1,1, 1,1, 1,1, 1,1,1, 1,1,1,
            1,0,0,0,0, 1,1,1, 1, 1,0,0,0,0 };

        uint8_t* uSite = FindUnique(uPat, uMask, sizeof(uPat));
        uint8_t* aSite = FindUnique(aPat, aMask, sizeof(aPat));

        // DIAGNOSTIC-ONLY: read-only scan, NO binary modification. The earlier
        // active version broke createServerPlayer (which also does the Player%d
        // naming), so the whole player came in with no fields set. Until we've
        // confirmed - from the log below - that these patterns resolve to
        // exactly the two getter call sites (and verified the bytes at site+13
        // are E8), we do NOT patch anything.
        bool uOk = uSite && uSite[13] == 0xE8;
        bool aOk = aSite && aSite[13] == 0xE8;
        LogF(L"[identity] SCAN-ONLY (no patch applied): "
             L"UserId site=%p (callByte=%02X ok=%d)  "
             L"AccountAge site=%p (callByte=%02X ok=%d)\n",
             uSite, uSite ? uSite[13] : 0, (int)uOk,
             aSite, aSite ? aSite[13] : 0, (int)aOk);

        (void)BuildThunk; (void)RedirectCall;   // kept for the verified pass
        (void)g_realRetUid; (void)g_realRetAge;
    }

    void SetRelayedIdentity(unsigned long long userId, unsigned int accountAge)
    {
        InstallIdentityPatch();                 // make sure the detours exist
        g_uidLo   = static_cast<uint32_t>(userId & 0xFFFFFFFFull);
        g_uidHi   = static_cast<uint32_t>(userId >> 32);
        g_haveUid = (userId != 0) ? 1 : 0;      // 0 -> let the engine value stand
        g_age     = accountAge;
        g_haveAge = 1;
        LogF(L"[identity] live values: userId=%llu (have=%d) accountAge=%u\n",
             userId, (int)g_haveUid, accountAge);
    }

#else  // _WIN64
    void InstallIdentityPatch() {}
    void SetRelayedIdentity(unsigned long long, unsigned int) {}
#endif
}
