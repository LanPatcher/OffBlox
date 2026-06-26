// identity_patch.cpp - see identity_patch.h for the design.

#include "identity_patch.h"
#include <cstdint>
#include <cstring>
#include <string>

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

#else  // _WIN64 ------------------------------------------------------------
    //
    // x64 USERID FIX - call-site redirect (no entry hook, no field offsets).
    //
    // createServerPlayer (RVA 0x4A17A80) gives every fresh player a DEFAULT
    // userId that is the NEGATIVE of an internal counter, assigned right after it
    // formats the "Player%d" name. The tail of that function (this build):
    //
    //   0x4A1835C  mov   rcx,[r12]; add rcx,0xC8     ; player UserId subobject
    //   0x4A18367  dec   dword [r13+0x2A4]           ; counter -> goes negative
    //   0x4A1836E  movsxd rdx, dword [r13+0x2A4]     ; rdx = negative placeholder id
    //   0x4A18375  call  0x144A00D50                 ; SetUserId(player, rdx)
    //
    // (So the default UserId is -(player#), NOT 0 - the earlier presumption.)
    //
    // The previous attempt hooked createServerPlayer's ENTRY and wrote the Player
    // object at a guessed offset, which corrupted the player and crashed. Instead
    // we redirect ONLY the `call` at 0x4A18375 to a tiny thunk that, when we have
    // a relayed userId, swaps rdx for it and tail-jumps to the engine's own
    // setter. The engine writes whatever field it always did - we only change the
    // value from the negative placeholder to ours. The thunk touches r10 only
    // (volatile, non-argument), leaving rcx/rdx/r8/r9/rax intact for the setter.

    static volatile unsigned long long g_uid       = 0;
    static volatile unsigned char      g_haveUid   = 0;
    static bool                        g_installed = false;

    // The SetUserId call site (build-specific, validated before any write).
    static const uintptr_t kSetUidCallRva = 0x4A18375;
    // The 25 bytes immediately preceding the call (mov/add/dec/movsxd) - a unique
    // fingerprint of the placeholder-id site, so we never patch the wrong call.
    static const unsigned char kSetUidAnchor[] = {
        0x49,0x8B,0x0C,0x24,                  // mov rcx,[r12]
        0x48,0x81,0xC1,0xC8,0x00,0x00,0x00,   // add rcx,0xC8
        0x41,0xFF,0x8D,0xA4,0x02,0x00,0x00,   // dec dword [r13+0x2A4]
        0x49,0x63,0x95,0xA4,0x02,0x00,0x00    // movsxd rdx,[r13+0x2A4]
    };

    // UserId int64 backing field, relative to the SetUserId `this` (the player
    // subobject = player+0xC8). Confirmed against this build:
    //   setter 0x4A00D50 writes  mov [rbx+0x240], rax   (rbx = this)
    //   getter 0x49FC860 reads   mov rax, [rcx+0x240]
    static const unsigned int kUserIdFieldOff = 0x240;

    // Allocate executable memory within +/-2GB of `anchor` so a 32-bit relative
    // call at the patch site can reach it. Walks outward from the anchor.
    static void* AllocNear(void* anchor, size_t size)
    {
        SYSTEM_INFO si; GetSystemInfo(&si);
        uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
        uintptr_t a = (uintptr_t)anchor;
        const uintptr_t span = 0x70000000ull;       // ~1.75 GB, safely < 2GB
        for (uintptr_t off = gran; off < span; off += gran)
        {
            for (int dir = 0; dir < 2; ++dir)
            {
                uintptr_t cand = dir ? (a - off) : (a + off);
                cand &= ~(gran - 1);
                void* p = VirtualAlloc((void*)cand, size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (p) return p;
            }
        }
        return nullptr;                              // caller falls back / skips
    }

    // Position-independent thunk that REPLACES the SetUserId call at the tail of
    // createServerPlayer. At that call site rcx = the subobject (this) and
    // rdx = the engine's negative placeholder id.
    //
    //   if (g_haveUid):  *(int64*)(rcx + 0x240) = g_uid ; ret   // RAW write
    //   else:            jmp realSetter                          // default id
    //
    // The raw write sets the property's backing field directly, so the getter
    // and every consumer return our id - but WITHOUT running the setter's
    // property-changed / replication / account+character callback path, which is
    // exactly what froze/crashed the offline server when a positive id was set
    // at creation. We skip that path entirely.
    static void* BuildUidThunk(void* realTarget)
    {
        unsigned char c[80]; size_t n = 0;
        auto imm64 = [&](const void* p){
            unsigned long long v = (unsigned long long)(uintptr_t)p;
            std::memcpy(c + n, &v, 8); n += 8; };

        c[n++]=0x49; c[n++]=0xBA; imm64((void*)&g_haveUid);   // mov r10,&g_haveUid
        c[n++]=0x41; c[n++]=0x80; c[n++]=0x3A; c[n++]=0x00;   // cmp byte [r10],0
        c[n++]=0x74; size_t jeRel = n; c[n++]=0x00;           // je pass
        c[n++]=0x49; c[n++]=0xBA; imm64((void*)&g_uid);       // mov r10,&g_uid
        c[n++]=0x4D; c[n++]=0x8B; c[n++]=0x12;                // mov r10,[r10]  (r10=g_uid)
        c[n++]=0x4C; c[n++]=0x89; c[n++]=0x91;                // mov [rcx+disp32], r10
        std::memcpy(c + n, &kUserIdFieldOff, 4); n += 4;
        c[n++]=0xC3;                                          // ret  (skip setter)
        c[jeRel] = (unsigned char)(n - (jeRel + 1));          // pass:
        c[n++]=0x49; c[n++]=0xBA; imm64(realTarget);          // mov r10,realTarget
        c[n++]=0x41; c[n++]=0xFF; c[n++]=0xE2;                // jmp r10

        // Must be within +/-2GB of the patched call site (realTarget is in the
        // same module as the call), so allocate near it for the rel32 to reach.
        void* mem = AllocNear(realTarget, n);
        if (!mem) return nullptr;
        std::memcpy(mem, c, n);
        FlushInstructionCache(GetCurrentProcess(), mem, n);
        return mem;
    }

    static int InstallUidRedirectImpl()
    {
        __try
        {
            unsigned char* base = reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
            if (!base) return 0;
            unsigned char* call   = base + kSetUidCallRva;
            unsigned char* anchor = call - sizeof(kSetUidAnchor);
            if (std::memcmp(anchor, kSetUidAnchor, sizeof(kSetUidAnchor)) != 0)
            {
                LogF(L"[identity] x64 userid anchor mismatch @%p - skipping\n", anchor);
                return 0;
            }
            if (call[0] != 0xE8)
            {
                LogF(L"[identity] x64 userid: site not a call (%02X) - skipping\n", call[0]);
                return 0;
            }
            int32_t rel = *reinterpret_cast<int32_t*>(call + 1);
            void* realTarget = call + 5 + rel;
            void* thunk = BuildUidThunk(realTarget);
            if (!thunk) { LogF(L"[identity] x64 userid: thunk alloc failed\n"); return 0; }

            intptr_t dist = reinterpret_cast<unsigned char*>(thunk) - (call + 5);
            if (dist > 0x7FFF0000ll || dist < -0x7FFF0000ll)
            {
                LogF(L"[identity] x64 userid: thunk out of rel32 range (%lld) - skipping\n",
                     (long long)dist);
                return 0;
            }
            int32_t newRel = static_cast<int32_t>(dist);
            DWORD op = 0;
            if (!VirtualProtect(call + 1, 4, PAGE_EXECUTE_READWRITE, &op)) return 0;
            *reinterpret_cast<int32_t*>(call + 1) = newRel;
            DWORD ig = 0; VirtualProtect(call + 1, 4, op, &ig);
            FlushInstructionCache(GetCurrentProcess(), call + 1, 4);

            LogF(L"[identity] x64 userid setter redirected @%p (real=%p thunk=%p)\n",
                 call, realTarget, thunk);
            return 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LogF(L"[identity] x64 userid: exception during install\n");
            return 0;
        }
    }

    void InstallIdentityPatch()
    {
        if (g_installed) return;
        g_installed = true;
        InstallUidRedirectImpl();
    }

    // The override now does a RAW field write (no property-setter callbacks),
    // which is why it no longer triggers the account/character freeze that the
    // old setter-call path did. It is therefore ON BY DEFAULT. If it ever
    // misbehaves it can be disabled without a rebuild by dropping a file named
    // "userid_off.txt" next to the DLL.
    static bool UseridOverrideEnabled()
    {
        std::wstring dir = GetDllDirectory();
        if (dir.empty()) return true;               // default ON
        DWORD a = GetFileAttributesW((dir + L"userid_off.txt").c_str());
        bool off = (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
        return !off;
    }

    void SetRelayedIdentity(unsigned long long userId, unsigned int /*accountAge*/)
    {
        InstallIdentityPatch();                      // ensure the call-site redirect exists
        bool on = UseridOverrideEnabled();
        g_uid     = userId;
        g_haveUid = (on && userId != 0) ? 1 : 0;
        LogF(L"[identity] relayed userId=%llu override=%ls have=%d (raw field write)\n",
             userId, on ? L"ON" : L"OFF(userid_off.txt present)", (int)g_haveUid);
    }
#endif
}
