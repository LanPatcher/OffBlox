// iat_hook.cpp - Import Address Table hooking implementation
//
// Walks the PE import descriptor table of the host EXE, finds the entry
// for (dllName, funcName), flips the page to PAGE_READWRITE, swaps the
// function pointer, and restores the original protection.

#include "iat_hook.h"
#include <cstring>

namespace RobloxStudioPatcher
{
    // Minimal x86/x64 instruction length decoder - only the opcodes we
    // actually see in ws2_32 function prologues. Returns 0 for anything
    // unrecognised (caller should abort).
    static SIZE_T InsnLen(const BYTE* p)
    {
#ifdef _WIN64
        // Skip (possibly multiple) prefixes, then a REX byte, to reach opcode.
        const BYTE* op = p;
        // operand-size / rep / segment prefixes occasionally precede prologue
        // insns; consume the common ones so the opcode decode stays aligned.
        while (*op == 0x66 || *op == 0x67 || *op == 0xF2 || *op == 0xF3) ++op;
        bool hasRex = (*op >= 0x40 && *op <= 0x4F);
        if (hasRex) ++op;
        BYTE b = *op;
        SIZE_T pre = (SIZE_T)(op - p);   // bytes consumed as prefixes/REX

        // ModRM (+SIB +disp) length, in bytes. Sets ripRel if the operand is
        // RIP-relative (mod=00, rm=101) - which we must NOT relocate, so the
        // caller aborts (returns 0).
        auto modrmLen = [](const BYTE* m, bool& ripRel) -> SIZE_T
        {
            BYTE mod = (m[0] >> 6) & 3;
            BYTE rm  = m[0] & 7;
            SIZE_T len = 1;                 // the ModRM byte itself
            if (mod == 3) return len;       // register-direct, no SIB/disp
            if (mod == 0 && rm == 5) { ripRel = true; return len + 4; } // [rip+disp32]
            if (rm == 4)                    // SIB present
            {
                len += 1;                   // SIB byte
                BYTE base = m[1] & 7;
                if (mod == 0 && base == 5) len += 4;   // disp32
                else if (mod == 1)         len += 1;   // disp8
                else if (mod == 2)         len += 4;   // disp32
            }
            else
            {
                if (mod == 1) len += 1;     // disp8
                if (mod == 2) len += 4;     // disp32
            }
            return len;
        };

        switch (b)
        {
        // PUSH/POP r64 (0x50-0x5F)
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            return pre + 1;

        case 0x88: case 0x89:   // MOV r/m, r
        case 0x8A: case 0x8B:   // MOV r, r/m
        case 0x8D:              // LEA r, m
        {
            bool ripRel = false;
            SIZE_T ml = modrmLen(op + 1, ripRel);
            if (ripRel) return 0;            // can't relocate RIP-relative - abort
            return pre + 1 + ml;
        }

        case 0x83:              // grp1 r/m, imm8
        {
            bool ripRel = false;
            SIZE_T ml = modrmLen(op + 1, ripRel);
            if (ripRel) return 0;
            return pre + 1 + ml + 1;
        }
        case 0x81:              // grp1 r/m, imm32
        {
            bool ripRel = false;
            SIZE_T ml = modrmLen(op + 1, ripRel);
            if (ripRel) return 0;
            return pre + 1 + ml + 4;
        }

        default:   return 0;     // unrecognised - abort
        }
#else
        // Helper: decode ModRM byte and return total extra bytes beyond opcode+ModRM.
        // Does NOT handle SIB (rm==4 with mod!=3) - if we see one we return 0
        // from the caller so the outer loop aborts safely rather than miscount.
        auto ModRmExtra = [](const BYTE* p) -> SIZE_T
        {
            BYTE mod = (p[1] >> 6) & 3;
            BYTE rm  = p[1] & 7;
            if (mod == 3) return 0;               // register operand, no extra bytes
            if (mod == 0 && rm == 5) return 4;    // disp32 direct
            if (rm == 4) return (SIZE_T)-1;       // SIB byte present - signal caller to abort
            if (mod == 1) return 1;               // disp8
            if (mod == 2) return 4;               // disp32
            return 0;
        };

        switch (*p)
        {
        // --- single-byte instructions ---
        case 0x40: case 0x41: case 0x42: case 0x43:  // INC reg32
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B:  // DEC reg32
        case 0x4C: case 0x4D: case 0x4E: case 0x4F:
        case 0x50: case 0x51: case 0x52: case 0x53:  // PUSH reg32
        case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5A: case 0x5B:  // POP reg32
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        case 0x90:                                    // NOP
        case 0x98:                                    // CWDE
        case 0x99:                                    // CDQ
        case 0xC3:                                    // RET (near) - can't copy, abort
            return (p[0] == 0xC3) ? 0 : 1;

        case 0xC2: return 0;   // RET imm16 - can't copy, abort

        // --- 2-byte: opcode + imm8 ---
        case 0x6A:  // PUSH imm8
        case 0xEB:  // JMP rel8 (hotpatch NOP stub)
            return 2;

        // --- 5-byte: opcode + imm32 ---
        case 0x68:  // PUSH imm32
        case 0xE8:  // CALL rel32  (don't copy - relative, would need fixup; abort)
        case 0xE9:  // JMP  rel32  (same)
            return (p[0] == 0x68) ? 5 : 0;

        // --- MOV reg, imm32  (B8+r) ---
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            return 5;

        // --- MOV r/m32, r32 or r32, r/m32 (+ModRM [+SIB] [+disp]) ---
        case 0x03:  // ADD r32, r/m32
        case 0x0B:  // OR  r32, r/m32
        case 0x1B:  // SBB r32, r/m32
        case 0x23:  // AND r32, r/m32
        case 0x2B:  // SUB r32, r/m32
        case 0x33:  // XOR r32, r/m32
        case 0x3B:  // CMP r32, r/m32
        case 0x85:  // TEST r/m32, r32
        case 0x87:  // XCHG r/m32, r32
        case 0x89:  // MOV r/m32, r32
        case 0x8B:  // MOV r32, r/m32
        case 0x8D:  // LEA r32, m
        {
            SIZE_T extra = ModRmExtra(p);
            if (extra == (SIZE_T)-1) return 0;  // SIB - abort
            return 2 + extra;
        }

        // --- TEST/NOT/NEG/MUL/IMUL/DIV/IDIV r/m32  (F7 /r) ---
        case 0xF7:
        {
            SIZE_T extra = ModRmExtra(p);
            if (extra == (SIZE_T)-1) return 0;
            // /0 (TEST) has an extra imm32 operand
            BYTE reg = (p[1] >> 3) & 7;
            return 2 + extra + (reg == 0 ? 4 : 0);
        }

        // --- ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m32, imm8  (83 /r ib) ---
        case 0x83:
        {
            SIZE_T extra = ModRmExtra(p);
            if (extra == (SIZE_T)-1) return 0;
            return 3 + extra;   // opcode + ModRM + imm8
        }

        // --- ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m32, imm32  (81 /r id) ---
        case 0x81:
        {
            SIZE_T extra = ModRmExtra(p);
            if (extra == (SIZE_T)-1) return 0;
            return 6 + extra;   // opcode + ModRM + imm32
        }

        // --- MOV r/m8, imm8  (C6 /0 ib) ---
        case 0xC6:
        {
            SIZE_T extra = ModRmExtra(p);
            if (extra == (SIZE_T)-1) return 0;
            return 3 + extra;
        }

        // --- MOV r/m32, imm32  (C7 /0 id) ---
        case 0xC7:
        {
            SIZE_T extra = ModRmExtra(p);
            if (extra == (SIZE_T)-1) return 0;
            return 6 + extra;
        }

        // --- MOV EAX, [imm32]  (A1 id) ---
        case 0xA1: return 5;
        // --- MOV [imm32], EAX  (A3 id) ---
        case 0xA3: return 5;

        // --- PUSH/POP FS/GS (26/2E/36/3E are seg overrides - don't support) ---

        // --- FF group: INC/DEC/CALL/JMP/PUSH r/m32 ---
        case 0xFF:
        {
            SIZE_T extra = ModRmExtra(p);
            if (extra == (SIZE_T)-1) return 0;
            BYTE reg = (p[1] >> 3) & 7;
            // /2 = CALL r/m32, /4 = JMP r/m32 - relative fixup not needed
            // (absolute indirect), safe to copy as-is IF mod==3 (register).
            // If it's a memory indirect (mod!=3) it's still absolute, safe.
            // But /2 and /4 with RIP-relative would need fixup - no RIP on x86.
            return 2 + extra;
        }

        default: return 0;   // unrecognised - abort
        }
#endif
    }

    // InlineHook - writes a JMP trampoline over the target function export.
    // Copies enough complete instructions to cover the patch, then appends
    // a jump back, giving the caller a safe trampoline to call through.
    bool InlineHook(const char* dllName,
                    const char* funcName,
                    void*  newFunction,
                    void** outOriginal)
    {
        if (!dllName || !funcName || !newFunction) return false;
        HMODULE hDll = GetModuleHandleA(dllName);
        if (!hDll) return false;
        auto target = reinterpret_cast<BYTE*>(GetProcAddress(hDll, funcName));
        if (!target) return false;

#ifdef _WIN64
        const SIZE_T kJmpSize = 14; // FF 25 00 00 00 00 [abs64]
#else
        const SIZE_T kJmpSize = 5;  // E9 rel32
#endif

        // Walk instructions until we've covered at least kJmpSize bytes.
        SIZE_T copied = 0;
        for (int i = 0; i < 32 && copied < kJmpSize; ++i)
        {
            SIZE_T len = InsnLen(target + copied);
            if (len == 0)
            {
                // Unrecognised instruction - bail out rather than corrupt.
                LogF(L"[udp_relay] InlineHook %hs: unrecognised insn at +%zu (byte=%02X), aborting\n",
                     funcName, copied, target[copied]);
                return false;
            }
            copied += len;
        }
        if (copied < kJmpSize) return false;

        // Allocate trampoline as executable.
        const SIZE_T kTrampolineSize = copied + kJmpSize + 8;
        BYTE* trampoline = reinterpret_cast<BYTE*>(
            VirtualAlloc(nullptr, kTrampolineSize,
                         MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE));
        if (!trampoline) return false;

        // Copy original instructions.
        std::memcpy(trampoline, target, copied);

        // Append jump back to target+copied.
        BYTE* retTarget = target + copied;
#ifdef _WIN64
        trampoline[copied + 0] = 0xFF;
        trampoline[copied + 1] = 0x25;
        *reinterpret_cast<int32_t*>(trampoline + copied + 2) = 0;
        *reinterpret_cast<void**>(trampoline + copied + 6) = retTarget;
#else
        trampoline[copied] = 0xE9;
        *reinterpret_cast<int32_t*>(trampoline + copied + 1) =
            static_cast<int32_t>(retTarget - (trampoline + copied + 5));
#endif

        if (outOriginal) *outOriginal = trampoline;

        // Patch target function.
        DWORD oldProtect = 0;
        if (!VirtualProtect(target, copied, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

#ifdef _WIN64
        BYTE patch[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0,0,0,0,0,0,0,0 };
        *reinterpret_cast<void**>(patch + 6) = newFunction;
#else
        BYTE patch[5] = { 0xE9, 0,0,0,0 };
        *reinterpret_cast<int32_t*>(patch + 1) =
            static_cast<int32_t>(
                reinterpret_cast<BYTE*>(newFunction) - (target + 5));
#endif
        std::memcpy(target, patch, kJmpSize);
        // Zero out any remaining copied bytes with NOPs so disassemblers
        // don't get confused by leftover instruction tails.
        if (copied > kJmpSize)
            std::memset(target + kJmpSize, 0x90, copied - kJmpSize);

        VirtualProtect(target, copied, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), target, copied);
        return true;
    }

    bool IatHook(const char* dllName,
                 const char* funcName,
                 void* newFunction,
                 void** outOriginal)
    {
        if (!dllName || !funcName || !newFunction) return false;

        // The host EXE - i.e. RobloxStudioBeta.exe - is the main module
        // returned by GetModuleHandleW(nullptr). We don't want to hook the
        // IATs of every loaded module, just this one.
        HMODULE hMod = GetModuleHandleW(nullptr);
        if (!hMod) return false;

        auto base = reinterpret_cast<BYTE*>(hMod);
        auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        IMAGE_DATA_DIRECTORY& importDir =
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress == 0 || importDir.Size == 0) return false;

        auto importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            base + importDir.VirtualAddress);

        for (; importDesc->Name != 0; ++importDesc)
        {
            const char* curDll = reinterpret_cast<const char*>(base + importDesc->Name);
            if (_stricmp(curDll, dllName) != 0) continue;

            // OriginalFirstThunk (INT) holds the names; FirstThunk (IAT)
            // initially holds names but the loader overwrites it with
            // resolved addresses by the time we run.
            //
            // Some linkers/tools (including stud_pe when adding imports!)
            // emit an import descriptor with OriginalFirstThunk == 0. In
            // that case the loader uses FirstThunk for both name lookup
            // AND the resolved IAT, then overwrites it - so we have no
            // way to recover names. Skip those descriptors rather than
            // dereferencing garbage at base+0 (which is the DOS header).
            if (importDesc->OriginalFirstThunk == 0 ||
                importDesc->FirstThunk == 0)
            {
                continue;
            }

            auto nameThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                base + importDesc->OriginalFirstThunk);
            auto iatThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                base + importDesc->FirstThunk);

            // Build a lookup table: resolve each ordinal-only thunk to a
            // name by calling GetProcAddress on the loaded DLL and comparing
            // the resulting address against what the IAT slot already holds.
            // This lets us match sendto even when it is imported by ordinal.
            HMODULE hTargetDll = GetModuleHandleA(dllName);

            for (; nameThunk->u1.AddressOfData != 0; ++nameThunk, ++iatThunk)
            {
                if (IMAGE_SNAP_BY_ORDINAL(nameThunk->u1.Ordinal))
                {
                    // Ordinal-only import: resolve by comparing the IAT slot's
                    // current value against GetProcAddress(dll, funcName).
                    // If they match this slot IS our target function.
                    if (!hTargetDll) continue;
                    FARPROC target = GetProcAddress(hTargetDll, funcName);
                    if (!target) continue;
                    if (reinterpret_cast<void*>(iatThunk->u1.Function)
                            != reinterpret_cast<void*>(target)) continue;
                    // Fall through to the swap below.
                }
                else
                {
                    auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        base + nameThunk->u1.AddressOfData);
                    if (_stricmp(importByName->Name, funcName) != 0) continue;
                }

                // Found it. Flip the page to writable, swap the pointer,
                // restore protection.
                DWORD oldProtect = 0;
                if (!VirtualProtect(&iatThunk->u1.Function,
                                    sizeof(iatThunk->u1.Function),
                                    PAGE_READWRITE,
                                    &oldProtect))
                {
                    return false;
                }

                // --- common swap path (reached from both name and ordinal branches) ---
                if (outOriginal)
                    *outOriginal = reinterpret_cast<void*>(iatThunk->u1.Function);

                iatThunk->u1.Function =
                    reinterpret_cast<ULONGLONG>(newFunction);

                DWORD ignored = 0;
                VirtualProtect(&iatThunk->u1.Function,
                               sizeof(iatThunk->u1.Function),
                               oldProtect,
                               &ignored);
                return true;
            }
        }
        return false;
    }

    // InlineHookVA - same mechanics as InlineHook but targets a raw virtual
    // address inside the host EXE rather than a DLL export resolved by name.
    // Used to hook internal functions whose VA is fixed (no ASLR on this build).
    bool InlineHookVA(uintptr_t targetVA,
                      void*  newFunction,
                      void** outOriginal)
    {
        if (!targetVA || !newFunction) return false;
        auto* target = reinterpret_cast<BYTE*>(targetVA);

#ifdef _WIN64
        const SIZE_T kJmpSize = 14;
#else
        const SIZE_T kJmpSize = 5;
#endif

        // Log the actual bytes at the target so we have them if the prologue
        // check ever fires or things go wrong.
        LogF(L"[InlineHookVA] target=%p bytes: %02X %02X %02X %02X %02X %02X %02X %02X\n",
             (void*)target,
             target[0], target[1], target[2], target[3],
             target[4], target[5], target[6], target[7]);

        // Walk instructions until we have stolen enough bytes for the JMP patch.
        SIZE_T copied = 0;
        for (int i = 0; i < 32 && copied < kJmpSize; ++i)
        {
            SIZE_T len = InsnLen(target + copied);
            if (len == 0)
            {
                LogF(L"[InlineHookVA] unrecognised insn at %p+%zu (byte=%02X) -- aborting\n",
                     (void*)target, copied, target[copied]);
                return false;
            }
            copied += len;
        }
        if (copied < kJmpSize)
        {
            LogF(L"[InlineHookVA] couldn't steal %zu bytes at %p -- aborting\n",
                 kJmpSize, (void*)target);
            return false;
        }

        // Allocate executable trampoline: stolen bytes + JMP back.
        const SIZE_T kTrampolineSize = copied + kJmpSize + 8;
        BYTE* trampoline = reinterpret_cast<BYTE*>(
            VirtualAlloc(nullptr, kTrampolineSize,
                         MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE));
        if (!trampoline)
        {
            LogF(L"[InlineHookVA] VirtualAlloc failed (err=%lu)\n", GetLastError());
            return false;
        }

        std::memcpy(trampoline, target, copied);

        BYTE* retTarget = target + copied;
#ifdef _WIN64
        trampoline[copied + 0] = 0xFF;
        trampoline[copied + 1] = 0x25;
        *reinterpret_cast<int32_t*>(trampoline + copied + 2) = 0;
        *reinterpret_cast<void**>(trampoline + copied + 6) = retTarget;
#else
        trampoline[copied] = 0xE9;
        *reinterpret_cast<int32_t*>(trampoline + copied + 1) =
            static_cast<int32_t>(retTarget - (trampoline + copied + 5));
#endif

        FlushInstructionCache(GetCurrentProcess(), trampoline, kTrampolineSize);
        if (outOriginal) *outOriginal = trampoline;

        DWORD oldProtect = 0;
        if (!VirtualProtect(target, copied, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            LogF(L"[InlineHookVA] VirtualProtect failed (err=%lu)\n", GetLastError());
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }

#ifdef _WIN64
        BYTE patch[14] = { 0xFF, 0x25, 0,0,0,0, 0,0,0,0,0,0,0,0 };
        *reinterpret_cast<void**>(patch + 6) = newFunction;
#else
        BYTE patch[5] = { 0xE9, 0,0,0,0 };
        *reinterpret_cast<int32_t*>(patch + 1) =
            static_cast<int32_t>(
                reinterpret_cast<BYTE*>(newFunction) - (target + 5));
#endif
        std::memcpy(target, patch, kJmpSize);
        if (copied > kJmpSize)
            std::memset(target + kJmpSize, 0x90, copied - kJmpSize);

        VirtualProtect(target, copied, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), target, copied);

        LogF(L"[InlineHookVA] hooked %p -> %p (trampoline %p, %zu stolen bytes)\n",
             (void*)target, newFunction, (void*)trampoline, copied);
        return true;
    }
}
