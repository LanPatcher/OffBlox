// devconsole_lock.cpp - see devconsole_lock.h.
//
// Forces the DFFlag "LuaGetCanManageAsync" ON in-process, from the DLL, so the
// server-side canManage verification the Developer Console depends on is
// actually performed instead of being skipped (which defaults the console
// OPEN for everyone). No CoreGui/Lua edit; no reliance on a FastFlag config
// file (which does not take effect on a Studio test-server child process).
//
// WHY THE FLAG IS OFF ON A STUDIO TEST SERVER
//   LuaGetCanManageAsync is a *dynamic* FastFlag (DFFlag). DFFlags are normally
//   delivered from the ClientSettings/PCStudioApp settings fetch at startup.
//   A Play -> Start Server (studio test server) child process takes the flag's
//   compiled default unless that settings response explicitly carries the flag,
//   so a config/FFlag override doesn't reliably reach it - which is why setting
//   it "the FFlag way" does nothing here. Forcing it in the injected DLL bypasses
//   the whole settings path: we make the code that reads the flag behave as if
//   it were on, regardless of the byte's runtime value or load timing.
//
// THE FLAG BYTE (0x14c783f38, .data) HAS TWO READERS:
//   1) Getter  0x144a39630 :  movzx eax, byte [flag] ; ret
//        i.e. IsLuaGetCanManageAsyncEnabled(). Callers use it to decide whether
//        to PERFORM the canManage verification at all. Off -> verification is
//        skipped -> console fails open.
//        FORCE: overwrite the 7-byte movzx with `mov eax,1 ; nop ; nop` so it
//        always returns 1 (enabled). The trailing `ret` is preserved.
//   2) Worker gate 0x144a41329 :  movzx eax,[flag] ; test al,al ; jne 0x144a41392
//        Inside the GetCanManageAsync worker: flag off -> reject with
//        "...not yet enabled" (no HTTP); flag on -> proceed to the request.
//        FORCE: flip the conditional jump to UNCONDITIONAL (75 -> EB) so the
//        worker always proceeds into the request path.
//
//   Patching BOTH readers makes the feature on regardless of the flag value,
//   the settings fetch, or load order - timing-independent and config-proof.
//
// AFTER THIS LANDS
//   With verification forced on, the server should once again issue its
//   canManage request; the AUTH-DIAG webserver logging will show exactly which
//   URL/params it sends so the webserver can answer it host-only. (If it turns
//   out to ride a universe-scoped /permissions URL, the webserver gate is the
//   next step; this patch is what makes the request happen in the first place.)
//
// RVAs are for the 82ca build (the unpacked exe you run, md5 e3dc264b...).

#include "devconsole_lock.h"
#include "patcher.h"

#include <cstdint>
#include <cstring>

namespace RobloxStudioPatcher
{
    extern bool IsStartClientTask_Pub();
    extern bool IsStartServerTask_Pub();

    // ---- CONFIGURE (per build) ------------------------------------------
    // Reader #1: IsLuaGetCanManageAsyncEnabled() getter.
    static const uintptr_t kGetterRva = 0x04a39630;
    static const unsigned char kGetterProbe[8] =
        { 0x0F, 0xB6, 0x05, 0x01, 0xA9, 0xD4, 0x07,   // movzx eax,[rip+0x7d4a901]
          0xC3 };                                      // ret
    static const unsigned char kGetterPatch[7] =
        { 0xB8, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90 };  // mov eax,1 ; nop ; nop

    // Reader #2: the worker's inline gate; flip jne -> jmp.
    static const uintptr_t kGateProbeRva = 0x04a41329;
    static const unsigned char kGateProbe[11] =
        { 0x0F, 0xB6, 0x05, 0x08, 0x2C, 0xD4, 0x07,   // movzx eax,[rip+0x7d42c08]
          0x84, 0xC0,                                  // test al,al
          0x75, 0x5E };                                // jne 0x144a41392
    static const uintptr_t kGateJneRva = 0x04a41332;

    // Reader #3/#4: dispatcher result-SELECTOR gates.
    //   The canManage dispatcher (0x144a32840) chooses, based on gate byte
    //   0x14cd8c1e8, between the real (HTTP-backed) canManage path and a
    //   canned result that issues NO request. That byte is zero-initialised
    //   .data and stays 0 on a Studio test-server child, so the canned
    //   (fail-OPEN, console-for-everyone) path is taken by default.
    //   Two call sites use the same gate (fresh-holder + cached-holder); each
    //   is `cmp byte[gate],dil ; je <canned>`. Forcing the `je` to fall
    //   through makes the server always run the HTTP permission check.
    static const uintptr_t kDispatch1Rva = 0x04a32862;  // je opcode at +7
    static const unsigned char kDispatch1Probe[9] =
        { 0x40,0x38,0x3D,0x7F,0x99,0x35,0x08, 0x74,0x60 };
    static const uintptr_t kDispatch2Rva = 0x04a3293f;  // je opcode at +7
    static const unsigned char kDispatch2Probe[9] =
        { 0x40,0x38,0x3D,0xA2,0x98,0x35,0x08, 0x74,0x6C };
    // ----------------------------------------------------------------------

    static bool WriteBytes(unsigned char* dst, const unsigned char* src, size_t n)
    {
        DWORD oldP = 0;
        if (!VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &oldP))
        {
            LogF(L"[devconsole_lock] VirtualProtect failed @ %p (err=%lu)\n",
                 (void*)dst, GetLastError());
            return false;
        }
        std::memcpy(dst, src, n);
        VirtualProtect(dst, n, oldP, &oldP);
        FlushInstructionCache(GetCurrentProcess(), dst, n);
        return true;
    }

    // True if <name> exists next to the DLL (used for runtime overrides
    // without a rebuild).
    static bool SidecarExists(const wchar_t* name)
    {
        std::wstring path = GetDllDirectory() + name;
        return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    }

    void StartDevConsoleLock()
    {
        // Game launches only (the studio test server + connecting clients).
        // The editor is left untouched.
        if (!IsStartClientTask_Pub() && !IsStartServerTask_Pub())
        {
            LogF(L"[devconsole_lock] not a game launch - skipping (editor untouched)\n");
            return;
        }

        HMODULE host = GetModuleHandleW(nullptr);
        uintptr_t base = reinterpret_cast<uintptr_t>(host);

        // ---- Reader #1: getter -> always return 1 --------------------------
        unsigned char* g = reinterpret_cast<unsigned char*>(base + kGetterRva);
        if (std::memcmp(g, kGetterProbe, sizeof(kGetterProbe)) != 0)
        {
            LogF(L"[devconsole_lock] getter mismatch @ %p "
                 L"(%02X %02X %02X %02X %02X %02X %02X %02X) - skipping getter\n",
                 (void*)g, g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7]);
        }
        else if (WriteBytes(g, kGetterPatch, sizeof(kGetterPatch)))
        {
            LogF(L"[devconsole_lock] LuaGetCanManageAsync getter @ %p forced -> "
                 L"return 1 (verification enabled)\n", (void*)g);
        }

        // ---- Reader #2: worker gate -> unconditional jump ------------------
        unsigned char* probe = reinterpret_cast<unsigned char*>(base + kGateProbeRva);
        unsigned char* jne   = reinterpret_cast<unsigned char*>(base + kGateJneRva);
        if (std::memcmp(probe, kGateProbe, sizeof(kGateProbe)) != 0)
        {
            LogF(L"[devconsole_lock] worker gate mismatch @ %p - skipping gate\n",
                 (void*)probe);
        }
        else if (*jne == 0xEB)
        {
            LogF(L"[devconsole_lock] worker gate @ %p already forced (EB)\n", (void*)jne);
        }
        else if (*jne != 0x75)
        {
            LogF(L"[devconsole_lock] worker gate @ %p unexpected opcode %02X - skipping\n",
                 (void*)jne, *jne);
        }
        else
        {
            unsigned char eb = 0xEB;
            if (WriteBytes(jne, &eb, 1))
                LogF(L"[devconsole_lock] worker gate @ %p forced (75->EB, proceed)\n",
                     (void*)jne);
        }

        // ---- Reader #3/#4: dispatcher gates -> always HTTP canManage path --
        if (SidecarExists(L"devconsole_dispatch_off.txt"))
        {
            LogF(L"[devconsole_lock] dispatcher force disabled by sidecar "
                 L"(devconsole_dispatch_off.txt); flag patches still applied\n");
        }
        else
        {
            const bool invert = SidecarExists(L"devconsole_dispatch_invert.txt");
            const uintptr_t   rvas[2]    = { kDispatch1Rva, kDispatch2Rva };
            const unsigned char* probes[2] = { kDispatch1Probe, kDispatch2Probe };
            for (int i = 0; i < 2; ++i)
            {
                unsigned char* p = reinterpret_cast<unsigned char*>(base + rvas[i]);
                if (std::memcmp(p, probes[i], 9) != 0)
                {
                    LogF(L"[devconsole_lock] dispatcher site %d mismatch @ %p "
                         L"(%02X %02X %02X %02X %02X %02X %02X %02X %02X) - skipping\n",
                         i + 1, (void*)p, p[0], p[1], p[2], p[3], p[4],
                         p[5], p[6], p[7], p[8]);
                    continue;
                }
                unsigned char* je = p + 7;             // the 'je' opcode byte
                if (*je == 0x90 || *je == 0xEB)
                {
                    LogF(L"[devconsole_lock] dispatcher site %d @ %p already patched "
                         L"(%02X)\n", i + 1, (void*)je, *je);
                    continue;
                }
                if (!invert)
                {
                    unsigned char nops[2] = { 0x90, 0x90 };   // fall through -> HTTP path
                    if (WriteBytes(je, nops, 2))
                        LogF(L"[devconsole_lock] dispatcher site %d @ %p forced "
                             L"(74 -> 90 90, always HTTP canManage check)\n",
                             i + 1, (void*)je);
                }
                else
                {
                    unsigned char jmp[2] = { 0xEB, je[1] };   // force canned path (debug)
                    if (WriteBytes(je, jmp, 2))
                        LogF(L"[devconsole_lock] dispatcher site %d @ %p INVERTED "
                             L"(74 -> EB, always canned path)\n", i + 1, (void*)je);
                }
            }
        }

        LogF(L"[devconsole_lock] DFFlagLuaGetCanManageAsync forced ON in-process "
             L"(both readers) - server canManage verification re-enabled\n");
    }
}
