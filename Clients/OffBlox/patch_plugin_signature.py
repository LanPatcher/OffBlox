#!/usr/bin/env python3
"""
OffBloxModern - disable Studio's built-in PLUGIN SIGNATURE check.

WHY
---
Studio loads built-in plugins from the OTA store
    %LOCALAPPDATA%\\Roblox\\OTAPlugins\\Deployed\\BuiltInStandalonePlugins\\
and verifies each plugin .rbxm's embedded signature (SIGN/SIGU chunks).
Editing a plugin (e.g. patching its subdomain URLs to localhost) changes the
bytes, so the signature no longer matches and Studio refuses to load it:

    Critical [FLog::PluginLoadingEnhanced] Failed to verify signature for plugin '...StartPage.rbxm'
    Error    [FLog::PluginLoadingEnhanced] PluginLoadUtils::loadPlugin returned nullptr {... OTA ...}

WHAT THIS DOES
--------------
There are three code sites that emit "Failed to verify signature for plugin".
Each is guarded by a branch that, when the signature IS valid, jumps over the
failure handler to the normal "continue loading" path:

    site1 (fn 0x1ad7f30):  cmp byte[rsp+0x40],0 ; JNE  continue
    site2 (fn 0x1ad7f30):  cmp byte[rsp+0x41],0 ; JNE  continue
    site3 (fn 0x1ada410):  call verifySig(0x1ad9370) ; test al,al ; JNE continue

This converts each of those conditional jumps into an UNCONDITIONAL jump, so the
"continue loading" path is always taken - signature valid or not. For genuinely
valid plugins the branch was already taken, so their behavior is unchanged; only
invalid/edited plugins are now allowed. Nothing else in Studio is touched.

It also reverts the earlier (ineffective) end-gate patch if present.

Each edit is matched by a unique byte signature and is length-preserving
(JNE rel32 -> JMP rel32 + NOP). The script refuses to touch a site whose
signature isn't found exactly once, so it can't corrupt an unexpected build.

USAGE
-----
    python patch_plugin_signature.py                       # auto-find exe(s) next to this script
    python patch_plugin_signature.py OffBlox.exe           # patch a specific file

Built/verified against OffBlox.exe / RobloxStudioBeta.exe 0.725.0.7251148
(212,510,720 bytes). A .orig_sig backup is written the first time.
Re-run after any Studio re-download. Launch via the OffBlox launcher (OffBlox.exe).
"""

import sys, os, shutil

# --- revert the earlier end-gate patch (harmless but ineffective) ---
OLD_PATCH = bytes.fromhex("e8c1efb40484c0e95206000090")
OLD_SIG   = bytes.fromhex("e8c1efb40484c00f8551060000")

# --- the three signature-failure gates: (name, find, replace) ---
# JNE rel32 (0F 85 ..)  ->  JMP rel32 (E9 ..) + NOP (90)   [length preserved]
SITES = [
    ("site1 cmp[rsp+0x40]", bytes.fromhex("807c2440000f853f020000"),
                            bytes.fromhex("807c244000e94002000090")),
    ("site2 cmp[rsp+0x41]", bytes.fromhex("807c2441000f853b010000"),
                            bytes.fromhex("807c244100e93c01000090")),
    ("site3 verifySig",     bytes.fromhex("e861ebffff84c00f850e020000"),
                            bytes.fromhex("e861ebffff84c0e90f02000090")),
]

CANDIDATES = ["OffBlox.exe", "RobloxStudioBeta.exe"]


def patch_file(path):
    data = bytearray(open(path, "rb").read())
    backed = os.path.exists(path + ".orig_sig")

    def backup():
        nonlocal backed
        if not backed:
            shutil.copy2(path, path + ".orig_sig")
            print(f"  backup written: {path}.orig_sig")
            backed = True

    changed = False

    # revert old end-gate patch
    if data.count(OLD_PATCH) == 1 and data.count(OLD_SIG) == 0:
        backup()
        i = data.find(OLD_PATCH); data[i:i+len(OLD_PATCH)] = OLD_SIG
        print("  reverted earlier end-gate patch")
        changed = True

    ok = 0
    for name, sig, rep in SITES:
        if data.count(rep) >= 1 and data.count(sig) == 0:
            print(f"  [skip] {name}: already patched")
            ok += 1
            continue
        n = data.count(sig)
        if n == 0:
            print(f"  [WARN] {name}: signature not found (wrong build?) - skipped")
            continue
        if n != 1:
            print(f"  [WARN] {name}: found {n} matches (ambiguous) - skipped")
            continue
        backup()
        i = data.find(sig); data[i:i+len(rep)] = rep
        print(f"  [ok]  {name}: patched at 0x{i:x}")
        ok += 1; changed = True

    if changed:
        with open(path, "wb") as fh:
            fh.write(data)
    print(f"  -> {ok}/{len(SITES)} signature gates open in {os.path.basename(path)}")
    return ok == len(SITES)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    targets = sys.argv[1:] or [os.path.join(here, n) for n in CANDIDATES
                               if os.path.exists(os.path.join(here, n))]
    if not targets:
        print("No OffBlox.exe / RobloxStudioBeta.exe found next to this script.")
        print("Pass the path explicitly:  python patch_plugin_signature.py <exe>")
        sys.exit(1)

    all_ok = True
    for t in targets:
        if not os.path.exists(t):
            print(f"  [WARN] not found: {t}"); all_ok = False; continue
        print(f"Patching {t} ...")
        all_ok &= patch_file(t)

    if all_ok:
        print("\nDone. Restart Studio. Edited/unsigned plugins will now load.")
        print("Make sure your fixed StartPage.rbxm is in:")
        print(r"  %LOCALAPPDATA%\Roblox\OTAPlugins\Deployed\BuiltInStandalonePlugins\StartPage.rbxm")
    else:
        print("\nSome sites were not patched - see warnings above.")


if __name__ == "__main__":
    main()
