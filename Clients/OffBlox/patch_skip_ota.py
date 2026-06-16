#!/usr/bin/env python3
r"""
Make OffBlox Studio behave as if the OTA plugin folder is EMPTY, so it falls back
to the internal/install built-in plugins.

You confirmed this empirically: deleting everything in
    %LOCALAPPDATA%\Roblox\OTAPlugins\Deployed\BuiltInStandalonePlugins
makes Studio load the internal plugins instead. This patch reproduces that state
permanently, in the exe, without you having to delete anything.

How it works
------------
The OTA store-scan routine builds the list of deployed plugins:
    cmp rbx,rax ; je <emptyReturn> ; <loop that adds each file>
We force that jump UNCONDITIONAL, so the scan always returns an EMPTY list - i.e.
Studio sees the OTA folder as empty. Its validation then finds the known-plugins
(from OTADataCache.json) don't match the (empty) file system, clears the OTA
known-list, and the loader falls back to the internal built-in plugins.

IMPORTANT: this also REVERTS the earlier "validation always passes" patch, because
that patch blocked the very clear/fallback we now want. (That's why the previous
combo failed: the two patches cancelled out.)

Matched by unique byte signatures; refuses to run if a signature isn't found
exactly once. Writes a .orig_ota backup once. Keep patch_plugin_signature.py
applied so the internal/edited plugins still load.

    python patch_skip_ota.py
    python patch_skip_ota.py OffBlox.exe
"""

import sys, os, shutil

PATCHES = [
    # OTA store-scan -> always empty (Studio sees the OTA folder as empty)
    ("OTA scan -> empty (fall back to internal)",
     bytes.fromhex("483bd80f842c01000049bcffffffffffffff03"),   # cmp rbx,rax; je end;  movabs r12,..
     bytes.fromhex("483bd8e92d0100009049bcffffffffffffff03")),  # cmp rbx,rax; jmp end; nop; movabs r12,..
]

# Undo the earlier validation-always-pass patch (it blocked the clear/fallback).
REVERTS = [
    ("undo validation->always-pass",
     bytes.fromhex("84c0909090909090b301"),                     # patched (test;nop*6;mov bl,1)
     bytes.fromhex("84c00f8468010000b301")),                    # original (test;je clear;mov bl,1)
]

CANDIDATES = ["OffBlox.exe", "RobloxStudioBeta.exe"]


def patch_file(path):
    data = bytearray(open(path, "rb").read())
    backed = os.path.exists(path + ".orig_ota")
    def backup():
        nonlocal backed
        if not backed:
            shutil.copy2(path, path + ".orig_ota"); backed = True
            print(f"  backup: {path}.orig_ota")
    for name, bad, good in REVERTS:
        if data.count(bad) == 1:
            backup(); i = data.find(bad); data[i:i+len(good)] = good
            print(f"  [revert] {name}")
    ok = 0
    for name, sig, rep in PATCHES:
        if data.count(rep) >= 1 and data.count(sig) == 0:
            print(f"  [skip] {name}: already patched"); ok += 1; continue
        n = data.count(sig)
        if n != 1:
            print(f"  [WARN] {name}: signature found {n}x (need 1) - skipped"); continue
        backup(); i = data.find(sig); data[i:i+len(rep)] = rep
        print(f"  [ok] {name} @ 0x{i:x}"); ok += 1
    open(path, "wb").write(data)
    print(f"  -> {ok}/{len(PATCHES)} patch(es) applied in {os.path.basename(path)}")
    return ok == len(PATCHES)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    targets = sys.argv[1:] or [os.path.join(here, n) for n in CANDIDATES
                               if os.path.exists(os.path.join(here, n))]
    if not targets:
        print("No OffBlox.exe / RobloxStudioBeta.exe found next to this script."); sys.exit(1)
    ok = False
    for t in targets:
        if not os.path.exists(t):
            print(f"  [WARN] not found: {t}"); continue
        print(f"Patching {t} ...")
        ok |= patch_file(t)
    print("\nDone. Restart Studio. The OTA store reads as empty, so Studio clears the"
          "\nOTA known-list and loads the internal built-in plugins (your edited ones)."
          if ok else "\nNot fully applied - see warnings.")


if __name__ == "__main__":
    main()
