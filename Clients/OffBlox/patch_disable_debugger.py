#!/usr/bin/env python3
r"""
Disable Studio's internal script debugger (StudioDebuggerV2) at the binary level
so it never pauses the 3D render.

WHY
---
The debugger flags this build reads do NOT exist in the binary (their names
aren't even present), so no FFlag/ClientAppSettings override can turn it off.
The debugger is the DAP-based "StudioDebuggerV2": a DebuggerConnection is set up
per session, and on transport-connect its onConnected() slot fires the DAP
handshake (initialize -> setExceptionBreakpoints -> configurationDone). That
handshake is what arms break-on-error / breakpoints on the runtime; when the
runtime then breaks, it suspends the DataModel and the viewport freezes.

WHAT THIS DOES
--------------
Neuters DebuggerConnection::onConnected() by overwriting its first byte with
0xC3 (ret). The slot returns immediately, BEFORE saving any register or touching
the stack, so it is safe: nonvolatile regs are untouched and the caller is
unaffected. With no handshake, the DAP session never initializes, so no
breakpoints / exception-breaks are ever set -> the runtime never breaks -> the
render never pauses. The TCP/transport may still connect; it just sits idle.

The function is located by a long, unique prologue signature (not a raw RVA),
so it survives minor rebases. Refuses to run unless the signature is found
exactly once. Writes a one-time .orig_dbg backup. Fully reversible.

    python patch_disable_debugger.py
    python patch_disable_debugger.py OffBlox.exe
    python patch_disable_debugger.py --revert OffBlox.exe
"""

import sys, os, shutil

# DebuggerConnection::onConnected prologue (RVA 0x1ff93e0 in 0.725.0.7251148):
#   mov [rsp+10],rbx ; mov [rsp+18],rsi ; push rdi ; sub rsp,40 ; mov rdi,rcx ;
#   xorps xmm0,xmm0 ; movdqu [rsp+20],xmm0 ; mov rdx,[rcx+38] ; test rdx,rdx ;
#   je .. ; mov eax,[rdx+8] ; test eax,eax
SIG = bytes.fromhex(
    "48895C2410"      # mov [rsp+10], rbx
    "4889742418"      # mov [rsp+18], rsi
    "57"              # push rdi
    "4883EC40"        # sub rsp, 0x40
    "488BF9"          # mov rdi, rcx
    "0F57C0"          # xorps xmm0, xmm0
    "F30F7F442420"    # movdqu [rsp+20], xmm0
    "488B5138"        # mov rdx, [rcx+0x38]
    "4885D2"          # test rdx, rdx
    "741E"            # je +0x1e
    "8B4208"          # mov eax, [rdx+8]
    "85C0"            # test eax, eax
)
PATCHED = b"\xC3" + SIG[1:]          # first byte -> ret

CANDIDATES = ["OffBlox.exe", "RobloxStudioBeta.exe"]


def patch_file(path, revert=False):
    data = bytearray(open(path, "rb").read())

    if revert:
        if data.count(PATCHED) == 1:
            i = data.find(PATCHED); data[i] = SIG[0]
            open(path, "wb").write(data)
            print(f"  [reverted] onConnected restored in {os.path.basename(path)}")
        elif data.count(SIG) == 1:
            print("  [skip] already un-patched")
        else:
            print("  [WARN] signature not found (wrong build?) - nothing done")
        return

    if data.count(PATCHED) == 1 and data.count(SIG) == 0:
        print("  [skip] already patched"); return True
    n = data.count(SIG)
    if n != 1:
        print(f"  [WARN] onConnected signature found {n}x (need 1) - skipped"); return False
    if not os.path.exists(path + ".orig_dbg"):
        shutil.copy2(path, path + ".orig_dbg"); print(f"  backup: {path}.orig_dbg")
    i = data.find(SIG); data[i] = 0xC3
    open(path, "wb").write(data)
    print(f"  [ok] debugger onConnected neutered @ file 0x{i:x} in {os.path.basename(path)}")
    return True


def main():
    args = sys.argv[1:]
    revert = "--revert" in args
    args = [a for a in args if a != "--revert"]
    here = os.path.dirname(os.path.abspath(__file__))
    targets = args or [os.path.join(here, n) for n in CANDIDATES
                       if os.path.exists(os.path.join(here, n))]
    if not targets:
        print("No OffBlox.exe / RobloxStudioBeta.exe found next to this script."); sys.exit(1)
    for t in targets:
        if not os.path.exists(t):
            print(f"  [WARN] not found: {t}"); continue
        print(f"Patching {t} ...")
        patch_file(t, revert)
    print("\nDone. Restart Studio. The script debugger no longer initializes, so it"
          "\ncan't pause the render. To undo: python patch_disable_debugger.py --revert")


if __name__ == "__main__":
    main()
