#!/usr/bin/env python3
"""
OffBloxModern - disable the StudioCookieManager "wait for security cookie" gate.

What it does (fully local, no roblox.com):
  In RobloxStudioBeta.exe (0.712.0.7120919), the cookie-save routine decides:
      cmp byte ptr [rdi+0x118], sil   ; is the security cookie cached?
      je  <WAIT branch>               ; if not cached -> park the callback forever
  Because the WebView2 harvest never fires offline, that flag is always 0, so the
  login callback (enter UserSession scope) is never run and Studio idles after
  "login [end][success]".

  This NOPs that single 'je' so execution always falls through to the PROCEED
  branch, which runs the callback and lets login finish. The security cookie
  itself is irrelevant offline (the server uses your real cookie for assets).

Usage:
  python patch_studio_cookiewait.py "C:\\...\\OffBlox\\RobloxStudioBeta.exe"

Re-run after any Studio re-download; it matches by byte signature, not a fixed
offset, and refuses to run if the signature isn't found exactly once.
"""
import sys, os, shutil

# cmp byte ptr [rdi+0x118], sil ; je rel8   -> the trailing 74 74 is the jump
SIG   = bytes.fromhex("4038b7180100007474")
PATCH = bytes.fromhex("4038b7180100009090")   # je -> nop nop
ALREADY = bytes.fromhex("4038b7180100009090")

def main():
    if len(sys.argv) != 2:
        print("usage: python patch_studio_cookiewait.py <path to RobloxStudioBeta.exe>")
        sys.exit(1)
    path = sys.argv[1]
    data = bytearray(open(path, "rb").read())

    if data.count(ALREADY) and not data.count(SIG):
        print("Already patched. Nothing to do.")
        return

    hits = data.count(SIG)
    if hits != 1:
        print(f"ERROR: expected exactly 1 match of the signature, found {hits}.")
        print("This build is not the expected 0.712.0.7120919, or it's already modified.")
        print("Aborting so nothing is corrupted.")
        sys.exit(2)

    idx = data.find(SIG)
    print(f"Found signature at file offset 0x{idx:x}")

    bak = path + ".orig"
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
        print(f"Backup written: {bak}")
    else:
        print(f"Backup already exists: {bak} (left as-is)")

    data[idx:idx+len(SIG)] = PATCH
    with open(path, "wb") as fh:
        fh.write(data)
    print("Patched: je (74 74) -> nop nop (90 90). The cookie-wait gate is disabled.")
    print("Launch Studio against your local server; login should now enter user scope.")

if __name__ == "__main__":
    main()