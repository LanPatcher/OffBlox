#!/usr/bin/env python3
r"""
Disable Studio's Plugin OTA by BLANKING OTADataCache.json so the built-in
standalone plugins load from the local install instead of the OTA store.

Why this works
--------------
Studio loads every built-in standalone plugin from the install folder EXCEPT the
ones listed in
    %LOCALAPPDATA%\Roblox\OTAPlugins\Deployed\OTADataCache.json
Those listed plugins (AssetManager, Assistant, Dialog, StartPage, SuperTemplate)
are forced down the OTA path and fail/override your edits. The non-listed plugins
(AnimationGraphEditor, AssetExport, ...) already load fine from the install.

So if OTADataCache.json lists NOTHING, all of them - including StartPage - load
from the install's BuiltInStandalonePlugins\Packed (your edited copies).

This script:
  1. writes {"schemaVersion":1,"data":{}} to OTADataCache.json (Deployed +
     Downloaded), and
  2. marks those files READ-ONLY so OTA can't repopulate them on the next launch.

Pair with patch_plugin_signature.py (edited plugins pass signature). The OTA
validation/scan binary patches are no longer needed - you can leave them or revert
via the .orig_ota backup.

    python use_local_plugins.py
"""

import os, json, stat, sys

LOCALAPPDATA = os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")
OTA = os.path.join(LOCALAPPDATA, "Roblox", "OTAPlugins")
BLANK = '{"schemaVersion":1,"data":{}}'


def blank_and_lock(path):
    # clear read-only if already set, rewrite empty, then re-lock
    if os.path.exists(path):
        try: os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        except Exception: pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(BLANK)
    try:
        os.chmod(path, stat.S_IREAD)          # read-only: OTA can't repopulate it
        ro = True
    except Exception:
        ro = False
    print(f"  [ok] blanked{' + read-only' if ro else ''}: {path}")


def main():
    if not os.path.isdir(OTA):
        print(f"OTA folder not found: {OTA}")
        print("Launch Studio once so it creates %LOCALAPPDATA%\\Roblox\\OTAPlugins, then re-run.")
        sys.exit(1)
    targets = [
        os.path.join(OTA, "Deployed",   "OTADataCache.json"),
        os.path.join(OTA, "Downloaded", "OTADataCache.json"),
    ]
    did = 0
    for t in targets:
        # write Deployed always; Downloaded only if that subfolder exists
        if "Downloaded" in t and not os.path.isdir(os.path.dirname(t)):
            continue
        blank_and_lock(t); did += 1
    print(f"\nBlanked {did} OTADataCache file(s). OTA now lists no plugins, so the"
          "\nbuilt-in standalone plugins (incl. your edited StartPage) load from"
          "\nthe install BuiltInStandalonePlugins\\Packed folder. Restart Studio.")
    print("\nTo undo: delete these files (or clear the read-only bit) and let Studio rebuild them.")


if __name__ == "__main__":
    main()
