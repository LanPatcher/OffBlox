#!/usr/bin/env python3
r"""
Stop the script debugger from activating by preventing its plugin from loading.

WHY
---
The freeze is the runtime breaking on exceptions (DAP "Stopped reason=Exception"),
even for pcall'd errors. The exception-break mode is driven by the built-in
Debugger plugin (sabuiltin_Debugger.rbxm) wiring up breakpoints / exception
breaking when a session starts. If that plugin never loads, nothing arms the
exception break, so the runtime never suspends and the viewport never freezes.

This renames Debugger.rbxm out of the way in every place Studio loads it from:
  - <install>\BuiltInStandalonePlugins\Packed\Debugger.rbxm
  - <install>\BuiltInStandalonePlugins\Optimized_Embedded_Signature\Debugger.rbxm
  - %LOCALAPPDATA%\Roblox\OTAPlugins\Deployed\BuiltInStandalonePlugins\Debugger.rbxm
(renames to Debugger.rbxm.disabled). Fully reversible.

    python disable_debugger_plugin.py            # disable
    python disable_debugger_plugin.py --revert   # restore
"""

import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
LOCALAPPDATA = os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")

TARGETS = [
    os.path.join(HERE, "BuiltInStandalonePlugins", "Packed", "Debugger.rbxm"),
    os.path.join(HERE, "BuiltInStandalonePlugins", "Optimized_Embedded_Signature", "Debugger.rbxm"),
    os.path.join(LOCALAPPDATA, "Roblox", "OTAPlugins", "Deployed",
                 "BuiltInStandalonePlugins", "Debugger.rbxm"),
]
SUFFIX = ".disabled"


def disable():
    n = 0
    for p in TARGETS:
        dis = p + SUFFIX
        if os.path.exists(p):
            if os.path.exists(dis):
                os.remove(dis)
            os.rename(p, dis)
            print(f"  [disabled] {p}")
            n += 1
        elif os.path.exists(dis):
            print(f"  [already disabled] {p}")
            n += 1
        else:
            print(f"  [not found] {p}")
    print(f"\nDisabled {n} location(s). Restart Studio. No debugger plugin => no"
          "\nbreakpoints / exception breaks => render won't freeze.")


def revert():
    n = 0
    for p in TARGETS:
        dis = p + SUFFIX
        if os.path.exists(dis):
            if os.path.exists(p):
                os.remove(dis)
            else:
                os.rename(dis, p)
            print(f"  [restored] {p}")
            n += 1
    print(f"\nRestored {n} location(s).")


if __name__ == "__main__":
    (revert if "--revert" in sys.argv[1:] else disable)()
