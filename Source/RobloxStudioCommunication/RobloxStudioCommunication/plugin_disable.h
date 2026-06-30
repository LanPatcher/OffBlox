// plugin_disable.h - skip the Studio editor plugin suite on StartServer.
//
// A headless game server loads ~40 "sabuiltin_*.rbxm" Studio editor plugins
// (AnimationGraphEditor, AssetManager, Debugger, PropertiesPlugin, Ribbon,
// ExplorerPlugin, the Audio*Editor tools, ...) that it never uses - each pulls
// in Lua + widgets and a tree of Studio:: components. We block them by failing
// the file open for any path containing "sabuiltin_". The plugin loader already
// handles a failed load gracefully ("Failed to load plugin ..."), so the rest
// of startup is unaffected.
//
// Critically, the engine builtins are named "builtin_" (no "sa" prefix) -
// builtin_SimulationStep.rbxm and the builtin_*Dragger.rbxm files - so they are
// NOT matched and continue to load. Server launches only.
#pragma once

namespace RobloxStudioPatcher
{
    void StartPluginDisable();
}
