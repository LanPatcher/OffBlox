// qt_widget_hider.h - hide Studio's chrome by Win32 window subclassing.
//
// Roblox Studio's chrome (ribbon, dock widgets, output console, status bar,
// tab bar) is Qt UI. Earlier versions tried to manipulate the Qt widget
// tree directly (hide / resize / setParent) - that either glitched or
// HARD-CRASHED the process, because Qt widget trees may only be mutated on
// the GUI thread and QtitanDocking re-shows anything it still manages.
//
// This version makes NO Qt calls at all. It works purely at the Win32
// window level:
//   * The 3D viewport is a native child window (class contains "OwnDC").
//     Its WndProc is subclassed so the viewport is forced to always fill
//     the whole window and stay on top - covering all the "alien" Qt chrome
//     widgets that have no window handle of their own.
//   * Every other child window of the main window is chrome that owns an
//     HWND; its WndProc is subclassed so it is permanently kept hidden and
//     zero-sized.
// Both subclasses intercept WM_WINDOWPOSCHANGING, so the enforced layout is
// permanent and flicker-free regardless of what Qt does afterwards.
//
// See qt_widget_hider.cpp for the full design notes.

#pragma once

#include "patcher.h"

namespace RobloxStudioPatcher
{
    // Subclasses the 3D viewport window (to fill the frame) and every chrome
    // child window (to stay hidden) of the given Studio main window.
    //
    // Returns true when the pass is stable - i.e. nothing new needed to be
    // subclassed, every chrome window already carries our blocker WndProc.
    //
    // Returns false in two distinct situations, distinguished by *outReady:
    //   *outReady == false  ->  The viewport window has not rendered yet, or
    //                           new chrome was just subclassed this pass.
    //                           The caller should retry on the next cycle.
    //   *outReady == true   ->  An SEH hard fault occurred. The caller
    //                           should stop retrying.
    //
    // Pure Win32 - safe to call from any thread. qt_hider.cpp calls it from
    // the main window's subclassed WndProc (the GUI thread), which is the
    // ideal place to subclass sibling windows.
    bool HideStudioChromeWidgets(HWND mainHwnd, bool* outReady = nullptr);

    // Server variant: instead of keeping the 3D viewport, keep the Output
    // dock panel and block/shrink everything else (viewport + all toolbars).
    // Identification order:
    //   1. Win32 title contains "Output"
    //   2. Qt class name contains "Output"
    //   3. Largest visible QDockWidget (fallback)
    // Same return semantics as HideStudioChromeWidgets.
    bool ExpandServerOutput(HWND mainHwnd, bool* outReady = nullptr);
}
