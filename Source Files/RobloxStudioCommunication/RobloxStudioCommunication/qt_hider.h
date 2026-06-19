// qt_hider.h - polls for Qt5 windows and hides them
//
// Qt's Windows backend names all of its top-level HWNDs with a class name
// that begins with "Qt5" and embeds the build version: e.g.
//   "Qt5QWindowIcon"     / "Qt5QWindowOwnDCIcon"     - 2023 Studio (Qt 5.x)
//   "Qt5159QWindowIcon"  / "Qt5159QWindowOwnDCIcon"  - 2023 Studio (Qt 5.15.9)
// OwnDC variants host the 3D viewport / OpenGL surface; the plain Icon
// variant hosts the chrome (ribbon, dock panels, etc.).
//
// On a background thread we EnumWindows every ~100ms and ShowWindow(SW_HIDE)
// each Qt5* HWND owned by our process - EXCEPT the main chrome host (we
// pass that to qt_widget_hider, which selectively hides only the chrome
// widgets while keeping the 3D viewport visible). Polling is necessary
// because the host EXE can create new Qt windows at any time during startup.

#pragma once

#include "patcher.h"

namespace RobloxStudioPatcher
{
    // Starts the background hider thread. Safe to call from DllMain.
    // The thread runs until the process exits.
    void StartQtHider();
}
