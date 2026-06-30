// dialog_suppress.h - suppress modal dialogs on StartServer instances.
//
// Forcing NoGraphics makes the engine pop a Qt QMessageBox ("graphics card not
// compatible / minimum system requirements"). The window hider hides it, but
// the Critical/Warning icon already played the Windows error sound and the box
// is modal. A headless server should never show a modal dialog anyway, so we
// IAT-hook the QMessageBox static convenience functions (and Win32 MessageBox
// as a backstop) to return a default WITHOUT showing anything - no window, no
// beep. Server launches only.
#pragma once

namespace RobloxStudioPatcher
{
    void StartDialogSuppress();
}
