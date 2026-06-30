// dialog_suppress.cpp - see dialog_suppress.h.
//
// On the server we IAT-hook the imported QMessageBox static convenience
// functions and Win32 MessageBox so no modal dialog is ever shown. Not showing
// the box means it never plays the error sound and never blocks the (headless)
// server thread.
//
// x64 ABI: rcx,rdx,r8,r9 then stack. The Qt statics are
//   StandardButton critical/warning/question(QWidget* parent,
//       const QString& title, const QString& text,
//       StandardButtons buttons, StandardButton defaultButton)
// returning the chosen button in eax. We return Ok (0x00000400) without
// touching the args - the graphics warning ignores the result, and any other
// server-side dialog can only be answered with a default anyway.

#include "dialog_suppress.h"
#include "patcher.h"
#include "iat_hook.h"

#include <windows.h>

namespace RobloxStudioPatcher
{
    extern bool IsStartServerTask_Pub();

    // QMessageBox::StandardButton::Ok
    static const int kQtOk = 0x00000400;

    // critical / warning / question share this prototype (5 args, last on stack).
    static int Hook_QMsgButton(void* /*parent*/, const void* /*title*/,
                               const void* /*text*/, int /*buttons*/,
                               int /*defaultButton*/)
    {
        return kQtOk;
    }

    // information(QWidget*, QString&, QString&, int, int, int) -> int
    static int Hook_QMsgInformation(void* /*parent*/, const void* /*title*/,
                                    const void* /*text*/, int /*b0*/,
                                    int /*b1*/, int /*b2*/)
    {
        return kQtOk;
    }

    static int WINAPI Hook_MessageBoxW(HWND, LPCWSTR, LPCWSTR, UINT) { return IDOK; }
    static int WINAPI Hook_MessageBoxA(HWND, LPCSTR,  LPCSTR,  UINT) { return IDOK; }

    // Decorated names exactly as imported from Qt5Widgets.dll (82ca build).
    static const char* kQtCritical =
        "?critical@QMessageBox@@SA?AW4StandardButton@1@PEAVQWidget@@AEBVQString@@1V?$QFlags@W4StandardButton@QMessageBox@@@@W421@@Z";
    static const char* kQtWarning =
        "?warning@QMessageBox@@SA?AW4StandardButton@1@PEAVQWidget@@AEBVQString@@1V?$QFlags@W4StandardButton@QMessageBox@@@@W421@@Z";
    static const char* kQtQuestion =
        "?question@QMessageBox@@SA?AW4StandardButton@1@PEAVQWidget@@AEBVQString@@1V?$QFlags@W4StandardButton@QMessageBox@@@@W421@@Z";
    static const char* kQtInformation =
        "?information@QMessageBox@@SAHPEAVQWidget@@AEBVQString@@1HHH@Z";

    void StartDialogSuppress()
    {
        if (!IsStartServerTask_Pub()) return;   // server launches only

        void* orig = nullptr;
        int n = 0;
        struct { const char* dll; const char* fn; void* hook; } targets[] = {
            { "Qt5Widgets.dll", kQtCritical,    (void*)&Hook_QMsgButton },
            { "Qt5Widgets.dll", kQtWarning,     (void*)&Hook_QMsgButton },
            { "Qt5Widgets.dll", kQtQuestion,    (void*)&Hook_QMsgButton },
            { "Qt5Widgets.dll", kQtInformation, (void*)&Hook_QMsgInformation },
            { "USER32.dll",     "MessageBoxW",  (void*)&Hook_MessageBoxW },
            { "USER32.dll",     "MessageBoxA",  (void*)&Hook_MessageBoxA },
        };
        for (auto& t : targets)
        {
            orig = nullptr;
            if (IatHook(t.dll, t.fn, t.hook, &orig)) ++n;
        }

        LogF(L"[dialog_suppress] hooked %d/%d modal-dialog entrypoints "
             L"(server: no popups / no error beep)\n", n,
             (int)(sizeof(targets) / sizeof(targets[0])));
    }
}
