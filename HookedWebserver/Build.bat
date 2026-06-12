@echo off
setlocal EnableDelayedExpansion
title HookedWebserver - Build
echo [Build] HookedWebserver DLL (x86, Windows XP compatible)
echo.

:: -----------------------------------------------------------------------
:: NOTE: Do NOT use "CL" as a variable name -- MSVC reads %CL% as extra
::       command-line flags and will pass the path as input files.
::       We use CLEXE instead.
:: -----------------------------------------------------------------------
set "CLEXE="
set "VCTOOLS="

:: -----------------------------------------------------------------------
:: 1.  Locate cl.exe -- search common Visual Studio installations
:: -----------------------------------------------------------------------

:: VS 2022 (v143)
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC"
) do (
    if exist "%%~P" (
        for /f "delims=" %%V in ('dir /b /ad /o-n "%%~P" 2^>nul') do (
            if not defined CLEXE (
                if exist "%%~P\%%V\bin\Hostx86\x86\cl.exe" (
                    set "CLEXE=%%~P\%%V\bin\Hostx86\x86\cl.exe"
                    set "VCTOOLS=%%~P\%%V"
                )
            )
        )
    )
)

:: VS 2019 (v142)
if not defined CLEXE (
for %%P in (
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Tools\MSVC"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC"
) do (
    if exist "%%~P" (
        for /f "delims=" %%V in ('dir /b /ad /o-n "%%~P" 2^>nul') do (
            if not defined CLEXE (
                if exist "%%~P\%%V\bin\Hostx86\x86\cl.exe" (
                    set "CLEXE=%%~P\%%V\bin\Hostx86\x86\cl.exe"
                    set "VCTOOLS=%%~P\%%V"
                )
            )
        )
    )
))

:: VS 2017 (v141)
if not defined CLEXE (
for %%P in (
    "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC"
    "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Tools\MSVC"
    "C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Tools\MSVC"
    "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Tools\MSVC"
) do (
    if exist "%%~P" (
        for /f "delims=" %%V in ('dir /b /ad /o-n "%%~P" 2^>nul') do (
            if not defined CLEXE (
                if exist "%%~P\%%V\bin\Hostx86\x86\cl.exe" (
                    set "CLEXE=%%~P\%%V\bin\Hostx86\x86\cl.exe"
                    set "VCTOOLS=%%~P\%%V"
                )
            )
        )
    )
))

:: VS 2015 (v140) -- preferred for XP toolset (v140_xp)
if not defined CLEXE (
    if exist "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\cl.exe" (
        set "CLEXE=C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\cl.exe"
        set "VCTOOLS=C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC"
    ) else if exist "C:\Program Files\Microsoft Visual Studio 14.0\VC\bin\cl.exe" (
        set "CLEXE=C:\Program Files\Microsoft Visual Studio 14.0\VC\bin\cl.exe"
        set "VCTOOLS=C:\Program Files\Microsoft Visual Studio 14.0\VC"
    )
)

:: VS 2013 (v120) -- fallback
if not defined CLEXE (
    if exist "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\cl.exe" (
        set "CLEXE=C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\cl.exe"
        set "VCTOOLS=C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC"
    ) else if exist "C:\Program Files\Microsoft Visual Studio 12.0\VC\bin\cl.exe" (
        set "CLEXE=C:\Program Files\Microsoft Visual Studio 12.0\VC\bin\cl.exe"
        set "VCTOOLS=C:\Program Files\Microsoft Visual Studio 12.0\VC"
    )
)

if not defined CLEXE (
    echo [ERROR] No Visual Studio installation found.
    echo         Please install Visual Studio 2013/2015/2017/2019/2022 with C++ workload.
    echo         Minimum: "Desktop development with C++" or "Build Tools for Visual Studio"
    pause
    exit /b 1
)

echo [Build] Using compiler: !CLEXE!
echo.

:: -----------------------------------------------------------------------
:: 2.  Set up include/lib paths for the detected toolset
:: -----------------------------------------------------------------------
set "INC_VC=!VCTOOLS!\include"
set "LIB_VC=!VCTOOLS!\lib\x86"
:: Fallback for older VS layout (VS2013/VS2015)
if not exist "!LIB_VC!" set "LIB_VC=!VCTOOLS!\lib"

:: Windows SDK -- try common locations
set "WINSDK_INC="
set "WINSDK_LIB="

for %%S in (
    "C:\Program Files (x86)\Windows Kits\10\Include"
    "C:\Program Files\Windows Kits\10\Include"
) do (
    if exist "%%~S" if not defined WINSDK_INC (
        :: WinKit 10 has versioned subdirs -- pick newest
        for /f "delims=" %%V in ('dir /b /ad /o-n "%%~S" 2^>nul') do (
            if not defined WINSDK_INC (
                if exist "%%~S\%%V\um\windows.h" (
                    set "WINSDK_INC=%%~S\%%V\um;%%~S\%%V\shared;%%~S\%%V\ucrt"
                    set "_LB=%%~S\%%V"
                    set "_LB=!_LB:Include=Lib!"
                    set "WINSDK_LIB=!_LB!\um\x86;!_LB!\ucrt\x86"
                )
            )
        )
    )
)

:: WinKit 8.1 fallback
if not defined WINSDK_INC (
    if exist "C:\Program Files (x86)\Windows Kits\8.1\Include\um\windows.h" (
        set "WINSDK_INC=C:\Program Files (x86)\Windows Kits\8.1\Include\um;C:\Program Files (x86)\Windows Kits\8.1\Include\shared"
        set "WINSDK_LIB=C:\Program Files (x86)\Windows Kits\8.1\Lib\winv6.3\um\x86"
    )
)

if not defined WINSDK_INC (
    echo [WARN] Windows SDK not found. Build may fail without SDK headers.
)

set "INCLUDE=!INC_VC!;!WINSDK_INC!"
set "LIB=!LIB_VC!;!WINSDK_LIB!"

:: -----------------------------------------------------------------------
:: 3.  Compile
:: -----------------------------------------------------------------------
cd /d "%~dp0"

if not exist "src\HookedWebserver.cpp" (
    echo [ERROR] src\HookedWebserver.cpp not found.
    pause
    exit /b 1
)

echo [Build] Compiling src\HookedWebserver.cpp ...
echo.

"!CLEXE!" ^
    /I zlib ^
    /nologo /W3 /O2 /MT /EHsc ^
    /D_WIN32_WINNT=0x0501 /DWINVER=0x0501 ^
    /DWIN32 /D_WINDOWS /D_USRDLL /DHOOKEDWEBSERVER_EXPORTS ^
    /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS ^
    /GS- /arch:IA32 ^
    src\HookedWebserver.cpp ^
    /link ^
    /LIBPATH:zlib ^
    zlib.lib ^
    /DLL /MACHINE:X86 ^
    /DEF:HookedWebserver.def ^
    /OUT:HookedWebserver.dll ^
    /SUBSYSTEM:WINDOWS,5.01 ^
    ws2_32.lib crypt32.lib secur32.lib shlwapi.lib advapi32.lib kernel32.lib user32.lib

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Compilation failed. See errors above.
    echo.
    echo Tips:
    echo   - Make sure "Desktop development with C++" is installed in Visual Studio
    echo   - On VS2017+, you may need "Windows XP support for C++" optional component
    echo     (Tools ^> Get Tools and Features ^> Individual components)
    pause
    exit /b 1
)

echo.
echo [Build] SUCCESS -- HookedWebserver.dll compiled (x86, /MT, XP-compatible)
echo.
echo Next steps:
echo   1. Run Install.bat as Administrator to convert SSL cert and set port 80 ACL
echo   2. Inject HookedWebserver.dll into Roblox Studio using Stud_PE:
echo        - Open Roblox Studio's EXE in Stud_PE
echo        - Go to Functions ^> PE Editor ^> Import Adder
echo        - Add HookedWebserver.dll and export: HWS_Start
echo   3. Launch Roblox Studio -- the server starts automatically in the background
echo.
pause
