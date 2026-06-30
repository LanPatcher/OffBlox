@echo off
setlocal EnableDelayedExpansion
title HookedWebserver - Build (x64)
echo [Build] HookedWebserver DLL (x64)
echo.

:: -----------------------------------------------------------------------
:: NOTE: Do NOT use "CL" as a variable name -- MSVC reads %CL% as extra
::       command-line flags and will pass the path as input files.
::       We use CLEXE instead.
:: -----------------------------------------------------------------------
set "CLEXE="
set "VCTOOLS="

:: -----------------------------------------------------------------------
:: 1.  Locate cl.exe (x64 host, x64 target)
::     We want Hostx64\x64\cl.exe so the compiler itself runs as 64-bit.
::     If that is absent we fall back to Hostx86\x64\cl.exe (cross-compiler).
::
::     NOTE: The MACHINE flag below must be X64 to match RobloxStudioBeta.exe
::     (PE32+ / x86-64).  Injecting an x86 DLL into an x64 process will
::     cause an immediate crash at load time.
:: -----------------------------------------------------------------------

:: Helper macro: try both host-native and cross variants
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC"
) do (
    if exist "%%~P" (
        for /f "delims=" %%V in ('dir /b /ad /o-n "%%~P" 2^>nul') do (
            if not defined CLEXE (
                if exist "%%~P\%%V\bin\Hostx64\x64\cl.exe" (
                    set "CLEXE=%%~P\%%V\bin\Hostx64\x64\cl.exe"
                    set "VCTOOLS=%%~P\%%V"
                ) else if exist "%%~P\%%V\bin\Hostx86\x64\cl.exe" (
                    set "CLEXE=%%~P\%%V\bin\Hostx86\x64\cl.exe"
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
                if exist "%%~P\%%V\bin\Hostx64\x64\cl.exe" (
                    set "CLEXE=%%~P\%%V\bin\Hostx64\x64\cl.exe"
                    set "VCTOOLS=%%~P\%%V"
                ) else if exist "%%~P\%%V\bin\Hostx86\x64\cl.exe" (
                    set "CLEXE=%%~P\%%V\bin\Hostx86\x64\cl.exe"
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
                if exist "%%~P\%%V\bin\Hostx64\x64\cl.exe" (
                    set "CLEXE=%%~P\%%V\bin\Hostx64\x64\cl.exe"
                    set "VCTOOLS=%%~P\%%V"
                ) else if exist "%%~P\%%V\bin\Hostx86\x64\cl.exe" (
                    set "CLEXE=%%~P\%%V\bin\Hostx86\x64\cl.exe"
                    set "VCTOOLS=%%~P\%%V"
                )
            )
        )
    )
))

if not defined CLEXE (
    echo [ERROR] No Visual Studio x64 compiler found.
    echo         Install "Desktop development with C++" in Visual Studio 2017/2019/2022.
    pause
    exit /b 1
)

echo [Build] Using compiler: !CLEXE!
echo.

:: -----------------------------------------------------------------------
:: 2.  Set up include/lib paths for the detected toolset (x64 libs)
:: -----------------------------------------------------------------------
set "INC_VC=!VCTOOLS!\include"
set "LIB_VC=!VCTOOLS!\lib\x64"

:: Windows SDK -- pick newest version, x64 lib dir
set "WINSDK_INC="
set "WINSDK_LIB="

for %%S in (
    "C:\Program Files (x86)\Windows Kits\10\Include"
    "C:\Program Files\Windows Kits\10\Include"
) do (
    if exist "%%~S" if not defined WINSDK_INC (
        for /f "delims=" %%V in ('dir /b /ad /o-n "%%~S" 2^>nul') do (
            if not defined WINSDK_INC (
                if exist "%%~S\%%V\um\windows.h" (
                    set "WINSDK_INC=%%~S\%%V\um;%%~S\%%V\shared;%%~S\%%V\ucrt"
                    set "_LB=%%~S\%%V"
                    set "_LB=!_LB:Include=Lib!"
                    :: x64 lib paths (not x86)
                    set "WINSDK_LIB=!_LB!\um\x64;!_LB!\ucrt\x64"
                )
            )
        )
    )
)

if not defined WINSDK_INC (
    echo [WARN] Windows SDK not found. Build may fail without SDK headers.
)

set "INCLUDE=!INC_VC!;!WINSDK_INC!"
set "LIB=!LIB_VC!;!WINSDK_LIB!"

:: -----------------------------------------------------------------------
:: 3.  Build zlib from source as x64 static lib (zlib_x64.lib)
::
::     The prebuilt zlib\zlib.lib in this repo is x86.  We compile the
::     core zlib C files directly to get a matching x64 .lib.
::     Output: zlib\zlib_x64.lib  (static, /MT, no gzip I/O helpers needed)
:: -----------------------------------------------------------------------
cd /d "%~dp0"

if not exist "zlib\deflate.c" (
    echo [ERROR] zlib source not found at zlib\deflate.c
    pause
    exit /b 1
)

echo [Build] Compiling zlib from source (x64) ...

:: Compile each core zlib source file to an object
set ZLIB_SRCS=adler32.c compress.c crc32.c deflate.c infback.c inffast.c inflate.c inftrees.c trees.c uncompr.c zutil.c

set ZLIB_OBJS=
for %%F in (!ZLIB_SRCS!) do (
    "!CLEXE!" /nologo /c /O2 /MT /W0 /GS- ^
        /D_CRT_SECURE_NO_WARNINGS /DWIN32 ^
        /Fozlib\%%~nF_x64.obj ^
        zlib\%%F
    if errorlevel 1 (
        echo [ERROR] Failed to compile zlib\%%F
        pause
        exit /b 1
    )
    set "ZLIB_OBJS=!ZLIB_OBJS! zlib\%%~nF_x64.obj"
)

:: Find lib.exe next to cl.exe
set "LIBEXE=!CLEXE:cl.exe=lib.exe!"
if not exist "!LIBEXE!" set "LIBEXE=lib.exe"

"!LIBEXE!" /nologo /MACHINE:X64 /OUT:zlib\zlib_x64.lib !ZLIB_OBJS!
if errorlevel 1 (
    echo [ERROR] lib.exe failed creating zlib_x64.lib
    pause
    exit /b 1
)
echo [Build] zlib_x64.lib created OK.
echo.

:: -----------------------------------------------------------------------
:: 3b. Compile tlse (portable, single-file TLS) as one x64 C object.
::     TLS_AMALGAMATION makes tlse.c pull in libtomcrypt.c + x509.c, so this
::     one compile produces the whole TLS stack. Replaces SChannel so HTTPS
::     works under Wine (where SChannel server creds fail).
:: -----------------------------------------------------------------------
if not exist "tlse\tlse.c" (
    echo [ERROR] tlse source not found at tlse\tlse.c
    pause
    exit /b 1
)
echo [Build] Compiling tlse (portable TLS) from source (x64) ...
"!CLEXE!" /nologo /c /O2 /MT /W0 /GS- ^
    /DTLS_AMALGAMATION /D_CRT_SECURE_NO_WARNINGS /DWIN32 /D_WINSOCK_DEPRECATED_NO_WARNINGS ^
    /I tlse ^
    /Fotlse\tlse_x64.obj ^
    tlse\tlse.c
if errorlevel 1 (
    echo [ERROR] Failed to compile tlse\tlse.c
    pause
    exit /b 1
)
echo [Build] tlse_x64.obj created OK.
echo.

:: -----------------------------------------------------------------------
:: 4.  Compile HookedWebserver.cpp (x64, static CRT)
::
::     Differences from the old x86 build:
::       /MACHINE:X64    -- PE32+ output, matches RobloxStudioBeta.exe
::       no /arch:IA32   -- removed (that flag is x86-only)
::       lib\x64         -- 64-bit VC runtime libs
::       WINSDK_LIB x64  -- 64-bit Windows SDK libs
::       zlib_x64.lib    -- freshly built x64 zlib (not the prebuilt x86 one)
::       no /SUBSYSTEM:WINDOWS,5.01  -- XP target removed (x64 XP is niche)
:: -----------------------------------------------------------------------

if not exist "src\HookedWebserver.cpp" (
    echo [ERROR] src\HookedWebserver.cpp not found.
    pause
    exit /b 1
)

echo [Build] Compiling src\HookedWebserver.cpp (x64) ...
echo.

"!CLEXE!" ^
    /I zlib ^
    /nologo /W3 /O2 /MT /EHsc ^
    /DWIN32 /D_WINDOWS /D_USRDLL /DHOOKEDWEBSERVER_EXPORTS ^
    /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS ^
    src\HookedWebserver.cpp ^
    /link ^
    /LIBPATH:zlib ^
    zlib_x64.lib ^
    tlse\tlse_x64.obj ^
    /DLL /MACHINE:X64 ^
    /DEF:HookedWebserver.def ^
    /OUT:HookedWebserver.dll ^
    /SUBSYSTEM:WINDOWS ^
    ws2_32.lib crypt32.lib secur32.lib shlwapi.lib advapi32.lib kernel32.lib user32.lib bcrypt.lib

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Compilation failed. See errors above.
    echo.
    echo Tips:
    echo   - Make sure "Desktop development with C++" is installed in Visual Studio
    echo   - VS 2017 or newer is required for x64 targets used here
    pause
    exit /b 1
)

echo.
echo [Build] SUCCESS -- HookedWebserver.dll compiled (x64, /MT)
echo.
echo Next steps:
echo   1. Copy HookedWebserver.dll to the Clients\OffBlox\ folder next to
echo      RbxInject.dll and RobloxStudioPatcher.dll.
echo   2. Ensure RbxInject.dll is already added to RobloxStudioBeta.exe via
echo      stud_pe (see RbxInject\README or the main README for instructions).
echo   3. The webserver process (HookedWebserver\Start.bat) is now launched
echo      automatically by RbxInject on Studio startup -- no manual start needed.
echo.
pause