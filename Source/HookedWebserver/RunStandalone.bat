@echo off
setlocal EnableDelayedExpansion
title HookedWebserver - Standalone Test
echo [Standalone] Building and launching StandaloneLoader...
echo.

cd /d "%~dp0"

:: Reuse the same VS detection logic from Build.bat
set "CLEXE="
set "VCTOOLS="

for %%P in (
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC"
    "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC"
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
)

if not defined CLEXE (
    if exist "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\cl.exe" (
        set "CLEXE=C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\cl.exe"
        set "VCTOOLS=C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC"
    )
)

if not defined CLEXE (
    echo [ERROR] No Visual Studio compiler found. Build HookedWebserver.dll first with Build.bat.
    pause
    exit /b 1
)

:: Set include/lib paths
set "INC_VC=!VCTOOLS!\include"
set "LIB_VC=!VCTOOLS!\lib\x86"
if not exist "!LIB_VC!" set "LIB_VC=!VCTOOLS!\lib"

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
                    set "WINSDK_LIB=!_LB!\um\x86;!_LB!\ucrt\x86"
                )
            )
        )
    )
)
if not defined WINSDK_INC (
    if exist "C:\Program Files (x86)\Windows Kits\8.1\Include\um\windows.h" (
        set "WINSDK_INC=C:\Program Files (x86)\Windows Kits\8.1\Include\um;C:\Program Files (x86)\Windows Kits\8.1\Include\shared"
        set "WINSDK_LIB=C:\Program Files (x86)\Windows Kits\8.1\Lib\winv6.3\um\x86"
    )
)

set "INCLUDE=!INC_VC!;!WINSDK_INC!"
set "LIB=!LIB_VC!;!WINSDK_LIB!"

:: Check HookedWebserver.dll exists
if not exist "HookedWebserver.dll" (
    echo [ERROR] HookedWebserver.dll not found. Run Build.bat first.
    pause
    exit /b 1
)

:: Compile StandaloneLoader.exe
echo [Standalone] Compiling StandaloneLoader.exe (x86)...
"!CLEXE!" /nologo /O1 /MT /D_CRT_SECURE_NO_WARNINGS ^
    StandaloneLoader.c /link /MACHINE:X86 /SUBSYSTEM:CONSOLE ^
    /OUT:StandaloneLoader.exe kernel32.lib user32.lib

if %errorlevel% neq 0 (
    echo [ERROR] Failed to compile StandaloneLoader.exe
    pause
    exit /b 1
)

echo [Standalone] Launching...
echo.
StandaloneLoader.exe
