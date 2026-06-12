@echo off
REM ============================================================================
REM  Build OffBloxLauncher and drop the exe into the OffBlox root (next to
REM  Clients\). Double-click this, or run it from a terminal.
REM ============================================================================
setlocal enabledelayedexpansion

set "MSBUILD="

REM 1) Try vswhere (ships with VS 2017+ / Build Tools)
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -prerelease -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set "MSBUILD=%%i"
)

REM 2) Fall back to MSBuild already on PATH
if not defined MSBUILD (
  where msbuild >nul 2>nul && set "MSBUILD=msbuild"
)

if not defined MSBUILD (
  echo.
  echo Could not find MSBuild.
  echo Either open OffBloxLauncher.sln in Visual Studio and press Build,
  echo or install the ".NET desktop build tools" workload.
  echo.
  pause
  exit /b 1
)

echo Using MSBuild: %MSBUILD%
echo.
"%MSBUILD%" "%~dp0OffBloxLauncher.sln" /t:Rebuild /p:Configuration=Release /p:Platform="Any CPU" /v:m
if errorlevel 1 (
  echo.
  echo BUILD FAILED.
  pause
  exit /b 1
)

REM Copy the fresh exe to the OffBlox root (..\..\ = OffBloxMain, where Clients\ lives)
set "OUT=%~dp0bin\Release\OffBloxLauncher.exe"
set "ROOT=%~dp0..\..\"
if exist "%OUT%" (
  copy /y "%OUT%" "%ROOT%OffBloxLauncher.exe" >nul
  echo.
  echo Built and copied to: %ROOT%OffBloxLauncher.exe
) else (
  echo.
  echo Build reported success but %OUT% was not found.
)

echo.
pause
