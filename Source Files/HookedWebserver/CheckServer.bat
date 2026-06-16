@echo off
title HookedWebserver - Server Status Check
echo [Check] HookedWebserver status
echo.

cd /d "%~dp0"

:: -----------------------------------------------------------------------
:: 1. Check log file
:: -----------------------------------------------------------------------
if exist "HookedWebserver.log" (
    echo [Log] Last 20 lines of HookedWebserver.log:
    echo -----------------------------------------------
    powershell -NoProfile -Command "Get-Content 'HookedWebserver.log' | Select-Object -Last 20" 2>nul
    if %errorlevel% neq 0 (
        :: fallback for XP
        type HookedWebserver.log
    )
    echo -----------------------------------------------
) else (
    echo [Log] HookedWebserver.log not found.
    echo       The DLL has not been loaded yet, or the log path is wrong.
)

echo.

:: -----------------------------------------------------------------------
:: 2. Check if port 80 is listening
:: -----------------------------------------------------------------------
echo [Port] Checking port 80...
netstat -ano | find ":80 " | find "LISTENING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [Port] Port 80 is LISTENING.
    netstat -ano | find ":80 " | find "LISTENING"
) else (
    echo [Port] Port 80 is NOT listening.
    echo        Either:
    echo          a) The DLL is not injected yet / Studio is not running
    echo          b) Port 80 bind failed -- run Install.bat as Admin first
    echo          c) Another process owns port 80 (check netstat -ano ^| find ":80")
)

echo.

:: -----------------------------------------------------------------------
:: 3. HTTP ping test
:: -----------------------------------------------------------------------
echo [HTTP] Pinging http://localhost/ping ...
powershell -NoProfile -Command ^
    "try { $r=(Invoke-WebRequest -Uri 'http://localhost/ping' -TimeoutSec 3 -UseBasicParsing).Content; Write-Host '[HTTP] Response:' $r } catch { Write-Host '[HTTP] No response:' $_.Exception.Message }" 2>nul

echo.

:: -----------------------------------------------------------------------
:: 4. Named mutex check
:: -----------------------------------------------------------------------
echo [Mutex] Checking named mutex (Global\HookedWebserver_Port80_Owner)...
powershell -NoProfile -Command ^
    "try { $m=[System.Threading.Mutex]::OpenExisting('Global\HookedWebserver_Port80_Owner'); $m.Close(); Write-Host '[Mutex] FOUND -- a server instance owns the mutex.' } catch { Write-Host '[Mutex] Not found -- no active server instance.' }" 2>nul

echo.
echo [Check] Done. If server is not running:
echo   1. Make sure Install.bat was run as Administrator
echo   2. Make sure HookedWebserver.dll is injected into a running Roblox Studio process
echo   3. Check HookedWebserver.log for startup errors
echo.
pause
