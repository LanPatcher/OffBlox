@echo off
setlocal EnableDelayedExpansion
title HookedWebserver - Install
echo [Install] HookedWebserver Setup
echo.

:: -----------------------------------------------------------------------
:: 1.  Require Administrator
:: -----------------------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    echo         Right-click Install.bat and choose "Run as administrator".
    pause
    exit /b 1
)

cd /d "%~dp0"

:: -----------------------------------------------------------------------
:: 2.  Copy PEM cert + key directly from Apache
::     (same files Apache uses — no openssl / PFX conversion needed)
:: -----------------------------------------------------------------------
if not exist "ssl" mkdir ssl

set "APACHE_CERT=%~dp0..\Webserver\bin\apache\certificats\main-server.com.cert"
set "APACHE_KEY=%~dp0..\Webserver\bin\apache\certificats\main-server.com.key"

set "CRT=ssl\server.crt"
set "KEY=ssl\server.key"

if exist "!APACHE_CERT!" (
    copy /y "!APACHE_CERT!" "!CRT!" >nul
    echo [Install] Copied Apache cert  -^> ssl\server.crt
) else (
    echo [WARN] Apache cert not found at: !APACHE_CERT!
    echo        Copy main-server.com.cert to ssl\server.crt manually.
)

if exist "!APACHE_KEY!" (
    copy /y "!APACHE_KEY!" "!KEY!" >nul
    echo [Install] Copied Apache key   -^> ssl\server.key
) else (
    echo [WARN] Apache key not found at: !APACHE_KEY!
    echo        Copy main-server.com.key to ssl\server.key manually.
)

:: -----------------------------------------------------------------------
:: 3.  Register URL ACL for port 80
:: -----------------------------------------------------------------------
echo.
echo [Install] Registering URL ACL for port 80...
netsh http add urlacl url=http://+:80/ user=Everyone >nul 2>&1
if %errorlevel% equ 0 goto :port80ok
netsh http show urlacl url=http://+:80/ >nul 2>&1
if %errorlevel% equ 0 goto :port80ok
echo [WARN] Could not register URL ACL for port 80. Server may need to run as Admin.
goto :do_443
:port80ok
echo [Install] Port 80 ACL registered.

:: -----------------------------------------------------------------------
:: 4.  Register URL ACL for port 443
:: -----------------------------------------------------------------------
:do_443
echo [Install] Registering URL ACL for port 443...
netsh http add urlacl url=https://+:443/ user=Everyone >nul 2>&1
if %errorlevel% equ 0 goto :port443ok
netsh http show urlacl url=https://+:443/ >nul 2>&1
if %errorlevel% equ 0 goto :port443ok
echo [WARN] Could not register URL ACL for port 443.
goto :do_dirs
:port443ok
echo [Install] Port 443 ACL registered.

:: -----------------------------------------------------------------------
:: 5.  Create required directories
:: -----------------------------------------------------------------------
:do_dirs
echo.
echo [Install] Creating required directories...
if not exist "data"                mkdir "data"
if not exist "data\datastores"     mkdir "data\datastores"
if not exist "data\persistence"    mkdir "data\persistence"
if not exist "data\SavedData"      mkdir "data\SavedData"
if not exist "www"                 mkdir "www"
echo [Install] Directories OK.

:: -----------------------------------------------------------------------
:: 6.  Done
:: -----------------------------------------------------------------------
echo.
echo [Install] Setup complete!
echo.
if exist "ssl\server.crt" (
    echo   [OK] ssl\server.crt  -- cert ready
) else (
    echo   [!!] ssl\server.crt  -- MISSING. Copy main-server.com.cert here.
)
if exist "ssl\server.key" (
    echo   [OK] ssl\server.key  -- key ready
) else (
    echo   [!!] ssl\server.key  -- MISSING. Copy main-server.com.key here.
)
echo   [OK] Port 80  ACL registered
echo   [OK] Port 443 ACL registered
echo.
echo Next steps:
echo   1. Build HookedWebserver.dll with Build.bat if not done yet
echo   2. Place HookedWebserver.dll next to RbxInject.dll (same dir as the patched EXE)
echo   3. Copy ssl\, www\, data\, config.json to that same directory
echo      (ssl\server.crt and ssl\server.key should already be there from above)
echo   4. Launch the patched Roblox Studio -- server starts automatically
echo   5. Run CheckServer.bat to verify it is running
echo.
pause
