@echo off
title HookedWebserver
echo [HookedWebserver] Starting...
echo [HookedWebserver] Node.js adaptive server - auto-detects if already running
echo.

where node >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js not found. Please install Node.js from https://nodejs.org
    pause
    exit /b 1
)

node "%~dp0server.js" %*
if %errorlevel% neq 0 (
    echo [HookedWebserver] Exited with error. Press any key to close.
    pause
)
