@echo off
setlocal

set "HERE=%~dp0"

:: Optional first argument: path to Madium.exe, or to the Madium install folder.
set "TARGET=%~1"
if not "%TARGET%"=="" (
    if exist "%TARGET%\Bin\Madium.exe" set "TARGET=%TARGET%\Bin\Madium.exe"
)

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [i] admin rights needed - requesting UAC...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%TARGET%' -Verb RunAs"
    exit /b
)

echo === Install Madium Entitlement Patch ===
echo.
if not "%TARGET%"=="" (
    echo [i] target : %TARGET%
) else (
    echo [i] target : auto-detect
)
echo.

if not "%TARGET%"=="" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%Install-MadiumPatch.ps1" -Target "%TARGET%"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%Install-MadiumPatch.ps1"
)

if errorlevel 1 (
    echo.
    echo [x] install failed - see the messages above
    pause
    exit /b 1
)

echo.
echo [i] later, to bring the endpoint back up without patching again: start.cmd
echo.
pause
