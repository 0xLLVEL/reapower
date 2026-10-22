@echo off
setlocal
set "HERE=%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [i] admin rights needed - requesting UAC...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo === Install Madium Entitlement Patch ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%Install-MadiumPatch.ps1"
echo.
echo [i] later, to bring the endpoint back up without patching again: start.cmd
echo.
pause
