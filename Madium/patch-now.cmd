@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [i] admin rights needed - requesting UAC...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo === Madium manual patch (no watcher, no task) ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0MadiumPatch.ps1"
echo.
pause
