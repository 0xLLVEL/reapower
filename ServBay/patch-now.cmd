@echo off
setlocal
cd /d "%~dp0"
echo === ServBay manual patch (no watcher, no task) ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ServBayAutoPatch.ps1"
echo.
pause