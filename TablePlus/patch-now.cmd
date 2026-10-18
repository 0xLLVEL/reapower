@echo off
setlocal
cd /d "%~dp0"
echo === TablePlus manual patch (no watcher, no task) ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0TablePlusPatch.ps1"
echo.
pause