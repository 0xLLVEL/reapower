@echo off
setlocal
cd /d "%~dp0"
echo === Herd manual patch (no watcher, no task) ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0HerdPatch.ps1" -Restart
echo.
pause