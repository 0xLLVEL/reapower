@echo off
setlocal
cd /d "%~dp0"

echo === Lunar patch status ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch-lunar.ps1" -Mode Status
echo.
pause
