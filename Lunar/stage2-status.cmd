@echo off
setlocal
cd /d "%~dp0"

echo === Lunar stage 2 status (app.asar spans + accounts.json) ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch-lunar.ps1" -Mode Stage2Status
echo.
pause
