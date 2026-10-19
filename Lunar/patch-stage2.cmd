@echo off
setlocal
cd /d "%~dp0"

echo === Lunar stage 2 - ownership gate (app.asar + accounts.json) ===
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch-lunar.ps1" -Mode Stage2Status
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch-lunar.ps1" -Mode Stage2Apply
if %errorlevel% neq 0 (
    echo.
    echo [!] stage 2 did not complete - close Lunar Client and run this again
)
echo.
pause
