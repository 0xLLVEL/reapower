@echo off
setlocal
cd /d "%~dp0"

echo === Lunar stage 2 revert (restores the pristine app.asar + accounts.json) ===
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch-lunar.ps1" -Mode Stage2Revert
if %errorlevel% neq 0 (
    echo.
    echo [!] revert did not complete - close Lunar Client and run this again
)
echo.
pause
