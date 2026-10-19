@echo off
setlocal
cd /d "%~dp0"

echo === Lunar patch revert (restores the pristine exe from backup) ===
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch-lunar.ps1" -Mode Revert
if %errorlevel% neq 0 (
    echo.
    echo [!] revert did not complete - close Lunar Client and run this again
)
echo.
pause
