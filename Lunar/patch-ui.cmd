@echo off
setlocal
cd /d "%~dp0"

echo === Lunar stage 4 - launcher branding + ad slot (app.asar) ===
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch-ui.ps1" -Mode Status
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch-ui.ps1" -Mode Apply
if %errorlevel% neq 0 (
    echo.
    echo [!] stage 4 did not complete - close Lunar Client and run this again
)
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch-ui.ps1" -Mode Status
echo.
pause
