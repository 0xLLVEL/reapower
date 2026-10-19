@echo off
setlocal
cd /d "%~dp0"

echo === Lunar integrity-gate patch (manual mode, no watcher, no task) ===
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch-lunar.ps1" -Mode Status
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch-lunar.ps1" -Mode Apply
if %errorlevel% neq 0 (
    echo.
    echo [!] patch did not complete - close Lunar Client and run this again
)
echo.
pause
