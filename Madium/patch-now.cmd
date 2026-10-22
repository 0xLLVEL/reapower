@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [i] admin rights needed - requesting UAC...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo === Madium manual patch (no watcher, no task) ===

set "STATE=%LOCALAPPDATA%\MadiumUnlock\state"
set "PUB="
if exist "%STATE%\keypair.pub" set /p PUB=<"%STATE%\keypair.pub"
if "%PUB%"=="" (
    echo [x] no keypair found in %STATE%\keypair.pub - run install.cmd first
    echo.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0MadiumPatch.ps1" -Profile full -Redirect 127.0.0.1:8080 -PubKey "%PUB%"
if errorlevel 1 (
    echo.
    echo [x] patch failed - the binary was left untouched
    pause
    exit /b 1
)

echo.
echo [i] re-check the result with:
echo     powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0MadiumPatch.ps1" -Profile full -Verify
echo.
pause
