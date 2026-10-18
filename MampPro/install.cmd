@echo off
setlocal
set "HERE=%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [i] admin rights needed - requesting UAC...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo === Install MAMP PRO License Patch ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%Install-MampProPatch.ps1"
echo.
pause
