@echo off
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
echo Removing scheduled task "ServBay AutoPatch"...
powershell -NoProfile -Command "Unregister-ScheduledTask -TaskName 'ServBay AutoPatch' -Confirm:$false -ErrorAction SilentlyContinue; Get-ScheduledTask -TaskName 'ServBay AutoPatch' -ErrorAction SilentlyContinue | Select-Object TaskName,State"
echo.
echo Files in C:\ProgramData\ServBayPatch were kept (log + pristine backups).
echo The patched ServBay.dll stays patched until ServBay updates itself.
echo.
pause
