@echo off
setlocal
cd /d "%~dp0"

echo === Lunar stage 7 - GameIPC account routing (app.asar) ===
echo.
echo [i] close Lunar Client and the game first - the file is replaced in place
echo.
python "%~dp0patch-gameipc.py" --status
if %errorlevel% neq 0 (
    echo.
    echo [!] applying GameIPC patch
    python "%~dp0patch-gameipc.py" --apply
    if %errorlevel% neq 0 (
        echo.
        echo [!] stage 7 did not complete - the asar was not installed
        goto :done
    )
    echo.
    python "%~dp0patch-gameipc.py" --status
)
:done
echo.
pause
