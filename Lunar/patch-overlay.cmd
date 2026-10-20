@echo off
setlocal
cd /d "%~dp0"

echo === Lunar stage 6 - in-game overlay (index.js) ===
echo.
python "%~dp0patch-overlay.py" --status
if %errorlevel% neq 0 (
    echo.
    echo [!] applying overlay patch
    python "%~dp0patch-overlay.py" --apply
    if %errorlevel% neq 0 (
        echo.
        echo [!] overlay patch did not complete - the bundle is untouched
        echo [!] check the site name reported above, then run this again
        goto :done
    )
    echo.
    python "%~dp0patch-overlay.py" --status
)
:done
echo.
pause
