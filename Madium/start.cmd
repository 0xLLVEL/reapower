@echo off
setlocal

echo === Start the local Madium auth endpoint ===
echo    (no patch, no UAC - this only brings the endpoint back up)
echo.

set "STATE=%LOCALAPPDATA%\MadiumUnlock\state"
if not exist "%STATE%\madium_mockauth.py" (
    echo [x] %STATE%\madium_mockauth.py is missing - run install.cmd once first
    echo.
    pause
    exit /b 1
)
if not exist "%STATE%\keypair.json" (
    echo [x] %STATE%\keypair.json is missing - run install.cmd once first
    echo.
    pause
    exit /b 1
)

python "%STATE%\madium_mockauth.py" --port 8080 --key-pair "%STATE%\keypair.json" --quiet --log "%STATE%\mockauth.log" --daemon --pid-file "%STATE%\mockauth.pid" --exit-after-verdict --idle-timeout 20
if errorlevel 1 (
    echo.
    echo [x] the endpoint did not start
    pause
    exit /b 1
)

echo [+] the endpoint is up on http://127.0.0.1:8080
echo [i] it retires itself 20s after the client has its verdict
echo.
pause
