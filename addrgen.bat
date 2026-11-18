@echo off
rem Do not leave a printed private key sitting on screen.
addrgen.py
if errorlevel 1 goto failed
echo.
echo warning: the private key above is on screen and may remain in scrollback.
echo Copy it now. Press a key to clear this window.
pause >nul
cls
goto end
:failed
echo.
echo addrgen failed before printing a private key. Press a key to close.
pause >nul
:end
