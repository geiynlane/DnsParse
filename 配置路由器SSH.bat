@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title Router SSH Setup

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell.exe"

"%PS_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Setup-RouterSsh.ps1"
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo [DONE] Router SSH key login is ready.
) else (
    echo [ERROR] Router SSH setup failed. Exit code: %RC%
    echo Read the message above, then try again.
)
echo.
echo Press any key to close this window...
pause >nul
exit /b %RC%
