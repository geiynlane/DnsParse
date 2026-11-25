@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title DNS Parser V0.7

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell.exe"

fltmc >nul 2>&1
if errorlevel 1 (
    echo Administrator rights are required to update the system hosts file.
    echo Requesting elevation...
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop } catch { exit 1 }"
    if errorlevel 1 (
        echo.
        echo Elevation was cancelled or failed.
        echo You can still run DnsParse.ps1 directly: it generates hosts and the report,
        echo but it will not update the system hosts file.
        echo.
        pause
    )
    exit /b 3
)

"%PS_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0DnsParse.ps1" %*
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo [DONE] hosts and the report are in this folder.
    echo The system hosts file and the router hosts file were updated.
) else if "%RC%"=="2" (
    echo [WARN] No usable address was generated. The system hosts file was not changed.
) else if "%RC%"=="3" (
    echo [WARN] hosts and the report were generated, but the system hosts file was NOT updated.
    echo Run this file as administrator and check the message above.
) else if "%RC%"=="4" (
    echo [WARN] Local hosts was updated, but the router hosts file was NOT updated.
    echo Run "配置路由器SSH.bat" first, or check the router address, key and permissions.
) else (
    echo [ERROR] DNS parsing did not finish successfully. Exit code: %RC%
    echo Check the message above and the report file.
)
echo.
echo Press any key to close this window...
pause >nul
exit /b %RC%
