@echo off
setlocal
title Happ TUN Windows Fix

cd /d "%~dp0"

echo Happ TUN Windows Fix
echo.
echo This configures local Happ TUN settings and adds a bypass route
echo to the VPN server endpoint through your normal LAN gateway.
echo.
echo Enter the VPN server domain or IP exactly as it appears in the profile.
echo Examples:
echo   edge.example.com
echo   203.0.113.10
echo.

set "TARGET=%~1"
if "%TARGET%"=="" (
    set /p "TARGET=VPN server domain or IP: "
)

if "%TARGET%"=="" (
    echo.
    echo No server target entered. Nothing was changed.
    echo.
    pause
    exit /b 2
)

echo.
echo Target: %TARGET%
echo Windows may show a UAC prompt for the route command.
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-happ-tun.ps1" -ServerTargets "%TARGET%" -BackupSettings -RestartHapp
set "code=%ERRORLEVEL%"

echo.
if not "%code%"=="0" (
    echo Fix failed with exit code %code%.
    echo Send a screenshot of this window to support.
) else (
    echo Done. Open Happ, select your profile, and connect.
)
echo.
pause
exit /b %code%
