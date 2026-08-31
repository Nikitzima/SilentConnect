@echo off
setlocal
title SilentConnect Happ Windows Fix

cd /d "%~dp0"

echo SilentConnect Happ Windows Fix
echo.
echo This will:
echo - configure Happ TUN settings for the current Windows user;
echo - disable Windows system proxy mode in Happ;
echo - disable Happ per-app proxy and fragmentation;
echo - add a persistent bypass route to the VPN server through your LAN gateway;
echo - restart Happ after applying the settings.
echo.
echo Windows may show a UAC prompt for the route command.
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-happ-tun.ps1" -ServerTargets "192.0.2.1" -BackupSettings -RestartHapp
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
