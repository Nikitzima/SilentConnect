param(
    [string]$OutputDir = "",
    [switch]$IncludeSubscriptionsDb
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputDir = Join-Path ([Environment]::GetFolderPath("Desktop")) "happ-settings-backup-$stamp"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$regFile = Join-Path $OutputDir "happ-hkcu-settings.reg"
& reg.exe export "HKCU\Software\Happ" $regFile /y | Out-Null

$localHapp = Join-Path $env:LOCALAPPDATA "Happ"
foreach ($name in @("config.json", "routing.json")) {
    $source = Join-Path $localHapp $name
    if (Test-Path $source) {
        Copy-Item $source (Join-Path $OutputDir $name) -Force
    }
}

if ($IncludeSubscriptionsDb) {
    $subs = Join-Path $localHapp "subs.db"
    if (Test-Path $subs) {
        Copy-Item $subs (Join-Path $OutputDir "subs.db") -Force
    }
}

& route.exe print -4 | Out-File -FilePath (Join-Path $OutputDir "windows-ipv4-routes.txt") -Encoding utf8

@"
Happ settings backup

Files:
- happ-hkcu-settings.reg: Happ UI/preferences registry settings.
- config.json: generated local TUN/sing-box style config.
- routing.json: local routing profiles.
- windows-ipv4-routes.txt: route table snapshot.
- subs.db: included only when -IncludeSubscriptionsDb is used.

Restore notes:
1. Install Happ first.
2. Close Happ.
3. Import happ-hkcu-settings.reg.
4. Copy config.json/routing.json into %LOCALAPPDATA%\Happ if needed.
5. Re-run setup-happ-tun.ps1 to recreate persistent Windows routes.

Do not distribute subs.db to customers.
"@ | Out-File -FilePath (Join-Path $OutputDir "RESTORE-NOTES.txt") -Encoding utf8

Write-Host "Backup created: $OutputDir"
