param(
    [string[]]$ServerTargets = @("192.0.2.1"),
    [string]$DnsIp = "1.1.1.1",
    [string]$DnsDomain = "cloudflare-dns.com",
    [string]$HappLink = "",
    [switch]$OpenHappLink,
    [switch]$NoAutoStart,
    [switch]$NoPersistentRoutes,
    [switch]$BackupSettings,
    [string]$BackupDir = "",
    [switch]$RestartHapp,
    [string]$HappExe = "$env:ProgramFiles\FlyFrogLLC\Happ\Happ.exe",
    [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IPv4 {
    param([string]$Value)
    $address = $null
    return [Net.IPAddress]::TryParse($Value, [ref]$address) -and $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
}

function Resolve-TargetIPv4 {
    param(
        [string[]]$Targets,
        [string]$Server
    )

    $ips = New-Object System.Collections.Generic.List[string]
    foreach ($target in $Targets) {
        if ([string]::IsNullOrWhiteSpace($target)) {
            continue
        }

        $clean = $target.Trim()
        if (Test-IPv4 $clean) {
            $ips.Add($clean)
            continue
        }

        try {
            $records = Resolve-DnsName -Name $clean -Type A -Server $Server -ErrorAction Stop
        } catch {
            $records = Resolve-DnsName -Name $clean -Type A -ErrorAction Stop
        }

        foreach ($record in $records) {
            if ($record.IPAddress -and (Test-IPv4 $record.IPAddress)) {
                $ips.Add($record.IPAddress)
            }
        }
    }

    return $ips | Sort-Object -Unique
}

function Get-PrimaryIPv4Route {
    $routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
        Where-Object {
            $_.NextHop -and
            $_.NextHop -ne "0.0.0.0" -and
            $_.InterfaceAlias -notmatch "(?i)happ|tun|wintun|wireguard|openvpn|tap|clash|mihomo|tailscale|zerotier"
        }

    $candidates = foreach ($route in $routes) {
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        if ($adapter -and $adapter.Status -eq "Up") {
            [pscustomobject]@{
                Route = $route
                EffectiveMetric = [int]$route.RouteMetric + [int]$route.InterfaceMetric
            }
        }
    }

    $selected = $candidates | Sort-Object EffectiveMetric | Select-Object -First 1
    if (-not $selected) {
        throw "No active physical IPv4 default route found."
    }

    return $selected.Route
}

function Backup-HappSettings {
    param([string]$OutputDir)

    if ([string]::IsNullOrWhiteSpace($OutputDir)) {
        $OutputDir = [Environment]::GetFolderPath("Desktop")
    }

    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupPath = Join-Path $OutputDir "happ-hkcu-before-silentconnect-$stamp.reg"

    if (Test-Path "HKCU:\Software\Happ") {
        & reg.exe export "HKCU\Software\Happ" $backupPath /y | Out-Null
        return $backupPath
    }

    return ""
}

function Stop-HappApp {
    Get-Process Happ -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 1
}

function Start-HappApp {
    param([string]$Path)

    if (Test-Path $Path) {
        Start-Process $Path
        return $true
    }

    return $false
}

function Set-HappGoldenSettings {
    param(
        [string]$DnsAddress,
        [string]$ResolverDomain,
        [bool]$AutoStart
    )

    $base = "HKCU:\Software\Happ\OrganizationDefaults\Preferences"
    $advanced = Join-Path $base "AdvancedSettings"
    $sniffing = Join-Path $base "TunnelSettings\Sniffing"
    $perApp = Join-Path $base "TunnelSettings\PerAppProxy"
    $fragmentation = Join-Path $base "TunnelSettings\Fragmentation"
    $subs = Join-Path $base "Subscriptions"

    New-Item -Path $advanced -Force | Out-Null
    New-Item -Path $sniffing -Force | Out-Null
    New-Item -Path $perApp -Force | Out-Null
    New-Item -Path $fragmentation -Force | Out-Null
    New-Item -Path $subs -Force | Out-Null

    New-ItemProperty -Path $advanced -Name "autoStart" -PropertyType String -Value ($AutoStart.ToString().ToLowerInvariant()) -Force | Out-Null
    New-ItemProperty -Path $advanced -Name "systemProxy" -PropertyType String -Value "false" -Force | Out-Null
    New-ItemProperty -Path $advanced -Name "tun" -PropertyType String -Value "true" -Force | Out-Null
    New-ItemProperty -Path $advanced -Name "resolveServerEnable" -PropertyType String -Value "true" -Force | Out-Null
    New-ItemProperty -Path $advanced -Name "dnsFromJson" -PropertyType String -Value "true" -Force | Out-Null
    New-ItemProperty -Path $advanced -Name "tunConfigMode" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $advanced -Name "tunDnsAddress" -PropertyType String -Value $DnsAddress -Force | Out-Null
    New-ItemProperty -Path $advanced -Name "tunProvider" -PropertyType String -Value "default" -Force | Out-Null
    New-ItemProperty -Path $advanced -Name "resolveServerDnsIp" -PropertyType String -Value $DnsAddress -Force | Out-Null
    New-ItemProperty -Path $advanced -Name "resolveServerDnsDomain" -PropertyType String -Value $ResolverDomain -Force | Out-Null

    New-ItemProperty -Path $sniffing -Name "useSniffing" -PropertyType String -Value "true" -Force | Out-Null
    New-ItemProperty -Path $perApp -Name "enabled" -PropertyType String -Value "false" -Force | Out-Null
    New-ItemProperty -Path $perApp -Name "mode" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $fragmentation -Name "useFragment" -PropertyType String -Value "false" -Force | Out-Null
    New-ItemProperty -Path $subs -Name "subsCollapseEnabled" -PropertyType String -Value "true" -Force | Out-Null
    New-ItemProperty -Path $subs -Name "subsIgnoreDuplicates" -PropertyType String -Value "true" -Force | Out-Null

    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Type DWord -Value 0
}

function Install-BypassRoutes {
    param(
        [string[]]$IPs,
        [string]$Gateway,
        [switch]$Persistent
    )

    if (-not $IPs -or $IPs.Count -eq 0) {
        return
    }

    $routeLines = foreach ($ip in $IPs) {
        "`"$ip`""
    }
    $ipArray = "@(" + ($routeLines -join ",") + ")"
    $persistFlag = if ($Persistent) { "-p" } else { "" }

    $script = @"
`$ErrorActionPreference = "Stop"
`$ips = $ipArray
`$gateway = "$Gateway"
foreach (`$ip in `$ips) {
    & route.exe delete `$ip 2>`$null | Out-Null
    if ("$persistFlag") {
        & route.exe -p add `$ip mask 255.255.255.255 `$gateway metric 1 | Out-Null
    } else {
        & route.exe add `$ip mask 255.255.255.255 `$gateway metric 1 | Out-Null
    }
}
"@

    if (Test-Admin) {
        Invoke-Expression $script
        return
    }

    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $process = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        $encoded
    )

    if ($process.ExitCode -ne 0) {
        throw "Route installation failed or UAC was cancelled."
    }
}

function Show-Verification {
    param([string[]]$IPs)

    foreach ($ip in $IPs) {
        Write-Host ""
        Write-Host "Route for $ip"
        Find-NetRoute -RemoteIPAddress $ip | Format-List IPAddress, InterfaceIndex, InterfaceAlias, NextHop, RouteMetric, InterfaceMetric, DestinationPrefix
    }

    $xray = Get-Process xray -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($xray) {
        Write-Host ""
        Write-Host "xray.exe established server connections"
        Get-NetTCPConnection -OwningProcess $xray.Id -State Established -ErrorAction SilentlyContinue |
            Where-Object { $IPs -contains $_.RemoteAddress } |
            Group-Object LocalAddress, RemoteAddress, RemotePort |
            ForEach-Object {
                $parts = $_.Name -split ", "
                [pscustomobject]@{
                    LocalAddress = $parts[0]
                    RemoteAddress = $parts[1]
                    RemotePort = $parts[2]
                    Connections = $_.Count
                }
            } |
            Sort-Object RemoteAddress, RemotePort, LocalAddress |
            Format-Table -AutoSize
    }
}

$serverIps = Resolve-TargetIPv4 -Targets $ServerTargets -Server $DnsIp
if (-not $serverIps -or $serverIps.Count -eq 0) {
    throw "No IPv4 server addresses resolved from ServerTargets."
}

if (-not $VerifyOnly) {
    $backupPath = ""
    if ($BackupSettings) {
        $backupPath = Backup-HappSettings -OutputDir $BackupDir
    }

    if ($RestartHapp) {
        Stop-HappApp
    }

    Set-HappGoldenSettings -DnsAddress $DnsIp -ResolverDomain $DnsDomain -AutoStart:(!$NoAutoStart)

    $primaryRoute = Get-PrimaryIPv4Route
    Install-BypassRoutes -IPs $serverIps -Gateway $primaryRoute.NextHop -Persistent:(!$NoPersistentRoutes)

    if ($RestartHapp) {
        $started = Start-HappApp -Path $HappExe
        if (-not $started) {
            Write-Warning "Happ executable was not found: $HappExe"
        }
    }

    if ($OpenHappLink -and -not [string]::IsNullOrWhiteSpace($HappLink)) {
        Start-Process $HappLink
    }
}

Show-Verification -IPs $serverIps

Write-Host ""
if ($VerifyOnly) {
    Write-Host "Happ TUN golden settings verified."
} else {
    Write-Host "Happ TUN golden settings applied."
    if ($backupPath) {
        Write-Host "Backup: $backupPath"
    }
}
Write-Host "Server IPs: $($serverIps -join ', ')"
Write-Host "DNS: $DnsIp / $DnsDomain"
