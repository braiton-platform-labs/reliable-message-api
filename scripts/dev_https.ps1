param(
  [Parameter(Position = 0)]
  [ValidateSet("enable","disable","status","help")]
  [string]$Command = "status",

  # WSL distro used by the repo scripts. Empty means "use WSL default distro".
  [string]$Distro = "",

  # kind defaults (Kong port-forward binds to these on Windows host).
  [int]$ListenPort = 443,
  [int]$TargetPort = 8443,
  [string]$ListenAddress = "127.0.0.1",
  [string]$TargetAddress = "127.0.0.1",

  # Install mkcert root CA into Windows CurrentUser Root store (recommended).
  [switch]$TrustWslMkcertCa,

  # Skip applying the Windows hosts block (api.local.dev / kong.local.dev).
  [switch]$SkipHosts
)

$ErrorActionPreference = "Stop"

function Usage {
  @"
Reliable Message API - Windows HTTPS helper (no-port HTTPS for Postman/Browser)

Usage:
  powershell -ExecutionPolicy Bypass -File .\scripts\dev_https.ps1 status
  powershell -ExecutionPolicy Bypass -File .\scripts\dev_https.ps1 enable [-TrustWslMkcertCa] [-SkipHosts]
  powershell -ExecutionPolicy Bypass -File .\scripts\dev_https.ps1 disable

What it does (enable):
  - Ensures Windows hosts entries exist: api.local.dev, kong.local.dev
  - Optionally trusts the mkcert root CA used inside WSL (imports to CurrentUser Root)
  - Adds a netsh portproxy rule: 127.0.0.1:443 -> 127.0.0.1:8443

Notes:
  - netsh portproxy requires Administrator privileges.
  - This does not terminate TLS; it only forwards TCP so you can hit https://api.local.dev without ':8443'.
"@ | Write-Output
}

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Ensure-Admin {
  if (Test-IsAdmin) { return }
  Write-Output "Re-launching elevated (UAC prompt expected)..."
  $exe = (Get-Process -Id $PID).Path
  if (-not $exe) { $exe = "powershell.exe" }
  $argsList = @("-NoProfile","-ExecutionPolicy","Bypass","-File",$PSCommandPath) + $script:args
  $p = Start-Process -FilePath $exe -Verb RunAs -ArgumentList $argsList -PassThru -Wait
  exit $p.ExitCode
}

function Get-RepoRoot {
  return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Ensure-WindowsHosts {
  param([string]$RepoRoot)
  $setupScript = Join-Path $RepoRoot "setup\\windows-11-wsl2-docker-desktop\\setup.ps1"
  if (-not (Test-Path -LiteralPath $setupScript)) { throw "setup script not found: $setupScript" }

  # apply self-elevates via its own Ensure-Admin.
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupScript hosts -HostsAction apply
}

function Test-PortListening([int]$Port, [string]$Addr = "127.0.0.1") {
  try {
    $conns = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop
    foreach ($c in $conns) {
      if ($c.LocalAddress -eq $Addr -or $c.LocalAddress -eq "0.0.0.0" -or $c.LocalAddress -eq "::") { return $true }
    }
    return $false
  } catch {
    # Fallback when Get-NetTCPConnection is blocked/unavailable.
    $lines = @(& netstat.exe -ano -p tcp 2>$null)
    foreach ($line in $lines) {
      $t = ($line -as [string]).Trim()
      if (-not $t) { continue }
      # Example:
      # TCP    0.0.0.0:443     0.0.0.0:0    LISTENING    4
      if ($t -match '^(TCP)\s+(\S+):(\d+)\s+(\S+):(\S+)\s+(LISTENING|OUVINDO)\s+(\d+)\s*$') {
        $localAddr = $Matches[2]
        $localPort = [int]$Matches[3]
        if ($localPort -ne $Port) { continue }

        # Accept exact listen addr, or wildcard listeners.
        if ($localAddr -eq $Addr -or $localAddr -eq "0.0.0.0" -or $localAddr -eq "127.0.0.1" -or $localAddr -eq "[::]" -or $localAddr -eq "::") {
          return $true
        }
      }
    }
    return $false
  }
}

function Describe-PortListeners([int]$Port) {
  $items = @()
  try {
    $conns = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop
    foreach ($c in $conns) {
      $pid = $c.OwningProcess
      $pname = ""
      try { $pname = (Get-Process -Id $pid -ErrorAction Stop).ProcessName } catch {}
      $items += ("{0}:{1} pid={2}{3}" -f $c.LocalAddress, $c.LocalPort, $pid, ($(if ($pname) { " ($pname)" } else { "" })))
    }
  } catch {
    # Best-effort fallback.
    try {
      $lines = @(& netstat.exe -ano -p tcp 2>$null)
      foreach ($line in $lines) {
        $t = ($line -as [string]).Trim()
        if (-not $t) { continue }
        if ($t -match '^(TCP)\s+(\S+):(\d+)\s+(\S+):(\S+)\s+(LISTENING|OUVINDO)\s+(\d+)\s*$') {
          $localPort = [int]$Matches[3]
          if ($localPort -ne $Port) { continue }
          $items += $t
        }
      }
    } catch {}
  }
  return $items
}

function Get-PortProxyRuleInfo([string]$ListenAddr, [int]$ListenPort) {
  $lines = @(& netsh.exe interface portproxy show v4tov4 2>$null)
  foreach ($l in $lines) {
    $t = ($l -as [string]).Trim()
    if (-not $t) { continue }
    if ($t -match '^\s*Listen on ipv4:\s*$') { continue }
    if ($t -match '^\s*Address\s+Port\s+Connect\s+Address\s+Port\s*$') { continue }
    if ($t -match '^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s*$') {
      $addr = $Matches[1]; $port = [int]$Matches[2]
      if ($addr -eq $ListenAddr -and $port -eq $ListenPort) {
        return [pscustomobject]@{
          ListenAddress  = $addr
          ListenPort     = $port
          ConnectAddress = $Matches[3]
          ConnectPort    = [int]$Matches[4]
          Raw            = $t
        }
      }
    }
  }
  return $null
}

function Ensure-IpHelperRunning {
  try {
    $svc = Get-Service -Name iphlpsvc -ErrorAction Stop
    if ($svc.Status -ne "Running") {
      Start-Service -Name iphlpsvc -ErrorAction Stop
    }
  } catch {
    # Best-effort only.
  }
}

function Trust-WslMkcertCa {
  param([string]$Distro)

  $wslExe = (Get-Command wsl.exe -ErrorAction SilentlyContinue)
  if (-not $wslExe) { throw "wsl.exe not found." }

  $invokeWsl = {
    param([string]$Cmd)
    if ($Distro) {
      & wsl.exe -d $Distro -- bash -lc $Cmd 2>$null
    } else {
      & wsl.exe -- bash -lc $Cmd 2>$null
    }
  }

  $hasMkcertRaw = & $invokeWsl "command -v mkcert >/dev/null 2>&1 && echo yes || true"
  $hasMkcertFirst = $hasMkcertRaw | Select-Object -First 1
  $hasMkcert = if ($null -ne $hasMkcertFirst) { $hasMkcertFirst.ToString().Trim() } else { "" }
  if ($hasMkcert -ne "yes") {
    throw "mkcert not found in WSL PATH. Run: .\\scripts\\wsl_bootstrap.ps1"
  }

  # Use mkcert inside WSL (installed by scripts/wsl_bootstrap.ps1).
  $carootRaw = & $invokeWsl "mkcert -CAROOT"
  $carootFirst = $carootRaw | Select-Object -First 1
  $caroot = if ($null -ne $carootFirst) { $carootFirst.ToString().Trim() } else { "" }
  if (-not $caroot) { throw "Failed to read mkcert CAROOT in WSL. Is mkcert installed? Run: .\\scripts\\wsl_bootstrap.ps1" }

  # Read rootCA.pem (public cert) and write to a Windows temp file.
  $pem = & $invokeWsl "cat '$caroot/rootCA.pem'"
  if (-not $pem) { throw "Failed to read $caroot/rootCA.pem from WSL." }

  $distroLabel = if ($Distro) { $Distro } else { "default" }
  $outFile = Join-Path $env:TEMP ("mkcert-wsl-rootCA-{0}.pem" -f $distroLabel)
  Set-Content -LiteralPath $outFile -Value $pem -Encoding Ascii

  # Import into CurrentUser Root store (no admin required).
  # Use -f to avoid interactive confirmation prompts when importing a root CA.
  & certutil.exe -user -addstore -f Root $outFile | Out-Null
  Write-Output "Trusted WSL mkcert root CA (CurrentUser Root): $outFile"
}

function Enable-PortProxy {
  param(
    [string]$ListenAddr,
    [int]$ListenPort,
    [string]$TargetAddr,
    [int]$TargetPort
  )

  $existing = Get-PortProxyRuleInfo -ListenAddr $ListenAddr -ListenPort $ListenPort
  if ($existing) {
    if ($existing.ConnectAddress -eq $TargetAddr -and $existing.ConnectPort -eq $TargetPort) {
      return
    }
    # We'll update the rule below (delete + add). A listener is expected in this case.
  } elseif (Test-PortListening -Port $ListenPort -Addr $ListenAddr) {
    $listeners = Describe-PortListeners -Port $ListenPort
    $detail = ""
    if ($listeners -and $listeners.Count -gt 0) {
      $detail = " Listeners: " + ($listeners -join "; ")
    }
    throw "Port $ListenPort is already in use. Free it (or stop the conflicting service) and retry.$detail"
  }

  Ensure-Admin
  Ensure-IpHelperRunning

  # Idempotent: delete existing rule for this listen socket, then re-add.
  & netsh.exe interface portproxy delete v4tov4 listenaddress=$ListenAddr listenport=$ListenPort 2>$null | Out-Null
  & netsh.exe interface portproxy add v4tov4 listenaddress=$ListenAddr listenport=$ListenPort connectaddress=$TargetAddr connectport=$TargetPort | Out-Null
}

function Disable-PortProxy {
  param([string]$ListenAddr, [int]$ListenPort)
  Ensure-Admin
  & netsh.exe interface portproxy delete v4tov4 listenaddress=$ListenAddr listenport=$ListenPort 2>$null | Out-Null
}

function Print-Status {
  param(
    [string]$RepoRoot,
    [string]$ListenAddr,
    [int]$ListenPort,
    [string]$TargetAddr,
    [int]$TargetPort
  )

  $rule = Get-PortProxyRuleInfo -ListenAddr $ListenAddr -ListenPort $ListenPort
  if ($rule) {
    Write-Output "portproxy: present ($($rule.Raw))"
  } else {
    Write-Output "portproxy: missing ($ListenAddr`:$ListenPort -> $TargetAddr`:$TargetPort)"
  }
  Write-Output ("admin: {0}" -f (Test-IsAdmin))
  $listening = Test-PortListening -Port $ListenPort -Addr $ListenAddr
  Write-Output ("443 listening: {0}" -f $listening)
  if (-not $rule -and $listening) {
    $listeners = Describe-PortListeners -Port $ListenPort
    if ($listeners -and $listeners.Count -gt 0) {
      Write-Output ("443 conflict: {0}" -f ($listeners -join "; "))
    }
  }

  $hostsScript = Join-Path $RepoRoot "setup\\windows-11-wsl2-docker-desktop\\setup.ps1"
  if (Test-Path -LiteralPath $hostsScript) {
    try {
      $status = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $hostsScript hosts -HostsAction status 2>$null
      if ($status) { $status | ForEach-Object { Write-Output $_ } }
    } catch {}
  }

  try {
    $mk = Get-ChildItem -Path Cert:\CurrentUser\Root -ErrorAction Stop |
      Where-Object { $_.Subject -like "*mkcert development CA*" }
    if ($mk) {
      Write-Output ("mkcert CA (CurrentUser Root): present ({0})" -f $mk.Count)
    } else {
      Write-Output "mkcert CA (CurrentUser Root): not found"
    }
  } catch {
    # Best-effort only.
  }
}

try {
  if ($Command -eq "help") { Usage; exit 0 }

  $repoRoot = Get-RepoRoot

  switch ($Command) {
    "status" {
      Print-Status -RepoRoot $repoRoot -ListenAddr $ListenAddress -ListenPort $ListenPort -TargetAddr $TargetAddress -TargetPort $TargetPort
      exit 0
    }

    "enable" {
      # Hosts entries are required for api.local.dev to resolve to 127.0.0.1.
      if (-not $SkipHosts) { Ensure-WindowsHosts -RepoRoot $repoRoot }

      if ($TrustWslMkcertCa) {
        Trust-WslMkcertCa -Distro $Distro
      }

      Enable-PortProxy -ListenAddr $ListenAddress -ListenPort $ListenPort -TargetAddr $TargetAddress -TargetPort $TargetPort
      Write-Output "Enabled: https://api.local.dev (no port) via portproxy $ListenAddress`:$ListenPort -> $TargetAddress`:$TargetPort"
      exit 0
    }

    "disable" {
      Disable-PortProxy -ListenAddr $ListenAddress -ListenPort $ListenPort
      Write-Output "Disabled portproxy for $ListenAddress`:$ListenPort"
      exit 0
    }

    default {
      Usage
      exit 2
    }
  }
} catch {
  [Console]::Error.WriteLine("ERROR: {0}" -f $_.Exception.Message)
  exit 1
}
