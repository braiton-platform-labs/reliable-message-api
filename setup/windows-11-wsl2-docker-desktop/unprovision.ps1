Param(
  # Target distro to remove (requested: Ubuntu 22.04).
  [string]$Distro = "Ubuntu-22.04",

  # Remove Docker/WSL data directories for all local user profiles under C:\Users (more aggressive).
  [switch]$AllUsers,

  # Disable WSL optional features (VirtualMachinePlatform + Microsoft-Windows-Subsystem-Linux) after cleanup.
  # If other non-Docker WSL distros exist, features will NOT be disabled unless -ForceDisableWSLFeatures is set.
  [switch]$DisableWSLFeatures,
  [switch]$ForceDisableWSLFeatures,

  # Timeouts (seconds) to avoid hangs.
  [int]$UnregisterTimeoutSeconds = 180,
  [int]$WingetTimeoutSeconds = 900,
  [int]$UninstallTimeoutSeconds = 900
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Summary = New-Object System.Collections.Generic.List[string]
$script:RebootRecommended = $false

function Write-Log([string]$message, [ValidateSet("INFO","WARN","ERROR")][string]$level = "INFO") {
  $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffK")
  $line = "[{0}] [{1}] {2}" -f $ts, $level, $message
  Write-Host $line
  try {
    $dir = Join-Path $PSScriptRoot ".logs"
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $path = Join-Path $dir "unprovision.log"
    Add-Content -LiteralPath $path -Value $line -Encoding UTF8
  } catch {
    # Best-effort only.
  }
}

function Add-Summary([string]$line) {
  $script:Summary.Add($line) | Out-Null
}

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "This script must be run from an elevated PowerShell session (Run as Administrator)."
  }
}

function Test-PendingReboot {
  $checks = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
  )
  foreach ($k in $checks) {
    if (Test-Path -LiteralPath $k) { return $true }
  }
  try {
    $sm = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue
    if ($sm -and $sm.PendingFileRenameOperations) { return $true }
  } catch {}
  return $false
}

function Invoke-ProcessWithTimeout(
  [Parameter(Mandatory=$true)][string]$FilePath,
  [string[]]$ArgumentList = @(),
  [int]$TimeoutSeconds = 600
) {
  $p = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru -WindowStyle Hidden
  try {
    $ms = [int]([Math]::Min([double]$TimeoutSeconds * 1000.0, [double][int]::MaxValue))
    $ok = $p.WaitForExit($ms)
    if (-not $ok) {
      try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
      throw "Process timed out after ${TimeoutSeconds}s: $FilePath $($ArgumentList -join ' ')"
    }
    return $p.ExitCode
  } finally {
    try { $p.Dispose() } catch {}
  }
}

function Stop-ProcessBestEffort([string[]]$names) {
  foreach ($n in @($names)) {
    try {
      Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
  }
}

function Stop-ServiceBestEffort([string[]]$names) {
  foreach ($n in @($names)) {
    try {
      $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
      if (-not $svc) { continue }
      if ($svc.Status -eq "Running") {
        try { Stop-Service -Name $n -Force -ErrorAction SilentlyContinue } catch {}
      }
    } catch {}
  }
}

function Remove-PathBestEffort([string]$path) {
  if (-not $path) { return }
  try {
    if (-not (Test-Path -LiteralPath $path)) { return }
    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
  } catch {}
}

function Normalize-WslTextLine([string]$s) {
  if ($null -eq $s) { return "" }
  return (($s -replace "\u0000", "").Trim())
}

function Get-WSLDistros([switch]$All) {
  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return @() }
  $args = @("-l","-q")
  if ($All) { $args += "--all" }
  try {
    $raw = & wsl.exe @args 2>$null
    if (($LASTEXITCODE -ne 0 -or -not $raw) -and $All) {
      # Older WSL builds may not support --all.
      $raw = & wsl.exe @("-l","-q") 2>$null
    }
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return @() }
    return @(
      $raw |
        ForEach-Object { Normalize-WslTextLine $_ } |
        Where-Object { $_ -and $_ -ne "" }
    )
  } catch {
    return @()
  }
}

function Wsl-ShutdownBestEffort {
  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return }
  try { & wsl.exe --shutdown | Out-Null } catch {}
}

function Wsl-UnregisterBestEffort([string]$name) {
  if (-not $name) { return $false }
  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $false }

  $distros = Get-WSLDistros -All
  if ($distros -notcontains $name) { return $false }

  Write-Log "Unregistering WSL distro: $name"
  try {
    $rc = Invoke-ProcessWithTimeout -FilePath "wsl.exe" -ArgumentList @("--unregister", $name) -TimeoutSeconds $UnregisterTimeoutSeconds
    if ($rc -eq 0) { return $true }
    Write-Log "WARN: wsl --unregister $name failed (exit code $rc)." "WARN"
    return $false
  } catch {
    Write-Log "WARN: wsl --unregister $name failed: $($_.Exception.Message)" "WARN"
    return $false
  }
}

function Test-WingetHasPackage([string]$id) {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return $false }
  try {
    $out = winget list -e --id $id 2>$null
    return ($LASTEXITCODE -eq 0 -and ($out | Select-String -Pattern $id -SimpleMatch))
  } catch {
    return $false
  }
}

function Uninstall-DockerDesktopViaWinget {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return $false }
  if (-not (Test-WingetHasPackage "Docker.DockerDesktop")) { return $false }

  Write-Log "Uninstalling Docker Desktop via winget..."
  $args = @(
    "uninstall",
    "-e",
    "--id","Docker.DockerDesktop",
    "--silent",
    "--disable-interactivity"
  )

  try {
    $rc = Invoke-ProcessWithTimeout -FilePath "winget" -ArgumentList $args -TimeoutSeconds $WingetTimeoutSeconds
    if ($rc -eq 0) { return $true }
    Write-Log "WARN: winget uninstall failed (exit code $rc)." "WARN"
    return $false
  } catch {
    Write-Log "WARN: winget uninstall failed: $($_.Exception.Message)" "WARN"
    return $false
  }
}

function Get-UninstallEntries {
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  $items = @()
  foreach ($p in $paths) {
    try { $items += Get-ItemProperty -Path $p -ErrorAction SilentlyContinue } catch {}
  }
  return $items
}

function Try-GetPropValue($obj, [string]$name) {
  if ($null -eq $obj -or -not $name) { return $null }
  try {
    $p = $obj.PSObject.Properties[$name]
    if ($null -eq $p) { return $null }
    return $p.Value
  } catch {
    return $null
  }
}

function Uninstall-DockerDesktopViaRegistry {
  $entries =
    Get-UninstallEntries |
      Where-Object {
        $dn = Try-GetPropValue $_ "DisplayName"
        ($dn -is [string]) -and ($dn -like "Docker Desktop*")
      } |
      Select-Object -First 1

  if (-not $entries) { return $false }

  $quiet = Try-GetPropValue $entries "QuietUninstallString"
  $uninstall = Try-GetPropValue $entries "UninstallString"
  $cmdLine = $null
  if ($quiet) { $cmdLine = [string]$quiet } elseif ($uninstall) { $cmdLine = [string]$uninstall }
  if (-not $cmdLine) { return $false }

  # Best-effort: normalize MSI uninstall to quiet.
  # Many installers register "MsiExec.exe /I{GUID}" (install) or "/X{GUID}" (uninstall).
  if ($cmdLine -match '(?i)msiexec\.exe') {
    if ($cmdLine -notmatch '(?i)\s/(q|quiet)') { $cmdLine += " /qn /norestart" }
    if ($cmdLine -match '(?i)\s/I\{') { $cmdLine = ($cmdLine -replace '(?i)\s/I\{', ' /X{') }
  } else {
    # Non-MSI: try adding common silent flags if they are not present.
    if ($cmdLine -notmatch '(?i)--quiet|/quiet|/s|/silent') { $cmdLine += " --quiet" }
  }

  Write-Log "Uninstalling Docker Desktop via registry uninstall string (silent best-effort)..."

  try {
    # Execute through cmd.exe to honor quoted command lines and embedded args.
    $rc = Invoke-ProcessWithTimeout -FilePath "cmd.exe" -ArgumentList @("/c", $cmdLine) -TimeoutSeconds $UninstallTimeoutSeconds
    if ($rc -eq 0) { return $true }
    Write-Log "WARN: registry uninstall returned exit code $rc." "WARN"
    return $false
  } catch {
    Write-Log "WARN: registry uninstall failed: $($_.Exception.Message)" "WARN"
    return $false
  }
}

function Remove-DockerDataBestEffort {
  Write-Log "Removing leftover Docker Desktop data directories (best-effort)..."

  $targets = New-Object System.Collections.Generic.List[string]
  $targets.Add((Join-Path $env:APPDATA "Docker")) | Out-Null
  $targets.Add((Join-Path $env:LOCALAPPDATA "Docker")) | Out-Null
  $targets.Add((Join-Path $env:LOCALAPPDATA "Docker Desktop")) | Out-Null
  $targets.Add((Join-Path $env:LOCALAPPDATA "DockerDesktop")) | Out-Null
  $targets.Add((Join-Path $env:PROGRAMDATA "Docker")) | Out-Null
  $targets.Add((Join-Path $env:PROGRAMDATA "DockerDesktop")) | Out-Null
  $targets.Add((Join-Path $env:PROGRAMDATA "Docker Desktop")) | Out-Null
  $targets.Add((Join-Path $env:USERPROFILE ".docker")) | Out-Null
  $targets.Add((Join-Path $env:ProgramFiles "Docker")) | Out-Null
  $targets.Add((Join-Path ${env:ProgramFiles(x86)} "Docker")) | Out-Null

  foreach ($t in @($targets)) { Remove-PathBestEffort $t }

  if ($AllUsers) {
    try {
      $profiles = Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue
      foreach ($p in @($profiles)) {
        $roam = Join-Path $p.FullName "AppData\Roaming\Docker"
        $local = Join-Path $p.FullName "AppData\Local\Docker"
        $local2 = Join-Path $p.FullName "AppData\Local\Docker Desktop"
        $homeDocker = Join-Path $p.FullName ".docker"
        Remove-PathBestEffort $roam
        Remove-PathBestEffort $local
        Remove-PathBestEffort $local2
        Remove-PathBestEffort $homeDocker
      }
    } catch {}
  }
}

function Disable-WSLFeaturesBestEffort {
  if (-not $DisableWSLFeatures) { return }

  $other = @()
  try {
    $distros = Get-WSLDistros -All
    $other = @($distros | Where-Object { $_ -and $_ -notin @($Distro,"docker-desktop","docker-desktop-data") })
  } catch {}

  if ($other.Count -gt 0 -and -not $ForceDisableWSLFeatures) {
    Write-Log ("Other WSL distros exist ({0}). Skipping feature disable. Re-run with -ForceDisableWSLFeatures to force." -f ($other -join ", ")) "WARN"
    Add-Summary "WSL features: kept enabled (other distros exist)"
    return
  }

  foreach ($f in @("VirtualMachinePlatform","Microsoft-Windows-Subsystem-Linux")) {
    try {
      $state = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue
      if ($state -and $state.State -eq "Disabled") {
        Write-Log "Windows feature already disabled: $f"
        continue
      }

      Write-Log "Disabling Windows feature (NoRestart): $f"
      $r = Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction SilentlyContinue
      if ($r -and $r.RestartNeeded) { $script:RebootRecommended = $true }
    } catch {}
  }

  Add-Summary "WSL features: disable attempted (NoRestart)"
}

if ($env:OS -notlike "*Windows*") {
  throw "This script is intended for Windows 11."
}

Assert-Admin

Write-Log "Unprovisioning local dev environment (WSL2 + Ubuntu + Docker Desktop) - unattended mode"
Write-Log ("Target distro: {0}" -f $Distro)
Write-Log ("AllUsers data removal: {0}" -f ($AllUsers.IsPresent))
Write-Log ("Disable WSL features: {0} (force={1})" -f ($DisableWSLFeatures.IsPresent), ($ForceDisableWSLFeatures.IsPresent))

if (Test-PendingReboot) {
  Write-Log "NOTE: a reboot is already pending before cleanup. This script will not reboot automatically." "WARN"
  $script:RebootRecommended = $true
}

# 1) Stop Docker/WSL activity (best-effort, idempotent).
Write-Log "Stopping Docker Desktop processes and services (best-effort)..."
Stop-ProcessBestEffort @("Docker Desktop","com.docker.backend","com.docker.proxy","vpnkit","dockerd")
Stop-ServiceBestEffort @("com.docker.service")
Wsl-ShutdownBestEffort
Add-Summary "Stopped Docker processes/services + wsl --shutdown (best-effort)"

# 2) Remove WSL distros (Ubuntu + Docker Desktop integration distros).
$removedDistro = $false
if (Wsl-UnregisterBestEffort "docker-desktop") { Add-Summary "WSL distro unregistered: docker-desktop"; $removedDistro = $true }
if (Wsl-UnregisterBestEffort "docker-desktop-data") { Add-Summary "WSL distro unregistered: docker-desktop-data"; $removedDistro = $true }
if (Wsl-UnregisterBestEffort $Distro) { Add-Summary "WSL distro unregistered: $Distro"; $removedDistro = $true }
if (-not $removedDistro) { Add-Summary "WSL distros: nothing to unregister (already absent)" }

# 3) Uninstall Docker Desktop (winget preferred; registry fallback).
$dockerUninstalled = $false
if (Uninstall-DockerDesktopViaWinget) {
  $dockerUninstalled = $true
  Add-Summary "Docker Desktop uninstalled via winget"
} elseif (Uninstall-DockerDesktopViaRegistry) {
  $dockerUninstalled = $true
  Add-Summary "Docker Desktop uninstalled via registry uninstall string (best-effort silent)"
} else {
  Add-Summary "Docker Desktop uninstall: not found or uninstall failed (best-effort)"
}

# 4) Remove leftover Docker data directories (best-effort).
Remove-DockerDataBestEffort
Add-Summary "Removed Docker Desktop data directories (best-effort)"

# 5) Best-effort cleanup: if the service still exists after uninstall, try deleting it.
try {
  $svc = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
  if ($svc) {
    Write-Log "Docker service still present after uninstall. Attempting to delete com.docker.service (best-effort)..." "WARN"
    try { Stop-Service -Name "com.docker.service" -Force -ErrorAction SilentlyContinue } catch {}
    try { sc.exe delete "com.docker.service" | Out-Null } catch {}
    Add-Summary "Removed com.docker.service (best-effort)"
  }
} catch {}

# 6) Optionally disable WSL Windows optional features (NoRestart).
Disable-WSLFeaturesBestEffort

Write-Log ""
Write-Log "Final summary:"
foreach ($s in @($script:Summary)) {
  Write-Host ("- {0}" -f $s)
}

Write-Log ""
if ($script:RebootRecommended) {
  Write-Log "Reboot recommended: YES (script did not reboot automatically)" "WARN"
  exit 3010
} else {
  Write-Log "Reboot recommended: NO"
}
