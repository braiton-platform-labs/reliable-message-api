Param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateSet("install","uninstall","status")]
  [string]$Command,

  # WSL distro used for running repo commands (make/bootstrap/dev).
  [string]$Distro = "Ubuntu-22.04",

  # kind cluster used by the Makefile defaults.
  [string]$KindClusterName = "bpl-dev",

  # If a Windows reboot is required (enabling/disabling optional features), reboot automatically.
  [switch]$AutoReboot,

  # Skip applying/removing Windows hosts file entries (api.local.dev / kong.local.dev).
  [switch]$SkipHosts,

  # Skip installing/uninstalling Docker Desktop via winget.
  [switch]$SkipDockerDesktop,

  # Skip installing Python via winget (Windows host). Installing Python avoids the Microsoft Store "python.exe" alias prompt.
  [switch]$SkipPython,

  # Skip enabling/disabling WSL2 Windows optional features and installing/unregistering the WSL distro.
  [switch]$SkipWSL2,

  # Skip running repo-level commands inside WSL (bootstrap.sh / make dev / kind cleanup).
  [switch]$SkipRepo,

  # For uninstall: also remove OS-level deps (Docker Desktop, WSL distros, optional features) using the manifest.
  [switch]$Purge,

  # For uninstall: remove OS-level deps even if they were not installed by this script (dangerous).
  [switch]$PurgeAll,

  # For uninstall: run `docker system prune -af` (very destructive).
  [switch]$NukeDocker
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$StateDir = Join-Path $PSScriptRoot ".state"
$StateFile = Join-Path $StateDir "dev-env.json"

$BeginHostsMarker = "# BEGIN reliable-message-api dev"

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-SelfArgumentList {
  $forward = @()

  # Preserve the script's bound parameters when re-launching elevated.
  if ($script:PSBoundParameters) {
    foreach ($kv in $script:PSBoundParameters.GetEnumerator()) {
      $name = $kv.Key
      $val = $kv.Value

      if ($val -is [System.Management.Automation.SwitchParameter]) {
        if ($val.IsPresent) { $forward += "-$name" }
        continue
      }

      $forward += "-$name"
      $forward += [string]$val
    }
  }

  # Preserve any extra/unbound args passed to the script (rare, but safe).
  if ($script:args -and $script:args.Count -gt 0) {
    $forward += $script:args
  }

  return $forward
}

function Ensure-Admin {
  if (Test-IsAdmin) { return }

  Write-Host "Re-launching elevated (UAC prompt expected)..." -ForegroundColor Yellow

  $exe = (Get-Process -Id $PID).Path
  if (-not $exe) { $exe = "powershell.exe" }

  $argsList = @("-NoProfile","-ExecutionPolicy","Bypass","-File",$PSCommandPath) + (Get-SelfArgumentList)
  $p = Start-Process -FilePath $exe -Verb RunAs -ArgumentList $argsList -PassThru -Wait
  # Propagate exit code from elevated run so callers (install-all.cmd) don't think we're done early.
  exit $p.ExitCode
}

function Refresh-Session {
  # Best-effort: pull the latest PATH from registry so newly installed tools are visible in this process.
  $machine = [Environment]::GetEnvironmentVariable("Path","Machine")
  $user = [Environment]::GetEnvironmentVariable("Path","User")

  $repoBin = Join-Path $RepoRoot "bin"
  $wingetUserLinks = Join-Path $env:LOCALAPPDATA "Microsoft\\WinGet\\Links"
  $wingetMachineLinks = Join-Path $Env:ProgramFiles "WinGet\\Links"

  $parts = @(
    $repoBin,
    $wingetUserLinks,
    $wingetMachineLinks,
    $user,
    $machine
  ) | Where-Object { $_ -and $_.Trim() -ne "" }

  $env:PATH = ($parts -join ";")

  # Warm up command discovery for common tools.
  try { Get-Command -Name wsl,winget,docker,kubectl,kind,mkcert -ErrorAction SilentlyContinue | Out-Null } catch {}
}

function Refresh-ExplorerBestEffort([string]$reason = "") {
  try {
    if (-not (Get-Process -Name "explorer" -ErrorAction SilentlyContinue)) { return }

    $msg = "Refreshing explorer.exe"
    if ($reason) { $msg += " ($reason)" }
    Write-Host "$msg..."

    # Broadcast environment/settings change to Explorer + other processes.
    if (-not ("RmaWin32" -as [type])) {
      Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RmaWin32 {
  [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
  public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
}
'@ | Out-Null
    }

    [UIntPtr]$result = [UIntPtr]::Zero
    [void][RmaWin32]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, "Environment", 0x2, 5000, [ref]$result)

    # Refresh open Explorer windows (best-effort).
    try {
      $shell = New-Object -ComObject Shell.Application
      foreach ($w in @($shell.Windows())) {
        try { $w.Refresh() } catch {}
      }
    } catch {}
  } catch {
    # Best-effort only.
  }
}

function Get-RealPythonVersion {
  $cmds = Get-Command "python" -All -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandType -eq "Application" } |
    Where-Object { $_.Source -and ($_.Source -notmatch '\\Microsoft\\WindowsApps\\python(3)?\\.exe$') }

  foreach ($c in @($cmds)) {
    try {
      $out = & $c.Source -c "import sys; print('.'.join(map(str, sys.version_info[:3])))" 2>$null
      if ($LASTEXITCODE -ne 0) { continue }
      $text = ($out | Select-Object -First 1).ToString().Trim()
      if ($text -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
    } catch {}
  }

  return $null
}

function Read-State {
  if (-not (Test-Path $StateFile)) { return $null }
  try {
    return (Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json)
  } catch {
    Write-Host "WARN: failed to parse state file; ignoring: $StateFile" -ForegroundColor Yellow
    return $null
  }
}

function Write-State($state) {
  New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
  $json = $state | ConvertTo-Json -Depth 10
  Set-Content -LiteralPath $StateFile -Value $json -Encoding UTF8
}

function New-State {
  return [ordered]@{
    version = 1
    createdAt = (Get-Date).ToString("o")
    windows = [ordered]@{
      enabledFeatures = (New-Object System.Collections.Generic.List[string])
      installedWingetIds = (New-Object System.Collections.Generic.List[string])
      installedDistros = (New-Object System.Collections.Generic.List[string])
      addedWindowsHostsBlock = $false
    }
    repo = [ordered]@{
      createdPaths = (New-Object System.Collections.Generic.List[string])
      kindClusters = (New-Object System.Collections.Generic.List[string])
    }
  }
}

function Ensure-StringList($value) {
  $list = New-Object System.Collections.Generic.List[string]
  if ($null -eq $value) { return $list }
  foreach ($v in @($value)) {
    if ($null -eq $v) { continue }
    $s = $v.ToString().Trim()
    if ($s) { $list.Add($s) | Out-Null }
  }
  return $list
}

function Normalize-State($state) {
  if (-not $state) { return $null }
  if (-not $state.windows) { $state.windows = [ordered]@{} }
  if (-not $state.repo) { $state.repo = [ordered]@{} }

  $state.windows.enabledFeatures = Ensure-StringList $state.windows.enabledFeatures
  $state.windows.installedWingetIds = Ensure-StringList $state.windows.installedWingetIds
  $state.windows.installedDistros = Ensure-StringList $state.windows.installedDistros
  if ($null -eq $state.windows.addedWindowsHostsBlock) { $state.windows.addedWindowsHostsBlock = $false }

  $state.repo.createdPaths = Ensure-StringList $state.repo.createdPaths
  $state.repo.kindClusters = Ensure-StringList $state.repo.kindClusters

  return $state
}

function Get-OptionalFeatureState([string]$featureName) {
  try {
    $f = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
    if ($f) { return $f.State }
  } catch {}
  return $null
}

function Get-WSLDistros {
  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return @() }
  try {
    $raw = & wsl.exe -l -q 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return @() }
    return @(
      $raw |
        ForEach-Object { ($_ -replace "\u0000", "").Trim() } |
        Where-Object { $_ -and $_ -ne "" }
    )
  } catch {
    return @()
  }
}

function Test-WindowsHostsBlockPresent {
  $hosts = Join-Path $Env:SystemRoot "System32\\drivers\\etc\\hosts"
  if (-not (Test-Path -LiteralPath $hosts)) { return $false }
  try {
    $text = Get-Content -LiteralPath $hosts -ErrorAction Stop
    foreach ($line in $text) {
      if ($line -eq $BeginHostsMarker) { return $true }
    }
  } catch {}
  return $false
}

function Test-DockerDesktopInstalled {
  $exe = Join-Path $Env:ProgramFiles "Docker\\Docker\\Docker Desktop.exe"
  if (Test-Path $exe) { return $true }

  try {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      $out = winget list -e --id Docker.DockerDesktop 2>$null
      return ($LASTEXITCODE -eq 0 -and ($out | Select-String -Pattern "Docker\\.DockerDesktop" -SimpleMatch))
    }
  } catch {}

  return $false
}

function Resolve-DockerCli {
  $cmd = Get-Command docker -ErrorAction SilentlyContinue
  if ($cmd -and $cmd.CommandType -eq "Application") { return $cmd.Source }

  $fallback = Join-Path $Env:ProgramFiles "Docker\\Docker\\resources\\bin\\docker.exe"
  if (Test-Path $fallback) { return $fallback }
  return $null
}

function Stop-DockerDesktop {
  try {
    $svc = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
      Write-Host "Stopping Docker service..."
      Stop-Service -Name "com.docker.service" -Force -ErrorAction SilentlyContinue
    }
  } catch {}

  # Best-effort process stop (some installs run without the service).
  try { Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
  try { Get-Process -Name "com.docker.backend" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
  try { Get-Process -Name "com.docker.vpnkit" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
}

function Invoke-WingetUninstall([string]$id, [int]$retries = 3) {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "winget not found; cannot uninstall $id" -ForegroundColor Yellow
    return $false
  }

  # If it's already not installed, consider it a success.
  try {
    $listOut = winget list -e --id $id 2>$null
    $listText = ($listOut | Out-String)
    if ($LASTEXITCODE -ne 0 -and $listText -match "No installed package found") {
      Write-Host "winget: $id is not installed (skip)."
      return $true
    }
    if ($listText -match "No installed package found") {
      Write-Host "winget: $id is not installed (skip)."
      return $true
    }
  } catch {}

  for ($i = 1; $i -le $retries; $i++) {
    Write-Host "winget uninstall (attempt $i/$retries): $id"
    $out = winget uninstall -e --id $id --silent --force --accept-source-agreements --disable-interactivity 2>&1
    if ($LASTEXITCODE -eq 0) { return $true }
    $text = ($out | Out-String)
    if ($text -match "No installed package found") {
      Write-Host "winget: $id is not installed (skip)."
      return $true
    }
    Write-Host "winget uninstall failed ($i/$retries). Retrying..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
  }

  Write-Host "winget uninstall failed after $retries attempts." -ForegroundColor Red
  return $false
}

function Disable-OptionalFeature([string]$featureName) {
  $f = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
  if ($f -and $f.State -eq "Disabled") { return $false }
  Write-Host "Disabling Windows feature: $featureName"
  $r = Disable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction SilentlyContinue
  return ($r -and $r.RestartNeeded -eq $true)
}

function Invoke-WslHere([string]$cmd) {
  $scriptPath = Join-Path $PSScriptRoot "wsl-here.ps1"
  if (-not (Test-Path $scriptPath)) { throw "wsl-here.ps1 not found at $scriptPath" }
  # Run in a separate PowerShell process because wsl-here.ps1 uses `exit` (CLI-friendly),
  # which would otherwise terminate this script if invoked in-process.
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath -Distro $Distro -Command $cmd
  return $LASTEXITCODE
}

function Add-Unique([System.Collections.IList]$list, $value) {
  if ($null -eq $value) { return }
  if ($value -is [array]) {
    foreach ($v in $value) { Add-Unique $list $v }
    return
  }
  if ($list -notcontains $value) { $list.Add($value) | Out-Null }
}

function Remove-PathBestEffort([string]$path) {
  if (-not $path) { return }
  $full = Join-Path $RepoRoot $path
  if (-not (Test-Path -LiteralPath $full)) { return }
  try {
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
    Write-Host "Removed $path"
  } catch {
    Write-Host "WARN: failed to remove ${path}: $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

function Remove-KindClusterViaDockerLabel([string]$cluster) {
  $docker = Resolve-DockerCli
  if (-not $docker) { return $false }
  try {
    $ok = $true

    $ids = & $docker @("ps","-a","-q","--filter","label=io.x-k8s.kind.cluster=$cluster") 2>$null
    $idList = @($ids | Where-Object { $_ -and $_.Trim() -ne "" })
    if ($idList.Count -gt 0) {
      Write-Host "Deleting kind containers via docker label (cluster=$cluster)..."
      & $docker @("rm","-f") + $idList | Out-Null
      if ($LASTEXITCODE -ne 0) { $ok = $false }
    }

    $nets = & $docker @("network","ls","-q","--filter","label=io.x-k8s.kind.cluster=$cluster") 2>$null
    $netList = @($nets | Where-Object { $_ -and $_.Trim() -ne "" })
    if ($netList.Count -gt 0) {
      Write-Host "Deleting kind networks via docker label (cluster=$cluster)..."
      & $docker @("network","rm") + $netList | Out-Null
      if ($LASTEXITCODE -ne 0) { $ok = $false }
    }

    $vols = & $docker @("volume","ls","-q","--filter","label=io.x-k8s.kind.cluster=$cluster") 2>$null
    $volList = @($vols | Where-Object { $_ -and $_.Trim() -ne "" })
    if ($volList.Count -gt 0) {
      Write-Host "Deleting kind volumes via docker label (cluster=$cluster)..."
      & $docker @("volume","rm","-f") + $volList | Out-Null
      if ($LASTEXITCODE -ne 0) { $ok = $false }
    }

    return $ok
  } catch {
    return $false
  }
}

function Cmd-Status {
  Refresh-Session
  Write-Host "State file: $StateFile"
  if (Test-Path $StateFile) { Write-Host "state: present" } else { Write-Host "state: missing" }
  Write-Host ""

  if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    Write-Host "WSL status:"
    try { wsl.exe --status } catch { Write-Host "WARN: wsl --status failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "WSL distros:"
    try { wsl.exe -l -v } catch { Write-Host "WARN: wsl -l -v failed: $($_.Exception.Message)" -ForegroundColor Yellow }
  } else {
    Write-Host "WSL: not found"
  }
  Write-Host ""

  Write-Host ("Docker Desktop installed: {0}" -f (Test-DockerDesktopInstalled))
  $docker = Resolve-DockerCli
  if ($docker) {
    try {
      & $docker @("info") | Out-Null
      Write-Host ("docker daemon reachable: {0}" -f ($LASTEXITCODE -eq 0))
    } catch {
      Write-Host "docker daemon reachable: false"
    }
  } else {
    Write-Host "docker CLI: not found"
  }

  Write-Host ""
  Write-Host ("Windows hosts block present: {0}" -f (Test-WindowsHostsBlockPresent))
  $py = Get-RealPythonVersion
  if ($py) { Write-Host ("Python detected: {0}" -f $py) } else { Write-Host "Python detected: not found" }
  Write-Host ""
  Write-Host "Next steps (if missing):"
  if ((Get-WSLDistros).Count -eq 0) { Write-Host "- Install Ubuntu for WSL: .\\hack\\install-wsl2.cmd" }
  if (-not (Test-DockerDesktopInstalled)) { Write-Host "- Install Docker Desktop: .\\hack\\install-docker.cmd" }
  if (-not (Test-WindowsHostsBlockPresent)) { Write-Host "- Apply Windows hosts: .\\hack\\dev-hosts.ps1 apply (run as Admin) or: .\\hack\\dev-env.cmd install" }
}

function Cmd-Install {
  if (-not $SkipWSL2 -or -not $SkipHosts -or -not $SkipDockerDesktop) {
    Ensure-Admin
  }
  Refresh-Session

  $state = Read-State
  if (-not $state) { $state = New-State } else { $state = Normalize-State $state }

  $preFeatures = [ordered]@{
    "Microsoft-Windows-Subsystem-Linux" = (Get-OptionalFeatureState "Microsoft-Windows-Subsystem-Linux")
    "VirtualMachinePlatform" = (Get-OptionalFeatureState "VirtualMachinePlatform")
  }
  $preDistros = Get-WSLDistros
  $preDockerDesktop = Test-DockerDesktopInstalled
  $preHosts = Test-WindowsHostsBlockPresent

  $preEnv = Test-Path (Join-Path $RepoRoot ".env")
  $preBin = Test-Path (Join-Path $RepoRoot "bin")
  $preCerts = Test-Path (Join-Path $RepoRoot "hack\\certs")

  if (-not $SkipWSL2) {
    Write-Host ""
    Write-Host "==> Step: WSL2 (features + distro)"
    $wslInstaller = Join-Path $PSScriptRoot "install-wsl2.ps1"
    $args = @()
    if ($AutoReboot) { $args += "-AutoReboot" }
    $args += @("-Distro", $Distro)
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $wslInstaller @args
    $rc = $LASTEXITCODE
    Refresh-Session
    $needsReboot = ($rc -eq 3010)
    if ($rc -ne 0 -and -not $needsReboot) { throw "install-wsl2 failed (exit code $rc)" }

    $postFeatures = [ordered]@{
      "Microsoft-Windows-Subsystem-Linux" = (Get-OptionalFeatureState "Microsoft-Windows-Subsystem-Linux")
      "VirtualMachinePlatform" = (Get-OptionalFeatureState "VirtualMachinePlatform")
    }
    foreach ($k in $postFeatures.Keys) {
      if ($preFeatures[$k] -ne "Enabled" -and $postFeatures[$k] -eq "Enabled") {
        Add-Unique $state.windows.enabledFeatures $k
      }
    }
    $postDistros = Get-WSLDistros
    foreach ($d in $postDistros) {
      if ($preDistros -notcontains $d) { Add-Unique $state.windows.installedDistros $d }
    }

    # Hard requirement for the rest of the flow: we need the requested distro to exist.
    if ((Get-WSLDistros) -notcontains $Distro) {
      throw "WSL distro '$Distro' is not installed. Run: .\\hack\\install-wsl2.cmd -Distro $Distro, then run once: wsl -d $Distro"
    }

    if ($needsReboot) {
      Write-State $state
      exit 3010
    }
  } else {
    Write-Host "Skipping WSL2 setup (SkipWSL2=1)."
  }

  if (-not $SkipDockerDesktop) {
    Write-Host ""
    Write-Host "==> Step: Docker Desktop"
    $dockerInstaller = Join-Path $PSScriptRoot "install-docker.ps1"
    $args = @("-SkipWSL")
    if ($AutoReboot) { $args += "-AutoReboot" }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $dockerInstaller @args
    $rc = $LASTEXITCODE
    $needsReboot = ($rc -eq 3010)
    if ($rc -ne 0 -and -not $needsReboot) { throw "install-docker failed (exit code $rc)" }
    Refresh-Session

    $postDockerDesktop = Test-DockerDesktopInstalled
    if (-not $preDockerDesktop -and $postDockerDesktop) {
      Add-Unique $state.windows.installedWingetIds "Docker.DockerDesktop"
    }

    if (-not (Test-DockerDesktopInstalled)) {
      throw "Docker Desktop is not installed. Run: .\\hack\\install-docker.cmd"
    }

    if ($needsReboot) {
      Write-State $state
      exit 3010
    }
  } else {
    Write-Host "Skipping Docker Desktop step (SkipDockerDesktop=1)."
  }

  if (-not $SkipPython) {
    Write-Host ""
    Write-Host "==> Step: Python (Windows)"
    $pythonInstaller = Join-Path $PSScriptRoot "install-python.ps1"

    $json = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $pythonInstaller | Out-String).Trim()
    $rc = $LASTEXITCODE
    Refresh-Session
    if ($rc -ne 0) { throw "install-python failed (exit code $rc)" }

    if ($json) {
      try {
        $res = $json | ConvertFrom-Json
        if ($res -and $res.installed -and $res.wingetId) {
          Add-Unique $state.windows.installedWingetIds ([string]$res.wingetId)
        }
      } catch {
        Write-Host "WARN: failed to parse install-python output; skipping state update." -ForegroundColor Yellow
      }
    }
  } else {
    Write-Host "Skipping Python step (SkipPython=1)."
  }

  if (-not $SkipHosts) {
    Write-Host ""
    Write-Host "==> Step: Windows hosts (api.local.dev / kong.local.dev)"
    $hostsScript = Join-Path $PSScriptRoot "dev-hosts.ps1"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $hostsScript apply
    Refresh-Session
    $postHosts = Test-WindowsHostsBlockPresent
    if (-not $preHosts -and $postHosts) {
      $state.windows.addedWindowsHostsBlock = $true
    }
  } else {
    Write-Host "Skipping Windows hosts step (SkipHosts=1)."
  }

  if (-not $SkipRepo) {
    Write-Host ""
    Write-Host "==> Step: Repo bootstrap + dev (WSL)"
    # Avoid assuming `make` exists in a fresh WSL distro: bootstrap.sh can install it.
    $bootstrapEnv = "BOOTSTRAP_INSTALL_MODE=local BOOTSTRAP_ENFORCE_GLOBAL_BIN=0 BOOTSTRAP_AUTO_CONFIRM=1 BOOTSTRAP_SYSCTL_PERSIST=0"
    $rc = Invoke-WslHere "$bootstrapEnv bash ./hack/bootstrap.sh"
    if ($rc -ne 0) { throw "bootstrap.sh failed (exit code $rc)" }

    $rc = Invoke-WslHere "make dev"
    if ($rc -ne 0) { throw "make dev failed (exit code $rc)" }

    # Best-effort validation: this exercises Kong + the API through port-forwarded proxy.
    try {
      $rc = Invoke-WslHere "make dev-verify"
      if ($rc -ne 0) { Write-Host "WARN: make dev-verify failed (exit code $rc). Check pods/logs with: make dev-status / make dev-logs" -ForegroundColor Yellow }
    } catch {
      Write-Host "WARN: make dev-verify failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Record repo artifacts created by this run.
    if (-not $preEnv -and (Test-Path (Join-Path $RepoRoot ".env"))) { Add-Unique $state.repo.createdPaths ".env" }
    if (-not $preBin -and (Test-Path (Join-Path $RepoRoot "bin"))) { Add-Unique $state.repo.createdPaths "bin" }
    if (-not $preCerts -and (Test-Path (Join-Path $RepoRoot "hack\\certs"))) { Add-Unique $state.repo.createdPaths "hack/certs" }
    $ipWhitelist = Join-Path $RepoRoot "k8s\\overlays\\dev\\kong\\ip-whitelist.yaml"
    if (Test-Path $ipWhitelist) { Add-Unique $state.repo.createdPaths "k8s/overlays/dev/kong/ip-whitelist.yaml" }
    $kongUser = Join-Path $RepoRoot ".git\\dev-kong-user"
    if (Test-Path $kongUser) { Add-Unique $state.repo.createdPaths ".git/dev-kong-user" }

    # Record cluster if it exists.
    try {
      $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "wsl-here.ps1") -Distro $Distro -Command "kind get clusters 2>/dev/null || true" 2>$null
      if ($out) {
        foreach ($line in $out) {
          $c = $line.ToString().Trim()
          if ($c) { Add-Unique $state.repo.kindClusters $c }
        }
      }
    } catch {}
  } else {
    Write-Host "Skipping repo step (SkipRepo=1)."
  }

  Write-State $state
  Write-Host ""
  Write-Host "dev-env install completed."
  Write-Host "State written: $StateFile"
}

function Cmd-Uninstall {
  # Purge implies OS-level changes which generally require elevation.
  if ($Purge -or $PurgeAll -or -not $SkipHosts -or -not $SkipDockerDesktop -or -not $SkipWSL2) {
    Ensure-Admin
  }
  Refresh-Session

  $stateMissing = $false
  $rebootRequired = $false

  $state = Read-State
  if (-not $state) {
    $stateMissing = $true
    $state = New-State
    Write-Host "WARN: state file missing; uninstall will be best-effort." -ForegroundColor Yellow
  } else {
    $state = Normalize-State $state
  }

  Write-Host ""
  Write-Host "==> Step: Stop port-forward / delete kind cluster (best-effort)"
  if (-not $SkipRepo) {
    try { Invoke-WslHere "make dev-port-stop" | Out-Null } catch {}

    $clusters = @()
    if ($state.repo -and $state.repo.kindClusters -and $state.repo.kindClusters.Count -gt 0) {
      $clusters = @($state.repo.kindClusters)
    } else {
      # Fall back to default cluster name.
      $clusters = @($KindClusterName)
    }

    foreach ($c in $clusters) {
      if (-not $c) { continue }
      # Prefer kind (also cleans kubeconfig), but always fall back to docker label cleanup.
      $null = Invoke-WslHere "if command -v kind >/dev/null 2>&1; then kind delete cluster --name '$c' 2>/dev/null || true; fi"
      $null = Remove-KindClusterViaDockerLabel $c
    }

    # Safe-ish prune for project images.
    $docker = Resolve-DockerCli
    if ($docker) {
      try { & $docker @("builder","prune","-f") | Out-Null } catch {}
      try { & $docker @("image","prune","-f","--filter","label=project=reliable-message-api") | Out-Null } catch {}
      if ($NukeDocker) {
        Write-Host "Running docker system prune -af (NukeDocker=1)..."
        try { & $docker @("system","prune","-af") | Out-Null } catch {}
      }
    }
  } else {
    Write-Host "Skipping repo cleanup (SkipRepo=1)."
  }

  Refresh-Session

  if (-not $SkipHosts) {
    Write-Host ""
    Write-Host "==> Step: Remove Windows hosts block"
    $hostsScript = Join-Path $PSScriptRoot "dev-hosts.ps1"
    try { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $hostsScript remove } catch { Write-Host "WARN: hosts removal failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    Refresh-ExplorerBestEffort "hosts"
  } else {
    Write-Host "Skipping hosts removal (SkipHosts=1)."
  }

  Refresh-Session

  Write-Host ""
  Write-Host "==> Step: mkcert uninstall (best-effort)"
  $shouldUninstallMkcert = $PurgeAll
  if (-not $shouldUninstallMkcert) {
    $shouldUninstallMkcert = ($state.repo -and $state.repo.createdPaths -and ($state.repo.createdPaths -contains "hack/certs"))
  }
  if ($shouldUninstallMkcert) {
    if (-not $SkipRepo) {
      try {
        Invoke-WslHere "if command -v mkcert >/dev/null 2>&1; then mkcert -uninstall || true; fi" | Out-Null
      } catch {}
    }
    $mkcertExe = Join-Path $RepoRoot "bin\\mkcert.exe"
    if (Test-Path $mkcertExe) {
      try { & $mkcertExe -uninstall | Out-Null } catch {}
    }
    Refresh-ExplorerBestEffort "mkcert"
  } else {
    Write-Host "Skipping mkcert uninstall (not installed/used by this script). Use -PurgeAll to force." -ForegroundColor Yellow
  }

  Refresh-Session

  Write-Host ""
  Write-Host "==> Step: Remove repo-local artifacts"
  Remove-PathBestEffort ".env"
  Remove-PathBestEffort "hack/certs"
  Remove-PathBestEffort "bin"
  Remove-PathBestEffort "k8s/overlays/dev/kong/ip-whitelist.yaml"
  Remove-PathBestEffort ".git/dev-kong-user"
  Refresh-ExplorerBestEffort "repo artifacts"

  Refresh-Session

  if ($Purge -or $PurgeAll) {
    Write-Host ""
    Write-Host "==> Step: Purge OS-level deps"

    if (-not $SkipDockerDesktop) {
      $shouldUninstallDocker = $PurgeAll
      if (-not $shouldUninstallDocker) {
        $shouldUninstallDocker = ($state.windows -and $state.windows.installedWingetIds -and ($state.windows.installedWingetIds -contains "Docker.DockerDesktop"))
      }
      if ($shouldUninstallDocker) {
        Stop-DockerDesktop
        $ok = $false
        try { $ok = Invoke-WingetUninstall "Docker.DockerDesktop" } catch { $ok = $false }
        if ($ok) { Refresh-ExplorerBestEffort "Docker Desktop" }
      } else {
        Write-Host "Skipping Docker Desktop uninstall (not installed by this script). Use -PurgeAll to force."
      }
    } else {
      Write-Host "Skipping Docker Desktop uninstall (SkipDockerDesktop=1)."
    }

    Refresh-Session

    # Uninstall other winget packages installed by this script (best-effort).
    if ($state.windows -and $state.windows.installedWingetIds -and $state.windows.installedWingetIds.Count -gt 0) {
      $didWingetUninstall = $false
      foreach ($id in @($state.windows.installedWingetIds)) {
        if (-not $id) { continue }
        if ($id -eq "Docker.DockerDesktop") { continue }
        if ($SkipPython -and ($id -like "Python.Python.*")) { continue }
        Write-Host "Uninstalling winget package: $id"
        $didWingetUninstall = $true
        try { $null = Invoke-WingetUninstall $id } catch { Write-Host "WARN: failed to uninstall ${id}: $($_.Exception.Message)" -ForegroundColor Yellow }
      }
      if ($didWingetUninstall) { Refresh-ExplorerBestEffort "winget packages" }
    }

    if (-not $SkipWSL2) {
      Write-Host ""
      Write-Host "==> Step: Unregister WSL distros"
      try { wsl.exe --shutdown | Out-Null } catch {}

      $current = Get-WSLDistros
      $targets = New-Object System.Collections.Generic.List[string]

      if ($PurgeAll) {
        Add-Unique $targets $Distro
        Add-Unique $targets "docker-desktop"
        Add-Unique $targets "docker-desktop-data"
      } else {
        if ($state.windows -and $state.windows.installedDistros) {
          Add-Unique $targets @($state.windows.installedDistros)
        }
        # If we uninstall Docker Desktop, remove its WSL distros too (they are not OS-default).
        if (($state.windows -and $state.windows.installedWingetIds -and ($state.windows.installedWingetIds -contains "Docker.DockerDesktop")) -or $PurgeAll) {
          Add-Unique $targets "docker-desktop"
          Add-Unique $targets "docker-desktop-data"
        }
      }

      if (-not $PurgeAll -and $stateMissing -and $targets.Count -eq 0) {
        # If we don't have state, still remove the requested distro (best-effort) so `uninstall-all.cmd`
        # actually tears down the dev WSL environment.
        Add-Unique $targets $Distro
      }

      $unregisteredAny = $false
      foreach ($d in $targets) {
        if ($current -notcontains $d) { continue }
        Write-Host "Unregistering WSL distro: $d"
        try {
          # Ensure it isn't running (unregister can fail if the distro is active).
          try { wsl.exe --terminate $d | Out-Null } catch {}
          wsl.exe --unregister $d | Out-Null
          if ($LASTEXITCODE -eq 0) { $unregisteredAny = $true }
        } catch {
          Write-Host "WARN: failed to unregister ${d}: $($_.Exception.Message)" -ForegroundColor Yellow
        }
      }
      if ($unregisteredAny) { Refresh-ExplorerBestEffort "WSL distros" }

      Refresh-Session

      Write-Host ""
      Write-Host "==> Step: Disable WSL2 Windows optional features"
      $restartNeeded = $false
      $features = @()
      if ($PurgeAll) {
        $features = @("Microsoft-Windows-Subsystem-Linux","VirtualMachinePlatform")
      } else {
        if ($state.windows -and $state.windows.enabledFeatures) {
          $features = @($state.windows.enabledFeatures)
        }
      }

      if (-not $PurgeAll -and $stateMissing -and (-not $features -or $features.Count -eq 0)) {
        # With no state file we can't know what we enabled earlier. If the only remaining distros
        # are the dev distro (or none) and Docker Desktop distros, it's safe to disable the WSL features.
        $remaining = Get-WSLDistros
        $other = @($remaining | Where-Object { $_ -and $_ -ne $Distro -and $_ -ne "docker-desktop" -and $_ -ne "docker-desktop-data" })
        if ($other.Count -eq 0) {
          $features = @("Microsoft-Windows-Subsystem-Linux","VirtualMachinePlatform")
        } else {
          Write-Host "WARN: state missing and other WSL distros were found ($($other -join ', ')); not disabling WSL features. Re-run with -PurgeAll to force." -ForegroundColor Yellow
        }
      }

      $disabledAny = $false
      foreach ($f in $features) {
        if (-not $f) { continue }
        $disabledAny = $true
        $restartNeeded = (Disable-OptionalFeature $f) -or $restartNeeded
      }

      if ($restartNeeded) {
        $rebootRequired = $true
      }
      if ($disabledAny) { Refresh-ExplorerBestEffort "Windows features" }
    } else {
      Write-Host "Skipping WSL2 purge (SkipWSL2=1)."
    }
  } else {
    Write-Host ""
    Write-Host "OS-level purge not requested. Re-run with -Purge to remove Docker Desktop/WSL distros/features."
  }

  # Remove state file last.
  try {
    if (Test-Path $StateFile) { Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue }
    if (Test-Path $StateDir) {
      $left = Get-ChildItem -LiteralPath $StateDir -Force -ErrorAction SilentlyContinue
      if (-not $left) { Remove-Item -LiteralPath $StateDir -Force -ErrorAction SilentlyContinue }
    }
  } catch {}

  Write-Host ""
  Write-Host "dev-env uninstall completed."
  if ($rebootRequired) {
    Write-Host "Reinicio necessario: reinicie o computador para que as desinstalacoes tenham efeito completo." -ForegroundColor Yellow
  }
}

switch ($Command) {
  "status" { Cmd-Status; break }
  "install" { Cmd-Install; break }
  "uninstall" { Cmd-Uninstall; break }
}
