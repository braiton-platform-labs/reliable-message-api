Param(
  [switch]$AutoReboot,
  [switch]$SkipWSL,
  [switch]$SkipDockerDesktop,
  [switch]$NoStart,
  [int]$WaitSeconds = 180
)

$ErrorActionPreference = "Stop"

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

  Start-Process -FilePath $exe -Verb RunAs -ArgumentList $argsList | Out-Null
  exit 0
}

function Require-Winget {
  if (Get-Command winget -ErrorAction SilentlyContinue) { return }
  throw "winget not found. Install 'App Installer' (Microsoft.DesktopAppInstaller) and re-run."
}

function Warn-Virtualization {
  try {
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    if ($null -ne $cpu.VirtualizationFirmwareEnabled -and -not $cpu.VirtualizationFirmwareEnabled) {
      Write-Host "WARNING: VirtualizationFirmwareEnabled=False. Enable Intel VT-x/AMD-V in BIOS/UEFI or Docker/WSL2 will not work." -ForegroundColor Yellow
    }
  } catch {
    # Best-effort only.
  }
}

function Ensure-WindowsOptionalFeatureEnabled($featureName) {
  $f = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
  if ($f -and $f.State -eq "Enabled") { return $false }

  Write-Host "Enabling Windows feature: $featureName"
  $r = Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart
  return ($r.RestartNeeded -eq $true)
}

function Ensure-WSL2 {
  $restartNeeded = $false
  $restartNeeded = (Ensure-WindowsOptionalFeatureEnabled "Microsoft-Windows-Subsystem-Linux") -or $restartNeeded
  $restartNeeded = (Ensure-WindowsOptionalFeatureEnabled "VirtualMachinePlatform") -or $restartNeeded

  if ($restartNeeded) {
    Write-Host "WSL2 prerequisites enabled, but a reboot is required." -ForegroundColor Yellow
    if ($AutoReboot) {
      Write-Host "Rebooting now..."
      Restart-Computer -Force
      return
    }
    Write-Host "Reboot Windows, then re-run: .\\hack\\install-docker.cmd" -ForegroundColor Yellow
    exit 3010
  }

  if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    try { wsl.exe --update | Out-Null } catch {}
    try { wsl.exe --set-default-version 2 | Out-Null } catch {}
  } else {
    Write-Host "wsl.exe not found after enabling features. Reboot and re-run." -ForegroundColor Yellow
    exit 3010
  }
}

function Test-DockerDesktopInstalled {
  $exe = Join-Path $Env:ProgramFiles "Docker\\Docker\\Docker Desktop.exe"
  if (Test-Path $exe) { return $true }

  try {
    $out = winget list -e --id Docker.DockerDesktop 2>$null
    return ($LASTEXITCODE -eq 0 -and ($out | Select-String -Pattern "Docker\\.DockerDesktop" -SimpleMatch))
  } catch {
    return $false
  }
}

function Install-DockerDesktop {
  Write-Host "Installing Docker Desktop via winget..."
  $wingetArgs = @(
    "install",
    "-e",
    "--id", "Docker.DockerDesktop",
    "--accept-source-agreements",
    "--accept-package-agreements",
    "--silent",
    "--disable-interactivity"
  )

  & winget @wingetArgs
  if ($LASTEXITCODE -ne 0) {
    Write-Host "Silent install failed; retrying with interactivity..." -ForegroundColor Yellow
    & winget install -e --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements
  }
  if ($LASTEXITCODE -ne 0) { throw "winget install Docker.DockerDesktop failed (exit code $LASTEXITCODE)" }
}

function Add-DockerUsersGroup {
  try {
    $g = Get-LocalGroup -Name "docker-users" -ErrorAction SilentlyContinue
    if (-not $g) { return }
    Add-LocalGroupMember -Group "docker-users" -Member $env:USERNAME -ErrorAction SilentlyContinue
  } catch {
    # Best-effort only. Docker Desktop can still work without this for most users.
  }
}

function Start-DockerDesktop {
  $exe = Join-Path $Env:ProgramFiles "Docker\\Docker\\Docker Desktop.exe"
  if (-not (Test-Path $exe)) { return }
  Write-Host "Starting Docker Desktop..."
  Start-Process $exe | Out-Null
}

function Resolve-DockerCli {
  $cmd = Get-Command docker -ErrorAction SilentlyContinue
  if ($cmd -and $cmd.CommandType -eq "Application") { return $cmd.Source }

  $fallback = Join-Path $Env:ProgramFiles "Docker\\Docker\\resources\\bin\\docker.exe"
  if (Test-Path $fallback) { return $fallback }
  return $null
}

function Wait-DockerReady([int]$seconds) {
  $docker = Resolve-DockerCli
  if (-not $docker) { return $false }

  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    try {
      & $docker info | Out-Null
      if ($LASTEXITCODE -eq 0) { return $true }
    } catch {}
    Start-Sleep -Seconds 2
  }
  return $false
}

if ($env:OS -notlike "*Windows*") {
  throw "This script is intended for Windows."
}

Warn-Virtualization
Ensure-Admin
Require-Winget

if (-not $SkipWSL) {
  Ensure-WSL2
} else {
  Write-Host "Skipping WSL2 setup (SkipWSL=1)."
}

if (-not $SkipDockerDesktop) {
  if (-not (Test-DockerDesktopInstalled)) {
    Install-DockerDesktop
  } else {
    Write-Host "Docker Desktop already installed."
  }
} else {
  Write-Host "Skipping Docker Desktop installation (SkipDockerDesktop=1)."
}

Add-DockerUsersGroup

if (-not $NoStart) {
  Start-DockerDesktop
  if (Wait-DockerReady $WaitSeconds) {
    Write-Host "Docker is ready."
  } else {
    Write-Host "Docker did not become ready within ${WaitSeconds}s. Open Docker Desktop and wait for it to finish starting, then run: docker info" -ForegroundColor Yellow
  }
} else {
  Write-Host "Docker Desktop install completed (NoStart=1)."
}
