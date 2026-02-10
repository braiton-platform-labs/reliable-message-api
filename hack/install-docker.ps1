Param(
  [switch]$AutoReboot,
  [switch]$SkipWSL,
  [switch]$SkipDockerDesktop,
  [switch]$NoStart,
  [int]$WaitSeconds = 180
)

$ErrorActionPreference = "Stop"

function Ensure-DockerDesktopFirstRunIsNonInteractive {
  # Docker Desktop can block first-run with UI screens (license + sign-in/onboarding),
  # which breaks unattended setup. The installer supports `--accept-license` (handled via winget override),
  # and onboarding can be suppressed via the user's settings store.
  try {
    $dir = Join-Path $Env:APPDATA "Docker"
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $path = Join-Path $dir "settings-store.json"
    $data = New-Object psobject
    if (Test-Path $path) {
      try {
        $raw = Get-Content $path -Raw
        if ($raw) { $data = $raw | ConvertFrom-Json }
      } catch {
        # If the JSON is corrupt/unparseable, replace it with a minimal safe object.
        $bak = "$path.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        try { Copy-Item $path $bak -Force } catch {}
        $data = New-Object psobject
      }
    }

    # This matches what Docker Desktop writes after you click through the welcome flow.
    $data | Add-Member -NotePropertyName "DisplayedOnboarding" -NotePropertyValue $true -Force

    ($data | ConvertTo-Json -Depth 10) | Set-Content -Path $path -Encoding UTF8
  } catch {
    # Best-effort only.
  }
}

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
  exit $p.ExitCode
}

function Require-Winget {
  if (Get-Command winget -ErrorAction SilentlyContinue) { return }
  throw "winget not found. Install 'App Installer' (Microsoft.DesktopAppInstaller) and re-run."
}

function Warn-Virtualization {
  try {
    $cs = Get-CimInstance Win32_ComputerSystem | Select-Object -First 1 HypervisorPresent
    if ($cs -and $cs.HypervisorPresent) {
      # When a hypervisor is already running (e.g., Hyper-V/WSL2), some WMI CPU virtualization flags
      # can show up as "False" even though virtualization is working. Avoid false-positive warnings.
      return
    }

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
    "--source", "winget",
    "--accept-source-agreements",
    "--accept-package-agreements",
    # Pre-accept the Docker Subscription Service Agreement so first-run doesn't block with the "Accept" dialog.
    "--override", "install --quiet --accept-license",
    "--silent",
    "--disable-interactivity"
  )

  & winget @wingetArgs
  if ($LASTEXITCODE -ne 0) {
    throw "winget install Docker.DockerDesktop failed (exit code $LASTEXITCODE). Re-run after fixing winget issues (or install Docker Desktop manually)."
  }
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
Ensure-DockerDesktopFirstRunIsNonInteractive

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
