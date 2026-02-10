Param(
  [switch]$AutoReboot,
  [switch]$SkipWSL,
  [switch]$SkipDockerDesktop,
  [switch]$NoStart,
  [int]$WaitSeconds = 600,

  # Validate Docker connectivity from a WSL distro too (needed for kind/k8s workflows).
  [string]$Distro = "Ubuntu-22.04",
  [switch]$SkipWslValidation
)

$ErrorActionPreference = "Stop"

$script:RebootRecommended = $false

function Write-InstallLog([string]$message) {
  try {
    $dir = Join-Path $PSScriptRoot ".logs"
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $path = Join-Path $dir "install-docker.log"
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffK")
    Add-Content -LiteralPath $path -Value ("[{0}] {1}" -f $ts, $message) -Encoding UTF8
  } catch {
    # Best-effort only.
  }
}

function Refresh-ExplorerBestEffort([string]$reason = "") {
  try {
    if (-not (Get-Process -Name "explorer" -ErrorAction SilentlyContinue)) { return }

    $suffix = ""
    if ($reason) { $suffix = " ($reason)" }
    Write-Host ("ATTENTION: Refreshing Windows Explorer (explorer.exe) to apply changes{0}..." -f $suffix) -ForegroundColor Blue

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

function Invoke-WslUpdateBestEffort {
  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return }
  try {
    & wsl.exe --update --web-download | Out-Null
    if ($LASTEXITCODE -eq 0) { return }
    throw "wsl --update --web-download exit code $LASTEXITCODE"
  } catch {
    try { & wsl.exe --update | Out-Null } catch {}
  }
}

function Invoke-WslNoRebootActivationBestEffort([string]$reason = "") {
  try {
    $msg = "Best-effort: trying to activate WSL without reboot"
    if ($reason) { $msg += " ($reason)" }
    Write-Host $msg -ForegroundColor Yellow
    Write-InstallLog $msg

    try {
      if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
        & wsl.exe --shutdown | Out-Null
      }
    } catch {}

    try { Invoke-WslUpdateBestEffort } catch {}

    try {
      Get-Service LxssManager,vmcompute,WslService -ErrorAction SilentlyContinue |
        Restart-Service -Force -ErrorAction SilentlyContinue
    } catch {}

    Refresh-ExplorerBestEffort "wsl"
  } catch {
    # Best-effort only.
  }
}

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
        # Docker Desktop settings-store.json must be valid JSON. Some writers add a UTF-8 BOM (EF BB BF),
        # which can cause Docker's JSON unmarshaller to error with: "invalid character 'ï' ...".
        $raw = $raw -replace "^\uFEFF", ""
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

    # Avoid features that tend to trigger extra first-run surfaces/prompts.
    $data | Add-Member -NotePropertyName "AutoStart" -NotePropertyValue $false -Force
    $data | Add-Member -NotePropertyName "EnableDockerAI" -NotePropertyValue $false -Force

    # Write UTF-8 without BOM to avoid Docker Desktop JSON parse issues.
    $json = ($data | ConvertTo-Json -Depth 10)
    [IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))
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

function Get-BundledDockerDesktopInstallerZipPath {
  $zip = Join-Path $PSScriptRoot "Docker Desktop Installer.zip"
  if (Test-Path -LiteralPath $zip) { return $zip }
  return $null
}

function Expand-DockerDesktopInstallerZip([string]$zipPath) {
  $outDir = Join-Path $env:TEMP ("reliable-message-api.docker-desktop-installer." + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null

  try {
    Expand-Archive -LiteralPath $zipPath -DestinationPath $outDir -Force
  } catch {
    # Expand-Archive can fail on some environments; fall back to ZipFile extraction.
    try {
      Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue | Out-Null
      [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $outDir, $true)
    } catch {
      throw "Failed to extract bundled Docker Desktop installer zip: $zipPath"
    }
  }

  $preferred = Get-ChildItem -LiteralPath $outDir -Recurse -File -Filter "*.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq "Docker Desktop Installer.exe" } |
    Select-Object -First 1
  if ($preferred) { return [ordered]@{ exe = $preferred.FullName; dir = $outDir } }

  $any = Get-ChildItem -LiteralPath $outDir -Recurse -File -Filter "*.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if (-not $any) {
    throw "Bundled installer zip did not contain any .exe: $zipPath"
  }
  return [ordered]@{ exe = $any.FullName; dir = $outDir }
}

function Invoke-ProcessWithTimeout([string]$FilePath, [string[]]$ArgumentList, [int]$TimeoutSeconds = 1800) {
  $p = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru
  try {
    Wait-Process -Id $p.Id -Timeout $TimeoutSeconds -ErrorAction Stop
  } catch {
    try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
    throw "Process timed out after ${TimeoutSeconds}s: $FilePath"
  }
  try { $p.Refresh() } catch {}
  return $p.ExitCode
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
    $script:RebootRecommended = $true
    Write-Host "WSL2 prerequisites enabled, but a reboot is recommended for full effectiveness." -ForegroundColor Yellow
    Write-Host "Continuing without reboot (best-effort)..." -ForegroundColor Yellow
    if ($AutoReboot) {
      Write-Host "NOTE: -AutoReboot was requested, but automatic reboot is suppressed by this script." -ForegroundColor Yellow
    }
    Write-InstallLog "Reboot recommended after enabling Windows optional features (continuing without reboot)."

    # User-requested best-effort "no reboot" tactics.
    Invoke-WslNoRebootActivationBestEffort "after enabling optional features"
  }

  if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    try { Invoke-WslUpdateBestEffort } catch {}
    try { wsl.exe --set-default-version 2 | Out-Null } catch {}
  } else {
    Write-Host "wsl.exe not found after enabling features. Reboot and re-run." -ForegroundColor Yellow
    Write-InstallLog "wsl.exe not found; reboot required before continuing."
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
  $zip = Get-BundledDockerDesktopInstallerZipPath
  if ($zip) {
    Write-Host "Installing Docker Desktop from bundled installer zip: $zip" -ForegroundColor Yellow
    $res = $null
    try {
      $res = Expand-DockerDesktopInstallerZip $zip
      $exe = [string]$res.exe
      $dir = [string]$res.dir

      $args = @("install", "--quiet", "--accept-license", "--backend=wsl-2")
      $rc = Invoke-ProcessWithTimeout -FilePath $exe -ArgumentList $args -TimeoutSeconds 1800
      if ($rc -ne 0) { throw "Bundled Docker Desktop installer failed (exit code $rc)." }
      return
    } catch {
      $msg = "WARN: bundled Docker Desktop installer zip failed; falling back to winget/web install. Details: $($_.Exception.Message)"
      Write-Host $msg -ForegroundColor Yellow
      Write-InstallLog $msg
    } finally {
      try {
        if ($res -and $res.dir -and (Test-Path -LiteralPath $res.dir)) {
          Remove-Item -LiteralPath $res.dir -Recurse -Force -ErrorAction SilentlyContinue
        }
      } catch {}
    }
  }

  if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "Installing Docker Desktop via winget..." -ForegroundColor Yellow
    $wingetArgs = @(
      "install",
      "-e",
      "--id", "Docker.DockerDesktop",
      "--source", "winget",
      "--accept-source-agreements",
      "--accept-package-agreements",
      # Pre-accept the Docker Subscription Service Agreement so first-run doesn't block with the "Accept" dialog.
      "--override", "install --quiet --accept-license --backend=wsl-2",
      "--silent",
      "--disable-interactivity"
    )

    & winget @wingetArgs
    if ($LASTEXITCODE -ne 0) {
      throw "winget install Docker.DockerDesktop failed (exit code $LASTEXITCODE). Re-run after fixing winget issues (or install Docker Desktop manually)."
    }
    return
  }

  Write-Host "winget not found and bundled installer zip missing. Downloading Docker Desktop installer from official URL..." -ForegroundColor Yellow
  $tmp = Join-Path $env:TEMP "DockerDesktopInstaller.exe"
  $url = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
  Invoke-WebRequest -Uri $url -OutFile $tmp
  $rc = Invoke-ProcessWithTimeout -FilePath $tmp -ArgumentList @("install", "--quiet", "--accept-license", "--backend=wsl-2") -TimeoutSeconds 1800
  if ($rc -ne 0) { throw "Docker Desktop installer failed (exit code $rc)." }
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
  Write-Host "Starting Docker Desktop UI..."
  Start-Process $exe | Out-Null
}

function Start-DockerServiceBestEffort {
  try {
    $svc = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    if ($svc.Status -eq "Running") { return }
    Write-Host "Starting Docker service (com.docker.service)..."
    Start-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
  } catch {
    # Best-effort only.
  }
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

function Test-DockerReadyInWsl([string]$distroName) {
  if (-not $distroName) { return $false }
  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return $false }

  try {
    # Use bash -lc so docker is resolved via PATH in the distro.
    & wsl.exe @("-d", $distroName, "--exec", "bash", "-lc", "docker info >/dev/null 2>&1") | Out-Null
    return ($LASTEXITCODE -eq 0)
  } catch {
    return $false
  }
}

function Heal-DockerDesktopBestEffort([string]$reason = "") {
  try {
    $msg = "Best-effort: attempting to heal Docker Desktop/WSL integration without reboot"
    if ($reason) { $msg += " ($reason)" }
    Write-Host $msg -ForegroundColor Yellow
    Write-InstallLog $msg

    # Stop Docker Desktop processes first so WSL terminate doesn't get immediately re-spawned mid-heal.
    try {
      Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
    try {
      Get-Process -Name "com.docker.backend" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}

    # Restart the Windows service (often enough to re-provision docker-desktop distros).
    try {
      $svc = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
      if ($svc) {
        try { Stop-Service -Name "com.docker.service" -Force -ErrorAction SilentlyContinue } catch {}
        Start-Sleep -Seconds 2
        try { Start-Service -Name "com.docker.service" -ErrorAction SilentlyContinue } catch {}
      }
    } catch {}

    # Terminate Docker Desktop WSL distros (non-destructive; does not unregister).
    try { & wsl.exe --terminate docker-desktop 2>$null | Out-Null } catch {}
    try { & wsl.exe --terminate docker-desktop-data 2>$null | Out-Null } catch {}

    # Kick WSL stack (your requested "no reboot" tactics).
    try { Invoke-WslNoRebootActivationBestEffort "docker-desktop heal" } catch {}

    # Bring the service up again.
    try { Start-DockerServiceBestEffort } catch {}
  } catch {
    # Best-effort only.
  }
}

function Show-DockerDiagnostics {
  try {
    Write-Host ""
    Write-Host "Docker diagnostics:" -ForegroundColor Yellow

    try {
      $svc = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
      if ($svc) {
        Write-Host ("- Service com.docker.service: {0} (StartType={1})" -f $svc.Status, $svc.StartType)
      } else {
        Write-Host "- Service com.docker.service: not found"
      }
    } catch {}

    try {
      $p = Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($p) {
        Write-Host ("- Process Docker Desktop: running (pid={0})" -f $p.Id)
      } else {
        Write-Host "- Process Docker Desktop: not running"
      }
    } catch {}

    try {
      $p = Get-Process -Name "com.docker.backend" -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($p) {
        Write-Host ("- Process com.docker.backend: running (pid={0})" -f $p.Id)
      } else {
        Write-Host "- Process com.docker.backend: not running"
      }
    } catch {}

    try {
      $docker = Resolve-DockerCli
      if ($docker) {
        Write-Host ("- docker CLI: {0}" -f $docker)
        & $docker version 2>$null | Select-Object -First 30
      } else {
        Write-Host "- docker CLI: not found"
      }
    } catch {}

    Write-Host ""
    Write-Host "Common fix:" -ForegroundColor Yellow
    Write-Host "- Open Docker Desktop once and complete any first-run prompts (license/onboarding), then wait until it shows 'Running'." -ForegroundColor Yellow
    Write-Host "- If Docker is reachable on Windows but not inside WSL, a Windows reboot often fixes WSL integration state." -ForegroundColor Yellow
  } catch {
    # Best-effort only.
  }
}

if ($env:OS -notlike "*Windows*") {
  throw "This script is intended for Windows."
}

Warn-Virtualization
Ensure-Admin

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
  # Starting the service first makes Docker Desktop "come up" faster in many setups.
  Start-DockerServiceBestEffort

  # Prefer bringing Docker up without launching the UI (avoids login/onboarding screens).
  $headlessWait = [Math]::Min([Math]::Max([int]($WaitSeconds / 3), 30), 120)
  $remainingWait = [Math]::Max($WaitSeconds - $headlessWait, 30)

  Write-Host "Trying to bring Docker up without launching the UI (best-effort)..." -ForegroundColor Yellow
  if (Wait-DockerReady $headlessWait) {
    Write-Host "Docker is ready."
  } else {
    Start-DockerDesktop
    if (Wait-DockerReady $remainingWait) {
      Write-Host "Docker is ready."
    } else {
      Write-Host "ERROR: Docker did not become ready within ${WaitSeconds}s." -ForegroundColor Red
      Write-Host "Open Docker Desktop and wait for it to finish starting, then run: docker info" -ForegroundColor Yellow
      Write-InstallLog "Docker not ready after ${WaitSeconds}s; failing so dependent steps don't run."
      Show-DockerDiagnostics
      exit 1
    }
  }

  if (-not $SkipWslValidation -and -not $SkipWSL) {
    Write-Host ""
    Write-Host "Validating Docker from inside WSL distro '$Distro' (required for kind/k8s)..." -ForegroundColor Yellow
    if (Test-DockerReadyInWsl $Distro) {
      Write-Host "WSL docker validation: OK"
    } else {
      Write-Host "WARN: Docker is reachable on Windows, but not reachable inside WSL yet." -ForegroundColor Yellow
      Write-InstallLog "WSL docker validation failed for distro '$Distro'."

      Heal-DockerDesktopBestEffort "WSL docker validation failed"

      # Give it another chance after heal. Try headless first; then UI.
      if (-not (Wait-DockerReady 60)) {
        Start-DockerDesktop
        $null = Wait-DockerReady 120
      }

      if (Test-DockerReadyInWsl $Distro) {
        Write-Host "WSL docker validation: OK (after heal)"
      } else {
        Write-Host "ERROR: Docker still not reachable inside WSL after best-effort heal." -ForegroundColor Red
        Write-Host "Recommendation: reboot Windows to fully reset WSL integration, then re-run:" -ForegroundColor Yellow
        Write-Host "  powershell -ExecutionPolicy Bypass -File setup\\windows-11-wsl2-docker-desktop\\setup.ps1 install" -ForegroundColor Yellow
        Write-InstallLog "WSL docker validation still failing after heal; reboot recommended."
        Show-DockerDiagnostics
        exit 1
      }
    }
  } elseif ($SkipWslValidation) {
    Write-Host "Skipping WSL docker validation (SkipWslValidation=1)."
  }
} else {
  Write-Host "Docker Desktop install completed (NoStart=1)."
}

if ($script:RebootRecommended) {
  Write-Host ""
  Write-Host "WARNING: For best results, reboot Windows after this installation." -ForegroundColor Yellow
  Write-InstallLog "Reboot recommended for full effectiveness after Docker/WSL2 prerequisites."
}
