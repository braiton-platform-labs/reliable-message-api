Param(
  # Target WSL distro name. Kept configurable, but defaults to the requested Ubuntu 22.04.
  [string]$Distro = "Ubuntu-22.04",

  # Requested default Linux user.
  [string]$LinuxUser = "devuser",

  # Timeouts (seconds) to prevent hangs.
  [int]$DistroInstallTimeoutSeconds = 1200,
  [int]$LauncherInitTimeoutSeconds = 600,
  [int]$DockerWaitSeconds = 600,

  # If set, do not install Docker Desktop (WSL/Ubuntu setup only).
  [switch]$SkipDockerDesktop
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Log([string]$message, [ValidateSet("INFO","WARN","ERROR")][string]$level = "INFO") {
  $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffK")
  $line = "[{0}] [{1}] {2}" -f $ts, $level, $message
  Write-Host $line
  try {
    $dir = Join-Path $PSScriptRoot ".logs"
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $path = Join-Path $dir "provision.log"
    Add-Content -LiteralPath $path -Value $line -Encoding UTF8
  } catch {
    # Best-effort only.
  }
}

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "This script must be run from an elevated PowerShell session (Run as Administrator)."
  }
}

function Test-PendingReboot {
  # Common indicators used by Windows Update / CBS / Session Manager.
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

  try {
    $u = Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Updates" -ErrorAction SilentlyContinue
    if ($u -and $u.UpdateExeVolatile) { return $true }
  } catch {}

  return $false
}

function Exit-IfPendingReboot([string]$context) {
  if (Test-PendingReboot) {
    Write-Log ("Reboot pending detected ({0}). Reboot Windows and re-run. Exiting without reboot." -f $context) "WARN"
    exit 3010
  }
}

function Ensure-WindowsFeatureEnabledNoRestart([string]$featureName) {
  $f = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
  if ($f -and $f.State -eq "Enabled") {
    Write-Log "Windows feature already enabled: $featureName"
    return $false
  }

  Write-Log "Enabling Windows feature (NoRestart): $featureName"
  $r = Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart
  return ($r.RestartNeeded -eq $true)
}

function Normalize-WslTextLine([string]$s) {
  if ($null -eq $s) { return "" }
  # wsl.exe output can be UTF-16 with NULs when captured; strip to compare reliably.
  return (($s -replace "\u0000", "").Trim())
}

function Get-WSLDistros([switch]$All) {
  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return @() }
  $args = @("-l","-q")
  if ($All) { $args += "--all" }
  try {
    $raw = & wsl.exe @args 2>$null
    if (($LASTEXITCODE -ne 0 -or -not $raw) -and $All) {
      # Older WSL builds may not support --all. Retry without it.
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

function Resolve-UbuntuLauncher([string]$distroName) {
  switch ($distroName) {
    "Ubuntu-22.04" { return "ubuntu2204.exe" }
    default { return $null }
  }
}

function Get-UbuntuLauncherPath([string]$distroName) {
  $launcher = Resolve-UbuntuLauncher $distroName
  if (-not $launcher) { return $null }

  $cmd = Get-Command $launcher -ErrorAction SilentlyContinue
  if ($cmd -and $cmd.CommandType -eq "Application") { return $cmd.Source }

  # App execution alias path (per-user).
  $alias = Join-Path $env:LOCALAPPDATA ("Microsoft\WindowsApps\{0}" -f $launcher)
  if (Test-Path -LiteralPath $alias) { return $alias }

  return $null
}

function Wait-ForUbuntuLauncherPath([string]$distroName, [int]$timeoutSeconds = 300) {
  $deadline = (Get-Date).AddSeconds($timeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    $p = Get-UbuntuLauncherPath $distroName
    if ($p) { return $p }
    Start-Sleep -Seconds 2
  }
  return $null
}

function Wait-ForDistroReady([string]$distroName, [int]$timeoutSeconds) {
  $deadline = (Get-Date).AddSeconds($timeoutSeconds)
  $lastLog = Get-Date "2000-01-01"

  while ((Get-Date) -lt $deadline) {
    $normal = Get-WSLDistros
    if ($normal -contains $distroName) {
      # Do not run any command that can trigger interactive OOBE. After launcher init (--root),
      # running a trivial command as root should be safe and non-interactive.
      try {
        & wsl.exe @("-d", $distroName, "-u", "root", "--exec", "bash", "-lc", "true") | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
      } catch {}
    }

    $all = Get-WSLDistros -All
    $now = Get-Date
    if ((New-TimeSpan -Start $lastLog -End $now).TotalSeconds -ge 15) {
      if ($normal -contains $distroName) {
        Write-Log "Waiting for WSL distro '$distroName' to become usable..." "WARN"
      } elseif ($all -contains $distroName) {
        Write-Log "Waiting for WSL distro '$distroName' to finish installing..." "WARN"
      } else {
        Write-Log "Waiting for WSL distro '$distroName' to appear..." "WARN"
      }
      $lastLog = $now
    }

    Start-Sleep -Seconds 3
  }

  return $false
}

function Invoke-WslRootScript([string]$distroName, [string]$bashScript) {
  $bashScript = $bashScript -replace "`r", ""
  if (-not $bashScript.EndsWith("`n")) { $bashScript += "`n" }

  function Quote-WinArg([string]$arg) {
    if ($null -eq $arg) { return '""' }
    if ($arg -notmatch '[\\s"]') { return $arg }
    $arg = $arg -replace '(\\*)"', '$1$1\"'
    $arg = $arg -replace '(\\+)$', '$1$1'
    return '"' + $arg + '"'
  }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = "wsl.exe"
  $psi.Arguments = "-d $(Quote-WinArg $distroName) -u root --exec bash -l -s"
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true

  $p = [System.Diagnostics.Process]::Start($psi)
  $p.StandardInput.Write($bashScript)
  $p.StandardInput.Close()
  $p.WaitForExit()
  return $p.ExitCode
}

function Ensure-WSL2AndUbuntuUnattended {
  Exit-IfPendingReboot "pre-check"

  $restartNeeded = $false
  $restartNeeded = (Ensure-WindowsFeatureEnabledNoRestart "Microsoft-Windows-Subsystem-Linux") -or $restartNeeded
  $restartNeeded = (Ensure-WindowsFeatureEnabledNoRestart "VirtualMachinePlatform") -or $restartNeeded

  if ($restartNeeded) {
    Write-Log "Windows optional features were enabled and a reboot is required. Exiting without reboot." "WARN"
    Exit-IfPendingReboot "post-feature-enable"
    exit 3010
  }

  Exit-IfPendingReboot "post-feature-check"

  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "wsl.exe not found. WSL must be available on Windows 11 before continuing."
  }

  # Ensure WSL2 defaults.
  try { & wsl.exe --set-default-version 2 | Out-Null } catch {}
  try { & wsl.exe --update | Out-Null } catch {}

    $distros = Get-WSLDistros -All
    $needsLauncherInit = $false

    if ($distros -contains $Distro) {
      Write-Log "WSL distro already installed: $Distro"
      # If the distro exists but isn't usable yet (half-installed / broken state), try launcher init.
      if (-not (Wait-ForDistroReady $Distro 30)) {
        Write-Log "Distro '$Distro' not usable yet. Will attempt launcher initialization (install --root)..." "WARN"
        $needsLauncherInit = $true
      }
    } else {
      Write-Log "Installing WSL distro (no launch): $Distro"
      $rc = Invoke-ProcessWithTimeout -FilePath "wsl.exe" -ArgumentList @("--install","-d",$Distro,"--no-launch") -TimeoutSeconds $DistroInstallTimeoutSeconds
      if ($rc -ne 0) { throw "wsl --install failed for '$Distro' (exit code $rc)." }
      $needsLauncherInit = $true
    }

    if ($needsLauncherInit) {
      # Initialize via distro launcher to avoid interactive user creation.
      $launcherPath = Wait-ForUbuntuLauncherPath $Distro 300
      if (-not $launcherPath) {
        throw "Could not find distro launcher for '$Distro' (expected ubuntu2204.exe). This is required for unattended initialization (install --root)."
      }

      Write-Log "Running launcher initialization to avoid OOBE prompt: ubuntu2204.exe install --root"
      $rc = Invoke-ProcessWithTimeout -FilePath $launcherPath -ArgumentList @("install","--root") -TimeoutSeconds $LauncherInitTimeoutSeconds
      if ($rc -ne 0) {
        throw "Launcher initialization failed (exit code $rc): $launcherPath install --root"
      }
    }

    $ok = Wait-ForDistroReady $Distro $DistroInstallTimeoutSeconds
    if (-not $ok) {
      throw "Timed out waiting for distro '$Distro' to become ready."
    }

  # Ensure distro uses WSL2.
  try { & wsl.exe --set-version $Distro 2 | Out-Null } catch {}
  try { & wsl.exe --set-default $Distro | Out-Null } catch {}
}

function Ensure-DevUser {
  if (-not $LinuxUser) { throw "LinuxUser cannot be empty." }
  if ($LinuxUser -notmatch '^[a-z_][a-z0-9_-]{0,31}$') {
    throw "LinuxUser '$LinuxUser' is not a valid Linux username for unattended creation."
  }

  Write-Log "Creating/configuring Linux user '$LinuxUser' (home=/home/$LinuxUser, shell=/bin/bash, passwordless sudo)"
  # Use a single-quoted here-string so Bash variables like $u are not interpolated by PowerShell (StrictMode).
  $bash = @'
set -euo pipefail
u='{0}'
export DEBIAN_FRONTEND=noninteractive

if ! command -v sudo >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y sudo
fi

if ! id "$u" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$u"
  usermod -aG sudo "$u"
fi

sudoers="/etc/sudoers.d/$u"
echo "$u ALL=(ALL) NOPASSWD:ALL" > "$sudoers"
chmod 0440 "$sudoers"
'@
  $bash = $bash -f $LinuxUser

  $rc = Invoke-WslRootScript $Distro $bash
  if ($rc -ne 0) { throw "Failed to provision Linux user '$LinuxUser' (exit code $rc)." }

  $launcherPath = Get-UbuntuLauncherPath $Distro
  if (-not $launcherPath) { throw "ubuntu2204.exe not found; cannot set default user non-interactively." }

  Write-Log "Setting default WSL user via launcher: ubuntu2204.exe config --default-user $LinuxUser"
  $rc = Invoke-ProcessWithTimeout -FilePath $launcherPath -ArgumentList @("config","--default-user",$LinuxUser) -TimeoutSeconds 120
  if ($rc -ne 0) { throw "Failed to set default user (exit code $rc): ubuntu2204.exe config --default-user $LinuxUser" }

  # Apply default user selection.
  Write-Log "Shutting down WSL to apply default-user configuration"
  try { & wsl.exe --shutdown | Out-Null } catch {}

  # Validate.
  try {
    $out = & wsl.exe @("-d",$Distro,"--exec","bash","-lc","id -un") 2>$null
    $user = (Normalize-WslTextLine ($out | Select-Object -First 1))
    if ($user -ne $LinuxUser) {
      throw "Default user validation failed. Expected '$LinuxUser', got '$user'."
    }
  } catch {
    throw "Default user validation failed: $($_.Exception.Message)"
  }

  try {
    & wsl.exe @("-d",$Distro,"-u",$LinuxUser,"--exec","bash","-lc","sudo -n true") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sudo -n true returned exit code $LASTEXITCODE" }
  } catch {
    throw "Passwordless sudo validation failed for '$LinuxUser': $($_.Exception.Message)"
  }
}

function Ensure-DockerDesktopFirstRunIsNonInteractive {
  # Best-effort: pre-create per-user settings to suppress onboarding and reduce first-run prompts.
  try {
    $dir = Join-Path $Env:APPDATA "Docker"
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $path = Join-Path $dir "settings-store.json"
    $obj = New-Object psobject
    if (Test-Path -LiteralPath $path) {
      try {
        $raw = Get-Content -LiteralPath $path -Raw
        $raw = $raw -replace "^\uFEFF", ""
        if ($raw) { $obj = $raw | ConvertFrom-Json }
      } catch {
        $bak = "$path.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        try { Copy-Item -LiteralPath $path -Destination $bak -Force } catch {}
        $obj = New-Object psobject
      }
    }

    $obj | Add-Member -NotePropertyName "DisplayedOnboarding" -NotePropertyValue $true -Force
    $obj | Add-Member -NotePropertyName "EnableDockerAI" -NotePropertyValue $false -Force

    $json = ($obj | ConvertTo-Json -Depth 10)
    [IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))
  } catch {
    # Best-effort only.
  }
}

  function Resolve-DockerCli {
    $cmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.CommandType -eq "Application") { return $cmd.Source }
    $fallback = Join-Path $Env:ProgramFiles "Docker\Docker\resources\bin\docker.exe"
    if (Test-Path -LiteralPath $fallback) { return $fallback }
    return $null
  }

  function Test-DockerEnginePipe {
    # Avoid spamming "failed to connect ... npipe" while Docker Desktop is still booting.
    try { return (Test-Path -LiteralPath "\\\\.\\pipe\\docker_engine") } catch { return $false }
  }

  function Start-DockerDesktopBestEffort([string]$desktopExe) {
    if (-not $desktopExe) { return }
    if (-not (Test-Path -LiteralPath $desktopExe)) { return }
    try {
      $p = Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($p) { return }
    } catch {}

    try {
      Write-Log "Starting Docker Desktop (best-effort)..." "WARN"
      Start-Process -FilePath $desktopExe | Out-Null
    } catch {
      # Best-effort only.
    }
  }

  function Heal-DockerDesktopBestEffort {
    # A few cheap, non-destructive tactics that often unstick WSL integration without requiring a reboot.
    try {
      Write-Log "Best-effort: attempting to heal Docker Desktop/WSL integration (no reboot)..." "WARN"

      try { Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
      try { Get-Process -Name "com.docker.backend" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}

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

      # Kick WSL stack.
      try { & wsl.exe --shutdown 2>$null | Out-Null } catch {}
    } catch {
      # Best-effort only.
    }
  }

  function Show-DockerDiagnostics {
    try {
      Write-Log "Docker diagnostics (best-effort):" "WARN"

      try {
        $svc = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
        if ($svc) {
          Write-Log ("- Service com.docker.service: {0} (StartType={1})" -f $svc.Status, $svc.StartType) "WARN"
        } else {
          Write-Log "- Service com.docker.service: not found" "WARN"
        }
      } catch {}

      try {
        $p = Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($p) { Write-Log ("- Process Docker Desktop: running (pid={0})" -f $p.Id) "WARN" }
        else { Write-Log "- Process Docker Desktop: not running" "WARN" }
      } catch {}

      try {
        $p = Get-Process -Name "com.docker.backend" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($p) { Write-Log ("- Process com.docker.backend: running (pid={0})" -f $p.Id) "WARN" }
        else { Write-Log "- Process com.docker.backend: not running" "WARN" }
      } catch {}

      try {
        Write-Log ("- Engine pipe \\\\.\\pipe\\docker_engine present: {0}" -f (Test-DockerEnginePipe)) "WARN"
      } catch {}

      try {
        $docker = Resolve-DockerCli
        if ($docker) {
          Write-Log ("- docker CLI: {0}" -f $docker) "WARN"
          # Hide noisy errors; just capture exit code/availability.
          & $docker version 1>$null 2>$null
          Write-Log ("- docker version exit code: {0}" -f $LASTEXITCODE) "WARN"
        } else {
          Write-Log "- docker CLI: not found" "WARN"
        }
      } catch {}

      try {
        if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
          $d = (& wsl.exe -l -q 2>$null) -join ", "
          if ($d) { Write-Log ("- WSL distros: {0}" -f $d) "WARN" }
        }
      } catch {}
    } catch {
      # Best-effort only.
    }
  }

  function Wait-DockerReady([int]$seconds) {
    $docker = Resolve-DockerCli
    if (-not $docker) { return $false }

    $deadline = (Get-Date).AddSeconds($seconds)
    $lastLog = Get-Date "2000-01-01"
    while ((Get-Date) -lt $deadline) {
      try {
        # Avoid noisy "npipe ... file not found" output while waiting.
        & $docker info 1>$null 2>$null
        if ($LASTEXITCODE -eq 0) { return $true }
      } catch {}

      $now = Get-Date
      if ((New-TimeSpan -Start $lastLog -End $now).TotalSeconds -ge 15) {
        $pipe = $false
        try { $pipe = Test-DockerEnginePipe } catch {}
        Write-Log ("Docker not ready yet (pipe={0}). Waiting..." -f $pipe) "INFO"
        $lastLog = $now
      }
      Start-Sleep -Seconds 2
    }
    return $false
  }

function Ensure-DockerDesktopInstalledAndReady {
  if ($SkipDockerDesktop) {
    Write-Log "Skipping Docker Desktop install (SkipDockerDesktop=1)."
    return
  }

  Exit-IfPendingReboot "pre-docker-install"

  $desktopExe = Join-Path $Env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
  $installed = (Test-Path -LiteralPath $desktopExe)

    if (-not $installed) {
      $bundledZip = Join-Path $PSScriptRoot "Docker Desktop Installer.zip"
      $installedViaZip = $false

      if (Test-Path -LiteralPath $bundledZip) {
        Write-Log ("Installing Docker Desktop from bundled installer zip: {0}" -f $bundledZip) "INFO"

        $outDir = Join-Path $env:TEMP ("reliable-message-api.docker-desktop-installer." + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
        try {
          try {
            Expand-Archive -LiteralPath $bundledZip -DestinationPath $outDir -Force
          } catch {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue | Out-Null
            [System.IO.Compression.ZipFile]::ExtractToDirectory($bundledZip, $outDir, $true)
          }

          $exe = Get-ChildItem -LiteralPath $outDir -Recurse -File -Filter "*.exe" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq "Docker Desktop Installer.exe" } |
            Select-Object -First 1
          if (-not $exe) {
            $exe = Get-ChildItem -LiteralPath $outDir -Recurse -File -Filter "*.exe" -ErrorAction SilentlyContinue |
              Select-Object -First 1
          }
          if (-not $exe) { throw "Bundled installer zip did not contain any .exe." }

          $rc = Invoke-ProcessWithTimeout -FilePath $exe.FullName -ArgumentList @("install","--quiet","--accept-license","--backend=wsl-2") -TimeoutSeconds 1800
          if ($rc -ne 0) { throw "Docker Desktop installer failed (exit code $rc)." }
          $installedViaZip = $true
        } catch {
          Write-Log ("Bundled installer zip failed; falling back to winget/web install. Details: {0}" -f $_.Exception.Message) "WARN"
        } finally {
          try { Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
        }
      }

      if (-not $installedViaZip) {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
          Write-Log "Installing Docker Desktop via winget (silent, WSL2 backend, license accepted)"
          $args = @(
            "install",
          "-e",
          "--id","Docker.DockerDesktop",
          "--source","winget",
          "--accept-source-agreements",
          "--accept-package-agreements",
          "--silent",
          "--disable-interactivity",
          "--override","install --quiet --accept-license --backend=wsl-2"
        )
          & winget @args
          if ($LASTEXITCODE -ne 0) { throw "winget install Docker.DockerDesktop failed (exit code $LASTEXITCODE)." }
        } else {
          # Fallback: download the official installer and run silently.
          $tmp = Join-Path $env:TEMP "DockerDesktopInstaller.exe"
          $url = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
          Write-Log "winget not found and bundled installer zip missing (or failed). Downloading Docker Desktop installer from official URL." "WARN"
          Invoke-WebRequest -Uri $url -OutFile $tmp
          $rc = Invoke-ProcessWithTimeout -FilePath $tmp -ArgumentList @("install","--quiet","--accept-license","--backend=wsl-2") -TimeoutSeconds 1800
          if ($rc -ne 0) { throw "Docker Desktop installer failed (exit code $rc)." }
        }
      }

      # Some setups require a reboot to finalize drivers/WSL integration. Prefer a clean exit over a long wait.
      Exit-IfPendingReboot "post-docker-install"
    } else {
      Write-Log "Docker Desktop already installed."
    }

  # Best-effort: allow the current Windows user to use Docker without elevation.
  try {
    $g = Get-LocalGroup -Name "docker-users" -ErrorAction SilentlyContinue
    if ($g) { Add-LocalGroupMember -Group "docker-users" -Member $env:USERNAME -ErrorAction SilentlyContinue }
  } catch {}

  Ensure-DockerDesktopFirstRunIsNonInteractive

  # Ensure the Windows service is set to start automatically (helps when no interactive UI session is running).
  try {
    $svc = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
    if ($svc) {
      try { Set-Service -Name "com.docker.service" -StartupType Automatic -ErrorAction SilentlyContinue } catch {}
      if ($svc.Status -ne "Running") {
        Write-Log "Starting Docker service (com.docker.service)"
        try { Start-Service -Name "com.docker.service" -ErrorAction SilentlyContinue } catch {}
      }
    }
  } catch {}

  # Prefer headless readiness first. If not ready, start Docker Desktop once (still unattended).
  $headlessWait = [Math]::Min([Math]::Max([int]($DockerWaitSeconds / 3), 30), 120)
  $remainingWait = [Math]::Max($DockerWaitSeconds - $headlessWait, 30)

    Write-Log "Waiting for Docker engine readiness (headless first)..." "INFO"
    if (-not (Wait-DockerReady $headlessWait)) {
      if (Test-Path -LiteralPath $desktopExe) {
        Write-Log "Docker not ready yet. Starting Docker Desktop to complete provisioning (still unattended)..." "WARN"
        Start-DockerDesktopBestEffort $desktopExe
      }
      if (-not (Wait-DockerReady $remainingWait)) {
        Write-Log "Docker still not ready after waiting. Attempting one best-effort heal before failing..." "WARN"
        Heal-DockerDesktopBestEffort
        Start-DockerDesktopBestEffort $desktopExe
        if (-not (Wait-DockerReady 180)) {
          Show-DockerDiagnostics
          throw "Docker did not become ready within ${DockerWaitSeconds}s (+ heal). Check Docker Desktop logs and WSL status."
        }
      }
    }

  Write-Log "Docker is ready."
}

if ($env:OS -notlike "*Windows*") {
  throw "This script is intended for Windows 11."
}

Assert-Admin

Write-Log "Provisioning local dev environment (WSL2 + Ubuntu 22.04 + Docker Desktop) - unattended mode"
Write-Log ("Target distro: {0}" -f $Distro)
Write-Log ("Target Linux user: {0}" -f $LinuxUser)

Ensure-WSL2AndUbuntuUnattended
Ensure-DevUser

Write-Log "Shutting down WSL (requested)"
try { & wsl.exe --shutdown | Out-Null } catch {}

Ensure-DockerDesktopInstalledAndReady

Write-Log "Provisioning completed successfully."
