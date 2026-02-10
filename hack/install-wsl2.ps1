Param(
  [switch]$AutoReboot,
  [switch]$SkipDistro,
  [string]$Distro = "Ubuntu-22.04",

  # Default Linux user to create/use inside the distro (used by dev scripts).
  # If omitted, it will derive from the Windows username.
  [string]$UserName = $null,

  # Optional: enable systemd in the WSL distro via /etc/wsl.conf (requires wsl --shutdown).
  [switch]$EnableSystemd
)

$ErrorActionPreference = "Stop"

function Normalize-WslTextLine([string]$s) {
  if ($null -eq $s) { return "" }
  # When wsl.exe output is captured (non-interactive), it may be UTF-16 with embedded NULs.
  # Strip NULs so comparisons like "-contains Ubuntu-22.04" work reliably.
  return (($s -replace "\u0000", "").Trim())
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
      Write-Host "WARNING: VirtualizationFirmwareEnabled=False. Enable Intel VT-x/AMD-V in BIOS/UEFI or WSL2/Docker will not work." -ForegroundColor Yellow
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

function Ensure-WSL2Prereqs {
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
    Write-Host "Reboot Windows, then re-run: .\\hack\\install-wsl2.cmd" -ForegroundColor Yellow
    exit 3010
  }
}

function Get-InstalledWSLDistros {
  Param([switch]$All)
  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { return @() }
  try {
    $args = @("-l","-q")
    if ($All) { $args += "--all" }
    $raw = & wsl.exe @args 2>$null
    if ($LASTEXITCODE -ne 0) { return @() }
    if (-not $raw) { return @() }
    return @(
      $raw |
        ForEach-Object { Normalize-WslTextLine $_ } |
        Where-Object { $_ -and $_ -ne "" }
    )
  } catch {
    return @()
  }
}

function Ensure-WSL2Defaults {
  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "wsl.exe not found after enabling features. Reboot and re-run." -ForegroundColor Yellow
    exit 3010
  }

  try { wsl.exe --update | Out-Null } catch {}
  try { wsl.exe --set-default-version 2 | Out-Null } catch {}
}

function Wait-ForDistroReady([string]$distroName, [int]$timeoutSeconds = 1200) {
  # wsl --install can return before the distro shows up in `wsl -l -q`, especially with --web-download.
  # Wait until the distro appears and can execute a trivial command.
  $deadline = (Get-Date).AddSeconds($timeoutSeconds)
  $lastLog = Get-Date "2000-01-01"

  while ((Get-Date) -lt $deadline) {
    $normal = Get-InstalledWSLDistros
    if ($normal -contains $distroName) {
      try {
        & wsl.exe @("-d", $distroName, "--exec", "bash", "-lc", "true") | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
      } catch {}
    }

    $all = Get-InstalledWSLDistros -All
    $now = Get-Date
    if ((New-TimeSpan -Start $lastLog -End $now).TotalSeconds -ge 15) {
      if ($normal -contains $distroName) {
        Write-Host "Waiting for WSL distro '$distroName' to become usable..." -ForegroundColor Yellow
      } elseif ($all -contains $distroName) {
        Write-Host "Waiting for WSL distro '$distroName' to finish installing..." -ForegroundColor Yellow
      } else {
        Write-Host "Waiting for WSL distro '$distroName' to appear..." -ForegroundColor Yellow
      }
      $lastLog = $now
    }
    Start-Sleep -Seconds 3
  }

  return $false
}

function Normalize-WslUserName([string]$name) {
  $s = ""
  if ($null -ne $name) { $s = [string]$name }
  $s = $s.Trim()
  if (-not $s) { $s = $env:USERNAME }
  if (-not $s) { $s = "dev" }

  $s = $s.ToLowerInvariant()
  $s = ($s -replace "[^a-z0-9_-]", "-")
  $s = ($s -replace "^-+", "")
  $s = ($s -replace "-+$", "")
  if (-not $s) { $s = "dev" }
  if ($s.Length -gt 32) { $s = $s.Substring(0, 32) }
  return $s
}

function Invoke-WslRoot([string]$distroName, [string]$bashCmd) {
  # Feed the script over stdin to avoid Windows argument quoting issues with multi-line/quoted commands.
  # Normalize CRLF -> LF so bash doesn't see stray `\r` characters (which can break parsing).
  # Avoid the PowerShell pipeline here because it always appends `\r\n` after the string object,
  # which can inject a stray `\r` line into the bash input stream.
  $bashCmd = $bashCmd -replace "`r", ""
  if (-not $bashCmd.EndsWith("`n")) { $bashCmd += "`n" }

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
  $p.StandardInput.Write($bashCmd)
  $p.StandardInput.Close()
  $p.WaitForExit()
  return $p.ExitCode
}

function Try-SetDefaultUserViaManage([string]$distroName, [string]$user) {
  try {
    & wsl.exe @("--manage", $distroName, "--set-default-user", $user) | Out-Null
    return ($LASTEXITCODE -eq 0)
  } catch {
    return $false
  }
}

function Ensure-WslConfDefaultUser([string]$distroName, [string]$user, [bool]$enableSystemd) {
  # Fallback path when `wsl.exe --manage --set-default-user` is unavailable.
  $enableSystemdText = if ($enableSystemd) { "true" } else { "false" }

  $bash = @'
set -euo pipefail
u='__RMA_USER__'
conf='/etc/wsl.conf'
tmp="/tmp/wsl.conf.$$"
touch "$conf"
awk -v u="$u" -v enable_systemd='__RMA_ENABLE_SYSTEMD__' '
  BEGIN {
    in_user=0; default_set=0;
    in_boot=0; systemd_set=0;
  }
  /^\[user\]$/ {
    if (in_boot && enable_systemd=="true" && !systemd_set) { print "systemd=true"; systemd_set=1 }
    in_user=1; in_boot=0; print; next
  }
  /^\[boot\]$/ {
    if (in_user && !default_set) { print "default=" u; default_set=1 }
    in_boot=1; in_user=0; print; next
  }
  /^\[.*\]$/ {
    if (in_user && !default_set) { print "default=" u; default_set=1 }
    if (in_boot && enable_systemd=="true" && !systemd_set) { print "systemd=true"; systemd_set=1 }
    in_user=0; in_boot=0; print; next
  }
  {
    if (in_user && $0 ~ /^default=/) {
      if (!default_set) { print "default=" u; default_set=1 }
      next
    }
    if (in_boot && enable_systemd=="true" && $0 ~ /^systemd=/) {
      if (!systemd_set) { print "systemd=true"; systemd_set=1 }
      next
    }
    print
  }
  END {
    if (in_user && !default_set) { print "default=" u; default_set=1 }
    if (in_boot && enable_systemd=="true" && !systemd_set) { print "systemd=true"; systemd_set=1 }
    if (!default_set) { print ""; print "[user]"; print "default=" u }
    if (enable_systemd=="true" && !systemd_set) { print ""; print "[boot]"; print "systemd=true" }
  }
' "$conf" > "$tmp"
mv "$tmp" "$conf"
'@

  $bash = $bash.Replace("__RMA_USER__", $user)
  $bash = $bash.Replace("__RMA_ENABLE_SYSTEMD__", $enableSystemdText)

  $rc = Invoke-WslRoot $distroName $bash
  if ($rc -ne 0) { throw "failed to update /etc/wsl.conf (exit code $rc)" }
}

function Ensure-DefaultUser([string]$distroName, [string]$user, [bool]$enableSystemd) {
  # Initialize the distro and create a non-root default user with passwordless sudo,
  # so repo scripts can run non-interactively.
  $bash = @'
set -euo pipefail
u='__RMA_USER__'
export DEBIAN_FRONTEND=noninteractive

# Ensure core tooling exists.
if ! command -v bash >/dev/null 2>&1; then
  echo "ERROR: bash not found in distro" >&2
  exit 1
fi

# Ensure sudo exists (Ubuntu images normally have it, but keep it robust).
if ! command -v sudo >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y sudo
fi

if ! id "$u" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$u"
  usermod -aG sudo "$u"
fi

sudoers="/etc/sudoers.d/99-reliable-message-api"
echo "$u ALL=(ALL) NOPASSWD:ALL" > "$sudoers"
chmod 0440 "$sudoers"
'@

  $bash = $bash.Replace("__RMA_USER__", $user)

  $rc = Invoke-WslRoot $distroName $bash
  if ($rc -ne 0) { throw "failed to create/configure WSL default user (exit code $rc)" }

  $ok = Try-SetDefaultUserViaManage $distroName $user
  if (-not $ok) {
    Write-Host "WARN: wsl --manage --set-default-user not supported; falling back to /etc/wsl.conf" -ForegroundColor Yellow
    Ensure-WslConfDefaultUser $distroName $user $enableSystemd
  } elseif ($enableSystemd) {
    # If manage worked but systemd is requested, still ensure wsl.conf has [boot] systemd=true.
    Ensure-WslConfDefaultUser $distroName $user $enableSystemd
  }

  # Apply default-user/systemd changes.
  try { wsl.exe --shutdown | Out-Null } catch {}

  # Validate the default user resolves and has passwordless sudo.
  try {
    & wsl.exe @("-d", $distroName, "--exec", "bash", "-lc", "id -un") | Out-Null
  } catch {}
  try {
    & wsl.exe @("-d", $distroName, "-u", $user, "--exec", "bash", "-lc", "sudo -n true") | Out-Null
  } catch {}
}

function Ensure-Distro([string]$name) {
  $distros = Get-InstalledWSLDistros
  if ($distros -contains $name) { return $distros }

  if ($distros.Count -eq 0) {
    Write-Host "No WSL distributions installed." -ForegroundColor Yellow
  } else {
    Write-Host "WSL distributions installed, but '$name' is missing. Installed: $($distros -join ', ')" -ForegroundColor Yellow
  }
  if ($SkipDistro) {
    Write-Host "Skipping distro installation (SkipDistro=1)."
    return $distros
  }

  Write-Host "Installing WSL distro: $name"
  $lastErr = $null
  try {
    # Prefer web download to avoid Microsoft Store dependencies, and avoid auto-launching the distro.
    & wsl.exe --install -d $name --web-download --no-launch
    if ($LASTEXITCODE -ne 0) {
      Write-Host "wsl --install (web-download) failed; retrying without --web-download..." -ForegroundColor Yellow
      & wsl.exe --install -d $name --no-launch
    }
    if ($LASTEXITCODE -ne 0) {
      Write-Host "wsl --install (no-launch) failed; retrying without extra flags..." -ForegroundColor Yellow
      & wsl.exe --install -d $name
    }
    if ($LASTEXITCODE -ne 0) {
      $lastErr = "wsl --install failed (exit code $LASTEXITCODE)"
    }
  } catch {
    $lastErr = $_.Exception.Message
  }

  if ($lastErr) {
    Write-Host "ERROR: $lastErr" -ForegroundColor Red
    Write-Host "You can install a distro manually:" -ForegroundColor Yellow
    Write-Host "  wsl --list --online"
    Write-Host "  wsl --install -d $name --web-download"
    return @()
  }

  # Wait for the distro to actually show up and become runnable (wsl can return early).
  $ok = Wait-ForDistroReady $name 1200
  if (-not $ok) {
    Write-Host "ERROR: timed out waiting for WSL distro '$name' to finish installing." -ForegroundColor Red
    Write-Host "Current WSL distros (including installing/uninstalling):" -ForegroundColor Yellow
    try { wsl.exe -l -v --all } catch {}
    return @()
  }

  $distros = Get-InstalledWSLDistros
  return $distros
}

function Ensure-AllDistrosVersion2([string[]]$distros) {
  if (-not $distros -or $distros.Count -eq 0) { return }
  foreach ($d in $distros) {
    try { & wsl.exe --set-version $d 2 | Out-Null } catch {}
  }
}

function Set-DefaultDistroIfPresent([string[]]$distros, [string]$name) {
  if (-not $distros -or $distros.Count -eq 0) { return }
  if ($distros -contains $name) {
    try { & wsl.exe --set-default $name | Out-Null } catch {}
  }
}

if ($env:OS -notlike "*Windows*") {
  throw "This script is intended for Windows."
}

Warn-Virtualization
Ensure-Admin
Ensure-WSL2Prereqs
Ensure-WSL2Defaults

$wslUser = Normalize-WslUserName $UserName
$distros = Ensure-Distro $Distro
if (-not $SkipDistro -and (-not $distros -or $distros.Count -eq 0)) {
  Write-Host "ERROR: WSL distro installation did not complete. Run manually:" -ForegroundColor Red
  Write-Host "  wsl --list --online"
  Write-Host "  wsl --install -d $Distro --web-download"
  exit 1
}
if (-not $SkipDistro -and ($distros -notcontains $Distro)) {
  Write-Host "ERROR: Requested distro '$Distro' not found after install. Installed: $($distros -join ', ')" -ForegroundColor Red
  Write-Host "Try:" -ForegroundColor Yellow
  Write-Host "  wsl --install -d $Distro --web-download"
  exit 1
}
Set-DefaultDistroIfPresent $distros $Distro
Ensure-AllDistrosVersion2 $distros

if (-not $SkipDistro) {
  Write-Host ""
  Write-Host "Configuring default Linux user in ${Distro}: $wslUser"
  Ensure-DefaultUser $Distro $wslUser ($EnableSystemd.IsPresent)
}

Write-Host ""
Write-Host "WSL2 setup completed."
Write-Host "Verify: wsl -l -v"
Write-Host "Open distro: wsl -d $Distro"
Write-Host "Open a shell in this repo: .\\hack\\wsl-here.cmd"
