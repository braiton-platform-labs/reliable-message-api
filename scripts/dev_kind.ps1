param(
  [Parameter(Position = 0)]
  [ValidateSet("up","reload","verify","status","logs","down","clean","help")]
  [string]$Command = "up",

  [string]$Distro = "",
  [string]$Cluster = "",
  [string]$Workers = "",

  [switch]$Foreground,
  # Applies BOTH: Windows hosts block (admin/UAC) + WSL /etc/hosts entries (may require sudo).
  [switch]$Hosts,
  # Apply Windows hosts block only (default for 'up' unless -SkipWindowsHosts).
  [switch]$WindowsHosts,
  # Apply WSL /etc/hosts entries only (may require sudo inside WSL).
  [switch]$WslHosts,
  # Skip Windows hosts auto-apply (useful for CI or restricted machines).
  [switch]$SkipWindowsHosts,
  [switch]$NoBootstrap,
  [switch]$SkipVerify,

  # Optional: enable https://api.local.dev without ':8443' by creating a Windows portproxy 443 -> 8443
  # and (optionally) trusting the WSL mkcert root CA for the current user.
  [switch]$Https443,
  [switch]$TrustWslMkcertCa,

  # Opt-outs (defaults for 'up' enable no-port HTTPS + trust mkcert CA).
  [switch]$SkipHttps443,
  [switch]$SkipTrustWslMkcertCa
)

$ErrorActionPreference = "Stop"

function Usage {
  @"
Reliable Message API - Windows wrapper (calls WSL)

Usage:
  powershell -ExecutionPolicy Bypass -File .\scripts\dev_kind.ps1 up [-Distro Ubuntu-22.04] [-Cluster NAME] [-Workers N|auto] [-Foreground] [-Hosts] [-NoBootstrap] [-SkipVerify]
  powershell -ExecutionPolicy Bypass -File .\scripts\dev_kind.ps1 up ... [-Https443] [-TrustWslMkcertCa] [-SkipHttps443] [-SkipTrustWslMkcertCa]
  powershell -ExecutionPolicy Bypass -File .\scripts\dev_kind.ps1 reload|verify|status|logs|down|clean

Notes:
  - This runs the real workflow inside WSL via ./scripts/dev_kind.sh.
  - On 'up' it auto-applies Windows hosts for api.local.dev/kong.local.dev unless -SkipWindowsHosts.
  - By default, 'up' also tries to:
    - configure https://api.local.dev (no ':8443') by creating a Windows portproxy 443 -> 8443 (requires Admin/UAC)
    - trust the WSL mkcert root CA in the Windows CurrentUser Root store (so browsers/Postman can validate TLS)
  - Use -SkipHttps443 / -SkipTrustWslMkcertCa to disable those steps.
  - Flags:
    -Hosts          Apply Windows hosts + WSL hosts
    -WindowsHosts   Apply Windows hosts only
    -WslHosts       Apply WSL hosts only
"@ | Write-Output
}

if ($Command -eq "help") { Usage; exit 0 }

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$setupScript = Join-Path $repoRoot "setup\\windows-11-wsl2-docker-desktop\\setup.ps1"
if (-not (Test-Path -LiteralPath $setupScript)) { throw "setup script not found: $setupScript" }

function Ensure-WindowsHosts {
  param([string]$SetupScriptPath)

  # status does not require admin; apply will self-elevate via Ensure-Admin (UAC prompt expected).
  $status = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $SetupScriptPath hosts -HostsAction status 2>$null
  if ($status -and ($status | Select-String -SimpleMatch "hosts block: present")) {
    Write-Output "Windows hosts: already present"
    return
  }

  Write-Output "Windows hosts: applying (UAC prompt expected)..."
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $SetupScriptPath hosts -HostsAction apply
}

$wslExe = (Get-Command wsl.exe -ErrorAction SilentlyContinue)
if (-not $wslExe) { throw "wsl.exe not found. Install WSL and a Linux distro (Ubuntu 22.04 recommended)." }

# Convert Windows path -> WSL path.
$repoRootForWslpath = $repoRoot -replace '\\','/'
$wslPath = & wsl.exe wslpath -a "$repoRootForWslpath"
if (-not $wslPath) { throw "Failed to convert repo path to WSL path via 'wsl wslpath'." }

$args = @($Command)
if ($Cluster) { $args += @("--cluster", $Cluster) }
if ($Workers) { $args += @("--workers", $Workers) }
if ($Foreground) { $args += "--foreground" }

# Host automation:
# - Default on 'up': apply Windows hosts unless explicitly skipped.
# - -Hosts: apply both (Windows + WSL).
# - -WindowsHosts: apply Windows only.
# - -WslHosts: apply WSL only.
$applyWindowsHosts = $false
$applyWslHosts = $false

if ($Hosts) { $applyWindowsHosts = $true; $applyWslHosts = $true }
elseif ($WindowsHosts) { $applyWindowsHosts = $true }
elseif ($WslHosts) { $applyWslHosts = $true }
elseif ($Command -eq "up" -and -not $SkipWindowsHosts) { $applyWindowsHosts = $true }

if ($applyWindowsHosts) {
  Ensure-WindowsHosts -SetupScriptPath $setupScript
}

# HTTPS without ':8443' defaults to enabled for 'up' (opt out with -SkipHttps443).
$enableHttps443 = $Https443 -or ($Command -eq "up" -and -not $SkipHttps443)
$enableTrustCa = $TrustWslMkcertCa -or ($enableHttps443 -and $Command -eq "up" -and -not $SkipTrustWslMkcertCa)
$httpsStrict = $Https443.IsPresent -or $TrustWslMkcertCa.IsPresent

if ($enableHttps443) {
  $httpsScript = Join-Path $repoRoot "scripts\\dev_https.ps1"
  if (-not (Test-Path -LiteralPath $httpsScript)) { throw "https helper script not found: $httpsScript" }
  $httpsArgs = @("enable","-SkipHosts")
  # Only pass -Distro when explicitly set; otherwise dev_https.ps1 will use its default.
  if ($Distro) { $httpsArgs += @("-Distro", $Distro) }
  if ($enableTrustCa) { $httpsArgs += "-TrustWslMkcertCa" }

  try {
    # This will self-elevate (UAC) if needed to configure portproxy.
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $httpsScript @httpsArgs
  } catch {
    if ($httpsStrict) { throw }
    Write-Warning ("HTTPS no-port setup failed; continuing with default https://api.local.dev:8443. Error: {0}" -f $_.Exception.Message)
  }
}

if ($applyWslHosts) { $args += "--hosts" }

if ($NoBootstrap) { $args += "--no-bootstrap" }
if ($SkipVerify) { $args += "--skip-verify" }

$bashCmd = "cd '$wslPath' && chmod +x scripts/dev_kind.sh >/dev/null 2>&1 || true && ./scripts/dev_kind.sh " + ($args -join " ")

if ($Distro) {
  & wsl.exe -d $Distro -- bash -lc $bashCmd
} else {
  & wsl.exe -- bash -lc $bashCmd
}
