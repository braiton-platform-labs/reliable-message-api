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
  - On 'up', it now runs the Datadog-enabled flow (equivalent to make dev-dd-bg/dev-dd-fg).
    Ensure DD_API_KEY is set in .env so dev/datadog-secret can be created.
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

function Sync-WindowsKindKubeconfig {
  param(
    [string]$ClusterName,
    [string]$DistroName,
    [string]$RepoWslPath
  )

  $resolvedCluster = if ([string]::IsNullOrWhiteSpace($ClusterName)) { "bpl-dev" } else { $ClusterName }
  $kubeDir = Join-Path $env:USERPROFILE ".kube"
  New-Item -ItemType Directory -Force -Path $kubeDir | Out-Null
  $winKubeconfig = Join-Path $kubeDir ("kind-{0}.yaml" -f $resolvedCluster)

  $winPathForWsl = $winKubeconfig -replace '\\','/'
  if ($DistroName) {
    $wslKubeconfig = (& wsl.exe -d $DistroName -- wslpath -a "$winPathForWsl")
  } else {
    $wslKubeconfig = (& wsl.exe wslpath -a "$winPathForWsl")
  }
  if (-not $wslKubeconfig) { throw "Failed to convert Windows kubeconfig path to WSL path." }
  $wslKubeconfig = $wslKubeconfig.Trim()

  $exportCmd = "cd '$RepoWslPath' && if [ -x ./bin/kind ]; then ./bin/kind export kubeconfig --name '$resolvedCluster' --kubeconfig '$wslKubeconfig' >/dev/null; " +
               "elif command -v kind >/dev/null 2>&1; then kind export kubeconfig --name '$resolvedCluster' --kubeconfig '$wslKubeconfig' >/dev/null; " +
               "else echo 'kind not found in WSL PATH or ./bin/kind' >&2; exit 127; fi"
  if ($DistroName) {
    & wsl.exe -d $DistroName -- bash -lc $exportCmd
  } else {
    & wsl.exe -- bash -lc $exportCmd
  }
  if ($LASTEXITCODE -ne 0) { throw "kind export kubeconfig failed for cluster '$resolvedCluster'." }
  if (-not (Test-Path -LiteralPath $winKubeconfig)) {
    throw "Expected kubeconfig file not found after export: $winKubeconfig"
  }

  Write-Output "Windows kubeconfig updated for Lens: $winKubeconfig"
}

$wslExe = (Get-Command wsl.exe -ErrorAction SilentlyContinue)
if (-not $wslExe) { throw "wsl.exe not found. Install WSL and a Linux distro (Ubuntu 22.04 recommended)." }

# Convert Windows path -> WSL path.
$repoRootForWslpath = $repoRoot -replace '\\','/'
$wslPath = & wsl.exe wslpath -a "$repoRootForWslpath"
if (-not $wslPath) { throw "Failed to convert repo path to WSL path via 'wsl wslpath'." }
$wslPath = $wslPath.ToString().Trim()

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

  # Execute via Start-Process so native stderr (for example missing mkcert in WSL)
  # does not become a terminating NativeCommandError in this wrapper.
  $httpsStdOutFile = [System.IO.Path]::GetTempFileName()
  $httpsStdErrFile = [System.IO.Path]::GetTempFileName()
  try {
    $httpsArgList = @("-NoProfile","-ExecutionPolicy","Bypass","-File",$httpsScript) + $httpsArgs
    $httpsProc = Start-Process -FilePath "powershell.exe" `
      -ArgumentList $httpsArgList `
      -Wait `
      -PassThru `
      -NoNewWindow `
      -RedirectStandardOutput $httpsStdOutFile `
      -RedirectStandardError $httpsStdErrFile
    $httpsExitCode = $httpsProc.ExitCode
    $httpsOutput = @()
    if (Test-Path -LiteralPath $httpsStdOutFile) {
      $httpsOutput += Get-Content -LiteralPath $httpsStdOutFile -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $httpsStdErrFile) {
      $httpsOutput += Get-Content -LiteralPath $httpsStdErrFile -ErrorAction SilentlyContinue
    }
  } finally {
    Remove-Item -LiteralPath $httpsStdOutFile,$httpsStdErrFile -Force -ErrorAction SilentlyContinue
  }

  if ($httpsExitCode -ne 0) {
    $details = (($httpsOutput | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine).Trim()
    if (-not $details) { $details = "exit code $httpsExitCode" }
    if ($httpsStrict) {
      throw "HTTPS no-port setup failed. $details"
    }
    Write-Warning ("HTTPS no-port setup failed; continuing with default https://api.local.dev:8443. Details: {0}" -f $details)
  } else {
    if ($httpsOutput.Count -gt 0) {
      $httpsOutput | ForEach-Object { Write-Output $_ }
    }
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

$wslExitCode = $LASTEXITCODE
if ($wslExitCode -ne 0) {
  exit $wslExitCode
}

if ($Command -eq "up") {
  try {
    Sync-WindowsKindKubeconfig -ClusterName $Cluster -DistroName $Distro -RepoWslPath $wslPath
  } catch {
    Write-Warning ("Failed to update Windows kubeconfig for Lens: {0}" -f $_.Exception.Message)
  }
}
