param(
  [string]$Distro = "Ubuntu-22.04",
  [switch]$SkipApt,
  [switch]$SkipToolBootstrap
)

$ErrorActionPreference = "Stop"

function Die([string]$msg) { throw $msg }

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$wslExe = (Get-Command wsl.exe -ErrorAction SilentlyContinue)
if (-not $wslExe) { Die "wsl.exe not found. Install WSL2 and an Ubuntu distro first." }

# Validate distro exists (best-effort).
try {
  $distros = @(& wsl.exe -l -q 2>$null) | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ }
  if ($distros.Count -gt 0 -and ($distros -notcontains $Distro)) {
    Die ("WSL distro not found: '{0}'. Available: {1}" -f $Distro, ($distros -join ", "))
  }
} catch {
  # Ignore; some environments restrict listing distros.
}

# Convert Windows path -> WSL path (work around backslash stripping in some wsl.exe invocations).
$repoRootForWslpath = $repoRoot -replace '\\','/'
$wslPath = (& wsl.exe wslpath -a "$repoRootForWslpath").ToString().Trim()
if (-not $wslPath) { Die "Failed to convert repo path to WSL path via 'wsl wslpath'." }

Write-Output "WSL distro: $Distro"
Write-Output "Repo (Windows): $repoRoot"
Write-Output "Repo (WSL): $wslPath"

if (-not $SkipApt) {
  # Install base packages required to run the repo Makefile + bootstrap script non-interactively.
  # This runs as root to avoid sudo prompts.
  $pkgs = @(
    "ca-certificates",
    "curl",
    "wget",
    "unzip",
    "git",
    "make",
    "python3",
    "python3-venv",
    "python3-pip",
    "openssl"
  )
  $pkgList = ($pkgs -join " ")
  $aptCmd = @"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y $pkgList
"@

  Write-Output "Installing base packages in WSL (apt, as root)..."
  & wsl.exe -d $Distro -u root -- bash -lc $aptCmd
}

if (-not $SkipToolBootstrap) {
  Write-Output "Bootstrapping pinned tools into ./bin (kubectl/kind/jq/kustomize/etc)..."
  $cmd = "cd '$wslPath' && chmod +x scripts/wsl_bootstrap.sh >/dev/null 2>&1 || true && ./scripts/wsl_bootstrap.sh"
  & wsl.exe -d $Distro -- bash -lc $cmd
}

