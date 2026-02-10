param(
  # kind cluster name (see: ./bin/kind get clusters)
  [string]$Cluster = "bpl-dev",
  # WSL distro name (see: wsl -l -q)
  [string]$Distro = "Ubuntu-22.04",
  # Where to write the kubeconfig that Lens will import
  [string]$OutFile = ""
)

$ErrorActionPreference = "Stop"

function Die([string]$msg) { throw $msg }

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$wslExe = (Get-Command wsl.exe -ErrorAction SilentlyContinue)
if (-not $wslExe) { Die "wsl.exe not found. Install WSL2 and an Ubuntu distro first." }

if (-not $OutFile) {
  $kubeDir = Join-Path $env:USERPROFILE ".kube"
  New-Item -ItemType Directory -Force -Path $kubeDir | Out-Null
  $OutFile = Join-Path $kubeDir ("kind-{0}.yaml" -f $Cluster)
}

# Convert Windows path -> WSL path (work around backslash stripping in some wsl.exe invocations).
$repoRootForWslpath = $repoRoot -replace '\\','/'
$wslPath = (& wsl.exe wslpath -a "$repoRootForWslpath").ToString().Trim()
if (-not $wslPath) { Die "Failed to convert repo path to WSL path via 'wsl wslpath'." }

# Use repo-pinned kind binary to avoid PATH issues.
$bash = @"
set -euo pipefail
cd '$wslPath'
./bin/kind get kubeconfig --name '$Cluster'
"@

Write-Output "Exporting kubeconfig for kind cluster '$Cluster' from WSL distro '$Distro'..."
$kubeconfig = & wsl.exe -d $Distro -- bash -lc $bash
if (-not $kubeconfig) { Die "No kubeconfig output. Is the cluster running? Try: powershell -ExecutionPolicy Bypass -File .\\scripts\\dev_kind.ps1 status" }

# Write UTF-8 (no BOM). Some tools are picky about UTF-16 / BOM.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutFile, ($kubeconfig -join "`n") + "`n", $utf8NoBom)

$serverLine = ($kubeconfig | Where-Object { $_ -match '^\s*server:\s+' } | Select-Object -First 1)
Write-Output "Wrote: $OutFile"
if ($serverLine) { Write-Output ("API server: {0}" -f $serverLine.Trim()) }

