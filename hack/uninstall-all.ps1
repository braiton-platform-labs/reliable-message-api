Param(
  # WSL distro used for running repo commands (make/bootstrap/dev).
  [string]$Distro = "Ubuntu-22.04",

  # Deprecated: uninstall no longer auto-reboots. Kept for compatibility.
  [switch]$NoAutoReboot,

  # Remove OS-level deps installed by this repo (Docker Desktop, WSL distros/features) using the manifest (default: on).
  [switch]$NoPurge
)

$ErrorActionPreference = "Stop"

$devEnv = Join-Path $PSScriptRoot "dev-env.ps1"
if (-not (Test-Path -LiteralPath $devEnv)) {
  throw "dev-env.ps1 not found at $devEnv"
}

$argsList = @("uninstall", "-Distro", $Distro)
if (-not $NoPurge) { $argsList += "-Purge" }

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $devEnv @argsList
$rc = $LASTEXITCODE

if ($rc -eq 0) {
  Write-Host ""
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $devEnv @("status", "-Distro", $Distro)
}

exit $rc
