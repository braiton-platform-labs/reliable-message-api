Param(
  # WSL distro used for running repo commands (make/bootstrap/dev).
  [string]$Distro = "Ubuntu-22.04",

  # Reboot automatically when Windows optional features require it (default: on).
  [switch]$NoAutoReboot,

  # Skip installing Python via winget (Windows host).
  [switch]$SkipPython
)

$ErrorActionPreference = "Stop"

$devEnv = Join-Path $PSScriptRoot "dev-env.ps1"
if (-not (Test-Path -LiteralPath $devEnv)) {
  throw "dev-env.ps1 not found at $devEnv"
}

$argsList = @("install", "-Distro", $Distro)
if (-not $NoAutoReboot) { $argsList += "-AutoReboot" }
if ($SkipPython) { $argsList += "-SkipPython" }

# Run in a separate process because dev-env.ps1 uses `exit` for CLI semantics.
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $devEnv @argsList
$rc = $LASTEXITCODE

if ($rc -eq 0) {
  Write-Host ""
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $devEnv @("status", "-Distro", $Distro)
  Write-Host ""
  Write-Host "Quick check (Windows):"
  Write-Host "  curl -H ""Host: api.local.dev"" http://localhost:8080/health"
  Write-Host "  curl -sk --resolve api.local.dev:8443:127.0.0.1 https://api.local.dev:8443/health"
}

exit $rc
