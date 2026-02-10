Param(
  [string]$Distro,
  [string]$Command
)

$ErrorActionPreference = "Stop"

function Get-RepoRoot {
  return (Split-Path -Parent $PSScriptRoot)
}

function Convert-ToWslPath([string]$windowsPath) {
  $full = (Resolve-Path $windowsPath).Path

  if ($full -match '^([A-Za-z]):\\(.*)$') {
    $drive = $Matches[1].ToLower()
    $rest = $Matches[2] -replace '\\', '/'
    return "/mnt/$drive/$rest"
  }

  throw "Unsupported path for WSL translation: $full"
}

function Escape-BashSingleQuotes([string]$s) {
  # In bash, you can escape a single quote inside single quotes by closing/opening: 'foo'"'"'bar'
  $rep = "'" + '"' + "'" + '"' + "'"
  return ($s -replace "'", $rep)
}

function Get-InstalledWSLDistros {
  try {
    $raw = & wsl.exe -l -q 2>$null
    if ($LASTEXITCODE -ne 0) { return @() }
    if (-not $raw) { return @() }
    return @(
      $raw |
        ForEach-Object { ($_ -replace "\u0000", "").Trim() } |
        Where-Object { $_ -and $_ -ne "" }
    )
  } catch {
    return @()
  }
}

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
  Write-Host "wsl.exe not found. Install/enable WSL2 first: .\\hack\\install-wsl2.cmd" -ForegroundColor Yellow
  exit 1
}

$distros = Get-InstalledWSLDistros
if ($distros.Count -eq 0) {
  Write-Host "No WSL distributions installed. Install one first: .\\hack\\install-wsl2.cmd" -ForegroundColor Yellow
  exit 1
}

if ($Distro -and -not ($distros -contains $Distro)) {
  Write-Host "Requested distro '$Distro' is not installed. Installed: $($distros -join ', ')" -ForegroundColor Yellow
  exit 1
}

$repoRoot = Get-RepoRoot
$wslRepo = Convert-ToWslPath $repoRoot
$wslRepoEsc = Escape-BashSingleQuotes $wslRepo

$bashCmd = if ($Command) {
  "cd '$wslRepoEsc' && $Command"
} else {
  "cd '$wslRepoEsc' && exec bash -l"
}

$argsList = @()
if ($Distro) { $argsList += @("-d", $Distro) }
# Use --exec so WSL doesn't run the command through the default shell (quoting issues).
$argsList += @("--exec", "bash", "-lc", $bashCmd)

& wsl.exe @argsList
exit $LASTEXITCODE
