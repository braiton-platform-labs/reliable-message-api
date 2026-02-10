Param(
  # Minimum required version. Defaults to the project's declared requirement.
  [string]$MinVersion = "3.11.0",

  # Winget scope. "user" avoids UAC and is typically what we want for dev boxes.
  [ValidateSet("user","machine")]
  [string]$Scope = "user"
)

$ErrorActionPreference = "Stop"

function Require-Winget {
  if (Get-Command winget -ErrorAction SilentlyContinue) { return }
  throw "winget not found. Install 'App Installer' (Microsoft.DesktopAppInstaller) and re-run."
}

function Parse-Version([string]$v) {
  if (-not $v) { return $null }
  try { return [Version]$v } catch { return $null }
}

function Version-Ge([string]$a, [string]$b) {
  $va = Parse-Version $a
  $vb = Parse-Version $b
  if (-not $va -or -not $vb) { return $false }
  return ($va -ge $vb)
}

function Refresh-Session {
  # Best-effort: refresh PATH so newly installed tools are visible in this process.
  $machine = [Environment]::GetEnvironmentVariable("Path","Machine")
  $user = [Environment]::GetEnvironmentVariable("Path","User")

  $wingetUserLinks = Join-Path $env:LOCALAPPDATA "Microsoft\\WinGet\\Links"
  $wingetMachineLinks = Join-Path $Env:ProgramFiles "WinGet\\Links"

  $parts = @(
    $wingetUserLinks,
    $wingetMachineLinks,
    $user,
    $machine
  ) | Where-Object { $_ -and $_.Trim() -ne "" }

  $env:PATH = ($parts -join ";")
}

function Get-PythonVersionFromExe([string]$exePath) {
  if (-not $exePath -or -not (Test-Path -LiteralPath $exePath)) { return $null }
  try {
    $out = & $exePath -c "import sys; print('.'.join(map(str, sys.version_info[:3])))" 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    $text = ($out | Select-Object -First 1).ToString().Trim()
    if ($text -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
    return $null
  } catch {
    return $null
  }
}

function Get-BestPythonCandidate {
  # IMPORTANT: Do not execute the Windows Store alias stub:
  #   %LOCALAPPDATA%\\Microsoft\\WindowsApps\\python.exe / python3.exe
  $cmds = Get-Command "python" -All -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandType -eq "Application" } |
    Where-Object { $_.Source -and ($_.Source -notmatch '\\Microsoft\\WindowsApps\\python(3)?\\.exe$') }

  $best = $null
  foreach ($c in @($cmds)) {
    $ver = Get-PythonVersionFromExe $c.Source
    $vobj = Parse-Version $ver
    if (-not $vobj) { continue }
    if (-not $best -or $vobj -gt $best.versionObj) {
      $best = [ordered]@{
        exe = $c.Source
        version = $ver
        versionObj = $vobj
      }
    }
  }

  return $best
}

function Invoke-WingetInstall([string]$id, [string]$scope) {
  $args = @(
    "install",
    "-e",
    "--id", $id,
    "--source", "winget",
    "--accept-source-agreements",
    "--accept-package-agreements",
    "--silent",
    "--disable-interactivity"
  )
  if ($scope) { $args += @("--scope", $scope) }

  Write-Host "winget install: $id (scope=$scope)"
  & winget @args
  if ($LASTEXITCODE -ne 0) { throw "winget install failed for $id (exit code $LASTEXITCODE)" }
}

if ($env:OS -notlike "*Windows*") {
  throw "This script is intended for Windows."
}

$pre = Get-BestPythonCandidate
if ($pre -and $pre.version -and (Version-Ge $pre.version $MinVersion)) {
  Write-Host "python detected: $($pre.version) OK (>= $MinVersion)"
  Write-Output (([ordered]@{
    installed = $false
    wingetId = $null
    pythonExe = $pre.exe
    pythonVersion = $pre.version
  } | ConvertTo-Json -Compress))
  exit 0
}

Require-Winget
Refresh-Session

$candidates = @(
  "Python.Python.3.14",
  "Python.Python.3.13",
  "Python.Python.3.12",
  "Python.Python.3.11"
)

$installedId = $null
foreach ($id in $candidates) {
  try {
    Invoke-WingetInstall $id $Scope
    $installedId = $id
    break
  } catch {
    Write-Host "winget install failed for $id; trying next candidate..." -ForegroundColor Yellow
  }
}

if (-not $installedId) {
  throw "Failed to install Python via winget (all candidates failed): $($candidates -join ', ')"
}

Refresh-Session

$post = Get-BestPythonCandidate
if (-not $post -or -not $post.version) {
  Write-Host "Python installed, but not detected in this session. Open a new terminal and run: python --version" -ForegroundColor Yellow
  Write-Output (([ordered]@{
    installed = $true
    wingetId = $installedId
    pythonExe = $null
    pythonVersion = $null
  } | ConvertTo-Json -Compress))
  exit 0
}

if (-not (Version-Ge $post.version $MinVersion)) {
  throw "Python version too old after install: $($post.version) (min: $MinVersion)"
}

Write-Host "python installed: $($post.version)"
Write-Output (([ordered]@{
  installed = $true
  wingetId = $installedId
  pythonExe = $post.exe
  pythonVersion = $post.version
} | ConvertTo-Json -Compress))

