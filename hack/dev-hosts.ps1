Param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateSet("status","apply","remove")]
  [string]$Command
)

$ErrorActionPreference = "Stop"

$HostsFile = $Env:HOSTS_FILE
if (-not $HostsFile) {
  $HostsFile = Join-Path $Env:SystemRoot "System32\drivers\etc\hosts"
}

$BeginMarker = "# BEGIN reliable-message-api dev"
$EndMarker = "# END reliable-message-api dev"
$Entries = @(
  "127.0.0.1 api.local.dev",
  "127.0.0.1 kong.local.dev"
)

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Read-HostsLines {
  if (-not (Test-Path -LiteralPath $HostsFile)) {
    throw "hosts file not found: $HostsFile"
  }
  return Get-Content -LiteralPath $HostsFile -ErrorAction Stop
}

function Strip-Block([string[]]$lines) {
  $out = New-Object System.Collections.Generic.List[string]
  $inBlock = $false
  foreach ($line in $lines) {
    if ($line -eq $BeginMarker) { $inBlock = $true; continue }
    if ($line -eq $EndMarker) { $inBlock = $false; continue }
    if (-not $inBlock) { $out.Add($line) | Out-Null }
  }
  return $out.ToArray()
}

function Get-Conflicts([string[]]$lines) {
  $conflicts = New-Object System.Collections.Generic.List[string]
  $inBlock = $false
  foreach ($line in $lines) {
    if ($line -eq $BeginMarker) { $inBlock = $true; continue }
    if ($line -eq $EndMarker) { $inBlock = $false; continue }
    if ($inBlock) { continue }

    $clean = ($line -replace "#.*$", "").Trim()
    if (-not $clean) { continue }
    $parts = $clean -split "\s+"
    if ($parts.Length -lt 2) { continue }

    $ip = $parts[0]
    foreach ($name in $parts[1..($parts.Length-1)]) {
      if (($name -eq "api.local.dev" -or $name -eq "kong.local.dev") -and $ip -ne "127.0.0.1") {
        $conflicts.Add($line) | Out-Null
        break
      }
    }
  }
  return $conflicts.ToArray()
}

function Write-HostsLines([string[]]$lines) {
  if (-not (Test-IsAdmin)) {
    throw "admin privileges required to modify $HostsFile. Re-run PowerShell as Administrator."
  }
  $backup = "$HostsFile.bak.reliable-message-api.$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
  Copy-Item -LiteralPath $HostsFile -Destination $backup -Force

  # hosts file is traditionally ASCII. Use ASCII to avoid BOM/encoding surprises.
  Set-Content -LiteralPath $HostsFile -Value $lines -Encoding Ascii
  Write-Host "Updated $HostsFile"
  Write-Host "Backup:  $backup"
}

function Show-Resolution([string]$hostname) {
  try {
    $addrs = [System.Net.Dns]::GetHostAddresses($hostname) | ForEach-Object { $_.IPAddressToString }
    if ($addrs -and $addrs.Count -gt 0) {
      Write-Host ("{0} -> {1}" -f $hostname, ($addrs -join ", "))
      return
    }
  } catch {}
  Write-Host ("{0} -> (not resolved)" -f $hostname)
}

$lines = Read-HostsLines

switch ($Command) {
  "status" {
    $present = $false
    foreach ($line in $lines) {
      if ($line -eq $BeginMarker) { $present = $true; break }
    }
    if ($present) { Write-Host "hosts block: present" } else { Write-Host "hosts block: missing" }
    Write-Host ""
    Write-Host "Resolution:"
    Show-Resolution "api.local.dev"
    Show-Resolution "kong.local.dev"
    exit 0
  }

  "apply" {
    $conflicts = Get-Conflicts $lines
    if ($conflicts.Length -gt 0) {
      Write-Host "ERROR: found conflicting entries for api.local.dev/kong.local.dev in $HostsFile:" -ForegroundColor Red
      $conflicts | ForEach-Object { Write-Host $_ -ForegroundColor Red }
      throw "conflicting hosts entries"
    }

    $base = Strip-Block $lines
    $newLines = New-Object System.Collections.Generic.List[string]
    $base | ForEach-Object { $newLines.Add($_) | Out-Null }
    $newLines.Add("") | Out-Null
    $newLines.Add($BeginMarker) | Out-Null
    $Entries | ForEach-Object { $newLines.Add($_) | Out-Null }
    $newLines.Add($EndMarker) | Out-Null
    $newLines.Add("") | Out-Null

    Write-HostsLines $newLines.ToArray()
    exit 0
  }

  "remove" {
    $present = $false
    foreach ($line in $lines) {
      if ($line -eq $BeginMarker) { $present = $true; break }
    }
    if (-not $present) {
      Write-Host "No dev block found in $HostsFile (nothing to do)."
      exit 0
    }
    $base = Strip-Block $lines
    Write-HostsLines $base
    exit 0
  }
}

