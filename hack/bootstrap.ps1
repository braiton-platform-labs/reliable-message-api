Param(
  [string]$VersionsFile = "./hack/tool-versions.env"
)

$ErrorActionPreference = "Stop"

$swTotal = [System.Diagnostics.Stopwatch]::StartNew()

$RootDir = Split-Path -Parent $PSScriptRoot
$BinDir = Join-Path $RootDir "bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$SummaryOrder = @(
  "apt-system","network-tools","curl","wget","unzip","git","make","python3","openssl",
  "docker","mkcert","kubectl","kind","kube-context","jq","kustomize","kubeconform"
)
$Summary = [ordered]@{}
$SummaryOrder | ForEach-Object { $Summary[$_] = "PENDING" }
$WingetUsed = [ordered]@{}
$HadFailure = $false
$script:HasWinget = $false

function Write-StepErrorDetails($err) {
  if (-not (Test-Truthy $env:BOOTSTRAP_DEBUG)) { return }

  try {
    if ($err.InvocationInfo -and $err.InvocationInfo.ScriptName) {
      Write-Host ("at {0}:{1}" -f $err.InvocationInfo.ScriptName, $err.InvocationInfo.ScriptLineNumber) -ForegroundColor DarkGray
      if ($err.InvocationInfo.Line) {
        Write-Host $err.InvocationInfo.Line.TrimEnd() -ForegroundColor DarkGray
      }
    }
    if ($err.ScriptStackTrace) {
      Write-Host $err.ScriptStackTrace -ForegroundColor DarkGray
    }
  } catch {
    # Best-effort debug output only.
  }
}

function Load-Versions($path) {
  if (-not (Test-Path $path)) { return }
  Get-Content $path | ForEach-Object {
    if ($_ -match '^\s*#') { return }
    if ($_ -match '^\s*$') { return }
    $parts = $_.Split('=', 2)
    if ($parts.Length -eq 2) {
      Set-Item -Path "Env:$($parts[0])" -Value $parts[1]
    }
  }
}

function Update-ToolVersions($path, $key, $value) {
  if (-not (Test-Path $path)) { return }
  $content = Get-Content $path
  $pattern = "^$key="
  $updated = $false
  $content = $content | ForEach-Object {
    if ($_ -match $pattern) {
      $updated = $true
      "$key=$value"
    } else {
      $_
    }
  }
  if (-not $updated) {
    $content += "$key=$value"
  }
  Set-Content -Path $path -Value $content
}

Load-Versions $VersionsFile

$kubectlVersion = $Env:KUBECTL_VERSION
$kindVersion = $Env:KIND_VERSION
$jqVersion = $Env:JQ_VERSION
$gitVersion = $Env:GIT_VERSION
$makeVersion = $Env:MAKE_VERSION
$pythonVersion = $Env:PYTHON_VERSION
$opensslMinVersion = $Env:OPENSSL_MIN_VERSION
$curlMinVersion = $Env:CURL_MIN_VERSION
$wgetMinVersion = $Env:WGET_MIN_VERSION
$unzipMinVersion = $Env:UNZIP_MIN_VERSION
$mkcertVersion = $Env:MKCERT_VERSION
$kustomizeVersion = $Env:KUSTOMIZE_VERSION
$kubeconformVersion = $Env:KUBECONFORM_VERSION
$dockerEngineMinVersion = $Env:DOCKER_ENGINE_MIN_VERSION
$dockerDesktopMinVersion = $Env:DOCKER_DESKTOP_MIN_VERSION
$bootstrapInstallMode = $Env:BOOTSTRAP_INSTALL_MODE
$bootstrapGlobalBinDir = $Env:BOOTSTRAP_GLOBAL_BIN_DIR
$bootstrapEnforceGlobalBin = $Env:BOOTSTRAP_ENFORCE_GLOBAL_BIN
$kindClusterName = $Env:KIND_CLUSTER_NAME
$bootstrapExpectedKubeContext = $Env:BOOTSTRAP_EXPECTED_KUBE_CONTEXT
$bootstrapAutoKubeContext = $Env:BOOTSTRAP_AUTO_KUBECONTEXT

if (-not $kubectlVersion) { $kubectlVersion = "v1.35.0" }
if (-not $kindVersion) { $kindVersion = "v0.30.0" }
if (-not $jqVersion) { $jqVersion = "1.8.1" }
if (-not $gitVersion) { $gitVersion = "2.34.0" }
if (-not $makeVersion) { $makeVersion = "4.3" }
if (-not $pythonVersion) { $pythonVersion = "3.8.0" }
if (-not $opensslMinVersion) { $opensslMinVersion = "1.1.1" }
if (-not $curlMinVersion) { $curlMinVersion = "7.68.0" }
if (-not $wgetMinVersion) { $wgetMinVersion = "1.20.0" }
if (-not $unzipMinVersion) { $unzipMinVersion = "6.0" }
if (-not $mkcertVersion) { $mkcertVersion = "1.4.4" }
if (-not $kustomizeVersion) { $kustomizeVersion = "5.8.0" }
if (-not $kubeconformVersion) { $kubeconformVersion = "0.7.0" }
if (-not $dockerEngineMinVersion) { $dockerEngineMinVersion = "28.0.0" }
if (-not $dockerDesktopMinVersion) { $dockerDesktopMinVersion = "4.56.0" }
if (-not $bootstrapInstallMode) { $bootstrapInstallMode = "system" }
if (-not $bootstrapGlobalBinDir) { $bootstrapGlobalBinDir = "$Env:ProgramFiles\reliable-message-api\bin" }
if (-not $bootstrapEnforceGlobalBin) { $bootstrapEnforceGlobalBin = "1" }
if (-not $kindClusterName) { $kindClusterName = "bpl-dev" }
if (-not $bootstrapExpectedKubeContext) { $bootstrapExpectedKubeContext = "kind-$kindClusterName" }
if (-not $bootstrapAutoKubeContext) { $bootstrapAutoKubeContext = "1" }

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Test-Truthy($value) {
  if (-not $value) { return $false }
  return ($value -in @("1","true","True","TRUE","yes","YES","on","ON"))
}

function Resolve-InstallDir {
  if ($bootstrapInstallMode -eq "local") { return $BinDir }
  if (Test-Truthy $bootstrapEnforceGlobalBin) { return $bootstrapGlobalBinDir }
  return $bootstrapGlobalBinDir
}

$InstallBinDir = Resolve-InstallDir
if (-not (Test-Path $InstallBinDir)) {
  $canCreate = $true
  try {
    New-Item -ItemType Directory -Force -Path $InstallBinDir | Out-Null
  } catch {
    $canCreate = $false
  }
  if (-not $canCreate) {
    if (Test-Truthy $bootstrapEnforceGlobalBin) {
      throw "failed to create global install dir $InstallBinDir. Run PowerShell as Administrator or set BOOTSTRAP_ENFORCE_GLOBAL_BIN=0."
    }
    $InstallBinDir = $BinDir
    New-Item -ItemType Directory -Force -Path $InstallBinDir | Out-Null
  }
}

if ($env:PATH -notlike "*$InstallBinDir*") {
  Write-Host "add to PATH: $InstallBinDir"
  $env:PATH = "$InstallBinDir;$env:PATH"
}
if ($InstallBinDir -ne $BinDir -and $env:PATH -notlike "*$BinDir*") {
  $env:PATH = "$BinDir;$env:PATH"
}

$WingetUserLinksDir = Join-Path $env:LOCALAPPDATA "Microsoft\\WinGet\\Links"
$WingetMachineLinksDir = Join-Path $Env:ProgramFiles "WinGet\\Links"
foreach ($d in @($WingetUserLinksDir, $WingetMachineLinksDir)) {
  if ($d -and (Test-Path $d) -and ($env:PATH -notlike "*$d*")) {
    $env:PATH = "$d;$env:PATH"
  }
}

Write-Host "Target versions (security/compat): kubectl=$kubectlVersion kind=$kindVersion jq=$jqVersion mkcert=$mkcertVersion kustomize=$kustomizeVersion kubeconform=$kubeconformVersion docker>=$dockerEngineMinVersion git>=$gitVersion make>=$makeVersion python>=$pythonVersion openssl>=$opensslMinVersion curl>=$curlMinVersion wget>=$wgetMinVersion unzip>=$unzipMinVersion"
Write-Host "SHA256 verification enabled for kubectl, kind, jq, mkcert, kustomize, kubeconform downloads."
Write-Host "Set BOOTSTRAP_AUTO_CONFIRM=1 to auto-accept reinstalls."
Write-Host "global binary mode: BOOTSTRAP_ENFORCE_GLOBAL_BIN=$bootstrapEnforceGlobalBin, install dir=$InstallBinDir"
Write-Host "kube context controls: BOOTSTRAP_EXPECTED_KUBE_CONTEXT=$bootstrapExpectedKubeContext BOOTSTRAP_AUTO_KUBECONTEXT=$bootstrapAutoKubeContext"

function Require-Winget {
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    $script:HasWinget = $true
    return
  }
  Write-Host "winget not found. Install App Installer from Microsoft Store (optional; bootstrap can still download pinned tools directly)." -ForegroundColor Yellow
  $script:HasWinget = $false
}

Require-Winget

function Get-AppCommand($name) {
  # Avoid PowerShell aliases like `curl`/`wget` that map to Invoke-WebRequest.
  return Get-Command $name -All -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandType -eq "Application" } |
    Select-Object -First 1
}

function Resolve-ExePath($exeName, $commandName) {
  foreach ($p in @((Join-Path $InstallBinDir $exeName), (Join-Path $BinDir $exeName))) {
    if ($p -and (Test-Path $p)) { return $p }
  }
  $cmdInfo = Get-AppCommand $commandName
  if ($cmdInfo) { return $cmdInfo.Source }
  return $null
}

function ConvertTo-Text($output) {
  if ($null -eq $output) { return $null }
  if ($output -is [array]) { return ($output -join "`n") }
  return [string]$output
}

function Invoke-NativeOutput($exe, [string[]]$argv) {
  if (-not $exe) { return $null }

  $oldEap = $ErrorActionPreference
  $hadNativePref = $false
  $oldNativePref = $null
  try {
    if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
      $hadNativePref = $true
      $oldNativePref = $PSNativeCommandUseErrorActionPreference
      $PSNativeCommandUseErrorActionPreference = $false
    }
  } catch {
    # ignore
  }

  $ErrorActionPreference = "Continue"
  try {
    $out = & $exe @argv 2>$null
    return (ConvertTo-Text $out)
  } catch {
    return $null
  } finally {
    $ErrorActionPreference = $oldEap
    if ($hadNativePref) {
      try { $PSNativeCommandUseErrorActionPreference = $oldNativePref } catch {}
    }
  }
}

function Get-CommandVersion($cmd, $pattern) {
  $cmdInfo = Get-AppCommand $cmd
  if (-not $cmdInfo) { return $null }

  $text = Invoke-NativeOutput $cmdInfo.Source @("--version")
  if ($text -match $pattern) { return $Matches[1] }
  return $null
}

function Get-KubectlVersion {
  $exe = Resolve-ExePath "kubectl.exe" "kubectl"
  if (-not $exe) { return $null }

  $text = Invoke-NativeOutput $exe @("version","--client","-o","yaml")
  if (-not $text) { return $null }

  if ($text -match 'gitVersion:\s*(v?\d+\.\d+\.\d+)') { return $Matches[1] }
  if ($text -match 'GitVersion:\"(v?\d+\.\d+\.\d+)\"') { return $Matches[1] }
  return $null
}

function Get-KindVersion {
  $exe = Resolve-ExePath "kind.exe" "kind"
  if (-not $exe) { return $null }

  $text = Invoke-NativeOutput $exe @("version")
  if ($text -match '(v\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-JqVersion {
  $exe = Resolve-ExePath "jq.exe" "jq"
  if (-not $exe) { return $null }

  $text = Invoke-NativeOutput $exe @("--version")
  if ($text -match 'jq-(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-MkcertVersion {
  $exe = Resolve-ExePath "mkcert.exe" "mkcert"
  if (-not $exe) { return $null }
  $text = Invoke-NativeOutput $exe @("-version")
  if ($text -match 'v?(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Normalize-Version($v) {
  if (-not $v) { return $null }
  if ($v -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Version-Ge($current, $min) {
  $c = Normalize-Version $current
  $m = Normalize-Version $min
  if (-not $c -or -not $m) { return $false }
  return ([version]$c -ge [version]$m)
}

function Invoke-Download($url, $out, $retries = 3) {
  $curlCmd = Get-AppCommand "curl"
  if (-not $curlCmd) {
    $curlPath = Join-Path $env:SystemRoot "System32\\curl.exe"
    if (Test-Path $curlPath) { $curlCmd = [pscustomobject]@{ Source = $curlPath } }
  }
  for ($i = 1; $i -le $retries; $i++) {
    Write-Host "download (attempt $i/$retries): $url"
    try {
      if ($curlCmd) {
        & $curlCmd.Source --fail --location --silent --show-error --retry 3 --retry-delay 2 --output $out $url 2>$null | Out-Null
      } else {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
          Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing | Out-Null
        } else {
          Invoke-WebRequest -Uri $url -OutFile $out | Out-Null
        }
      }
      if ((Test-Path $out) -and (Get-Item $out).Length -gt 0) { return }
    } catch {
      Write-Host "download failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    Start-Sleep -Seconds (2 * $i)
  }
  Write-Host "download failed after $retries attempts: $url" -ForegroundColor Red
  throw "bootstrap step failed"
}

function Invoke-DownloadOptional($url, $out) {
  try {
    Invoke-Download $url $out 1
    return $true
  } catch {
    return $false
  }
}

function Verify-Sha256File($file, $checksumUrl) {
  $checksumFile = Join-Path $env:TEMP "checksum.txt"
  Invoke-Download $checksumUrl $checksumFile
  $raw = (Get-Content $checksumFile -Raw)
  $expected = $null
  if ($raw -match '([0-9a-fA-F]{64})') { $expected = $Matches[1] }
  if (-not $expected) {
    Write-Host "checksum not found at $checksumUrl" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  $actual = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
  if ($expected.ToLower() -ne $actual) {
    Write-Host "checksum mismatch for $file" -ForegroundColor Red
    Write-Host "expected: $expected"
    Write-Host "actual:   $actual"
    throw "bootstrap step failed"
  }
}

function Verify-Sha256Checksums($file, $checksumsUrl, $assetName = $null) {
  $checksumFile = Join-Path $env:TEMP "checksums.txt"
  Invoke-Download $checksumsUrl $checksumFile
  $filename = $assetName
  if (-not $filename) { $filename = Split-Path $file -Leaf }

  $expected = $null
  foreach ($line in (Get-Content $checksumFile)) {
    if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') {
      $hash = $Matches[1]
      $name = $Matches[2].Trim()
      if ($name -eq $filename) {
        $expected = $hash
        break
      }
    }
  }
  if (-not $expected) {
    Write-Host "checksum for $filename not found at $checksumsUrl" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  $actual = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
  if ($expected.ToLower() -ne $actual) {
    Write-Host "checksum mismatch for $file" -ForegroundColor Red
    Write-Host "expected: $expected"
    Write-Host "actual:   $actual"
    throw "bootstrap step failed"
  }
}

function Install-BinaryFile($source, $targetName) {
  $targetPath = Join-Path $InstallBinDir $targetName
  try {
    Copy-Item -Force $source $targetPath
  } catch {
    if (Test-Truthy $bootstrapEnforceGlobalBin) {
      throw "failed to install $targetName into $InstallBinDir. Re-run PowerShell as Administrator or set BOOTSTRAP_ENFORCE_GLOBAL_BIN=0."
    }
    Copy-Item -Force $source (Join-Path $BinDir $targetName)
    return
  }
}

function Install-Kubectl($version) {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
  $exe = Join-Path $env:TEMP "kubectl.exe"
  $url = "https://dl.k8s.io/release/$version/bin/windows/$arch/kubectl.exe"
  $sha = "$url.sha256"
  Write-Host "installing kubectl $version"
  Invoke-Download $url $exe
  Verify-Sha256File $exe $sha
  Install-BinaryFile $exe "kubectl.exe"
}

function Install-Kind($version) {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
  $exe = Join-Path $env:TEMP "kind.exe"
  $url = "https://kind.sigs.k8s.io/dl/$version/kind-windows-$arch"
  $sha = "$url.sha256sum"
  Write-Host "installing kind $version"
  Invoke-Download $url $exe
  Verify-Sha256File $exe $sha
  Install-BinaryFile $exe "kind.exe"
}

function Install-Jq($version) {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
  $checksums = "https://github.com/jqlang/jq/releases/download/jq-$version/sha256sum.txt"
  $checksumsFile = Join-Path $env:TEMP "jq-sha256sum.txt"
  Invoke-Download $checksums $checksumsFile

  $asset = $null
  foreach ($line in (Get-Content $checksumsFile)) {
    if ($line -match "^[0-9a-fA-F]{64}\s+\*?(jq-windows-$arch(\.exe)?)\s*$") {
      $asset = $Matches[1]
      break
    }
  }
  if (-not $asset) {
    Write-Host "jq checksum entry not found for windows/$arch at $checksums" -ForegroundColor Red
    throw "bootstrap step failed"
  }

  $exe = Join-Path $env:TEMP $asset
  $url = "https://github.com/jqlang/jq/releases/download/jq-$version/$asset"
  Write-Host "installing jq $version"
  Invoke-Download $url $exe
  Verify-Sha256Checksums $exe $checksums $asset
  Install-BinaryFile $exe "jq.exe"
}

function Install-Mkcert($version) {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
  $exe = Join-Path $env:TEMP "mkcert-v$version-windows-$arch.exe"
  $url = "https://github.com/FiloSottile/mkcert/releases/download/v$version/mkcert-v$version-windows-$arch.exe"
  $sha = "$url.sha256"
  Write-Host "installing mkcert $version"
  Invoke-Download $url $exe
  if (Invoke-DownloadOptional $sha (Join-Path $env:TEMP "mkcert.sha256")) {
    Verify-Sha256File $exe $sha
  } else {
    Write-Host "warning: mkcert release does not provide $sha; proceeding without checksum verification for this artifact" -ForegroundColor Yellow
  }
  Install-BinaryFile $exe "mkcert.exe"
}

function Get-KustomizeVersion {
  $exe = Resolve-ExePath "kustomize.exe" "kustomize"
  if (-not $exe) { return $null }
  $text = Invoke-NativeOutput $exe @("version")
  if ($text -match 'v?(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-KubeconformVersion {
  $exe = Resolve-ExePath "kubeconform.exe" "kubeconform"
  if (-not $exe) { return $null }

  # kubeconform prints version with `-v`.
  $text = Invoke-NativeOutput $exe @("-v")
  if ($text -match 'v?(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-DockerVersion {
  $cmdInfo = Get-AppCommand "docker"
  if (-not $cmdInfo) { return $null }
  $text = Invoke-NativeOutput $cmdInfo.Source @("version","--format","{{.Server.Version}}")
  return (Normalize-Version $text)
}

function Get-GitVersion {
  $cmdInfo = Get-AppCommand "git"
  if (-not $cmdInfo) { return $null }
  $text = Invoke-NativeOutput $cmdInfo.Source @("--version")
  if ($text -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-MakeVersion {
  $cmdInfo = Get-AppCommand "make"
  if (-not $cmdInfo) { return $null }
  $text = Invoke-NativeOutput $cmdInfo.Source @("--version")
  if ($text -match '(\d+\.\d+(\.\d+)?)') { return $Matches[1] }
  return $null
}

function Get-PythonVersion {
  $cmdInfo = Get-Command "python" -All -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandType -eq "Application" } |
    Where-Object { $_.Source -and ($_.Source -notmatch '\\Microsoft\\WindowsApps\\python(3)?\\.exe$') } |
    Select-Object -First 1
  if (-not $cmdInfo) { return $null }

  # Avoid `python --version`/`-V` stderr quirks; print a clean version to stdout.
  $text = Invoke-NativeOutput $cmdInfo.Source @("-c","import sys; print('.'.join(map(str, sys.version_info[:3])))")
  if ($text -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-OpenSSLVersion {
  $cmdInfo = Get-AppCommand "openssl"
  if (-not $cmdInfo) { return $null }
  $text = Invoke-NativeOutput $cmdInfo.Source @("version")
  if ($text -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-CurlVersion {
  $exe = Resolve-ExePath "curl.exe" "curl"
  if (-not $exe) {
    $fallback = Join-Path $env:SystemRoot "System32\\curl.exe"
    if (Test-Path $fallback) { $exe = $fallback }
  }
  if (-not $exe) { return $null }
  $text = Invoke-NativeOutput $exe @("--version")
  if ($text -match 'curl (\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-WgetVersion {
  $cmdInfo = Get-AppCommand "wget"
  if (-not $cmdInfo) { return $null }
  $text = Invoke-NativeOutput $cmdInfo.Source @("--version")
  if ($text -match 'GNU Wget (\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-UnzipVersion {
  $cmdInfo = Get-AppCommand "unzip"
  if (-not $cmdInfo) { return $null }
  $text = Invoke-NativeOutput $cmdInfo.Source @("-v")
  if ($text -match 'UnZip (\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Show-Version($name, $value) {
  if (-not $value) { $value = "not found" }
  Write-Host ("{0,-12} {1}" -f "${name}:", $value)
}

function Measure-Block($name, [scriptblock]$block) {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  & $block
  $sw.Stop()
  Write-Host "$name took $([math]::Round($sw.Elapsed.TotalSeconds, 1))s"
}

function Run-Step($name, [scriptblock]$block) {
  try {
    Measure-Block $name $block
    $Summary[$name] = "OK"
  } catch {
    $Summary[$name] = "FAIL"
    $script:HadFailure = $true
    Write-Host "$name failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StepErrorDetails $_
  }
}

function Run-SoftStep($name, [scriptblock]$block) {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $status = & $block
    if (-not $status) { $status = "OK" }
    if ($status -notin @("OK","WARN","FAIL")) { $status = "OK" }
    $Summary[$name] = $status
    if ($status -eq "FAIL") {
      $script:HadFailure = $true
      Write-Host "$name failed" -ForegroundColor Red
    }
  } catch {
    $Summary[$name] = "FAIL"
    $script:HadFailure = $true
    Write-Host "$name failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-StepErrorDetails $_
  } finally {
    $sw.Stop()
    Write-Host "$name took $([math]::Round($sw.Elapsed.TotalSeconds, 1))s"
  }
}

function Get-CurrentKubeContext {
  $exe = Resolve-ExePath "kubectl.exe" "kubectl"
  if (-not $exe) { return $null }
  $ctx = Invoke-NativeOutput $exe @("config","current-context")
  if (-not $ctx) { return $null }
  $ctx = $ctx.Trim()
  if (-not $ctx) { return $null }
  return $ctx
}

function Ensure-KubeContext($expected, $autoSwitch) {
  $exe = Resolve-ExePath "kubectl.exe" "kubectl"
  if (-not $exe) {
    Write-Host "kubectl not found; skipping kube context validation" -ForegroundColor Yellow
    return "WARN"
  }

  $contextsText = Invoke-NativeOutput $exe @("config","get-contexts","-o","name")
  if (-not $contextsText) {
    Write-Host "unable to read kube contexts from kubectl config" -ForegroundColor Yellow
    return "WARN"
  }
  $contexts = $contextsText.Split("`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ }

  if (-not ($contexts -contains $expected)) {
    Write-Host "kube context $expected not found yet" -ForegroundColor Yellow
    Write-Host "create it with: kind create cluster --name $kindClusterName"
    return "WARN"
  }

  $current = Get-CurrentKubeContext
  if ($current -eq $expected) {
    Write-Host "kube context OK: $current"
    return "OK"
  }

  if (Test-Truthy $autoSwitch) {
    Write-Host "switching kube context to $expected"
    $null = Invoke-NativeOutput $exe @("config","use-context",$expected)
    if ((Get-CurrentKubeContext) -eq $expected) {
      Write-Host "kube context switched to $expected"
      return "OK"
    }
    Write-Host "failed to switch kube context automatically" -ForegroundColor Yellow
    return "WARN"
  }

  Write-Host "current kube context is $current; expected $expected" -ForegroundColor Yellow
  Write-Host "run: kubectl config use-context $expected"
  Write-Host "or set BOOTSTRAP_AUTO_KUBECONTEXT=1 to auto-switch during bootstrap"
  return "WARN"
}

function Should-Reinstall($name, $current, $desired) {
  if ($env:BOOTSTRAP_AUTO_CONFIRM -eq "1" -or $env:BOOTSTRAP_AUTO_CONFIRM -eq "true") {
    Write-Host "auto-confirm enabled; proceeding to reinstall $name"
    return $true
  }
  if ($Host.Name -ne "ConsoleHost") {
    Write-Host "Non-interactive shell; set BOOTSTRAP_AUTO_CONFIRM=1 to allow reinstall." -ForegroundColor Red
    throw "bootstrap step failed"
  }
  Write-Host "$name version mismatch: current=$current desired=$desired"
  Write-Host "Reinstalling improves security and compatibility."
  $reply = Read-Host "Proceed? [y/N]"
  if ($reply -match '^(y|yes)$') { return $true }
  Write-Host "Aborting; user declined $name reinstall." -ForegroundColor Red
  throw "bootstrap step failed"
}

function Invoke-WingetInstall($id, $desiredVersion = $null, $retries = 3, [string]$scope = $null) {
  for ($i = 1; $i -le $retries; $i++) {
    $args = @(
      "install",
      "-e",
      "--id", $id,
      "--accept-source-agreements",
      "--accept-package-agreements",
      "--silent",
      "--disable-interactivity"
    )
    if ($desiredVersion) { $args += @("--version", $desiredVersion) }
    if ($scope) { $args += @("--scope", $scope) }

    if ($desiredVersion) {
      Write-Host "winget install (attempt $i/$retries): $id $desiredVersion"
    } else {
      Write-Host "winget install (attempt $i/$retries): $id"
    }
    winget @args
    if ($LASTEXITCODE -eq 0) { return }
    Write-Host "winget install failed ($i/$retries). Retrying..." -ForegroundColor Yellow
    Start-Sleep -Seconds (2 * $i)
  }
  Write-Host "winget install failed after $retries attempts." -ForegroundColor Red
  throw "bootstrap step failed"
}

function Invoke-WingetInstallAny($name, $ids, $desiredVersion = $null, [string]$scope = $null) {
  foreach ($id in $ids) {
    try {
      Invoke-WingetInstall $id $desiredVersion 3 $scope
      if (-not $script:WingetUsed) { $script:WingetUsed = [ordered]@{} }
      $script:WingetUsed[$name] = $id
      return $id
    } catch {
      Write-Host "winget install failed for $id; trying next candidate..." -ForegroundColor Yellow
    }
  }
  if ($desiredVersion) {
    foreach ($id in $ids) {
      try {
        Invoke-WingetInstall $id $null 3 $scope
        if (-not $script:WingetUsed) { $script:WingetUsed = [ordered]@{} }
        $script:WingetUsed[$name] = $id
        return $id
      } catch {
        Write-Host "winget install (no version) failed for $id; trying next candidate..." -ForegroundColor Yellow
      }
    }
  }
  Write-Host "winget install failed for all candidates: $($ids -join ', ')" -ForegroundColor Red
  throw "bootstrap step failed"
}

function Invoke-WingetUninstall($id, $retries = 3) {
  for ($i = 1; $i -le $retries; $i++) {
    Write-Host "winget uninstall (attempt $i/$retries): $id"
    $out = winget uninstall -e --id $id --silent --force --accept-source-agreements --disable-interactivity 2>&1
    if ($LASTEXITCODE -eq 0) { return }
    if ($out -match "No installed package found") { return }
    Write-Host "winget uninstall failed ($i/$retries). Retrying..." -ForegroundColor Yellow
    Start-Sleep -Seconds (2 * $i)
  }
  Write-Host "winget uninstall failed after $retries attempts." -ForegroundColor Red
  throw "bootstrap step failed"
}

function Ensure-WingetPackage($id, $name, $desiredVersion, $versionPattern, $cmdName) {
  $current = Get-CommandVersion $cmdName $versionPattern
  if ($current) {
    Write-Host "$name detected: $current (desired: $desiredVersion)"
  } else {
    Write-Host "$name detected: not found (desired: $desiredVersion)"
  }
  if ($current -eq $desiredVersion) {
    Write-Host "$name $current already installed"
    return
  }
  if ($current) {
    Should-Reinstall $name $current $desiredVersion | Out-Null
    Write-Host "Removing $name $current"
    Invoke-WingetUninstall $id
  }
  Write-Host "Installing $name $desiredVersion"
  Invoke-WingetInstall $id $desiredVersion
  $current = Get-CommandVersion $cmdName $versionPattern
  if (-not $current) {
    Write-Host "Error: $name did not install correctly (version not detected)" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  if ($current -ne $desiredVersion) {
    Write-Host "Error: $name version is $current, expected $desiredVersion" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  Write-Host "$name installed: $current"
}

function Ensure-Git($version) {
  $current = Get-GitVersion
  if ($current) { Write-Host "git detected: $current (desired: $version)" } else { Write-Host "git detected: not found (desired: $version)" }
  if ($current -and (Version-Ge $current $version)) { Write-Host "git $current OK (>= $version)"; return }
  if ($current) { Should-Reinstall "git" $current $version | Out-Null }
  Invoke-WingetInstallAny "git" @("Git.Git","GitHub.GitHubDesktop") $version | Out-Null
  $current = Get-GitVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: git version is $current, expected >= $version" -ForegroundColor Red; throw "bootstrap step failed" }
  Write-Host "git installed: $current"
}

function Ensure-Make($version) {
  $current = Get-MakeVersion
  if ($current) { Write-Host "make detected: $current (desired: $version)" } else { Write-Host "make detected: not found (desired: $version)" }
  if ($current -and (Version-Ge $current $version)) { Write-Host "make $current OK (>= $version)"; return }
  if ($current) { Should-Reinstall "make" $current $version | Out-Null }
  Invoke-WingetInstallAny "make" @("GnuWin32.Make","GnuWin.Make","MSYS2.MSYS2") $version | Out-Null
  $current = Get-MakeVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: make version is $current, expected >= $version" -ForegroundColor Red; throw "bootstrap step failed" }
  Write-Host "make installed: $current"
}

function Ensure-Python($version) {
  $current = Get-PythonVersion
  if ($current) { Write-Host "python detected: $current (desired: $version)" } else { Write-Host "python detected: not found (desired: $version)" }
  if ($current -and (Version-Ge $current $version)) { Write-Host "python $current OK (>= $version)"; return }
  if ($current) { Should-Reinstall "python" $current $version | Out-Null }

  # Install in user scope (no UAC) and avoid the Microsoft Store "python.exe" stub.
  Invoke-WingetInstallAny "python" @("Python.Python.3.14","Python.Python.3.13","Python.Python.3.12") $version "user" | Out-Null
  $current = Get-PythonVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: python version is $current, expected >= $version" -ForegroundColor Red; throw "bootstrap step failed" }
  Write-Host "python installed: $current"
}

function Ensure-OpenSSL($version) {
  $current = Get-OpenSSLVersion
  if ($current) { Write-Host "openssl detected: $current (desired: $version)" } else { Write-Host "openssl detected: not found (desired: $version)" }
  if ($current -and (Version-Ge $current $version)) { Write-Host "openssl $current OK (>= $version)"; return }
  if ($current) { Should-Reinstall "openssl" $current $version | Out-Null }
  Invoke-WingetInstallAny "openssl" @("OpenSSL.OpenSSL","ShiningLight.OpenSSL") | Out-Null
  $current = Get-OpenSSLVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: openssl version is $current, expected >= $version" -ForegroundColor Red; throw "bootstrap step failed" }
  Write-Host "openssl installed: $current"
}

function Ensure-Curl($version) {
  $current = Get-CurlVersion
  if ($current) { Write-Host "curl detected: $current (desired: $version)" } else { Write-Host "curl detected: not found (desired: $version)" }
  if ($current -and (Version-Ge $current $version)) { Write-Host "curl $current OK (>= $version)"; return }
  if ($current) { Should-Reinstall "curl" $current $version | Out-Null }
  Invoke-WingetInstallAny "curl" @("cURL.cURL") | Out-Null
  $current = Get-CurlVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: curl version is $current, expected >= $version" -ForegroundColor Red; throw "bootstrap step failed" }
  Write-Host "curl installed: $current"
}

function Ensure-Wget($version) {
  $current = Get-WgetVersion
  if ($current) { Write-Host "wget detected: $current (desired: $version)" } else { Write-Host "wget detected: not found (desired: $version)" }
  if ($current -and (Version-Ge $current $version)) { Write-Host "wget $current OK (>= $version)"; return }
  if ($current) { Should-Reinstall "wget" $current $version | Out-Null }
  Invoke-WingetInstallAny "wget" @("GnuWin32.Wget","JernejSimoncic.Wget") | Out-Null
  $current = Get-WgetVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: wget version is $current, expected >= $version" -ForegroundColor Red; throw "bootstrap step failed" }
  Write-Host "wget installed: $current"
}

function Ensure-Unzip($version) {
  $current = Get-UnzipVersion
  if ($current) { Write-Host "unzip detected: $current (desired: $version)" } else { Write-Host "unzip detected: not found (desired: $version)" }
  if ($current -eq $version) { Write-Host "unzip $current already installed"; return }
  if ($current) { Should-Reinstall "unzip" $current $version | Out-Null }
  Invoke-WingetInstallAny "unzip" @("GnuWin32.UnZip","GnuWin32.Unzip","7zip.7zip") | Out-Null
  $current = Get-UnzipVersion
  if (-not $current) {
    if (Get-Command 7z -ErrorAction SilentlyContinue) {
      Write-Host "Using 7zip as unzip provider"
      $current = "7zip"
    }
  }
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: unzip version is $current, expected >= $version" -ForegroundColor Red; throw "bootstrap step failed" }
  Write-Host "unzip installed: $current"
}

function Ensure-Kubectl($version) {
  $current = Get-KubectlVersion
  if ($current) {
    Write-Host "kubectl detected: $current (desired: $version)"
  } else {
    Write-Host "kubectl detected: not found (desired: $version)"
  }
  if ($current -eq $version) {
    Write-Host "kubectl $current already installed"
    return
  }
  if ($current) { Write-Host "installing pinned kubectl $version into $InstallBinDir (existing: $current)" }
  Install-Kubectl $version
  $WingetUsed["kubectl"] = "direct"
  $current = Get-KubectlVersion
  if ($current -ne $version) {
    Write-Host "Error: kubectl version is $current, expected $version" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  Write-Host "kubectl installed: $current"
}

function Ensure-Kind($version) {
  $current = Get-KindVersion
  if ($current) {
    Write-Host "kind detected: $current (desired: $version)"
  } else {
    Write-Host "kind detected: not found (desired: $version)"
  }
  if ($current -eq $version) {
    Write-Host "kind $current already installed"
    return
  }
  if ($current) { Write-Host "installing pinned kind $version into $InstallBinDir (existing: $current)" }
  Install-Kind $version
  $WingetUsed["kind"] = "direct"
  $current = Get-KindVersion
  if ($current -ne $version) {
    Write-Host "Error: kind version is $current, expected $version" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  Write-Host "kind installed: $current"
}

function Ensure-Jq($version) {
  $current = Get-JqVersion
  if ($current) {
    Write-Host "jq detected: $current (desired: $version)"
  } else {
    Write-Host "jq detected: not found (desired: $version)"
  }
  if ($current -eq $version) {
    Write-Host "jq $current already installed"
    return
  }
  if ($current) { Write-Host "installing pinned jq $version into $InstallBinDir (existing: $current)" }
  Install-Jq $version
  $WingetUsed["jq"] = "direct"
  $current = Get-JqVersion
  if ($current -ne $version) {
    Write-Host "Error: jq version is $current, expected $version" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  Write-Host "jq installed: $current"
}

function Ensure-Mkcert($version) {
  $exe = Resolve-ExePath "mkcert.exe" "mkcert"
  $current = Get-MkcertVersion
  if ($current) {
    Write-Host "mkcert detected: $current (desired: $version)"
  } else {
    Write-Host "mkcert detected: not found (desired: $version)"
  }
  if ($current -eq $version) {
    Write-Host "mkcert $current already installed"
  } else {
    if ($current) { Write-Host "installing pinned mkcert $version into $InstallBinDir (existing: $current)" }
    Install-Mkcert $version
    $WingetUsed["mkcert"] = "direct"
    $current = Get-MkcertVersion
    if ($current -ne $version) {
      Write-Host "Error: mkcert version is $current, expected $version" -ForegroundColor Red
      throw "bootstrap step failed"
    }
    Write-Host "mkcert installed: $current"
  }
  if (-not $exe) { $exe = Resolve-ExePath "mkcert.exe" "mkcert" }
  $caroot = Invoke-NativeOutput $exe @("-CAROOT")
  if ($caroot) { $caroot = $caroot.Trim() }
  if (-not $caroot -or -not (Test-Path (Join-Path $caroot "rootCA.pem"))) {
    Write-Host "mkcert found, but CA not installed; running mkcert -install"
    $null = Invoke-NativeOutput $exe @("-install")
    $caroot = Invoke-NativeOutput $exe @("-CAROOT")
    if ($caroot) { $caroot = $caroot.Trim() }
    if (-not $caroot -or -not (Test-Path (Join-Path $caroot "rootCA.pem"))) {
      Write-Host "Error: mkcert CA install failed. Fix manually and re-run." -ForegroundColor Red
      throw "bootstrap step failed"
    }
  }
}

function Install-Kustomize($version) {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
  $archiveName = "kustomize_v${version}_windows_${arch}.zip"
  $zip = Join-Path $env:TEMP $archiveName
  $url = "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v$version/$archiveName"
  $checksums = "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v$version/checksums.txt"
  Write-Host "installing kustomize $version"
  Invoke-Download $url $zip
  Verify-Sha256Checksums $zip $checksums $archiveName
  $tmp = Join-Path $env:TEMP "kustomize_extract"
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  Install-BinaryFile (Join-Path $tmp "kustomize.exe") "kustomize.exe"
}

function Install-Kubeconform($version) {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
  $archiveName = "kubeconform-windows-$arch.zip"
  $zip = Join-Path $env:TEMP $archiveName
  $url = "https://github.com/yannh/kubeconform/releases/download/v$version/$archiveName"
  $checksums = "https://github.com/yannh/kubeconform/releases/download/v$version/CHECKSUMS"
  Write-Host "installing kubeconform $version"
  Invoke-Download $url $zip
  Verify-Sha256Checksums $zip $checksums $archiveName
  $tmp = Join-Path $env:TEMP "kubeconform_extract"
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  Install-BinaryFile (Join-Path $tmp "kubeconform.exe") "kubeconform.exe"
}

function Ensure-Kustomize($version) {
  $current = Get-KustomizeVersion
  if ($current) {
    Write-Host "kustomize detected: $current (desired: $version)"
  } else {
    Write-Host "kustomize detected: not found (desired: $version)"
  }
  if ($current -eq $version) {
    Write-Host "kustomize $current already installed"
    return
  }
  if ($current) { Write-Host "installing pinned kustomize $version into $InstallBinDir (existing: $current)" }
  Install-Kustomize $version
  $current = Get-KustomizeVersion
  if ($current -ne $version) {
    Write-Host "Error: kustomize version is $current, expected $version" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  Write-Host "kustomize installed: $current"
}

function Ensure-Kubeconform($version) {
  $current = Get-KubeconformVersion
  if ($current) {
    Write-Host "kubeconform detected: $current (desired: $version)"
  } else {
    Write-Host "kubeconform detected: not found (desired: $version)"
  }
  if ($current -eq $version) {
    Write-Host "kubeconform $current already installed"
    return
  }
  if ($current) { Write-Host "installing pinned kubeconform $version into $InstallBinDir (existing: $current)" }
  Install-Kubeconform $version
  $current = Get-KubeconformVersion
  if ($current -ne $version) {
    Write-Host "Error: kubeconform version is $current, expected $version" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  Write-Host "kubeconform installed: $current"
}

try {
  $Summary["apt-system"] = "WARN"
  Run-Step "network-tools" { Write-Host "Windows bootstrap does not use apt; validating network tools directly." }

  # Windows 11 already ships with curl.exe; treat wget/unzip/make/python/openssl as optional.
  Run-SoftStep "curl" {
    $current = Get-CurlVersion
    if ($current -and (Version-Ge $current $curlMinVersion)) { Write-Host "curl OK: $current"; return "OK" }
    Write-Host "curl not found or too old. Windows 11 normally includes curl.exe; install/update it and re-run." -ForegroundColor Yellow
    return "WARN"
  }

  Run-SoftStep "wget" {
    $current = Get-WgetVersion
    if ($current -and (Version-Ge $current $wgetMinVersion)) { Write-Host "wget OK: $current"; return "OK" }
    Write-Host "wget not found (optional on Windows; bootstrap uses curl.exe for downloads)." -ForegroundColor Yellow
    return "WARN"
  }

  Run-SoftStep "unzip" {
    $current = Get-UnzipVersion
    if ($current -and (Version-Ge $current $unzipMinVersion)) { Write-Host "unzip OK: $current"; return "OK" }
    Write-Host "unzip not found (optional on Windows; bootstrap uses Expand-Archive for .zip)." -ForegroundColor Yellow
    return "WARN"
  }

  Run-SoftStep "git" {
    $current = Get-GitVersion
    if ($current -and (Version-Ge $current $gitVersion)) { Write-Host "git OK: $current"; return "OK" }
    Write-Host "git not found (or too old). Install Git for Windows and re-run." -ForegroundColor Yellow
    return "WARN"
  }

  Run-SoftStep "make" {
    $current = Get-MakeVersion
    if ($current -and (Version-Ge $current $makeVersion)) { Write-Host "make OK: $current"; return "OK" }
    Write-Host "make not found (optional). On Windows, run repo commands from Git Bash or WSL2, which provide a POSIX shell + make." -ForegroundColor Yellow
    return "WARN"
  }

  Run-SoftStep "python3" {
    $current = Get-PythonVersion
    if ($current -and (Version-Ge $current $pythonVersion)) { Write-Host "python OK: $current"; return "OK" }
    Write-Host "python not found (optional). Install Python from python.org or via winget, then re-run." -ForegroundColor Yellow
    return "WARN"
  }

  Run-SoftStep "openssl" {
    $current = Get-OpenSSLVersion
    if ($current -and (Version-Ge $current $opensslMinVersion)) { Write-Host "openssl OK: $current"; return "OK" }
    Write-Host "openssl not found (optional). Install OpenSSL if you need it, then re-run." -ForegroundColor Yellow
    return "WARN"
  }

  Run-Step "kubectl" { Ensure-Kubectl $kubectlVersion }
  Run-Step "kind" { Ensure-Kind $kindVersion }
  Run-SoftStep "kube-context" { Ensure-KubeContext $bootstrapExpectedKubeContext $bootstrapAutoKubeContext }
  Run-Step "jq" { Ensure-Jq $jqVersion }

  Run-SoftStep "kustomize" {
    try {
      Ensure-Kustomize $kustomizeVersion
      return "OK"
    } catch {
      Write-Host "kustomize not available (optional): $($_.Exception.Message)" -ForegroundColor Yellow
      return "WARN"
    }
  }

  Run-SoftStep "kubeconform" {
    try {
      Ensure-Kubeconform $kubeconformVersion
      return "OK"
    } catch {
      Write-Host "kubeconform not available (optional): $($_.Exception.Message)" -ForegroundColor Yellow
      return "WARN"
    }
  }

function Wait-Docker($retries = 30, $delay = 2) {
  $exe = Resolve-ExePath "docker.exe" "docker"
  if (-not $exe) { return $false }
  for ($i = 1; $i -le $retries; $i++) {
    $null = Invoke-NativeOutput $exe @("info")
    if ($LASTEXITCODE -eq 0) { return $true }
    Start-Sleep -Seconds $delay
  }
  return $false
}

function Start-DockerDesktop {
  $service = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
  if ($service) {
    if ($service.Status -ne "Running") {
      Write-Host "Starting Docker service..."
      Start-Service -Name "com.docker.service"
    }
    return
  }
  $dockerExe = "$Env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
  if (Test-Path $dockerExe) {
    Write-Host "Starting Docker Desktop..."
    Start-Process $dockerExe | Out-Null
    return
  }
  $dockerCmd = Get-Command "Docker Desktop" -ErrorAction SilentlyContinue
  if ($dockerCmd) {
    Write-Host "Starting Docker Desktop..."
    Start-Process "Docker Desktop" | Out-Null
  }
}

  Run-SoftStep "docker" {
    $dockerCmd = Get-AppCommand "docker"
    if (-not $dockerCmd) {
      $dockerInstaller = Join-Path $PSScriptRoot "install-docker.cmd"
      Write-Host "docker not found. Docker Desktop is required to run kind-based local dev." -ForegroundColor Yellow
      if (Test-Path $dockerInstaller) {
        Write-Host "Install automatically (Windows): $dockerInstaller" -ForegroundColor Yellow
      }
      return "WARN"
    }

    $null = Invoke-NativeOutput $dockerCmd.Source @("info")
    if ($LASTEXITCODE -ne 0) {
      Write-Host "docker not running; attempting to start..."
      Start-DockerDesktop
      Write-Host "waiting for docker to be ready..."
      if (-not (Wait-Docker)) {
        Write-Host "docker daemon not running. Start Docker Desktop and re-run." -ForegroundColor Yellow
        return "WARN"
      }
    }

    $dockerVersion = Get-DockerVersion
    Write-Host "docker detected: $dockerVersion (min: $dockerEngineMinVersion)"
    if ($dockerVersion -and -not (Version-Ge $dockerVersion $dockerEngineMinVersion)) {
      Write-Host "docker version is below the recommended minimum ($dockerEngineMinVersion). Please update Docker Desktop and re-run." -ForegroundColor Yellow
      return "WARN"
    }

    $desktopExe = "$Env:ProgramFiles\\Docker\\Docker\\Docker Desktop.exe"
    if (Test-Path $desktopExe) {
      $desktopVersion = (Get-Item $desktopExe).VersionInfo.ProductVersion
      Write-Host "docker desktop detected: $desktopVersion (min: $dockerDesktopMinVersion)"
      if (-not (Version-Ge $desktopVersion $dockerDesktopMinVersion)) {
        Write-Host "docker desktop version is below the recommended minimum ($dockerDesktopMinVersion). Please update and re-run." -ForegroundColor Yellow
        return "WARN"
      }
    }

    Write-Host "docker running"
    return "OK"
  }

  Run-SoftStep "mkcert" {
    try {
      Ensure-Mkcert $mkcertVersion
      return "OK"
    } catch {
      Write-Host "mkcert not available (optional): $($_.Exception.Message)" -ForegroundColor Yellow
      return "WARN"
    }
  }

  Write-Host "Final versions:"
  Show-Version "kubectl" (Get-KubectlVersion)
  Show-Version "kind" (Get-KindVersion)
  Show-Version "kube-context" (Get-CurrentKubeContext)
  Show-Version "kube-context expected" $bootstrapExpectedKubeContext
  Show-Version "jq" (Get-JqVersion)
  Show-Version "mkcert" (Get-MkcertVersion)
  Show-Version "kustomize" (Get-KustomizeVersion)
  Show-Version "kubeconform" (Get-KubeconformVersion)
  Show-Version "docker" (Get-DockerVersion)
  Show-Version "git" (Get-GitVersion)
  Show-Version "make" (Get-MakeVersion)
  Show-Version "python3" (Get-PythonVersion)
  Show-Version "openssl" (Get-OpenSSLVersion)
  Show-Version "curl" (Get-CurlVersion)
  Show-Version "wget" (Get-WgetVersion)
  Show-Version "unzip" (Get-UnzipVersion)

  if (Get-Command Get-Command -ErrorAction SilentlyContinue) {
    Write-Host "refreshing command cache..."
    try { Get-Command -Name kubectl,kind,jq,mkcert,kustomize,kubeconform -ErrorAction SilentlyContinue | Out-Null } catch {}
  }
  Write-Host "if your current terminal still does not find a command, open a new PowerShell session."

} catch {
  $HadFailure = $true
  Write-Host "Bootstrap failed: $($_.Exception.Message)" -ForegroundColor Red
} finally {
  $swTotal.Stop()
  Write-Host "bootstrap total took $([math]::Round($swTotal.Elapsed.TotalSeconds, 1))s"
  Write-Host ""
  Write-Host "Summary:"
  foreach ($k in $SummaryOrder) {
    Write-Host ("  {0,-12} {1}" -f $k, $Summary[$k])
  }
  if ($WingetUsed.Count -gt 0) {
    Write-Host ""
    Write-Host "Install sources:"
    foreach ($k in $WingetUsed.Keys) {
      Write-Host ("  {0,-12} {1}" -f $k, $WingetUsed[$k])
    }
  }
  if ($HadFailure) { exit 1 }
  Write-Host "Bootstrap complete."
}
