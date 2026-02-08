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
  "docker","mkcert","kubectl","kind","kube-context","jq","kustomize","kubeconform","awscli"
)
$Summary = [ordered]@{}
$SummaryOrder | ForEach-Object { $Summary[$_] = "PENDING" }
$WingetUsed = [ordered]@{}
$HadFailure = $false

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
$awscliVersion = $Env:AWSCLI_VERSION
$awscliWindowsMsiSha256 = $Env:AWSCLI_WINDOWS_MSI_SHA256
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
if (-not $awscliVersion) { $awscliVersion = "2.33.17" }
if (-not $awscliWindowsMsiSha256) { $awscliWindowsMsiSha256 = "" }
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

Write-Host "Target versions (security/compat): kubectl=$kubectlVersion kind=$kindVersion jq=$jqVersion awscli=$awscliVersion mkcert=$mkcertVersion kustomize=$kustomizeVersion kubeconform=$kubeconformVersion docker>=$dockerEngineMinVersion git>=$gitVersion make>=$makeVersion python>=$pythonVersion openssl>=$opensslMinVersion curl>=$curlMinVersion wget>=$wgetMinVersion unzip>=$unzipMinVersion"
Write-Host "SHA256 verification enabled for kubectl, kind, jq, mkcert, kustomize, kubeconform downloads."
Write-Host "Set BOOTSTRAP_AUTO_CONFIRM=1 to auto-accept reinstalls."
Write-Host "global binary mode: BOOTSTRAP_ENFORCE_GLOBAL_BIN=$bootstrapEnforceGlobalBin, install dir=$InstallBinDir"
Write-Host "kube context controls: BOOTSTRAP_EXPECTED_KUBE_CONTEXT=$bootstrapExpectedKubeContext BOOTSTRAP_AUTO_KUBECONTEXT=$bootstrapAutoKubeContext"

function Require-Winget {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "winget not found. Install App Installer from Microsoft Store." -ForegroundColor Yellow
    throw "bootstrap step failed"
  }
}

Require-Winget

function Get-CommandVersion($cmd, $pattern) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { return $null }
  $output = & $cmd --version 2>$null
  if ($output -match $pattern) { return $Matches[1] }
  return $null
}

function Get-MkcertVersion {
  if (-not (Get-Command mkcert -ErrorAction SilentlyContinue)) { return $null }
  $output = & mkcert -version 2>$null
  if ($output -match 'v?(\d+\.\d+\.\d+)') { return $Matches[1] }
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
  for ($i = 1; $i -le $retries; $i++) {
    Write-Host "download (attempt $i/$retries): $url"
    try {
      Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing | Out-Null
      if ((Get-Item $out).Length -gt 0) { return }
    } catch {
      Write-Host "download failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    Start-Sleep -Seconds (2 * $i)
  }
  Write-Host "download failed after $retries attempts: $url" -ForegroundColor Red
  throw "bootstrap step failed"
}

function Verify-Sha256File($file, $checksumUrl) {
  $checksumFile = Join-Path $env:TEMP "checksum.txt"
  Invoke-Download $checksumUrl $checksumFile
  $expected = (Get-Content $checksumFile | Select-Object -First 1).Split(" ")[0].Trim()
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

function Verify-Sha256Checksums($file, $checksumsUrl) {
  $checksumFile = Join-Path $env:TEMP "checksums.txt"
  Invoke-Download $checksumsUrl $checksumFile
  $filename = Split-Path $file -Leaf
  $expected = (Select-String -Path $checksumFile -Pattern " $filename$" | Select-Object -First 1).Line.Split(" ")[0].Trim()
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
  $exe = Join-Path $env:TEMP "jq.exe"
  $url = "https://github.com/jqlang/jq/releases/download/jq-$version/jq-windows-$arch.exe"
  $sha = "$url.sha256"
  Write-Host "installing jq $version"
  Invoke-Download $url $exe
  Verify-Sha256File $exe $sha
  Install-BinaryFile $exe "jq.exe"
}

function Install-Mkcert($version) {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
  $exe = Join-Path $env:TEMP "mkcert.exe"
  $url = "https://github.com/FiloSottile/mkcert/releases/download/v$version/mkcert-v$version-windows-$arch.exe"
  $sha = "$url.sha256"
  Write-Host "installing mkcert $version"
  Invoke-Download $url $exe
  Verify-Sha256File $exe $sha
  Install-BinaryFile $exe "mkcert.exe"
}

function Get-KustomizeVersion {
  if (-not (Get-Command kustomize -ErrorAction SilentlyContinue)) { return $null }
  $output = & kustomize version --short 2>$null
  if ($output -match 'v?(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-KubeconformVersion {
  if (-not (Get-Command kubeconform -ErrorAction SilentlyContinue)) { return $null }
  $output = & kubeconform -version 2>$null
  if ($output -match 'v?(\d+\.\d+\.\d+)') { return $Matches[1] }
  $output = & kubeconform --version 2>$null
  if ($output -match 'v?(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-DockerVersion {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { return $null }
  $output = & docker version --format "{{.Server.Version}}" 2>$null
  return (Normalize-Version $output)
}

function Get-GitVersion {
  if (-not (Get-Command git -ErrorAction SilentlyContinue)) { return $null }
  $output = & git --version 2>$null
  if ($output -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-MakeVersion {
  if (-not (Get-Command make -ErrorAction SilentlyContinue)) { return $null }
  $output = & make --version 2>$null
  if ($output -match '(\d+\.\d+(\.\d+)?)') { return $Matches[1] }
  return $null
}

function Get-PythonVersion {
  if (-not (Get-Command python -ErrorAction SilentlyContinue)) { return $null }
  $output = & python --version 2>$null
  if ($output -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-OpenSSLVersion {
  if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) { return $null }
  $output = & openssl version 2>$null
  if ($output -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-CurlVersion {
  if (-not (Get-Command curl -ErrorAction SilentlyContinue)) { return $null }
  $output = & curl --version 2>$null
  if ($output -match 'curl (\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-WgetVersion {
  if (-not (Get-Command wget -ErrorAction SilentlyContinue)) { return $null }
  $output = & wget --version 2>$null
  if ($output -match 'GNU Wget (\d+\.\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Get-UnzipVersion {
  if (-not (Get-Command unzip -ErrorAction SilentlyContinue)) { return $null }
  $output = & unzip -v 2>$null
  if ($output -match 'UnZip (\d+\.\d+)') { return $Matches[1] }
  return $null
}

function Show-Version($name, $value) {
  if (-not $value) { $value = "not found" }
  Write-Host ("{0,-12} {1}" -f "$name:", $value)
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
  } finally {
    $sw.Stop()
    Write-Host "$name took $([math]::Round($sw.Elapsed.TotalSeconds, 1))s"
  }
}

function Get-CurrentKubeContext {
  if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) { return $null }
  $ctx = & kubectl config current-context 2>$null
  if ($LASTEXITCODE -ne 0) { return $null }
  return $ctx
}

function Ensure-KubeContext($expected, $autoSwitch) {
  if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    Write-Host "kubectl not found; skipping kube context validation" -ForegroundColor Yellow
    return "WARN"
  }

  $contexts = & kubectl config get-contexts -o name 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $contexts) {
    Write-Host "unable to read kube contexts from kubectl config" -ForegroundColor Yellow
    return "WARN"
  }

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
    & kubectl config use-context $expected | Out-Null
    if ($LASTEXITCODE -eq 0) {
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

function Invoke-WingetInstall($id, $desiredVersion = $null, $retries = 3) {
  for ($i = 1; $i -le $retries; $i++) {
    if ($desiredVersion) {
      Write-Host "winget install (attempt $i/$retries): $id $desiredVersion"
      $result = winget install -e --id $id --version $desiredVersion
    } else {
      Write-Host "winget install (attempt $i/$retries): $id"
      $result = winget install -e --id $id
    }
    if ($LASTEXITCODE -eq 0) { return }
    Write-Host "winget install failed ($i/$retries). Retrying..." -ForegroundColor Yellow
    Start-Sleep -Seconds (2 * $i)
  }
  Write-Host "winget install failed after $retries attempts." -ForegroundColor Red
  throw "bootstrap step failed"
}

function Invoke-WingetInstallAny($name, $ids, $desiredVersion = $null) {
  foreach ($id in $ids) {
    try {
      Invoke-WingetInstall $id $desiredVersion
      $WingetUsed[$name] = $id
      return $id
    } catch {
      Write-Host "winget install failed for $id; trying next candidate..." -ForegroundColor Yellow
    }
  }
  if ($desiredVersion) {
    foreach ($id in $ids) {
      try {
        Invoke-WingetInstall $id
        $WingetUsed[$name] = $id
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
    $result = winget uninstall -e --id $id
    if ($LASTEXITCODE -eq 0) { return }
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

function Install-AwsCliMsi($version, $sha256) {
  $msi = Join-Path $env:TEMP "AWSCLIV2.msi"
  $url = "https://awscli.amazonaws.com/AWSCLIV2.msi"
  Write-Host "installing AWS CLI $version from MSI"
  Invoke-Download $url $msi
  $actual = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLower()
  if ($sha256) {
    if ($actual -ne $sha256.ToLower()) {
      Write-Host "AWS CLI MSI checksum mismatch" -ForegroundColor Red
      Write-Host "expected: $sha256"
      Write-Host "actual:   $actual"
      throw "bootstrap step failed"
    }
  } else {
    Write-Host "AWSCLI_WINDOWS_MSI_SHA256 not set; using computed hash and updating tool-versions.env" -ForegroundColor Yellow
    Update-ToolVersions $VersionsFile "AWSCLI_WINDOWS_MSI_SHA256" $actual
    $sha256 = $actual
  }
  Start-Process "msiexec.exe" -ArgumentList "/i `"$msi`" /qn" -Wait
}

function Ensure-AwsCli($version, $sha256) {
  $current = Get-CommandVersion "aws" 'aws-cli/(\d+\.\d+\.\d+)'
  if ($current) {
    Write-Host "awscli detected: $current (desired: $version)"
  } else {
    Write-Host "awscli detected: not found (desired: $version)"
  }
  if ($current -eq $version) {
    Write-Host "awscli $current already installed"
    return
  }
  if ($current) { Should-Reinstall "awscli" $current $version | Out-Null }
  Install-AwsCliMsi $version $sha256
  $WingetUsed["awscli"] = "MSI"
  $current = Get-CommandVersion "aws" 'aws-cli/(\d+\.\d+\.\d+)'
  if ($current -ne $version) {
    Write-Host "Error: awscli version is $current, expected $version" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  Write-Host "awscli installed: $current"
}

function Ensure-Git($version) {
  $current = Get-GitVersion
  if ($current) { Write-Host "git detected: $current (desired: $version)" } else { Write-Host "git detected: not found (desired: $version)" }
  if ($current -eq $version) { Write-Host "git $current already installed"; return }
  if ($current) { Should-Reinstall "git" $current $version | Out-Null }
  Invoke-WingetInstallAny "git" @("Git.Git","GitHub.GitHubDesktop") $version | Out-Null
  $current = Get-GitVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: git version is $current, expected >= $version" -ForegroundColor Red; throw }
  Write-Host "git installed: $current"
}

function Ensure-Make($version) {
  $current = Get-MakeVersion
  if ($current) { Write-Host "make detected: $current (desired: $version)" } else { Write-Host "make detected: not found (desired: $version)" }
  if ($current -eq $version) { Write-Host "make $current already installed"; return }
  if ($current) { Should-Reinstall "make" $current $version | Out-Null }
  Invoke-WingetInstallAny "make" @("GnuWin32.Make","GnuWin.Make","MSYS2.MSYS2") $version | Out-Null
  $current = Get-MakeVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: make version is $current, expected >= $version" -ForegroundColor Red; throw }
  Write-Host "make installed: $current"
}

function Ensure-Python($version) {
  $current = Get-PythonVersion
  if ($current) { Write-Host "python detected: $current (desired: $version)" } else { Write-Host "python detected: not found (desired: $version)" }
  if ($current -eq $version) { Write-Host "python $current already installed"; return }
  if ($current) { Should-Reinstall "python" $current $version | Out-Null }
  Invoke-WingetInstallAny "python" @("Python.Python.3.14","Python.Python.3") $version | Out-Null
  $current = Get-PythonVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: python version is $current, expected >= $version" -ForegroundColor Red; throw }
  Write-Host "python installed: $current"
}

function Ensure-OpenSSL($version) {
  $current = Get-OpenSSLVersion
  if ($current) { Write-Host "openssl detected: $current (desired: $version)" } else { Write-Host "openssl detected: not found (desired: $version)" }
  if ($current -eq $version) { Write-Host "openssl $current already installed"; return }
  if ($current) { Should-Reinstall "openssl" $current $version | Out-Null }
  Invoke-WingetInstallAny "openssl" @("OpenSSL.OpenSSL","ShiningLight.OpenSSL") | Out-Null
  $current = Get-OpenSSLVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: openssl version is $current, expected >= $version" -ForegroundColor Red; throw }
  Write-Host "openssl installed: $current"
}

function Ensure-Curl($version) {
  $current = Get-CurlVersion
  if ($current) { Write-Host "curl detected: $current (desired: $version)" } else { Write-Host "curl detected: not found (desired: $version)" }
  if ($current -eq $version) { Write-Host "curl $current already installed"; return }
  if ($current) { Should-Reinstall "curl" $current $version | Out-Null }
  Invoke-WingetInstallAny "curl" @("cURL.cURL") | Out-Null
  $current = Get-CurlVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: curl version is $current, expected >= $version" -ForegroundColor Red; throw }
  Write-Host "curl installed: $current"
}

function Ensure-Wget($version) {
  $current = Get-WgetVersion
  if ($current) { Write-Host "wget detected: $current (desired: $version)" } else { Write-Host "wget detected: not found (desired: $version)" }
  if ($current -eq $version) { Write-Host "wget $current already installed"; return }
  if ($current) { Should-Reinstall "wget" $current $version | Out-Null }
  Invoke-WingetInstallAny "wget" @("GnuWin32.Wget","JernejSimoncic.Wget") | Out-Null
  $current = Get-WgetVersion
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: wget version is $current, expected >= $version" -ForegroundColor Red; throw }
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
  if (-not $current -or -not (Version-Ge $current $version)) { Write-Host "Error: unzip version is $current, expected >= $version" -ForegroundColor Red; throw }
  Write-Host "unzip installed: $current"
}

function Ensure-Kubectl($version) {
  $current = Get-CommandVersion "kubectl" 'v(\d+\.\d+\.\d+)'
  if ($current) {
    Write-Host "kubectl detected: $current (desired: $version)"
  } else {
    Write-Host "kubectl detected: not found (desired: $version)"
  }
  if ($current -eq $version) {
    Write-Host "kubectl $current already installed"
    return
  }
  if ($current) { Should-Reinstall "kubectl" $current $version | Out-Null }
  Install-Kubectl $version
  $WingetUsed["kubectl"] = "direct"
  $current = Get-CommandVersion "kubectl" 'v(\d+\.\d+\.\d+)'
  if ($current -ne $version) {
    Write-Host "Error: kubectl version is $current, expected $version" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  Write-Host "kubectl installed: $current"
}

function Ensure-Kind($version) {
  $current = Get-CommandVersion "kind" 'v(\d+\.\d+\.\d+)'
  if ($current) {
    Write-Host "kind detected: $current (desired: $version)"
  } else {
    Write-Host "kind detected: not found (desired: $version)"
  }
  if ($current -eq $version) {
    Write-Host "kind $current already installed"
    return
  }
  if ($current) { Should-Reinstall "kind" $current $version | Out-Null }
  Install-Kind $version
  $WingetUsed["kind"] = "direct"
  $current = Get-CommandVersion "kind" 'v(\d+\.\d+\.\d+)'
  if ($current -ne $version) {
    Write-Host "Error: kind version is $current, expected $version" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  Write-Host "kind installed: $current"
}

function Ensure-Jq($version) {
  $current = Get-CommandVersion "jq" 'jq-(\d+\.\d+\.\d+)'
  if ($current) {
    Write-Host "jq detected: $current (desired: $version)"
  } else {
    Write-Host "jq detected: not found (desired: $version)"
  }
  if ($current -eq $version) {
    Write-Host "jq $current already installed"
    return
  }
  if ($current) { Should-Reinstall "jq" $current $version | Out-Null }
  Install-Jq $version
  $WingetUsed["jq"] = "direct"
  $current = Get-CommandVersion "jq" 'jq-(\d+\.\d+\.\d+)'
  if ($current -ne $version) {
    Write-Host "Error: jq version is $current, expected $version" -ForegroundColor Red
    throw "bootstrap step failed"
  }
  Write-Host "jq installed: $current"
}

function Ensure-Mkcert($version) {
  $current = Get-MkcertVersion
  if ($current) {
    Write-Host "mkcert detected: $current (desired: $version)"
  } else {
    Write-Host "mkcert detected: not found (desired: $version)"
  }
  if ($current -eq $version) {
    Write-Host "mkcert $current already installed"
  } else {
    if ($current) { Should-Reinstall "mkcert" $current $version | Out-Null }
    Install-Mkcert $version
    $WingetUsed["mkcert"] = "direct"
    $current = Get-MkcertVersion
    if ($current -ne $version) {
      Write-Host "Error: mkcert version is $current, expected $version" -ForegroundColor Red
      throw "bootstrap step failed"
    }
    Write-Host "mkcert installed: $current"
  }
  $caroot = & mkcert -CAROOT 2>$null
  if (-not $caroot -or -not (Test-Path (Join-Path $caroot "rootCA.pem"))) {
    Write-Host "mkcert found, but CA not installed; running mkcert -install"
    & mkcert -install | Out-Null
    $caroot = & mkcert -CAROOT 2>$null
    if (-not $caroot -or -not (Test-Path (Join-Path $caroot "rootCA.pem"))) {
      Write-Host "Error: mkcert CA install failed. Fix manually and re-run." -ForegroundColor Red
      throw "bootstrap step failed"
    }
  }
}

function Install-Kustomize($version) {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
  $zip = Join-Path $env:TEMP "kustomize.zip"
  $url = "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v$version/kustomize_v$version`_windows_$arch.zip"
  $checksums = "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v$version/checksums.txt"
  Write-Host "installing kustomize $version"
  Invoke-Download $url $zip
  Verify-Sha256Checksums $zip $checksums
  $tmp = Join-Path $env:TEMP "kustomize_extract"
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  Install-BinaryFile (Join-Path $tmp "kustomize.exe") "kustomize.exe"
}

function Install-Kubeconform($version) {
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
  $zip = Join-Path $env:TEMP "kubeconform.zip"
  $url = "https://github.com/yannh/kubeconform/releases/download/v$version/kubeconform-windows-$arch.zip"
  $checksums = "https://github.com/yannh/kubeconform/releases/download/v$version/checksums.txt"
  Write-Host "installing kubeconform $version"
  Invoke-Download $url $zip
  Verify-Sha256Checksums $zip $checksums
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
  if ($current) {
    Should-Reinstall "kustomize" $current $version | Out-Null
  }
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
  if ($current) {
    Should-Reinstall "kubeconform" $current $version | Out-Null
  }
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
  Run-Step "curl" { Ensure-Curl $curlMinVersion }
  Run-Step "wget" { Ensure-Wget $wgetMinVersion }
  Run-Step "unzip" { Ensure-Unzip $unzipMinVersion }
  Run-Step "git" { Ensure-Git $gitVersion }
  Run-Step "make" { Ensure-Make $makeVersion }
  Run-Step "python3" { Ensure-Python $pythonVersion }
  Run-Step "openssl" { Ensure-OpenSSL $opensslMinVersion }
  Run-Step "kubectl" { Ensure-Kubectl $kubectlVersion }
  Run-Step "kind" { Ensure-Kind $kindVersion }
  Run-SoftStep "kube-context" { Ensure-KubeContext $bootstrapExpectedKubeContext $bootstrapAutoKubeContext }
  Run-Step "jq" { Ensure-Jq $jqVersion }
  Run-Step "awscli" { Ensure-AwsCli $awscliVersion $awscliWindowsMsiSha256 }
  Run-Step "kustomize" { Ensure-Kustomize $kustomizeVersion }
  Run-Step "kubeconform" { Ensure-Kubeconform $kubeconformVersion }

function Wait-Docker($retries = 30, $delay = 2) {
  for ($i = 1; $i -le $retries; $i++) {
    docker info | Out-Null
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

  Run-Step "docker" {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
      Write-Host "Error: docker not found. Install Docker Desktop and re-run." -ForegroundColor Red
      throw "bootstrap step failed"
    }
    docker info | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Host "docker not running; attempting to start..."
      Start-DockerDesktop
      Write-Host "waiting for docker to be ready..."
      if (-not (Wait-Docker)) {
        Write-Host "Error: docker daemon not running. Start Docker Desktop and re-run." -ForegroundColor Red
        throw "bootstrap step failed"
      }
    }
    $dockerVersion = Get-DockerVersion
    Write-Host "docker detected: $dockerVersion (min: $dockerEngineMinVersion)"
    if ($dockerVersion -and -not (Version-Ge $dockerVersion $dockerEngineMinVersion)) {
      Should-Reinstall "docker" $dockerVersion $dockerEngineMinVersion | Out-Null
      Write-Host "Please update Docker Engine/Desktop to at least $dockerEngineMinVersion and re-run." -ForegroundColor Red
      throw "bootstrap step failed"
    }
    $desktopExe = "$Env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
    if (Test-Path $desktopExe) {
      $desktopVersion = (Get-Item $desktopExe).VersionInfo.ProductVersion
      Write-Host "docker desktop detected: $desktopVersion (min: $dockerDesktopMinVersion)"
      if (-not (Version-Ge $desktopVersion $dockerDesktopMinVersion)) {
        Should-Reinstall "docker desktop" $desktopVersion $dockerDesktopMinVersion | Out-Null
        Write-Host "Please update Docker Desktop to at least $dockerDesktopMinVersion and re-run." -ForegroundColor Red
        throw "bootstrap step failed"
      }
    }
    Write-Host "docker running"
  }

  Run-Step "mkcert" { Ensure-Mkcert $mkcertVersion }
  Write-Host "mkcert found (CA installed)"

  Write-Host "Final versions:"
  Show-Version "kubectl" (Get-CommandVersion 'kubectl' 'v(\d+\.\d+\.\d+)')
  Show-Version "kind" (Get-CommandVersion 'kind' 'v(\d+\.\d+\.\d+)')
  Show-Version "kube-context" (Get-CurrentKubeContext)
  Show-Version "kube-context expected" $bootstrapExpectedKubeContext
  Show-Version "jq" (Get-CommandVersion 'jq' 'jq-(\d+\.\d+\.\d+)')
  Show-Version "awscli" (Get-CommandVersion 'aws' 'aws-cli/(\d+\.\d+\.\d+)')
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
    try { Get-Command -Name kubectl,kind,jq,aws,mkcert,kustomize,kubeconform -ErrorAction SilentlyContinue | Out-Null } catch {}
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
