param(
    [string]$RunDir = "",
    [string]$CosignOIDCIssuer = "https://token.actions.githubusercontent.com",
    [string]$CosignCertIdentityRegexp = "https://github.com/johndansu/Baseline/.github/workflows/ci.yml@refs/(heads/.+|tags/.+)"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-LatestRunDir {
    param([string]$Root)
    if (-not (Test-Path $Root)) {
        return ""
    }
    $dirs = Get-ChildItem -Path $Root -Directory | Sort-Object Name
    if (-not $dirs) {
        return ""
    }
    return $dirs[-1].FullName
}

function Test-ChecksumFile {
    param(
        [string]$ChecksumFile,
        [string]$BaseDir
    )
    $lines = Get-Content -Path $ChecksumFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach ($line in $lines) {
        if ($line -notmatch '^(?<hash>[0-9a-fA-F]{64})\s{2}(?<name>.+)$') {
            throw "Invalid checksum line in ${ChecksumFile}: $line"
        }
        $expected = $Matches['hash'].ToLowerInvariant()
        $name = $Matches['name']
        $path = Join-Path $BaseDir $name
        if (-not (Test-Path $path)) {
            throw "Checksum target missing: $path"
        }
        $actual = (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "Checksum mismatch for $name"
        }
        Write-Host "$name OK"
    }
}

if ([string]::IsNullOrWhiteSpace($RunDir)) {
    $RunDir = Resolve-LatestRunDir ".artifacts/release"
}

if ([string]::IsNullOrWhiteSpace($RunDir) -or -not (Test-Path $RunDir)) {
    throw "Release directory not found. Pass a run directory explicitly, for example: .\scripts\verify-release.ps1 -RunDir .artifacts\release\20260318_120000"
}

$binaryChecksums = Join-Path $RunDir "SHA256SUMS.binaries"
$archiveChecksums = Join-Path $RunDir "SHA256SUMS.archives"
if (-not (Test-Path $binaryChecksums) -or -not (Test-Path $archiveChecksums)) {
    throw "Missing checksum files in $RunDir"
}

Write-Host "==> Verifying binary checksums"
Test-ChecksumFile -ChecksumFile $binaryChecksums -BaseDir (Join-Path $RunDir "binaries")

Write-Host ""
Write-Host "==> Verifying archive checksums"
Test-ChecksumFile -ChecksumFile $archiveChecksums -BaseDir (Join-Path $RunDir "archives")

$cosign = Get-Command cosign -ErrorAction SilentlyContinue
if (-not $cosign) {
    Write-Host ""
    Write-Host "cosign not found; skipping signature verification"
    exit 0
}

$signatureTargets = New-Object System.Collections.Generic.List[string]
Get-ChildItem -Path (Join-Path $RunDir "archives") -File | ForEach-Object {
    $sig = "$($_.FullName).sig"
    $pem = "$($_.FullName).pem"
    if ((Test-Path $sig) -and (Test-Path $pem)) {
        $signatureTargets.Add($_.FullName)
    }
}
foreach ($checksumName in @("SHA256SUMS.binaries", "SHA256SUMS.archives")) {
    $target = Join-Path $RunDir $checksumName
    if ((Test-Path "$target.sig") -and (Test-Path "$target.pem")) {
        $signatureTargets.Add($target)
    }
}

if ($signatureTargets.Count -eq 0) {
    Write-Host ""
    Write-Host "no signatures found in $RunDir; checksum verification completed"
    exit 0
}

Write-Host ""
Write-Host "==> Verifying keyless cosign signatures"
foreach ($target in $signatureTargets) {
    Write-Host "verifying $(Split-Path $target -Leaf)"
    & $cosign.Source verify-blob `
        --certificate "$target.pem" `
        --signature "$target.sig" `
        --certificate-identity-regexp $CosignCertIdentityRegexp `
        --certificate-oidc-issuer $CosignOIDCIssuer `
        $target | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "cosign verification failed for $target"
    }
}

Write-Host ""
Write-Host "release verification completed for: $RunDir"
