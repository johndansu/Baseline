param(
    [string]$RunDir = "",
    [string]$ArchiveName = "",
    [switch]$KeepDir
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

function Resolve-CurrentPlatformArchive {
    param([string]$ArchivesDir)
    $osDescription = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription.ToLowerInvariant()
    $platform = if ($osDescription.Contains("darwin") -or $osDescription.Contains("mac")) {
        "darwin"
    } elseif ($osDescription.Contains("linux")) {
        "linux"
    } else {
        "windows"
    }
    $arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()) {
        "arm64" { "arm64" }
        default { "amd64" }
    }
    $extension = if ($platform -eq "windows") { ".zip" } else { ".tar.gz" }
    $pattern = "*_${platform}_${arch}${extension}"
    $match = Get-ChildItem -Path $ArchivesDir -File | Where-Object { $_.Name -like $pattern } | Sort-Object Name | Select-Object -Last 1
    if (-not $match) {
        throw "No matching archive found for ${platform}/${arch} in $ArchivesDir"
    }
    return $match.FullName
}

if ([string]::IsNullOrWhiteSpace($RunDir)) {
    $RunDir = Resolve-LatestRunDir ".artifacts/release"
}

if ([string]::IsNullOrWhiteSpace($RunDir) -or -not (Test-Path $RunDir)) {
    throw "Release directory not found. Pass a run directory explicitly."
}

& powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-release.ps1 -RunDir $RunDir
if ($LASTEXITCODE -ne 0) {
    throw "Release verification failed for $RunDir"
}

$archivesDir = Join-Path $RunDir "archives"
$archivePath = if ([string]::IsNullOrWhiteSpace($ArchiveName)) {
    Resolve-CurrentPlatformArchive -ArchivesDir $archivesDir
} else {
    if (Test-Path $ArchiveName) { $ArchiveName } else { Join-Path $archivesDir $ArchiveName }
}

if (-not (Test-Path $archivePath)) {
    throw "Archive not found: $archivePath"
}

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("baseline-install-smoke-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
try {
    Write-Host "==> Extracting $archivePath"
    if ($archivePath.EndsWith(".zip", [System.StringComparison]::OrdinalIgnoreCase)) {
        Expand-Archive -Path $archivePath -DestinationPath $tempDir -Force
    } elseif ($archivePath.EndsWith(".tar.gz", [System.StringComparison]::OrdinalIgnoreCase)) {
        & tar -C $tempDir -xzf $archivePath
        if ($LASTEXITCODE -ne 0) {
            throw "tar extraction failed for $archivePath"
        }
    } else {
        throw "Unsupported archive format: $archivePath"
    }

    $binary = Get-ChildItem -Path $tempDir -Recurse -File | Where-Object { $_.Name -like 'baseline*' } | Select-Object -First 1
    if (-not $binary) {
        throw "Baseline binary not found after extraction"
    }

    Write-Host ""
    Write-Host "==> Smoke-checking installed binary"
    & $binary.FullName version
    if ($LASTEXITCODE -ne 0) {
        throw "baseline version failed"
    }
    & $binary.FullName --help | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "baseline --help failed"
    }
    & $binary.FullName ci setup --help | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "baseline ci setup --help failed"
    }

    Write-Host ""
    Write-Host "clean install smoke passed for: $archivePath"
    Write-Host "extracted binary: $($binary.FullName)"
    if ($KeepDir) {
        Write-Host "kept extraction directory: $tempDir"
    }
} finally {
    if (-not $KeepDir -and (Test-Path $tempDir)) {
        Remove-Item -Recurse -Force $tempDir
    }
}
