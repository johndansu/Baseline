param(
    [string]$OutputRoot = ".artifacts/release",
    [string]$Version = "",
    [string[]]$Targets = @(
        "windows/amd64",
        "windows/arm64",
        "linux/amd64",
        "linux/arm64",
        "darwin/amd64",
        "darwin/arm64"
    )
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-GitValue {
    param(
        [string]$Command,
        [string]$Fallback
    )

    try {
        $value = Invoke-Expression $Command
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($value)) {
            return ($value | Out-String).Trim()
        }
    } catch {
    }
    return $Fallback
}

function Build-Binary {
    param(
        [string]$Target,
        [string]$Destination,
        [string]$VersionValue,
        [string]$CommitValue,
        [string]$BuildDateValue
    )

    $parts = $Target.Split("/")
    if ($parts.Length -ne 2) {
        throw "Invalid target '$Target'. Expected GOOS/GOARCH."
    }

    $env:GOOS = $parts[0]
    $env:GOARCH = $parts[1]

    $ldflags = @(
        "-s",
        "-w",
        "-X", "github.com/baseline/baseline/internal/version.Version=$VersionValue",
        "-X", "github.com/baseline/baseline/internal/version.GitCommit=$CommitValue",
        "-X", "github.com/baseline/baseline/internal/version.BuildDate=$BuildDateValue"
    ) -join " "

    & go build -trimpath -ldflags $ldflags -o $Destination .\cmd\baseline
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed for $Target"
    }
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $OutputRoot $timestamp
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$binariesDir = Join-Path $runDir "binaries"
$archivesDir = Join-Path $runDir "archives"
New-Item -ItemType Directory -Path $binariesDir -Force | Out-Null
New-Item -ItemType Directory -Path $archivesDir -Force | Out-Null

$resolvedVersion = if ([string]::IsNullOrWhiteSpace($Version)) {
    Resolve-GitValue -Command "git describe --tags --always --dirty" -Fallback "dev"
} else {
    $Version.Trim()
}
$gitCommit = Resolve-GitValue -Command "git rev-parse --short HEAD" -Fallback "unknown"
$buildDate = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")

$metadata = @(
    "timestamp=$timestamp",
    "version=$resolvedVersion",
    "commit=$gitCommit",
    "build_date=$buildDate",
    "workspace=$(Get-Location)",
    "go_version=$(& go version)"
)
Set-Content -Path (Join-Path $runDir "metadata.txt") -Value $metadata
Set-Content -Path (Join-Path $runDir "RELEASE_INFO.txt") -Value @(
    "Baseline release artifacts",
    "version=$resolvedVersion",
    "commit=$gitCommit",
    "build_date=$buildDate"
)

$binaryChecksums = New-Object System.Collections.Generic.List[string]
$archiveChecksums = New-Object System.Collections.Generic.List[string]

foreach ($target in $Targets) {
    $parts = $target.Split("/")
    $goos = $parts[0]
    $goarch = $parts[1]
    $suffix = if ($goos -eq "windows") { ".exe" } else { "" }
    $binaryName = "baseline_${resolvedVersion}_${goos}_${goarch}${suffix}"
    $destination = Join-Path $binariesDir $binaryName
    $stageDir = Join-Path $runDir ("stage_" + $goos + "_" + $goarch)

    Write-Host ""
    Write-Host "==> Building $target"
    Build-Binary -Target $target -Destination $destination -VersionValue $resolvedVersion -CommitValue $gitCommit -BuildDateValue $buildDate

    $hash = (Get-FileHash -Path $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    $binaryChecksums.Add("$hash  $binaryName")

    if (Test-Path $stageDir) {
        Remove-Item -Recurse -Force $stageDir
    }
    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
    Copy-Item $destination (Join-Path $stageDir $binaryName)
    Copy-Item (Join-Path $runDir "RELEASE_INFO.txt") (Join-Path $stageDir "RELEASE_INFO.txt")

    if ($goos -eq "windows") {
        $archiveName = "baseline_${resolvedVersion}_${goos}_${goarch}.zip"
        $archivePath = Join-Path $archivesDir $archiveName
        if (Test-Path $archivePath) {
            Remove-Item -Force $archivePath
        }
        Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $archivePath -CompressionLevel Optimal
    } else {
        $archiveName = "baseline_${resolvedVersion}_${goos}_${goarch}.tar.gz"
        $archivePath = Join-Path $archivesDir $archiveName
        & tar -C $stageDir -czf $archivePath .
        if ($LASTEXITCODE -ne 0) {
            throw "archive creation failed for $target"
        }
    }

    $archiveHash = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $archiveChecksums.Add("$archiveHash  $archiveName")

    Remove-Item -Recurse -Force $stageDir
}

Set-Content -Path (Join-Path $runDir "SHA256SUMS.binaries") -Value $binaryChecksums
Set-Content -Path (Join-Path $runDir "SHA256SUMS.archives") -Value $archiveChecksums

Write-Host ""
Write-Host "Release artifacts written to: $runDir"
Write-Host "Binary checksums written to: $(Join-Path $runDir 'SHA256SUMS.binaries')"
Write-Host "Archive checksums written to: $(Join-Path $runDir 'SHA256SUMS.archives')"
