param(
    [string]$OutputRoot = ".artifacts/release-gate"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Run-Step {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    Write-Host ""
    Write-Host "==> $Name"
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $OutputRoot $timestamp
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$meta = @(
    "timestamp=$timestamp",
    "workspace=$(Get-Location)",
    "go_version=$(& go version)"
)
Set-Content -Path (Join-Path $runDir "metadata.txt") -Value $meta

Write-Host "Release gate artifacts: $runDir"

Run-Step -Name "go test ./..." -Command {
    & go test ./... 2>&1 | Tee-Object -FilePath (Join-Path $runDir "go-test.log")
}

Run-Step -Name "go run ./cmd/baseline check" -Command {
    & go run ./cmd/baseline check 2>&1 | Tee-Object -FilePath (Join-Path $runDir "baseline-check.log")
}

Run-Step -Name "go run ./cmd/baseline report --json" -Command {
    & go run ./cmd/baseline report --json | Tee-Object -FilePath (Join-Path $runDir "baseline-report.json") | Out-Null
}

Run-Step -Name "go run ./cmd/baseline report --sarif" -Command {
    & go run ./cmd/baseline report --sarif | Tee-Object -FilePath (Join-Path $runDir "baseline-report.sarif") | Out-Null
}

Write-Host ""
Write-Host "Release gate passed."
Write-Host "Artifacts written to: $runDir"
