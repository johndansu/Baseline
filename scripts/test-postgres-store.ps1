[CmdletBinding()]
param(
    [string]$Image = "postgres:16-alpine",
    [string]$ContainerName = "baseline-postgres-test",
    [int]$Port = 55432,
    [string]$Database = "baseline_test",
    [string]$Username = "baseline",
    [string]$Password = "baseline",
    [string]$TestPattern = "^TestPostgresStore",
    [switch]$KeepContainer
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-DockerAvailable {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "docker is not installed or not on PATH"
    }
    & docker info --format "{{.ServerVersion}}" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "docker daemon is not available. Start Docker Desktop (or your daemon) first."
    }
}

function Remove-ContainerIfExists {
    param([string]$Name)
    $existing = & docker ps -aq -f "name=^${Name}$"
    if (-not [string]::IsNullOrWhiteSpace(($existing | Out-String))) {
        & docker rm -f $Name | Out-Null
    }
}

function Wait-For-Postgres {
    param(
        [string]$Name,
        [string]$User,
        [string]$Db
    )
    for ($i = 0; $i -lt 30; $i++) {
        & docker exec $Name pg_isready -U $User -d $Db | Out-Null
        if ($LASTEXITCODE -eq 0) {
            return
        }
        Start-Sleep -Seconds 1
    }
    throw "Postgres container did not become ready in time"
}

Assert-DockerAvailable
Remove-ContainerIfExists -Name $ContainerName

try {
    Write-Host "==> Starting disposable Postgres container"
    & docker run -d `
        --name $ContainerName `
        -e "POSTGRES_DB=$Database" `
        -e "POSTGRES_USER=$Username" `
        -e "POSTGRES_PASSWORD=$Password" `
        -p "${Port}:5432" `
        $Image | Out-Null

    Write-Host "==> Waiting for Postgres readiness"
    Wait-For-Postgres -Name $ContainerName -User $Username -Db $Database

    $env:BASELINE_TEST_POSTGRES_URL = "postgres://${Username}:${Password}@127.0.0.1:${Port}/${Database}?sslmode=disable"

    Write-Host "==> Running focused Postgres store tests"
    & go test ./internal/api -run $TestPattern -count=1
    if ($LASTEXITCODE -ne 0) {
        throw "go test failed"
    }

    Write-Host ""
    Write-Host "Postgres store tests passed."
    Write-Host "DSN: $env:BASELINE_TEST_POSTGRES_URL"
}
finally {
    Remove-Item Env:BASELINE_TEST_POSTGRES_URL -ErrorAction SilentlyContinue
    if (-not $KeepContainer) {
        Write-Host "==> Cleaning up container"
        Remove-ContainerIfExists -Name $ContainerName
    }
}
