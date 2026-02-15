param(
  [int]$Port = 8080,
  [string]$SessionRole = "operator",
  [string]$DBPath = ":memory:",
  [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$stateDir = Join-Path $repoRoot ".baseline"
if (!(Test-Path $stateDir)) {
  New-Item -ItemType Directory -Path $stateDir | Out-Null
}

$pidFile = Join-Path $stateDir "dashboard-api.pid"
$exePath = Join-Path $stateDir "baseline-dashboard.exe"
$healthURL = "http://127.0.0.1:$Port/healthz"
$dashboardURL = "http://127.0.0.1:$Port/dashboard"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outLog = Join-Path $stateDir "dashboard-$timestamp.out.log"
$errLog = Join-Path $stateDir "dashboard-$timestamp.err.log"
$logPointerFile = Join-Path $stateDir "dashboard-api.logs"

function Test-ServerReady {
  param([string]$Url)
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
    return ($response.StatusCode -eq 200)
  } catch {
    return $false
  }
}

function Stop-ExistingFromPidFile {
  param([string]$Path)
  if (!(Test-Path $Path)) { return }
  $existingPid = Get-Content -Path $Path -ErrorAction SilentlyContinue | Select-Object -First 1
  if ([string]::IsNullOrWhiteSpace($existingPid)) { return }
  $proc = Get-Process -Id ([int]$existingPid) -ErrorAction SilentlyContinue
  if ($null -ne $proc) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
  }
}

Set-Location $repoRoot

if (Test-ServerReady -Url $healthURL) {
  Write-Host "Baseline API already running at $dashboardURL"
  if ($OpenBrowser) { Start-Process $dashboardURL | Out-Null }
  exit 0
}

Stop-ExistingFromPidFile -Path $pidFile

Write-Host "Building dashboard server binary..."
go build -o $exePath ./cmd/baseline
if ($LASTEXITCODE -ne 0) {
  throw "go build failed"
}

$command = "set BASELINE_API_DASHBOARD_SESSION_ENABLED=true&& set BASELINE_API_DASHBOARD_SESSION_ROLE=$SessionRole&& set BASELINE_API_DB_PATH=$DBPath&& `"$exePath`" api serve --addr :$Port"
$process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $command -WorkingDirectory $repoRoot -RedirectStandardOutput $outLog -RedirectStandardError $errLog -PassThru

Set-Content -Path $pidFile -Value $process.Id
Set-Content -Path $logPointerFile -Value @("OUT=$outLog", "ERR=$errLog")

$ready = $false
for ($i = 0; $i -lt 30; $i++) {
  if (Test-ServerReady -Url $healthURL) {
    $ready = $true
    break
  }
  Start-Sleep -Milliseconds 500
}

if (-not $ready) {
  Write-Host "Server failed to start. Check $errLog"
  exit 1
}

Write-Host "Baseline API running at $dashboardURL"
Write-Host "Logs: $outLog"
Write-Host "Errors: $errLog"
if ($OpenBrowser) { Start-Process $dashboardURL | Out-Null }
