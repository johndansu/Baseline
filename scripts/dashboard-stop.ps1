$ErrorActionPreference = "SilentlyContinue"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$pidFile = Join-Path $repoRoot ".baseline\dashboard-api.pid"

if (!(Test-Path $pidFile)) {
  Write-Host "No dashboard pid file found."
  exit 0
}

$pidValue = Get-Content -Path $pidFile | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($pidValue)) {
  Remove-Item -Force $pidFile
  Write-Host "Dashboard pid file was empty and has been cleared."
  exit 0
}

$proc = Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue
if ($null -ne $proc) {
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  Write-Host "Stopped dashboard process PID $pidValue."
} else {
  Write-Host "Dashboard process PID $pidValue was not running."
}

Remove-Item -Force $pidFile -ErrorAction SilentlyContinue
