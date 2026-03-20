param(
    [string]$BaseURL = "http://127.0.0.1:8080",
    [string]$AdminKey = "",
    [string]$ProjectID = "",
    [string]$ScanID = "",
    [string]$OutputRoot = ".artifacts/postgres-cutover-smoke"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

function Normalize-BaseURL {
    param([string]$RawURL)

    $trimmed = $RawURL.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return "http://127.0.0.1:8080"
    }
    if ($trimmed.StartsWith("http://") -or $trimmed.StartsWith("https://")) {
        return $trimmed.TrimEnd("/")
    }
    if ($trimmed.StartsWith(":")) {
        return "http://127.0.0.1$trimmed"
    }
    return "http://$($trimmed.TrimEnd('/'))"
}

function Invoke-SmokeStep {
    param(
        [string]$Step,
        [string]$Path,
        [int]$ExpectedStatus,
        [string[]]$Headers,
        [string]$ExpectedBodyText
    )

    $safeStep = ($Step.ToLower() -replace "[^a-z0-9_-]", "_")
    $bodyPath = Join-Path $runDir "$safeStep.body"
    $headerPath = Join-Path $runDir "$safeStep.headers"

    $curlArgs = @("-sS", "-D", $headerPath, "-o", $bodyPath, "-w", "%{http_code}")
    foreach ($header in $Headers) {
        $curlArgs += @("-H", $header)
    }
    $curlArgs += "$normalizedBaseURL$Path"

    $status = & curl.exe @curlArgs
    if ($LASTEXITCODE -ne 0) {
        throw "[$Step] curl failed"
    }
    if ("$status" -ne "$ExpectedStatus") {
        $responseBody = ""
        if (Test-Path $bodyPath) {
            $responseBody = Get-Content -Path $bodyPath -Raw
        }
        throw "[$Step] expected HTTP $ExpectedStatus, got $status. Body: $responseBody"
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedBodyText)) {
        $responseBody = Get-Content -Path $bodyPath -Raw
        if (-not $responseBody.Contains($ExpectedBodyText)) {
            throw "[$Step] response body does not contain expected text '$ExpectedBodyText'"
        }
    }

    Add-Content -Path $summaryPath -Value "${Step}: PASS (HTTP $status)"
    Write-Host "$Step ok (HTTP $status)"
    return $bodyPath
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $OutputRoot $timestamp
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$summaryPath = Join-Path $runDir "summary.log"

$normalizedBaseURL = Normalize-BaseURL -RawURL $BaseURL
Add-Content -Path $summaryPath -Value "base_url=$normalizedBaseURL"
Add-Content -Path $summaryPath -Value "authenticated=$(-not [string]::IsNullOrWhiteSpace($AdminKey))"

$publicHeaders = @()
$authHeaders = @()
if (-not [string]::IsNullOrWhiteSpace($AdminKey)) {
    $authHeaders = @("Authorization: Bearer $AdminKey")
}

Invoke-SmokeStep -Step "01-healthz" -Path "/healthz" -ExpectedStatus 200 -Headers $publicHeaders -ExpectedBodyText '"status":"ok"' | Out-Null
Invoke-SmokeStep -Step "02-signin-page" -Path "/signin.html" -ExpectedStatus 200 -Headers $publicHeaders -ExpectedBodyText "Sign In" | Out-Null
Invoke-SmokeStep -Step "03-dashboard-page" -Path "/dashboard" -ExpectedStatus 200 -Headers $publicHeaders -ExpectedBodyText "Baseline Dashboard" | Out-Null

if ($authHeaders.Count -gt 0) {
    Invoke-SmokeStep -Step "04-auth-me" -Path "/v1/auth/me" -ExpectedStatus 200 -Headers $authHeaders -ExpectedBodyText '"auth_source":"api_key"' | Out-Null
    Invoke-SmokeStep -Step "05-dashboard-summary" -Path "/v1/dashboard" -ExpectedStatus 200 -Headers $authHeaders -ExpectedBodyText '"metrics"' | Out-Null
    Invoke-SmokeStep -Step "06-dashboard-capabilities" -Path "/v1/dashboard/capabilities" -ExpectedStatus 200 -Headers $authHeaders -ExpectedBodyText '"capabilities"' | Out-Null
    Invoke-SmokeStep -Step "07-project-list" -Path "/v1/projects" -ExpectedStatus 200 -Headers $authHeaders -ExpectedBodyText '"projects"' | Out-Null
    $scanPath = "/v1/scans?limit=10"
    if (-not [string]::IsNullOrWhiteSpace($ProjectID)) {
        $scanPath = "/v1/scans?project_id=$ProjectID"
    }
    $scanBodyPath = Invoke-SmokeStep -Step "08-scan-list" -Path $scanPath -ExpectedStatus 200 -Headers $authHeaders -ExpectedBodyText '"scans"'

    if (-not [string]::IsNullOrWhiteSpace($ProjectID)) {
        $projectsBody = Get-Content -Path (Join-Path $runDir "07-project-list.body") -Raw
        if (-not $projectsBody.Contains($ProjectID)) {
            throw "[07-project-list] expected project id '$ProjectID' in response body"
        }
        Add-Content -Path $summaryPath -Value "project_id_check=PASS ($ProjectID)"
        Write-Host "project id check ok ($ProjectID)"
    }
    if (-not [string]::IsNullOrWhiteSpace($ScanID)) {
        $scansBody = Get-Content -Path $scanBodyPath -Raw
        if (-not $scansBody.Contains($ScanID)) {
            throw "[08-scan-list] expected scan id '$ScanID' in response body"
        }
        Add-Content -Path $summaryPath -Value "scan_id_check=PASS ($ScanID)"
        Write-Host "scan id check ok ($ScanID)"
    }
}
else {
    Add-Content -Path $summaryPath -Value "authenticated_checks=SKIPPED"
    Write-Host "Admin key not provided; skipping authenticated cutover checks."
}

Write-Host ""
Write-Host "Postgres cutover smoke passed. Artifacts written to: $runDir"
