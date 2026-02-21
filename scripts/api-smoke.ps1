param(
    [string]$Addr = "127.0.0.1:18080",
    [string]$OutputRoot = ".artifacts/api-smoke",
    [int]$StartupTimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $OutputRoot $timestamp
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$stdoutLog = Join-Path $runDir "api-server.out.log"
$stderrLog = Join-Path $runDir "api-server.err.log"
$dbPath = Join-Path $runDir "baseline-api-smoke.db"
$summaryPath = Join-Path $runDir "summary.log"

function Resolve-BaseURL {
    param([string]$RawAddr)

    $trimmed = $RawAddr.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return "http://127.0.0.1:8080"
    }
    if ($trimmed.StartsWith(":")) {
        return "http://127.0.0.1$trimmed"
    }
    return "http://$trimmed"
}

function Wait-ForHealthyServer {
    param(
        [string]$URL,
        [int]$TimeoutSeconds
    )

    $attempts = [Math]::Max($TimeoutSeconds * 2, 1)
    for ($i = 0; $i -lt $attempts; $i++) {
        $status = & curl.exe -sS -o NUL -w "%{http_code}" "$URL/healthz"
        if ($LASTEXITCODE -eq 0 -and "$status" -eq "200") {
            return
        }
        Start-Sleep -Milliseconds 500
    }

    throw "API server did not become healthy within ${TimeoutSeconds}s"
}

function Invoke-APICheck {
    param(
        [string]$Step,
        [string]$Method,
        [string]$Path,
        [int]$ExpectedStatus,
        [string[]]$Headers,
        [string]$RequestBody,
        [string]$ExpectedBodyText,
        [string]$ExpectedHeaderText
    )

    $safeStep = ($Step.ToLower() -replace "[^a-z0-9_-]", "_")
    $bodyPath = Join-Path $runDir "$safeStep.body"
    $headerPath = Join-Path $runDir "$safeStep.headers"

    $curlArgs = @("-sS", "-D", $headerPath, "-o", $bodyPath, "-w", "%{http_code}", "-X", $Method)
    foreach ($header in $Headers) {
        $curlArgs += @("-H", $header)
    }
    if (-not [string]::IsNullOrWhiteSpace($RequestBody)) {
        $requestPath = Join-Path $runDir "$safeStep.request.json"
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($requestPath, $RequestBody, $utf8NoBom)
        $curlArgs += @("--data-binary", "@$requestPath")
    }
    $curlArgs += "$baseURL$Path"

    $status = & curl.exe @curlArgs
    if ($LASTEXITCODE -ne 0) {
        throw "[$Step] curl failed"
    }
    if ("$status" -ne "$ExpectedStatus") {
        $responseBody = ""
        if (Test-Path $bodyPath) {
            $responseBody = (Get-Content -Path $bodyPath -Raw)
        }
        throw "[$Step] expected HTTP $ExpectedStatus, got $status. Body: $responseBody"
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedBodyText)) {
        $responseBody = Get-Content -Path $bodyPath -Raw
        if (-not $responseBody.Contains($ExpectedBodyText)) {
            throw "[$Step] response body does not contain expected text '$ExpectedBodyText'"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedHeaderText)) {
        $responseHeaders = Get-Content -Path $headerPath -Raw
        if (-not $responseHeaders.ToLower().Contains($ExpectedHeaderText.ToLower())) {
            throw "[$Step] response headers do not contain expected text '$ExpectedHeaderText'"
        }
    }

    Add-Content -Path $summaryPath -Value "${Step}: PASS (HTTP $status)"
    Write-Host "$Step ok (HTTP $status)"
}

$adminKey = (& go run ./cmd/baseline api keygen).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($adminKey)) {
    throw "Unable to generate API key"
}

$baseURL = Resolve-BaseURL -RawAddr $Addr
$serverCommand = @(
    "set BASELINE_API_KEY=$adminKey",
    "set `"BASELINE_API_DB_PATH=$dbPath`"",
    "set BASELINE_API_SELF_SERVICE_ENABLED=false",
    "set BASELINE_API_DASHBOARD_SESSION_ENABLED=false",
    "set BASELINE_API_REQUIRE_HTTPS=false",
    "go run ./cmd/baseline api serve --addr `"$Addr`""
) -join "&& "

$serverProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $serverCommand -WorkingDirectory $repoRoot -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru

try {
    Wait-ForHealthyServer -URL $baseURL -TimeoutSeconds $StartupTimeoutSeconds

    Add-Content -Path $summaryPath -Value "base_url=$baseURL"
    Add-Content -Path $summaryPath -Value "db_path=$dbPath"

    $authHeaders = @("Authorization: Bearer $adminKey")

    Invoke-APICheck -Step "01-healthz" -Method "GET" -Path "/healthz" -ExpectedStatus 200 -Headers @() -RequestBody "" -ExpectedBodyText '"status":"ok"' -ExpectedHeaderText ""
    Invoke-APICheck -Step "02-readyz" -Method "GET" -Path "/readyz" -ExpectedStatus 200 -Headers @() -RequestBody "" -ExpectedBodyText '"status":"ready"' -ExpectedHeaderText ""
    Invoke-APICheck -Step "03-dashboard-unauthorized" -Method "GET" -Path "/v1/dashboard" -ExpectedStatus 401 -Headers @() -RequestBody "" -ExpectedBodyText '"code":"unauthorized"' -ExpectedHeaderText "www-authenticate"

    $projectPayload = '{"id":"smoke-project","name":"Smoke Project","default_branch":"main","policy_set":"baseline:prod"}'
    Invoke-APICheck -Step "04-project-create" -Method "POST" -Path "/v1/projects" -ExpectedStatus 201 -Headers ($authHeaders + @("Content-Type: application/json")) -RequestBody $projectPayload -ExpectedBodyText '"id":"smoke-project"' -ExpectedHeaderText ""

    $scanPayload = '{"id":"smoke-scan-1","project_id":"smoke-project","commit_sha":"abc123","status":"fail","violations":[{"policy_id":"A1","severity":"block","message":"smoke violation"}]}'
    Invoke-APICheck -Step "05-scan-create" -Method "POST" -Path "/v1/scans" -ExpectedStatus 201 -Headers ($authHeaders + @("Content-Type: application/json", "Idempotency-Key: smoke-idempotency-1")) -RequestBody $scanPayload -ExpectedBodyText '"id":"smoke-scan-1"' -ExpectedHeaderText ""

    Invoke-APICheck -Step "06-scan-idempotent-replay" -Method "POST" -Path "/v1/scans" -ExpectedStatus 201 -Headers ($authHeaders + @("Content-Type: application/json", "Idempotency-Key: smoke-idempotency-1")) -RequestBody $scanPayload -ExpectedBodyText '"id":"smoke-scan-1"' -ExpectedHeaderText "x-idempotency-replayed: true"

    Invoke-APICheck -Step "07-scan-sarif" -Method "GET" -Path "/v1/scans/smoke-scan-1/report?format=sarif" -ExpectedStatus 200 -Headers $authHeaders -RequestBody "" -ExpectedBodyText '"runs"' -ExpectedHeaderText ""
    Invoke-APICheck -Step "08-dashboard-summary" -Method "GET" -Path "/v1/dashboard" -ExpectedStatus 200 -Headers $authHeaders -RequestBody "" -ExpectedBodyText '"metrics"' -ExpectedHeaderText ""
    Invoke-APICheck -Step "09-audit-events" -Method "GET" -Path "/v1/audit/events?limit=5" -ExpectedStatus 200 -Headers $authHeaders -RequestBody "" -ExpectedBodyText '"events"' -ExpectedHeaderText ""
    Invoke-APICheck -Step "10-api-keys" -Method "GET" -Path "/v1/api-keys" -ExpectedStatus 200 -Headers $authHeaders -RequestBody "" -ExpectedBodyText '"api_keys"' -ExpectedHeaderText ""
    Invoke-APICheck -Step "11-metrics" -Method "GET" -Path "/metrics" -ExpectedStatus 200 -Headers @() -RequestBody "" -ExpectedBodyText "baseline_projects_total" -ExpectedHeaderText ""

    Write-Host ""
    Write-Host "API smoke passed. Artifacts written to: $runDir"
}
finally {
    if ($null -ne $serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
    }
}
