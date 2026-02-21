param(
    [Parameter(Mandatory = $true)]
    [string]$ApiBaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$AdminApiKey,

    [ValidateSet("admin", "operator", "viewer")]
    [string]$Role = "operator",

    [string]$Name = "",

    [string]$RevokeKeyId = ""
)

$ErrorActionPreference = "Stop"
$base = $ApiBaseUrl.Trim().TrimEnd("/")
if ([string]::IsNullOrWhiteSpace($base)) {
    throw "ApiBaseUrl is required"
}

if ([string]::IsNullOrWhiteSpace($Name)) {
    $Name = "rotated-" + (Get-Date -Format "yyyyMMddHHmmss")
}

$headers = @{
    "Authorization" = "Bearer $AdminApiKey"
    "Content-Type"  = "application/json"
    "Accept"        = "application/json"
}

$payload = @{
    name = $Name
    role = $Role
} | ConvertTo-Json -Compress

$createResponse = Invoke-RestMethod -Method Post -Uri "$base/v1/api-keys" -Headers $headers -Body $payload

if ([string]::IsNullOrWhiteSpace($createResponse.api_key)) {
    throw "API key create succeeded but no api_key was returned."
}

Write-Host "New key created"
Write-Host ("id: {0}" -f $createResponse.id)
Write-Host ("role: {0}" -f $createResponse.role)
Write-Host ("name: {0}" -f $Name)
Write-Host ("api_key: {0}" -f $createResponse.api_key)

if (-not [string]::IsNullOrWhiteSpace($RevokeKeyId)) {
    $null = Invoke-RestMethod -Method Delete -Uri "$base/v1/api-keys/$RevokeKeyId" -Headers @{
        "Authorization" = "Bearer $AdminApiKey"
        "Accept"        = "application/json"
    }
    Write-Host ("Revoked previous key id: {0}" -f $RevokeKeyId)
}
