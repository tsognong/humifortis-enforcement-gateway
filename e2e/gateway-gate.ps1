param(
  [switch]$Keep
)

$ErrorActionPreference = "Stop"
$composeFile = "docker-compose.gateway.e2e.yml"
$core = $env:HUMIFORTIS_URL
if ([string]::IsNullOrWhiteSpace($core)) { $core = "http://localhost:8080/api/v1" }
$tenant = $env:CAEP_TENANT_ID
if ([string]::IsNullOrWhiteSpace($tenant)) { $tenant = "d4f7a2c1-8b3e-4f6a-9c1d-2e5f8a7b3c4d" }
$delivery = "http://host.docker.internal:18081/ssf/caep/events"

Write-Host "Starting gateway gate against Core: $core"
docker compose -f $composeFile up -d --build
try {
  $login = $null
  foreach ($password in @("Admin123!", "Demo1234!")) {
    $loginBody = @{ email = "admin@humifortis.com"; password = $password } | ConvertTo-Json
    try { $login = Invoke-RestMethod "$core/auth/login" -Method Post -ContentType "application/json" -Body $loginBody; break } catch { }
  }
  if ([string]::IsNullOrWhiteSpace($login.token)) { throw "Core login did not return a token" }
  $headers = @{ Authorization = "Bearer $($login.token)" }

  $streamBody = @{ receiver_name = "local-enforcement-gateway"; delivery = @{ url = $delivery } } | ConvertTo-Json -Depth 4
  $stream = Invoke-RestMethod "$core/caep/streams" -Method Post -Headers $headers -ContentType "application/json" -Body $streamBody
  if ([string]::IsNullOrWhiteSpace($stream.stream_id)) { throw "Core did not return a CAEP stream_id" }
  Write-Host "Registered Core CAEP stream $($stream.stream_id) -> $delivery"

  $testResult = Invoke-RestMethod "$core/caep/streams/$($stream.stream_id)/test" -Method Post -Headers $headers
  if (-not $testResult.success) { throw "Core CAEP test delivery failed: $($testResult.error)" }
  Write-Host "Core delivered a signed CAEP SET"

  $authHeaders = @{ "X-Tenant-ID" = $tenant; "X-Subject" = "test-user@demo.local"; "X-Session-ID" = "local-caep-session" }
  $response = Invoke-WebRequest "http://localhost:18080/protected" -Headers $authHeaders -UseBasicParsing -SkipHttpErrorCheck
  if ($response.StatusCode -ne 401 -or $response.Headers["X-Humifortis-Decision"] -ne "CHALLENGE") {
    throw "Expected protected request to return CHALLENGE/401, got $($response.StatusCode) decision=$($response.Headers["X-Humifortis-Decision"])"
  }
  Write-Host "PASS: NGINX -> gateway -> CAEP constraint returned CHALLENGE"
}
finally {
  if (-not $Keep) { docker compose -f $composeFile down -v }
}