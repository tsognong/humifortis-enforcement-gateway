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
$streamId = $null
$coreRoot = $core -replace '/api/v1$', ''
$ssf = Invoke-RestMethod "$coreRoot/.well-known/ssf-configuration?tenant_id=$tenant"
if ([string]::IsNullOrWhiteSpace($ssf.issuer)) { throw "Core SSF configuration did not return a tenant issuer" }
$env:CAEP_ISSUER = $ssf.issuer
$env:CAEP_AUDIENCE = $delivery
$env:CAEP_TENANT_ID = $tenant
$env:CAEP_JWKS_URL = "http://host.docker.internal:8080/.well-known/jwks.json"
$env:HUMIFORTIS_URL = "http://host.docker.internal:8080/api/v1"
Write-Host "Using Core CAEP issuer: $($env:CAEP_ISSUER)"

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
  $streamId = $stream.stream_id
  Write-Host "Registered Core CAEP stream $($stream.stream_id) -> $delivery"

  $subject = "gateway-e2e-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())@demo.local"
  $authHeaders = @{ "X-Tenant-ID" = $tenant; "X-Subject" = $subject; "X-Session-ID" = "local-caep-session" }

  function Get-ProtectedDecision {
    try {
      $response = Invoke-WebRequest "http://localhost:18080/protected" -Headers $authHeaders -UseBasicParsing
      return @{ Status = [int]$response.StatusCode; Decision = $response.Headers["X-Humifortis-Decision"] }
    } catch {
      return @{ Status = [int]$_.Exception.Response.StatusCode; Decision = $_.Exception.Response.Headers["X-Humifortis-Decision"] }
    }
  }

  $baseline = Get-ProtectedDecision
  if ($baseline.Status -notin @(200, 204)) {
    throw "Expected baseline protected request to be allowed, got $($baseline.Status) decision=$($baseline.Decision)"
  }
  Write-Host "Baseline protected request allowed: HTTP $($baseline.Status)"

  $apiKey = $env:HUMIFORTIS_API_KEY
  if ([string]::IsNullOrWhiteSpace($apiKey)) { $apiKey = "hf_e2e_test_runner_2026" }
  for ($index = 1; $index -le 8; $index++) {
    $eventBody = @{
      event = @{
        entity_id = $subject
        entity_type = "user"
        event_type = "AUTH_LOGIN_FAILED"
        source = "gateway-real-risk-spike"
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        metadata = @{ ip = "203.0.113.$(20 + $index)"; user_agent = "gateway-e2e" }
      }
      available_methods = @("TOTP")
    } | ConvertTo-Json -Depth 6
    $evaluation = Invoke-RestMethod "$core/evaluate" -Method Post -Headers @{ "X-API-Key" = $apiKey } -ContentType "application/json" -Body $eventBody
    Write-Host "Risk spike event $index -> action=$($evaluation.action) level=$($evaluation.risk_level) score=$($evaluation.risk_score)"
  }

  $deadline = (Get-Date).AddSeconds(15)
  do {
    Start-Sleep -Milliseconds 500
    $decision = Get-ProtectedDecision
    if ($decision.Status -in @(401, 403)) { break }
  } while ((Get-Date) -lt $deadline)

  if ($decision.Status -notin @(401, 403)) {
    throw "Expected risk spike to enforce through CAEP, got HTTP $($decision.Status) decision=$($decision.Decision)"
  }
  Write-Host "PASS: real Core risk spike -> signed CAEP -> gateway constraint -> NGINX HTTP $($decision.Status) decision=$($decision.Decision)"
}
finally {
  if ($streamId -and $headers) { try { Invoke-RestMethod "$core/caep/streams/$streamId" -Method Delete -Headers $headers | Out-Null } catch { Write-Warning "Could not delete temporary CAEP stream $streamId" } }
  if (-not $Keep) { docker compose -f $composeFile down -v }
}