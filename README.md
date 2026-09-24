# Humifortis Enforcement Gateway

Vendor-neutral external authorization for NGINX `auth_request`. The gateway
does not authenticate users, execute MFA, calculate risk, or own policy. It
normalizes trusted request context, asks Humifortis Core for a decision, and
returns `ALLOW`, `BLOCK`, or `CHALLENGE`.

## Endpoints

- `GET /auth` -> `204`, `403`, or `401` for NGINX `auth_request`
- `POST /ssf/caep/events` -> signed CAEP/SSF risk-level-change receiver
- `GET /health` -> liveness
- `GET /ready` -> backend/state readiness
- `GET /metrics` -> Prometheus text format

## Configuration

Copy [.env.example](.env.example) and set the required production secrets.
`HUMIFORTIS_API_KEY` is preferred for the Core client. `GATEWAY_TRUSTED_HEADER_SECRET`
is required when trusted identity headers are accepted from NGINX.

The gateway defaults to in-memory state for one instance. Set `REDIS_URL` for
shared constraints and replay protection in HA deployments.

## Run

```bash
go test ./...
go run ./cmd/gateway
```

## E2E

The Compose deployment in [docker-compose.e2e.yml](docker-compose.e2e.yml)
starts Redis, Humifortis Core, the gateway, an NGINX PEP, and a protected demo
upstream. The Core source is expected beside this repository at
`../humifortis-core`; override `HUMIFORTIS_CORE_CONTEXT` when needed.

For the local sidecar gate against an already-running Core E2E stack, use
[gateway-gate.ps1](e2e/gateway-gate.ps1). It registers a temporary CAEP stream,
checks a baseline request, drives eight real `AUTH_LOGIN_FAILED` events through
Core `/evaluate`, waits for the signed CAEP constraint, and verifies NGINX
returns `401 CHALLENGE` or `403 BLOCK`. The temporary stream is deleted during
teardown unless `-Keep` is supplied.

```bash
docker compose -f docker-compose.e2e.yml up --build
curl -i http://localhost:8081/protected
```
