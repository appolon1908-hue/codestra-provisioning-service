# SIP Provisioning API Build Report

## Executive summary

The mock-only API source and deployment proposals are complete under
`/opt/codestra/sip-provisioning`. The application-server identity is confirmed
as `65.109.65.169`; port 8110 is unused. No live integration is activated.

## Scope and architecture

The service is intended for the application server and binds internally to
`127.0.0.1:8110`. It authenticates mock test identities, enforces one synthetic
endpoint per identity and one active session, rotates short-lived credentials,
and exposes health/config/session routes. A future Asterisk adapter on
`65.21.67.207` is explicitly out of scope.

## Files and stack

Python 3.12, FastAPI 0.116.1, Pydantic 2.11.7, Uvicorn 0.35.0, SQLAlchemy
2.0.43, Alembic 1.16.4, asyncpg 0.30.0, redis-py 6.4.0, and cryptography
45.0.6 are pinned in `pyproject.toml` and `lockfile`. Source, schemas, model
proposal, mock/disabled provisioners, redaction, tests, OpenAPI, Dockerfile,
Compose proposal, Caddy proposal, threat model, lifecycle, and rollback docs
are present.

## Persistence and credential lifecycle

SQLAlchemy models define endpoint assignments, sessions, append-only audit, and
hashed idempotency records without password columns. The reviewed production
design reserves PostgreSQL for durable records and Redis namespace
`codestra:sip:v1:*` for expiring encrypted credentials, leases, locks, replay,
and rate limits. Those stores are not activated in this offline mock phase.
Credentials are generated with `secrets`, returned only from create/renew, and
marked `memory-only`; they are not logged or placed in URLs/cookies/storage.

## API and controls

Routes: `POST /api/v1/sip/session`, `POST /api/v1/sip/session/renew`,
`DELETE /api/v1/sip/session`, `GET /api/v1/sip/config`, `GET /healthz`, and
`GET /readyz`. Mutations require `Idempotency-Key` and
`X-Client-Instance-ID`; responses use `Cache-Control: no-store`. Fail-closed
flags keep mock mode true, live authorization/provisioning false, endpoint 6101
disallowed, and public routing disabled.

## Verification and limitations

The test suite covers health/config, create replay, renew, revoke, required
headers, and one-active-session behavior. Full dependency installation,
PostgreSQL/Redis restore tests, coverage, lint, type checking, vulnerability
scan, container scan, and runtime OpenAPI validation remain deployment gates;
they were not run because dependencies are not installed and no service was
activated. The current process-local store is intentionally not production
persistence.

## Safety confirmations

Mock mode: true. Live Asterisk provisioning: false. Endpoint 6101 created: NO.
The host `65.21.67.207` was not contacted or modified. Asterisk, VICIdial,
DIDWW, Twilio, VICIphone, campaigns, trunks, calls, recordings, routing, DNS,
TLS, firewall, Odoo, n8n, middleware, Caddy, and Agent Desktop were not
modified. No public listener or Caddy route was activated.

## Next milestone

Create a separate approved deployment task for least-privilege PostgreSQL and
Redis provisioning, production migrations, restore tests, external auth
integration, and review of the future Asterisk-side adapter. Do not create
endpoint 6101 before the written approval gate is satisfied.
