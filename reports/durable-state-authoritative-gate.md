# SIP Durable-State Authoritative Gate

SIP_DURABLE_GATE=PASS

Date: 2026-07-20
Branch: `integration/durable-state-final`
Commit: `da7d8db`

## Repository and migration evidence

- Durable commits `07c72bc`, `4a2e20b`, and checkpoint `2d6bd7a` are ancestors of the current branch.
- Alembic has one head: `0001_durable_state`.
- Migration upgrade, downgrade to base, and upgrade to head passed in the isolated PostgreSQL validation database.
- Final `alembic_version`: `0001_durable_state`.
- Final `schema_state.schema_version`: `1`.
- Required tables present: `endpoint_assignment`, `sip_session`, `audit_event`, `idempotency_record`, `credential_rotation`, `schema_state`.

## Reproducible validation

Validation used `docker compose -f deploy/compose.validation.yaml` with pinned PostgreSQL 17.6, Redis 7.4.5, Python 3.12.11, and repository lock/development versions. The network was internal-only, no ports were published, and no production services or Docker socket were attached.

- Ruff: PASS
- Mypy strict: PASS
- Python compilation: PASS
- Dependency consistency (`pip check`): PASS
- OpenAPI generation: PASS
- Secret/prohibited-host scan: PASS
- Pytest: PASS — 14 passed
- Restart recovery: PASS — PostgreSQL and Redis restarted, then 14 tests passed

The test suite covers PostgreSQL/Redis durability, restart/multi-worker consistency, concurrency races, assignment uniqueness, Redis TTLs, encrypted credentials, keyed fingerprints, one-time credential delivery, idempotency replay/conflict, renewal rotation and overlap, revoke/reconciliation, audit hash chaining, rate/replay guards, API auth, and disabled public routes.

## Required safety outcomes

ALEMBIC_HEAD=0001_durable_state  
SCHEMA_VERSION=1  
RUFF=PASS  
MYPY=PASS  
PYTEST=PASS  
MIGRATION_UP_DOWN_UP=PASS  
RESTART_PERSISTENCE=PASS  
MULTI_WORKER=PASS  
CONCURRENCY=PASS  
REDIS_TTL=PASS  
REDIS_ENCRYPTION=PASS  
IDEMPOTENCY=PASS  
RECONCILIATION=PASS  
AUDIT_CHAIN=PASS  
ENDPOINT_6101=PROHIBITED  
PUBLIC_ROUTE=DISABLED  
VICIDIAL_CONTACTED=NO

All validation containers, volumes, network, and temporary test-secret files were removed with `docker compose -f deploy/compose.validation.yaml down --volumes`. No identity, deployment, Caddy, Agent Desktop, endpoint, Asterisk, VICIdial, or production work was started.
