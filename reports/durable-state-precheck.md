# Durable state precheck

Recorded: 2026-07-20 16:35 America/Santo_Domingo

## Safety gates

- Server: `middleware`, public IPv4 `65.109.65.169` (confirmed).
- Protected telephony host was not resolved, probed, or contacted.
- Active provisioner remains `MockProvisioner`; all live flags are false.
- Endpoint 6101 is prohibited.
- PostgreSQL, Redis, and port 8110 have no public listeners.
- Caddy is out of scope and will not be modified.

## Platform

- Ubuntu 22.04.5 LTS, Linux 5.15, 12 CPUs, 62 GiB RAM, 32 GiB swap.
- Root filesystem: 436 GiB total, 397 GiB available at inventory.
- Docker 29.6.2; Docker Compose v5.3.1.
- Private networks: `codestra_backend` (internal) and `codestra_edge`.
- PostgreSQL 17.6 (`codestra-postgres-1`); Redis 7.4.5 (`codestra-redis-1`).
- Redis uses password authentication, AOF persistence, snapshotting, and `noeviction`.

## Repository and baseline

- Repository: `/opt/codestra/sip-provisioning`.
- Branch created for this work: `feat/durable-postgres-redis-state`.
- Starting commit: `2baaa05`.
- Baseline commands could not run because the existing `.venv` lacked executable
  Ruff, mypy, and pytest entry points (exit 127). Evidence is retained in the backup.
- Backup: `/opt/codestra/backups/sip-provisioning-durable-state/20260720-163500/`;
  archive, Git bundle, configuration, OpenAPI, and SHA-256 manifest validated.

## Mutable-state classification

| Existing state | Classification | Destination |
|---|---|---|
| `Store.assignments` dictionary | authoritative | PostgreSQL assignment repository |
| `Store.sessions` dictionary | authoritative lifecycle | PostgreSQL session repository |
| `Store.idempotency` dictionary | authoritative request outcome | PostgreSQL idempotency repository |
| plaintext password in `SessionState` | forbidden credential state | encrypted Redis envelope; HMAC fingerprint in PostgreSQL |
| request/response dictionaries | request-local, harmless | retain as typed schemas |
| immutable settings and provisioner instance | immutable/service wiring | retain without authoritative mutable data |

No process-local rate-limit, replay, or lock implementation is authoritative in
the current API; those controls are absent and must be introduced in Redis.

## Refactor plan

1. Fail-closed typed configuration and isolated authentication providers.
2. Explicit SQLAlchemy models and deterministic Alembic migration.
3. Validated Redis keys, AES-256-GCM envelopes, leases, locks, replay, rate limits.
4. Async repositories for assignments, sessions, idempotency, rotations, schema,
   and serialized hash-chain audit.
5. Lifecycle services for create, renew, revoke, and reconciliation.
6. Thin routes, dependency-aware readiness, strict schemas, and problem details.
7. Isolated PostgreSQL/Redis integration, concurrency, restart, TTL, and safety tests.
8. Internal-only hardened container/Compose proposal; no public route or Caddy change.
