# Durable PostgreSQL + Redis state layer report

## 1–7. Summary, host, state removal, and repository

Status: **durable foundation complete; internal deployment proposal only**.

- Host identity: `middleware`, IPv4 `65.109.65.169`, Ubuntu 22.04.5 LTS.
- Repository: `/opt/codestra/sip-provisioning`.
- Branch: `integration/durable-state-final`.
- Starting stores removed: process-local assignment, session, plaintext
  credential, and idempotency dictionaries from the API.
- Remaining dictionaries are request-local serialization/configuration values;
  none is authoritative.
- Backup: `/opt/codestra/backups/sip-provisioning-durable-state/20260720-163500/`
  with verified SHA-256 manifest and Git bundle.
- Precheck: `reports/durable-state-precheck.md`.

## 8–11. Migration and PostgreSQL

Alembic revision `0001_durable_state` creates `endpoint_assignment`,
`sip_session`, `audit_event`, `idempotency_record`, `credential_rotation`, and
`schema_state`. It has explicit foreign keys, unique constraints, indexes,
endpoint-6101 check, nonnegative renewal check, and a partial unique index for
one active session per subject. No table has a plaintext credential column.

The design uses database `codestra_sip_provisioning` and least-privilege role
`sip_provisioning_app`; this task did not create or migrate the persistent
production database. Empty-database upgrade, downgrade to base, re-upgrade,
logical dump, and restore were proven using isolated PostgreSQL 17.6.

## 12–15. Redis, TTL, encryption, and fingerprinting

Redis keys use `codestra:sip:v1:*`; every tested key had positive TTL. Session,
credential, lease, lock, rate-limit, replay, overlap, and endpoint-cache policies
are documented in `docs/redis-key-model.md`.

Temporary credentials use AES-256-GCM with random 96-bit nonce, versioned key,
expiry, and AAD binding service/session/subject/endpoint/version. Redis tests
proved the value is an encrypted envelope and does not contain the returned
credential. PostgreSQL stores only domain-separated HMAC-SHA256 fingerprints.

## 16–23. Lifecycle and concurrency controls

- Assignment: stable `mock-<12 hex>` name, PostgreSQL uniqueness, Redis lock,
  endpoint 6101 rejected in code and schema.
- Session: create 201, renew 200 with rotation, revoke 204 with immediate Redis
  deletion, expiration reconciliation preserving assignment.
- Idempotency: PostgreSQL authoritative; exact replay returns session reference
  but never the credential; changed payload returns 409.
- Locks: Redis SET NX PX, random owner, bounded wait, compare-and-delete release.
- Limits: create 5/10m, renew 12/h, revoke 20/h; counters have TTL.
- Replay helper uses an HMAC key and atomic TTL first-use claim.
- Reconciliation uses a distributed leader lock and row locking.
- Audit metadata is recursively redacted; append is serialized with a PostgreSQL
  advisory transaction lock and chained using HMAC(previous hash + canonical event).

## 24–29. API, readiness, authentication, and provisioners

Routes: `/healthz`, `/readyz`, `/api/v1/sip/config`, create, renew, and revoke.
Mutations require Authorization, Idempotency-Key, and X-Client-Instance-ID;
schemas reject unknown fields, responses are no-store, and errors use problem JSON.

Readiness checks PostgreSQL, Redis, Alembic revision, schema compatibility,
MockProvisioner, mock mode, encryption-key version, public-auth gate, endpoint
6101, and all live flags. Test authentication is accepted only with APP_ENV=test.
Preproduction/production uses the disabled trusted-provider boundary until a
separate auth approval. Public routing remains disabled.

MockProvisioner is active and has no network/shell path. AsteriskOfflineProvisioner
is isolated and rejects 6101. The future adapter is top-level documentation only;
no telephony connection code was implemented.

## 30–42. Validation evidence

- Compilation: PASS with bytecode redirected to temporary storage.
- Ruff: PASS, full repository.
- strict mypy: PASS, 26 source files.
- pytest: PASS, 6 integration tests containing multiple acceptance assertions.
- Coverage: 78% (729 statements, 163 missed).
- Multi-worker/restart: PASS using two independent service/engine/Redis clients.
- Concurrent create: PASS; one assignment and one active session.
- Redis TTL/encryption/revocation: PASS.
- Credential plaintext checks in PostgreSQL and Redis: PASS.
- Audit chain and expiration audit: PASS.
- OpenAPI 3.1 runtime parity: PASS; `docs/openapi.yaml` is generated runtime JSON
  (valid YAML 1.2) and compared structurally in tests.
- Alembic upgrade/downgrade/upgrade: PASS.
- Logical backup/restore: PASS; restored assignment count 1, audit count 1.
- Dependency audit after repinning: PASS, no known vulnerabilities.
- Secret scanner: gitleaks unavailable; scoped forbidden/high-risk searches run.
- Container scanner: trivy unavailable.
- SBOM: PASS; CycloneDX JSON generated at `reports/sbom.cdx.json` by pip-audit.
- Image: `codestra/sip-provisioning:0.2.0-durable`, non-root `10001:10001`,
  internal expose only, two workers, `0.0.0.0:8110` inside container.
- Compose proposal: read-only root, tmpfs, all capabilities dropped,
  no-new-privileges, resource limits, log rotation, health check, backend only,
  and no host `ports` mapping.

## 43–50. Deployment boundary, rollback, and confirmations

No active Compose file, Caddy configuration, DNS, TLS, firewall, Odoo, n8n,
Asterisk, VICIdial, DIDWW, or VICIphone service was changed. The API was not
deployed; only an internal-only proposal and local validation image were built.
Rollback is source/image rollback plus explicit migration downgrade only when
approved; PostgreSQL assignments/audit must be preserved and Redis may be rebuilt.

- process-local authoritative state remaining: **NO**
- plaintext SIP credential in PostgreSQL: **NO**
- plaintext SIP credential in Redis: **NO**
- MockProvisioner active: **YES**
- live Asterisk provisioning enabled: **NO**
- endpoint 6101 created: **NO**
- endpoint 6101 assigned: **NO**
- `65.21.67.207` contacted/resolved/probed: **NO**
- port 8110 public: **NO**
- public session route enabled: **NO**
- Caddy/Odoo/n8n/Asterisk/VICIdial modified: **NO**

Known blocker: trusted production authentication remains separately unapproved,
so no public session route may be activated.
