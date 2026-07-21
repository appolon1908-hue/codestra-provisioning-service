# Durable State Final Gate Report

## Decision

Gate 1 — SIP Durable State: **PASS**

The durable SIP lifecycle is validated against isolated PostgreSQL 17.6 and
Redis 7.4.5 using the pinned Python 3.12.11 validation image. The canonical
commit `2baaa0550fdf3cb352fa14378917cd4bd183de07` is an ancestor of the validated
checkpoint, and canonical Alembic revision `0001_durable_state` remains the
only schema revision. No service was deployed or restarted.

Validated checkpoint:
`b983f1b4d1a54281d2d83dac908b4160ddb00e34`

## Preservation and single-writer gate

- Branch: `integration/durable-state-final`
- Single-writer observation: PASS; no process owned the repository, no relevant
  open files existed, and source mtimes were stable for 16 seconds.
- Backup: `/opt/codestra/backups/program-gates/gate-01-sip/20260720-200820`
- Backup checksum and archive readability: PASS
- Pre-existing reconciliation reports were preserved and excluded from the
  scoped source checkpoint.

## Isolated validation topology

- Python: 3.12.11
- Validation image: `codestra/sip-provisioning:0.2.0-durable`
- PostgreSQL: `postgres:17.6-alpine`
- Redis: `redis:7.4.5-alpine`
- Docker network: internal-only
- Published PostgreSQL ports: none
- Published Redis ports: none
- Published SIP API port 8110: none
- Runtime test passwords and keys: generated ephemerally, stored only in
  mode-600 temporary files, and deleted by cleanup traps
- Validation containers and volumes after the run: absent

## Migration and schema results

- Empty database upgrade to `0001_durable_state`: PASS
- `schema_state.schema_version`: `1`
- Required tables: PASS
  - `endpoint_assignment`
  - `sip_session`
  - `audit_event`
  - `idempotency_record`
  - `credential_rotation`
  - `schema_state`
- Downgrade to base: PASS; durable table count after downgrade was zero
- Re-upgrade to head: PASS
- ORM/migration consistency (`alembic check`): PASS; no new upgrade operations
- Partial unique active-session index represented in ORM: YES
- Audit timestamp index represented in ORM: YES

## Durable lifecycle results

- Process-local authoritative state: NO
- Durable assignment: PASS
- One subject to one endpoint: PASS
- One endpoint to one subject: PASS
- One active session per subject: PASS
- Concurrent create: PASS
- Multiple service instances/workers: PASS
- Restart persistence: PASS
- Redis TTL enforcement: PASS
- AES-256-GCM Redis credential encryption: PASS
- Plaintext SIP credential in PostgreSQL: NO
- Revoke deletes runtime credential: PASS
- Renew rotates exactly once: PASS
- Renew replay rotates again: NO
- Same idempotency key with changed payload: HTTP 409
- Replay guard: PASS
- Rate limit enforcement and TTL: PASS
- Expiration reconciliation: PASS
- Audit recursive redaction: PASS
- Audit hash-chain integrity: PASS
- `/readyz`: PASS
- MockProvisioner capability: active and network-free

## Quality and contract results

- Python compilation: PASS using a network-disabled, read-only source mount
- Ruff: PASS
- Strict mypy: PASS, 27 source files
- Pytest: PASS, 17 tests
- Coverage: PASS, 82.37% with an 80% minimum
- OpenAPI JSON parse: PASS
- Runtime OpenAPI equals committed contract: PASS
- OpenAPI version: 3.1.0
- OpenAPI external server declaration: absent
- Secret and sensitive-file scan: PASS
- Process-local store scan: PASS
- Prohibited host/integration/shell scan: PASS

## Corrections made

- Replaced fixed validation placeholders with required runtime-provided
  ephemeral values.
- Declared the canonical partial unique session index and audit timestamp index
  in ORM metadata so migration and model ownership agree.
- Added explicit coverage for renew rotation/replay, PostgreSQL plaintext
  exclusion, encrypted Redis envelopes, readiness, request limits, rate limits,
  replay protection, and recursive redaction.

## Evidence

- `/opt/codestra/program-gates/evidence/gate-01-sip/final-validation.log`
- `/opt/codestra/program-gates/evidence/gate-01-sip/isolated-validation.log`
- `/opt/codestra/program-gates/evidence/gate-01-sip/consistency-and-static.log`
- `/opt/codestra/program-gates/manifests/program-evidence-SHA256SUMS`

The historical blocked toolchain reports remain preserved for audit history but
are superseded by the isolated validation evidence above.

## Rollback

1. Stop only an isolated Gate 1 validation project if present.
2. Restore the source archive from the recorded backup, or revert checkpoint
   `b983f1b4d1a54281d2d83dac908b4160ddb00e34` after preserving later work.
3. No production database or Redis rollback is required because neither was
   modified.

## Safety confirmations

- Public session route: OFF
- MockProvisioner: active
- Production migrations: NONE
- Production Redis keys: NONE
- Live Asterisk provisioning: OFF
- Endpoint 6101 created or assigned: NO
- Port 8110 published: NO
- Protected telephony server contacted: NO
- Asterisk modified: NO
- VICIdial modified: NO
- WSS/SIP registration performed: NO
- Calls originated: NO
- External messages sent: NO

## Next gate

Gate 2 may begin with its own single-writer check and checkpoint. Its first
mandatory technical action is the isolated owner-preserving and portable
identity database restore validation. Public identity activation remains out of
scope until every Gate 2 acceptance condition passes.
