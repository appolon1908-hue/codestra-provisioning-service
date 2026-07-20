# Concurrent work reconciliation

Recorded: 2026-07-20, America/Santo_Domingo

## Active writer status

- Other Codex orchestration processes exist on the host.
- No Alembic, pytest, mypy, Ruff, SIP build, or migration process was running.
- No process had an open file below this repository during the audit.
- Two source-tree hashes and Git status snapshots taken ten seconds apart were identical.
- Active repository writer: **NO**.

No protected telephony host was resolved, probed, or contacted. No Caddy,
deployment, public-route, endpoint, or production-service action was performed.

## Repository reconciliation

The supplied current-state description was stale:

- Supplied branch: `finish/sip-provisioning-production` at `2baaa05`.
- Actual clean branch: `integration/durable-state-final` at `07c72bc`.
- History is linear: `2d6bd7a` → `2baaa05` → `3bdce32` → `07c72bc`.
- Uncommitted files discovered: **none**.
- Uncommitted diffs inspected: **none**.

Previously concurrent files were preserved in logical commits rather than
deleted as unknown work:

- `2baaa05` — durable state primitives.
- `3bdce32` — route wiring and lifecycle integration.
- `07c72bc` — coherent migration/model/service reconciliation, tests, docs,
  internal-only deployment proposal, dependency remediation, SBOM, and reports.

## Per-file classification relative to `finish/sip-provisioning-production`

| File | Classification | Finding |
|---|---|---|
| `alembic.ini` | compatible | Alembic source path/invalid placeholder only |
| `deploy/Dockerfile` | compatible | non-root internal listener; no host publication |
| `deploy/compose.proposal.yaml` | compatible | backend-only, no `ports`, no Caddy/edge route |
| `deploy/compose.test.yaml` | compatible | isolated internal PostgreSQL/Redis tests |
| `docs/architecture.md` | compatible | durable ownership and auth boundary |
| `docs/openapi.yaml` | compatible | generated runtime OpenAPI 3.1 |
| `docs/redis-key-model.md` | compatible | HMAC keying, encrypted values, TTL policy |
| `lockfile` | compatible | exact patched dependency pins |
| `migrations/env.py` | compatible | async Alembic runner |
| `migrations/versions/0001_durable_state.py` | compatible | canonical durable schema |
| `pyproject.toml` | compatible | strict lint/type/test configuration |
| `reports/durable-route-wiring-report.md` | incomplete/historical | correctly records the intermediate `3bdce32` state, but its statement that full gates were unavailable is superseded by `07c72bc`; retained, not deleted |
| `reports/durable-state-layer-report.md` | compatible | final validated durable-state evidence |
| `reports/durable-state-precheck.md` | compatible | preserved inventory and plan |
| `reports/sbom.cdx.json` | compatible | CycloneDX dependency inventory |
| `scripts/generate_openapi.py` | compatible | deterministic schema generation with runtime-only fake keys |
| `auth/principal.py` | compatible | typed principal boundary |
| `auth/provider.py` | compatible | test auth restricted to test environment; trusted provider disabled otherwise |
| `config.py` | compatible | typed fail-closed secrets and live flags |
| `dependencies.py` | compatible | async PostgreSQL/Redis/cipher wiring |
| `main.py` | compatible | thin durable routes, no local Store |
| `models/__init__.py` | compatible | canonical model exports |
| `models/database.py` | compatible | matches migration and lifecycle fields |
| `provisioning/asterisk_offline.py` | compatible | offline-only, rejects endpoint 6101 |
| `provisioning/disabled_live.py` | compatible | live operations always fail |
| `schemas/__init__.py` | compatible | strict schema exports |
| `schemas/sessions.py` | compatible | strict request/response models |
| `security/redaction.py` | compatible | recursive sensitive-field redaction |
| `services/__init__.py` | compatible | exports canonical lifecycle service |
| `services/durable.py` | compatible supersession | deleted in `3bdce32` because duplicate/incomplete service definitions were replaced by `services/lifecycle.py`; deletion is committed and reviewed, not unknown work |
| `services/lifecycle.py` | compatible | canonical PostgreSQL/Redis lifecycle |
| `state/__init__.py` | compatible | canonical state exports |
| `state/crypto.py` | compatible | AES-256-GCM and domain-separated fingerprints |
| `state/guards.py` | compatible | distributed lock, replay, and rate-limit primitives |
| `state/redis_keys.py` | compatible | validated namespaced TTL-key builders |
| `tests/test_api.py` | compatible | isolated durability, concurrency, TTL, encryption, audit, and contract tests |

Unrelated files: **none**. Current unresolved source/schema conflicts: **none**.

## Migration graph

- Alembic heads: `0001_durable_state (head)`.
- Parent: `<base>`.
- Duplicate heads: **NO**.
- Missing or out-of-order revision: **NO**.
- Migration/model naming conflict: **NO** in the current integration commit.

## Read-only validation results

- Ruff: **PASS** — all repository checks passed.
- strict mypy: **PASS** — 26 source files.
- pytest: **PASS** — 6 tests against isolated PostgreSQL 17.6 and Redis 7.4.5.
- Test migration upgrade: **PASS**.
- Git diff check from `finish/sip-provisioning-production`: **PASS**.
- Worktree after validation: clean.

## Commits created/preserved

No source commit was necessary during this reconciliation because compatible
work was already preserved in `2baaa05`, `3bdce32`, and `07c72bc`. This report
is the only new reconciliation artifact and should be committed separately.

## Safety state and exact next step

- Public SIP routes remain disabled.
- No API container was deployed.
- Endpoint 6101 was not created or assigned.
- `65.21.67.207` was not contacted, resolved, or probed.
- Caddy was not modified.

Exact safe next step: review and merge/cherry-pick `07c72bc` plus this report
commit from `integration/durable-state-final` into the desired release branch.
Do not deploy or expose session routes until trusted authentication receives a
separate approval and the internal deployment procedure is explicitly authorized.
