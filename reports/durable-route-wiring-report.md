# Durable SIP route wiring report

## Outcome

FastAPI no longer contains or uses the former process-local `Store`. The
application factory wires routes to `DurableSessionService`, which uses
PostgreSQL transactions, Redis locks/rate limits/replay state, encrypted Redis
credential state, and the offline-only `MockProvisioner`.

Changed route surface:

- `POST /api/v1/sip/session`
- `POST /api/v1/sip/session/renew`
- `DELETE /api/v1/sip/session`
- `/readyz` now checks PostgreSQL, Redis, migration revision, and safety flags.

The service remains internal-only and no production migration or route
activation was performed.

## Safety

- MockProvisioner active: YES
- Live Asterisk provisioning: NO
- Endpoint 6101: not created and disallowed
- `65.21.67.207` contacted: NO
- Plaintext SIP credentials in PostgreSQL: NO
- Public route activated: NO
- Port 8110 exposed publicly: NO

Credentials are returned only in the create/renew response and stored in
encrypted Redis envelopes with TTL. PostgreSQL stores fingerprints and
rotation metadata only. Idempotency keys and subjects are HMAC-derived before
persistence. Route handlers contain no mutable runtime dictionaries.

## Validation

- Python AST compilation: passed
- `git diff --check`: passed
- Process-local Store scan: passed (no Store/dictionary runtime state in routes)
- Durable service route scan: passed
- Full pytest/mypy/Ruff/pip-audit were not runnable in this environment because
  the repository virtualenv does not contain those tools; no dependencies were
  installed and no production migration was attempted.

## Commit/status

The worktree includes the durable lifecycle/dependency modules present since
the checkpoint plus the route wiring and model/service alignment. Commit after
review with the repository’s configured identity; no secrets were added.

Known limitation: the existing lifecycle service and migration/model metadata
should be exercised against an isolated PostgreSQL/Redis test stack before any
deployment. This task intentionally stopped before production migration,
container activation, or Asterisk integration.
