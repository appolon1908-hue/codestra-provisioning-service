# APP-PROVISIONING completion record

Verified: `2026-07-26T04:00Z`

## Provenance and preservation

```text
HOSTNAME=middleware
REPOSITORY=/root/codestra-provisioning-service
ORIGINAL_BRANCH=main
ORIGINAL_COMMIT=443817236cd19da45ad69ee99ce28c7903278540
WORK_BRANCH=codex/app-provisioning-completion-20260725
IMPLEMENTATION_COMMIT=eed6973
ORIGINAL_DIRTY_STATE=untracked Python cache directories only
COMPONENT_LOCK=/run/lock/codestra-app-provisioning.lock
```

Unknown work was preserved at
`/root/codestra-provisioning-service-preservation-20260725T2351AST`.
All entries in its `SHA256SUMS` file verified.

The repository bundle, consistent SQLite backup, and compose backup are at
`/root/codestra-provisioning-service-backup-20260725T2352AST`. All checksums
verified.

## Implemented controls

- Private TLS API with strict JWT issuer, audience, client, scope, freshness,
  replay, body-size, and rate-limit enforcement.
- WAL-backed executions, atomic step claims, per-request and per-step
  idempotency, bounded exponential retry, dead letters, callback retry state,
  compensation state, and stale-work recovery.
- Odoo, Keycloak, telephony provisioning, SIP browser-session, mailbox,
  Agent Desktop, n8n notification, protected credential-storage,
  verification, and reconciliation contracts.
- Accounts are created disabled. Activation is rejected until durable
  verification evidence exists for every latest mandatory create/update step.
- Later-step failures never delete a successful external identity.
  Compensation is limited to remove-excess-access, suspend, or revoke.
- Signed, replay-safe HTTPS callbacks with no credentials in URLs.
- Secret values load only from protected regular-file references. Plaintext
  credential-bearing payload keys are rejected recursively.
- Health, readiness, metrics, callback backlog, dead-letter, adapter,
  compensation, and recovery observability.

## Validation

```text
ISOLATED_CONTAINER_TESTS=39 passed
RUFF=PASS
CANDIDATE_IMAGE_USER=10001:10001
SECRET_SCAN=PASS
DATABASE_BACKUP_INTEGRITY=ok
ISOLATED_ROLLBACK_RESTORE=PASS
```

The actual staging-only service was restarted. Before/after durable counts
matched exactly: 13 executions, 33 steps, 6 historical dead letters,
13 callbacks, and 2 compensation records. It returned healthy; `/health`,
`/ready`, and `/metrics` returned HTTP 200 over private TLS.

The live callback binding is credential-free private HTTPS. Nine historical
callbacks are delivered, none is pending, and four exhausted historical
callback records remain observable. No record was deleted or rewritten.

The live Odoo provisioning adapter remains explicitly disabled because no
approved private Odoo provisioning endpoint/credential is present in the
service-owned configuration. This control was not bypassed.

## External adapter status

```text
ODOO=BLOCKED_EXTERNAL_PREREQUISITE
KEYCLOAK=PASS
TELEPHONY_PROVISIONING=BLOCKED_EXTERNAL_PREREQUISITE
SIP_BROWSER_SESSIONS=BLOCKED_EXTERNAL_PREREQUISITE
MAILBOX_PROVIDER=BLOCKED_EXTERNAL_PREREQUISITE
AGENT_DESKTOP_REVOCATION=BLOCKED_EXTERNAL_PREREQUISITE
N8N_EVENT_NOTIFICATION=BLOCKED_EXTERNAL_PREREQUISITE
```

The blocked adapters have complete fail-closed contracts but lack an approved
enabled runtime binding. The deterministic mailbox adapter is a staging test
double and is not claimed as a provider-backed runtime pass.

## Required gates

```text
PROVISIONING_SERVICE_GATE=PASS
ODOO_PROVISIONING_BINDING_GATE=BLOCKED_EXTERNAL_PREREQUISITE
STEP_ENGINE_GATE=PASS
IDEMPOTENCY_GATE=PASS
RETRY_GATE=PASS
DEAD_LETTER_GATE=PASS
CALLBACK_GATE=PASS
PARTIAL_PROVISIONING_RUNTIME_GATE=PASS
RECONCILIATION_GATE=PASS
RESTART_RECOVERY_GATE=PASS
SECRET_STORAGE_GATE=PASS
ROLLBACK_GATE=PASS
```

No production workflow, callback, account, email, SMS, call, campaign, or
route was activated. No external component repository or database was
modified.
