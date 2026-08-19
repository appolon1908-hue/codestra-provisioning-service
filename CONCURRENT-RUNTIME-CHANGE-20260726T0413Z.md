# Concurrent APP-PROVISIONING runtime change

Observed: `2026-07-26T04:13Z`

The active component session held
`/run/lock/codestra-app-provisioning.lock` and had deployed the audited
repository candidate. A separate actor subsequently:

- rewrote `deploy/staging-candidate.override.yaml` from
  `app-provisioning-audit-20260726` to
  `identity-integration-20260726-v14`;
- recreated the staging service using that image; and
- updated `/opt/codestra/provisioning-service` to the same source as `v14`.

The `v14` runtime is healthy, private, and has no host ports, but its source
does not match repository commit `a464b27`. It does not contain the audited
durable mandatory-verification activation guard, reconciliation drift
classification, or bounded restart recovery for failed compensation.

The unknown tracked override diff and runtime image metadata were preserved
without modification at:

```text
/root/codestra-provisioning-service-preservation-20260726T0413Z
```

All preservation checksums pass. The concurrent override remains untouched in
the worktree. The audited candidate was not redeployed over it.

Current gate impact:

```text
PROVISIONING_SERVICE_GATE=FAIL
ODOO_PROVISIONING_BINDING_GATE=BLOCKED_EXTERNAL_PREREQUISITE
STEP_ENGINE_GATE=FAIL
IDEMPOTENCY_GATE=PASS
RETRY_GATE=PASS
DEAD_LETTER_GATE=PASS
CALLBACK_GATE=PASS
PARTIAL_PROVISIONING_RUNTIME_GATE=FAIL
RECONCILIATION_GATE=FAIL
RESTART_RECOVERY_GATE=PASS
SECRET_STORAGE_GATE=PASS
ROLLBACK_GATE=PASS
```

`FAIL` reflects the authoritative current staging runtime, not the repository
candidate, whose 42-test container suite passes.
