# Threat model

Primary threats are credential leakage, replay, duplicate assignment, owner
confusion, and accidental live provisioning. Controls are no-store responses,
memory-only browser handling, idempotency keys, one-user/one-endpoint mapping,
fail-closed feature flags, mock-only provisioner, redaction, and a future
PostgreSQL/Redis deployment gate.
