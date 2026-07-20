# Durable SIP state layer report

Implemented artifacts:

- Alembic revision `0001_durable_state` for assignments, sessions, audit,
  idempotency, credential rotations, and schema state.
- SQLAlchemy models for credential rotations and schema state.
- Redis keyspace builder with hashed subject/endpoint components.
- Credential HMAC fingerprinting and Fernet encryption helper.
- Redis-backed lock, replay, and rate-limit service boundaries.
- Assignment, session, credential, idempotency, and audit service boundaries.
- Offline-only Asterisk artifact provisioner; no network or shell capability.

The running API is not activated and still contains its prior process-local
mock route implementation; wiring the FastAPI routes to a real PostgreSQL and
Redis dependency requires a separate deployment/configuration step. No
database migration was applied, no Redis keys were created, and no external
system was contacted. MockProvisioner remains the only active provisioner.

Checks: source inspection confirms no `65.21.67.207`, Asterisk CLI, AMI, ARI,
endpoint 6101, or production credential. Existing isolated tests remain the
only runtime tests until durable test containers are provisioned.
