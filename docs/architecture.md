# Architecture

The service runs only on the application server and listens on `0.0.0.0:8110`
inside its container. The deployment proposal publishes no host port and joins
only the internal `codestra_backend` network. No Caddy or edge-network route is
part of this task.

PostgreSQL is authoritative for endpoint assignments, lifecycle records,
idempotency outcomes, credential fingerprints, rotations, schema compatibility,
and hash-chained audit. Redis owns only expiring runtime state: encrypted
credential envelopes, sessions, leases, locks, replay claims, rate-limit
windows, and endpoint cache. Every Redis write has a positive TTL.

API workers contain no correctness-critical dictionary, lock, assignment,
session, credential, rate-limit, replay, or idempotency store. Independent
workers coordinate through PostgreSQL constraints/transactions and Redis locks.

`MockProvisioner` is the sole active provisioner. It has no network or shell
capability. Live provisioning flags and endpoint 6101 fail closed. Trusted
authentication remains a separate approval gate, so public session routing is
disabled.
