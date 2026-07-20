# API state requirements

Mutating routes require authorization, `Idempotency-Key`, and
`X-Client-Instance-ID`. Responses are `no-store`. Durable service failures
must return a fail-closed dependency error; mock provisioning remains the only
active provisioner.
