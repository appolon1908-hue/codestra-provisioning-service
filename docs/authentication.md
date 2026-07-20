# Trusted authentication and authorization

The service supports three deliberately separate principal sources:

- `jwt`: an OIDC/JWT access token signed by an explicitly allowed asymmetric algorithm. The service validates signature, issuer, audience, `sub`, `exp`, `nbf`, token type, roles, scopes, and configured clock skew. Verification uses either one HTTPS JWKS URL or one pinned public key; configuring both or neither fails startup.
- `mtls`: a service principal selected by the SHA-256 fingerprint of the actual TLS peer certificate exposed by the ASGI server. Identity headers are never trusted. Only `service_*` roles are accepted.
- `test`: a test-token provider accepted only with `APP_ENV=test`. It cannot be selected in preproduction or production.

`disabled_trusted` is the safe default. In that mode session mutations return a fail-closed authentication error. A trusted mode requires `LIVE_AUTHORIZATION_ENABLED=true`; all other modes require it to remain false. `PUBLIC_SESSION_ROUTE_ENABLED` remains false until a trusted issuer or approved mTLS client is configured and separately approved.

## SIP route policy

| Operation | Required scope | Allowed human roles | Allowed service role |
|---|---|---|---|
| Create session | `sip:session:create` | agent, closer, supervisor, manager, platform_admin | service_sip |
| Renew session | `sip:session:renew` | agent, closer, supervisor, manager, platform_admin | service_sip |
| Revoke session | `sip:session:revoke` | agent, closer, supervisor, manager, platform_admin | service_sip |

Renew and revoke also require durable ownership of the target session. `compliance_auditor` cannot mutate. `service_vicidial` and `service_n8n` cannot mutate SIP sessions even if a malformed token grants a SIP scope. No role, including `platform_admin`, can retrieve an already-issued plaintext credential; no such recovery route exists.

Every authentication and authorization allow or deny is appended to the existing PostgreSQL audit hash chain. Audit metadata includes only a reason code and keyed subject hash; it never includes the Authorization header, JWT, certificate, credential, or connection secret.

## Configuration

JWT mode requires `JWT_ISSUER`, `JWT_AUDIENCE`, exactly one of `JWT_JWKS_URL` or `JWT_PINNED_PUBLIC_KEY`, a non-empty `JWT_ALLOWED_ALGORITHMS` list, and configured claim names/type/skew. Only RS256/384/512 and ES256/384/512 are accepted. `none` and symmetric algorithms are rejected.

mTLS mode requires `MTLS_PRINCIPALS`, keyed by lowercase certificate SHA-256 fingerprint, with a stable subject plus allowlisted service roles and scopes. TLS termination must provide the verified peer certificate directly to the ASGI scope; forwarding a certificate identity in an HTTP header is unsupported by design.
