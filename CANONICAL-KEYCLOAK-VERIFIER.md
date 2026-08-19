# Canonical Keycloak machine-token verifier

The provisioning service accepts only the canonical issuer
`https://auth.codestra.co/realms/codestra`, audience
`codestra-provisioning-service`, and authorized party
`codestra-provisioning-service-staging` for the TEST_SYN webphone machine path.
The canonical JWKS endpoint supplies signing keys over verified HTTPS.

Tokens must carry integer `iat` and `exp` claims, `exp` must be later than
`iat`, and their difference must not exceed 300 seconds. `jti` is mandatory and
single-use. `codestra_scopes` must contain exactly `identity:rotate`,
`provisioning:execute`, and `provisioning:read`; realm or client roles never
substitute for these route permissions.

Machine tokens are not tenant authority. Canonical browser subject validation
and the Odoo identity lookup bind tenant `COD`, campaign `TEST_SYN`, and
extension `6101`. The provisioning request model rejects client-supplied tenant
and production-mode fields, and the session manager independently restricts the
certification campaign and endpoint.

The release advances the recovered runtime baseline with the last clean local
safety implementations for adapter contracts, activation verification,
reconciliation drift, durable compensation, logging, mailbox state, and
repository behavior. It deliberately excludes all six uncommitted files from
the original Server A checkout; their binary-safe recovery patches remain in
root-only evidence.
