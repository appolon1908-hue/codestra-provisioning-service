# Keycloak Provisioning Test Results

Execution: 2026-07-26 UTC, realm `codestra`, staging-only identities prefixed
`KP-STAGING` / `kp-staging`.

| Acceptance | Result |
|---|---|
| Valid disabled creation | PASS |
| Duplicate request, username and identity | PASS |
| Wrong client / missing or wrong scope | PASS |
| Expired token / disabled client | PASS |
| Group and role isolation | PASS |
| Nine signed claim mappings | PASS |
| Password and MFA required actions | PASS |
| Activation | PASS |
| Session logout/revocation endpoint | PASS |
| Suspension / reactivation / termination | PASS |
| Reconciliation / privilege drift | PASS |

Unit suite: 25 tests passed. Live acceptance assigned an approved nested
staging group, realm role, and desktop client role, verified required actions,
activated without email, reconciled aligned state, detected intentional drift,
suspended, reactivated, and terminated. The final user is disabled. Temporary
negative-test clients and credentials were deleted.

```text
KEYCLOAK_SERVICE_CLIENT_GATE=PASS
KEYCLOAK_USER_PROVISIONING_GATE=PASS
KEYCLOAK_ROLE_MAPPING_GATE=PASS
KEYCLOAK_MFA_GATE=PASS
KEYCLOAK_SESSION_REVOCATION_GATE=PASS
KEYCLOAK_RECONCILIATION_GATE=PASS
```

The client has no `realm-admin`. Production users were not selected, updated,
disabled, or deleted.
