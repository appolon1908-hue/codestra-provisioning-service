# Keycloak Staging Provisioning

## Security boundary

The confidential client `codestra-provisioning-service-staging` has service
accounts enabled, browser/direct grants disabled, full scope disabled, and only
these `realm-management` roles:

- `query-users`
- `view-users`
- `manage-users`
- `view-clients`
- `view-realm`

`manage-users` is required by Keycloak 26.7 Admin REST for create/update,
enable/disable, required actions, mappings, and logout. `view-realm` resolves
realm roles; `view-clients` resolves client roles. The client does not have
`realm-admin`, `manage-realm`, or `manage-clients`.

Keycloak expands the two view composites to effective `query-clients` and
`query-groups`; these are read-only prerequisites. Thus five roles are
explicitly assigned and seven are effective.

Standard Keycloak admin roles cannot constrain `manage-users` to an entitlement
allowlist. The adapter therefore enforces exact server-side allowlists before
issuing Admin REST calls. Groups are confined below
`/provisioning-staging`; realm and client roles are enumerated in protected
configuration. The secret is root-owned and file-mounted, tokens are short
lived, and the service is private-network only.

## Lifecycle

1. Search exact username and `employee_id`.
2. Create disabled with no credentials.
3. Store nine organizational attributes and an idempotency key.
4. Require `UPDATE_PASSWORD` and `CONFIGURE_TOTP`.
5. Assign only approved staging groups and roles.
6. Enable into `awaiting_required_actions`.
7. Keycloak completes its single-use required-action flow. The provisioning
   service never receives the final password or TOTP seed.
8. Suspension and termination disable the user and call logout. Reactivation
   enables the retained identity.
9. Reconciliation compares state, actions, claims, groups, and roles;
   differences return `privilege_drift`.

`execute-actions-email` support uses a 15-minute lifespan and exact
client/redirect allowlists. It remains fail-closed because staging has no SMTP
and the only desktop redirect is a production hostname. No email was sent.

## Claims

The `codestra_identity_claims` scope maps `employee_id`, `company_id`,
`business_unit_id`, `department_id`, `team_id`, `supervisor_id`,
`campaign_ids`, `role_template`, and `agent_desktop_roles`.

These attributes are administrator-editable and user-readable, not
user-editable. Signed-token mapping was tested with temporary service-account
attributes, which were removed afterward.
