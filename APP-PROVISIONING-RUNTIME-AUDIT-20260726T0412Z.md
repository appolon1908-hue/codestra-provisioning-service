# APP-PROVISIONING runtime completion audit

Cutoff: `2026-07-26T04:12Z`

## Attributable state

```text
HOSTNAME=middleware
REPOSITORY=/root/codestra-provisioning-service
BRANCH=codex/app-provisioning-completion-20260725
IMPLEMENTATION_COMMIT=a464b27
STAGING_IMAGE=codestra/provisioning-service:app-provisioning-audit-20260726
STAGING_IMAGE_ID=sha256:1229f5fdd103891cf819240da387ae22f5eb21d02a3429af652ae4bc3042ab26
HOST_PORTS=none
RUNTIME_HEALTH=healthy
```

Runtime hashes for `contracts.py`, `repository.py`, `engine.py`,
`adapters.py`, and `main.py` match the owned repository.

The fresh pre-change bundle, consistent SQLite backup, compose backup, and
checksums are at
`/root/codestra-provisioning-service-backup-20260726T040217Z`.

## Completion audit

| Requirement | Authoritative evidence | Result |
|---|---|---|
| API and private authentication | Strict JWT/API tests; private TLS health/readiness; no host ports | PASS |
| Durable step engine | Atomic WAL claims, ordered steps, durable request/step state | PASS |
| Idempotency | Replay, payload-conflict, concurrent duplicate, and external replay tests | PASS |
| Retry and dead letter | Bounded transient retry and permanent/exhausted dead-letter tests | PASS |
| Safe compensation | Remove-access/suspend/revoke only; no delete operation; durable bounded compensation retry after restart | PASS |
| Created disabled first | Activation rejects an update-only history | PASS |
| Mandatory verification before Active | Durable per-system verification evidence gates activation across restart | PASS |
| Signed callbacks | HMAC, timestamp, event ID and idempotency headers; live private duplicate replay accepted without payload exposure | PASS |
| Adapter contracts | Odoo, Keycloak, telephony, SIP browser, mailbox, Agent Desktop, n8n event, secret storage, verification, reconciliation | PASS |
| Reconciliation truth | Drift response is now a failed/drift result, never `aligned` | PASS |
| Health/readiness/metrics | All returned HTTP 200 over private TLS after deployment and restart | PASS |
| Secret-file references | Protected regular-file validation and recursive inline-secret rejection | PASS |
| Runtime integration | 42 isolated container tests; live Keycloak acceptance; private telephony reconciliation; signed callback replay | PASS |
| Restart recovery | Staging restart retained exactly 18 executions and 48 steps | PASS |
| Rollback | Backup integrity passed; prior image opened an isolated restored copy successfully | PASS |

## Live adapter probes

### Keycloak

The fresh staging-only acceptance identity passed:

```text
disabled_creation=PASS
duplicate_request=PASS
duplicate_username=PASS
duplicate_identity=PASS
password_required_action=PASS
mfa_required_action=PASS
group_assignment=PASS
realm_role_assignment=PASS
client_role_assignment=PASS
activation=PASS
session_revocation=PASS
suspension=PASS
reactivation=PASS
termination=PASS
reconciliation=PASS
privilege_drift=PASS
```

The final synthetic user state is terminated/disabled. It was not deleted.

### Telephony and SIP

Read-only reconciliation through the private mTLS/HMAC provisioning contract
returned `aligned` for synthetic non-customer VICIdial and SIP probes. No live
write flag was enabled.

### Callback

A previously delivered service callback was replayed through the signed
private HTTPS binding. The Odoo endpoint accepted its idempotent duplicate;
the payload was not printed.

### Odoo provisioning

The service callback binding is live, but it is not an Odoo provisioning
adapter. The Odoo component exposes the documented signed callback route only.
The provisioning-service `odoo` adapter remains explicitly disabled and has
no approved private base URL or protected credential reference. No substitute
database access or callback misuse was attempted.

## Fail-closed state

The observed staging control set remains:

```text
SEND_EVENTS=false
PRODUCTION_CALLBACKS_ENABLED=false
VICIDIAL_WRITES_ENABLED=false
EXTERNAL_DIAL_ENABLED=false
TRANSFERS_ENABLED=false
N8N_PRODUCTION_WORKFLOWS_ENABLED=false
WEBRTC_PRODUCTION_ROUTES_ENABLED=false
ALLOW_LIVE_EMAIL=false
ALLOW_LIVE_SMS=false
ALLOW_LIVE_CALLS=false
ALLOW_CAMPAIGN_ACTIVATION=false
```

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

The Odoo gate requires the Odoo component owner to expose and authorize a
private provisioning API contract. That change is outside this component's
repository and database ownership.
