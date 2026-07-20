# Redis key model

Namespace: `codestra:sip:v1`.

| Key | Value | TTL |
|---|---|---|
| `sessions:<uuid>` | non-secret runtime state | remaining session + 60s |
| `credentials:<uuid>` | AES-256-GCM JSON envelope | remaining session |
| `credentials:<uuid>:previous` | prior encrypted envelope | at most 15s |
| `leases:<subject_hmac>` | session UUID | remaining session |
| `locks:<subject_hmac>:<operation>` | random ownership token | 20s |
| `replay:<nonce_hmac>` | first-use marker | 15m |
| `ratelimit:<subject_hmac>:<route>:<window>` | counter | window + 1s |
| `endpoints:<mock-name>` | subject HMAC | at most 30m |

Subject, client, idempotency, and nonce identifiers use domain-separated keyed
HMAC-SHA256. Key builders reject control characters and invalid endpoint
formats. All writes set TTL atomically. PostgreSQL remains the durable source.

Credential envelopes bind service, session UUID, subject hash, endpoint, and
key version as AES-GCM additional authenticated data. Envelopes are never
logged or stored in PostgreSQL.
