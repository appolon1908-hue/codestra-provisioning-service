# Session lifecycle

Create allocates a deterministic synthetic endpoint and one temporary mock
credential. Renew rotates the credential while retaining the endpoint. Revoke
invalidates the session and credential. All responses are `no-store`.
