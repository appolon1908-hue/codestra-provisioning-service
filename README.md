# Codestra SIP Provisioning API

Mock-only, application-server-side SIP session lifecycle service. It binds
one test identity to one synthetic endpoint and never contacts Asterisk,
VICIdial, Odoo, n8n, or the Agent Desktop. Credentials are returned only from
create/renew responses and are marked memory-only.

Run offline after installing the pinned dependencies:

```sh
python -m uvicorn codestra_sip_provisioning.main:app --host 127.0.0.1 --port 8110
```

The deployment proposal is deliberately not active. Live authorization,
Asterisk provisioning, endpoint 6101, public routing, and all external
integrations remain disabled.
