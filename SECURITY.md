# Security boundary

This phase is mock-only. No real SIP password, endpoint, Asterisk file,
VICIdial record, Odoo record, or public route is used. The process binds to
`127.0.0.1:8110`; credentials are process-memory test values and never logged,
audited, placed in URLs, cookies, or browser storage. Production persistence
and Redis encryption are deployment prerequisites, not activated here.
