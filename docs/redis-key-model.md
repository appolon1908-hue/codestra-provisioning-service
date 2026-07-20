# Redis key model

`RedisKeyspace` constructs the required `codestra:sip:v1:*` keys. Subject and
endpoint components are SHA-256 digests; raw usernames and secrets never enter
keys. Credentials, leases, locks, replay claims, and rate-limit windows must
always be written with explicit TTLs.
