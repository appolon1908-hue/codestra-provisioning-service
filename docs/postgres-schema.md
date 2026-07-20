# PostgreSQL durable schema

Alembic revision `0001_durable_state` creates assignments, sessions, audit
events, idempotency records, credential rotations, and schema state. The only
credential value stored in PostgreSQL is an HMAC fingerprint; plaintext and
encrypted credential material remain outside PostgreSQL.
