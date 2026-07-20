# Deployment proposal

Use a non-root container, read-only filesystem, dropped capabilities, internal
network only, resource limits, and a separately provisioned PostgreSQL database
and Redis namespace. Do not merge this proposal into the active Compose or Caddy
configuration until live authorization is separately approved.
