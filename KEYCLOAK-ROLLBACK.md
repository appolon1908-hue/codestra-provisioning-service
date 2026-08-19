# Keycloak Provisioning Rollback

Baseline artifacts:

`/opt/codestra/backups/keycloak-provisioning-20260726T020822Z`

1. Stop only the staging provisioning service.
2. Disable `codestra-provisioning-service-staging`.
3. Disconnect the provisioning container from the staging identity network.
4. Restore the source and Compose archives.
5. For configuration rollback, remove the claim scope mappings, staging group
   tree, and service client with an audited temporary bootstrap administrator.
6. For database rollback, restore the dump into a new PostgreSQL database and
   validate Keycloak startup before any active-database change.
7. Remove the temporary administrator and local configuration.
8. Verify Keycloak health and provisioning-service fail-closed readiness.

The database dump, realm JSON, source, Compose file, runtime state, and SHA-256
manifest are preserved. Production Odoo and production users are not rollback
targets.
