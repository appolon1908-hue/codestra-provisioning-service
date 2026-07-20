# Rollback

The current build has no active deployment or database migration. Rollback is
therefore removal of the unactivated proposal image and source revision. A
future deployment must back up PostgreSQL and record Redis keyspace policy
before activation.
