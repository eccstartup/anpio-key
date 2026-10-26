-- Session grants (P1). Existing rows are all request grants: one HTTP signature each.
-- ALTER TABLE rather than rebuild: `requests` has a LIVE foreign key to `grants`,
-- and `PRAGMA foreign_keys` cannot be turned off inside the migration transaction.
ALTER TABLE grants ADD COLUMN kind TEXT NOT NULL DEFAULT 'request' CHECK(kind IN ('request','session'));
ALTER TABLE grants ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0 CHECK(created_at>=0);
ALTER TABLE grants ADD COLUMN max_renewals INTEGER NOT NULL DEFAULT 0 CHECK(max_renewals>=0);
ALTER TABLE grants ADD COLUMN renewals INTEGER NOT NULL DEFAULT 0 CHECK(renewals>=0 AND renewals<=max_renewals);
CREATE TABLE grant_operations (grant_id TEXT NOT NULL REFERENCES grants(grant_id), operation TEXT NOT NULL, PRIMARY KEY(grant_id,operation)) STRICT;
INSERT INTO grant_operations SELECT grant_id,'SIGN_HTTP' FROM grants;
CREATE TABLE service_meta_v4 (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL CHECK(schema_version=4),
 instance_id TEXT NOT NULL, boot_epoch INTEGER NOT NULL CHECK(boot_epoch>=0), mutation_epoch INTEGER NOT NULL CHECK(mutation_epoch>=0)
) STRICT;
INSERT INTO service_meta_v4 SELECT singleton,4,instance_id,boot_epoch,mutation_epoch FROM service_meta;
DROP TABLE service_meta;
ALTER TABLE service_meta_v4 RENAME TO service_meta;
PRAGMA user_version=4;
