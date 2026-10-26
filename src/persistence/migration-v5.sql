-- Device signing keys (P2). `keys` cannot gain a role value or a purpose binding
-- through ALTER TABLE: the role CHECK is part of the table definition, and
-- `grants` holds a live foreign key to it. Rebuild the table instead; the caller
-- turns `PRAGMA foreign_keys` off outside this transaction and runs
-- `PRAGMA foreign_key_check` before accepting the result.
--
-- `key_agreement` is admitted here although nothing can bind it yet: adding the
-- role now keeps P3's X25519 keys from needing a second rebuild of this table.
CREATE TABLE keys_v5 (
 key_id TEXT PRIMARY KEY, vault_id TEXT NOT NULL REFERENCES vaults(vault_id), did TEXT NOT NULL, kid TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'unclassified' CHECK(role IN ('unclassified','root','hot','recovery','challenge','device_signing','key_agreement')),
 purpose TEXT NOT NULL DEFAULT '' CHECK(purpose IN ('','device_assertion','application_assertion')),
 envelope_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','maintenance','retired')),
 identity_epoch INTEGER NOT NULL CHECK(identity_epoch>=0), generation INTEGER NOT NULL CHECK(generation>=0), document_digest TEXT NOT NULL, UNIQUE(vault_id,kid),
 -- A device signing key is always bound to exactly one purpose; every other
 -- role carries none. The binding is set by ConfirmRole and cannot be edited
 -- afterwards without revoking the grants that name the key.
 CHECK((role='device_signing') = (purpose<>''))
) STRICT;
INSERT INTO keys_v5(key_id,vault_id,did,kid,role,purpose,envelope_digest,state,identity_epoch,generation,document_digest)
 SELECT key_id,vault_id,did,kid,role,'',envelope_digest,state,identity_epoch,generation,document_digest FROM keys;
DROP TABLE keys;
ALTER TABLE keys_v5 RENAME TO keys;
CREATE TABLE service_meta_v5 (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL CHECK(schema_version=5),
 instance_id TEXT NOT NULL, boot_epoch INTEGER NOT NULL CHECK(boot_epoch>=0), mutation_epoch INTEGER NOT NULL CHECK(mutation_epoch>=0)
) STRICT;
INSERT INTO service_meta_v5 SELECT singleton,5,instance_id,boot_epoch,mutation_epoch FROM service_meta;
DROP TABLE service_meta;
ALTER TABLE service_meta_v5 RENAME TO service_meta;
PRAGMA user_version=5;
