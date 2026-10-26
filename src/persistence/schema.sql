CREATE TABLE service_meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL CHECK(schema_version=5),
 instance_id TEXT NOT NULL, boot_epoch INTEGER NOT NULL CHECK(boot_epoch>=0),
 mutation_epoch INTEGER NOT NULL CHECK(mutation_epoch>=0)
) STRICT;
CREATE TABLE principals (
 principal_id TEXT PRIMARY KEY, uid INTEGER NOT NULL CHECK(uid>=0 AND uid<4294967295),
 generation INTEGER NOT NULL CHECK(generation>0), state TEXT NOT NULL CHECK(state IN ('enabled','disabled')),
 created_at INTEGER NOT NULL, UNIQUE(uid,generation)
) STRICT;
CREATE UNIQUE INDEX enabled_uid ON principals(uid) WHERE state='enabled';
CREATE TABLE vaults (vault_id TEXT PRIMARY KEY, relative_path TEXT UNIQUE NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','maintenance','retired'))) STRICT;
CREATE TABLE keys (
 key_id TEXT PRIMARY KEY, vault_id TEXT NOT NULL REFERENCES vaults(vault_id), did TEXT NOT NULL, kid TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'unclassified' CHECK(role IN ('unclassified','root','hot','recovery','challenge','device_signing','key_agreement')),
 purpose TEXT NOT NULL DEFAULT '' CHECK(purpose IN ('','device_assertion','application_assertion')),
 envelope_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','maintenance','retired')),
 identity_epoch INTEGER NOT NULL CHECK(identity_epoch>=0), generation INTEGER NOT NULL CHECK(generation>=0), document_digest TEXT NOT NULL, UNIQUE(vault_id,kid),
 CHECK((role='device_signing') = (purpose<>''))
) STRICT;
CREATE TABLE policies (
 policy_id TEXT NOT NULL, version INTEGER NOT NULL CHECK(version>0), content TEXT NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(policy_id,version)
) STRICT;
CREATE TRIGGER immutable_policy_update BEFORE UPDATE ON policies BEGIN SELECT RAISE(ABORT,'immutable policy'); END;
CREATE TRIGGER immutable_policy_delete BEFORE DELETE ON policies BEGIN SELECT RAISE(ABORT,'immutable policy'); END;
CREATE TABLE grants (
 grant_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(principal_id),
 key_id TEXT NOT NULL REFERENCES keys(key_id), policy_id TEXT NOT NULL, policy_version INTEGER NOT NULL,
 boot_epoch INTEGER NOT NULL CHECK(boot_epoch>=0), expiry INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('request','session')),
 created_at INTEGER NOT NULL CHECK(created_at>=0),
 max_uses INTEGER NOT NULL CHECK(max_uses>0), used_uses INTEGER NOT NULL CHECK(used_uses>=0 AND used_uses<=max_uses),
 max_renewals INTEGER NOT NULL CHECK(max_renewals>=0), renewals INTEGER NOT NULL CHECK(renewals>=0 AND renewals<=max_renewals),
 state TEXT NOT NULL CHECK(state IN ('active','revoked','revoked_restart','exhausted','expired')),
 FOREIGN KEY(policy_id,policy_version) REFERENCES policies(policy_id,version)
) STRICT;
CREATE TABLE grant_operations (grant_id TEXT NOT NULL REFERENCES grants(grant_id), operation TEXT NOT NULL, PRIMARY KEY(grant_id,operation)) STRICT;
CREATE TABLE requests (
 principal_id TEXT NOT NULL REFERENCES principals(principal_id), request_id TEXT NOT NULL,
 grant_id TEXT NOT NULL REFERENCES grants(grant_id), input_digest TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('reserved','completed','failed_reserved','outcome_unknown','denied')),
 result BLOB, result_expiry INTEGER, PRIMARY KEY(principal_id,request_id)
) STRICT;
CREATE TABLE admin_operations (
 operation_id TEXT PRIMARY KEY, actor INTEGER NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL,
 digest TEXT NOT NULL, identity_epoch INTEGER NOT NULL CHECK(identity_epoch>=0), boot_epoch INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, monotonic_deadline INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('prepared','committed','expired_restart'))
) STRICT;
CREATE TABLE audit_events (
 seq INTEGER PRIMARY KEY CHECK(seq>0), prev TEXT NOT NULL, event_digest TEXT NOT NULL, event_data BLOB NOT NULL
) STRICT;

CREATE TABLE file_operations (
 operation_id TEXT PRIMARY KEY REFERENCES admin_operations(operation_id),
 vault_id TEXT NOT NULL REFERENCES vaults(vault_id), did TEXT NOT NULL,
 before_digest TEXT NOT NULL, after_digest TEXT NOT NULL, document BLOB NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','complete'))
) STRICT;

CREATE TABLE grant_deadlines (grant_id TEXT PRIMARY KEY REFERENCES grants(grant_id), monotonic_deadline INTEGER NOT NULL) STRICT;
