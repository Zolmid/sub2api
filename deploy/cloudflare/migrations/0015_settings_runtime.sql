-- Encrypted, D1-authoritative settings foundation.  The Worker owns the
-- cryptographic checks; SQLite rejects malformed state and unsafe transitions.
INSERT INTO schema_metadata(key, value)
VALUES ('cloudflare_settings_runtime_schema_version', '2026-09-10.v1');

CREATE TABLE IF NOT EXISTS settings_runtime (
  scope_id TEXT NOT NULL CHECK(length(scope_id) = 64 AND scope_id NOT GLOB '*[^0-9a-f]*'),
  setting_key TEXT NOT NULL CHECK(length(setting_key) BETWEEN 1 AND 128 AND setting_key NOT GLOB '*[^A-Za-z0-9._:-]*'),
  version TEXT NOT NULL CHECK(length(version) BETWEEN 1 AND 19 AND version NOT GLOB '*[^0-9]*' AND substr(version,1,1) BETWEEN '1' AND '9' AND (length(version) < 19 OR version <= '9223372036854775807')),
  tombstone INTEGER NOT NULL CHECK(tombstone IN (0,1)),
  envelope_version INTEGER,
  algorithm TEXT,
  key_id TEXT,
  nonce_b64 TEXT,
  ciphertext_b64 TEXT,
  context_tag TEXT,
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at),
  updated_at TEXT NOT NULL CHECK(length(updated_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',updated_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',updated_at)=updated_at AND updated_at >= created_at),
  PRIMARY KEY(scope_id, setting_key),
  CHECK((tombstone=1 AND envelope_version IS NULL AND algorithm IS NULL AND key_id IS NULL AND nonce_b64 IS NULL AND ciphertext_b64 IS NULL AND context_tag IS NULL) OR (tombstone=0 AND envelope_version IS NOT NULL AND envelope_version=1 AND algorithm IS NOT NULL AND algorithm='A256GCM-HKDF-SHA256' AND key_id IS NOT NULL AND length(key_id) BETWEEN 1 AND 64 AND key_id NOT GLOB '*[^A-Za-z0-9._:-]*' AND nonce_b64 IS NOT NULL AND length(nonce_b64) BETWEEN 16 AND 24 AND nonce_b64 NOT GLOB '*[^A-Za-z0-9_-]*' AND ciphertext_b64 IS NOT NULL AND length(ciphertext_b64) BETWEEN 22 AND 21868 AND ciphertext_b64 NOT GLOB '*[^A-Za-z0-9_-]*' AND context_tag IS NOT NULL AND length(context_tag)=64 AND context_tag NOT GLOB '*[^0-9a-f]*'))
);

CREATE TABLE IF NOT EXISTS settings_runtime_batch_guards (
  guard_id TEXT PRIMARY KEY CHECK(length(guard_id)=32 AND guard_id NOT GLOB '*[^0-9a-f]*'),
  expected_count INTEGER NOT NULL CHECK(expected_count BETWEEN 1 AND 16),
  actual_count INTEGER NOT NULL,
  CHECK(expected_count=actual_count)
);

-- A permanent claim is compact CAS history: exactly one request may consume a
-- given observed version, including version 0 for creation.  It prevents two
-- concurrent D1 snapshots from both accepting the same optimistic precondition.
CREATE TABLE IF NOT EXISTS settings_runtime_cas_claims (
  scope_id TEXT NOT NULL CHECK(length(scope_id)=64 AND scope_id NOT GLOB '*[^0-9a-f]*'),
  setting_key TEXT NOT NULL CHECK(length(setting_key) BETWEEN 1 AND 128 AND setting_key NOT GLOB '*[^A-Za-z0-9._:-]*'),
  expected_version TEXT NOT NULL CHECK(length(expected_version) BETWEEN 1 AND 19 AND expected_version NOT GLOB '*[^0-9]*' AND (expected_version='0' OR substr(expected_version,1,1) BETWEEN '1' AND '9') AND (length(expected_version)<19 OR expected_version<='9223372036854775807')),
  request_id TEXT NOT NULL CHECK(length(request_id) BETWEEN 16 AND 128 AND request_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at),
  PRIMARY KEY(scope_id,setting_key,expected_version)
);

CREATE TABLE IF NOT EXISTS settings_runtime_audit (
  audit_id TEXT PRIMARY KEY CHECK(length(audit_id)=32 AND audit_id NOT GLOB '*[^0-9a-f]*'),
  scope_id TEXT NOT NULL CHECK(length(scope_id)=64 AND scope_id NOT GLOB '*[^0-9a-f]*'),
  setting_id TEXT NOT NULL CHECK(length(setting_id)=64 AND setting_id NOT GLOB '*[^0-9a-f]*'),
  operation TEXT NOT NULL CHECK(operation IN ('set','delete')),
  version TEXT NOT NULL CHECK(length(version) BETWEEN 1 AND 19 AND version NOT GLOB '*[^0-9]*' AND substr(version,1,1) BETWEEN '1' AND '9' AND (length(version)<19 OR version<='9223372036854775807')),
  request_id TEXT NOT NULL CHECK(length(request_id) BETWEEN 16 AND 128 AND request_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
  semantic_digest TEXT NOT NULL CHECK(length(semantic_digest)=64 AND semantic_digest NOT GLOB '*[^0-9a-f]*'),
  result_digest TEXT NOT NULL CHECK(length(result_digest)=64 AND result_digest NOT GLOB '*[^0-9a-f]*'),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at)
);

CREATE TABLE IF NOT EXISTS settings_runtime_outbox (
  outbox_id TEXT PRIMARY KEY CHECK(length(outbox_id)=32 AND outbox_id NOT GLOB '*[^0-9a-f]*'),
  audit_id TEXT NOT NULL UNIQUE REFERENCES settings_runtime_audit(audit_id),
  scope_id TEXT NOT NULL CHECK(length(scope_id)=64 AND scope_id NOT GLOB '*[^0-9a-f]*'),
  setting_id TEXT NOT NULL CHECK(length(setting_id)=64 AND setting_id NOT GLOB '*[^0-9a-f]*'),
  operation TEXT NOT NULL CHECK(operation IN ('set','delete')),
  version TEXT NOT NULL CHECK(length(version) BETWEEN 1 AND 19 AND version NOT GLOB '*[^0-9]*' AND substr(version,1,1) BETWEEN '1' AND '9' AND (length(version)<19 OR version<='9223372036854775807')),
  request_id TEXT NOT NULL CHECK(length(request_id) BETWEEN 16 AND 128 AND request_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64 AND payload_digest NOT GLOB '*[^0-9a-f]*'),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at)
);

CREATE TABLE IF NOT EXISTS settings_runtime_idempotency (
  scope_id TEXT NOT NULL CHECK(length(scope_id)=64 AND scope_id NOT GLOB '*[^0-9a-f]*'),
  request_id TEXT NOT NULL CHECK(length(request_id) BETWEEN 16 AND 128 AND request_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
  semantic_digest TEXT NOT NULL CHECK(length(semantic_digest)=64 AND semantic_digest NOT GLOB '*[^0-9a-f]*'),
  result_digest TEXT NOT NULL CHECK(length(result_digest)=64 AND result_digest NOT GLOB '*[^0-9a-f]*'),
  witness_count INTEGER NOT NULL CHECK(witness_count BETWEEN 1 AND 16),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at),
  PRIMARY KEY(scope_id,request_id)
);

CREATE TABLE IF NOT EXISTS settings_runtime_request_witness (
  scope_id TEXT NOT NULL CHECK(length(scope_id)=64 AND scope_id NOT GLOB '*[^0-9a-f]*'),
  request_id TEXT NOT NULL CHECK(length(request_id) BETWEEN 16 AND 128 AND request_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
  audit_id TEXT NOT NULL UNIQUE REFERENCES settings_runtime_audit(audit_id),
  outbox_id TEXT NOT NULL UNIQUE REFERENCES settings_runtime_outbox(outbox_id),
  setting_id TEXT NOT NULL CHECK(length(setting_id)=64 AND setting_id NOT GLOB '*[^0-9a-f]*'),
  operation TEXT NOT NULL CHECK(operation IN ('set','delete')),
  version TEXT NOT NULL CHECK(length(version) BETWEEN 1 AND 19 AND version NOT GLOB '*[^0-9]*' AND substr(version,1,1) BETWEEN '1' AND '9' AND (length(version)<19 OR version<='9223372036854775807')),
  PRIMARY KEY(scope_id,request_id,setting_id),
  FOREIGN KEY(scope_id,request_id) REFERENCES settings_runtime_idempotency(scope_id,request_id)
);

CREATE TRIGGER IF NOT EXISTS settings_runtime_version_overflow BEFORE UPDATE ON settings_runtime
WHEN OLD.version='9223372036854775807'
BEGIN SELECT RAISE(ABORT,'settings version exhausted'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_transition BEFORE UPDATE ON settings_runtime
WHEN NEW.scope_id<>OLD.scope_id OR NEW.setting_key<>OLD.setting_key OR NEW.created_at<>OLD.created_at OR NEW.version<>CAST(CAST(OLD.version AS INTEGER)+1 AS TEXT) OR NEW.updated_at<OLD.updated_at
BEGIN SELECT RAISE(ABORT,'illegal settings transition'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_no_delete BEFORE DELETE ON settings_runtime
BEGIN SELECT RAISE(ABORT,'settings are tombstoned, never deleted'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_no_transplant_insert BEFORE INSERT ON settings_runtime
WHEN NEW.tombstone=0 AND EXISTS(SELECT 1 FROM settings_runtime WHERE nonce_b64=NEW.nonce_b64 AND ciphertext_b64=NEW.ciphertext_b64)
BEGIN SELECT RAISE(ABORT,'transplantable settings envelope'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_no_transplant_update BEFORE UPDATE OF nonce_b64,ciphertext_b64 ON settings_runtime
WHEN NEW.tombstone=0 AND EXISTS(SELECT 1 FROM settings_runtime WHERE (scope_id<>NEW.scope_id OR setting_key<>NEW.setting_key) AND nonce_b64=NEW.nonce_b64 AND ciphertext_b64=NEW.ciphertext_b64)
BEGIN SELECT RAISE(ABORT,'transplantable settings envelope'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_audit_no_update BEFORE UPDATE ON settings_runtime_audit BEGIN SELECT RAISE(ABORT,'settings audit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_audit_no_delete BEFORE DELETE ON settings_runtime_audit BEGIN SELECT RAISE(ABORT,'settings audit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_outbox_no_update BEFORE UPDATE ON settings_runtime_outbox BEGIN SELECT RAISE(ABORT,'settings outbox is immutable'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_outbox_no_delete BEFORE DELETE ON settings_runtime_outbox BEGIN SELECT RAISE(ABORT,'settings outbox is immutable'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_idempotency_no_update BEFORE UPDATE ON settings_runtime_idempotency BEGIN SELECT RAISE(ABORT,'settings idempotency is immutable'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_idempotency_no_delete BEFORE DELETE ON settings_runtime_idempotency BEGIN SELECT RAISE(ABORT,'settings idempotency is immutable'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_witness_no_update BEFORE UPDATE ON settings_runtime_request_witness BEGIN SELECT RAISE(ABORT,'settings witness is immutable'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_witness_no_delete BEFORE DELETE ON settings_runtime_request_witness BEGIN SELECT RAISE(ABORT,'settings witness is immutable'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_cas_claim_no_update BEFORE UPDATE ON settings_runtime_cas_claims BEGIN SELECT RAISE(ABORT,'settings CAS claim is immutable'); END;
CREATE TRIGGER IF NOT EXISTS settings_runtime_cas_claim_no_delete BEFORE DELETE ON settings_runtime_cas_claims BEGIN SELECT RAISE(ABORT,'settings CAS claim is immutable'); END;

CREATE INDEX IF NOT EXISTS settings_runtime_live_idx ON settings_runtime(scope_id,tombstone,setting_key);
CREATE INDEX IF NOT EXISTS settings_runtime_outbox_pending_idx ON settings_runtime_outbox(scope_id,created_at,outbox_id);
