-- Stage C is forward-only. Do not rewrite Stage B's 0001 schema: this file
-- applies cleanly to both new D1 databases and databases that already applied
-- the native gateway vertical-slice migration.
ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN notes TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN rpm_limit INTEGER NOT NULL DEFAULT 0 CHECK(rpm_limit >= 0);
ALTER TABLE users ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN deleted_at TEXT;

ALTER TABLE groups ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
ALTER TABLE groups ADD COLUMN deleted_at TEXT;
ALTER TABLE api_keys ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
ALTER TABLE api_keys ADD COLUMN deleted_at TEXT;
ALTER TABLE accounts ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
ALTER TABLE accounts ADD COLUMN deleted_at TEXT;

-- Existing Stage B rows must expose a real timestamp immediately after the
-- forward migration. New rows write both timestamps in the control plane.
UPDATE users SET updated_at=created_at WHERE updated_at='';
UPDATE groups SET updated_at=created_at WHERE updated_at='';
UPDATE api_keys SET updated_at=created_at WHERE updated_at='';
UPDATE accounts SET updated_at=created_at WHERE updated_at='';

-- Empty legacy rows are deliberately excluded until an explicit management
-- operation populates them; raw password hashes are write-only protocol input.
CREATE UNIQUE INDEX users_email_live_idx
  ON users(email) WHERE email <> '' AND deleted_at IS NULL;

CREATE TABLE management_operations (
  operation_id TEXT PRIMARY KEY CHECK(length(operation_id) BETWEEN 1 AND 128),
  route TEXT NOT NULL CHECK(length(route) BETWEEN 1 AND 128),
  request_hash TEXT NOT NULL CHECK(length(request_hash) = 64 AND request_hash NOT GLOB '*[^0-9a-f]*'),
  response_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
