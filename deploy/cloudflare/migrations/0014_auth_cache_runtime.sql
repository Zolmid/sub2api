-- D1-authoritative auth-cache revision and invalidation runtime.
-- Revisions and outbox payload values are canonical decimal/digest text so
-- downstream consumers never depend on SQLite numeric coercion or CAST limits.

INSERT INTO schema_metadata(key, value)
VALUES ('cloudflare_auth_cache_schema_version', '2026-09-09.v4');

CREATE TABLE IF NOT EXISTS auth_cache_entity_revisions (
  entity_type TEXT NOT NULL CHECK(entity_type IN ('api_key', 'user', 'group', 'subscription')),
  entity_id TEXT NOT NULL CHECK(length(entity_id) BETWEEN 1 AND 64),
  revision TEXT NOT NULL DEFAULT '1' CHECK(
    length(revision) BETWEEN 1 AND 19
    AND revision NOT GLOB '*[^0-9]*'
    AND substr(revision, 1, 1) BETWEEN '1' AND '9'
    AND (length(revision) < 19 OR revision <= '9223372036854775807')
  ),
  updated_at TEXT NOT NULL CHECK(
    length(updated_at) = 24
    AND substr(updated_at, 1, 4) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 5, 1) = '-'
    AND substr(updated_at, 6, 2) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 8, 1) = '-'
    AND substr(updated_at, 9, 2) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 11, 1) = 'T'
    AND substr(updated_at, 12, 2) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 14, 1) = ':'
    AND substr(updated_at, 15, 2) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 17, 1) = ':'
    AND substr(updated_at, 18, 2) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 20, 1) = '.'
    AND substr(updated_at, 21, 3) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 24, 1) = 'Z'
    AND substr(updated_at, 1, 4) BETWEEN '0000' AND '9999'
    AND CAST(substr(updated_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
    AND CAST(substr(updated_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(updated_at, 6, 2) AS INTEGER)
      WHEN 2 THEN CASE WHEN CAST(substr(updated_at, 1, 4) AS INTEGER) % 4 = 0
        AND (CAST(substr(updated_at, 1, 4) AS INTEGER) % 100 <> 0
          OR CAST(substr(updated_at, 1, 4) AS INTEGER) % 400 = 0) THEN 29 ELSE 28 END
      WHEN 1 THEN 31 WHEN 3 THEN 31 WHEN 5 THEN 31 WHEN 7 THEN 31 WHEN 8 THEN 31 WHEN 10 THEN 31 WHEN 12 THEN 31
      ELSE 30 END
    AND CAST(substr(updated_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
    AND CAST(substr(updated_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
    AND CAST(substr(updated_at, 18, 2) AS INTEGER) BETWEEN 0 AND 59
    AND strftime('%Y-%m-%dT%H:%M:%fZ', updated_at) = updated_at
  ),
  CHECK(
    (entity_type IN ('api_key', 'user', 'group')
      AND length(entity_id) BETWEEN 1 AND 19
      AND entity_id NOT GLOB '*[^0-9]*'
      AND substr(entity_id, 1, 1) BETWEEN '1' AND '9'
      AND (length(entity_id) < 19 OR entity_id <= '9223372036854775807'))
    OR
    (entity_type = 'subscription'
      AND length(entity_id) BETWEEN 3 AND 39
      AND entity_id NOT GLOB '*[^0-9:]*'
      AND length(entity_id) - length(replace(entity_id, ':', '')) = 1
      AND instr(entity_id, ':') BETWEEN 2 AND 20
      AND length(substr(entity_id, instr(entity_id, ':') + 1)) BETWEEN 1 AND 19
      AND substr(entity_id, 1, 1) BETWEEN '1' AND '9'
      AND substr(entity_id, instr(entity_id, ':') + 1, 1) BETWEEN '1' AND '9'
      AND (instr(entity_id, ':') < 20 OR substr(entity_id, 1, instr(entity_id, ':') - 1) <= '9223372036854775807')
      AND (length(substr(entity_id, instr(entity_id, ':') + 1)) < 19
        OR substr(entity_id, instr(entity_id, ':') + 1) <= '9223372036854775807'))
  ),
  PRIMARY KEY(entity_type, entity_id)
);

CREATE TABLE IF NOT EXISTS auth_cache_credential_revisions (
  credential_digest TEXT PRIMARY KEY CHECK(
    length(credential_digest) = 64
    AND credential_digest NOT GLOB '*[^0-9a-f]*'
  ),
  revision TEXT NOT NULL DEFAULT '1' CHECK(
    length(revision) BETWEEN 1 AND 19
    AND revision NOT GLOB '*[^0-9]*'
    AND substr(revision, 1, 1) BETWEEN '1' AND '9'
    AND (length(revision) < 19 OR revision <= '9223372036854775807')
  ),
  updated_at TEXT NOT NULL CHECK(
    length(updated_at) = 24
    AND substr(updated_at, 1, 4) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 5, 1) = '-'
    AND substr(updated_at, 6, 2) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 8, 1) = '-'
    AND substr(updated_at, 9, 2) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 11, 1) = 'T'
    AND substr(updated_at, 12, 2) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 14, 1) = ':'
    AND substr(updated_at, 15, 2) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 17, 1) = ':'
    AND substr(updated_at, 18, 2) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 20, 1) = '.'
    AND substr(updated_at, 21, 3) NOT GLOB '*[^0-9]*'
    AND substr(updated_at, 24, 1) = 'Z'
    AND substr(updated_at, 1, 4) BETWEEN '0000' AND '9999'
    AND CAST(substr(updated_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
    AND CAST(substr(updated_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(updated_at, 6, 2) AS INTEGER)
      WHEN 2 THEN CASE WHEN CAST(substr(updated_at, 1, 4) AS INTEGER) % 4 = 0
        AND (CAST(substr(updated_at, 1, 4) AS INTEGER) % 100 <> 0
          OR CAST(substr(updated_at, 1, 4) AS INTEGER) % 400 = 0) THEN 29 ELSE 28 END
      WHEN 1 THEN 31 WHEN 3 THEN 31 WHEN 5 THEN 31 WHEN 7 THEN 31 WHEN 8 THEN 31 WHEN 10 THEN 31 WHEN 12 THEN 31
      ELSE 30 END
    AND CAST(substr(updated_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
    AND CAST(substr(updated_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
    AND CAST(substr(updated_at, 18, 2) AS INTEGER) BETWEEN 0 AND 59
    AND strftime('%Y-%m-%dT%H:%M:%fZ', updated_at) = updated_at
  )
);

CREATE TRIGGER IF NOT EXISTS auth_cache_entity_revision_overflow
BEFORE UPDATE OF revision ON auth_cache_entity_revisions
WHEN length(OLD.revision) = 19 AND OLD.revision >= '9223372036854775807'
BEGIN
  SELECT RAISE(ABORT, 'auth cache entity revision exhausted');
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_credential_revision_overflow
BEFORE UPDATE OF revision ON auth_cache_credential_revisions
WHEN length(OLD.revision) = 19 AND OLD.revision >= '9223372036854775807'
BEGIN
  SELECT RAISE(ABORT, 'auth cache credential revision exhausted');
END;

CREATE TABLE IF NOT EXISTS auth_cache_outbox (
  event_id TEXT PRIMARY KEY CHECK(
    length(event_id) = 32
    AND event_id NOT GLOB '*[^0-9a-f]*'
  ),
  entity_type TEXT NOT NULL CHECK(
    entity_type IN ('api_key', 'user', 'group', 'subscription', 'credential')
  ),
  entity_id TEXT NOT NULL CHECK(length(entity_id) BETWEEN 1 AND 64),
  credential_digest TEXT CHECK(
    credential_digest IS NULL OR (
      length(credential_digest) = 64
      AND credential_digest NOT GLOB '*[^0-9a-f]*'
    )
  ),
  old_credential_digest TEXT CHECK(
    old_credential_digest IS NULL OR (
      length(old_credential_digest) = 64
      AND old_credential_digest NOT GLOB '*[^0-9a-f]*'
    )
  ),
  new_credential_digest TEXT CHECK(
    new_credential_digest IS NULL OR (
      length(new_credential_digest) = 64
      AND new_credential_digest NOT GLOB '*[^0-9a-f]*'
    )
  ),
  revision TEXT NOT NULL CHECK(
    length(revision) BETWEEN 1 AND 19
    AND revision NOT GLOB '*[^0-9]*'
    AND substr(revision, 1, 1) BETWEEN '1' AND '9'
    AND (length(revision) < 19 OR revision <= '9223372036854775807')
  ),
  state TEXT NOT NULL DEFAULT 'pending' CHECK(
    state IN ('pending', 'claimed', 'published', 'dead')
  ),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 32),
  claim_version TEXT NOT NULL DEFAULT '0' CHECK(
    length(claim_version) BETWEEN 1 AND 19
    AND claim_version NOT GLOB '*[^0-9]*'
    AND (
      claim_version = '0'
      OR substr(claim_version, 1, 1) BETWEEN '1' AND '9'
    )
    AND (length(claim_version) < 19 OR claim_version <= '9223372036854775807')
  ),
  claim_token TEXT CHECK(
    claim_token IS NULL OR (
      length(claim_token) = 32
      AND claim_token NOT GLOB '*[^0-9a-f]*'
    )
  ),
  claim_expires_at TEXT CHECK(
    claim_expires_at IS NULL OR (
      length(claim_expires_at) = 24
      AND substr(claim_expires_at, 1, 4) NOT GLOB '*[^0-9]*'
      AND substr(claim_expires_at, 5, 1) = '-'
      AND substr(claim_expires_at, 6, 2) NOT GLOB '*[^0-9]*'
      AND substr(claim_expires_at, 8, 1) = '-'
      AND substr(claim_expires_at, 9, 2) NOT GLOB '*[^0-9]*'
      AND substr(claim_expires_at, 11, 1) = 'T'
      AND substr(claim_expires_at, 12, 2) NOT GLOB '*[^0-9]*'
      AND substr(claim_expires_at, 14, 1) = ':'
      AND substr(claim_expires_at, 15, 2) NOT GLOB '*[^0-9]*'
      AND substr(claim_expires_at, 17, 1) = ':'
      AND substr(claim_expires_at, 18, 2) NOT GLOB '*[^0-9]*'
      AND substr(claim_expires_at, 20, 1) = '.'
      AND substr(claim_expires_at, 21, 3) NOT GLOB '*[^0-9]*'
      AND substr(claim_expires_at, 24, 1) = 'Z'
      AND substr(claim_expires_at, 1, 4) BETWEEN '0000' AND '9999'
      AND CAST(substr(claim_expires_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
      AND CAST(substr(claim_expires_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(claim_expires_at, 6, 2) AS INTEGER)
        WHEN 2 THEN CASE WHEN CAST(substr(claim_expires_at, 1, 4) AS INTEGER) % 4 = 0
          AND (CAST(substr(claim_expires_at, 1, 4) AS INTEGER) % 100 <> 0
            OR CAST(substr(claim_expires_at, 1, 4) AS INTEGER) % 400 = 0) THEN 29 ELSE 28 END
        WHEN 1 THEN 31 WHEN 3 THEN 31 WHEN 5 THEN 31 WHEN 7 THEN 31 WHEN 8 THEN 31 WHEN 10 THEN 31 WHEN 12 THEN 31
        ELSE 30 END
      AND CAST(substr(claim_expires_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
      AND CAST(substr(claim_expires_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
      AND CAST(substr(claim_expires_at, 18, 2) AS INTEGER) BETWEEN 0 AND 59
      AND strftime('%Y-%m-%dT%H:%M:%fZ', claim_expires_at) = claim_expires_at
    )
  ),
  created_at TEXT NOT NULL CHECK(
    length(created_at) = 24
    AND substr(created_at, 1, 4) NOT GLOB '*[^0-9]*'
    AND substr(created_at, 5, 1) = '-'
    AND substr(created_at, 6, 2) NOT GLOB '*[^0-9]*'
    AND substr(created_at, 8, 1) = '-'
    AND substr(created_at, 9, 2) NOT GLOB '*[^0-9]*'
    AND substr(created_at, 11, 1) = 'T'
    AND substr(created_at, 12, 2) NOT GLOB '*[^0-9]*'
    AND substr(created_at, 14, 1) = ':'
    AND substr(created_at, 15, 2) NOT GLOB '*[^0-9]*'
    AND substr(created_at, 17, 1) = ':'
    AND substr(created_at, 18, 2) NOT GLOB '*[^0-9]*'
    AND substr(created_at, 20, 1) = '.'
    AND substr(created_at, 21, 3) NOT GLOB '*[^0-9]*'
    AND substr(created_at, 24, 1) = 'Z'
    AND substr(created_at, 1, 4) BETWEEN '0000' AND '9999'
    AND CAST(substr(created_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
    AND CAST(substr(created_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(created_at, 6, 2) AS INTEGER)
      WHEN 2 THEN CASE WHEN CAST(substr(created_at, 1, 4) AS INTEGER) % 4 = 0
        AND (CAST(substr(created_at, 1, 4) AS INTEGER) % 100 <> 0
          OR CAST(substr(created_at, 1, 4) AS INTEGER) % 400 = 0) THEN 29 ELSE 28 END
      WHEN 1 THEN 31 WHEN 3 THEN 31 WHEN 5 THEN 31 WHEN 7 THEN 31 WHEN 8 THEN 31 WHEN 10 THEN 31 WHEN 12 THEN 31
      ELSE 30 END
    AND CAST(substr(created_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
    AND CAST(substr(created_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
    AND CAST(substr(created_at, 18, 2) AS INTEGER) BETWEEN 0 AND 59
    AND strftime('%Y-%m-%dT%H:%M:%fZ', created_at) = created_at
  ),
  published_at TEXT CHECK(
    published_at IS NULL OR (
      length(published_at) = 24
      AND substr(published_at, 1, 4) NOT GLOB '*[^0-9]*'
      AND substr(published_at, 5, 1) = '-'
      AND substr(published_at, 6, 2) NOT GLOB '*[^0-9]*'
      AND substr(published_at, 8, 1) = '-'
      AND substr(published_at, 9, 2) NOT GLOB '*[^0-9]*'
      AND substr(published_at, 11, 1) = 'T'
      AND substr(published_at, 12, 2) NOT GLOB '*[^0-9]*'
      AND substr(published_at, 14, 1) = ':'
      AND substr(published_at, 15, 2) NOT GLOB '*[^0-9]*'
      AND substr(published_at, 17, 1) = ':'
      AND substr(published_at, 18, 2) NOT GLOB '*[^0-9]*'
      AND substr(published_at, 20, 1) = '.'
      AND substr(published_at, 21, 3) NOT GLOB '*[^0-9]*'
      AND substr(published_at, 24, 1) = 'Z'
      AND substr(published_at, 1, 4) BETWEEN '0000' AND '9999'
      AND CAST(substr(published_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
      AND CAST(substr(published_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(published_at, 6, 2) AS INTEGER)
        WHEN 2 THEN CASE WHEN CAST(substr(published_at, 1, 4) AS INTEGER) % 4 = 0
          AND (CAST(substr(published_at, 1, 4) AS INTEGER) % 100 <> 0
            OR CAST(substr(published_at, 1, 4) AS INTEGER) % 400 = 0) THEN 29 ELSE 28 END
        WHEN 1 THEN 31 WHEN 3 THEN 31 WHEN 5 THEN 31 WHEN 7 THEN 31 WHEN 8 THEN 31 WHEN 10 THEN 31 WHEN 12 THEN 31
        ELSE 30 END
      AND CAST(substr(published_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
      AND CAST(substr(published_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
      AND CAST(substr(published_at, 18, 2) AS INTEGER) BETWEEN 0 AND 59
      AND strftime('%Y-%m-%dT%H:%M:%fZ', published_at) = published_at
    )
  ),
  CHECK(
    (state = 'pending'
      AND claim_token IS NULL
      AND claim_expires_at IS NULL
      AND published_at IS NULL)
    OR
    (state = 'claimed'
      AND claim_token IS NOT NULL
      AND claim_expires_at IS NOT NULL
      AND published_at IS NULL)
    OR
    (state = 'published'
      AND claim_token IS NULL
      AND claim_expires_at IS NULL
      AND published_at IS NOT NULL)
    OR
    (state = 'dead'
      AND claim_token IS NULL
      AND claim_expires_at IS NULL
      AND published_at IS NULL)
  ),
  CHECK(
    (entity_type IN ('api_key', 'user', 'group')
      AND length(entity_id) BETWEEN 1 AND 19
      AND entity_id NOT GLOB '*[^0-9]*'
      AND substr(entity_id, 1, 1) BETWEEN '1' AND '9'
      AND (length(entity_id) < 19 OR entity_id <= '9223372036854775807'))
    OR
    (entity_type = 'subscription'
      AND length(entity_id) BETWEEN 3 AND 39
      AND entity_id NOT GLOB '*[^0-9:]*'
      AND length(entity_id) - length(replace(entity_id, ':', '')) = 1
      AND instr(entity_id, ':') BETWEEN 2 AND 20
      AND length(substr(entity_id, instr(entity_id, ':') + 1)) BETWEEN 1 AND 19
      AND substr(entity_id, 1, 1) BETWEEN '1' AND '9'
      AND substr(entity_id, instr(entity_id, ':') + 1, 1) BETWEEN '1' AND '9'
      AND (instr(entity_id, ':') < 20 OR substr(entity_id, 1, instr(entity_id, ':') - 1) <= '9223372036854775807')
      AND (length(substr(entity_id, instr(entity_id, ':') + 1)) < 19
        OR substr(entity_id, instr(entity_id, ':') + 1) <= '9223372036854775807'))
    OR
    (entity_type = 'credential'
      AND entity_id = credential_digest
      AND credential_digest IS NOT NULL)
  ),
  CHECK(
    entity_type = 'credential'
    OR old_credential_digest IS NULL
    OR new_credential_digest IS NULL
    OR old_credential_digest <> new_credential_digest
  ),
  UNIQUE(entity_type, entity_id, revision)
);

CREATE INDEX IF NOT EXISTS auth_cache_outbox_claim_idx
  ON auth_cache_outbox(state, claim_expires_at, attempts, created_at, event_id);

CREATE TRIGGER IF NOT EXISTS auth_cache_entity_revisions_no_delete
BEFORE DELETE ON auth_cache_entity_revisions
BEGIN
  SELECT RAISE(ABORT, 'auth cache entity revision is immutable');
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_credential_revisions_no_delete
BEFORE DELETE ON auth_cache_credential_revisions
BEGIN
  SELECT RAISE(ABORT, 'auth cache credential revision is immutable');
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_entity_revisions_state_machine
BEFORE UPDATE ON auth_cache_entity_revisions
WHEN NEW.entity_type <> OLD.entity_type
  OR NEW.entity_id <> OLD.entity_id
  OR NEW.revision <> CAST(OLD.revision + 1 AS TEXT)
  OR NEW.updated_at < OLD.updated_at
BEGIN
  SELECT RAISE(ABORT, 'invalid auth cache entity revision transition');
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_credential_revisions_state_machine
BEFORE UPDATE ON auth_cache_credential_revisions
WHEN NEW.credential_digest <> OLD.credential_digest
  OR NEW.revision <> CAST(OLD.revision + 1 AS TEXT)
  OR NEW.updated_at < OLD.updated_at
BEGIN
  SELECT RAISE(ABORT, 'invalid auth cache credential revision transition');
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_outbox_no_delete
BEFORE DELETE ON auth_cache_outbox
BEGIN
  SELECT RAISE(ABORT, 'auth cache outbox is immutable');
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_outbox_claim_version_overflow
BEFORE UPDATE OF claim_version ON auth_cache_outbox
WHEN length(OLD.claim_version) = 19 AND OLD.claim_version >= '9223372036854775807'
BEGIN
  SELECT RAISE(ABORT, 'auth cache outbox claim version exhausted');
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_outbox_initial_state
BEFORE INSERT ON auth_cache_outbox
WHEN NEW.state <> 'pending'
  OR NEW.attempts <> 0
  OR NEW.claim_version <> '0'
  OR NEW.claim_token IS NOT NULL
  OR NEW.claim_expires_at IS NOT NULL
  OR NEW.published_at IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'auth cache outbox must begin pending');
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_outbox_event_shape_insert
BEFORE INSERT ON auth_cache_outbox
WHEN NOT (
  (NEW.entity_type = 'credential'
    AND NEW.entity_id = NEW.credential_digest
    AND NEW.credential_digest IS NOT NULL
    AND NOT (NEW.old_credential_digest IS NOT NULL AND NEW.new_credential_digest IS NOT NULL)
    AND (NEW.old_credential_digest IS NULL OR NEW.old_credential_digest = NEW.credential_digest)
    AND (NEW.new_credential_digest IS NULL OR NEW.new_credential_digest = NEW.credential_digest))
  OR
  (NEW.entity_type IN ('user', 'group', 'subscription')
    AND NEW.credential_digest IS NULL
    AND NEW.old_credential_digest IS NULL
    AND NEW.new_credential_digest IS NULL)
  OR
  (NEW.entity_type = 'api_key'
    AND NEW.credential_digest IS NOT NULL
    AND (
      (NEW.old_credential_digest IS NULL AND NEW.new_credential_digest IS NULL)
      OR
      (NEW.old_credential_digest IS NULL AND NEW.new_credential_digest = NEW.credential_digest)
      OR
      (NEW.old_credential_digest = NEW.credential_digest AND NEW.new_credential_digest IS NULL)
      OR
      (NEW.old_credential_digest IS NOT NULL
        AND NEW.new_credential_digest = NEW.credential_digest
        AND NEW.old_credential_digest <> NEW.new_credential_digest)
    ))
)
BEGIN
  SELECT RAISE(ABORT, 'invalid auth cache outbox event shape');
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_outbox_revision_identity_insert
BEFORE INSERT ON auth_cache_outbox
WHEN NOT (
  (NEW.entity_type = 'credential' AND EXISTS(
    SELECT 1 FROM auth_cache_credential_revisions
    WHERE credential_digest = NEW.entity_id AND revision = NEW.revision
  ))
  OR
  (NEW.entity_type IN ('api_key', 'user', 'group', 'subscription') AND EXISTS(
    SELECT 1 FROM auth_cache_entity_revisions
    WHERE entity_type = NEW.entity_type
      AND entity_id = NEW.entity_id
      AND revision = NEW.revision
  ))
)
BEGIN
  SELECT RAISE(ABORT, 'auth cache outbox revision does not match source history');
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_outbox_state_machine
BEFORE UPDATE ON auth_cache_outbox
WHEN NEW.event_id <> OLD.event_id
  OR NEW.entity_type <> OLD.entity_type
  OR NEW.entity_id <> OLD.entity_id
  OR NEW.credential_digest IS NOT OLD.credential_digest
  OR NEW.old_credential_digest IS NOT OLD.old_credential_digest
  OR NEW.new_credential_digest IS NOT OLD.new_credential_digest
  OR NEW.revision <> OLD.revision
  OR NEW.created_at <> OLD.created_at
  OR OLD.state IN ('published', 'dead')
  OR NOT (
    (OLD.state = 'pending'
      AND NEW.state = 'claimed'
      AND NEW.attempts = OLD.attempts + 1
      AND NEW.claim_version = CAST(OLD.claim_version + 1 AS TEXT)
      AND NEW.claim_token IS NOT NULL
      AND NEW.claim_expires_at IS NOT NULL
      AND NEW.published_at IS NULL)
    OR
    (OLD.state = 'claimed'
      AND NEW.state = 'claimed'
      AND NEW.claim_token = OLD.claim_token
      AND NEW.attempts = OLD.attempts
      AND NEW.claim_version = CAST(OLD.claim_version + 1 AS TEXT)
      AND NEW.claim_expires_at > OLD.claim_expires_at
      AND NEW.published_at IS NULL)
    OR
    (OLD.state = 'claimed'
      AND NEW.state = 'claimed'
      AND NEW.claim_token <> OLD.claim_token
      AND NEW.attempts = OLD.attempts + 1
      AND NEW.claim_version = CAST(OLD.claim_version + 1 AS TEXT)
      AND NEW.claim_expires_at IS NOT NULL
      AND NEW.published_at IS NULL)
    OR
    (OLD.state = 'claimed'
      AND NEW.state = 'published'
      AND NEW.attempts = OLD.attempts
      AND NEW.claim_version = CAST(OLD.claim_version + 1 AS TEXT)
      AND NEW.claim_token IS NULL
      AND NEW.claim_expires_at IS NULL
      AND NEW.published_at IS NOT NULL
      AND NEW.published_at >= OLD.created_at)
    OR
    (OLD.state = 'claimed'
      AND NEW.state IN ('pending', 'dead')
      AND NEW.attempts = OLD.attempts
      AND NEW.claim_version = CAST(OLD.claim_version + 1 AS TEXT)
      AND NEW.claim_token IS NULL
      AND NEW.claim_expires_at IS NULL
      AND NEW.published_at IS NULL)
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid auth cache outbox transition');
END;

INSERT OR IGNORE INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
SELECT 'api_key', id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM api_keys;

INSERT OR IGNORE INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
SELECT 'user', id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM users;

INSERT OR IGNORE INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
SELECT 'group', id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM groups;

INSERT OR IGNORE INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
SELECT 'subscription', user_id || ':' || group_id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM user_subscriptions;

INSERT OR IGNORE INTO auth_cache_credential_revisions(credential_digest, revision, updated_at)
SELECT key_hash, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM api_keys;

CREATE TRIGGER IF NOT EXISTS auth_cache_api_keys_ai
AFTER INSERT ON api_keys
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('api_key', NEW.id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_credential_revisions(credential_digest, revision, updated_at)
  VALUES(NEW.key_hash, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(credential_digest) DO UPDATE SET
    revision = CAST(auth_cache_credential_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(
    event_id, entity_type, entity_id, credential_digest, new_credential_digest, revision, created_at
  )
  SELECT lower(hex(randomblob(16))), 'api_key', NEW.id, NEW.key_hash, NEW.key_hash, revision,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'api_key' AND entity_id = NEW.id;

  INSERT INTO auth_cache_outbox(
    event_id, entity_type, entity_id, credential_digest, new_credential_digest, revision, created_at
  )
  SELECT lower(hex(randomblob(16))), 'credential', NEW.key_hash, NEW.key_hash, NEW.key_hash,
    revision, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_credential_revisions
  WHERE credential_digest = NEW.key_hash;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_api_keys_au
AFTER UPDATE ON api_keys
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('api_key', NEW.id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_credential_revisions(credential_digest, revision, updated_at)
  SELECT OLD.key_hash, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  WHERE OLD.key_hash <> NEW.key_hash
  ON CONFLICT(credential_digest) DO UPDATE SET
    revision = CAST(auth_cache_credential_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_credential_revisions(credential_digest, revision, updated_at)
  VALUES(NEW.key_hash, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(credential_digest) DO UPDATE SET
    revision = CAST(auth_cache_credential_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(
    event_id, entity_type, entity_id, credential_digest,
    old_credential_digest, new_credential_digest, revision, created_at
  )
  SELECT lower(hex(randomblob(16))), 'api_key', NEW.id, NEW.key_hash,
    CASE WHEN OLD.key_hash <> NEW.key_hash THEN OLD.key_hash ELSE NULL END,
    CASE WHEN OLD.key_hash <> NEW.key_hash THEN NEW.key_hash ELSE NULL END,
    revision, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'api_key' AND entity_id = NEW.id;

  INSERT INTO auth_cache_outbox(
    event_id, entity_type, entity_id, credential_digest,
    old_credential_digest, revision, created_at
  )
  SELECT lower(hex(randomblob(16))), 'credential', OLD.key_hash, OLD.key_hash,
    OLD.key_hash, revision, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_credential_revisions
  WHERE credential_digest = OLD.key_hash AND OLD.key_hash <> NEW.key_hash;

  INSERT INTO auth_cache_outbox(
    event_id, entity_type, entity_id, credential_digest,
    new_credential_digest, revision, created_at
  )
  SELECT lower(hex(randomblob(16))), 'credential', NEW.key_hash, NEW.key_hash,
    NEW.key_hash, revision, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_credential_revisions
  WHERE credential_digest = NEW.key_hash;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_api_keys_ad
AFTER DELETE ON api_keys
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('api_key', OLD.id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_credential_revisions(credential_digest, revision, updated_at)
  VALUES(OLD.key_hash, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(credential_digest) DO UPDATE SET
    revision = CAST(auth_cache_credential_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(
    event_id, entity_type, entity_id, credential_digest, old_credential_digest, revision, created_at
  )
  SELECT lower(hex(randomblob(16))), 'api_key', OLD.id, OLD.key_hash, OLD.key_hash, revision,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'api_key' AND entity_id = OLD.id;

  INSERT INTO auth_cache_outbox(
    event_id, entity_type, entity_id, credential_digest, old_credential_digest, revision, created_at
  )
  SELECT lower(hex(randomblob(16))), 'credential', OLD.key_hash, OLD.key_hash, OLD.key_hash,
    revision, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_credential_revisions
  WHERE credential_digest = OLD.key_hash;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_users_ai
AFTER INSERT ON users
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('user', NEW.id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at)
  SELECT lower(hex(randomblob(16))), 'user', NEW.id, revision,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'user' AND entity_id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_users_au
AFTER UPDATE ON users
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('user', NEW.id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at)
  SELECT lower(hex(randomblob(16))), 'user', NEW.id, revision,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'user' AND entity_id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_users_ad
AFTER DELETE ON users
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('user', OLD.id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at)
  SELECT lower(hex(randomblob(16))), 'user', OLD.id, revision,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'user' AND entity_id = OLD.id;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_groups_ai
AFTER INSERT ON groups
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('group', NEW.id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at)
  SELECT lower(hex(randomblob(16))), 'group', NEW.id, revision,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'group' AND entity_id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_groups_au
AFTER UPDATE ON groups
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('group', NEW.id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at)
  SELECT lower(hex(randomblob(16))), 'group', NEW.id, revision,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'group' AND entity_id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_groups_ad
AFTER DELETE ON groups
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('group', OLD.id, '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at)
  SELECT lower(hex(randomblob(16))), 'group', OLD.id, revision,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'group' AND entity_id = OLD.id;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_subscriptions_ai
AFTER INSERT ON user_subscriptions
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('subscription', NEW.user_id || ':' || NEW.group_id, '1',
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at)
  SELECT lower(hex(randomblob(16))), 'subscription', NEW.user_id || ':' || NEW.group_id,
    revision, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'subscription' AND entity_id = NEW.user_id || ':' || NEW.group_id;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_subscriptions_au_old_identity
AFTER UPDATE ON user_subscriptions
WHEN OLD.user_id <> NEW.user_id OR OLD.group_id <> NEW.group_id
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('subscription', OLD.user_id || ':' || OLD.group_id, '1',
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at)
  SELECT lower(hex(randomblob(16))), 'subscription', OLD.user_id || ':' || OLD.group_id,
    revision, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'subscription' AND entity_id = OLD.user_id || ':' || OLD.group_id;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_subscriptions_au_new_identity
AFTER UPDATE ON user_subscriptions
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('subscription', NEW.user_id || ':' || NEW.group_id, '1',
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at)
  SELECT lower(hex(randomblob(16))), 'subscription', NEW.user_id || ':' || NEW.group_id,
    revision, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'subscription' AND entity_id = NEW.user_id || ':' || NEW.group_id;
END;

CREATE TRIGGER IF NOT EXISTS auth_cache_subscriptions_ad
AFTER DELETE ON user_subscriptions
BEGIN
  INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at)
  VALUES('subscription', OLD.user_id || ':' || OLD.group_id, '1',
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  ON CONFLICT(entity_type, entity_id) DO UPDATE SET
    revision = CAST(auth_cache_entity_revisions.revision + 1 AS TEXT),
    updated_at = excluded.updated_at;

  INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at)
  SELECT lower(hex(randomblob(16))), 'subscription', OLD.user_id || ':' || OLD.group_id,
    revision, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM auth_cache_entity_revisions
  WHERE entity_type = 'subscription' AND entity_id = OLD.user_id || ':' || OLD.group_id;
END;
