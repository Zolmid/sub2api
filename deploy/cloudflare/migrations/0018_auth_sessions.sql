-- D1-authoritative refresh-token session storage and rotation runtime.
-- Token material never crosses this schema: callers provide SHA-256 hashes
-- only, and all numeric JSON/JS identifiers are canonical decimal text.

INSERT INTO schema_metadata(key, value)
VALUES ('cloudflare_auth_sessions_schema_version', '2026-09-10.v1');

CREATE TABLE auth_sessions (
  token_hash TEXT PRIMARY KEY CHECK(
    length(token_hash) = 64
    AND token_hash NOT GLOB '*[^0-9a-f]*'
  ),
  user_id TEXT NOT NULL REFERENCES users(id) CHECK(
    length(user_id) BETWEEN 1 AND 19
    AND user_id NOT GLOB '*[^0-9]*'
    AND substr(user_id, 1, 1) BETWEEN '1' AND '9'
    AND (length(user_id) < 19 OR user_id <= '9223372036854775807')
  ),
  token_version TEXT NOT NULL CHECK(
    length(token_version) BETWEEN 1 AND 19
    AND token_version NOT GLOB '*[^0-9]*'
    AND substr(token_version, 1, 1) BETWEEN '1' AND '9'
    AND (length(token_version) < 19 OR token_version <= '9223372036854775807')
  ),
  family_id TEXT NOT NULL CHECK(
    length(family_id) BETWEEN 1 AND 128
    AND trim(family_id) = family_id
    AND family_id NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  binding_hash TEXT NOT NULL CHECK(
    length(binding_hash) = 64
    AND binding_hash NOT GLOB '*[^0-9a-f]*'
  ),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'consumed', 'revoked', 'expired')),
  created_at TEXT NOT NULL CHECK(
    length(created_at) = 24
    AND created_at GLOB '????-??-??T??:??:??.???Z'
    AND strftime('%Y-%m-%dT%H:%M:%fZ', created_at) = created_at
  ),
  expires_at TEXT NOT NULL CHECK(
    length(expires_at) = 24
    AND expires_at GLOB '????-??-??T??:??:??.???Z'
    AND strftime('%Y-%m-%dT%H:%M:%fZ', expires_at) = expires_at
    AND expires_at > created_at
  ),
  consumed_at TEXT CHECK(
    consumed_at IS NULL OR (
      length(consumed_at) = 24
      AND consumed_at GLOB '????-??-??T??:??:??.???Z'
      AND strftime('%Y-%m-%dT%H:%M:%fZ', consumed_at) = consumed_at
    )
  ),
  replaced_by_token_hash TEXT UNIQUE CHECK(
    replaced_by_token_hash IS NULL OR (
      length(replaced_by_token_hash) = 64
      AND replaced_by_token_hash NOT GLOB '*[^0-9a-f]*'
      AND replaced_by_token_hash <> token_hash
    )
  ),
  revoked_at TEXT CHECK(
    revoked_at IS NULL OR (
      length(revoked_at) = 24
      AND revoked_at GLOB '????-??-??T??:??:??.???Z'
      AND strftime('%Y-%m-%dT%H:%M:%fZ', revoked_at) = revoked_at
    )
  ),
  revoke_reason TEXT CHECK(
    revoke_reason IS NULL OR revoke_reason IN ('single', 'user', 'family', 'token_reuse')
  ),
  updated_at TEXT NOT NULL CHECK(
    length(updated_at) = 24
    AND updated_at GLOB '????-??-??T??:??:??.???Z'
    AND strftime('%Y-%m-%dT%H:%M:%fZ', updated_at) = updated_at
  ),
  CHECK(
    (status = 'active' AND consumed_at IS NULL AND replaced_by_token_hash IS NULL AND revoked_at IS NULL AND revoke_reason IS NULL)
    OR (status = 'consumed' AND consumed_at IS NOT NULL AND replaced_by_token_hash IS NOT NULL AND revoked_at IS NULL AND revoke_reason IS NULL)
    OR (status = 'revoked' AND consumed_at IS NULL AND replaced_by_token_hash IS NULL AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)
    OR (status = 'expired' AND consumed_at IS NULL AND replaced_by_token_hash IS NULL AND revoked_at IS NULL AND revoke_reason IS NULL)
  )
);

CREATE INDEX auth_sessions_user_active_idx
  ON auth_sessions(user_id, status, expires_at, token_hash);
CREATE INDEX auth_sessions_family_active_idx
  ON auth_sessions(family_id, status, expires_at, token_hash);
CREATE INDEX auth_sessions_replaced_by_idx
  ON auth_sessions(replaced_by_token_hash);

CREATE TABLE auth_session_family_revocations (
  family_id TEXT PRIMARY KEY CHECK(
    length(family_id) BETWEEN 1 AND 128
    AND trim(family_id) = family_id
    AND family_id NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  reason TEXT NOT NULL CHECK(reason IN ('family', 'token_reuse')),
  revoked_at TEXT NOT NULL CHECK(
    length(revoked_at) = 24
    AND revoked_at GLOB '????-??-??T??:??:??.???Z'
    AND strftime('%Y-%m-%dT%H:%M:%fZ', revoked_at) = revoked_at
  ),
  detail_hash TEXT NOT NULL CHECK(
    length(detail_hash) = 64
    AND detail_hash NOT GLOB '*[^0-9a-f]*'
  )
);

CREATE TABLE auth_session_audit_events (
  audit_id TEXT PRIMARY KEY CHECK(
    length(audit_id) BETWEEN 1 AND 160
    AND trim(audit_id) = audit_id
    AND audit_id NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  event_type TEXT NOT NULL CHECK(event_type IN (
    'store', 'delete', 'revoke_user', 'revoke_family', 'rotate', 'reuse_detected'
  )),
  token_hash TEXT CHECK(
    token_hash IS NULL OR (
      length(token_hash) = 64
      AND token_hash NOT GLOB '*[^0-9a-f]*'
    )
  ),
  user_id TEXT CHECK(
    user_id IS NULL OR (
      length(user_id) BETWEEN 1 AND 19
      AND user_id NOT GLOB '*[^0-9]*'
      AND substr(user_id, 1, 1) BETWEEN '1' AND '9'
      AND (length(user_id) < 19 OR user_id <= '9223372036854775807')
    )
  ),
  family_id TEXT CHECK(
    family_id IS NULL OR (
      length(family_id) BETWEEN 1 AND 128
      AND trim(family_id) = family_id
      AND family_id NOT GLOB '*[^A-Za-z0-9._:-]*'
    )
  ),
  detail_hash TEXT NOT NULL CHECK(
    length(detail_hash) = 64
    AND detail_hash NOT GLOB '*[^0-9a-f]*'
  ),
  created_at TEXT NOT NULL CHECK(
    length(created_at) = 24
    AND created_at GLOB '????-??-??T??:??:??.???Z'
    AND strftime('%Y-%m-%dT%H:%M:%fZ', created_at) = created_at
  )
);
CREATE INDEX auth_session_audit_subject_idx
  ON auth_session_audit_events(user_id, family_id, created_at);

CREATE TABLE auth_session_rotation_witnesses (
  old_token_hash TEXT PRIMARY KEY REFERENCES auth_sessions(token_hash) CHECK(
    length(old_token_hash) = 64
    AND old_token_hash NOT GLOB '*[^0-9a-f]*'
  ),
  new_token_hash TEXT NOT NULL UNIQUE REFERENCES auth_sessions(token_hash) CHECK(
    length(new_token_hash) = 64
    AND new_token_hash NOT GLOB '*[^0-9a-f]*'
  ),
  detail_hash TEXT NOT NULL CHECK(
    length(detail_hash) = 64
    AND detail_hash NOT GLOB '*[^0-9a-f]*'
  ),
  created_at TEXT NOT NULL CHECK(
    length(created_at) = 24
    AND created_at GLOB '????-??-??T??:??:??.???Z'
    AND strftime('%Y-%m-%dT%H:%M:%fZ', created_at) = created_at
  )
);

CREATE TRIGGER auth_session_rotation_witness_assert
BEFORE INSERT ON auth_session_rotation_witnesses
BEGIN
  SELECT CASE WHEN
    NOT EXISTS(
      SELECT 1
      FROM auth_sessions old_session
      JOIN auth_sessions new_session ON new_session.token_hash = NEW.new_token_hash
      WHERE old_session.token_hash = NEW.old_token_hash
        AND old_session.status = 'consumed'
        AND old_session.replaced_by_token_hash = NEW.new_token_hash
        AND old_session.consumed_at = NEW.created_at
        AND new_session.status = 'active'
        AND old_session.user_id = new_session.user_id
        AND old_session.family_id = new_session.family_id
        AND old_session.binding_hash = new_session.binding_hash
        AND (
          length(new_session.token_version) > length(old_session.token_version)
          OR (length(new_session.token_version) = length(old_session.token_version)
            AND new_session.token_version > old_session.token_version)
        )
        AND NOT EXISTS(
          SELECT 1 FROM auth_session_family_revocations revoked
          WHERE revoked.family_id = old_session.family_id
        )
    )
  THEN RAISE(ABORT, 'auth session rotation invariant') END;
END;

CREATE TRIGGER auth_session_family_revocation_immutable_update
BEFORE UPDATE ON auth_session_family_revocations
BEGIN SELECT RAISE(ABORT, 'auth session family revocation is immutable'); END;
CREATE TRIGGER auth_session_family_revocation_immutable_delete
BEFORE DELETE ON auth_session_family_revocations
BEGIN SELECT RAISE(ABORT, 'auth session family revocation is immutable'); END;
CREATE TRIGGER auth_session_audit_immutable_update
BEFORE UPDATE ON auth_session_audit_events
BEGIN SELECT RAISE(ABORT, 'auth session audit is immutable'); END;
CREATE TRIGGER auth_session_audit_immutable_delete
BEFORE DELETE ON auth_session_audit_events
BEGIN SELECT RAISE(ABORT, 'auth session audit is immutable'); END;
CREATE TRIGGER auth_session_rotation_witness_immutable_update
BEFORE UPDATE ON auth_session_rotation_witnesses
BEGIN SELECT RAISE(ABORT, 'auth session rotation witness is immutable'); END;
CREATE TRIGGER auth_session_rotation_witness_immutable_delete
BEFORE DELETE ON auth_session_rotation_witnesses
BEGIN SELECT RAISE(ABORT, 'auth session rotation witness is immutable'); END;
