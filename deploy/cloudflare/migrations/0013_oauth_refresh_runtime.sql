-- OAuth refresh coordination is additive. D1 is durable authority for
-- credential versions, opaque fingerprints, attempts, audit, and invalidation.
-- The paired Durable Object holds only per-account lease/fence metadata.

ALTER TABLE accounts ADD COLUMN credential_version INTEGER NOT NULL DEFAULT 1
  CHECK(credential_version BETWEEN 1 AND 2147483647);
ALTER TABLE accounts ADD COLUMN credential_fingerprint TEXT
  CHECK(credential_fingerprint IS NULL OR
    (length(credential_fingerprint) = 64
      AND credential_fingerprint NOT GLOB '*[^0-9a-f]*'));

CREATE TABLE oauth_refresh_attempts (
  operation_id TEXT PRIMARY KEY CHECK(
    length(operation_id) BETWEEN 1 AND 120
    AND trim(operation_id)=operation_id
    AND operation_id NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  account_id TEXT NOT NULL REFERENCES accounts(id) CHECK(
    account_id GLOB '[1-9]*' AND account_id NOT GLOB '*[^0-9]*'
    AND (length(account_id) < 19 OR
      (length(account_id) = 19 AND account_id <= '9223372036854775807'))
  ),
  expected_credential_version INTEGER NOT NULL CHECK(expected_credential_version BETWEEN 1 AND 2147483647),
  expected_credential_fingerprint TEXT NOT NULL
    CHECK(length(expected_credential_fingerprint) = 64
      AND expected_credential_fingerprint NOT GLOB '*[^0-9a-f]*'),
  owner TEXT NOT NULL CHECK(
    length(owner) BETWEEN 1 AND 160 AND trim(owner)=owner
    AND owner NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  fence INTEGER NOT NULL CHECK(fence BETWEEN 1 AND 2147483647),
  lease_expires_at_ms INTEGER NOT NULL CHECK(lease_expires_at_ms BETWEEN 0 AND 4102444800000),
  request_digest TEXT NOT NULL
    CHECK(length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
  state TEXT NOT NULL CHECK(state IN (
    'pre_provider', 'provider_started', 'succeeded', 'failed_retryable',
    'manual_review', 'superseded'
  )),
  terminal_at_ms INTEGER CHECK(terminal_at_ms IS NULL OR terminal_at_ms BETWEEN 0 AND 4102444800000),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 4102444800000),
  updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms BETWEEN created_at_ms AND 4102444800000),
  CHECK(lease_expires_at_ms > created_at_ms),
  CHECK(CASE
    WHEN state IN ('pre_provider', 'provider_started') THEN terminal_at_ms IS NULL
    WHEN state IN ('succeeded', 'failed_retryable', 'manual_review', 'superseded')
      THEN terminal_at_ms IS NOT NULL
        AND terminal_at_ms >= created_at_ms
        AND terminal_at_ms <= updated_at_ms
    ELSE 0
  END = 1)
);

-- A takeover must terminalize an expired predecessor before beginning a new
-- operation; this partial index makes two live operations impossible in D1.
CREATE UNIQUE INDEX oauth_refresh_attempt_one_live_account
  ON oauth_refresh_attempts(account_id)
  WHERE state IN ('pre_provider', 'provider_started');
CREATE INDEX oauth_refresh_attempt_account_state_idx
  ON oauth_refresh_attempts(account_id, state, updated_at_ms);

CREATE TABLE oauth_refresh_audit (
  audit_id TEXT PRIMARY KEY CHECK(
    length(audit_id) BETWEEN 1 AND 160 AND trim(audit_id)=audit_id
    AND audit_id NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  operation_id TEXT NOT NULL REFERENCES oauth_refresh_attempts(operation_id) CHECK(
    length(operation_id) BETWEEN 1 AND 120 AND trim(operation_id)=operation_id
    AND operation_id NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  account_id TEXT NOT NULL REFERENCES accounts(id) CHECK(
    account_id GLOB '[1-9]*' AND account_id NOT GLOB '*[^0-9]*'
    AND (length(account_id) < 19 OR
      (length(account_id) = 19 AND account_id <= '9223372036854775807'))
  ),
  event TEXT NOT NULL CHECK(event IN (
    'refresh_pre_provider', 'provider_started', 'expired_before_provider',
    'provider_result_unknown', 'credential_cas_succeeded',
    'invalid_grant_credential_advanced', 'invalid_grant_manual_review'
  )),
  detail_digest TEXT NOT NULL
    CHECK(length(detail_digest) = 64 AND detail_digest NOT GLOB '*[^0-9a-f]*'),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 4102444800000)
);
CREATE INDEX oauth_refresh_audit_operation_idx
  ON oauth_refresh_audit(operation_id, created_at_ms);

CREATE TABLE oauth_refresh_fingerprint_audit (
  audit_id TEXT PRIMARY KEY CHECK(
    length(audit_id) BETWEEN 1 AND 160 AND trim(audit_id)=audit_id
    AND audit_id NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  account_id TEXT NOT NULL REFERENCES accounts(id) CHECK(
    account_id GLOB '[1-9]*' AND account_id NOT GLOB '*[^0-9]*'
    AND (length(account_id) < 19 OR
      (length(account_id) = 19 AND account_id <= '9223372036854775807'))
  ),
  credential_version INTEGER NOT NULL CHECK(credential_version BETWEEN 1 AND 2147483647),
  credential_fingerprint TEXT NOT NULL
    CHECK(length(credential_fingerprint) = 64
      AND credential_fingerprint NOT GLOB '*[^0-9a-f]*'),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 4102444800000),
  UNIQUE(account_id, credential_version)
);

-- This is an opaque D1 outbox, never a Queue envelope. It contains no
-- credential envelope or provider data.
CREATE TABLE oauth_refresh_invalidation_outbox (
  event_id TEXT PRIMARY KEY CHECK(
    length(event_id) BETWEEN 1 AND 160 AND trim(event_id)=event_id
    AND event_id NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  operation_id TEXT NOT NULL UNIQUE REFERENCES oauth_refresh_attempts(operation_id) CHECK(
    length(operation_id) BETWEEN 1 AND 120 AND trim(operation_id)=operation_id
    AND operation_id NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  account_id TEXT NOT NULL REFERENCES accounts(id) CHECK(
    account_id GLOB '[1-9]*' AND account_id NOT GLOB '*[^0-9]*'
    AND (length(account_id) < 19 OR
      (length(account_id) = 19 AND account_id <= '9223372036854775807'))
  ),
  credential_version INTEGER NOT NULL CHECK(credential_version BETWEEN 1 AND 2147483647),
  event_type TEXT NOT NULL CHECK(event_type = 'oauth_credentials_invalidated'),
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending', 'published', 'dead')),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 4102444800000),
  published_at_ms INTEGER CHECK(published_at_ms IS NULL OR published_at_ms BETWEEN created_at_ms AND 4102444800000),
  CHECK(
    (state='pending' AND published_at_ms IS NULL)
    OR (state='published' AND published_at_ms IS NOT NULL)
    OR (state='dead' AND published_at_ms IS NULL)
  )
);
CREATE INDEX oauth_refresh_invalidation_pending_idx
  ON oauth_refresh_invalidation_outbox(state, created_at_ms);

-- Inserted as the final D1 batch statement for a successful rotation. Its
-- trigger aborts the entire batch if any preceding conditional write did not
-- establish one mutually consistent terminal commit.
CREATE TABLE oauth_refresh_commit_witnesses (
  operation_id TEXT PRIMARY KEY REFERENCES oauth_refresh_attempts(operation_id) CHECK(
    length(operation_id) BETWEEN 1 AND 120 AND trim(operation_id)=operation_id
    AND operation_id NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  account_id TEXT NOT NULL REFERENCES accounts(id) CHECK(
    account_id GLOB '[1-9]*' AND account_id NOT GLOB '*[^0-9]*'
    AND (length(account_id) < 19 OR
      (length(account_id) = 19 AND account_id <= '9223372036854775807'))
  ),
  expected_credential_version INTEGER NOT NULL CHECK(expected_credential_version BETWEEN 1 AND 2147483647),
  expected_credential_fingerprint TEXT NOT NULL
    CHECK(length(expected_credential_fingerprint) = 64
      AND expected_credential_fingerprint NOT GLOB '*[^0-9a-f]*'),
  committed_credential_version INTEGER NOT NULL CHECK(committed_credential_version BETWEEN 2 AND 2147483647),
  committed_credential_fingerprint TEXT NOT NULL
    CHECK(length(committed_credential_fingerprint) = 64
      AND committed_credential_fingerprint NOT GLOB '*[^0-9a-f]*'),
  audit_id TEXT NOT NULL UNIQUE REFERENCES oauth_refresh_audit(audit_id),
  outbox_event_id TEXT NOT NULL UNIQUE REFERENCES oauth_refresh_invalidation_outbox(event_id),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 4102444800000)
);

CREATE TRIGGER oauth_refresh_commit_witness_assert
BEFORE INSERT ON oauth_refresh_commit_witnesses
BEGIN
  SELECT CASE WHEN
    NEW.committed_credential_version != NEW.expected_credential_version + 1
    OR NOT EXISTS(
      SELECT 1 FROM accounts WHERE id=NEW.account_id
        AND credential_version=NEW.committed_credential_version
        AND credential_fingerprint=NEW.committed_credential_fingerprint
    )
    OR NOT EXISTS(
      SELECT 1 FROM oauth_refresh_attempts WHERE operation_id=NEW.operation_id
        AND account_id=NEW.account_id
        AND expected_credential_version=NEW.expected_credential_version
        AND expected_credential_fingerprint=NEW.expected_credential_fingerprint
        AND state='succeeded'
    )
    OR NOT EXISTS(
      SELECT 1 FROM oauth_refresh_audit WHERE audit_id=NEW.audit_id
        AND operation_id=NEW.operation_id AND account_id=NEW.account_id
        AND event='credential_cas_succeeded' AND detail_digest=(
          SELECT request_digest FROM oauth_refresh_attempts WHERE operation_id=NEW.operation_id
        )
    )
    OR NOT EXISTS(
      SELECT 1 FROM oauth_refresh_invalidation_outbox WHERE event_id=NEW.outbox_event_id
        AND operation_id=NEW.operation_id AND account_id=NEW.account_id
        AND credential_version=NEW.committed_credential_version
        AND event_type='oauth_credentials_invalidated'
    )
  THEN RAISE(ABORT, 'oauth refresh commit witness invariant') END;
END;

-- Terminal records and commit witnesses are append-only. Retries use a new id.
CREATE TRIGGER oauth_refresh_attempt_terminal_immutable
BEFORE UPDATE ON oauth_refresh_attempts
WHEN OLD.state IN ('succeeded', 'failed_retryable', 'manual_review', 'superseded')
BEGIN SELECT RAISE(ABORT, 'oauth refresh terminal attempt is immutable'); END;
CREATE TRIGGER oauth_refresh_attempt_terminal_immutable_delete
BEFORE DELETE ON oauth_refresh_attempts
WHEN OLD.state IN ('succeeded', 'failed_retryable', 'manual_review', 'superseded')
BEGIN SELECT RAISE(ABORT, 'oauth refresh terminal attempt is immutable'); END;
CREATE TRIGGER oauth_refresh_audit_immutable_update
BEFORE UPDATE ON oauth_refresh_audit
BEGIN SELECT RAISE(ABORT, 'oauth refresh audit is immutable'); END;
CREATE TRIGGER oauth_refresh_audit_immutable_delete
BEFORE DELETE ON oauth_refresh_audit
BEGIN SELECT RAISE(ABORT, 'oauth refresh audit is immutable'); END;
CREATE TRIGGER oauth_refresh_fingerprint_audit_immutable_update
BEFORE UPDATE ON oauth_refresh_fingerprint_audit
BEGIN SELECT RAISE(ABORT, 'oauth refresh fingerprint audit is immutable'); END;
CREATE TRIGGER oauth_refresh_fingerprint_audit_immutable_delete
BEFORE DELETE ON oauth_refresh_fingerprint_audit
BEGIN SELECT RAISE(ABORT, 'oauth refresh fingerprint audit is immutable'); END;
CREATE TRIGGER oauth_refresh_commit_witness_immutable_update
BEFORE UPDATE ON oauth_refresh_commit_witnesses
BEGIN SELECT RAISE(ABORT, 'oauth refresh commit witness is immutable'); END;
CREATE TRIGGER oauth_refresh_commit_witness_immutable_delete
BEFORE DELETE ON oauth_refresh_commit_witnesses
BEGIN SELECT RAISE(ABORT, 'oauth refresh commit witness is immutable'); END;
CREATE TRIGGER oauth_refresh_attempt_immutable_delete
BEFORE DELETE ON oauth_refresh_attempts
BEGIN SELECT RAISE(ABORT, 'oauth refresh attempt is immutable'); END;
CREATE TRIGGER oauth_refresh_audit_attempt_account_assert
BEFORE INSERT ON oauth_refresh_audit
WHEN NOT EXISTS(SELECT 1 FROM oauth_refresh_attempts a WHERE a.operation_id=NEW.operation_id AND a.account_id=NEW.account_id)
BEGIN SELECT RAISE(ABORT, 'oauth refresh audit account mismatch'); END;
CREATE TRIGGER oauth_refresh_outbox_attempt_account_assert
BEFORE INSERT ON oauth_refresh_invalidation_outbox
WHEN NOT EXISTS(SELECT 1 FROM oauth_refresh_attempts a WHERE a.operation_id=NEW.operation_id AND a.account_id=NEW.account_id)
BEGIN SELECT RAISE(ABORT, 'oauth refresh outbox account mismatch'); END;
CREATE TRIGGER oauth_refresh_outbox_transition
BEFORE UPDATE ON oauth_refresh_invalidation_outbox
WHEN OLD.event_id!=NEW.event_id OR OLD.operation_id!=NEW.operation_id OR OLD.account_id!=NEW.account_id
  OR OLD.credential_version!=NEW.credential_version OR OLD.event_type!=NEW.event_type OR OLD.created_at_ms!=NEW.created_at_ms
  OR NOT ((OLD.state='pending' AND NEW.state IN ('pending','published','dead'))
    OR (OLD.state=NEW.state AND OLD.state IN ('published','dead')
      AND OLD.published_at_ms IS NEW.published_at_ms))
BEGIN SELECT RAISE(ABORT, 'oauth refresh outbox transition is immutable'); END;
CREATE TRIGGER oauth_refresh_outbox_immutable_delete
BEFORE DELETE ON oauth_refresh_invalidation_outbox
BEGIN SELECT RAISE(ABORT, 'oauth refresh outbox is append-only'); END;
