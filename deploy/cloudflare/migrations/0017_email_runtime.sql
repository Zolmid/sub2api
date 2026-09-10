-- Email challenge and durable-delivery authority. Payloads are deliberately
-- opaque: token and delivery-reference plaintext never appear in D1.
INSERT INTO schema_metadata(key, value)
VALUES ('cloudflare_email_runtime_schema_version', '2026-09-10.v4');

CREATE TABLE IF NOT EXISTS email_challenges (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id) BETWEEN 8 AND 128 AND id NOT GLOB '*[^a-z0-9_-]*'),
  account_id TEXT NOT NULL CHECK(length(account_id) BETWEEN 1 AND 64 AND account_id NOT GLOB '*[^a-z0-9._-]*'),
  purpose TEXT NOT NULL CHECK(length(purpose) BETWEEN 1 AND 64 AND purpose NOT GLOB '*[^a-z0-9._-]*'),
  token_hmac_key_id TEXT NOT NULL CHECK(length(token_hmac_key_id) BETWEEN 1 AND 64 AND token_hmac_key_id NOT GLOB '*[^a-z0-9._-]*'),
  token_verifier TEXT NOT NULL CHECK(length(token_verifier)=43 AND token_verifier NOT GLOB '*[^A-Za-z0-9_-]*'),
  token_envelope_key_id TEXT NOT NULL CHECK(length(token_envelope_key_id) BETWEEN 1 AND 64 AND token_envelope_key_id NOT GLOB '*[^a-z0-9._-]*'),
  token_nonce TEXT NOT NULL CHECK(length(token_nonce)=16 AND token_nonce NOT GLOB '*[^A-Za-z0-9_-]*'),
  token_ciphertext TEXT NOT NULL CHECK(length(token_ciphertext)=79 AND token_ciphertext NOT GLOB '*[^A-Za-z0-9_-]*'),
  delivery_envelope_key_id TEXT NOT NULL CHECK(length(delivery_envelope_key_id) BETWEEN 1 AND 64 AND delivery_envelope_key_id NOT GLOB '*[^a-z0-9._-]*'),
  delivery_nonce TEXT NOT NULL CHECK(length(delivery_nonce)=16 AND delivery_nonce NOT GLOB '*[^A-Za-z0-9_-]*'),
  delivery_ciphertext TEXT NOT NULL CHECK(length(delivery_ciphertext) BETWEEN 17 AND 5496 AND delivery_ciphertext NOT GLOB '*[^A-Za-z0-9_-]*'),
  state TEXT NOT NULL CHECK(state IN ('issued','consumed','expired')),
  failed_attempts INTEGER NOT NULL CHECK(typeof(failed_attempts)='integer' AND failed_attempts BETWEEN 0 AND 20),
  max_attempts INTEGER NOT NULL CHECK(typeof(max_attempts)='integer' AND max_attempts BETWEEN 1 AND 20 AND failed_attempts<=max_attempts),
  expires_at TEXT NOT NULL CHECK(length(expires_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',expires_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',expires_at)=expires_at),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at),
  consumed_at TEXT CHECK(consumed_at IS NULL OR (length(consumed_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',consumed_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',consumed_at)=consumed_at)),
  version TEXT NOT NULL CHECK(length(version) BETWEEN 1 AND 19 AND version NOT GLOB '*[^0-9]*' AND substr(version,1,1) BETWEEN '1' AND '9' AND (length(version)<19 OR version<='9223372036854775807')),
  CHECK((state='consumed' AND consumed_at IS NOT NULL) OR (state<>'consumed' AND consumed_at IS NULL)),
  CHECK(created_at<expires_at),
  CHECK(token_hmac_key_id<>token_envelope_key_id AND token_hmac_key_id<>delivery_envelope_key_id)
);

CREATE TABLE IF NOT EXISTS email_delivery_jobs (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id) BETWEEN 8 AND 128 AND id NOT GLOB '*[^a-z0-9_-]*'),
  challenge_id TEXT NOT NULL UNIQUE REFERENCES email_challenges(id),
  state TEXT NOT NULL CHECK(state IN ('pending','claimed','delivered','dead','cancelled')),
  attempt INTEGER NOT NULL CHECK(typeof(attempt)='integer' AND attempt BETWEEN 0 AND 20),
  max_attempts INTEGER NOT NULL CHECK(typeof(max_attempts)='integer' AND max_attempts BETWEEN 1 AND 20 AND attempt<=max_attempts),
  not_before TEXT NOT NULL CHECK(length(not_before)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',not_before) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',not_before)=not_before),
  lease_owner TEXT CHECK(lease_owner IS NULL OR (length(lease_owner) BETWEEN 1 AND 64 AND lease_owner NOT GLOB '*[^a-z0-9._-]*')),
  lease_until TEXT CHECK(lease_until IS NULL OR (length(lease_until)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',lease_until) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',lease_until)=lease_until)),
  fence TEXT NOT NULL CHECK(length(fence) BETWEEN 1 AND 19 AND fence NOT GLOB '*[^0-9]*' AND substr(fence,1,1) BETWEEN '1' AND '9' AND (length(fence)<19 OR fence<='9223372036854775807')),
  version TEXT NOT NULL CHECK(length(version) BETWEEN 1 AND 19 AND version NOT GLOB '*[^0-9]*' AND substr(version,1,1) BETWEEN '1' AND '9' AND (length(version)<19 OR version<='9223372036854775807')),
  last_error_code TEXT CHECK(last_error_code IS NULL OR (length(last_error_code) BETWEEN 1 AND 64 AND last_error_code NOT GLOB '*[^a-z0-9._-]*')),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at),
  updated_at TEXT NOT NULL CHECK(length(updated_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',updated_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',updated_at)=updated_at AND updated_at>=created_at),
  CHECK((state='claimed' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) OR (state<>'claimed' AND lease_owner IS NULL AND lease_until IS NULL)),
  CHECK((state='dead' AND attempt=max_attempts) OR state<>'dead')
);

CREATE TABLE IF NOT EXISTS email_runtime_batch_guards (
  guard_id TEXT PRIMARY KEY NOT NULL CHECK(length(guard_id)=32 AND guard_id NOT GLOB '*[^0-9a-f]*'),
  matched INTEGER NOT NULL CHECK(matched=1)
);

CREATE TABLE IF NOT EXISTS email_runtime_audit (
  audit_id TEXT PRIMARY KEY NOT NULL CHECK(length(audit_id)=32 AND audit_id NOT GLOB '*[^0-9a-f]*'),
  challenge_id TEXT NOT NULL REFERENCES email_challenges(id),
  job_id TEXT REFERENCES email_delivery_jobs(id),
  event TEXT NOT NULL CHECK(event IN ('issued','rejected','expired','consumed','claimed','renewed','delivered','retry_scheduled','dead','cancelled')),
  challenge_version TEXT NOT NULL CHECK(length(challenge_version) BETWEEN 1 AND 19 AND challenge_version NOT GLOB '*[^0-9]*' AND substr(challenge_version,1,1) BETWEEN '1' AND '9' AND (length(challenge_version)<19 OR challenge_version<='9223372036854775807')),
  job_version TEXT CHECK(job_version IS NULL OR (length(job_version) BETWEEN 1 AND 19 AND job_version NOT GLOB '*[^0-9]*' AND substr(job_version,1,1) BETWEEN '1' AND '9' AND (length(job_version)<19 OR job_version<='9223372036854775807'))),
  fence TEXT CHECK(fence IS NULL OR (length(fence) BETWEEN 1 AND 19 AND fence NOT GLOB '*[^0-9]*' AND substr(fence,1,1) BETWEEN '1' AND '9' AND (length(fence)<19 OR fence<='9223372036854775807'))),
  evidence_hmac_key_id TEXT NOT NULL CHECK(length(evidence_hmac_key_id) BETWEEN 1 AND 64 AND evidence_hmac_key_id NOT GLOB '*[^a-z0-9._-]*'),
  evidence_hmac TEXT NOT NULL CHECK(length(evidence_hmac)=43 AND evidence_hmac NOT GLOB '*[^A-Za-z0-9_-]*'),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at),
  CHECK((event IN ('claimed','renewed','delivered','retry_scheduled','dead') AND job_id IS NOT NULL AND job_version IS NOT NULL AND fence IS NOT NULL) OR (event NOT IN ('claimed','renewed','delivered','retry_scheduled','dead') AND (job_id IS NULL OR event='cancelled') AND (job_version IS NULL OR event='cancelled') AND (fence IS NULL OR event='cancelled')))
);

CREATE TABLE IF NOT EXISTS email_runtime_outbox (
  outbox_id TEXT PRIMARY KEY NOT NULL CHECK(length(outbox_id)=32 AND outbox_id NOT GLOB '*[^0-9a-f]*'),
  audit_id TEXT NOT NULL UNIQUE REFERENCES email_runtime_audit(audit_id),
  challenge_id TEXT NOT NULL REFERENCES email_challenges(id),
  job_id TEXT REFERENCES email_delivery_jobs(id),
  event TEXT NOT NULL CHECK(event IN ('issued','rejected','expired','consumed','claimed','renewed','delivered','retry_scheduled','dead','cancelled')),
  payload_hmac_key_id TEXT NOT NULL CHECK(length(payload_hmac_key_id) BETWEEN 1 AND 64 AND payload_hmac_key_id NOT GLOB '*[^a-z0-9._-]*'),
  payload_hmac TEXT NOT NULL CHECK(length(payload_hmac)=43 AND payload_hmac NOT GLOB '*[^A-Za-z0-9_-]*'),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at)
);

CREATE TABLE IF NOT EXISTS email_issue_idempotency (
  account_id TEXT NOT NULL CHECK(length(account_id) BETWEEN 1 AND 64 AND account_id NOT GLOB '*[^a-z0-9._-]*'),
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 64 AND idempotency_key NOT GLOB '*[^a-z0-9._-]*'),
  request_hmac_key_id TEXT NOT NULL CHECK(length(request_hmac_key_id) BETWEEN 1 AND 64 AND request_hmac_key_id NOT GLOB '*[^a-z0-9._-]*'),
  semantic_hmac TEXT NOT NULL CHECK(length(semantic_hmac)=43 AND semantic_hmac NOT GLOB '*[^A-Za-z0-9_-]*'),
  challenge_id TEXT NOT NULL REFERENCES email_challenges(id),
  job_id TEXT NOT NULL REFERENCES email_delivery_jobs(id),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at),
  PRIMARY KEY(account_id,idempotency_key)
);

CREATE TABLE IF NOT EXISTS email_issue_witnesses (
  account_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  challenge_id TEXT NOT NULL REFERENCES email_challenges(id),
  job_id TEXT NOT NULL REFERENCES email_delivery_jobs(id),
  audit_id TEXT NOT NULL UNIQUE REFERENCES email_runtime_audit(audit_id),
  outbox_id TEXT NOT NULL UNIQUE REFERENCES email_runtime_outbox(outbox_id),
  challenge_version TEXT NOT NULL CHECK(challenge_version='1'),
  job_version TEXT NOT NULL CHECK(job_version='1'),
  fence TEXT NOT NULL CHECK(fence='1'),
  evidence_hmac TEXT NOT NULL CHECK(length(evidence_hmac)=43 AND evidence_hmac NOT GLOB '*[^A-Za-z0-9_-]*'),
  PRIMARY KEY(account_id,idempotency_key),
  FOREIGN KEY(account_id,idempotency_key) REFERENCES email_issue_idempotency(account_id,idempotency_key)
);

CREATE TABLE IF NOT EXISTS email_delivery_witnesses (
  job_id TEXT NOT NULL REFERENCES email_delivery_jobs(id),
  event TEXT NOT NULL CHECK(event='claimed'),
  audit_id TEXT NOT NULL UNIQUE REFERENCES email_runtime_audit(audit_id),
  outbox_id TEXT NOT NULL UNIQUE REFERENCES email_runtime_outbox(outbox_id),
  job_version TEXT NOT NULL CHECK(length(job_version) BETWEEN 1 AND 19 AND job_version NOT GLOB '*[^0-9]*' AND substr(job_version,1,1) BETWEEN '1' AND '9'),
  fence TEXT NOT NULL CHECK(length(fence) BETWEEN 1 AND 19 AND fence NOT GLOB '*[^0-9]*' AND substr(fence,1,1) BETWEEN '1' AND '9'),
  evidence_hmac TEXT NOT NULL CHECK(length(evidence_hmac)=43 AND evidence_hmac NOT GLOB '*[^A-Za-z0-9_-]*'),
  PRIMARY KEY(job_id,fence,event)
);

CREATE TRIGGER IF NOT EXISTS email_challenge_version_overflow
BEFORE UPDATE ON email_challenges
WHEN OLD.version='9223372036854775807'
BEGIN
  SELECT RAISE(ABORT,'email challenge version exhausted');
END;

CREATE TRIGGER IF NOT EXISTS email_challenge_immutable_identity
BEFORE UPDATE ON email_challenges
WHEN NEW.id<>OLD.id OR NEW.account_id<>OLD.account_id OR NEW.purpose<>OLD.purpose OR NEW.token_hmac_key_id<>OLD.token_hmac_key_id OR NEW.created_at<>OLD.created_at
BEGIN
  SELECT RAISE(ABORT,'email challenge immutable identity violated');
END;

CREATE TRIGGER IF NOT EXISTS email_challenge_transition
BEFORE UPDATE ON email_challenges
WHEN NEW.version<>CAST(CAST(OLD.version AS INTEGER)+1 AS TEXT) OR NOT (
  (OLD.state='issued' AND NEW.state IN ('issued','consumed','expired')) OR
  (OLD.state=NEW.state AND OLD.state IN ('consumed','expired'))
)
BEGIN
  SELECT RAISE(ABORT,'illegal email challenge transition');
END;

CREATE TRIGGER IF NOT EXISTS email_job_version_overflow
BEFORE UPDATE ON email_delivery_jobs
WHEN OLD.version='9223372036854775807' OR (OLD.fence='9223372036854775807' AND NEW.fence<>OLD.fence)
BEGIN
  SELECT RAISE(ABORT,'email job version exhausted');
END;

CREATE TRIGGER IF NOT EXISTS email_job_immutable_identity
BEFORE UPDATE ON email_delivery_jobs
WHEN NEW.id<>OLD.id OR NEW.challenge_id<>OLD.challenge_id OR NEW.created_at<>OLD.created_at
BEGIN
  SELECT RAISE(ABORT,'email job immutable identity violated');
END;

CREATE TRIGGER IF NOT EXISTS email_job_transition
BEFORE UPDATE ON email_delivery_jobs
WHEN NEW.version<>CAST(CAST(OLD.version AS INTEGER)+1 AS TEXT) OR NOT (
  (OLD.state='pending' AND NEW.state IN ('pending','claimed','cancelled')) OR
  (OLD.state='claimed' AND NEW.state IN ('claimed','pending','delivered','dead','cancelled')) OR
  (OLD.state=NEW.state AND OLD.state IN ('delivered','dead','cancelled'))
)
BEGIN
  SELECT RAISE(ABORT,'illegal email job transition');
END;

CREATE TRIGGER IF NOT EXISTS email_job_claim_requires_sendable_challenge
BEFORE UPDATE ON email_delivery_jobs
WHEN OLD.state IN ('pending','claimed') AND NEW.state='claimed' AND NOT EXISTS (
  SELECT 1 FROM email_challenges c
  WHERE c.id=NEW.challenge_id AND c.state='issued' AND c.expires_at>NEW.updated_at
)
BEGIN
  SELECT RAISE(ABORT,'email job claim requires sendable challenge');
END;

CREATE TRIGGER IF NOT EXISTS email_audit_job_linkage
BEFORE INSERT ON email_runtime_audit
WHEN NEW.job_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM email_delivery_jobs j WHERE j.id=NEW.job_id AND j.challenge_id=NEW.challenge_id
)
BEGIN
  SELECT RAISE(ABORT,'email audit job linkage violated');
END;

CREATE TRIGGER IF NOT EXISTS email_outbox_audit_linkage
BEFORE INSERT ON email_runtime_outbox
WHEN NOT EXISTS (
  SELECT 1 FROM email_runtime_audit a
  WHERE a.audit_id=NEW.audit_id
    AND a.challenge_id=NEW.challenge_id
    AND a.job_id IS NEW.job_id
    AND a.event=NEW.event
    AND a.created_at=NEW.created_at
)
BEGIN
  SELECT RAISE(ABORT,'email outbox audit linkage violated');
END;

CREATE TRIGGER IF NOT EXISTS email_issue_witness_linkage
BEFORE INSERT ON email_issue_witnesses
WHEN NOT EXISTS (
  SELECT 1
  FROM email_issue_idempotency i
  JOIN email_runtime_audit a ON a.audit_id=NEW.audit_id
  JOIN email_runtime_outbox o ON o.outbox_id=NEW.outbox_id
  WHERE i.account_id=NEW.account_id
    AND i.idempotency_key=NEW.idempotency_key
    AND i.challenge_id=NEW.challenge_id
    AND i.job_id=NEW.job_id
    AND a.challenge_id=NEW.challenge_id
    AND a.job_id IS NULL
    AND a.event='issued'
    AND o.audit_id=NEW.audit_id
    AND o.challenge_id=NEW.challenge_id
    AND o.job_id IS NULL
    AND o.event='issued'
)
BEGIN
  SELECT RAISE(ABORT,'email issue witness linkage violated');
END;

CREATE TRIGGER IF NOT EXISTS email_audit_immutable_update
BEFORE UPDATE ON email_runtime_audit
BEGIN
  SELECT RAISE(ABORT,'email audit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS email_audit_immutable_delete
BEFORE DELETE ON email_runtime_audit
BEGIN
  SELECT RAISE(ABORT,'email audit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS email_outbox_immutable_update
BEFORE UPDATE ON email_runtime_outbox
BEGIN
  SELECT RAISE(ABORT,'email outbox is immutable');
END;

CREATE TRIGGER IF NOT EXISTS email_outbox_immutable_delete
BEFORE DELETE ON email_runtime_outbox
BEGIN
  SELECT RAISE(ABORT,'email outbox is immutable');
END;

CREATE TRIGGER IF NOT EXISTS email_issue_idempotency_immutable_update
BEFORE UPDATE ON email_issue_idempotency
BEGIN
  SELECT RAISE(ABORT,'email idempotency is immutable');
END;

CREATE TRIGGER IF NOT EXISTS email_issue_idempotency_immutable_delete
BEFORE DELETE ON email_issue_idempotency
BEGIN
  SELECT RAISE(ABORT,'email idempotency is immutable');
END;

CREATE TRIGGER IF NOT EXISTS email_issue_witness_immutable_update
BEFORE UPDATE ON email_issue_witnesses
BEGIN
  SELECT RAISE(ABORT,'email issue witness is immutable');
END;

CREATE TRIGGER IF NOT EXISTS email_issue_witness_immutable_delete
BEFORE DELETE ON email_issue_witnesses
BEGIN
  SELECT RAISE(ABORT,'email issue witness is immutable');
END;

CREATE TRIGGER IF NOT EXISTS email_delivery_witness_immutable_update
BEFORE UPDATE ON email_delivery_witnesses
BEGIN
  SELECT RAISE(ABORT,'email delivery witness is immutable');
END;

CREATE TRIGGER IF NOT EXISTS email_delivery_witness_immutable_delete
BEFORE DELETE ON email_delivery_witnesses
BEGIN
  SELECT RAISE(ABORT,'email delivery witness is immutable');
END;

CREATE INDEX IF NOT EXISTS email_delivery_jobs_claimable
ON email_delivery_jobs(state,not_before,lease_until);
