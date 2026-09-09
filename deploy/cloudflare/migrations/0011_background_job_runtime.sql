-- Durable authority for generic Cloudflare Queue work. Queue messages only
-- carry the opaque job identity and routing/version metadata; payload bytes
-- stay in D1.
CREATE TABLE IF NOT EXISTS background_jobs (
  job_id TEXT PRIMARY KEY
    CHECK(length(job_id) BETWEEN 1 AND 160),
  route TEXT NOT NULL CHECK(length(route) BETWEEN 1 AND 96),
  job_type TEXT NOT NULL CHECK(length(job_type) BETWEEN 1 AND 96),
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 192),
  payload_codec TEXT NOT NULL
    CHECK(payload_codec IN ('json', 'app_encrypted_v1')),
  payload_body TEXT NOT NULL CHECK(length(payload_body) BETWEEN 1 AND 1048576),
  payload_digest TEXT NOT NULL CHECK(length(payload_digest) BETWEEN 1 AND 160),
  status TEXT NOT NULL
    CHECK(status IN (
      'queued', 'claimed', 'running', 'retry_wait',
      'succeeded', 'failed', 'dead_letter', 'manual_review'
    )),
  version INTEGER NOT NULL CHECK(version >= 1),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
  max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 100),
  base_delay_ms INTEGER NOT NULL CHECK(base_delay_ms BETWEEN 0 AND 86400000),
  max_delay_ms INTEGER NOT NULL CHECK(max_delay_ms BETWEEN base_delay_ms AND 604800000),
  available_at_ms INTEGER NOT NULL CHECK(available_at_ms >= 0),
  lease_owner TEXT,
  lease_token TEXT,
  delivery_id TEXT,
  lease_expires_at_ms INTEGER CHECK(lease_expires_at_ms >= 0),
  result_digest TEXT CHECK(result_digest IS NULL OR length(result_digest) BETWEEN 1 AND 160),
  error_code TEXT CHECK(error_code IS NULL OR length(error_code) BETWEEN 1 AND 96),
  replay_of_job_id TEXT REFERENCES background_jobs(job_id),
  replay_key TEXT UNIQUE,
  replay_actor TEXT,
  replay_reason_code TEXT,
  replay_evidence_ref TEXT,
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
  updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
  completed_at_ms INTEGER CHECK(completed_at_ms IS NULL OR completed_at_ms >= created_at_ms),
  UNIQUE(route, idempotency_key),
  CHECK(payload_codec <> 'json' OR json_valid(payload_body)),
  CHECK(attempt_count <= max_attempts),
  CHECK(
    (lease_owner IS NULL AND lease_token IS NULL AND delivery_id IS NULL AND lease_expires_at_ms IS NULL)
    OR
    (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND delivery_id IS NOT NULL AND lease_expires_at_ms IS NOT NULL)
  ),
  CHECK(status IN ('claimed', 'running') OR lease_owner IS NULL),
  CHECK(status <> 'succeeded' OR result_digest IS NOT NULL),
  CHECK(
    (replay_of_job_id IS NULL AND replay_key IS NULL AND replay_actor IS NULL
      AND replay_reason_code IS NULL AND replay_evidence_ref IS NULL)
    OR
    (replay_of_job_id IS NOT NULL AND replay_key IS NOT NULL AND replay_actor IS NOT NULL
      AND replay_reason_code IS NOT NULL AND replay_evidence_ref IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS background_job_transitions (
  transition_id TEXT PRIMARY KEY CHECK(length(transition_id) BETWEEN 1 AND 160),
  job_id TEXT NOT NULL REFERENCES background_jobs(job_id),
  event_type TEXT NOT NULL
    CHECK(event_type IN (
      'created', 'replayed', 'claimed', 'started', 'succeeded',
      'retry_scheduled', 'failed', 'dead_lettered', 'manual_review',
      'claim_recovered'
    )),
  from_status TEXT,
  to_status TEXT NOT NULL,
  from_version INTEGER NOT NULL CHECK(from_version >= 0),
  to_version INTEGER NOT NULL CHECK(to_version = from_version + 1),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 160),
  reason_code TEXT CHECK(reason_code IS NULL OR length(reason_code) BETWEEN 1 AND 96),
  evidence_ref TEXT CHECK(evidence_ref IS NULL OR length(evidence_ref) BETWEEN 1 AND 256),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
  UNIQUE(job_id, to_version),
  CHECK(
    (from_version = 0 AND from_status IS NULL AND event_type IN ('created', 'replayed'))
    OR
    (from_version > 0 AND from_status IS NOT NULL AND event_type NOT IN ('created', 'replayed'))
  )
);

CREATE TABLE IF NOT EXISTS background_job_outbox (
  outbox_id TEXT PRIMARY KEY CHECK(length(outbox_id) BETWEEN 1 AND 160),
  job_id TEXT NOT NULL REFERENCES background_jobs(job_id),
  job_version INTEGER NOT NULL CHECK(job_version >= 1),
  envelope_json TEXT NOT NULL CHECK(json_valid(envelope_json)),
  state TEXT NOT NULL CHECK(state IN ('pending', 'publishing', 'published')),
  version INTEGER NOT NULL CHECK(version >= 1),
  available_at_ms INTEGER NOT NULL CHECK(available_at_ms >= 0),
  publish_owner TEXT,
  publish_lease_expires_at_ms INTEGER CHECK(publish_lease_expires_at_ms >= 0),
  published_at_ms INTEGER CHECK(published_at_ms >= 0),
  last_error_code TEXT CHECK(last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 96),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
  UNIQUE(job_id, job_version),
  CHECK(
    (state = 'publishing' AND publish_owner IS NOT NULL AND publish_lease_expires_at_ms IS NOT NULL)
    OR
    (state <> 'publishing' AND publish_owner IS NULL AND publish_lease_expires_at_ms IS NULL)
  ),
  CHECK((state = 'published') = (published_at_ms IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS background_jobs_due_idx
  ON background_jobs(status, available_at_ms, job_id);
CREATE INDEX IF NOT EXISTS background_jobs_lease_expiry_idx
  ON background_jobs(status, lease_expires_at_ms, job_id);
CREATE INDEX IF NOT EXISTS background_jobs_replay_idx
  ON background_jobs(replay_of_job_id, created_at_ms, job_id);
CREATE INDEX IF NOT EXISTS background_job_transitions_job_idx
  ON background_job_transitions(job_id, to_version);
CREATE INDEX IF NOT EXISTS background_job_outbox_drain_idx
  ON background_job_outbox(state, available_at_ms, publish_lease_expires_at_ms, outbox_id);

CREATE TRIGGER IF NOT EXISTS background_job_transitions_no_update
BEFORE UPDATE ON background_job_transitions
BEGIN
  SELECT RAISE(ABORT, 'background job transition is immutable');
END;

CREATE TRIGGER IF NOT EXISTS background_job_transitions_no_delete
BEFORE DELETE ON background_job_transitions
BEGIN
  SELECT RAISE(ABORT, 'background job transition is immutable');
END;

CREATE TRIGGER IF NOT EXISTS background_jobs_terminal_immutable
BEFORE UPDATE ON background_jobs
WHEN OLD.status IN ('succeeded', 'failed', 'dead_letter', 'manual_review')
BEGIN
  SELECT RAISE(ABORT, 'terminal background job is immutable');
END;

CREATE TRIGGER IF NOT EXISTS background_jobs_transition_guard
BEFORE UPDATE ON background_jobs
WHEN
  NEW.version <> OLD.version + 1
  OR NEW.attempt_count < OLD.attempt_count
  OR NEW.updated_at_ms < OLD.updated_at_ms
  OR NOT (
    (OLD.status IN ('queued', 'retry_wait') AND NEW.status IN ('claimed', 'dead_letter'))
    OR (OLD.status = 'claimed' AND NEW.status IN ('running', 'retry_wait', 'failed', 'dead_letter', 'manual_review'))
    OR (OLD.status = 'running' AND NEW.status IN ('succeeded', 'retry_wait', 'failed', 'dead_letter', 'manual_review'))
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid background job transition');
END;
