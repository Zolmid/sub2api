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
  version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 2147483647),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 2147483647),
  max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 100),
  base_delay_ms INTEGER NOT NULL CHECK(base_delay_ms BETWEEN 0 AND 86400000),
  max_delay_ms INTEGER NOT NULL CHECK(max_delay_ms BETWEEN base_delay_ms AND 604800000),
  available_at_ms INTEGER NOT NULL CHECK(available_at_ms BETWEEN 0 AND 4102444800000),
  lease_owner TEXT,
  lease_token TEXT,
  delivery_id TEXT,
  lease_expires_at_ms INTEGER CHECK(lease_expires_at_ms BETWEEN 0 AND 4102444800000),
  result_digest TEXT CHECK(result_digest IS NULL OR length(result_digest) BETWEEN 1 AND 160),
  error_code TEXT CHECK(error_code IS NULL OR length(error_code) BETWEEN 1 AND 96),
  replay_of_job_id TEXT REFERENCES background_jobs(job_id),
  replay_key TEXT UNIQUE,
  replay_actor TEXT,
  replay_reason_code TEXT,
  replay_evidence_ref TEXT,
  replay_source_version INTEGER,
  replay_source_status TEXT,
  replay_evidence_kind TEXT,
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 4102444800000),
  updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms BETWEEN created_at_ms AND 4102444800000),
  completed_at_ms INTEGER CHECK(completed_at_ms IS NULL OR completed_at_ms BETWEEN created_at_ms AND 4102444800000),
  UNIQUE(route, idempotency_key),
  CHECK(payload_codec <> 'json' OR json_valid(payload_body)),
  CHECK(attempt_count <= max_attempts),
  CHECK(
    (lease_owner IS NULL AND lease_token IS NULL AND delivery_id IS NULL AND lease_expires_at_ms IS NULL)
    OR
    (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND delivery_id IS NOT NULL AND lease_expires_at_ms IS NOT NULL)
  ),
  CHECK(
    (status IN ('claimed', 'running')) =
    (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND delivery_id IS NOT NULL
      AND lease_expires_at_ms IS NOT NULL)
  ),
  CHECK(status NOT IN ('claimed', 'running') OR lease_expires_at_ms > updated_at_ms),
  CHECK((status IN ('succeeded', 'failed', 'dead_letter', 'manual_review')) = (completed_at_ms IS NOT NULL)),
  CHECK(status <> 'succeeded' OR (result_digest IS NOT NULL AND error_code IS NULL)),
  CHECK(status NOT IN ('queued', 'claimed', 'running') OR (result_digest IS NULL AND error_code IS NULL)),
  CHECK(
    (replay_of_job_id IS NULL AND replay_key IS NULL AND replay_actor IS NULL
      AND replay_reason_code IS NULL AND replay_evidence_ref IS NULL
      AND replay_source_version IS NULL AND replay_source_status IS NULL AND replay_evidence_kind IS NULL)
    OR
    (replay_of_job_id IS NOT NULL AND replay_key IS NOT NULL AND replay_actor IS NOT NULL
      AND replay_reason_code IS NOT NULL AND replay_evidence_ref IS NOT NULL
      AND replay_source_version BETWEEN 1 AND 2147483647
      AND replay_source_status IN ('dead_letter', 'manual_review')
      AND replay_evidence_kind IN (
        'provider_idempotency', 'provider_query_no_effect', 'operator_confirmed_no_effect'
      ))
  )
);

CREATE TABLE IF NOT EXISTS background_job_transitions (
  transition_id TEXT PRIMARY KEY CHECK(length(transition_id) BETWEEN 1 AND 160),
  job_id TEXT NOT NULL REFERENCES background_jobs(job_id),
  event_type TEXT NOT NULL
    CHECK(event_type IN (
      'created', 'replayed', 'claimed', 'started', 'succeeded',
      'retry_scheduled', 'failed', 'dead_lettered', 'manual_review',
      'claim_recovered', 'lease_renewed'
    )),
  from_status TEXT,
  to_status TEXT NOT NULL,
  from_version INTEGER NOT NULL CHECK(from_version BETWEEN 0 AND 2147483646),
  to_version INTEGER NOT NULL CHECK(to_version BETWEEN 1 AND 2147483647 AND to_version = from_version + 1),
  actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 160),
  reason_code TEXT CHECK(reason_code IS NULL OR length(reason_code) BETWEEN 1 AND 96),
  evidence_ref TEXT CHECK(evidence_ref IS NULL OR length(evidence_ref) BETWEEN 1 AND 256),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 4102444800000),
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
  job_version INTEGER NOT NULL CHECK(job_version BETWEEN 1 AND 2147483647),
  envelope_json TEXT NOT NULL CHECK(json_valid(envelope_json)),
  state TEXT NOT NULL CHECK(state IN ('pending', 'publishing', 'published')),
  version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 2147483647),
  available_at_ms INTEGER NOT NULL CHECK(available_at_ms BETWEEN 0 AND 4102444800000),
  publish_owner TEXT,
  publish_lease_expires_at_ms INTEGER CHECK(publish_lease_expires_at_ms BETWEEN 0 AND 4102444800000),
  published_at_ms INTEGER CHECK(published_at_ms BETWEEN 0 AND 4102444800000),
  last_error_code TEXT CHECK(last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 96),
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 4102444800000),
  UNIQUE(job_id, job_version),
  CHECK(
    (state = 'publishing' AND publish_owner IS NOT NULL AND publish_lease_expires_at_ms IS NOT NULL
      AND published_at_ms IS NULL)
    OR (state = 'pending' AND publish_owner IS NULL AND publish_lease_expires_at_ms IS NULL
      AND published_at_ms IS NULL)
    OR (state = 'published' AND publish_owner IS NULL AND publish_lease_expires_at_ms IS NULL
      AND published_at_ms IS NOT NULL)
  ),
  CHECK(published_at_ms IS NULL OR published_at_ms >= created_at_ms),
  CHECK(publish_lease_expires_at_ms IS NULL OR publish_lease_expires_at_ms >= created_at_ms),
  CHECK(available_at_ms >= created_at_ms)
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

CREATE TRIGGER IF NOT EXISTS background_jobs_no_delete
BEFORE DELETE ON background_jobs
BEGIN
  SELECT RAISE(ABORT, 'background job is immutable');
END;

CREATE TRIGGER IF NOT EXISTS background_job_outbox_no_delete
BEFORE DELETE ON background_job_outbox
BEGIN
  SELECT RAISE(ABORT, 'background job outbox is immutable');
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
  NEW.job_id IS NOT OLD.job_id
  OR NEW.route IS NOT OLD.route
  OR NEW.job_type IS NOT OLD.job_type
  OR NEW.idempotency_key IS NOT OLD.idempotency_key
  OR NEW.payload_codec IS NOT OLD.payload_codec
  OR NEW.payload_body IS NOT OLD.payload_body
  OR NEW.payload_digest IS NOT OLD.payload_digest
  OR NEW.max_attempts IS NOT OLD.max_attempts
  OR NEW.base_delay_ms IS NOT OLD.base_delay_ms
  OR NEW.max_delay_ms IS NOT OLD.max_delay_ms
  OR NEW.replay_of_job_id IS NOT OLD.replay_of_job_id
  OR NEW.replay_key IS NOT OLD.replay_key
  OR NEW.replay_actor IS NOT OLD.replay_actor
  OR NEW.replay_reason_code IS NOT OLD.replay_reason_code
  OR NEW.replay_evidence_ref IS NOT OLD.replay_evidence_ref
  OR NEW.replay_source_version IS NOT OLD.replay_source_version
  OR NEW.replay_source_status IS NOT OLD.replay_source_status
  OR NEW.replay_evidence_kind IS NOT OLD.replay_evidence_kind
  OR NEW.created_at_ms IS NOT OLD.created_at_ms
  OR OLD.version >= 2147483647
  OR
  NEW.version <> OLD.version + 1
  OR NEW.attempt_count < OLD.attempt_count
  OR NEW.attempt_count > OLD.attempt_count + 1
  OR (OLD.status IN ('queued', 'retry_wait') AND NEW.status = 'claimed'
    AND NEW.attempt_count <> OLD.attempt_count + 1)
  OR (NOT (OLD.status IN ('queued', 'retry_wait') AND NEW.status = 'claimed')
    AND NEW.attempt_count <> OLD.attempt_count)
  OR (NEW.status <> 'retry_wait' AND NEW.available_at_ms <> OLD.available_at_ms)
  OR NEW.updated_at_ms < OLD.updated_at_ms
  OR (NEW.completed_at_ms IS NOT NULL AND NEW.completed_at_ms < OLD.updated_at_ms)
  OR NOT (
    (OLD.status IN ('queued', 'retry_wait') AND NEW.status IN ('claimed', 'dead_letter'))
    OR (OLD.status = 'claimed' AND NEW.status IN ('running', 'retry_wait', 'failed', 'dead_letter', 'manual_review'))
    OR (OLD.status = 'running' AND NEW.status IN ('succeeded', 'retry_wait', 'failed', 'dead_letter', 'manual_review'))
    OR (OLD.status IN ('claimed', 'running') AND NEW.status = OLD.status
      AND NEW.lease_owner IS OLD.lease_owner
      AND NEW.lease_token IS OLD.lease_token
      AND NEW.delivery_id IS OLD.delivery_id
      AND NEW.lease_expires_at_ms > OLD.lease_expires_at_ms
      AND NEW.result_digest IS OLD.result_digest
      AND NEW.error_code IS OLD.error_code
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.completed_at_ms IS OLD.completed_at_ms)
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid background job transition');
END;

CREATE TRIGGER IF NOT EXISTS background_job_transition_exact_guard
BEFORE INSERT ON background_job_transitions
WHEN
  NOT (
    (NEW.event_type IN ('created', 'replayed') AND NEW.from_status IS NULL
      AND NEW.to_status = 'queued' AND NEW.from_version = 0 AND NEW.to_version = 1)
    OR (NEW.event_type = 'claimed' AND NEW.from_status IN ('queued', 'retry_wait')
      AND NEW.to_status = 'claimed')
    OR (NEW.event_type = 'started' AND NEW.from_status = 'claimed' AND NEW.to_status = 'running')
    OR (NEW.event_type = 'succeeded' AND NEW.from_status = 'running' AND NEW.to_status = 'succeeded')
    OR (NEW.event_type = 'retry_scheduled' AND NEW.from_status IN ('claimed', 'running')
      AND NEW.to_status = 'retry_wait')
    OR (NEW.event_type = 'failed' AND NEW.from_status IN ('claimed', 'running') AND NEW.to_status = 'failed')
    OR (NEW.event_type = 'dead_lettered' AND NEW.from_status IN ('queued', 'retry_wait', 'claimed', 'running')
      AND NEW.to_status = 'dead_letter')
    OR (NEW.event_type = 'manual_review' AND NEW.from_status = 'running' AND NEW.to_status = 'manual_review')
    OR (NEW.event_type = 'claim_recovered' AND NEW.from_status = 'claimed' AND NEW.to_status = 'retry_wait')
    OR (NEW.event_type = 'lease_renewed' AND NEW.from_status IN ('claimed', 'running')
      AND NEW.to_status = NEW.from_status)
  )
  OR (
    NEW.event_type IN ('created', 'claimed', 'started', 'succeeded', 'lease_renewed')
    AND (NEW.reason_code IS NOT NULL OR NEW.evidence_ref IS NOT NULL)
  )
  OR (
    NEW.event_type IN ('replayed', 'manual_review')
    AND (NEW.reason_code IS NULL OR NEW.evidence_ref IS NULL)
  )
  OR (
    NEW.event_type IN ('retry_scheduled', 'failed', 'dead_lettered', 'claim_recovered')
    AND (NEW.reason_code IS NULL OR NEW.evidence_ref IS NOT NULL)
  )
  OR NOT EXISTS (
    SELECT 1 FROM background_jobs AS job
    WHERE job.job_id = NEW.job_id AND job.version = NEW.to_version
      AND job.status = NEW.to_status AND job.updated_at_ms = NEW.created_at_ms
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid background job transition ledger entry');
END;

CREATE TRIGGER IF NOT EXISTS background_job_outbox_envelope_guard
BEFORE INSERT ON background_job_outbox
WHEN NEW.envelope_json <> json_object(
  'v', 1, 'jobId', NEW.job_id, 'route',
  (SELECT route FROM background_jobs WHERE job_id = NEW.job_id), 'jobVersion', NEW.job_version
)
BEGIN
  SELECT RAISE(ABORT, 'invalid background job outbox envelope');
END;

CREATE TRIGGER IF NOT EXISTS background_job_outbox_transition_guard
BEFORE UPDATE ON background_job_outbox
WHEN
  NEW.outbox_id IS NOT OLD.outbox_id
  OR NEW.job_id IS NOT OLD.job_id
  OR NEW.job_version IS NOT OLD.job_version
  OR NEW.envelope_json IS NOT OLD.envelope_json
  OR NEW.created_at_ms IS NOT OLD.created_at_ms
  OR OLD.version >= 2147483647
  OR NEW.version <> OLD.version + 1
  OR NEW.available_at_ms < OLD.available_at_ms
  OR NEW.published_at_ms IS NOT NULL AND NEW.published_at_ms < OLD.created_at_ms
  OR NOT (
    (OLD.state = 'pending' AND NEW.state = 'publishing')
    OR (OLD.state = 'publishing' AND NEW.state IN ('publishing', 'pending', 'published'))
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid background job outbox transition');
END;
