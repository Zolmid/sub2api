-- Runtime scheduler facts are non-secret and carry explicit provenance and
-- freshness. Live concurrency/RPM/cooldown counters remain in Durable Objects.
CREATE TABLE IF NOT EXISTS scheduler_account_runtime (
  account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  capabilities_json TEXT NOT NULL CHECK(json_valid(capabilities_json)),
  capabilities_evidence TEXT NOT NULL
    CHECK(capabilities_evidence IN ('confirmed', 'estimated', 'unknown')),
  capabilities_source TEXT NOT NULL
    CHECK(length(capabilities_source) BETWEEN 1 AND 64
      AND capabilities_source NOT GLOB '*[^A-Za-z0-9._:-]*'),
  capabilities_observed_at_ms INTEGER NOT NULL
    CHECK(capabilities_observed_at_ms >= 0),
  capabilities_fresh_until_ms INTEGER NOT NULL
    CHECK(capabilities_fresh_until_ms >= capabilities_observed_at_ms),
  quota_exhausted INTEGER CHECK(quota_exhausted IN (0, 1)),
  quota_remaining_bps INTEGER
    CHECK(quota_remaining_bps BETWEEN 0 AND 10000),
  quota_evidence TEXT NOT NULL
    CHECK(quota_evidence IN ('confirmed', 'estimated', 'unknown')),
  quota_source TEXT NOT NULL CHECK(length(quota_source) BETWEEN 1 AND 64
    AND quota_source NOT GLOB '*[^A-Za-z0-9._:-]*'),
  quota_observed_at_ms INTEGER NOT NULL CHECK(quota_observed_at_ms >= 0),
  quota_fresh_until_ms INTEGER NOT NULL
    CHECK(quota_fresh_until_ms >= quota_observed_at_ms),
  version INTEGER NOT NULL CHECK(version >= 1),
  updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
  CHECK(capabilities_evidence <> 'unknown' OR capabilities_json = '{}'),
  CHECK(capabilities_evidence = 'unknown' OR (
    json_type(capabilities_json, '$.platforms') = 'array'
    AND json_type(capabilities_json, '$.accountTypes') = 'array'
    AND json_type(capabilities_json, '$.models') = 'array'
    AND json_remove(
      capabilities_json, '$.platforms', '$.accountTypes', '$.models'
    ) = '{}'
  )),
  CHECK(quota_evidence <> 'unknown'
    OR (quota_exhausted IS NULL AND quota_remaining_bps IS NULL))
);

CREATE TABLE IF NOT EXISTS scheduler_principal_limits (
  scope TEXT NOT NULL CHECK(scope IN ('account', 'user', 'api_key')),
  principal_id TEXT NOT NULL
    CHECK(length(principal_id) BETWEEN 1 AND 20
      AND principal_id NOT GLOB '*[^0-9]*'
      AND substr(principal_id, 1, 1) BETWEEN '1' AND '9'),
  rpm_limit INTEGER NOT NULL CHECK(rpm_limit BETWEEN 1 AND 100000),
  evidence TEXT NOT NULL
    CHECK(evidence IN ('confirmed', 'estimated', 'unknown')),
  source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 64
    AND source NOT GLOB '*[^A-Za-z0-9._:-]*'),
  observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
  fresh_until_ms INTEGER NOT NULL CHECK(fresh_until_ms >= observed_at_ms),
  version INTEGER NOT NULL CHECK(version >= 1),
  updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
  PRIMARY KEY(scope, principal_id),
  CHECK(evidence <> 'unknown' OR rpm_limit = 1)
);

CREATE INDEX IF NOT EXISTS scheduler_runtime_freshness_idx
  ON scheduler_account_runtime(capabilities_fresh_until_ms, quota_fresh_until_ms);
CREATE INDEX IF NOT EXISTS scheduler_limit_freshness_idx
  ON scheduler_principal_limits(scope, fresh_until_ms, principal_id);

-- Billing becomes authoritative before scheduler cleanup runs. Persist the
-- cleanup obligation on the reservation so a post-commit Durable Object
-- failure can be retried without reporting a false billing failure.
ALTER TABLE billing_reservations ADD COLUMN scheduler_release_state TEXT
  NOT NULL DEFAULT 'pending'
  CHECK(scheduler_release_state IN ('pending', 'released'));
ALTER TABLE billing_reservations ADD COLUMN scheduler_release_attempts INTEGER
  NOT NULL DEFAULT 0 CHECK(scheduler_release_attempts >= 0);
ALTER TABLE billing_reservations ADD COLUMN scheduler_release_last_at TEXT;
ALTER TABLE billing_reservations ADD COLUMN scheduler_released_at TEXT;

CREATE INDEX IF NOT EXISTS billing_scheduler_release_idx
  ON billing_reservations(
    scheduler_release_state, state, created_at, request_id
  );
