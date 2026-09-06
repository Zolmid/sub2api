-- D1-crossing identifiers and fixed-point microusd amounts are canonical TEXT.
CREATE TABLE schema_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT INTO schema_metadata(key, value)
VALUES ('cloudflare_bridge_schema_version', '2026-09-06.v1');

CREATE TABLE users (
  id TEXT PRIMARY KEY
    CHECK(length(id) BETWEEN 1 AND 20 AND id NOT GLOB '*[^0-9]*'
      AND substr(id, 1, 1) BETWEEN '1' AND '9'),
  status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
  role TEXT NOT NULL,
  concurrency INTEGER NOT NULL CHECK(concurrency >= 1),
  balance_microusd TEXT NOT NULL
    CHECK(length(balance_microusd) BETWEEN 1 AND 40
      AND balance_microusd NOT GLOB '*[^0-9]*'
      AND (balance_microusd = '0'
        OR substr(balance_microusd, 1, 1) BETWEEN '1' AND '9')),
  allowed_group_ids_json TEXT NOT NULL DEFAULT '[]',
  restrict_public_groups INTEGER NOT NULL DEFAULT 0
    CHECK(restrict_public_groups IN (0, 1)),
  created_at TEXT NOT NULL
);

CREATE TABLE groups (
  id TEXT PRIMARY KEY
    CHECK(length(id) BETWEEN 1 AND 20 AND id NOT GLOB '*[^0-9]*'
      AND substr(id, 1, 1) BETWEEN '1' AND '9'),
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
  is_exclusive INTEGER NOT NULL DEFAULT 0 CHECK(is_exclusive IN (0, 1)),
  subscription_type TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE api_keys (
  id TEXT PRIMARY KEY
    CHECK(length(id) BETWEEN 1 AND 20 AND id NOT GLOB '*[^0-9]*'
      AND substr(id, 1, 1) BETWEEN '1' AND '9'),
  user_id TEXT NOT NULL REFERENCES users(id),
  group_id TEXT NOT NULL REFERENCES groups(id),
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
  key_hash TEXT NOT NULL UNIQUE
    CHECK(length(key_hash) = 64 AND key_hash NOT GLOB '*[^0-9a-f]*'),
  ip_whitelist_json TEXT NOT NULL DEFAULT '[]',
  ip_blacklist_json TEXT NOT NULL DEFAULT '[]',
  expires_at TEXT,
  last_used_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX api_keys_lookup_idx ON api_keys(key_hash, status);

CREATE TABLE accounts (
  id TEXT PRIMARY KEY
    CHECK(length(id) BETWEEN 1 AND 20 AND id NOT GLOB '*[^0-9]*'
      AND substr(id, 1, 1) BETWEEN '1' AND '9'),
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  type TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
  schedulable INTEGER NOT NULL CHECK(schedulable IN (0, 1)),
  priority INTEGER NOT NULL DEFAULT 0,
  max_concurrency INTEGER NOT NULL CHECK(max_concurrency >= 1),
  credential_envelope TEXT NOT NULL,
  extra_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE account_groups (
  account_id TEXT NOT NULL REFERENCES accounts(id),
  group_id TEXT NOT NULL REFERENCES groups(id),
  PRIMARY KEY(account_id, group_id)
);

CREATE INDEX account_group_schedule_idx
  ON account_groups(group_id, account_id);

CREATE TABLE model_aliases (
  alias TEXT PRIMARY KEY,
  upstream_model TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
  updated_at TEXT NOT NULL
);

CREATE TABLE gateway_requests (
  request_id TEXT PRIMARY KEY,
  api_key_id TEXT NOT NULL REFERENCES api_keys(id),
  account_id TEXT NOT NULL REFERENCES accounts(id),
  lease_id TEXT NOT NULL,
  lease_epoch TEXT NOT NULL
    CHECK(length(lease_epoch) BETWEEN 1 AND 20
      AND lease_epoch NOT GLOB '*[^0-9]*'
      AND substr(lease_epoch, 1, 1) BETWEEN '1' AND '9'),
  owner TEXT NOT NULL,
  model TEXT NOT NULL,
  upstream_model TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('admitted', 'succeeded', 'failed')),
  event_id TEXT UNIQUE,
  completion_nonce TEXT UNIQUE,
  completed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX gateway_requests_identity_idx
  ON gateway_requests(
    request_id, api_key_id, account_id, lease_id, lease_epoch, owner, state
  );

CREATE TABLE outbox_events (
  event_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL REFERENCES gateway_requests(request_id),
  payload_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL
    CHECK(length(payload_hash) = 64
      AND payload_hash NOT GLOB '*[^0-9a-f]*'),
  state TEXT NOT NULL CHECK(state IN ('pending', 'published', 'dead')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  last_attempt_at TEXT,
  published_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX outbox_pending_idx
  ON outbox_events(state, attempts, created_at);

CREATE TABLE outbox_conflicts (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL CHECK(source IN ('completion', 'queue')),
  event_id TEXT NOT NULL,
  existing_hash TEXT NOT NULL,
  incoming_hash TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  UNIQUE(source, event_id, incoming_hash)
);

CREATE TABLE usage_events (
  event_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL REFERENCES gateway_requests(request_id),
  payload_hash TEXT NOT NULL
    CHECK(length(payload_hash) = 64
      AND payload_hash NOT GLOB '*[^0-9a-f]*'),
  schema_version TEXT NOT NULL,
  event_type TEXT NOT NULL,
  api_key_id TEXT NOT NULL REFERENCES api_keys(id),
  account_id TEXT NOT NULL REFERENCES accounts(id),
  lease_id TEXT NOT NULL,
  lease_epoch TEXT NOT NULL
    CHECK(length(lease_epoch) BETWEEN 1 AND 20
      AND lease_epoch NOT GLOB '*[^0-9]*'
      AND substr(lease_epoch, 1, 1) BETWEEN '1' AND '9'),
  model TEXT NOT NULL,
  upstream_model TEXT NOT NULL,
  upstream_request_id TEXT,
  outcome TEXT NOT NULL CHECK(outcome IN ('succeeded', 'failed')),
  usage_state TEXT NOT NULL CHECK(usage_state IN ('confirmed', 'unknown')),
  input_tokens TEXT NOT NULL
    CHECK(length(input_tokens) BETWEEN 1 AND 20
      AND input_tokens NOT GLOB '*[^0-9]*'
      AND (input_tokens = '0'
        OR substr(input_tokens, 1, 1) BETWEEN '1' AND '9')),
  output_tokens TEXT NOT NULL
    CHECK(length(output_tokens) BETWEEN 1 AND 20
      AND output_tokens NOT GLOB '*[^0-9]*'
      AND (output_tokens = '0'
        OR substr(output_tokens, 1, 1) BETWEEN '1' AND '9')),
  cache_read_tokens TEXT NOT NULL
    CHECK(length(cache_read_tokens) BETWEEN 1 AND 20
      AND cache_read_tokens NOT GLOB '*[^0-9]*'
      AND (cache_read_tokens = '0'
        OR substr(cache_read_tokens, 1, 1) BETWEEN '1' AND '9')),
  duration_ms TEXT NOT NULL
    CHECK(length(duration_ms) BETWEEN 1 AND 20
      AND duration_ms NOT GLOB '*[^0-9]*'
      AND (duration_ms = '0'
        OR substr(duration_ms, 1, 1) BETWEEN '1' AND '9')),
  created_at TEXT NOT NULL
);

CREATE INDEX usage_request_idx ON usage_events(request_id);
