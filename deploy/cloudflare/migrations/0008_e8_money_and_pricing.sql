-- Cloudflare money is stored as canonical integer e8 USD TEXT. The guarded
-- updates deliberately fail the migration rather than silently overflowing or
-- normalizing a legacy value that was not a canonical microusd amount.
DROP TRIGGER balance_ledger_no_update;

CREATE TRIGGER users_e8_migration_guard
BEFORE UPDATE OF balance_microusd ON users
WHEN NOT (
  length(OLD.balance_microusd) BETWEEN 1 AND 38
  AND OLD.balance_microusd NOT GLOB '*[^0-9]*'
  AND (OLD.balance_microusd = '0' OR substr(OLD.balance_microusd, 1, 1) BETWEEN '1' AND '9')
)
BEGIN
  SELECT RAISE(ABORT, 'invalid or overflowing legacy user balance');
END;

CREATE TRIGGER balance_ledger_e8_migration_guard
BEFORE UPDATE OF delta_microusd, balance_before_microusd, balance_after_microusd ON balance_ledger
WHEN NOT (
  length(OLD.balance_before_microusd) BETWEEN 1 AND 38
  AND OLD.balance_before_microusd NOT GLOB '*[^0-9]*'
  AND (OLD.balance_before_microusd = '0' OR substr(OLD.balance_before_microusd, 1, 1) BETWEEN '1' AND '9')
  AND length(OLD.balance_after_microusd) BETWEEN 1 AND 38
  AND OLD.balance_after_microusd NOT GLOB '*[^0-9]*'
  AND (OLD.balance_after_microusd = '0' OR substr(OLD.balance_after_microusd, 1, 1) BETWEEN '1' AND '9')
  AND length(OLD.delta_microusd) BETWEEN 1 AND 39
  AND (
    OLD.delta_microusd = '0'
    OR (OLD.delta_microusd NOT GLOB '*[^0-9]*' AND substr(OLD.delta_microusd, 1, 1) BETWEEN '1' AND '9')
    OR (substr(OLD.delta_microusd, 1, 1) = '-' AND length(OLD.delta_microusd) BETWEEN 2 AND 39
      AND substr(OLD.delta_microusd, 2) NOT GLOB '*[^0-9]*'
      AND substr(OLD.delta_microusd, 2, 1) BETWEEN '1' AND '9')
  )
)
BEGIN
  SELECT RAISE(ABORT, 'invalid or overflowing legacy balance ledger');
END;

UPDATE users
SET balance_microusd = CASE WHEN balance_microusd = '0' THEN '0' ELSE balance_microusd || '00' END;

UPDATE balance_ledger
SET delta_microusd = CASE
      WHEN delta_microusd = '0' THEN '0'
      WHEN substr(delta_microusd, 1, 1) = '-' THEN '-' || substr(delta_microusd, 2) || '00'
      ELSE delta_microusd || '00'
    END,
    balance_before_microusd = CASE WHEN balance_before_microusd = '0' THEN '0' ELSE balance_before_microusd || '00' END,
    balance_after_microusd = CASE WHEN balance_after_microusd = '0' THEN '0' ELSE balance_after_microusd || '00' END;

DROP TRIGGER users_e8_migration_guard;
DROP TRIGGER balance_ledger_e8_migration_guard;

ALTER TABLE users RENAME COLUMN balance_microusd TO balance_e8_usd;
ALTER TABLE balance_ledger RENAME COLUMN delta_microusd TO delta_e8_usd;
ALTER TABLE balance_ledger RENAME COLUMN balance_before_microusd TO balance_before_e8_usd;
ALTER TABLE balance_ledger RENAME COLUMN balance_after_microusd TO balance_after_e8_usd;

CREATE TRIGGER balance_ledger_no_update BEFORE UPDATE ON balance_ledger BEGIN SELECT RAISE(ABORT, 'balance ledger is immutable'); END;

ALTER TABLE gateway_requests ADD COLUMN pricing_version_id TEXT CHECK(
  pricing_version_id IS NULL OR (length(pricing_version_id) BETWEEN 1 AND 128
    AND pricing_version_id NOT GLOB '*[^a-z0-9._:-]*')
);
ALTER TABLE gateway_requests ADD COLUMN pricing_digest TEXT CHECK(
  pricing_digest IS NULL OR (length(pricing_digest) = 64
    AND pricing_digest NOT GLOB '*[^0-9a-f]*')
);
ALTER TABLE gateway_requests ADD COLUMN pricing_rule_pattern TEXT CHECK(
  pricing_rule_pattern IS NULL OR (
    length(pricing_rule_pattern) BETWEEN 1 AND 257
    AND (
      (instr(pricing_rule_pattern, '*') = 0 AND pricing_rule_pattern NOT GLOB '*[^a-z0-9._:/-]*')
      OR (substr(pricing_rule_pattern, -1) = '*' AND length(pricing_rule_pattern) > 1
        AND instr(substr(pricing_rule_pattern, 1, length(pricing_rule_pattern) - 1), '*') = 0
        AND substr(pricing_rule_pattern, 1, length(pricing_rule_pattern) - 1) NOT GLOB '*[^a-z0-9._:/-]*')
    )
  )
);

CREATE TRIGGER gateway_requests_require_pricing
BEFORE INSERT ON gateway_requests
WHEN NEW.pricing_version_id IS NULL OR NEW.pricing_digest IS NULL OR NEW.pricing_rule_pattern IS NULL
BEGIN
  SELECT RAISE(ABORT, 'gateway request requires admitted pricing');
END;

CREATE TRIGGER gateway_requests_pricing_immutable
BEFORE UPDATE OF pricing_version_id, pricing_digest, pricing_rule_pattern ON gateway_requests
BEGIN
  SELECT RAISE(ABORT, 'gateway request pricing is immutable');
END;

INSERT INTO schema_metadata(key, value) VALUES
  ('cloudflare_e8_money_scale', '8'),
  ('cloudflare_pricing_schema_version', '2026-09-08.v1');

-- Price cards and rules are append-only. The singleton pointer is the only
-- mutable state needed to activate a fully written, digest-checked version.
CREATE TABLE pricing_versions (
  version_id TEXT PRIMARY KEY CHECK(length(version_id) BETWEEN 1 AND 128 AND version_id NOT GLOB '*[^a-z0-9._:-]*'),
  digest TEXT NOT NULL CHECK(length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*'),
  max_reservation_e8_usd TEXT NOT NULL CHECK(
    length(max_reservation_e8_usd) BETWEEN 1 AND 40
    AND max_reservation_e8_usd NOT GLOB '*[^0-9]*'
    AND substr(max_reservation_e8_usd, 1, 1) BETWEEN '1' AND '9'
  ),
  created_at TEXT NOT NULL
);

CREATE TABLE pricing_rules (
  version_id TEXT NOT NULL REFERENCES pricing_versions(version_id),
  model_pattern TEXT NOT NULL CHECK(length(model_pattern) BETWEEN 1 AND 257),
  match_kind TEXT NOT NULL CHECK(match_kind IN ('exact', 'family')),
  input_e8_per_million TEXT NOT NULL,
  output_e8_per_million TEXT NOT NULL,
  cache_read_e8_per_million TEXT NOT NULL,
  cache_write_e8_per_million TEXT NOT NULL,
  cache_write_5m_e8_per_million TEXT NOT NULL,
  cache_write_1h_e8_per_million TEXT NOT NULL,
  image_input_e8_per_million TEXT NOT NULL,
  image_output_e8_per_million TEXT NOT NULL,
  priority_input_e8_per_million TEXT NOT NULL,
  priority_output_e8_per_million TEXT NOT NULL,
  priority_cache_read_e8_per_million TEXT NOT NULL,
  priority_cache_write_e8_per_million TEXT NOT NULL,
  fast_multiplier_bps TEXT NOT NULL,
  flex_multiplier_bps TEXT NOT NULL,
  max_reasoning_effort_multiplier_bps TEXT NOT NULL,
  PRIMARY KEY(version_id, model_pattern),
  CHECK(
    (match_kind = 'exact' AND instr(model_pattern, '*') = 0)
    OR (match_kind = 'family' AND substr(model_pattern, -1) = '*' AND length(model_pattern) > 1
      AND instr(substr(model_pattern, 1, length(model_pattern) - 1), '*') = 0)
  ),
  CHECK(
    (CASE WHEN match_kind = 'family' THEN substr(model_pattern, 1, length(model_pattern) - 1) ELSE model_pattern END)
      NOT GLOB '*[^A-Za-z0-9._:/-]*'
  ),
  CHECK(length(input_e8_per_million) BETWEEN 1 AND 40 AND input_e8_per_million NOT GLOB '*[^0-9]*' AND (input_e8_per_million = '0' OR substr(input_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(output_e8_per_million) BETWEEN 1 AND 40 AND output_e8_per_million NOT GLOB '*[^0-9]*' AND (output_e8_per_million = '0' OR substr(output_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(cache_read_e8_per_million) BETWEEN 1 AND 40 AND cache_read_e8_per_million NOT GLOB '*[^0-9]*' AND (cache_read_e8_per_million = '0' OR substr(cache_read_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(cache_write_e8_per_million) BETWEEN 1 AND 40 AND cache_write_e8_per_million NOT GLOB '*[^0-9]*' AND (cache_write_e8_per_million = '0' OR substr(cache_write_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(cache_write_5m_e8_per_million) BETWEEN 1 AND 40 AND cache_write_5m_e8_per_million NOT GLOB '*[^0-9]*' AND (cache_write_5m_e8_per_million = '0' OR substr(cache_write_5m_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(cache_write_1h_e8_per_million) BETWEEN 1 AND 40 AND cache_write_1h_e8_per_million NOT GLOB '*[^0-9]*' AND (cache_write_1h_e8_per_million = '0' OR substr(cache_write_1h_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(image_input_e8_per_million) BETWEEN 1 AND 40 AND image_input_e8_per_million NOT GLOB '*[^0-9]*' AND (image_input_e8_per_million = '0' OR substr(image_input_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(image_output_e8_per_million) BETWEEN 1 AND 40 AND image_output_e8_per_million NOT GLOB '*[^0-9]*' AND (image_output_e8_per_million = '0' OR substr(image_output_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(priority_input_e8_per_million) BETWEEN 1 AND 40 AND priority_input_e8_per_million NOT GLOB '*[^0-9]*' AND (priority_input_e8_per_million = '0' OR substr(priority_input_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(priority_output_e8_per_million) BETWEEN 1 AND 40 AND priority_output_e8_per_million NOT GLOB '*[^0-9]*' AND (priority_output_e8_per_million = '0' OR substr(priority_output_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(priority_cache_read_e8_per_million) BETWEEN 1 AND 40 AND priority_cache_read_e8_per_million NOT GLOB '*[^0-9]*' AND (priority_cache_read_e8_per_million = '0' OR substr(priority_cache_read_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(priority_cache_write_e8_per_million) BETWEEN 1 AND 40 AND priority_cache_write_e8_per_million NOT GLOB '*[^0-9]*' AND (priority_cache_write_e8_per_million = '0' OR substr(priority_cache_write_e8_per_million,1,1) BETWEEN '1' AND '9')),
  CHECK(length(fast_multiplier_bps) BETWEEN 1 AND 8 AND fast_multiplier_bps NOT GLOB '*[^0-9]*' AND (fast_multiplier_bps = '0' OR substr(fast_multiplier_bps,1,1) BETWEEN '1' AND '9')),
  CHECK(length(flex_multiplier_bps) BETWEEN 1 AND 8 AND flex_multiplier_bps NOT GLOB '*[^0-9]*' AND (flex_multiplier_bps = '0' OR substr(flex_multiplier_bps,1,1) BETWEEN '1' AND '9')),
  CHECK(length(max_reasoning_effort_multiplier_bps) BETWEEN 1 AND 8 AND max_reasoning_effort_multiplier_bps NOT GLOB '*[^0-9]*' AND substr(max_reasoning_effort_multiplier_bps,1,1) BETWEEN '1' AND '9')
);

CREATE TRIGGER pricing_versions_validate_insert
BEFORE INSERT ON pricing_versions
WHEN NEW.version_id <> lower(NEW.version_id)
BEGIN
  SELECT RAISE(ABORT, 'invalid pricing version id');
END;

CREATE TRIGGER pricing_rules_validate_insert
BEFORE INSERT ON pricing_rules
WHEN NEW.version_id <> lower(NEW.version_id)
  OR NEW.model_pattern <> lower(NEW.model_pattern)
  OR (NEW.match_kind = 'family' AND substr(NEW.model_pattern, -1) <> '*')
  OR (substr(NEW.model_pattern, 1, 7) = 'claude-' AND instr(NEW.model_pattern, '.') > 0)
BEGIN
  SELECT RAISE(ABORT, 'invalid pricing rule pattern');
END;

CREATE TRIGGER pricing_rules_no_overlapping_families
BEFORE INSERT ON pricing_rules
WHEN NEW.match_kind = 'family' AND EXISTS (
  SELECT 1 FROM pricing_rules AS prior
  WHERE prior.version_id = NEW.version_id AND prior.match_kind = 'family'
    AND (
      (length(NEW.model_pattern) <= length(prior.model_pattern)
        AND substr(prior.model_pattern, 1, length(NEW.model_pattern) - 1) = substr(NEW.model_pattern, 1, length(NEW.model_pattern) - 1))
      OR (length(prior.model_pattern) <= length(NEW.model_pattern)
        AND substr(NEW.model_pattern, 1, length(prior.model_pattern) - 1) = substr(prior.model_pattern, 1, length(prior.model_pattern) - 1))
    )
)
BEGIN
  SELECT RAISE(ABORT, 'ambiguous pricing wildcard family');
END;

CREATE TRIGGER pricing_versions_no_update BEFORE UPDATE ON pricing_versions BEGIN SELECT RAISE(ABORT, 'pricing version is immutable'); END;
CREATE TRIGGER pricing_versions_no_delete BEFORE DELETE ON pricing_versions BEGIN SELECT RAISE(ABORT, 'pricing version is immutable'); END;
CREATE TRIGGER pricing_rules_no_update BEFORE UPDATE ON pricing_rules BEGIN SELECT RAISE(ABORT, 'pricing rule is immutable'); END;
CREATE TRIGGER pricing_rules_no_delete BEFORE DELETE ON pricing_rules BEGIN SELECT RAISE(ABORT, 'pricing rule is immutable'); END;

CREATE TABLE pricing_active_version (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  version_id TEXT NOT NULL REFERENCES pricing_versions(version_id),
  activated_at TEXT NOT NULL
);

CREATE TABLE pricing_version_activations (
  version_id TEXT PRIMARY KEY REFERENCES pricing_versions(version_id),
  first_activated_at TEXT NOT NULL
);

CREATE TRIGGER pricing_active_version_record_insert
AFTER INSERT ON pricing_active_version
BEGIN
  INSERT OR IGNORE INTO pricing_version_activations(version_id,first_activated_at)
  VALUES(NEW.version_id,NEW.activated_at);
END;

CREATE TRIGGER pricing_active_version_record_update
AFTER UPDATE OF version_id ON pricing_active_version
BEGIN
  INSERT OR IGNORE INTO pricing_version_activations(version_id,first_activated_at)
  VALUES(NEW.version_id,NEW.activated_at);
END;

CREATE TRIGGER pricing_version_activations_no_update BEFORE UPDATE ON pricing_version_activations BEGIN SELECT RAISE(ABORT, 'pricing activation is immutable'); END;
CREATE TRIGGER pricing_version_activations_no_delete BEFORE DELETE ON pricing_version_activations BEGIN SELECT RAISE(ABORT, 'pricing activation is immutable'); END;

CREATE TRIGGER pricing_rules_no_insert_after_activation
BEFORE INSERT ON pricing_rules
WHEN EXISTS(SELECT 1 FROM pricing_version_activations WHERE version_id=NEW.version_id)
BEGIN
  SELECT RAISE(ABORT, 'active pricing version is immutable');
END;
