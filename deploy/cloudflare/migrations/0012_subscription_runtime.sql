-- Cloudflare-native subscription plans and user subscriptions. Monetary values
-- are canonical, non-negative E8 USD TEXT bounded to signed int64. Runtime IDs
-- also remain TEXT so Workers never round persistent int64 values through
-- JavaScript Number.
INSERT INTO schema_metadata(key, value) VALUES
  ('cloudflare_subscription_runtime_schema_version', '2026-09-09.v1');

CREATE TABLE subscription_plans (
  id TEXT PRIMARY KEY CHECK(
    length(id) BETWEEN 1 AND 19 AND id NOT GLOB '*[^0-9]*'
    AND substr(id, 1, 1) BETWEEN '1' AND '9'
    AND (length(id) < 19 OR id <= '9223372036854775807')
  ),
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
  description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 4096),
  price_e8_usd TEXT NOT NULL CHECK(
    length(price_e8_usd) BETWEEN 1 AND 19
    AND price_e8_usd NOT GLOB '*[^0-9]*'
    AND (price_e8_usd = '0' OR substr(price_e8_usd, 1, 1) BETWEEN '1' AND '9')
    AND (length(price_e8_usd) < 19 OR price_e8_usd <= '9223372036854775807')
  ),
  original_price_e8_usd TEXT CHECK(
    original_price_e8_usd IS NULL OR (
      length(original_price_e8_usd) BETWEEN 1 AND 19
      AND original_price_e8_usd NOT GLOB '*[^0-9]*'
      AND (original_price_e8_usd = '0' OR substr(original_price_e8_usd, 1, 1) BETWEEN '1' AND '9')
      AND (length(original_price_e8_usd) < 19 OR original_price_e8_usd <= '9223372036854775807')
    )
  ),
  daily_limit_e8_usd TEXT CHECK(
    daily_limit_e8_usd IS NULL OR (
      length(daily_limit_e8_usd) BETWEEN 1 AND 19
      AND daily_limit_e8_usd NOT GLOB '*[^0-9]*'
      AND (daily_limit_e8_usd = '0' OR substr(daily_limit_e8_usd, 1, 1) BETWEEN '1' AND '9')
      AND (length(daily_limit_e8_usd) < 19 OR daily_limit_e8_usd <= '9223372036854775807')
    )
  ),
  weekly_limit_e8_usd TEXT CHECK(
    weekly_limit_e8_usd IS NULL OR (
      length(weekly_limit_e8_usd) BETWEEN 1 AND 19
      AND weekly_limit_e8_usd NOT GLOB '*[^0-9]*'
      AND (weekly_limit_e8_usd = '0' OR substr(weekly_limit_e8_usd, 1, 1) BETWEEN '1' AND '9')
      AND (length(weekly_limit_e8_usd) < 19 OR weekly_limit_e8_usd <= '9223372036854775807')
    )
  ),
  monthly_limit_e8_usd TEXT CHECK(
    monthly_limit_e8_usd IS NULL OR (
      length(monthly_limit_e8_usd) BETWEEN 1 AND 19
      AND monthly_limit_e8_usd NOT GLOB '*[^0-9]*'
      AND (monthly_limit_e8_usd = '0' OR substr(monthly_limit_e8_usd, 1, 1) BETWEEN '1' AND '9')
      AND (length(monthly_limit_e8_usd) < 19 OR monthly_limit_e8_usd <= '9223372036854775807')
    )
  ),
  currency TEXT NOT NULL CHECK(length(currency) = 3 AND currency NOT GLOB '*[^A-Z]*'),
  validity_days INTEGER NOT NULL CHECK(validity_days BETWEEN 1 AND 36500),
  validity_unit TEXT NOT NULL CHECK(validity_unit = 'day'),
  features TEXT NOT NULL DEFAULT '' CHECK(length(features) <= 8192),
  product_name TEXT NOT NULL DEFAULT '' CHECK(length(product_name) <= 100),
  for_sale INTEGER NOT NULL DEFAULT 1 CHECK(for_sale IN (0, 1)),
  sort_order INTEGER NOT NULL DEFAULT 0 CHECK(sort_order BETWEEN -1000000 AND 1000000),
  version INTEGER NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 2147483647),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);

CREATE INDEX subscription_plans_group_live_idx
  ON subscription_plans(group_id, for_sale, sort_order, id)
  WHERE deleted_at IS NULL;

CREATE TRIGGER subscription_plans_validate_insert
BEFORE INSERT ON subscription_plans
WHEN NOT EXISTS (
  SELECT 1 FROM groups
  WHERE id = NEW.group_id AND deleted_at IS NULL
    AND subscription_type = 'subscription'
)
BEGIN
  SELECT RAISE(ABORT, 'subscription plan requires a live subscription group');
END;

CREATE TRIGGER subscription_plans_validate_update
BEFORE UPDATE OF group_id, deleted_at ON subscription_plans
WHEN NEW.deleted_at IS NULL AND NOT EXISTS (
  SELECT 1 FROM groups
  WHERE id = NEW.group_id AND deleted_at IS NULL
    AND subscription_type = 'subscription'
)
BEGIN
  SELECT RAISE(ABORT, 'subscription plan requires a live subscription group');
END;

CREATE TABLE user_subscriptions (
  id TEXT PRIMARY KEY CHECK(
    length(id) BETWEEN 1 AND 19 AND id NOT GLOB '*[^0-9]*'
    AND substr(id, 1, 1) BETWEEN '1' AND '9'
    AND (length(id) < 19 OR id <= '9223372036854775807')
  ),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  plan_id TEXT REFERENCES subscription_plans(id) ON DELETE SET NULL,
  starts_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active', 'expired', 'suspended')),
  initial_daily_boundary TEXT,
  daily_window_start TEXT,
  weekly_window_start TEXT,
  monthly_window_start TEXT,
  weekly_anchor_kind TEXT CHECK(weekly_anchor_kind IS NULL OR weekly_anchor_kind IN ('activation', 'manual', 'legacy_initial')),
  monthly_anchor_kind TEXT CHECK(monthly_anchor_kind IS NULL OR monthly_anchor_kind IN ('activation', 'manual', 'legacy_initial')),
  daily_limit_e8_usd TEXT,
  weekly_limit_e8_usd TEXT,
  monthly_limit_e8_usd TEXT,
  daily_usage_e8_usd TEXT NOT NULL DEFAULT '0',
  weekly_usage_e8_usd TEXT NOT NULL DEFAULT '0',
  monthly_usage_e8_usd TEXT NOT NULL DEFAULT '0',
  assigned_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  assigned_at TEXT NOT NULL,
  notes TEXT NOT NULL DEFAULT '' CHECK(length(notes) <= 4096),
  version INTEGER NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 2147483647),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT,
  CHECK(starts_at < expires_at),
  CHECK((weekly_window_start IS NULL) = (weekly_anchor_kind IS NULL)),
  CHECK((monthly_window_start IS NULL) = (monthly_anchor_kind IS NULL)),
  CHECK(initial_daily_boundary IS NULL OR initial_daily_boundary <= starts_at),
  CHECK(
    daily_limit_e8_usd IS NULL OR (
      length(daily_limit_e8_usd) BETWEEN 1 AND 19
      AND daily_limit_e8_usd NOT GLOB '*[^0-9]*'
      AND (daily_limit_e8_usd = '0' OR substr(daily_limit_e8_usd, 1, 1) BETWEEN '1' AND '9')
      AND (length(daily_limit_e8_usd) < 19 OR daily_limit_e8_usd <= '9223372036854775807')
    )
  ),
  CHECK(
    weekly_limit_e8_usd IS NULL OR (
      length(weekly_limit_e8_usd) BETWEEN 1 AND 19
      AND weekly_limit_e8_usd NOT GLOB '*[^0-9]*'
      AND (weekly_limit_e8_usd = '0' OR substr(weekly_limit_e8_usd, 1, 1) BETWEEN '1' AND '9')
      AND (length(weekly_limit_e8_usd) < 19 OR weekly_limit_e8_usd <= '9223372036854775807')
    )
  ),
  CHECK(
    monthly_limit_e8_usd IS NULL OR (
      length(monthly_limit_e8_usd) BETWEEN 1 AND 19
      AND monthly_limit_e8_usd NOT GLOB '*[^0-9]*'
      AND (monthly_limit_e8_usd = '0' OR substr(monthly_limit_e8_usd, 1, 1) BETWEEN '1' AND '9')
      AND (length(monthly_limit_e8_usd) < 19 OR monthly_limit_e8_usd <= '9223372036854775807')
    )
  ),
  CHECK(
    length(daily_usage_e8_usd) BETWEEN 1 AND 19
    AND daily_usage_e8_usd NOT GLOB '*[^0-9]*'
    AND (daily_usage_e8_usd = '0' OR substr(daily_usage_e8_usd, 1, 1) BETWEEN '1' AND '9')
    AND (length(daily_usage_e8_usd) < 19 OR daily_usage_e8_usd <= '9223372036854775807')
  ),
  CHECK(
    length(weekly_usage_e8_usd) BETWEEN 1 AND 19
    AND weekly_usage_e8_usd NOT GLOB '*[^0-9]*'
    AND (weekly_usage_e8_usd = '0' OR substr(weekly_usage_e8_usd, 1, 1) BETWEEN '1' AND '9')
    AND (length(weekly_usage_e8_usd) < 19 OR weekly_usage_e8_usd <= '9223372036854775807')
  ),
  CHECK(
    length(monthly_usage_e8_usd) BETWEEN 1 AND 19
    AND monthly_usage_e8_usd NOT GLOB '*[^0-9]*'
    AND (monthly_usage_e8_usd = '0' OR substr(monthly_usage_e8_usd, 1, 1) BETWEEN '1' AND '9')
    AND (length(monthly_usage_e8_usd) < 19 OR monthly_usage_e8_usd <= '9223372036854775807')
  )
);

CREATE UNIQUE INDEX user_subscriptions_user_group_live_idx
  ON user_subscriptions(user_id, group_id) WHERE deleted_at IS NULL;
CREATE INDEX user_subscriptions_user_list_idx
  ON user_subscriptions(user_id, deleted_at, status, expires_at, id);
CREATE INDEX user_subscriptions_group_list_idx
  ON user_subscriptions(group_id, deleted_at, status, expires_at, id);
CREATE INDEX user_subscriptions_expiry_idx
  ON user_subscriptions(status, expires_at, id) WHERE deleted_at IS NULL;

CREATE TRIGGER user_subscriptions_validate_insert
BEFORE INSERT ON user_subscriptions
WHEN NOT EXISTS (SELECT 1 FROM users WHERE id = NEW.user_id AND deleted_at IS NULL)
  OR NOT EXISTS (
    SELECT 1 FROM groups WHERE id = NEW.group_id AND deleted_at IS NULL
      AND subscription_type = 'subscription'
  )
  OR (NEW.assigned_by IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM users WHERE id = NEW.assigned_by AND deleted_at IS NULL AND role = 'admin'
  ))
  OR (NEW.plan_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM subscription_plans
    WHERE id = NEW.plan_id AND group_id = NEW.group_id AND deleted_at IS NULL
  ))
BEGIN
  SELECT RAISE(ABORT, 'subscription requires live matching references');
END;

CREATE TRIGGER user_subscriptions_validate_live_update
BEFORE UPDATE OF user_id, group_id, plan_id, assigned_by, deleted_at ON user_subscriptions
WHEN NEW.deleted_at IS NULL AND (
  NOT EXISTS (SELECT 1 FROM users WHERE id = NEW.user_id AND deleted_at IS NULL)
  OR NOT EXISTS (
    SELECT 1 FROM groups WHERE id = NEW.group_id AND deleted_at IS NULL
      AND subscription_type = 'subscription'
  )
  OR (NEW.assigned_by IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM users WHERE id = NEW.assigned_by AND deleted_at IS NULL AND role = 'admin'
  ))
  OR (NEW.plan_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM subscription_plans
    WHERE id = NEW.plan_id AND group_id = NEW.group_id AND deleted_at IS NULL
  ))
)
BEGIN
  SELECT RAISE(ABORT, 'subscription requires live matching references');
END;

-- A guard row exists only when its preceding conditional statement changed
-- exactly one row. Operation effects reference the guard, so UPDATE 0 makes the
-- complete D1 batch fail and roll back, including the operation record.
CREATE TABLE subscription_runtime_guards (
  guard_id TEXT PRIMARY KEY CHECK(length(guard_id) = 64 AND guard_id NOT GLOB '*[^0-9a-f]*'),
  created_at TEXT NOT NULL
);

CREATE TABLE subscription_operations (
  operation_id TEXT PRIMARY KEY CHECK(
    length(operation_id) BETWEEN 1 AND 128
    AND operation_id NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  operation_kind TEXT NOT NULL CHECK(operation_kind IN (
    'create_plan', 'assign_or_extend', 'revoke', 'restore', 'extend',
    'activate_windows', 'maintain_windows', 'reset_windows',
    'reserve_usage', 'expiry_sweep'
  )),
  request_hash TEXT NOT NULL CHECK(length(request_hash) = 64 AND request_hash NOT GLOB '*[^0-9a-f]*'),
  result_json TEXT NOT NULL CHECK(length(result_json) BETWEEN 2 AND 65536),
  entity_id TEXT,
  actor_user_id TEXT,
  user_id TEXT,
  group_id TEXT,
  entity_version INTEGER CHECK(entity_version IS NULL OR entity_version BETWEEN 1 AND 2147483647),
  created_at TEXT NOT NULL
);

CREATE TABLE subscription_operation_effects (
  operation_id TEXT NOT NULL REFERENCES subscription_operations(operation_id),
  ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 100),
  guard_id TEXT NOT NULL UNIQUE REFERENCES subscription_runtime_guards(guard_id),
  entity_kind TEXT NOT NULL CHECK(entity_kind IN ('plan', 'subscription')),
  entity_id TEXT NOT NULL,
  before_version INTEGER CHECK(before_version IS NULL OR before_version BETWEEN 1 AND 2147483647),
  after_version INTEGER NOT NULL CHECK(after_version BETWEEN 1 AND 2147483647),
  PRIMARY KEY(operation_id, ordinal)
);

CREATE TRIGGER subscription_operations_validate_actor
BEFORE INSERT ON subscription_operations
WHEN NEW.actor_user_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM users
  WHERE id = NEW.actor_user_id AND deleted_at IS NULL AND role = 'admin'
)
BEGIN
  SELECT RAISE(ABORT, 'subscription operation requires a live administrator');
END;

CREATE INDEX subscription_operations_entity_created_idx
  ON subscription_operations(entity_id, created_at, operation_id);
CREATE INDEX subscription_operations_user_created_idx
  ON subscription_operations(user_id, created_at, operation_id);

CREATE TRIGGER subscription_operations_no_update
BEFORE UPDATE ON subscription_operations
BEGIN
  SELECT RAISE(ABORT, 'subscription operation audit is immutable');
END;
CREATE TRIGGER subscription_operations_no_delete
BEFORE DELETE ON subscription_operations
BEGIN
  SELECT RAISE(ABORT, 'subscription operation audit is immutable');
END;
CREATE TRIGGER subscription_operation_effects_no_update
BEFORE UPDATE ON subscription_operation_effects
BEGIN
  SELECT RAISE(ABORT, 'subscription operation effect is immutable');
END;
CREATE TRIGGER subscription_operation_effects_no_delete
BEFORE DELETE ON subscription_operation_effects
BEGIN
  SELECT RAISE(ABORT, 'subscription operation effect is immutable');
END;
