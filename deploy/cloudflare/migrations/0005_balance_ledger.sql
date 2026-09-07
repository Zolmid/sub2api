-- Forward-only immutable administrator balance ledger. Amounts are canonical
-- signed microusd TEXT so neither the Worker nor D1 mutation math uses FLOAT.
CREATE TABLE balance_ledger (
  id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 128),
  operation_id TEXT NOT NULL UNIQUE,
  -- IDs are durable audit facts: a later user tombstone must not erase or
  -- block the immutable historical entry.
  actor_user_id TEXT NOT NULL CHECK(
    length(actor_user_id) BETWEEN 1 AND 20
    AND actor_user_id NOT GLOB '*[^0-9]*'
    AND substr(actor_user_id, 1, 1) BETWEEN '1' AND '9'
  ),
  target_user_id TEXT NOT NULL CHECK(
    length(target_user_id) BETWEEN 1 AND 20
    AND target_user_id NOT GLOB '*[^0-9]*'
    AND substr(target_user_id, 1, 1) BETWEEN '1' AND '9'
  ),
  adjustment_type TEXT NOT NULL CHECK(adjustment_type IN ('set', 'add', 'subtract')),
  reason TEXT NOT NULL CHECK(length(reason) <= 4096),
  delta_microusd TEXT NOT NULL CHECK(
    length(delta_microusd) BETWEEN 1 AND 41
    AND (
      delta_microusd = '0'
      OR (
        delta_microusd NOT GLOB '*[^0-9]*'
        AND substr(delta_microusd, 1, 1) BETWEEN '1' AND '9'
      )
      OR (
        substr(delta_microusd, 1, 1) = '-'
        AND substr(delta_microusd, 2) NOT GLOB '*[^0-9]*'
        AND substr(delta_microusd, 2, 1) BETWEEN '1' AND '9'
      )
    )
  ),
  balance_before_microusd TEXT NOT NULL CHECK(
    length(balance_before_microusd) BETWEEN 1 AND 40
    AND balance_before_microusd NOT GLOB '*[^0-9]*'
    AND (
      balance_before_microusd = '0'
      OR substr(balance_before_microusd, 1, 1) BETWEEN '1' AND '9'
    )
  ),
  balance_after_microusd TEXT NOT NULL CHECK(
    length(balance_after_microusd) BETWEEN 1 AND 40
    AND balance_after_microusd NOT GLOB '*[^0-9]*'
    AND (
      balance_after_microusd = '0'
      OR substr(balance_after_microusd, 1, 1) BETWEEN '1' AND '9'
    )
  ),
  created_at TEXT NOT NULL
);
CREATE INDEX balance_ledger_target_created_idx ON balance_ledger(target_user_id, created_at, id);
CREATE TRIGGER balance_ledger_no_update BEFORE UPDATE ON balance_ledger BEGIN SELECT RAISE(ABORT, 'balance ledger is immutable'); END;
CREATE TRIGGER balance_ledger_no_delete BEFORE DELETE ON balance_ledger BEGIN SELECT RAISE(ABORT, 'balance ledger is immutable'); END;
