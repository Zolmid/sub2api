-- D1 is the monetary authority. The Durable Object only serializes calls for
-- one principal; every balance mutation is accompanied by an immutable row.
ALTER TABLE users ADD COLUMN balance_version INTEGER NOT NULL DEFAULT 0
  CHECK(balance_version >= 0 AND balance_version < 9007199254740991);

-- Preserve current group-management behaviour while freezing the exact
-- multiplier selected at admission. Broader group-management UI support is a
-- separate migration.
ALTER TABLE groups ADD COLUMN rate_multiplier_bps TEXT NOT NULL DEFAULT '10000'
  CHECK(length(rate_multiplier_bps) BETWEEN 1 AND 8
    AND rate_multiplier_bps NOT GLOB '*[^0-9]*'
    AND rate_multiplier_bps <> '0'
    AND substr(rate_multiplier_bps,1,1) BETWEEN '1' AND '9');

ALTER TABLE gateway_requests ADD COLUMN pricing_model TEXT;
ALTER TABLE gateway_requests ADD COLUMN pricing_rule_match_kind TEXT;
ALTER TABLE gateway_requests ADD COLUMN rate_multiplier_bps TEXT;

CREATE TABLE billing_reservations (
  request_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  api_key_id TEXT NOT NULL REFERENCES api_keys(id),
  group_id TEXT NOT NULL REFERENCES groups(id),
  account_id TEXT NOT NULL REFERENCES accounts(id),
  lease_id TEXT NOT NULL,
  lease_epoch TEXT NOT NULL,
  owner TEXT NOT NULL,
  model TEXT NOT NULL,
  upstream_model TEXT NOT NULL,
  pricing_version_id TEXT NOT NULL,
  pricing_digest TEXT NOT NULL,
  pricing_model TEXT NOT NULL,
  pricing_rule_pattern TEXT NOT NULL,
  pricing_rule_match_kind TEXT NOT NULL CHECK(pricing_rule_match_kind IN ('exact','family')),
  rate_multiplier_bps TEXT NOT NULL,
  reservation_e8_usd TEXT NOT NULL,
  charged_e8_usd TEXT,
  usage_present INTEGER CHECK(usage_present IS NULL OR usage_present IN (0,1)),
  state TEXT NOT NULL CHECK(state IN ('reserved','started','completed','released','unknown')),
  version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1 AND version < 9007199254740991),
  completion_event_id TEXT,
  completion_payload_hash TEXT,
  completion_outcome TEXT,
  upstream_request_id TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  completed_at TEXT,
  released_at TEXT,
  unknown_at TEXT,
  reconciled_at TEXT,
  CHECK(length(request_id) BETWEEN 1 AND 256),
  CHECK(length(user_id) BETWEEN 1 AND 20 AND user_id NOT GLOB '*[^0-9]*' AND substr(user_id,1,1) BETWEEN '1' AND '9'),
  CHECK(length(api_key_id) BETWEEN 1 AND 20 AND api_key_id NOT GLOB '*[^0-9]*' AND substr(api_key_id,1,1) BETWEEN '1' AND '9'),
  CHECK(length(group_id) BETWEEN 1 AND 20 AND group_id NOT GLOB '*[^0-9]*' AND substr(group_id,1,1) BETWEEN '1' AND '9'),
  CHECK(length(account_id) BETWEEN 1 AND 20 AND account_id NOT GLOB '*[^0-9]*' AND substr(account_id,1,1) BETWEEN '1' AND '9'),
  CHECK(length(lease_id) BETWEEN 1 AND 256),
  CHECK(length(lease_epoch) BETWEEN 1 AND 20 AND lease_epoch NOT GLOB '*[^0-9]*' AND substr(lease_epoch,1,1) BETWEEN '1' AND '9'),
  CHECK(length(owner) BETWEEN 1 AND 256),
  CHECK(length(model) BETWEEN 1 AND 256),
  CHECK(length(upstream_model) BETWEEN 1 AND 256),
  CHECK(length(pricing_version_id) BETWEEN 1 AND 128 AND pricing_version_id NOT GLOB '*[^a-z0-9._:-]*'),
  CHECK(length(pricing_digest)=64 AND pricing_digest NOT GLOB '*[^0-9a-f]*'),
  CHECK(length(pricing_model) BETWEEN 1 AND 256 AND pricing_model NOT GLOB '*[^a-z0-9._:/-]*'),
  CHECK(length(pricing_rule_pattern) BETWEEN 1 AND 257),
  CHECK(length(rate_multiplier_bps) BETWEEN 1 AND 8 AND rate_multiplier_bps NOT GLOB '*[^0-9]*' AND substr(rate_multiplier_bps,1,1) BETWEEN '1' AND '9'),
  CHECK(length(reservation_e8_usd) BETWEEN 1 AND 18 AND reservation_e8_usd NOT GLOB '*[^0-9]*' AND substr(reservation_e8_usd,1,1) BETWEEN '1' AND '9' AND (length(reservation_e8_usd)<18 OR reservation_e8_usd<='900719925474099100')),
  CHECK(charged_e8_usd IS NULL OR (length(charged_e8_usd) BETWEEN 1 AND 18 AND charged_e8_usd NOT GLOB '*[^0-9]*' AND (charged_e8_usd='0' OR substr(charged_e8_usd,1,1) BETWEEN '1' AND '9') AND (length(charged_e8_usd)<18 OR charged_e8_usd<='900719925474099100'))),
  CHECK(completion_payload_hash IS NULL OR (length(completion_payload_hash)=64 AND completion_payload_hash NOT GLOB '*[^0-9a-f]*')),
  CHECK(completion_outcome IS NULL OR completion_outcome IN ('succeeded','failed')),
  CHECK(upstream_request_id IS NULL OR length(upstream_request_id) <= 512)
);
CREATE INDEX billing_reservations_user_state_idx ON billing_reservations(user_id,state,created_at);

-- A zero-row assertion aborts a D1 batch and rolls back every preceding
-- statement, so a CAS miss cannot leave a partial balance mutation.
CREATE TABLE billing_cas_guards (
  guard_id TEXT PRIMARY KEY,
  changed_rows INTEGER NOT NULL CHECK(changed_rows = 1)
);

CREATE TABLE billing_reservation_events (
  operation_id TEXT PRIMARY KEY,
  operation_kind TEXT NOT NULL CHECK(operation_kind IN ('reserve','start','partial_settle','final_settle','release','expire_refund','expire_unknown','reconcile_charge','reconcile_refund')),
  request_id TEXT NOT NULL REFERENCES billing_reservations(request_id),
  user_id TEXT NOT NULL,
  from_state TEXT CHECK(from_state IS NULL OR from_state IN ('reserved','started','completed','released','unknown')),
  to_state TEXT NOT NULL CHECK(to_state IN ('reserved','started','completed','released','unknown')),
  reservation_version INTEGER NOT NULL CHECK(reservation_version >= 1 AND reservation_version < 9007199254740991),
  event_id TEXT,
  payload_hash TEXT,
  outcome TEXT CHECK(outcome IS NULL OR outcome IN ('succeeded','failed')),
  upstream_request_id TEXT,
  evidence_digest TEXT,
  created_at TEXT NOT NULL,
  CHECK(length(operation_id) BETWEEN 1 AND 300),
  CHECK(length(request_id) BETWEEN 1 AND 256),
  CHECK(length(user_id) BETWEEN 1 AND 20 AND user_id NOT GLOB '*[^0-9]*' AND substr(user_id,1,1) BETWEEN '1' AND '9'),
  CHECK(event_id IS NULL OR length(event_id) BETWEEN 1 AND 300),
  CHECK(payload_hash IS NULL OR (length(payload_hash)=64 AND payload_hash NOT GLOB '*[^0-9a-f]*')),
  CHECK(evidence_digest IS NULL OR (length(evidence_digest)=64 AND evidence_digest NOT GLOB '*[^0-9a-f]*')),
  CHECK(upstream_request_id IS NULL OR length(upstream_request_id) <= 512)
);

CREATE TABLE billing_monetary_ledger (
  operation_id TEXT PRIMARY KEY REFERENCES billing_reservation_events(operation_id),
  request_id TEXT NOT NULL REFERENCES billing_reservations(request_id),
  user_id TEXT NOT NULL REFERENCES users(id),
  operation_kind TEXT NOT NULL CHECK(operation_kind IN ('reserve','refund_complete','refund_release','refund_expire','reconcile_charge','reconcile_refund','manual_adjustment')),
  delta_e8_usd TEXT NOT NULL,
  balance_before_e8_usd TEXT NOT NULL,
  balance_after_e8_usd TEXT NOT NULL,
  balance_version_before INTEGER NOT NULL CHECK(balance_version_before >= 0 AND balance_version_before < 9007199254740991),
  balance_version_after INTEGER NOT NULL CHECK(balance_version_after >= 1 AND balance_version_after < 9007199254740991),
  reservation_version INTEGER NOT NULL CHECK(reservation_version >= 1 AND reservation_version < 9007199254740991),
  pricing_version_id TEXT NOT NULL,
  pricing_digest TEXT NOT NULL,
  reason_digest TEXT,
  created_at TEXT NOT NULL,
  CHECK(length(operation_id) BETWEEN 1 AND 300),
  CHECK(length(request_id) BETWEEN 1 AND 256),
  CHECK(length(user_id) BETWEEN 1 AND 20 AND user_id NOT GLOB '*[^0-9]*' AND substr(user_id,1,1) BETWEEN '1' AND '9'),
  CHECK(
    delta_e8_usd='0'
    OR (length(delta_e8_usd) BETWEEN 1 AND 18
      AND delta_e8_usd NOT GLOB '*[^0-9]*'
      AND substr(delta_e8_usd,1,1) BETWEEN '1' AND '9'
      AND (length(delta_e8_usd)<18 OR delta_e8_usd<='900719925474099100'))
    OR (length(delta_e8_usd) BETWEEN 2 AND 19
      AND substr(delta_e8_usd,1,1)='-'
      AND substr(delta_e8_usd,2) NOT GLOB '*[^0-9]*'
      AND substr(delta_e8_usd,2,1) BETWEEN '1' AND '9'
      AND (length(substr(delta_e8_usd,2))<18 OR substr(delta_e8_usd,2)<='900719925474099100'))
  ),
  CHECK(length(balance_before_e8_usd) BETWEEN 1 AND 18 AND balance_before_e8_usd NOT GLOB '*[^0-9]*' AND (length(balance_before_e8_usd)<18 OR balance_before_e8_usd<='900719925474099100')),
  CHECK(length(balance_after_e8_usd) BETWEEN 1 AND 18 AND balance_after_e8_usd NOT GLOB '*[^0-9]*' AND (length(balance_after_e8_usd)<18 OR balance_after_e8_usd<='900719925474099100')),
  CHECK(length(pricing_version_id) BETWEEN 1 AND 128),
  CHECK(length(pricing_digest)=64 AND pricing_digest NOT GLOB '*[^0-9a-f]*'),
  CHECK(reason_digest IS NULL OR (length(reason_digest)=64 AND reason_digest NOT GLOB '*[^0-9a-f]*'))
);
CREATE INDEX billing_monetary_ledger_user_created_idx ON billing_monetary_ledger(user_id,created_at,operation_id);

CREATE TRIGGER billing_reservation_events_no_update BEFORE UPDATE ON billing_reservation_events BEGIN SELECT RAISE(ABORT,'billing reservation event is immutable'); END;
CREATE TRIGGER billing_reservation_events_no_delete BEFORE DELETE ON billing_reservation_events BEGIN SELECT RAISE(ABORT,'billing reservation event is immutable'); END;
CREATE TRIGGER billing_monetary_ledger_no_update BEFORE UPDATE ON billing_monetary_ledger BEGIN SELECT RAISE(ABORT,'billing monetary ledger is immutable'); END;
CREATE TRIGGER billing_monetary_ledger_no_delete BEFORE DELETE ON billing_monetary_ledger BEGIN SELECT RAISE(ABORT,'billing monetary ledger is immutable'); END;
CREATE TRIGGER billing_reservations_no_delete BEFORE DELETE ON billing_reservations BEGIN SELECT RAISE(ABORT,'billing reservation is auditable'); END;
CREATE TRIGGER billing_reservations_identity_immutable BEFORE UPDATE OF request_id,user_id,api_key_id,group_id,account_id,lease_id,lease_epoch,owner,pricing_version_id,pricing_digest,pricing_model,pricing_rule_pattern,pricing_rule_match_kind,rate_multiplier_bps,reservation_e8_usd ON billing_reservations BEGIN SELECT RAISE(ABORT,'billing reservation identity is immutable'); END;

INSERT INTO schema_metadata(key,value) VALUES('cloudflare_billing_reservation_schema_version','2026-09-09.v3');
