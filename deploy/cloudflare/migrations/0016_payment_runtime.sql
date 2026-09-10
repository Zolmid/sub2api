-- Unwired, D1-authoritative E8 USD payment state.  Every externally visible
-- result is snapshotted into an immutable idempotency witness.
CREATE TABLE IF NOT EXISTS payment_records (
  payment_id TEXT PRIMARY KEY NOT NULL CHECK(length(payment_id) BETWEEN 1 AND 96 AND payment_id GLOB '[A-Za-z0-9]*' AND payment_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
  account_id TEXT NOT NULL CHECK(length(account_id) BETWEEN 1 AND 96 AND account_id GLOB '[A-Za-z0-9]*' AND account_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
  amount_e8 TEXT NOT NULL CHECK(amount_e8 GLOB '[1-9]*' AND amount_e8 NOT GLOB '*[^0-9]*' AND (length(amount_e8)<19 OR (length(amount_e8)=19 AND amount_e8<='9223372036854775807'))),
  refunded_e8 TEXT NOT NULL DEFAULT '0' CHECK((refunded_e8='0' OR (refunded_e8 GLOB '[1-9]*' AND refunded_e8 NOT GLOB '*[^0-9]*')) AND (length(refunded_e8)<19 OR (length(refunded_e8)=19 AND refunded_e8<='9223372036854775807'))),
  pending_refund_e8 TEXT NOT NULL DEFAULT '0' CHECK((pending_refund_e8='0' OR (pending_refund_e8 GLOB '[1-9]*' AND pending_refund_e8 NOT GLOB '*[^0-9]*')) AND (length(pending_refund_e8)<19 OR (length(pending_refund_e8)=19 AND pending_refund_e8<='9223372036854775807'))),
  currency TEXT NOT NULL DEFAULT 'USD' CHECK(currency='USD'),
  state TEXT NOT NULL CHECK(state IS NOT NULL AND state IN ('created','authorized','succeeded','failed','manual_review','refunded')),
  version TEXT NOT NULL DEFAULT '1' CHECK(version IS NOT NULL AND version GLOB '[1-9]*' AND version NOT GLOB '*[^0-9]*' AND (length(version)<19 OR (length(version)=19 AND version<='9223372036854775807'))),
  created_at TEXT NOT NULL CHECK(created_at IS NOT NULL AND length(created_at)=24 AND substr(created_at,1,4)>='2020' AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at),
  updated_at TEXT NOT NULL CHECK(updated_at IS NOT NULL AND length(updated_at)=24 AND substr(updated_at,1,4)>='2020' AND strftime('%Y-%m-%dT%H:%M:%fZ',updated_at)=updated_at AND updated_at>=created_at)
);
CREATE TABLE IF NOT EXISTS payment_refund_records (
  refund_id TEXT PRIMARY KEY NOT NULL CHECK(length(refund_id) BETWEEN 1 AND 96 AND refund_id GLOB '[A-Za-z0-9]*' AND refund_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
  payment_id TEXT NOT NULL REFERENCES payment_records(payment_id),
  amount_e8 TEXT NOT NULL CHECK(amount_e8 GLOB '[1-9]*' AND amount_e8 NOT GLOB '*[^0-9]*' AND (length(amount_e8)<19 OR (length(amount_e8)=19 AND amount_e8<='9223372036854775807'))),
  state TEXT NOT NULL CHECK(state IS NOT NULL AND state IN ('created','succeeded','failed','manual_review')),
  version TEXT NOT NULL DEFAULT '1' CHECK(version IS NOT NULL AND version GLOB '[1-9]*' AND version NOT GLOB '*[^0-9]*' AND (length(version)<19 OR (length(version)=19 AND version<='9223372036854775807'))),
  created_at TEXT NOT NULL CHECK(created_at IS NOT NULL AND length(created_at)=24 AND substr(created_at,1,4)>='2020' AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at),
  updated_at TEXT NOT NULL CHECK(updated_at IS NOT NULL AND length(updated_at)=24 AND substr(updated_at,1,4)>='2020' AND strftime('%Y-%m-%dT%H:%M:%fZ',updated_at)=updated_at AND updated_at>=created_at)
);
CREATE TABLE IF NOT EXISTS payment_ledger_transactions (
  ledger_id TEXT PRIMARY KEY NOT NULL CHECK(length(ledger_id)=32 AND ledger_id NOT GLOB '*[^0-9a-f]*'),
  payment_id TEXT NOT NULL REFERENCES payment_records(payment_id), refund_id TEXT REFERENCES payment_refund_records(refund_id),
  kind TEXT NOT NULL CHECK(kind IN ('payment_settlement','refund_settlement')),
  debit_account TEXT NOT NULL CHECK(length(debit_account) BETWEEN 1 AND 96), credit_account TEXT NOT NULL CHECK(length(credit_account) BETWEEN 1 AND 96 AND debit_account<>credit_account),
  amount_e8 TEXT NOT NULL CHECK(amount_e8 GLOB '[1-9]*' AND amount_e8 NOT GLOB '*[^0-9]*' AND (length(amount_e8)<19 OR (length(amount_e8)=19 AND amount_e8<='9223372036854775807'))),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at),
  UNIQUE(payment_id,refund_id,kind)
);
-- SQLite considers NULL values distinct in a multi-column UNIQUE constraint.
-- Payment settlements therefore need a separate partial key: they always have
-- no refund, and a payment may settle only once.
CREATE UNIQUE INDEX IF NOT EXISTS payment_ledger_payment_settlement_once
  ON payment_ledger_transactions(payment_id,kind)
  WHERE kind='payment_settlement' AND refund_id IS NULL;
CREATE TABLE IF NOT EXISTS payment_audit_events (
  event_id TEXT PRIMARY KEY NOT NULL CHECK(length(event_id)=32 AND event_id NOT GLOB '*[^0-9a-f]*'),
  payment_id TEXT NOT NULL REFERENCES payment_records(payment_id), refund_id TEXT REFERENCES payment_refund_records(refund_id),
  action TEXT NOT NULL CHECK(action IN ('payment_created','payment_transitioned','refund_created','refund_transitioned','refund_succeeded','provider_event_accepted')),
  previous_state TEXT CHECK(previous_state IS NULL OR previous_state IN ('created','authorized','succeeded','failed','manual_review','refunded')),
  next_state TEXT NOT NULL CHECK(next_state IN ('created','authorized','succeeded','failed','manual_review','refunded')),
  version TEXT NOT NULL CHECK(version IS NOT NULL AND version GLOB '[1-9]*' AND version NOT GLOB '*[^0-9]*'),
  semantic_digest TEXT NOT NULL CHECK(length(semantic_digest)=64 AND semantic_digest NOT GLOB '*[^0-9a-f]*'),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at)
);
CREATE TABLE IF NOT EXISTS payment_outbox_events (
  event_id TEXT PRIMARY KEY NOT NULL CHECK(length(event_id)=32 AND event_id NOT GLOB '*[^0-9a-f]*'),
  payment_id TEXT NOT NULL REFERENCES payment_records(payment_id), refund_id TEXT REFERENCES payment_refund_records(refund_id),
  topic TEXT NOT NULL CHECK(topic IN ('payment.changed','refund.changed')), semantic_digest TEXT NOT NULL CHECK(length(semantic_digest)=64 AND semantic_digest NOT GLOB '*[^0-9a-f]*'),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at)
);
CREATE TABLE IF NOT EXISTS payment_idempotency_witnesses (
  operation TEXT NOT NULL CHECK(operation IN ('create','transition','refund','refund_create','refund_transition','provider_event')),
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128 AND idempotency_key GLOB '[A-Za-z0-9]*' AND idempotency_key NOT GLOB '*[^A-Za-z0-9._:-]*'),
  semantic_digest TEXT NOT NULL CHECK(length(semantic_digest)=64 AND semantic_digest NOT GLOB '*[^0-9a-f]*'),
  payment_id TEXT NOT NULL REFERENCES payment_records(payment_id), refund_id TEXT REFERENCES payment_refund_records(refund_id),
  snapshot_json TEXT NOT NULL CHECK(length(snapshot_json) BETWEEN 2 AND 16384),
  result_digest TEXT NOT NULL CHECK(length(result_digest)=64 AND result_digest NOT GLOB '*[^0-9a-f]*'),
  audit_event_id TEXT NOT NULL REFERENCES payment_audit_events(event_id), outbox_event_id TEXT NOT NULL REFERENCES payment_outbox_events(event_id),
  created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at),
  PRIMARY KEY(operation,idempotency_key)
);
CREATE TABLE IF NOT EXISTS payment_provider_event_dedup (
  provider_event_id TEXT PRIMARY KEY NOT NULL CHECK(length(provider_event_id) BETWEEN 1 AND 128 AND provider_event_id GLOB '[A-Za-z0-9]*' AND provider_event_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
  semantic_digest TEXT NOT NULL CHECK(length(semantic_digest)=64 AND semantic_digest NOT GLOB '*[^0-9a-f]*'),
  payment_id TEXT NOT NULL REFERENCES payment_records(payment_id), created_at TEXT NOT NULL CHECK(length(created_at)=24 AND strftime('%Y-%m-%dT%H:%M:%fZ',created_at)=created_at)
);
CREATE TABLE IF NOT EXISTS payment_batch_guards (guard_id TEXT PRIMARY KEY NOT NULL CHECK(length(guard_id)=32 AND guard_id NOT GLOB '*[^0-9a-f]*'), matched INTEGER NOT NULL CHECK(matched=1));
CREATE TRIGGER IF NOT EXISTS payment_identity_immutable BEFORE UPDATE OF payment_id,account_id,amount_e8,currency,created_at ON payment_records BEGIN SELECT RAISE(ABORT,'payment identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS refund_identity_immutable BEFORE UPDATE OF refund_id,payment_id,amount_e8,created_at ON payment_refund_records BEGIN SELECT RAISE(ABORT,'refund identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS payment_version_overflow BEFORE UPDATE OF version ON payment_records WHEN OLD.version='9223372036854775807' BEGIN SELECT RAISE(ABORT,'payment version exhausted'); END;
CREATE TRIGGER IF NOT EXISTS refund_version_overflow BEFORE UPDATE OF version ON payment_refund_records WHEN OLD.version='9223372036854775807' BEGIN SELECT RAISE(ABORT,'refund version exhausted'); END;
CREATE TRIGGER IF NOT EXISTS payment_legal_edge BEFORE UPDATE OF state ON payment_records WHEN NOT (OLD.state=NEW.state OR (OLD.state='created' AND NEW.state IN ('authorized','succeeded','failed','manual_review')) OR (OLD.state='authorized' AND NEW.state IN ('succeeded','failed','manual_review')) OR (OLD.state='manual_review' AND NEW.state IN ('authorized','succeeded','failed')) OR (OLD.state='succeeded' AND NEW.state='refunded')) BEGIN SELECT RAISE(ABORT,'illegal payment transition'); END;
CREATE TRIGGER IF NOT EXISTS refund_legal_edge BEFORE UPDATE OF state ON payment_refund_records WHEN NOT ((OLD.state='created' AND NEW.state IN ('succeeded','failed','manual_review')) OR (OLD.state='manual_review' AND NEW.state IN ('succeeded','failed'))) BEGIN SELECT RAISE(ABORT,'illegal refund transition'); END;
CREATE TRIGGER IF NOT EXISTS payment_ledger_kind_refund_link BEFORE INSERT ON payment_ledger_transactions WHEN (NEW.kind='payment_settlement' AND NEW.refund_id IS NOT NULL) OR (NEW.kind='refund_settlement' AND (NEW.refund_id IS NULL OR NOT EXISTS(SELECT 1 FROM payment_refund_records WHERE refund_id=NEW.refund_id AND payment_id=NEW.payment_id))) BEGIN SELECT RAISE(ABORT,'payment ledger kind/refund linkage is invalid'); END;
CREATE TRIGGER IF NOT EXISTS payment_ledger_immutable_update BEFORE UPDATE ON payment_ledger_transactions BEGIN SELECT RAISE(ABORT,'payment ledger is immutable'); END;
CREATE TRIGGER IF NOT EXISTS payment_ledger_immutable_delete BEFORE DELETE ON payment_ledger_transactions BEGIN SELECT RAISE(ABORT,'payment ledger is immutable'); END;
CREATE TRIGGER IF NOT EXISTS payment_audit_immutable_update BEFORE UPDATE ON payment_audit_events BEGIN SELECT RAISE(ABORT,'payment audit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS payment_audit_immutable_delete BEFORE DELETE ON payment_audit_events BEGIN SELECT RAISE(ABORT,'payment audit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS payment_outbox_immutable_update BEFORE UPDATE ON payment_outbox_events BEGIN SELECT RAISE(ABORT,'payment outbox is immutable'); END;
CREATE TRIGGER IF NOT EXISTS payment_outbox_immutable_delete BEFORE DELETE ON payment_outbox_events BEGIN SELECT RAISE(ABORT,'payment outbox is immutable'); END;
CREATE TRIGGER IF NOT EXISTS payment_witness_immutable_update BEFORE UPDATE ON payment_idempotency_witnesses BEGIN SELECT RAISE(ABORT,'payment witness is immutable'); END;
CREATE TRIGGER IF NOT EXISTS payment_witness_immutable_delete BEFORE DELETE ON payment_idempotency_witnesses BEGIN SELECT RAISE(ABORT,'payment witness is immutable'); END;
CREATE TRIGGER IF NOT EXISTS payment_provider_dedup_immutable_update BEFORE UPDATE ON payment_provider_event_dedup BEGIN SELECT RAISE(ABORT,'provider dedup is immutable'); END;
CREATE TRIGGER IF NOT EXISTS payment_provider_dedup_immutable_delete BEFORE DELETE ON payment_provider_event_dedup BEGIN SELECT RAISE(ABORT,'provider dedup is immutable'); END;
