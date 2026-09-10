import { env } from "cloudflare:test";
import {
  applyD1Migrations,
  runInDurableObject,
  type D1Migration,
} from "cloudflare:test";
import { beforeEach } from "vitest";
import type { AccountLeaseDO } from "../src/lease";
import type { APIKeyRateLimitDO, UserRateLimitDO } from "../src/rate-limit";

type TestEnv = Env & {
  TEST_MIGRATIONS: D1Migration[];
  TEST_FIXTURE_SQL: string;
};

const testEnv = env as TestEnv;
await applyD1Migrations(testEnv.DB, testEnv.TEST_MIGRATIONS);
let observationVersion = Date.now();

type SchemaTrigger = {
  name: string;
  sql: string;
};

const schemaTriggerRows = await testEnv.DB.prepare(
  "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND sql IS NOT NULL ORDER BY name",
).all<SchemaTrigger>();
const schemaTriggers = schemaTriggerRows.results.map((trigger) => {
  if (!/^[A-Za-z0-9_]+$/.test(trigger.name) || trigger.sql.length === 0) {
    throw new Error("invalid trigger metadata in test schema");
  }
  return trigger;
});

async function resetFixture(): Promise<void> {
  await testEnv.DB.batch(schemaTriggers.map((trigger) =>
    testEnv.DB.prepare(`DROP TRIGGER IF EXISTS ${trigger.name}`)
  ));
  try {
    await testEnv.DB.exec(`
      DELETE FROM email_delivery_witnesses;
      DELETE FROM email_issue_witnesses;
      DELETE FROM email_issue_idempotency;
      DELETE FROM email_runtime_outbox;
      DELETE FROM email_runtime_audit;
      DELETE FROM email_delivery_jobs;
      DELETE FROM email_challenges;
      DELETE FROM email_runtime_batch_guards;
      DELETE FROM payment_idempotency_witnesses;
      DELETE FROM payment_provider_event_dedup;
      DELETE FROM payment_ledger_transactions;
      DELETE FROM payment_audit_events;
      DELETE FROM payment_outbox_events;
      DELETE FROM payment_refund_records;
      DELETE FROM payment_records;
      DELETE FROM payment_batch_guards;
      DELETE FROM settings_runtime_request_witness;
      DELETE FROM settings_runtime_outbox;
      DELETE FROM settings_runtime_audit;
      DELETE FROM settings_runtime_idempotency;
      DELETE FROM settings_runtime_cas_claims;
      DELETE FROM settings_runtime_batch_guards;
      DELETE FROM settings_runtime;
      DELETE FROM oauth_refresh_commit_witnesses;
      DELETE FROM oauth_refresh_invalidation_outbox;
      DELETE FROM oauth_refresh_audit;
      DELETE FROM oauth_refresh_fingerprint_audit;
      DELETE FROM oauth_refresh_attempts;
      DELETE FROM auth_cache_outbox;
      DELETE FROM auth_cache_credential_revisions;
      DELETE FROM auth_cache_entity_revisions;
      DELETE FROM background_job_outbox;
      DELETE FROM background_job_transitions;
      DELETE FROM background_jobs;
      DELETE FROM subscription_operation_effects;
      DELETE FROM subscription_operations;
      DELETE FROM subscription_runtime_guards;
      DELETE FROM user_subscriptions;
      DELETE FROM subscription_plans;
      DELETE FROM outbox_conflicts;
      DELETE FROM usage_events;
      DELETE FROM outbox_events;
      DELETE FROM billing_monetary_ledger;
      DELETE FROM billing_reservation_events;
      DELETE FROM billing_reservations;
      DELETE FROM billing_cas_guards;
      DELETE FROM gateway_requests;
      -- balance_ledger is intentionally immutable; test rows use fresh IDs and
      -- remain as append-only evidence across fixture resets.
      DELETE FROM admin_role_change_audit;
      DELETE FROM management_operations;
      DELETE FROM scheduler_principal_limits;
      DELETE FROM scheduler_account_runtime;
      DELETE FROM account_groups;
      DELETE FROM api_keys;
      DELETE FROM accounts;
      DELETE FROM users;
      DELETE FROM groups;
      DELETE FROM model_aliases;
      DELETE FROM pricing_active_version;
    `);
  } finally {
    await testEnv.DB.batch(schemaTriggers.map((trigger) =>
      testEnv.DB.prepare(trigger.sql)
    ));
  }
  await testEnv.DB.exec(testEnv.TEST_FIXTURE_SQL);
  const accountLease = testEnv.ACCOUNT_LEASE.getByName("account:4001");
  await runInDurableObject(
    accountLease as DurableObjectStub<AccountLeaseDO>,
    async (_instance, state) => {
      state.storage.sql.exec(`
        DELETE FROM rate_admissions;
        DELETE FROM rate_tombstones;
        DELETE FROM rate_identities;
        DELETE FROM rate_finalized;
        DELETE FROM leases;
        DELETE FROM released_leases;
        DELETE FROM lease_admission_identity;
      `);
      await state.storage.deleteAlarm();
    },
  );
  await runInDurableObject(
    testEnv.USER_RATE_LIMIT.getByName("user:1001") as DurableObjectStub<UserRateLimitDO>,
    async (_instance, state) => {
      state.storage.sql.exec(`
        DELETE FROM rate_admissions;
        DELETE FROM rate_tombstones;
        DELETE FROM rate_identities;
        DELETE FROM rate_finalized;
      `);
      await state.storage.deleteAlarm();
    },
  );
  await runInDurableObject(
    testEnv.API_KEY_RATE_LIMIT.getByName("api-key:3001") as DurableObjectStub<APIKeyRateLimitDO>,
    async (_instance, state) => {
      state.storage.sql.exec(`
        DELETE FROM rate_admissions;
        DELETE FROM rate_tombstones;
        DELETE FROM rate_identities;
        DELETE FROM rate_finalized;
      `);
      await state.storage.deleteAlarm();
    },
  );
  const observedAt = Date.now();
  const freshUntil = observedAt + 4 * 60_000;
  await testEnv.DB.prepare("INSERT INTO scheduler_account_runtime(account_id,capabilities_json,capabilities_evidence,capabilities_source,capabilities_observed_at_ms,capabilities_fresh_until_ms,quota_exhausted,quota_remaining_bps,quota_evidence,quota_source,quota_observed_at_ms,quota_fresh_until_ms,version,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind("4001", '{"platforms":["openai"],"accountTypes":["apikey"],"models":["fixture-model"]}', "confirmed", "test.fixture", observedAt, freshUntil, 0, 10000, "confirmed", "test.fixture", observedAt, freshUntil, 1, observedAt)
    .run();
  for (const [scope, principal] of [["account", "4001"], ["user", "1001"], ["api_key", "3001"]]) {
    await testEnv.DB.prepare("INSERT INTO scheduler_principal_limits(scope,principal_id,rpm_limit,evidence,source,observed_at_ms,fresh_until_ms,version,updated_at_ms) VALUES(?,?,100,'confirmed','test.fixture',?,?,1,?)")
      .bind(scope, principal, observedAt, freshUntil, observedAt)
      .run();
  }
  const lease = accountLease;
  for (const [kind, value] of [
    ["health_bps", 10000],
    ["cooldown_until_ms", null],
    ["temporary_until_ms", null],
  ] as const) {
    observationVersion += 1;
    const response = await lease.fetch("https://lease/state/update", {
      method: "POST",
      body: JSON.stringify({
        account_id: "4001",
        kind,
        value,
        evidence: "confirmed",
        source: "test.fixture",
        observed_at_ms: observedAt,
        fresh_until_ms: freshUntil,
        version: observationVersion,
      }),
    });
    if (!response.ok) {
      throw new Error(`failed to seed scheduler observation: ${kind}`);
    }
  }
}

await resetFixture();
beforeEach(resetFixture);
