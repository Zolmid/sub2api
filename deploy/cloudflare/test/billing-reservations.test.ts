import {
  env,
  runDurableObjectAlarm,
  runInDurableObject,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { controlPlane, recoverStaleAdmissions } from "../src/control-plane";
import worker from "../src/index";
import type { BillingIdentity, ReserveBillingInput } from "../src/billing";
import {
  BRIDGE_VERSION,
  USAGE_EVENT_TYPE,
  USAGE_SCHEMA_VERSION,
  type Completion,
} from "../src/contracts";
import { pricingDigest, type PricingRule } from "../src/pricing";

const OWNER = "billing-test-container";
const CAP = "100000000000";

type Admission = {
  account: { id: string };
  upstream_model: string;
  price_card: {
    version_id: string;
    digest: string;
    max_reservation_e8_usd: string;
    rule: { model_pattern: string };
  };
  lease: {
    account_id: string;
    request_id: string;
    lease_id: string;
    owner: string;
    epoch: string;
    expires_at: string;
  };
};

type Reservation = {
  state: "reserved" | "started" | "completed" | "released" | "unknown";
  charged_e8_usd: string | null;
  usage_present: number | null;
  version: number;
};

const request = (path: string, body: object, owner = OWNER) =>
  new Request(`http://sub2api.internal${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Sub2API-Bridge-Version": BRIDGE_VERSION,
      "X-Sub2API-Container-Id": owner,
    },
    body: JSON.stringify(body),
  });

const call = (path: string, body: object, targetEnv: Env = env, owner = OWNER) =>
  controlPlane(request(path, body, owner), targetEnv);

async function admit(requestID: string, targetEnv: Env = env): Promise<Admission> {
  const response = await call("/v1/requests/admit", {
    request_id: requestID,
    api_key_id: "3001",
    group_id: "2001",
    model: "fixture-model",
    lease_ttl_seconds: 30,
  }, targetEnv);
  if (response.status !== 200) {
    const account = targetEnv.ACCOUNT_LEASE.getByName("account:4001");
    const [body, lease, accountRate, userRate, keyRate] = await Promise.all([
      response.clone().text(),
      account.fetch("https://lease/inspect", {
        method: "POST", body: JSON.stringify({ account_id: "4001" }),
      }).then((value) => value.text()),
      account.fetch("https://lease/rate/inspect", {
        method: "POST", body: JSON.stringify({ scope: "account", principal_id: "4001", rpm_limit: 100 }),
      }).then((value) => value.text()),
      targetEnv.USER_RATE_LIMIT.getByName("user:1001").fetch("https://rate/rate/inspect", {
        method: "POST", body: JSON.stringify({ scope: "user", principal_id: "1001", rpm_limit: 100 }),
      }).then((value) => value.text()),
      targetEnv.API_KEY_RATE_LIMIT.getByName("api-key:3001").fetch("https://rate/rate/inspect", {
        method: "POST", body: JSON.stringify({ scope: "api_key", principal_id: "3001", rpm_limit: 100 }),
      }).then((value) => value.text()),
    ]);
    expect(response.status, `${body}; lease=${lease}; account=${accountRate}; user=${userRate}; key=${keyRate}`).toBe(200);
  }
  return response.json<Admission>();
}

const start = (admission: Admission, overrides: Record<string, unknown> = {}) =>
  call("/v1/requests/start", {
    request_id: admission.lease.request_id,
    api_key_id: "3001",
    account_id: admission.account.id,
    lease_id: admission.lease.lease_id,
    lease_epoch: admission.lease.epoch,
    model: "fixture-model",
    upstream_model: admission.upstream_model,
    ...overrides,
  }, env, admission.lease.owner);

const release = (admission: Admission) =>
  call("/v1/leases/release", admission.lease, env, admission.lease.owner);

const completion = (
  admission: Admission,
  usageState: "confirmed" | "unknown",
  counters: Partial<Pick<Completion, "input_tokens" | "output_tokens" | "cache_read_tokens">> = {},
): Completion => ({
  schema_version: USAGE_SCHEMA_VERSION,
  event_type: USAGE_EVENT_TYPE,
  event_id: `${admission.lease.request_id}:usage:v2`,
  request_id: admission.lease.request_id,
  api_key_id: "3001",
  account_id: admission.account.id,
  lease_id: admission.lease.lease_id,
  lease_epoch: admission.lease.epoch,
  outcome: "succeeded",
  usage_state: usageState,
  input_tokens: "0",
  image_input_tokens: "0",
  output_tokens: "0",
  image_output_tokens: "0",
  cache_creation_tokens: "0",
  cache_creation_5m_tokens: "0",
  cache_creation_1h_tokens: "0",
  cache_read_tokens: "0",
  service_tier: "",
  reasoning_effort: "",
  model: "fixture-model",
  upstream_model: admission.upstream_model,
  upstream_request_id: "billing-test-upstream",
  duration_ms: "1",
  ...counters,
});

const complete = (
  admission: Admission,
  payload: Completion,
  targetEnv: Env = env,
) => call(
  "/v1/requests/complete",
  payload,
  targetEnv,
  admission.lease.owner,
);

const balance = () =>
  env.DB.prepare("SELECT balance_e8_usd FROM users WHERE id='1001'")
    .first<string>("balance_e8_usd");

const reservation = (requestID: string) =>
  env.DB.prepare("SELECT state,charged_e8_usd,usage_present,version FROM billing_reservations WHERE request_id=?")
    .bind(requestID).first<Reservation>();

async function schedulerState(): Promise<{ inFlight: number; rateUsed: number[] }> {
  const account = env.ACCOUNT_LEASE.getByName("account:4001");
  const [lease, accountRate, userRate, keyRate] = await Promise.all([
    account.fetch("https://lease/inspect", {
      method: "POST", body: JSON.stringify({ account_id: "4001" }),
    }).then((response) => response.json<{ in_flight: number }>()),
    account.fetch("https://lease/rate/inspect", {
      method: "POST", body: JSON.stringify({ scope: "account", principal_id: "4001", rpm_limit: 100 }),
    }).then((response) => response.json<{ used: number }>()),
    env.USER_RATE_LIMIT.getByName("user:1001").fetch("https://rate/rate/inspect", {
      method: "POST", body: JSON.stringify({ scope: "user", principal_id: "1001", rpm_limit: 100 }),
    }).then((response) => response.json<{ used: number }>()),
    env.API_KEY_RATE_LIMIT.getByName("api-key:3001").fetch("https://rate/rate/inspect", {
      method: "POST", body: JSON.stringify({ scope: "api_key", principal_id: "3001", rpm_limit: 100 }),
    }).then((response) => response.json<{ used: number }>()),
  ]);
  return {
    inFlight: lease.in_flight,
    rateUsed: [accountRate.used, userRate.used, keyRate.used],
  };
}

async function naturallyCloseSchedulerResources(admission: Admission): Promise<void> {
  const expiredAt = Date.now() - 1;
  const nextAlarm = Date.now() + 60_000;
  const account = env.ACCOUNT_LEASE.getByName(`account:${admission.account.id}`);
  const user = env.USER_RATE_LIMIT.getByName("user:1001");
  const key = env.API_KEY_RATE_LIMIT.getByName("api-key:3001");
  await runInDurableObject(account, async (_instance, state) => {
    state.storage.sql.exec("UPDATE leases SET expires_at=? WHERE lease_id=?", expiredAt, admission.lease.lease_id);
    state.storage.sql.exec(
      "UPDATE rate_admissions SET window_end_ms=?,reservation_expires_at_ms=? WHERE admission_id=?",
      expiredAt,
      expiredAt,
      admission.lease.request_id,
    );
    await state.storage.setAlarm(nextAlarm);
  });
  for (const stub of [user, key]) {
    await runInDurableObject(stub, async (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE rate_admissions SET window_end_ms=?,reservation_expires_at_ms=? WHERE admission_id=?",
        expiredAt,
        expiredAt,
        admission.lease.request_id,
      );
      await state.storage.setAlarm(nextAlarm);
    });
  }
  await Promise.all([account, user, key].map((stub) => runDurableObjectAlarm(stub)));
}

async function cloneFixturePricing(versionID: string): Promise<string> {
  const source = await env.DB.prepare("SELECT * FROM pricing_rules WHERE version_id='fixture-v1'")
    .all<PricingRule>();
  const rules = source.results.map((rule) => ({ ...rule, version_id: versionID }));
  const digest = await pricingDigest(versionID, CAP, rules);
  await env.DB.prepare(
    "INSERT INTO pricing_versions(version_id,digest,max_reservation_e8_usd,created_at) VALUES(?,?,?,?)",
  ).bind(versionID, digest, CAP, new Date().toISOString()).run();
  for (const rule of rules) {
    await env.DB.prepare(`INSERT INTO pricing_rules(
      version_id,model_pattern,match_kind,input_e8_per_million,output_e8_per_million,
      cache_read_e8_per_million,cache_write_e8_per_million,cache_write_5m_e8_per_million,
      cache_write_1h_e8_per_million,image_input_e8_per_million,image_output_e8_per_million,
      priority_input_e8_per_million,priority_output_e8_per_million,
      priority_cache_read_e8_per_million,priority_cache_write_e8_per_million,
      fast_multiplier_bps,flex_multiplier_bps,max_reasoning_effort_multiplier_bps
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
      rule.version_id,
      rule.model_pattern,
      rule.match_kind,
      rule.input_e8_per_million,
      rule.output_e8_per_million,
      rule.cache_read_e8_per_million,
      rule.cache_write_e8_per_million,
      rule.cache_write_5m_e8_per_million,
      rule.cache_write_1h_e8_per_million,
      rule.image_input_e8_per_million,
      rule.image_output_e8_per_million,
      rule.priority_input_e8_per_million,
      rule.priority_output_e8_per_million,
      rule.priority_cache_read_e8_per_million,
      rule.priority_cache_write_e8_per_million,
      rule.fast_multiplier_bps,
      rule.flex_multiplier_bps,
      rule.max_reasoning_effort_multiplier_bps,
    ).run();
  }
  return digest;
}

const activatePricing = (versionID: string) =>
  env.DB.prepare(
    "UPDATE pricing_active_version SET version_id=?,activated_at=? WHERE singleton=1",
  ).bind(versionID, new Date().toISOString()).run();

function overrideBillingReserve(beforeReserve: () => Promise<void>): Env {
  let intercepted = false;
  const namespace = new Proxy(env.BILLING_PRINCIPAL, {
    get(target, property, receiver) {
      if (property !== "getByName") return Reflect.get(target, property, receiver);
      return (...args: Parameters<typeof target.getByName>) => {
        const stub = target.getByName(...args);
        return new Proxy(stub, {
          get(stubTarget, stubProperty, stubReceiver) {
            if (stubProperty !== "reserve") {
              return Reflect.get(stubTarget, stubProperty, stubReceiver);
            }
            return async (input: Parameters<typeof stub.reserve>[0]) => {
              if (!intercepted) {
                intercepted = true;
                await beforeReserve();
              }
              return stub.reserve(input);
            };
          },
        });
      };
    },
  });
  return new Proxy(env, {
    get(target, property, receiver) {
      return property === "BILLING_PRINCIPAL"
        ? namespace
        : Reflect.get(target, property, receiver);
    },
  });
}

function overrideLeaseReleaseFailures(count: number): Env {
  let remaining = count;
  const namespace = new Proxy(env.ACCOUNT_LEASE, {
    get(target, property, receiver) {
      if (property !== "get") {
        const value = Reflect.get(target, property, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      }
      return (...args: Parameters<typeof target.get>) => {
        const stub = target.get(...args);
        return new Proxy(stub, {
          get(stubTarget, stubProperty, stubReceiver) {
            if (stubProperty !== "fetch") {
              return Reflect.get(stubTarget, stubProperty, stubReceiver);
            }
            return async (...fetchArgs: Parameters<typeof stub.fetch>) => {
              const [input] = fetchArgs;
              if (
                remaining > 0 &&
                typeof input === "string" &&
                new URL(input).pathname === "/release"
              ) {
                remaining -= 1;
                return new Response(null, { status: 503 });
              }
              return stub.fetch(...fetchArgs);
            };
          },
        });
      };
    },
  });
  return new Proxy(env, {
    get(target, property, receiver) {
      return property === "ACCOUNT_LEASE"
        ? namespace
        : Reflect.get(target, property, receiver);
    },
  });
}

    describe("D1 billing reservations", () => {
  it("installs an exact, versioned, immutable reservation ledger", async () => {
    expect(await env.DB.prepare(
      "SELECT value FROM schema_metadata WHERE key='cloudflare_billing_reservation_schema_version'",
    ).first("value")).toBe("2026-09-09.v3");

    const columns = await env.DB.prepare("PRAGMA table_info('billing_reservations')")
      .all<{ name: string; type: string }>();
    expect(columns.results.find((column) => column.name === "reservation_e8_usd")?.type).toBe("TEXT");
    expect(columns.results.find((column) => column.name === "charged_e8_usd")?.type).toBe("TEXT");
    expect(columns.results.find((column) => column.name === "usage_present")?.type).toBe("INTEGER");
    expect(columns.results.find((column) => column.name === "version")?.type).toBe("INTEGER");
    const definitions = await env.DB.prepare(
      "SELECT sql FROM sqlite_master WHERE name IN ('billing_reservations','billing_reservation_events')",
    ).all<{ sql: string }>();
    expect(definitions.results.map((row) => row.sql).join("\n")).not.toMatch(/\b(?:REAL|FLOAT)\b/i);

    const admission = await admit("billing-schema-audit");
    const event = await env.DB.prepare(
      `SELECT operation_kind,request_id,user_id,to_state,reservation_version
       FROM billing_reservation_events WHERE operation_id=?`,
    ).bind("billing-schema-audit:reserve").first<Record<string, unknown>>();
    expect(event).toMatchObject({
      operation_kind: "reserve",
      request_id: admission.lease.request_id,
      user_id: "1001",
      to_state: "reserved",
      reservation_version: 1,
    });
    await expect(env.DB.prepare(
      "UPDATE billing_reservation_events SET owner='tampered' WHERE operation_id=?",
    ).bind("billing-schema-audit:reserve").run()).rejects.toThrow();
    await expect(env.DB.prepare(
      "DELETE FROM billing_reservation_events WHERE operation_id=?",
    ).bind("billing-schema-audit:reserve").run()).rejects.toThrow();
    await expect(env.DB.prepare(
      "UPDATE billing_reservations SET lease_id='tampered' WHERE request_id=?",
    ).bind("billing-schema-audit").run()).rejects.toThrow();
    await expect(env.DB.prepare(
      "DELETE FROM billing_reservations WHERE request_id=?",
    ).bind("billing-schema-audit").run()).rejects.toThrow();
    expect((await release(admission)).status).toBe(200);
  });

  it("reserves exactly once and releases only an unstarted reservation", async () => {
    const admission = await admit("billing-release-replay");
    expect(await balance()).toBe("0");
    expect(await reservation(admission.lease.request_id)).toEqual({
      state: "reserved",
      charged_e8_usd: null,
      usage_present: null,
      version: 1,
    });

    const persisted = await env.DB.prepare(
      `SELECT request_id,user_id,api_key_id,group_id,account_id,lease_id,
              lease_epoch,owner,model,upstream_model,pricing_version_id,
              pricing_digest,pricing_model,pricing_rule_pattern,
              pricing_rule_match_kind,rate_multiplier_bps,reservation_e8_usd
       FROM billing_reservations WHERE request_id=?`,
    ).bind(admission.lease.request_id).first<BillingIdentity>();
    expect(persisted).not.toBeNull();
    const replayInput: ReserveBillingInput = {
      ...persisted!,
      operation_id: "billing-release-replay:reserve",
      model: "fixture-model",
      upstream_model: admission.upstream_model,
    };
    const directReplay = await env.BILLING_PRINCIPAL.getByName("user:1001").reserve(replayInput);
    expect(directReplay).toEqual({ kind: "ok", state: "reserved", replayed: true });

    const duplicate = await admit("billing-release-replay");
    expect(duplicate.lease.lease_id).toBe(admission.lease.lease_id);
    expect(await env.DB.prepare(
      "SELECT count(*) count FROM billing_reservation_events WHERE request_id=?",
    ).bind(admission.lease.request_id).first("count")).toBe(1);
    expect(await balance()).toBe("0");

    expect((await release(admission)).status).toBe(200);
    expect((await release(admission)).status).toBe(200);
    expect(await reservation(admission.lease.request_id)).toMatchObject({
      state: "released",
      charged_e8_usd: null,
      usage_present: null,
      version: 2,
    });
    expect(await balance()).toBe(CAP);
    expect((await start(admission)).status).toBe(409);
  });

  it("treats present all-zero usage as confirmed zero", async () => {
    const admission = await admit("billing-zero-usage");
    expect((await start(admission)).status).toBe(204);
    expect((await start(admission)).status).toBe(204);
    const payload = completion(admission, "confirmed");
    expect((await complete(admission, payload)).status).toBe(204);
    expect((await complete(admission, payload)).status).toBe(204);
    expect((await call(
      "/v1/requests/complete",
      payload,
      env,
      "different-container",
    )).status).toBe(409);
    expect(await reservation(admission.lease.request_id)).toEqual({
      state: "completed",
      charged_e8_usd: "0",
      usage_present: 1,
      version: 3,
    });
    expect(await balance()).toBe(CAP);
    expect(await env.DB.prepare(
      "SELECT count(*) count FROM billing_reservation_events WHERE request_id=?",
    ).bind(admission.lease.request_id).first("count")).toBe(3);
    expect((await release(admission)).status).toBe(200);
    expect(await balance()).toBe(CAP);
  });

  it("acknowledges committed billing while scheduled recovery finishes cleanup", async () => {
    const admission = await admit("billing-post-commit-cleanup");
    expect((await start(admission)).status).toBe(204);
    const payload = completion(admission, "confirmed", {
      input_tokens: "1",
      output_tokens: "1",
    });

    const response = await complete(
      admission,
      payload,
      overrideLeaseReleaseFailures(2),
    );
    expect(response.status, await response.clone().text()).toBe(204);
    expect(await reservation(admission.lease.request_id)).toMatchObject({
      state: "completed",
      usage_present: 1,
    });
    expect(await env.DB.prepare(
      `SELECT scheduler_release_state,scheduler_release_attempts
       FROM billing_reservations WHERE request_id=?`,
    ).bind(admission.lease.request_id).first()).toEqual({
      scheduler_release_state: "pending",
      scheduler_release_attempts: 1,
    });
    expect(await env.DB.prepare(
      "SELECT state FROM outbox_events WHERE event_id=?",
    ).bind(payload.event_id).first("state")).toBe("published");

    await recoverStaleAdmissions(env);
    expect(await env.DB.prepare(
      `SELECT scheduler_release_state,scheduler_release_attempts
       FROM billing_reservations WHERE request_id=?`,
    ).bind(admission.lease.request_id).first()).toEqual({
      scheduler_release_state: "released",
      scheduler_release_attempts: 2,
    });
    expect(await schedulerState()).toEqual({
      inFlight: 0,
      rateUsed: [1, 1, 1],
    });
    expect((await complete(admission, payload)).status).toBe(204);
    expect(await env.DB.prepare(
      "SELECT scheduler_release_attempts FROM billing_reservations WHERE request_id=?",
    ).bind(admission.lease.request_id).first("scheduler_release_attempts"))
      .toBe(2);
  });

  it("moves absent usage and started release to unknown without refund", async () => {
    const absent = await admit("billing-absent-usage");
    expect((await start(absent)).status).toBe(204);
    expect((await complete(absent, completion(absent, "unknown"))).status).toBe(204);
    expect(await reservation(absent.lease.request_id)).toMatchObject({
      state: "unknown",
      charged_e8_usd: null,
      usage_present: 0,
    });
    expect(await balance()).toBe("0");
    expect((await release(absent)).status).toBe(200);
    expect(await balance()).toBe("0");

    await env.DB.prepare(
      "UPDATE users SET balance_e8_usd=?,balance_version=balance_version+1 WHERE id='1001'",
    ).bind(CAP).run();
    const releasedAfterStart = await admit("billing-started-release");
    expect((await start(releasedAfterStart)).status).toBe(204);
    expect((await release(releasedAfterStart)).status).toBe(200);
    expect(await reservation(releasedAfterStart.lease.request_id)).toMatchObject({
      state: "unknown",
      charged_e8_usd: null,
      usage_present: 0,
    });
    expect(await balance()).toBe("0");
  });

  it("rejects completion before start without fabricating a terminal state", async () => {
    const admission = await admit("billing-complete-before-start");
    const payload = completion(admission, "confirmed", { input_tokens: "1" });
    expect((await complete(admission, payload)).status).toBe(409);
    expect(await reservation(admission.lease.request_id)).toMatchObject({ state: "reserved", version: 1 });
    expect(await env.DB.prepare(
      "SELECT count(*) count FROM outbox_events WHERE request_id=?",
    ).bind(admission.lease.request_id).first("count")).toBe(0);
    expect((await release(admission)).status).toBe(200);
    expect(await balance()).toBe(CAP);
  });

  it("records over-cap present usage as unknown and replays it safely", async () => {
    const admission = await admit("billing-over-cap");
    expect((await start(admission)).status).toBe(204);
    const payload = completion(admission, "confirmed", {
      input_tokens: "99999999999999999999",
      output_tokens: "0",
      cache_read_tokens: "0",
    });
    const firstCompletion = await complete(admission, payload);
    expect(firstCompletion.status, await firstCompletion.clone().text()).toBe(204);
    expect((await complete(admission, payload)).status).toBe(204);
    const row = await reservation(admission.lease.request_id);
    expect(row?.state).toBe("unknown");
    expect(row?.usage_present).toBe(0);
    expect(row?.charged_e8_usd).toBeNull();
    const outboxPayload = await env.DB.prepare(
      "SELECT payload_json FROM outbox_events WHERE request_id=?",
    ).bind(admission.lease.request_id).first<string>("payload_json");
    expect(JSON.parse(outboxPayload ?? "{}")).toMatchObject({
      input_tokens: "99999999999999999999",
      usage_state: "confirmed",
    });
    expect(await balance()).toBe("0");
    expect((await release(admission)).status).toBe(200);
    expect(await balance()).toBe("0");
  });

  it("recovers reserved orphans in deterministic bounded batches without double refunds", async () => {
    const count = 26;
    const total = (BigInt(CAP) * BigInt(count)).toString();
    await env.DB.prepare(
      "UPDATE accounts SET max_concurrency=? WHERE id='4001'",
    ).bind(count).run();
    await env.DB.prepare(
      "UPDATE users SET balance_e8_usd=?,balance_version=balance_version+1 WHERE id='1001'",
    ).bind(total).run();
    for (let index = 0; index < count; index += 1) {
      await admit(`billing-recovery-${String(index).padStart(2, "0")}`);
    }
    const recoveryTime = Date.now();
    const staleAt = new Date(recoveryTime - 20 * 60_000).toISOString();
    await env.DB.prepare(
      "UPDATE billing_reservations SET created_at=? WHERE request_id LIKE 'billing-recovery-%'",
    ).bind(staleAt).run();

    await recoverStaleAdmissions(env, recoveryTime);
    const remaining = await env.DB.prepare(
      "SELECT request_id FROM billing_reservations WHERE state='reserved' ORDER BY request_id",
    ).all<{ request_id: string }>();
    expect(remaining.results).toEqual([{ request_id: "billing-recovery-25" }]);
    expect(await balance()).toBe((BigInt(CAP) * BigInt(count - 1)).toString());
    expect(await schedulerState()).toEqual({ inFlight: 1, rateUsed: [1, 1, 1] });

    await recoverStaleAdmissions(env, recoveryTime);
    await recoverStaleAdmissions(env, recoveryTime);
    expect(await env.DB.prepare(
      "SELECT count(*) count FROM billing_reservations WHERE state='released'",
    ).first("count")).toBe(count);
    expect(await env.DB.prepare(
      "SELECT count(*) count FROM billing_reservation_events WHERE operation_kind='expire_refund'",
    ).first("count")).toBe(count);
    expect(await env.DB.prepare(
      "SELECT count(*) count FROM billing_monetary_ledger WHERE operation_kind='refund_expire'",
    ).first("count")).toBe(count);
    expect(await balance()).toBe(total);
    expect(await schedulerState()).toEqual({ inFlight: 0, rateUsed: [0, 0, 0] });
  }, 15_000);

  it("finishes stale-admission recovery after its lease and RPM records naturally close", async () => {
    const admission = await admit("billing-recovery-after-natural-close");
    await naturallyCloseSchedulerResources(admission);
    const recoveryTime = Date.now();
    await env.DB.prepare(
      "UPDATE billing_reservations SET created_at=? WHERE request_id=?",
    ).bind(
      new Date(recoveryTime - 20 * 60_000).toISOString(),
      admission.lease.request_id,
    ).run();

    await expect(
      recoverStaleAdmissions(overrideLeaseReleaseFailures(2), recoveryTime),
    ).rejects.toThrow("scheduler admission recovery incomplete: 1");
    expect(await reservation(admission.lease.request_id)).toMatchObject({
      state: "released",
      version: 2,
    });
    await recoverStaleAdmissions(env, recoveryTime);
    expect(await reservation(admission.lease.request_id)).toMatchObject({
      state: "released",
      version: 2,
    });
    expect(await env.DB.prepare(
      "SELECT count(*) count FROM billing_reservation_events WHERE request_id=? AND operation_kind='expire_refund'",
    ).bind(admission.lease.request_id).first("count")).toBe(1);
    expect(await balance()).toBe(CAP);
    expect(await schedulerState()).toEqual({ inFlight: 0, rateUsed: [0, 0, 0] });
  });

  it("fences stale recovery and moves a started orphan to unknown without refund", async () => {
    const admission = await admit("billing-recovery-started");
    expect((await start(admission)).status).toBe(204);
    const identity = await env.DB.prepare(
      `SELECT request_id,user_id,api_key_id,group_id,account_id,lease_id,
              lease_epoch,owner,model,upstream_model,pricing_version_id,
              pricing_digest,pricing_model,pricing_rule_pattern,
              pricing_rule_match_kind,rate_multiplier_bps,reservation_e8_usd
       FROM billing_reservations WHERE request_id=?`,
    ).bind(admission.lease.request_id).first<BillingIdentity>();
    expect(identity).not.toBeNull();
    const stale = await env.BILLING_PRINCIPAL.getByName("user:1001").expire({
      ...identity!,
      operation_id: `${admission.lease.request_id}:stale-recovery`,
      expected_reservation_version: "1",
      reason: "crash",
      evidence_digest: "e".repeat(64),
    });
    expect(stale).toEqual({ kind: "out_of_order" });
    expect(await reservation(admission.lease.request_id)).toMatchObject({
      state: "started",
      version: 2,
    });

    const recoveryTime = Date.now();
    await env.DB.prepare(
      "UPDATE billing_reservations SET started_at=? WHERE request_id=?",
    ).bind(
      new Date(recoveryTime - 20 * 60_000).toISOString(),
      admission.lease.request_id,
    ).run();
    await recoverStaleAdmissions(env, recoveryTime);
    await recoverStaleAdmissions(env, recoveryTime);
    expect(await reservation(admission.lease.request_id)).toEqual({
      state: "unknown",
      charged_e8_usd: null,
      usage_present: 0,
      version: 3,
    });
    expect(await balance()).toBe("0");
    expect(await env.DB.prepare(
      "SELECT count(*) count FROM billing_reservation_events WHERE operation_kind='expire_unknown'",
    ).first("count")).toBe(1);
    expect(await schedulerState()).toEqual({ inFlight: 0, rateUsed: [1, 1, 1] });
  });

  it("wires orphan recovery through the Worker scheduled handler", async () => {
    const admission = await admit("billing-recovery-scheduled-route");
    await env.DB.prepare(
      "UPDATE billing_reservations SET created_at=? WHERE request_id=?",
    ).bind(
      new Date(Date.now() - 20 * 60_000).toISOString(),
      admission.lease.request_id,
    ).run();
    const pending: Promise<unknown>[] = [];
    const context = {
      waitUntil(promise: Promise<unknown>) {
        pending.push(promise);
      },
    } as unknown as ExecutionContext;
    await worker.scheduled({} as ScheduledController, env, context);
    expect(pending).toHaveLength(1);
    await Promise.all(pending);
    expect(await reservation(admission.lease.request_id)).toMatchObject({
      state: "released",
      version: 2,
    });
    expect(await balance()).toBe(CAP);
    expect(await schedulerState()).toEqual({ inFlight: 0, rateUsed: [0, 0, 0] });
  });

  it("atomically rejects stale activation and releases the newly created lease", async () => {
    const versionID = "fixture-v2-race";
    await cloneFixturePricing(versionID);
    const racedEnv = overrideBillingReserve(() => activatePricing(versionID).then(() => undefined));
    const response = await call("/v1/requests/admit", {
      request_id: "billing-stale-pricing",
      api_key_id: "3001",
      group_id: "2001",
      model: "fixture-model",
      lease_ttl_seconds: 30,
    }, racedEnv);
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: { code: "PRICING_UNAVAILABLE" } });
    expect(await balance()).toBe(CAP);
    expect(await env.DB.prepare(
      "SELECT count(*) count FROM gateway_requests WHERE request_id='billing-stale-pricing'",
    ).first("count")).toBe(0);
    expect(await env.DB.prepare(
      "SELECT count(*) count FROM billing_reservations WHERE request_id='billing-stale-pricing'",
    ).first("count")).toBe(0);
    expect(await env.DB.prepare("SELECT count(*) count FROM billing_cas_guards").first("count")).toBe(0);

    const next = await admit("billing-after-stale-pricing");
    expect(next.price_card.version_id).toBe(versionID);
    expect((await release(next)).status).toBe(200);
  });

  it("serializes per-user reservations and compensates the losing lease", async () => {
    await env.DB.prepare("UPDATE accounts SET max_concurrency=2 WHERE id='4001'").run();
    const responses = await Promise.all([
      call("/v1/requests/admit", {
        request_id: "billing-concurrent-a", api_key_id: "3001", group_id: "2001",
        model: "fixture-model", lease_ttl_seconds: 30,
      }),
      call("/v1/requests/admit", {
        request_id: "billing-concurrent-b", api_key_id: "3001", group_id: "2001",
        model: "fixture-model", lease_ttl_seconds: 30,
      }),
    ]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 402]);
    const winnerResponse = responses.find((response) => response.status === 200);
    expect(winnerResponse).toBeDefined();
    const winner = await winnerResponse!.json<Admission>();
    expect(await balance()).toBe("0");
    expect(await env.DB.prepare("SELECT count(*) count FROM billing_reservations").first("count")).toBe(1);
    expect(await env.DB.prepare("SELECT count(*) count FROM gateway_requests").first("count")).toBe(1);
    expect(await env.DB.prepare("SELECT count(*) count FROM billing_cas_guards").first("count")).toBe(0);

    expect((await release(winner)).status).toBe(200);
    await env.DB.prepare("UPDATE accounts SET max_concurrency=1 WHERE id='4001'").run();
    const afterCompensation = await admit("billing-after-concurrent-loss");
    expect((await release(afterCompensation)).status).toBe(200);
  });
});
