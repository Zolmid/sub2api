import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  SubscriptionRuntime,
  SubscriptionRuntimeError,
  type UserSubscription,
} from "../src/subscription-runtime";

const runtime = new SubscriptionRuntime(env.DB);

async function seedReferences(userID: string, groupID: string, adminID: string, type = "subscription") {
  const at = "2026-01-01T00:00:00.000Z";
  const user = (id: string, role: string) => env.DB.prepare(`INSERT INTO users(
    id,status,role,concurrency,balance_e8_usd,allowed_group_ids_json,restrict_public_groups,
    created_at,updated_at,email,password_hash,username,notes,rpm_limit,deleted_at
  ) VALUES(?,?,?,?,?,'[]',0,?,?,?,?,?,?,0,NULL)`).bind(
    id, "active", role, 1, "0", at, at, `${id}@subscription.test`, "", `user-${id}`, "",
  );
  await env.DB.batch([
    user(userID, "user"),
    user(adminID, "admin"),
    env.DB.prepare(`INSERT INTO groups(
      id,name,platform,status,is_exclusive,subscription_type,created_at,updated_at,deleted_at
    ) VALUES(?,?,?,?,0,?,?,?,NULL)`).bind(groupID, `group-${groupID}`, "openai", "active", type, at, at),
  ]);
}

function planInput(operationID: string, planID: string, groupID: string, adminID: string, extra: Record<string, unknown> = {}) {
  return {
    operation_id: operationID, id: planID, group_id: groupID, name: "Exact E8 plan",
    description: "", price_e8_usd: "0", original_price_e8_usd: null,
    daily_limit_e8_usd: "1000000000", weekly_limit_e8_usd: "2000000000",
    monthly_limit_e8_usd: "3000000000", currency: "USD", validity_days: 30,
    validity_unit: "day", features: "", product_name: "", for_sale: true,
    sort_order: 0, actor_user_id: adminID, at: "2026-01-01T00:00:00Z", ...extra,
  };
}

function assignInput(operationID: string, subscriptionID: string, userID: string, groupID: string, extra: Record<string, unknown> = {}) {
  return {
    operation_id: operationID, new_subscription_id: subscriptionID, user_id: userID,
    group_id: groupID, plan_id: null, validity_days: 30, assigned_by: null, notes: "",
    now: "2026-01-01T12:00:00Z", daily_boundary: "2026-01-01T00:00:00Z", ...extra,
  };
}

async function errorCode(promise: Promise<unknown>): Promise<string> {
  try { await promise; } catch (error) {
    expect(error).toBeInstanceOf(SubscriptionRuntimeError);
    return (error as SubscriptionRuntimeError).code;
  }
  throw new Error("expected SubscriptionRuntimeError");
}

async function stored(id: string): Promise<UserSubscription> {
  const row = await env.DB.prepare("SELECT * FROM user_subscriptions WHERE id=?").bind(id).first<UserSubscription>();
  if (!row) throw new Error(`missing subscription ${id}`);
  return row;
}

describe("Cloudflare-native subscription runtime", () => {
  it("stores exact E8 values and rejects missing, invalid, hostile, and unsafe inputs", async () => {
    await seedReferences("5101", "5201", "5102");
    const zero = await runtime.createPlan(planInput("plan-zero", "5301", "5201", "5102"));
    expect(zero.plan.price_e8_usd).toBe("0");
    expect(zero.plan.original_price_e8_usd).toBeNull();
    expect(await errorCode(runtime.createPlan(planInput("plan-null", "5304", "5201", "5102", { price_e8_usd: null })))).toBe("INVALID_MONEY");
    expect(await errorCode(runtime.createPlan(planInput("plan-float", "5305", "5201", "5102", { price_e8_usd: "1.0" })))).toBe("INVALID_MONEY");
    expect(await errorCode(runtime.createPlan(planInput("plan-overflow", "5306", "5201", "5102", { price_e8_usd: "9223372036854775808" })))).toBe("MONEY_OVERFLOW");
    expect(await errorCode(runtime.createPlan(planInput("plan-unknown", "5307", "5201", "5102", { surprise: true })))).toBe("UNKNOWN_FIELD");
    expect(await errorCode(runtime.createPlan(planInput("plan-control", "5308", "5201", "5102", { name: "bad" + String.fromCharCode(0) })))).toBe("INVALID_TEXT");
    expect(await errorCode(runtime.createPlan(planInput("plan-id", "5309", "5201", "5102", { id: 9_007_199_254_740_992 })))).toBe("INVALID_ID");
    const missing = planInput("plan-missing", "5310", "5201", "5102") as Record<string, unknown>;
    delete missing.price_e8_usd;
    expect(await errorCode(runtime.createPlan(missing))).toBe("MISSING_FIELD");

    const assigned = await runtime.assignOrExtend(assignInput("assign-empty", "5401", "5101", "5201", {
      plan_id: "5301", assigned_by: "5102", notes: "",
    }));
    expect(assigned.subscription.notes).toBe("");
    expect(assigned.subscription.daily_limit_e8_usd).toBe("1000000000");

    await seedReferences("5111", "5211", "5112", "standard");
    expect(await errorCode(runtime.assignOrExtend(assignInput("assign-standard", "5411", "5111", "5211")))).toBe("GROUP_NOT_SUBSCRIPTION_TYPE");
    expect(await errorCode(runtime.assignOrExtend(assignInput("assign-no-user", "5412", "5999", "5201")))).toBe("USER_NOT_FOUND");
    expect(await errorCode(runtime.createPlan(planInput("plan-non-admin", "5311", "5201", "5101")))).toBe("ADMIN_NOT_FOUND");
    expect(await errorCode(runtime.listPlans({ group_id: null, for_sale: null, include_deleted: false, after_id: null, limit: 0 }))).toBe("INVALID_INTEGER");
    expect(await errorCode(runtime.listSubscriptions({ user_id: null, group_id: null, status: null, include_deleted: false, after_id: null, limit: 101 }))).toBe("INVALID_INTEGER");
    expect(await errorCode(runtime.assignOrExtend(assignInput("assign-bad-time", "5413", "5101", "5201", {
      now: "2026-02-30T12:00:00Z",
    })))).toBe("INVALID_TIMESTAMP");
    const foreignKeys = await env.DB.prepare("PRAGMA foreign_key_list('user_subscriptions')").all<{ table: string }>();
    expect(new Set(foreignKeys.results.map((row) => row.table))).toEqual(
      new Set(["users", "groups", "subscription_plans"]),
    );
  });

  it("enforces live uniqueness, exact replay, soft-delete replacement, restore, and statuses", async () => {
    await seedReferences("6101", "6201", "6102");
    const request = assignInput("assign-replay", "6301", "6101", "6201", { notes: "first" });
    const first = await runtime.assignOrExtend(request);
    expect(await runtime.assignOrExtend(request)).toEqual(first);
    expect(await errorCode(runtime.assignOrExtend({ ...request, notes: "changed" }))).toBe("IDEMPOTENCY_CONFLICT");
    const revoked = await runtime.revoke({ operation_id: "revoke-old", subscription_id: "6301", expected_version: 1,
      actor_user_id: "6102", at: "2026-01-02T00:00:00Z" });
    const replacement = await runtime.assignOrExtend(assignInput("assign-new", "6302", "6101", "6201", { now: "2026-01-03T00:00:00Z" }));
    expect(replacement.subscription.id).toBe("6302");
    expect(await errorCode(runtime.restore({ operation_id: "restore-conflict", subscription_id: "6301",
      expected_version: revoked.subscription.version, actor_user_id: "6102", now: "2026-01-03T00:00:00Z" }))).toBe("RESTORE_CONFLICT");
    await expect(env.DB.prepare("DELETE FROM subscription_operations WHERE operation_id='assign-replay'").run()).rejects.toThrow();

    await seedReferences("6111", "6211", "6112");
    const old = await runtime.assignOrExtend(assignInput("assign-expired", "6311", "6111", "6211", { validity_days: 1 }));
    const gone = await runtime.revoke({ operation_id: "revoke-expired", subscription_id: "6311", expected_version: old.subscription.version,
      actor_user_id: "6112", at: "2026-01-02T13:00:00Z" });
    const restored = await runtime.restore({ operation_id: "restore-expired", subscription_id: "6311", expected_version: gone.subscription.version,
      actor_user_id: "6112", now: "2026-01-03T00:00:00Z" });
    expect(restored.subscription.status).toBe("expired");
    const extended = await runtime.extend({ operation_id: "extend-expired", subscription_id: "6311", expected_version: restored.subscription.version,
      days: 3, actor_user_id: "6112", now: "2026-01-03T00:00:00Z" });
    expect(extended.subscription.status).toBe("active");
    await env.DB.prepare("UPDATE user_subscriptions SET status='suspended' WHERE id='6311'").run();
    expect(await errorCode(runtime.reserveUsage({ operation_id: "usage-suspended", subscription_id: "6311",
      expected_version: extended.subscription.version, amount_e8_usd: "1", at: "2026-01-03T01:00:00Z" }))).toBe("SUBSCRIPTION_SUSPENDED");
    const suspendedExtension = await runtime.extend({ operation_id: "extend-suspended", subscription_id: "6311",
      expected_version: extended.subscription.version, days: 1, actor_user_id: "6112", now: "2026-01-03T02:00:00Z" });
    expect(suspendedExtension.subscription.status).toBe("suspended");
  });

  it("converges two concurrent assign-or-extend deliveries without losing either term", async () => {
    await seedReferences("6501", "6601", "6502");
    const results = await Promise.all([
      runtime.assignOrExtend(assignInput("assign-race-a", "6701", "6501", "6601", { validity_days: 1 })),
      runtime.assignOrExtend(assignInput("assign-race-b", "6702", "6501", "6601", { validity_days: 1 })),
    ]);
    expect(results.filter((result) => result.extended)).toHaveLength(1);
    const list = await runtime.listSubscriptions({ user_id: "6501", group_id: "6601", status: null,
      include_deleted: false, after_id: null, limit: 10 });
    expect(list.items).toHaveLength(1);
    expect(list.items[0].expires_at).toBe("2026-01-03T12:00:00.000Z");
    expect(list.items[0].version).toBe(2);
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM subscription_operations WHERE operation_id IN ('assign-race-a','assign-race-b')").first<number>("count")).toBe(2);
  });

  it("uses explicit DST boundaries and never refills a one-day term", async () => {
    await seedReferences("7101", "7201", "7102");
    const initial = await runtime.assignOrExtend(assignInput("assign-dst", "7301", "7101", "7201", {
      now: "2026-03-08T06:30:00Z", daily_boundary: "2026-03-08T05:00:00Z", validity_days: 10,
    }));
    expect((await stored("7301")).id).toBe(initial.subscription.id);
    const active = await runtime.activateWindows({ operation_id: "activate-dst", subscription_id: "7301",
      expected_version: initial.subscription.version, activated_at: "2026-03-08T06:30:00Z", daily_boundary: "2026-03-08T05:00:00Z" });
    await runtime.reserveUsage({ operation_id: "usage-dst", subscription_id: "7301", expected_version: active.subscription.version,
      amount_e8_usd: "7", at: "2026-03-08T07:00:00Z" });
    const maintained = await runtime.maintainWindows({ operation_id: "maintain-dst", subscription_id: "7301", expected_version: 3,
      now: "2026-03-09T04:30:00Z", daily_boundary: "2026-03-09T04:00:00Z" });
    expect(maintained.subscription.daily_window_start).toBe("2026-03-09T04:00:00.000Z");
    expect(maintained.subscription.daily_usage_e8_usd).toBe("0");

    await seedReferences("7111", "7211", "7112");
    const one = await runtime.assignOrExtend(assignInput("assign-one", "7302", "7111", "7211", {
      now: "2026-04-01T12:00:00Z", daily_boundary: "2026-04-01T04:00:00Z", validity_days: 1,
    }));
    const oneActive = await runtime.activateWindows({ operation_id: "activate-one", subscription_id: "7302",
      expected_version: one.subscription.version, activated_at: "2026-04-01T12:00:00Z", daily_boundary: "2026-04-01T04:00:00Z" });
    await runtime.reserveUsage({ operation_id: "usage-one", subscription_id: "7302", expected_version: oneActive.subscription.version,
      amount_e8_usd: "9", at: "2026-04-01T13:00:00Z" });
    const noRefill = await runtime.maintainWindows({ operation_id: "maintain-one", subscription_id: "7302", expected_version: 3,
      now: "2026-04-02T05:00:00Z", daily_boundary: "2026-04-02T04:00:00Z" });
    expect(noRefill.subscription.daily_window_start).toBe("2026-04-01T04:00:00.000Z");
    expect(noRefill.subscription.daily_usage_e8_usd).toBe("9");
  });

  it("advances 7-day and 30-day anchors, normalizes legacy values, and preserves manual cadence", async () => {
    await seedReferences("8101", "8201", "8102");
    const assigned = await runtime.assignOrExtend(assignInput("assign-windows", "8301", "8101", "8201", {
      validity_days: 100, now: "2026-01-01T12:00:00Z",
    }));
    const active = await runtime.activateWindows({ operation_id: "activate-windows", subscription_id: "8301",
      expected_version: assigned.subscription.version, activated_at: "2026-01-01T12:00:00Z", daily_boundary: "2026-01-01T00:00:00Z" });
    await env.DB.prepare(`UPDATE user_subscriptions SET weekly_window_start=initial_daily_boundary,
      monthly_window_start=initial_daily_boundary,weekly_anchor_kind='legacy_initial',monthly_anchor_kind='legacy_initial',
      weekly_usage_e8_usd='70',monthly_usage_e8_usd='300' WHERE id='8301'`).run();
    const advanced = await runtime.maintainWindows({ operation_id: "maintain-windows", subscription_id: "8301",
      expected_version: active.subscription.version, now: "2026-03-07T12:00:00Z", daily_boundary: "2026-03-07T00:00:00Z" });
    expect(advanced.subscription.weekly_window_start).toBe("2026-03-05T12:00:00.000Z");
    expect(advanced.subscription.monthly_window_start).toBe("2026-03-02T12:00:00.000Z");
    expect(advanced.subscription.weekly_usage_e8_usd).toBe("0");
    expect(advanced.subscription.monthly_usage_e8_usd).toBe("0");
    const reset = await runtime.resetWindows({ operation_id: "manual-reset", subscription_id: "8301",
      expected_version: advanced.subscription.version, reset_daily: true, reset_weekly: true, reset_monthly: true,
      reset_at: "2026-03-08T10:37:42Z", daily_boundary: "2026-03-08T00:00:00Z", actor_user_id: "8102" });
    expect(reset.subscription.daily_window_start).toBe("2026-03-08T00:00:00.000Z");
    expect(reset.subscription.weekly_window_start).toBe("2026-03-08T10:37:42.000Z");
    expect(reset.subscription.monthly_window_start).toBe("2026-03-08T10:37:42.000Z");
    expect(reset.subscription.weekly_anchor_kind).toBe("manual");

    await seedReferences("8111", "8211", "8112");
    const short = await runtime.assignOrExtend(assignInput("assign-partial", "8302", "8111", "8211", {
      validity_days: 5, now: "2026-05-01T12:00:00Z",
    }));
    const shortActive = await runtime.activateWindows({ operation_id: "activate-partial", subscription_id: "8302",
      expected_version: short.subscription.version, activated_at: "2026-05-01T12:00:00Z", daily_boundary: "2026-05-01T00:00:00Z" });
    await env.DB.prepare("UPDATE user_subscriptions SET weekly_usage_e8_usd='11',monthly_usage_e8_usd='12' WHERE id='8302'").run();
    const atExpiry = await runtime.maintainWindows({ operation_id: "maintain-partial", subscription_id: "8302",
      expected_version: shortActive.subscription.version, now: "2026-05-06T12:00:00Z", daily_boundary: "2026-05-06T00:00:00Z" });
    expect(atExpiry.subscription.weekly_window_start).toBe("2026-05-01T12:00:00.000Z");
    expect(atExpiry.subscription.monthly_window_start).toBe("2026-05-01T12:00:00.000Z");
    expect(atExpiry.subscription.weekly_usage_e8_usd).toBe("11");
    expect(atExpiry.subscription.monthly_usage_e8_usd).toBe("12");
  });

  it("prevents exact quota overflow and concurrent stale writes without partial audit", async () => {
    await seedReferences("9101", "9201", "9102");
    await runtime.createPlan(planInput("plan-quota", "9301", "9201", "9102", {
      daily_limit_e8_usd: "10", weekly_limit_e8_usd: "10", monthly_limit_e8_usd: "10",
    }));
    const assigned = await runtime.assignOrExtend(assignInput("assign-quota", "9401", "9101", "9201", { plan_id: "9301" }));
    const active = await runtime.activateWindows({ operation_id: "activate-quota", subscription_id: "9401",
      expected_version: assigned.subscription.version, activated_at: "2026-01-01T12:00:00Z", daily_boundary: "2026-01-01T00:00:00Z" });
    const exact = await runtime.reserveUsage({ operation_id: "usage-exact", subscription_id: "9401",
      expected_version: active.subscription.version, amount_e8_usd: "10", at: "2026-01-01T12:01:00Z" });
    expect(exact.subscription.daily_usage_e8_usd).toBe("10");
    expect(await errorCode(runtime.reserveUsage({ operation_id: "usage-over-limit", subscription_id: "9401",
      expected_version: exact.subscription.version, amount_e8_usd: "1", at: "2026-01-01T12:02:00Z" }))).toBe("DAILY_LIMIT_EXCEEDED");
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM subscription_operations WHERE operation_id='usage-over-limit'").first<number>("count")).toBe(0);

    await env.DB.prepare(`UPDATE user_subscriptions SET daily_limit_e8_usd=NULL,weekly_limit_e8_usd=NULL,
      monthly_limit_e8_usd=NULL,daily_usage_e8_usd='9223372036854775807',weekly_usage_e8_usd='9223372036854775807',
      monthly_usage_e8_usd='9223372036854775807' WHERE id='9401'`).run();
    expect(await errorCode(runtime.reserveUsage({ operation_id: "usage-overflow", subscription_id: "9401",
      expected_version: exact.subscription.version, amount_e8_usd: "1", at: "2026-01-01T12:03:00Z" }))).toBe("MONEY_OVERFLOW");

    await env.DB.prepare(`UPDATE user_subscriptions SET daily_usage_e8_usd='0',weekly_usage_e8_usd='0',monthly_usage_e8_usd='0',
      daily_limit_e8_usd='10',weekly_limit_e8_usd='10',monthly_limit_e8_usd='10' WHERE id='9401'`).run();
    const version = (await stored("9401")).version;
    const outcomes = await Promise.allSettled([
      runtime.reserveUsage({ operation_id: "usage-race-a", subscription_id: "9401", expected_version: version,
        amount_e8_usd: "6", at: "2026-01-01T12:04:00Z" }),
      runtime.reserveUsage({ operation_id: "usage-race-b", subscription_id: "9401", expected_version: version,
        amount_e8_usd: "6", at: "2026-01-01T12:04:00Z" }),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    expect((await stored("9401")).daily_usage_e8_usd).toBe("6");
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM subscription_operations WHERE operation_id IN ('usage-race-a','usage-race-b')").first<number>("count")).toBe(1);
    expect(await env.DB.prepare("SELECT COUNT(*) AS count FROM subscription_operation_effects WHERE operation_id IN ('usage-race-a','usage-race-b')").first<number>("count")).toBe(1);

    const raceVersion = (await stored("9401")).version;
    const resetVsUsage = await Promise.allSettled([
      runtime.resetWindows({ operation_id: "reset-race", subscription_id: "9401", expected_version: raceVersion,
        reset_daily: true, reset_weekly: false, reset_monthly: false, reset_at: "2026-01-01T13:00:00Z",
        daily_boundary: "2026-01-01T00:00:00Z", actor_user_id: "9102" }),
      runtime.reserveUsage({ operation_id: "usage-reset-race", subscription_id: "9401", expected_version: raceVersion,
        amount_e8_usd: "1", at: "2026-01-01T13:00:00Z" }),
    ]);
    expect(resetVsUsage.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
  });

  it("sweeps expiry idempotently and old delivery cannot overwrite a later extension", async () => {
    await seedReferences("10101", "10201", "10102");
    await runtime.assignOrExtend(assignInput("assign-sweep", "10301", "10101", "10201", { validity_days: 1 }));
    const request = { operation_id: "expiry-sweep-a", cutoff: "2026-01-03T00:00:00Z", after_id: null, limit: 20 };
    const swept = await runtime.sweepExpired(request);
    expect(swept).toEqual({ expired_ids: ["10301"], count: 1 });
    expect(await runtime.sweepExpired(request)).toEqual(swept);
    const expired = await stored("10301");
    const extended = await runtime.extend({ operation_id: "extend-after-sweep", subscription_id: "10301",
      expected_version: expired.version, days: 5, actor_user_id: "10102", now: "2026-01-03T01:00:00Z" });
    expect(extended.subscription.status).toBe("active");
    expect(await runtime.sweepExpired(request)).toEqual(swept);
    expect(await errorCode(runtime.sweepExpired({ ...request, cutoff: "2026-01-04T00:00:00Z" }))).toBe("IDEMPOTENCY_CONFLICT");
    expect((await stored("10301")).status).toBe("active");

    await seedReferences("10111", "10211", "10112");
    const second = await runtime.assignOrExtend(assignInput("assign-restore-race", "10311", "10111", "10211", { validity_days: 1 }));
    const revoked = await runtime.revoke({ operation_id: "revoke-restore-race", subscription_id: "10311",
      expected_version: second.subscription.version, actor_user_id: "10112", at: "2026-01-02T13:00:00Z" });
    await Promise.all([
      runtime.restore({ operation_id: "restore-race", subscription_id: "10311", expected_version: revoked.subscription.version,
        actor_user_id: "10112", now: "2026-01-03T00:00:00Z" }),
      runtime.sweepExpired({ operation_id: "expiry-restore-race", cutoff: "2026-01-03T00:00:00Z", after_id: null, limit: 20 }),
    ]);
    expect((await stored("10311")).status).toBe("expired");
  });
});
