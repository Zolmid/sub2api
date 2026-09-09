import { describe, expect, it } from "vitest";
import { decideSchedulerPolicy, type Evidence, type SchedulerAccount, type SchedulerCapability, type SchedulerRequest } from "../src/scheduler-policy";

const confirmed = <T>(value: T): Evidence<T> => ({ kind: "confirmed", value });
const estimated = <T>(value: T): Evidence<T> => ({ kind: "estimated", value });
const unknown = <T>(): Evidence<T> => ({ kind: "unknown" });

function account(accountId = "10", overrides: Partial<SchedulerAccount> = {}): SchedulerAccount {
  return {
    accountId,
    stableId: `stable-${accountId}`,
    priority: 10,
    active: confirmed(true),
    schedulable: confirmed(true),
    groups: confirmed(["default"]),
    capabilities: confirmed({ platforms: ["openai"], accountTypes: ["shared"], models: ["gpt-test"] }),
    accountConcurrencyLimit: confirmed(10),
    accountConcurrencyInFlight: confirmed(1),
    accountRpmLimit: confirmed(100),
    accountRpmUsed: confirmed(1),
    userRpmLimit: confirmed(50),
    userRpmUsed: confirmed(1),
    quotaExhausted: confirmed(false),
    quotaRemainingRatio: confirmed(0.5),
    temporarilyUnschedulableUntilMs: confirmed(null),
    cooldownUntilMs: confirmed(null),
    healthRatio: confirmed(0.5),
    ...overrides,
  };
}

function request(accounts: readonly SchedulerAccount[], overrides: Partial<SchedulerRequest> = {}): SchedulerRequest {
  return { nowMs: 1_700_000_000_000, requiredGroup: "default", platform: "openai", accountType: "shared", model: "gpt-test", accounts, ...overrides };
}

function unsafeAccount(overrides: Record<string, unknown> = {}): unknown {
  return { ...account(), ...overrides };
}

function unsafeRequest(accounts: readonly unknown[], overrides: Record<string, unknown> = {}): unknown {
  return { ...request([]), accounts, ...overrides };
}

function rejectedReason(candidate: unknown): string | undefined {
  return decideSchedulerPolicy(unsafeRequest([candidate])).rejected[0]?.reason;
}

describe("decideSchedulerPolicy", () => {
  it.each([
    ["inactive", { active: confirmed(false) }, "ACTIVE_FALSE"],
    ["estimated active", { active: estimated(true) }, "ACTIVE_UNCONFIRMED"],
    ["unknown active", { active: unknown<boolean>() }, "ACTIVE_UNKNOWN"],
    ["not schedulable", { schedulable: confirmed(false) }, "SCHEDULABLE_FALSE"],
    ["estimated schedulable", { schedulable: estimated(true) }, "SCHEDULABLE_UNCONFIRMED"],
    ["unknown schedulable", { schedulable: unknown<boolean>() }, "SCHEDULABLE_UNKNOWN"],
    ["estimated group", { groups: estimated(["default"]) }, "GROUP_UNCONFIRMED"],
    ["unknown group", { groups: unknown<readonly string[]>() }, "GROUP_UNKNOWN"],
    ["wrong group", { groups: confirmed(["other"]) }, "GROUP_MISMATCH"],
    ["estimated capability", { capabilities: estimated({ platforms: ["openai"], accountTypes: ["shared"], models: ["gpt-test"] }) }, "CAPABILITY_UNCONFIRMED"],
    ["unknown capability", { capabilities: unknown<SchedulerCapability>() }, "CAPABILITY_UNKNOWN"],
    ["wrong platform", { capabilities: confirmed({ platforms: ["anthropic"], accountTypes: ["shared"], models: ["gpt-test"] }) }, "PLATFORM_UNSUPPORTED"],
    ["wrong type", { capabilities: confirmed({ platforms: ["openai"], accountTypes: ["dedicated"], models: ["gpt-test"] }) }, "ACCOUNT_TYPE_UNSUPPORTED"],
    ["wrong model", { capabilities: confirmed({ platforms: ["openai"], accountTypes: ["shared"], models: ["other"] }) }, "MODEL_UNSUPPORTED"],
    ["concurrency full", { accountConcurrencyLimit: confirmed(1), accountConcurrencyInFlight: confirmed(1) }, "ACCOUNT_CONCURRENCY_EXHAUSTED"],
    ["concurrency limit estimated", { accountConcurrencyLimit: estimated(10) }, "ACCOUNT_CONCURRENCY_UNCONFIRMED"],
    ["concurrency usage estimated", { accountConcurrencyInFlight: estimated(1) }, "ACCOUNT_CONCURRENCY_UNCONFIRMED"],
    ["concurrency unknown", { accountConcurrencyInFlight: unknown<number>() }, "ACCOUNT_CONCURRENCY_UNKNOWN"],
    ["account rpm full", { accountRpmLimit: confirmed(1), accountRpmUsed: confirmed(1) }, "ACCOUNT_RPM_EXHAUSTED"],
    ["account rpm estimated", { accountRpmUsed: estimated(1) }, "ACCOUNT_RPM_UNCONFIRMED"],
    ["account rpm unknown", { accountRpmLimit: unknown<number>() }, "ACCOUNT_RPM_UNKNOWN"],
    ["user rpm estimated", { userRpmLimit: estimated(50) }, "USER_RPM_UNCONFIRMED"],
    ["user rpm unknown", { userRpmUsed: unknown<number>() }, "USER_RPM_UNKNOWN"],
    ["confirmed quota", { quotaExhausted: confirmed(true) }, "QUOTA_EXHAUSTED_CONFIRMED"],
    ["estimated quota", { quotaExhausted: estimated(true) }, "QUOTA_EXHAUSTED_ESTIMATED"],
    ["temporary deadline", { temporarilyUnschedulableUntilMs: confirmed(1_700_000_000_001) }, "TEMPORARILY_UNSCHEDULABLE"],
    ["cooldown deadline", { cooldownUntilMs: estimated(1_700_000_000_001) }, "COOLDOWN_ACTIVE"],
  ])("rejects %s with %s", (_name, overrides, reason) => {
    const result = decideSchedulerPolicy(request([account("10", overrides)]));
    expect(result.rejected).toEqual([{ accountId: "10", stableId: "stable-10", reason }]);
  });

  it("allows boundaries and records unknown quota as unknown rather than zero or confirmed", () => {
    const result = decideSchedulerPolicy(request([account("10", {
      accountConcurrencyLimit: confirmed(1), accountConcurrencyInFlight: confirmed(0),
      accountRpmLimit: confirmed(1), accountRpmUsed: confirmed(0), userRpmLimit: confirmed(1), userRpmUsed: confirmed(0),
      quotaExhausted: unknown<boolean>(), quotaRemainingRatio: unknown<number>(), healthRatio: unknown<number>(),
      cooldownUntilMs: unknown<number | null>(), temporarilyUnschedulableUntilMs: unknown<number | null>(),
    })]));
    expect(result.selectedAccountId).toBe("10");
    expect(result.eligible[0].score.quota).toBe(0);
    expect(result.eligible[0].evidence).toMatchObject({
      quotaRemaining: "unknown",
      quotaExhaustion: "unknown",
      health: "unknown",
      cooldown: "unknown",
      accountConcurrency: "confirmed",
      accountRpm: "confirmed",
      userRpm: "confirmed",
    });
  });

  it.each([
    ["NaN health", { healthRatio: confirmed(Number.NaN) }, "INVALID_HEALTH_METRIC"],
    ["Infinity quota", { quotaRemainingRatio: confirmed(Infinity) }, "INVALID_QUOTA_METRIC"],
    ["negative capacity", { accountConcurrencyLimit: confirmed(-1) }, "INVALID_CAPACITY_METRIC"],
    ["past deadline is ready", { cooldownUntilMs: confirmed(1_699_999_999_999) }, null],
    ["exact deadline is ready", { cooldownUntilMs: confirmed(1_700_000_000_000) }, null],
  ])("handles metric and deadline boundary %s", (_name, overrides, reason) => {
    const result = decideSchedulerPolicy(request([account("10", overrides)]));
    expect(reason ? result.rejected[0]?.reason : result.selectedAccountId).toBe(reason ?? "10");
  });

  it.each([
    null,
    undefined,
    42,
    "request",
    [],
    {},
    unsafeRequest([], { nowMs: Number.NaN }),
    unsafeRequest([], { accounts: null }),
    unsafeRequest([], { requiredGroup: "bad\nvalue" }),
    unsafeRequest([], { platform: `x${"p".repeat(128)}` }),
    unsafeRequest([], { stickinessKey: "k".repeat(257) }),
    unsafeRequest(Array.from({ length: 257 }, () => null)),
  ])("fails closed for malformed top-level input %#", (value) => {
    expect(() => decideSchedulerPolicy(value)).not.toThrow();
    expect(decideSchedulerPolicy(value)).toEqual({
      selectedAccountId: null,
      eligible: [],
      rejected: [],
      requestErrors: ["INVALID_REQUEST"],
      selection: "none",
    });
  });

  it("fails closed when an untrusted object throws during property access", () => {
    const throwing = new Proxy({}, { get: () => { throw new Error("untrusted getter"); } });
    expect(decideSchedulerPolicy(throwing).requestErrors).toEqual(["INVALID_REQUEST"]);
  });

  it.each([
    [null, "INVALID_ACCOUNT"],
    [17, "INVALID_ACCOUNT"],
    [{}, "INVALID_ACCOUNT_ID"],
    [unsafeAccount({ active: null }), "INVALID_EVIDENCE"],
    [unsafeAccount({ active: { kind: "confirmed" } }), "INVALID_EVIDENCE"],
    [unsafeAccount({ active: { kind: "confirmed", value: "true" } }), "INVALID_EVIDENCE"],
    [unsafeAccount({ active: { kind: "unknown", value: true } }), "INVALID_EVIDENCE"],
    [unsafeAccount({ schedulable: { kind: "other", value: true } }), "INVALID_EVIDENCE"],
  ])("rejects malformed account or evidence %#", (candidate, reason) => {
    expect(() => rejectedReason(candidate)).not.toThrow();
    expect(rejectedReason(candidate)).toBe(reason);
  });

  it.each(["false", "true", 0, 1, null, [], {}])(
    "requires quotaExhausted to contain an actual boolean: %#",
    (value) => {
      expect(rejectedReason(unsafeAccount({ quotaExhausted: { kind: "confirmed", value } })))
        .toBe("INVALID_QUOTA_EXHAUSTED");
    },
  );

  it("rejects malformed quotaExhausted evidence shapes", () => {
    expect(rejectedReason(unsafeAccount({ quotaExhausted: null })))
      .toBe("INVALID_QUOTA_EXHAUSTED");
    expect(rejectedReason(unsafeAccount({ quotaExhausted: { kind: "confirmed" } })))
      .toBe("INVALID_QUOTA_EXHAUSTED");
    expect(rejectedReason(unsafeAccount({ quotaExhausted: { kind: "unknown", value: false } })))
      .toBe("INVALID_QUOTA_EXHAUSTED");
  });

  it.each([
    [null, "INVALID_GROUPS"],
    [confirmed("default"), "INVALID_GROUPS"],
    [confirmed(["default", "default"]), "INVALID_GROUPS"],
    [confirmed(["default", "bad\u0000group"]), "INVALID_GROUPS"],
    [confirmed(["default", "x".repeat(129)]), "INVALID_GROUPS"],
    [confirmed(Array.from({ length: 65 }, (_, index) => `group-${index}`)), "INVALID_GROUPS"],
  ])("bounds and validates group arrays %#", (groups, reason) => {
    expect(rejectedReason(unsafeAccount({ groups }))).toBe(reason);
  });

  it("rejects sparse group arrays", () => {
    const sparse = new Array<string>(1);
    expect(rejectedReason(unsafeAccount({ groups: confirmed(sparse) })))
      .toBe("INVALID_GROUPS");
  });

  it.each([
    null,
    [],
    { platforms: ["openai"], accountTypes: ["shared"] },
    { platforms: ["openai", "openai"], accountTypes: ["shared"], models: ["gpt-test"] },
    { platforms: ["openai"], accountTypes: ["shared\u0007"], models: ["gpt-test"] },
    { platforms: ["openai"], accountTypes: ["shared"], models: Array.from({ length: 65 }, (_, index) => `model-${index}`) },
  ])("bounds and validates capability arrays %#", (capabilities) => {
    expect(rejectedReason(unsafeAccount({ capabilities: confirmed(capabilities) })))
      .toBe("INVALID_CAPABILITIES");
  });

  it("accepts exact text and list bounds", () => {
    const groups = ["default", ...Array.from({ length: 63 }, (_, index) => `group-${index}`)];
    const models = ["gpt-test", ...Array.from({ length: 63 }, (_, index) => `model-${index}`)];
    const candidate = account("1234567890123456789", {
      stableId: "s".repeat(128),
      groups: confirmed(groups),
      capabilities: confirmed({ platforms: ["openai"], accountTypes: ["shared"], models }),
    });
    expect(decideSchedulerPolicy(request([candidate], { stickinessKey: "k".repeat(256) })).selectedAccountId)
      .toBe("1234567890123456789");
  });

  it.each([
    [unsafeAccount({ stableId: "bad\nvalue" }), "INVALID_STABLE_ID"],
    [unsafeAccount({ stableId: "s".repeat(129) }), "INVALID_STABLE_ID"],
    [unsafeAccount({ stableId: " padded" }), "INVALID_STABLE_ID"],
    [unsafeAccount({ accountId: "12345678901234567890" }), "INVALID_ACCOUNT_ID"],
    [unsafeAccount({ accountId: "01" }), "INVALID_ACCOUNT_ID"],
  ])("enforces strict identifier text bounds %#", (candidate, reason) => {
    expect(rejectedReason(candidate)).toBe(reason);
  });

  it("rejects duplicate canonical IDs without selecting", () => {
    expect(decideSchedulerPolicy(request([account("10"), account("10", { stableId: "other" })])))
      .toMatchObject({ selectedAccountId: null, requestErrors: ["DUPLICATE_ACCOUNT_ID"] });
  });

  it("preserves traditional lower-number-wins account priority", () => {
    const lowerPriorityNumber = account("20", {
      priority: 1,
      accountConcurrencyInFlight: confirmed(9),
      healthRatio: confirmed(0),
      quotaRemainingRatio: confirmed(0),
      cooldownUntilMs: unknown<number | null>(),
    });
    const higherPriorityNumber = account("10", {
      priority: 2,
      accountConcurrencyInFlight: confirmed(0),
      healthRatio: confirmed(1),
      quotaRemainingRatio: confirmed(1),
    });
    const result = decideSchedulerPolicy(request([higherPriorityNumber, lowerPriorityNumber]));
    expect(result.selectedAccountId).toBe("20");
    expect(result.eligible.map((candidate) => candidate.accountId)).toEqual(["20", "10"]);
  });

  it("allows bounded estimated evidence only in non-hard ranking inputs", () => {
    const result = decideSchedulerPolicy(request([account("10", {
      quotaExhausted: estimated(false),
      quotaRemainingRatio: estimated(0.75),
      healthRatio: estimated(0.25),
    })]));
    expect(result.selectedAccountId).toBe("10");
    expect(result.eligible[0].evidence).toMatchObject({
      health: "estimated",
      quotaRemaining: "estimated",
      quotaExhaustion: "estimated",
      accountConcurrency: "confirmed",
      accountRpm: "confirmed",
      userRpm: "confirmed",
    });
  });

  it("is deterministic across repeated and permuted input, with bytewise account ID and stable ID ties", () => {
    const a = account("12", { priority: 1, stableId: "b" });
    const b = account("2", { priority: 1, stableId: "a" });
    const c = account("12", { priority: 1, stableId: "a" });
    const unique = [account("12", { priority: 1, stableId: "b" }), account("2", { priority: 1, stableId: "a" })];
    const first = decideSchedulerPolicy(request(unique));
    const second = decideSchedulerPolicy(request([...unique].reverse()));
    expect(first).toEqual(second);
    expect(first.selectedAccountId).toBe("12");
    expect(decideSchedulerPolicy(request([a, c]))).toMatchObject({ selectedAccountId: null, requestErrors: ["DUPLICATE_ACCOUNT_ID"] });
    expect(b.accountId).toBe("2");
  });

  it("uses a deterministic sticky winner only inside the documented tolerance and fails over when it becomes ineligible", () => {
    const accounts = [account("10", { priority: 10 }), account("20", { priority: 10, healthRatio: confirmed(0.4) })];
    const stickinessKey = Array.from({ length: 100 }, (_, index) => `tenant-${index}`).find((key) =>
      decideSchedulerPolicy(request(accounts, { stickinessKey: key })).selectedAccountId === "20"
    );
    expect(stickinessKey).toBeDefined();
    const keyed = request(accounts, { stickinessKey });
    const first = decideSchedulerPolicy(keyed);
    expect(decideSchedulerPolicy(keyed)).toEqual(first);
    expect(first).toMatchObject({ selectedAccountId: "20", selection: "sticky" });
    const farBehind = decideSchedulerPolicy(request([accounts[0], account("20", { priority: 11 })], { stickinessKey }));
    expect(farBehind.selectedAccountId).toBe("10");
    const failedOver = decideSchedulerPolicy(request([accounts[0], account("20", { priority: 10, schedulable: confirmed(false) })], { stickinessKey }));
    expect(failedOver.selectedAccountId).toBe("10");
  });

  it("returns only safe identifiers, components, evidence flags, and reason codes", () => {
    const result = decideSchedulerPolicy(unsafeRequest([unsafeAccount({
      accountName: "must-not-leak",
      credentials: "must-not-leak",
      proxyUrl: "must-not-leak",
      accessToken: "must-not-leak",
    })])) as unknown as Record<string, unknown>;
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("must-not-leak");
    expect(serialized).not.toMatch(/accountName|accessToken|proxyUrl|credentials/i);
    expect(Object.keys(result).sort()).toEqual(["eligible", "rejected", "requestErrors", "selectedAccountId", "selection"]);
  });
});
