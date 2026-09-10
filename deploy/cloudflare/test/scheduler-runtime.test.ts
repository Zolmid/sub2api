import {
  applyD1Migrations,
  env,
  evictDurableObject,
  type D1Migration,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  buildSchedulerSnapshot,
  decideSchedulerRuntime,
  reserveSchedulerResources,
} from "../src/scheduler-runtime";

type RuntimeEnv = Env & { TEST_MIGRATIONS: D1Migration[] };

const runtimeEnv = env as RuntimeEnv;

const post = (stub: DurableObjectStub, path: string, body: object) =>
  stub.fetch(`https://scheduler-runtime${path}`, {
    method: "POST",
    body: JSON.stringify(body),
  });

const accountStub = (accountID: string) =>
  env.ACCOUNT_LEASE.get(env.ACCOUNT_LEASE.idFromName(`account:${accountID}`));

const rateStub = (scope: "account" | "user" | "api_key", principalID: string) =>
  scope === "account"
    ? accountStub(principalID)
    : scope === "user"
      ? env.USER_RATE_LIMIT.get(env.USER_RATE_LIMIT.idFromName(`user:${principalID}`))
      : env.API_KEY_RATE_LIMIT.get(env.API_KEY_RATE_LIMIT.idFromName(`api-key:${principalID}`));

const acceptedBilling = {
  reserve: async () => ({ ok: true as const }),
  release: async () => true,
};

type TraceFailure = Readonly<{
  namespace: "account" | "user" | "api_key";
  path: "/acquire" | "/rate/reserve" | "/rate/commit";
  status: number;
  mode?: "reject" | "throw_after_commit";
}>;

function tracedSchedulerEnv(events: string[], failure?: TraceFailure): Env {
  const wrap = <T extends Rpc.DurableObjectBranded | undefined>(
    namespace: DurableObjectNamespace<T>,
    label: TraceFailure["namespace"],
  ) => ({
    idFromName: (name: string) => namespace.idFromName(name),
    get: (id: DurableObjectId) => {
      const real = namespace.get(id);
      return {
        fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = input instanceof Request ? input.url
            : typeof input === "string" ? input : input.toString();
          const path = new URL(url).pathname;
          events.push(`${label}:${path}`);
          if (failure?.namespace === label && failure.path === path) {
            if (failure.mode === "throw_after_commit") {
              const response = await real.fetch(input, init);
              await response.text();
              throw new Error("injected response loss");
            }
            return Response.json({ error: "injected" }, { status: failure.status });
          }
          return real.fetch(input, init);
        },
      } as DurableObjectStub<T>;
    },
  }) as DurableObjectNamespace<T>;
  const account = wrap(env.ACCOUNT_LEASE, "account");
  const user = wrap(env.USER_RATE_LIMIT, "user");
  const apiKey = wrap(env.API_KEY_RATE_LIMIT, "api_key");
  return new Proxy(env, {
    get(target, property, receiver) {
      if (property === "ACCOUNT_LEASE") return account;
      if (property === "USER_RATE_LIMIT") return user;
      if (property === "API_KEY_RATE_LIMIT") return apiKey;
      return Reflect.get(target, property, receiver);
    },
  }) as Env;
}

function admissionInput(fixture: Awaited<ReturnType<typeof seed>>, suffix: string) {
  return {
    accountId: fixture.accountA,
    userId: fixture.userID,
    apiKeyId: fixture.keyID,
    admissionId: `admission-${suffix}`,
    requestId: `request-${suffix}`,
    owner: "gateway-trace",
    maxConcurrency: 1,
    accountRpmLimit: 10,
    userRpmLimit: 10,
    apiKeyRpmLimit: 10,
    leaseTtlSeconds: 30,
    reservationTtlSeconds: 30,
    admissionFingerprint: suffix.padEnd(64, "a").slice(0, 64),
  };
}

async function seed(prefix: string) {
  const now = Date.now();
  const userID = `${prefix}01`;
  const keyID = `${prefix}02`;
  const groupA = `${prefix}03`;
  const groupB = `${prefix}04`;
  const accountA = `${prefix}05`;
  const accountB = `${prefix}06`;
  const keyB = `${prefix}07`;
  const created = new Date(now).toISOString();
  const capabilities = JSON.stringify({
    platforms: ["openai"],
    accountTypes: ["oauth"],
    models: ["gpt-runtime"],
  });

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO users(
         id,status,role,concurrency,balance_e8_usd,allowed_group_ids_json,
         restrict_public_groups,created_at,email,password_hash,username,notes,
         rpm_limit,updated_at
       ) VALUES(?,'active','user',1,'0','[]',0,?,'','',?,'',10,?)`,
    ).bind(userID, created, `runtime-user-${prefix}`, created),
    env.DB.prepare(
      `INSERT INTO groups(
         id,name,platform,status,is_exclusive,subscription_type,created_at,updated_at
       ) VALUES(?,?,'openai','active',0,'standard',?,?)`,
    ).bind(groupA, `runtime-a-${prefix}`, created, created),
    env.DB.prepare(
      `INSERT INTO groups(
         id,name,platform,status,is_exclusive,subscription_type,created_at,updated_at
       ) VALUES(?,?,'openai','active',0,'standard',?,?)`,
    ).bind(groupB, `runtime-b-${prefix}`, created, created),
    env.DB.prepare(
      `INSERT INTO api_keys(
         id,user_id,group_id,name,status,key_hash,ip_whitelist_json,
         ip_blacklist_json,created_at,updated_at
       ) VALUES(?,?,?,'runtime-key','active',?,'[]','[]',?,?)`,
    ).bind(keyID, userID, groupA, prefix.padEnd(64, "a").slice(0, 64), created, created),
    env.DB.prepare(
      `INSERT INTO api_keys(
         id,user_id,group_id,name,status,key_hash,ip_whitelist_json,
         ip_blacklist_json,created_at,updated_at
       ) VALUES(?,?,?,'runtime-key-b','active',?,'[]','[]',?,?)`,
    ).bind(keyB, userID, groupB, prefix.padEnd(64, "b").slice(0, 64), created, created),
    ...[accountA, accountB].map((accountID, index) => env.DB.prepare(
      `INSERT INTO accounts(
         id,name,platform,type,status,schedulable,priority,max_concurrency,
         credential_envelope,extra_json,created_at,updated_at
       ) VALUES(?,?,'openai','oauth','active',1,?,1,?,'{}',?,?)`,
    ).bind(
      accountID,
      `runtime-account-${prefix}-${index}`,
      index,
      `PRIVATE-CREDENTIAL-${accountID}`,
      created,
      created,
    )),
    ...[accountA, accountB].flatMap((accountID) => [groupA, groupB].map((groupID) =>
      env.DB.prepare("INSERT INTO account_groups(account_id,group_id) VALUES(?,?)")
        .bind(accountID, groupID))),
    ...[accountA, accountB].map((accountID) => env.DB.prepare(
      `INSERT INTO scheduler_account_runtime(
         account_id,capabilities_json,capabilities_evidence,capabilities_source,
         capabilities_observed_at_ms,capabilities_fresh_until_ms,
         quota_exhausted,quota_remaining_bps,quota_evidence,quota_source,
         quota_observed_at_ms,quota_fresh_until_ms,version,updated_at_ms
       ) VALUES(?,?,'confirmed','account-sync',?,?,0,9000,'confirmed',
                'quota-probe',?,?,1,?)`,
    ).bind(accountID, capabilities, now, now + 60_000, now, now + 60_000, now)),
    ...([
      ["user", userID],
      ["api_key", keyID],
      ["api_key", keyB],
      ["account", accountA],
      ["account", accountB],
    ] as const).map(([scope, principalID]) => env.DB.prepare(
      `INSERT INTO scheduler_principal_limits(
         scope,principal_id,rpm_limit,evidence,source,observed_at_ms,
         fresh_until_ms,version,updated_at_ms
       ) VALUES(?,?,10,'confirmed','management-config',?,?,1,?)`,
    ).bind(scope, principalID, now, now + 60_000, now)),
  ]);

  for (const accountID of [accountA, accountB]) {
    for (const observation of [
      { kind: "health_bps", value: 9_000 },
      { kind: "cooldown_until_ms", value: null },
      { kind: "temporary_until_ms", value: null },
    ]) {
      const response = await post(accountStub(accountID), "/state/update", {
        account_id: accountID,
        evidence: "confirmed",
        source: "provider-probe",
        observed_at_ms: now,
        fresh_until_ms: now + 60_000,
        version: 1,
        ...observation,
      });
      expect(response.status).toBe(200);
      await response.text();
    }
  }

  return { now, userID, keyID, keyB, groupA, groupB, accountA, accountB };
}

function request(fixture: Awaited<ReturnType<typeof seed>>, group = fixture.groupA) {
  return {
    nowMs: fixture.now + 1,
    userId: fixture.userID,
    apiKeyId: group === fixture.groupB ? fixture.keyB : fixture.keyID,
    requiredGroup: group,
    platform: "openai",
    accountType: "oauth",
    model: "gpt-runtime",
    stickinessKey: "sticky-runtime",
  };
}

describe("scheduler runtime migration", () => {
  it("is present on a fresh test database, is migration-reentrant, and isolates constraint failure", async () => {
    const tables = await env.DB.prepare(
      `SELECT name FROM sqlite_master
       WHERE type='table' AND name IN ('scheduler_account_runtime','scheduler_principal_limits')
       ORDER BY name`,
    ).all<{ name: string }>();
    expect(tables.results.map((row) => row.name)).toEqual([
      "scheduler_account_runtime",
      "scheduler_principal_limits",
    ]);

    await expect(applyD1Migrations(env.DB, runtimeEnv.TEST_MIGRATIONS)).resolves.toBeUndefined();
    await expect(applyD1Migrations(env.DB, runtimeEnv.TEST_MIGRATIONS)).resolves.toBeUndefined();

    await expect(env.DB.prepare(
      `INSERT INTO scheduler_principal_limits(
         scope,principal_id,rpm_limit,evidence,source,observed_at_ms,
         fresh_until_ms,version,updated_at_ms
       ) VALUES('user','099',0,'confirmed','test',1,2,1,1)`,
    ).run()).rejects.toThrow();
    const invalid = await env.DB.prepare(
      "SELECT count(*) count FROM scheduler_principal_limits WHERE principal_id='099'",
    ).first<{ count: number }>();
    expect(invalid?.count).toBe(0);
  });
});

describe("scheduler runtime", () => {
  it("builds source-labelled D1/DO snapshots without credential or body leakage", async () => {
    const fixture = await seed("81");
    const snapshot = await buildSchedulerSnapshot(env, request(fixture));
    expect(snapshot.runtimeErrors).toEqual([]);
    expect(snapshot.policyRequest.accounts).toHaveLength(2);
    expect(snapshot.policyRequest.accounts[0]).toMatchObject({
      active: { kind: "confirmed", value: true },
      groups: { kind: "confirmed", value: [fixture.groupA] },
      capabilities: { kind: "confirmed" },
      accountConcurrencyInFlight: { kind: "confirmed", value: 0 },
      accountRpmUsed: { kind: "confirmed", value: 0 },
      healthRatio: { kind: "confirmed", value: 0.9 },
    });
    expect(snapshot.apiKeyRate).toMatchObject({
      source: "management-config",
      limit: { kind: "confirmed", value: 10 },
      used: { kind: "confirmed", value: 0 },
    });
    expect(snapshot.accountProvenance[0]).toMatchObject({
      capabilities: {
        evidence: "confirmed",
        source: "account-sync",
        observedAtMs: fixture.now,
        freshUntilMs: fixture.now + 60_000,
        version: 1,
      },
      quota: { evidence: "confirmed", source: "quota-probe", version: 1 },
      health: { evidence: "confirmed", source: "provider-probe", version: 1 },
      cooldown: { evidence: "confirmed", source: "provider-probe", version: 1 },
    });
    const serialized = JSON.stringify(snapshot);
    expect(serialized).not.toContain("PRIVATE-CREDENTIAL");
    expect(serialized.toLowerCase()).not.toContain("authorization");
    expect(serialized.toLowerCase()).not.toContain("request_body");
    expect(Object.keys(snapshot.policyRequest.accounts[0]).sort()).not.toContain("credential_envelope");
  });

  it("uses one account object across groups and deterministically fails over", async () => {
    const fixture = await seed("82");
    const first = await decideSchedulerRuntime(env, request(fixture));
    const repeated = await decideSchedulerRuntime(env, request(fixture));
    expect(repeated).toEqual(first);
    expect(first.ready).toBe(true);
    const selected = first.decision.selectedAccountId!;
    const other = selected === fixture.accountA ? fixture.accountB : fixture.accountA;

    const lease = await post(accountStub(selected), "/acquire", {
      account_id: selected,
      request_id: "cross-group-request",
      owner: "gateway-a",
      max_concurrency: 1,
      ttl_seconds: 30,
      admission_fingerprint: "1".repeat(64),
    });
    expect(lease.status).toBe(200);
    const acrossGroup = await buildSchedulerSnapshot(env, request(fixture, fixture.groupB));
    const shared = acrossGroup.policyRequest.accounts.find((account) => account.accountId === selected)!;
    expect(shared.accountConcurrencyInFlight).toEqual({ kind: "confirmed", value: 1 });

    const failedOver = await decideSchedulerRuntime(env, request(fixture, fixture.groupB));
    expect(failedOver.decision.selectedAccountId).toBe(other);
  });

  it("serializes cross-group admissions through one account fence", async () => {
    const fixture = await seed("90");
    let billingReservations = 0;
    const billing = {
      reserve: async () => {
        billingReservations += 1;
        return { ok: true as const };
      },
      release: async () => true,
    };
    const base = {
      accountId: fixture.accountA,
      userId: fixture.userID,
      owner: "gateway-cross-group",
      maxConcurrency: 1,
      accountRpmLimit: 10,
      userRpmLimit: 10,
      apiKeyRpmLimit: 10,
      leaseTtlSeconds: 30,
      reservationTtlSeconds: 30,
    };
    const results = await Promise.all([
      reserveSchedulerResources(env, {
        ...base,
        apiKeyId: fixture.keyID,
        admissionId: "cross-group-a",
        requestId: "cross-group-a",
        admissionFingerprint: "c".repeat(64),
      }, billing),
      reserveSchedulerResources(env, {
        ...base,
        apiKeyId: fixture.keyB,
        admissionId: "cross-group-b",
        requestId: "cross-group-b",
        admissionFingerprint: "d".repeat(64),
      }, billing),
    ]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(results.filter((result) => !result.ok)).toHaveLength(1);
    expect(billingReservations).toBe(1);
    const inspected = await post(accountStub(fixture.accountA), "/inspect", {
      account_id: fixture.accountA,
    });
    expect(await inspected.json()).toMatchObject({ in_flight: 1 });
  });

  it("reserves account/user/key RPM in fixed order and preserves duplicate admission", async () => {
    const fixture = await seed("83");
    const input = {
      accountId: fixture.accountA,
      userId: fixture.userID,
      apiKeyId: fixture.keyID,
      admissionId: "admission-complete",
      requestId: "request-complete",
      owner: "gateway-a",
      maxConcurrency: 1,
      accountRpmLimit: 10,
      userRpmLimit: 10,
      apiKeyRpmLimit: 10,
      leaseTtlSeconds: 30,
      reservationTtlSeconds: 30,
      admissionFingerprint: "a".repeat(64),
    };
    const admitted = await reserveSchedulerResources(env, input, acceptedBilling);
    expect(admitted).toMatchObject({
      ok: true,
      acquisitionOrder: [
        "account_lease",
        "account_rpm",
        "user_rpm",
        "api_key_rpm",
        "billing_reservation",
      ],
    });
    const duplicate = await reserveSchedulerResources(env, input, acceptedBilling);
    expect(duplicate).toMatchObject({ ok: true });
    for (const [scope, principalID] of [
      ["account", fixture.accountA],
      ["user", fixture.userID],
      ["api_key", fixture.keyID],
    ] as const) {
      const inspected = await post(rateStub(scope, principalID), "/rate/inspect", {
        scope,
        principal_id: principalID,
        rpm_limit: 10,
      });
      expect(await inspected.json()).toMatchObject({ used: 1, evidence: "confirmed" });
    }
  });

  it("moves sticky selection when the chosen account RPM window is exhausted", async () => {
    const fixture = await seed("86");
    const initial = await decideSchedulerRuntime(env, request(fixture));
    const selected = initial.decision.selectedAccountId!;
    const other = selected === fixture.accountA ? fixture.accountB : fixture.accountA;
    await env.DB.prepare(
      `UPDATE scheduler_principal_limits SET rpm_limit=1
       WHERE scope='account' AND principal_id=?`,
    ).bind(selected).run();
    const body = {
      scope: "account",
      principal_id: selected,
      admission_id: "sticky-rpm-admission",
      request_id: "sticky-rpm-request",
      account_id: selected,
      rpm_limit: 1,
      reservation_ttl_seconds: 30,
      admission_fingerprint: "2".repeat(64),
    };
    expect((await post(rateStub("account", selected), "/rate/reserve", body)).status).toBe(200);
    expect((await post(rateStub("account", selected), "/rate/commit", body)).status).toBe(200);
    const failedOver = await decideSchedulerRuntime(env, request(fixture));
    expect(failedOver.decision.selectedAccountId).toBe(other);
    expect(failedOver.decision.rejected).toContainEqual({
      accountId: selected,
      stableId: selected,
      reason: "ACCOUNT_RPM_EXHAUSTED",
    });
  });

  it("moves sticky selection on cooldown and rejects a stale clear", async () => {
    const fixture = await seed("87");
    const initial = await decideSchedulerRuntime(env, request(fixture));
    const selected = initial.decision.selectedAccountId!;
    const other = selected === fixture.accountA ? fixture.accountB : fixture.accountA;
    const update = {
      account_id: selected,
      kind: "cooldown_until_ms",
      evidence: "confirmed",
      source: "provider-probe",
      value: fixture.now + 30_000,
      observed_at_ms: fixture.now + 2,
      fresh_until_ms: fixture.now + 60_000,
      version: 2,
    };
    expect((await post(accountStub(selected), "/state/update", update)).status).toBe(200);
    expect((await post(accountStub(selected), "/state/update", {
      ...update,
      value: null,
      observed_at_ms: fixture.now + 1,
      version: 3,
    })).status).toBe(200);
    const moved = await decideSchedulerRuntime(env, request(fixture));
    expect(moved.decision.selectedAccountId).toBe(other);
    expect(moved.decision.rejected).toContainEqual({
      accountId: selected,
      stableId: selected,
      reason: "COOLDOWN_ACTIVE",
    });
  });

  it("compensates newly acquired lease and pending counters when a later DO rejects", async () => {
    const fixture = await seed("84");
    const keyStub = rateStub("api_key", fixture.keyID);
    const blocking = {
      scope: "api_key",
      principal_id: fixture.keyID,
      admission_id: "blocking-admission",
      request_id: "blocking-request",
      account_id: fixture.accountB,
      rpm_limit: 1,
      reservation_ttl_seconds: 30,
      admission_fingerprint: "3".repeat(64),
    };
    expect((await post(keyStub, "/rate/reserve", blocking)).status).toBe(200);
    expect((await post(keyStub, "/rate/commit", blocking)).status).toBe(200);

    const rejected = await reserveSchedulerResources(env, {
      accountId: fixture.accountA,
      userId: fixture.userID,
      apiKeyId: fixture.keyID,
      admissionId: "compensated-admission",
      requestId: "compensated-request",
      owner: "gateway-b",
      maxConcurrency: 1,
      accountRpmLimit: 10,
      userRpmLimit: 10,
      apiKeyRpmLimit: 1,
      leaseTtlSeconds: 30,
      reservationTtlSeconds: 30,
      admissionFingerprint: "b".repeat(64),
    }, acceptedBilling);
    expect(rejected).toEqual({
      ok: false,
      failedStep: "api_key_rpm",
      status: 429,
      committedScopes: [],
      compensationFailures: [],
    });
    const account = await post(accountStub(fixture.accountA), "/inspect", {
      account_id: fixture.accountA,
    });
    expect(await account.json()).toMatchObject({ in_flight: 0 });
    for (const [scope, principalID] of [
      ["account", fixture.accountA],
      ["user", fixture.userID],
    ] as const) {
      const inspected = await post(rateStub(scope, principalID), "/rate/inspect", {
        scope,
        principal_id: principalID,
        rpm_limit: 10,
      });
      expect(await inspected.json()).toMatchObject({ used: 0 });
    }
  });

  it("fails closed when D1 capability freshness expires and after DO eviction", async () => {
    const fixture = await seed("85");
    await env.DB.prepare(
      "UPDATE scheduler_account_runtime SET capabilities_fresh_until_ms=? WHERE account_id=?",
    ).bind(fixture.now, fixture.accountA).run();
    await evictDurableObject(accountStub(fixture.accountA));
    const decision = await decideSchedulerRuntime(env, request(fixture));
    const account = decision.snapshot.policyRequest.accounts.find(
      (candidate) => candidate.accountId === fixture.accountA,
    )!;
    expect(account.capabilities).toEqual({ kind: "unknown" });
    expect(decision.decision.rejected).toContainEqual({
      accountId: fixture.accountA,
      stableId: fixture.accountA,
      reason: "CAPABILITY_UNKNOWN",
    });
  });

  it("places billing last and reverses scheduler reservations when billing rejects", async () => {
    const fixture = await seed("88");
    const result = await reserveSchedulerResources(env, {
      accountId: fixture.accountA,
      userId: fixture.userID,
      apiKeyId: fixture.keyID,
      admissionId: "billing-reject",
      requestId: "billing-reject",
      owner: "gateway-a",
      maxConcurrency: 1,
      accountRpmLimit: 10,
      userRpmLimit: 10,
      apiKeyRpmLimit: 10,
      leaseTtlSeconds: 30,
      reservationTtlSeconds: 30,
      admissionFingerprint: "8".repeat(64),
    }, {
      reserve: async () => ({
        ok: false,
        status: 503,
        failedStep: "billing_reservation",
      }),
      release: async () => true,
    });
    expect(result).toEqual({
      ok: false,
      failedStep: "billing_reservation",
      status: 503,
      committedScopes: ["account", "user", "api_key"],
      compensationFailures: [],
    });
    const inspected = await post(accountStub(fixture.accountA), "/inspect", {
      account_id: fixture.accountA,
    });
    expect(await inspected.json()).toMatchObject({ in_flight: 0 });
    for (const [scope, principalID] of [
      ["account", fixture.accountA],
      ["user", fixture.userID],
      ["api_key", fixture.keyID],
    ] as const) {
      const rate = await post(rateStub(scope, principalID), "/rate/inspect", {
        scope,
        principal_id: principalID,
        rpm_limit: 10,
      });
      expect(await rate.json()).toMatchObject({ used: 0 });
    }
  });

  it("does not reserve billing when a preceding RPM commit fails", async () => {
    const fixture = await seed("89");
    const realNamespace = env.API_KEY_RATE_LIMIT;
    const failingNamespace = {
      idFromName: (name: string) => realNamespace.idFromName(name),
      get: (id: DurableObjectId) => {
        const real = realNamespace.get(id);
        return {
          fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = input instanceof Request ? input.url
              : typeof input === "string" ? input : input.toString();
            if (new URL(url).pathname === "/rate/commit") {
              return Response.json({ error: "injected" }, { status: 503 });
            }
            return real.fetch(input, init);
          },
        } as DurableObjectStub;
      },
    } as DurableObjectNamespace;
    const targetEnv = new Proxy(env, {
      get(target, property, receiver) {
        if (property === "API_KEY_RATE_LIMIT") return failingNamespace;
        return Reflect.get(target, property, receiver);
      },
    }) as Env;
    let billingReserveCalls = 0;
    const result = await reserveSchedulerResources(targetEnv, {
      accountId: fixture.accountA,
      userId: fixture.userID,
      apiKeyId: fixture.keyID,
      admissionId: "commit-failure",
      requestId: "commit-failure",
      owner: "gateway-a",
      maxConcurrency: 1,
      accountRpmLimit: 10,
      userRpmLimit: 10,
      apiKeyRpmLimit: 10,
      leaseTtlSeconds: 30,
      reservationTtlSeconds: 30,
      admissionFingerprint: "9".repeat(64),
    }, {
      reserve: async () => {
        billingReserveCalls += 1;
        return { ok: true };
      },
      release: async () => false,
    });
    expect(result).toMatchObject({
      ok: false,
      failedStep: "api_key_rpm_commit",
      status: 503,
      committedScopes: ["account", "user"],
      compensationFailures: [],
    });
    expect(billingReserveCalls).toBe(0);
  });

  it("executes the full account-first acquisition order", async () => {
    const fixture = await seed("91");
    const events: string[] = [];
    const result = await reserveSchedulerResources(
      tracedSchedulerEnv(events),
      admissionInput(fixture, "1"),
      {
        reserve: async () => {
          events.push("billing:/reserve");
          return { ok: true };
        },
        release: async () => true,
      },
    );
    expect(result).toMatchObject({ ok: true });
    expect(events).toEqual([
      "account:/acquire",
      "account:/rate/reserve",
      "user:/rate/reserve",
      "api_key:/rate/reserve",
      "account:/rate/commit",
      "user:/rate/commit",
      "api_key:/rate/commit",
      "billing:/reserve",
    ]);
  });

  it("compensates every RPM reservation failure in exact reverse order", async () => {
    const cases = [
      {
        prefix: "92",
        failed: "account" as const,
        expected: ["account:/acquire", "account:/rate/reserve", "account:/release"],
      },
      {
        prefix: "93",
        failed: "user" as const,
        expected: [
          "account:/acquire", "account:/rate/reserve", "user:/rate/reserve",
          "account:/rate/rollback", "account:/release",
        ],
      },
      {
        prefix: "94",
        failed: "api_key" as const,
        expected: [
          "account:/acquire", "account:/rate/reserve", "user:/rate/reserve",
          "api_key:/rate/reserve", "user:/rate/rollback",
          "account:/rate/rollback", "account:/release",
        ],
      },
    ];
    for (const testCase of cases) {
      const fixture = await seed(testCase.prefix);
      const events: string[] = [];
      const result = await reserveSchedulerResources(
        tracedSchedulerEnv(events, {
          namespace: testCase.failed,
          path: "/rate/reserve",
          status: 429,
        }),
        admissionInput(fixture, testCase.prefix),
        acceptedBilling,
      );
      expect(result).toMatchObject({ ok: false, compensationFailures: [] });
      expect(events).toEqual(testCase.expected);
    }
  });

  it("compensates every RPM commit failure before billing in exact reverse order", async () => {
    for (const [prefix, failed] of [
      ["95", "account"],
      ["96", "user"],
      ["97", "api_key"],
    ] as const) {
      const fixture = await seed(prefix);
      const events: string[] = [];
      let billingCalls = 0;
      const result = await reserveSchedulerResources(
        tracedSchedulerEnv(events, {
          namespace: failed,
          path: "/rate/commit",
          status: 503,
        }),
        admissionInput(fixture, prefix),
        {
          reserve: async () => {
            billingCalls += 1;
            return { ok: true };
          },
          release: async () => true,
        },
      );
      expect(result).toMatchObject({ ok: false, compensationFailures: [] });
      expect(billingCalls).toBe(0);
      expect(events.slice(-4)).toEqual([
        "api_key:/rate/rollback",
        "user:/rate/rollback",
        "account:/rate/rollback",
        "account:/release",
      ]);
    }
  });

  it("aborts the exact account lease when acquire authority is unknown", async () => {
    const fixture = await seed("99");
    const events: string[] = [];
    const result = await reserveSchedulerResources(
      tracedSchedulerEnv(events, {
        namespace: "account",
        path: "/acquire",
        status: 503,
        mode: "throw_after_commit",
      }),
      admissionInput(fixture, "99"),
      acceptedBilling,
    );
    expect(result).toEqual({
      ok: false,
      failedStep: "account_lease",
      status: 503,
      committedScopes: [],
      compensationFailures: [],
    });
    expect(events).toEqual(["account:/acquire", "account:/abort"]);
    const inspected = await post(accountStub(fixture.accountA), "/inspect", {
      account_id: fixture.accountA,
    });
    expect(await inspected.json()).toMatchObject({ in_flight: 0 });
  });

  it("rolls back a rate reservation whose response authority is unknown", async () => {
    const cases = [
      {
        prefix: "71",
        failed: "account" as const,
        expected: [
          "account:/acquire", "account:/rate/reserve",
          "account:/rate/rollback", "account:/release",
        ],
      },
      {
        prefix: "72",
        failed: "user" as const,
        expected: [
          "account:/acquire", "account:/rate/reserve", "user:/rate/reserve",
          "user:/rate/rollback", "account:/rate/rollback", "account:/release",
        ],
      },
      {
        prefix: "73",
        failed: "api_key" as const,
        expected: [
          "account:/acquire", "account:/rate/reserve", "user:/rate/reserve",
          "api_key:/rate/reserve", "api_key:/rate/rollback",
          "user:/rate/rollback", "account:/rate/rollback", "account:/release",
        ],
      },
    ];
    for (const testCase of cases) {
      const fixture = await seed(testCase.prefix);
      const events: string[] = [];
      const result = await reserveSchedulerResources(
        tracedSchedulerEnv(events, {
          namespace: testCase.failed,
          path: "/rate/reserve",
          status: 503,
          mode: "throw_after_commit",
        }),
        admissionInput(fixture, testCase.prefix),
        acceptedBilling,
      );
      expect(result).toMatchObject({
        ok: false,
        compensationFailures: [],
      });
      expect(events).toEqual(testCase.expected);
    }
  });

  it("fails closed when unknown billing authority cannot be compensated", async () => {
    const fixture = await seed("98");
    const events: string[] = [];
    const result = await reserveSchedulerResources(
      tracedSchedulerEnv(events),
      admissionInput(fixture, "8"),
      {
        reserve: async () => {
          events.push("billing:/reserve");
          throw new Error("injected response loss");
        },
        release: async () => {
          events.push("billing:/release");
          return false;
        },
      },
    );
    expect(result).toMatchObject({
      ok: false,
      failedStep: "billing_reservation",
      status: 503,
      compensationFailures: ["billing_reservation_release"],
    });
    expect(events.slice(-5)).toEqual([
      "billing:/release",
      "api_key:/rate/rollback",
      "user:/rate/rollback",
      "account:/rate/rollback",
      "account:/release",
    ]);
  });
});
