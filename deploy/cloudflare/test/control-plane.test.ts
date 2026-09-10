import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { controlPlane, recoverStaleAdmissions } from "../src/control-plane";
import {
  BRIDGE_VERSION,
  D1_BASE_SCHEMA_VERSION,
  USAGE_EVENT_TYPE,
  USAGE_SCHEMA_VERSION,
  type Completion,
} from "../src/contracts";
import worker from "../src/index";

const internalRequest = (
  path: string,
  body: object,
  owner = "container-test-a",
): Request =>
  new Request(`http://sub2api.internal${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Sub2API-Bridge-Version": BRIDGE_VERSION,
      "X-Sub2API-Container-Id": owner,
    },
    body: JSON.stringify(body),
  });

const call = (path: string, body: object, targetEnv: Env = env, owner?: string) =>
  controlPlane(internalRequest(path, body, owner), targetEnv);

type Admission = {
  account: {
    id: string;
    type: string;
    platform: string;
    credentials: Record<string, string>;
    extra: Record<string, unknown>;
  };
  upstream_model: string;
  price_card: {
    version_id: string;
    digest: string;
    max_reservation_e8_usd: string;
    rule: { version_id: string; model_pattern: string; match_kind: string };
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

const admit = async (
  requestID: string,
  targetEnv: Env = env,
  owner = "container-test-a",
): Promise<Admission> => {
  const response = await call(
    "/v1/requests/admit",
    {
      request_id: requestID,
      api_key_id: "3001",
      group_id: "2001",
      model: "fixture-model",
      lease_ttl_seconds: 30,
    },
    targetEnv,
    owner,
  );
  expect(response.status).toBe(200);
  return response.json<Admission>();
};

const release = (admission: Admission, targetEnv: Env = env) =>
  call(
    "/v1/leases/release",
    admission.lease,
    targetEnv,
    admission.lease.owner,
  );

const start = (admission: Admission, targetEnv: Env = env) =>
  call(
    "/v1/requests/start",
    {
      request_id: admission.lease.request_id,
      api_key_id: "3001",
      account_id: admission.account.id,
      lease_id: admission.lease.lease_id,
      lease_epoch: admission.lease.epoch,
      model: "fixture-model",
      upstream_model: admission.upstream_model,
    },
    targetEnv,
    admission.lease.owner,
  );

const completionFor = (
  admission: Admission,
  overrides: Partial<Completion> = {},
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
  usage_state: "confirmed",
  input_tokens: "11",
  image_input_tokens: "0",
  output_tokens: "4",
  image_output_tokens: "0",
  cache_creation_tokens: "0",
  cache_creation_5m_tokens: "0",
  cache_creation_1h_tokens: "0",
  cache_read_tokens: "0",
  service_tier: "",
  reasoning_effort: "",
  model: "fixture-model",
  upstream_model: admission.upstream_model,
  upstream_request_id: "fixture-completion",
  duration_ms: "0",
  ...overrides,
});

const overrideEnv = (overrides: Partial<Record<keyof Env, unknown>>): Env =>
  new Proxy(env, {
    get(target, property, receiver) {
      if (Object.prototype.hasOwnProperty.call(overrides, property)) {
        return overrides[property as keyof Env];
      }
      return Reflect.get(target, property, receiver);
    },
  }) as Env;

const failingQueueEnv = (): Env =>
  overrideEnv({
    USAGE_QUEUE: {
      send: async () => {
        throw new Error("injected queue failure");
      },
    } as unknown as Queue,
  });

async function seedAccountScheduler(accountID: string): Promise<void> {
  const observedAt = Date.now();
  const freshUntil = observedAt + 4 * 60_000;
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO scheduler_account_runtime(account_id,capabilities_json,capabilities_evidence,capabilities_source,capabilities_observed_at_ms,capabilities_fresh_until_ms,quota_exhausted,quota_remaining_bps,quota_evidence,quota_source,quota_observed_at_ms,quota_fresh_until_ms,version,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    ).bind(
      accountID,
      '{"platforms":["openai"],"accountTypes":["apikey"],"models":["fixture-model"]}',
      "confirmed", "test.fixture", observedAt, freshUntil, 0, 10000,
      "confirmed", "test.fixture", observedAt, freshUntil, 1, observedAt,
    ),
    env.DB.prepare(
      "INSERT INTO scheduler_principal_limits(scope,principal_id,rpm_limit,evidence,source,observed_at_ms,fresh_until_ms,version,updated_at_ms) VALUES('account',?,100,'confirmed','test.fixture',?,?,1,?)",
    ).bind(accountID, observedAt, freshUntil, observedAt),
  ]);
  const stub = env.ACCOUNT_LEASE.get(
    env.ACCOUNT_LEASE.idFromName(`account:${accountID}`),
  );
  for (const [kind, value] of [
    ["health_bps", 10000],
    ["cooldown_until_ms", null],
    ["temporary_until_ms", null],
  ] as const) {
    const response = await stub.fetch("https://lease/state/update", {
      method: "POST",
      body: JSON.stringify({
        account_id: accountID,
        kind,
        value,
        evidence: "confirmed",
        source: "test.fixture",
        observed_at_ms: observedAt,
        fresh_until_ms: freshUntil,
        version: 1,
      }),
    });
    expect(response.status).toBe(200);
  }
}

describe("D1-backed private control plane", () => {
  it("installs the schema with canonical decimal constraints", async () => {
    expect(
      await env.DB.prepare(
        "SELECT value FROM schema_metadata WHERE key='cloudflare_bridge_schema_version'",
      ).first("value"),
    ).toBe(D1_BASE_SCHEMA_VERSION);
    await expect(
      env.DB.prepare(
        `INSERT INTO users(
           id,status,role,concurrency,balance_e8_usd,
           allowed_group_ids_json,restrict_public_groups,created_at
         ) VALUES('01','active','user',1,'1','[]',0,'now')`,
      ).run(),
    ).rejects.toThrow();
  });

  it("resolves only active users and never stores the raw API key", async () => {
    const response = await call("/v1/auth/resolve", { key: "fixture-test-key" });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      api_key: {
        id: "3001", user_id: "1001", name: "fixture active", status: "active", group_id: "2001",
        ip_whitelist: [], ip_blacklist: [], expires_at: null,
      },
      user: {
        id: "1001", status: "active", role: "user", concurrency: 1, balance_positive: true,
        allowed_group_ids: ["2001"], restrict_public_groups: false,
      },
      group: {
        id: "2001", name: "fixture-group", platform: "openai", status: "active",
        is_exclusive: false, subscription_type: "standard",
      },
    });

    const stored = await env.DB.prepare(
      "SELECT key_hash FROM api_keys WHERE id='3001'",
    ).first<{ key_hash: string }>();
    expect(stored?.key_hash).toHaveLength(64);
    expect(stored?.key_hash).not.toContain("fixture-test-key");

    expect(
      (await call("/v1/auth/resolve", { key: "fixture-disabled-key" })).status,
    ).toBe(404);
    expect((await call("/v1/auth/resolve", { key: "unknown" })).status).toBe(404);
  });

  it("linearizes warm resolves through D1 for standard, exclusive, and subscription groups", async () => {
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(200);
    await env.DB.prepare("UPDATE users SET allowed_group_ids_json='[]', restrict_public_groups=1 WHERE id='1001'").run();
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(404);

    await env.DB.prepare("UPDATE users SET allowed_group_ids_json='[\"2001\"]' WHERE id='1001'").run();
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(200);
    await env.DB.prepare("UPDATE groups SET is_exclusive=1 WHERE id='2001'").run();
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(200);
    await env.DB.prepare("UPDATE users SET allowed_group_ids_json='[]' WHERE id='1001'").run();
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(404);

    await env.DB.batch([
      env.DB.prepare("UPDATE groups SET is_exclusive=0, subscription_type='subscription' WHERE id='2001'"),
      env.DB.prepare("UPDATE users SET allowed_group_ids_json='[\"2001\"]', restrict_public_groups=0 WHERE id='1001'"),
    ]);
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(404);
    await env.DB.prepare(
      `INSERT INTO user_subscriptions(id,user_id,group_id,starts_at,expires_at,status,assigned_at,created_at,updated_at,deleted_at)
       VALUES('9001','1001','2001','2026-01-01T00:00:00.000Z','2028-01-01T00:00:00.000Z','active','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z',NULL)`,
    ).run();
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(200);
    await env.DB.prepare("UPDATE user_subscriptions SET status='suspended', version=version+1 WHERE id='9001'").run();
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(404);
    await env.DB.prepare("UPDATE user_subscriptions SET status='active', expires_at='2026-01-02T00:00:00.000Z', version=version+1 WHERE id='9001'").run();
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(404);
    await env.DB.prepare("UPDATE user_subscriptions SET expires_at='2028-01-01T00:00:00.000Z', deleted_at='2026-09-06T00:00:00.000Z', version=version+1 WHERE id='9001'").run();
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(404);
  });

  it.each([
    ["rotated API key", "UPDATE api_keys SET key_hash='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE id='3001'"],
    ["revoked API key", "UPDATE api_keys SET status='disabled' WHERE id='3001'"],
    ["disabled user", "UPDATE users SET status='disabled' WHERE id='1001'"],
    ["deleted user", "UPDATE users SET deleted_at='2026-09-06T00:00:00.000Z' WHERE id='1001'"],
    ["disabled group", "UPDATE groups SET status='disabled' WHERE id='2001'"],
    ["deleted group", "UPDATE groups SET deleted_at='2026-09-06T00:00:00.000Z' WHERE id='2001'"],
  ])("fails closed on a warm cache after %s", async (_label, mutation) => {
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(200);
    await env.DB.exec(mutation);
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(404);
  });

  it("does not authorize malformed auth-cache rows or D1 storage failures", async () => {
    const unavailable = overrideEnv({
      DB: { prepare: () => { throw new Error("injected D1 failure"); } } as unknown as D1Database,
    });
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" }, unavailable)).status).toBe(503);
    const malformed = overrideEnv({
      DB: { prepare: () => ({ bind: () => ({ first: async () => ({ credential_digest: "not-a-digest" }) }) }) } as unknown as D1Database,
    });
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" }, malformed)).status).toBe(503);
  });

  it("keeps API-key last-used metadata monotonic", async () => {
    expect(
      (
        await call("/v1/auth/touch", {
          api_key_id: "3001",
          used_at: "2026-09-06T12:00:00+00:00",
        })
      ).status,
    ).toBe(204);
    expect(
      (
        await call("/v1/auth/touch", {
          api_key_id: "3001",
          used_at: "2026-09-06T11:00:00Z",
        })
      ).status,
    ).toBe(204);
    expect(
      await env.DB.prepare("SELECT last_used_at FROM api_keys WHERE id='3001'").first(
        "last_used_at",
      ),
    ).toBe("2026-09-06T12:00:00.000Z");
  });

  it("returns a Go-compatible admission and persists the Container owner", async () => {
    const admission = await admit("request-admission-compatible");
    expect(admission).toMatchObject({
      account: {
        id: "4001",
        platform: "openai",
        type: "apikey",
        credentials: {
          api_key: "fixture-upstream-token",
          base_url: "https://mock.upstream",
        },
        extra: { openai_responses_supported: false },
      },
      upstream_model: "mock-upstream-model",
      price_card: {
        version_id: "fixture-v1",
        digest: "37c6c3745cdf65cf1c54ddbcb1a205657ea2d4fabb0121807a9f99aefcbd5d1d",
        max_reservation_e8_usd: "100000000000",
        rule: {
          version_id: "fixture-v1",
          model_pattern: "fixture-model",
          match_kind: "exact",
        },
      },
      lease: {
        account_id: "4001",
        request_id: "request-admission-compatible",
        owner: "container-test-a",
      },
    });
    expect(Date.parse(admission.lease.expires_at)).toBeGreaterThan(Date.now());

    const row = await env.DB.prepare(
      "SELECT owner,upstream_model,pricing_version_id,pricing_digest,pricing_rule_pattern FROM gateway_requests WHERE request_id=?",
    )
      .bind(admission.lease.request_id)
      .first<{ owner: string; upstream_model: string; pricing_version_id: string; pricing_digest: string; pricing_rule_pattern: string }>();
    expect(row).toEqual({
      owner: "container-test-a",
      upstream_model: "mock-upstream-model",
      pricing_version_id: admission.price_card.version_id,
      pricing_digest: admission.price_card.digest,
      pricing_rule_pattern: admission.price_card.rule.model_pattern,
    });
    expect((await release(admission)).status).toBe(200);
  });

  it("replays bounded scheduled expiry without double-refunding or retaining a lease", async () => {
    const admission = await admit("request-scheduled-recovery");
    await env.DB.prepare(
      "UPDATE billing_reservations SET created_at='2000-01-01T00:00:00Z' WHERE request_id=?",
    ).bind(admission.lease.request_id).run();
    await recoverStaleAdmissions(env);
    await recoverStaleAdmissions(env);
    expect(await env.DB.prepare(
      "SELECT state FROM billing_reservations WHERE request_id=?",
    ).bind(admission.lease.request_id).first("state")).toBe("released");
    const inspected = await env.ACCOUNT_LEASE.getByName("account:4001").fetch(
      "https://lease/inspect",
      { method: "POST", body: JSON.stringify({ account_id: "4001" }) },
    );
    expect(await inspected.json()).toMatchObject({ in_flight: 0 });
  });

  it("returns one admission for ten retries and conflicts a changed semantic owner", async () => {
    const responses = await Promise.all(
      Array.from({ length: 10 }, () => call("/v1/requests/admit", {
        request_id: "request-ten-retries",
        api_key_id: "3001",
        group_id: "2001",
        model: "fixture-model",
        lease_ttl_seconds: 30,
      })),
    );
    expect(responses.every((response) => response.status === 200)).toBe(true);
    const admissions = await Promise.all(
      responses.map((response) => response.json<Admission>()),
    );
    expect(new Set(admissions.map((value) => value.lease.lease_id)).size).toBe(1);
    expect((await call("/v1/requests/admit", {
      request_id: "request-ten-retries",
      api_key_id: "3001",
      group_id: "2001",
      model: "fixture-model",
      lease_ttl_seconds: 30,
    }, env, "container-test-b")).status).toBe(409);
    expect((await release(admissions[0])).status).toBe(200);
  });

  it("fails closed before leasing when the active price snapshot is unavailable", async () => {
    await env.DB.prepare("DELETE FROM pricing_active_version").run();
    const noLeaseEnv = overrideEnv({
      ACCOUNT_LEASE: {
        idFromName: () => { throw new Error("lease access must not occur"); },
      },
    });
    const before = await env.DB.prepare(
      "SELECT count(*) AS count FROM gateway_requests WHERE request_id='request-no-price'",
    ).first<number>("count");
    const response = await call(
      "/v1/requests/admit",
      {
        request_id: "request-no-price",
        api_key_id: "3001",
        group_id: "2001",
        model: "fixture-model",
        lease_ttl_seconds: 30,
      },
      noLeaseEnv,
    );
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({
      error: { code: "PRICING_UNAVAILABLE", message: "PRICING_UNAVAILABLE" },
    });
    expect(before).toBe(0);
    expect(await env.DB.prepare(
      "SELECT count(*) AS count FROM gateway_requests WHERE request_id='request-no-price'",
    ).first<number>("count")).toBe(0);
  });

  it("uses D1 authority on KV miss, stale value, and KV failure", async () => {
    await env.CONFIG_CACHE.delete("model:fixture-model");
    const missed = await admit("request-kv-miss");
    expect(missed.upstream_model).toBe("mock-upstream-model");
    await release(missed);

    await env.CONFIG_CACHE.put(
      "model:fixture-model",
      JSON.stringify({
        alias: "fixture-model",
        upstream_model: "stale-poisoned-model",
        status: "active",
        updated_at: "2000-01-01T00:00:00Z",
      }),
    );
    const stale = await admit("request-kv-stale");
    expect(stale.upstream_model).toBe("mock-upstream-model");
    await release(stale);

    const failedKV = overrideEnv({
      CONFIG_CACHE: {
        get: async () => {
          throw new Error("injected KV read failure");
        },
        put: async () => {
          throw new Error("injected KV write failure");
        },
      } as unknown as KVNamespace,
    });
    const fallback = await admit("request-kv-failure", failedKV);
    expect(fallback.upstream_model).toBe("mock-upstream-model");
    await release(fallback, failedKV);
  });

  it("chooses the smallest group-account priority and excludes deleted rows", async () => {
    await env.DB.prepare("INSERT INTO accounts(id,name,platform,type,status,schedulable,priority,max_concurrency,credential_envelope,extra_json,created_at,updated_at) VALUES('4002','lower priority','openai','apikey','active',1,1,1,'fixture:v1:mock-upstream','{}','now','now')").run();
    await env.DB.prepare("INSERT INTO account_groups(account_id,group_id) VALUES('4002','2001')").run();
    await seedAccountScheduler("4002");
    const selected = await admit("request-priority-smallest");
    expect(selected.account.id).toBe("4002");
    await release(selected);
    await env.DB.prepare("UPDATE accounts SET deleted_at='now' WHERE id='4002'").run();
    const fallback = await admit("request-priority-deleted");
    expect(fallback.account.id).toBe("4001");
    await release(fallback);
    await env.DB.prepare("UPDATE api_keys SET deleted_at='2026-09-06T00:00:00.000Z' WHERE id='3001'").run();
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(404);
  });

  it("atomically finalizes once, accepts zero counters, and audits conflicts", async () => {
    const targetEnv = failingQueueEnv();
    const admission = await admit("request-completion-idempotent", targetEnv);
    const completion = completionFor(admission);
    expect((await start(admission, targetEnv)).status).toBe(204);

    expect(
      (
        await call(
          "/v1/requests/complete",
          completion,
          targetEnv,
          admission.lease.owner,
        )
      ).status,
    ).toBe(204);
    for (let index = 0; index < 10; index += 1) {
      expect(
        (
          await call(
            "/v1/requests/complete",
            completion,
            targetEnv,
            admission.lease.owner,
          )
        ).status,
      ).toBe(204);
    }

    const requestRow = await env.DB.prepare(
      "SELECT state,event_id FROM gateway_requests WHERE request_id=?",
    )
      .bind(completion.request_id)
      .first<{ state: string; event_id: string }>();
    expect(requestRow).toEqual({
      state: "succeeded",
      event_id: completion.event_id,
    });
    const outbox = await env.DB.prepare(
      "SELECT state,attempts FROM outbox_events WHERE event_id=?",
    )
      .bind(completion.event_id)
      .first<{ state: string; attempts: number }>();
    expect(outbox).toEqual({ state: "pending", attempts: 1 });
    expect(
      await env.DB.prepare("SELECT count(*) count FROM outbox_events")
        .first("count"),
    ).toBe(1);

    const conflicting = completionFor(admission, { output_tokens: "5" });
    expect(
      (
        await call(
          "/v1/requests/complete",
          conflicting,
          targetEnv,
          admission.lease.owner,
        )
      ).status,
    ).toBe(409);
    expect(
      await env.DB.prepare(
        "SELECT count(*) count FROM outbox_conflicts WHERE source='completion'",
      ).first("count"),
    ).toBe(1);
    await release(admission, targetEnv);
  });

  it("does not create an outbox row when completion identity mismatches", async () => {
    const admission = await admit("request-completion-mismatch");
    expect((await start(admission)).status).toBe(204);
    const completion = completionFor(admission, { lease_epoch: "999" });
    const response = await call(
      "/v1/requests/complete",
      completion,
      failingQueueEnv(),
      admission.lease.owner,
    );
    expect(response.status).toBe(409);
    expect(
      await env.DB.prepare("SELECT count(*) count FROM outbox_events WHERE event_id=?")
        .bind(completion.event_id)
        .first("count"),
    ).toBe(0);
    expect(
      await env.DB.prepare("SELECT state FROM gateway_requests WHERE request_id=?")
        .bind(completion.request_id)
        .first("state"),
    ).toBe("admitted");
    await release(admission);
  });

  it("rechecks revocation at admission time", async () => {
    expect(
      (await call("/v1/auth/resolve", { key: "fixture-test-key" })).status,
    ).toBe(200);
    await env.DB.prepare("UPDATE api_keys SET status='disabled' WHERE id='3001'").run();
    expect(
      (
        await call("/v1/requests/admit", {
          request_id: "request-after-revoke",
          api_key_id: "3001",
          group_id: "2001",
          model: "fixture-model",
          lease_ttl_seconds: 30,
        })
      ).status,
    ).toBe(429);
  });

  it("rejects public or malformed attempts to address the private bridge", async () => {
    expect(
      (
        await worker.fetch(
          internalRequest("/v1/auth/resolve", { key: "fixture-test-key" }),
          env,
        )
      ).status,
    ).toBe(404);
    const publicRequest = new Request("https://public.example/v1/auth/resolve", {
      method: "POST",
      headers: { "X-Sub2API-Bridge-Version": BRIDGE_VERSION },
      body: JSON.stringify({ key: "fixture-test-key" }),
    });
    expect((await controlPlane(publicRequest, env)).status).toBe(404);
  });
});
