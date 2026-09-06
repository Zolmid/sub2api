import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { controlPlane } from "../src/control-plane";
import {
  BRIDGE_VERSION,
  USAGE_EVENT_TYPE,
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

const completionFor = (
  admission: Admission,
  overrides: Partial<Completion> = {},
): Completion => ({
  schema_version: BRIDGE_VERSION,
  event_type: USAGE_EVENT_TYPE,
  event_id: `${admission.lease.request_id}:usage:v1`,
  request_id: admission.lease.request_id,
  api_key_id: "3001",
  account_id: admission.account.id,
  lease_id: admission.lease.lease_id,
  lease_epoch: admission.lease.epoch,
  outcome: "succeeded",
  usage_state: "confirmed",
  input_tokens: "11",
  output_tokens: "4",
  cache_read_tokens: "0",
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

describe("D1-backed private control plane", () => {
  it("installs the schema with canonical decimal constraints", async () => {
    expect(
      await env.DB.prepare(
        "SELECT value FROM schema_metadata WHERE key='cloudflare_bridge_schema_version'",
      ).first("value"),
    ).toBe(BRIDGE_VERSION);
    await expect(
      env.DB.prepare(
        `INSERT INTO users(
           id,status,role,concurrency,balance_microusd,
           allowed_group_ids_json,restrict_public_groups,created_at
         ) VALUES('01','active','user',1,'1','[]',0,'now')`,
      ).run(),
    ).rejects.toThrow();
  });

  it("resolves only active users and never stores the raw API key", async () => {
    const response = await call("/v1/auth/resolve", { key: "fixture-test-key" });
    expect(response.status).toBe(200);
    const body = await response.json<{
      api_key: { id: string; user_id: string; group_id: string };
      user: { id: string; balance_positive: boolean };
      group: { id: string };
    }>();
    expect(body.api_key).toMatchObject({
      id: "3001",
      user_id: "1001",
      group_id: "2001",
    });
    expect(body.user).toMatchObject({ id: "1001", balance_positive: true });
    expect(body.group.id).toBe("2001");

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
      lease: {
        account_id: "4001",
        request_id: "request-admission-compatible",
        owner: "container-test-a",
      },
    });
    expect(Date.parse(admission.lease.expires_at)).toBeGreaterThan(Date.now());

    const row = await env.DB.prepare(
      "SELECT owner,upstream_model FROM gateway_requests WHERE request_id=?",
    )
      .bind(admission.lease.request_id)
      .first<{ owner: string; upstream_model: string }>();
    expect(row).toEqual({
      owner: "container-test-a",
      upstream_model: "mock-upstream-model",
    });
    expect((await release(admission)).status).toBe(200);
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
    const selected = await admit("request-priority-smallest");
    expect(selected.account.id).toBe("4002");
    await release(selected);
    await env.DB.prepare("UPDATE accounts SET deleted_at='now' WHERE id='4002'").run();
    const fallback = await admit("request-priority-deleted");
    expect(fallback.account.id).toBe("4001");
    await release(fallback);
    await env.DB.prepare("UPDATE api_keys SET deleted_at='now' WHERE id='3001'").run();
    expect((await call("/v1/auth/resolve", { key: "fixture-test-key" })).status).toBe(404);
  });

  it("atomically finalizes once, accepts zero counters, and audits conflicts", async () => {
    const targetEnv = failingQueueEnv();
    const admission = await admit("request-completion-idempotent", targetEnv);
    const completion = completionFor(admission);

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
