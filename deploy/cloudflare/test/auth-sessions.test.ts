import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { controlPlane } from "../src/control-plane";
import { BRIDGE_VERSION, sha256 } from "../src/contracts";

const future = "2030-01-01T00:00:00.000Z";
const later = "2030-01-02T00:00:00.000Z";
const past = "2020-01-01T00:00:00.000Z";
const rawRefresh = "private-refresh-token-material";
const rawAccess = "private-access-token-material";

function hex(seed: number): string {
  return seed.toString(16).padStart(64, "0");
}

function bindingHex(seed: number): string {
  return seed.toString(16).padStart(32, "0");
}

function session(seed: number, overrides: Partial<Record<string, string>> = {}) {
  return {
    token_hash: hex(seed),
    user_id: "1001",
    token_version: String(seed),
    family_id: `family-${seed}`,
    binding_hash: bindingHex(900 + seed),
    created_at: "2026-09-10T00:00:00.000Z",
    expires_at: future,
    ...overrides,
  };
}

function request(path: string, body: Record<string, unknown>, container = "auth-session-test") {
  return new Request(`http://sub2api.internal${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Sub2API-Bridge-Version": BRIDGE_VERSION,
      ...(container === "" ? {} : { "X-Sub2API-Container-Id": container }),
    },
    body: JSON.stringify(body),
  });
}

async function invoke(path: string, body: Record<string, unknown>, databaseEnv = env as Env) {
  return controlPlane(request(path, body), databaseEnv);
}

async function expectCode(response: Response, code: string) {
  expect(await response.json()).toEqual({ error: { code, message: code } });
}

async function store(record: ReturnType<typeof session>) {
  const response = await invoke("/v1/auth-sessions/store", record);
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({ success: true, code: "OK" });
}

describe("auth sessions control plane", () => {
  it("stores and gets a session without persisting plaintext token material", async () => {
    const tokenHash = await sha256(rawRefresh);
    const record = session(1, {
      token_hash: tokenHash,
      binding_hash: (await sha256("binding")).slice(0, 32),
    });
    await store(record);

    const loaded = await invoke("/v1/auth-sessions/get", { token_hash: tokenHash });
    expect(loaded.status).toBe(200);
    expect(await loaded.json()).toEqual({ session: record });

    const rawRows = await env.DB.prepare(
      `SELECT
         (SELECT json_group_array(json_object('token_hash',token_hash,'binding_hash',binding_hash)) FROM auth_sessions) AS sessions,
         (SELECT json_group_array(json_object('detail_hash',detail_hash)) FROM auth_session_audit_events) AS audit_rows`,
    ).first<{ sessions: string; audit_rows: string }>();
    const serialized = JSON.stringify(rawRows);
    expect(serialized).toContain(tokenHash);
    expect(serialized).not.toContain(rawRefresh);
    expect(serialized).not.toContain(rawAccess);
  });

  it("distinguishes expiry, single revoke, user/family revokes, active lists, and membership", async () => {
    const one = session(10, { family_id: "shared-family", token_version: "1" });
    const two = session(11, { family_id: "shared-family", token_version: "2" });
    const other = session(12, { user_id: "1002", family_id: "other-family" });
    const expired = session(13, {
      family_id: "expired-family",
      created_at: "2019-01-01T00:00:00.000Z",
      expires_at: past,
    });
    await store(one);
    await store(two);
    await store(other);
    await store(expired);

    expect(await (await invoke("/v1/auth-sessions/contains", {
      family_id: one.family_id,
      token_hash: one.token_hash,
    })).json())
      .toEqual({ contains: true, code: "OK" });
    expect(await (await invoke("/v1/auth-sessions/contains", {
      family_id: "wrong-family",
      token_hash: one.token_hash,
    })).json()).toEqual({ contains: false, code: "AUTH_SESSION_NOT_FOUND" });
    expect(await (await invoke("/v1/auth-sessions/contains", {
      family_id: expired.family_id,
      token_hash: expired.token_hash,
    })).json())
      .toEqual({ contains: false, code: "AUTH_SESSION_EXPIRED" });
    await expectCode(
      await invoke("/v1/auth-sessions/get", { token_hash: expired.token_hash }),
      "AUTH_SESSION_EXPIRED",
    );

    expect(await (await invoke("/v1/auth-sessions/list-user", { user_id: "1001" })).json())
      .toEqual({ token_hashes: [one.token_hash, two.token_hash] });
    expect(await (await invoke("/v1/auth-sessions/list-family", { family_id: "shared-family" })).json())
      .toEqual({ token_hashes: [one.token_hash, two.token_hash] });

    expect((await invoke("/v1/auth-sessions/delete", { token_hash: one.token_hash })).status)
      .toBe(200);
    expect(await (await invoke("/v1/auth-sessions/contains", {
      family_id: one.family_id,
      token_hash: one.token_hash,
    })).json())
      .toEqual({ contains: false, code: "AUTH_SESSION_REVOKED" });

    expect((await invoke("/v1/auth-sessions/revoke-user", { user_id: "1001" })).status)
      .toBe(200);
    expect(await (await invoke("/v1/auth-sessions/list-user", { user_id: "1001" })).json())
      .toEqual({ token_hashes: [] });

    expect(await (await invoke("/v1/auth-sessions/contains", {
      family_id: other.family_id,
      token_hash: other.token_hash,
    })).json())
      .toEqual({ contains: true, code: "OK" });
    expect((await invoke("/v1/auth-sessions/revoke-family", { family_id: "other-family" })).status)
      .toBe(200);
    expect(await (await invoke("/v1/auth-sessions/contains", {
      family_id: other.family_id,
      token_hash: other.token_hash,
    })).json())
      .toEqual({ contains: false, code: "AUTH_SESSION_REVOKED" });
  });

  it("allows exactly one distinct concurrent rotation winner", async () => {
    const old = session(20, { family_id: "race-family", token_version: "7" });
    const nextA = session(21, {
      family_id: old.family_id,
      token_version: old.token_version,
      binding_hash: old.binding_hash,
    });
    const nextB = session(22, {
      family_id: old.family_id,
      token_version: old.token_version,
      binding_hash: old.binding_hash,
    });
    await store(old);

    const results = await Promise.all([
      invoke("/v1/auth-sessions/rotate", { old_token_hash: old.token_hash, ...nextA }),
      invoke("/v1/auth-sessions/rotate", { old_token_hash: old.token_hash, ...nextB }),
    ]);
    const bodies = await Promise.all(results.map((response) => response.json<Record<string, unknown>>()));
    expect(bodies.filter((body) => body.code === "OK")).toHaveLength(1);
    expect(bodies.filter((body) =>
      typeof body.error === "object" &&
      body.error !== null &&
      (body.error as { code?: string }).code === "AUTH_SESSION_REUSE"
    )).toHaveLength(1);

    const witnesses = await env.DB.prepare(
      "SELECT count(*) AS count FROM auth_session_rotation_witnesses WHERE old_token_hash=?",
    ).bind(old.token_hash).first<{ count: number }>();
    expect(witnesses?.count).toBe(1);
  });

  it("treats an exact rotation retry as idempotent", async () => {
    const old = session(30, { family_id: "retry-family", token_version: "0" });
    const next = session(31, {
      family_id: old.family_id,
      token_version: old.token_version,
      binding_hash: old.binding_hash,
    });
    await store(old);

    expect((await invoke("/v1/auth-sessions/rotate", { old_token_hash: old.token_hash, ...next })).status)
      .toBe(200);
    const retry = await invoke("/v1/auth-sessions/rotate", { old_token_hash: old.token_hash, ...next });
    expect(retry.status).toBe(200);
    expect(await retry.json()).toMatchObject({ success: true, code: "OK" });
  });

  it("revokes a whole family and descendants after consumed-token reuse", async () => {
    const old = session(40, { family_id: "reuse-family", token_version: "1" });
    const child = session(41, {
      family_id: old.family_id,
      token_version: old.token_version,
      binding_hash: old.binding_hash,
    });
    const attacker = session(42, {
      family_id: old.family_id,
      token_version: old.token_version,
      binding_hash: old.binding_hash,
    });
    await store(old);
    expect((await invoke("/v1/auth-sessions/rotate", { old_token_hash: old.token_hash, ...child })).status)
      .toBe(200);

    const replay = await invoke("/v1/auth-sessions/rotate", { old_token_hash: old.token_hash, ...attacker });
    expect(replay.status).toBe(409);
    await expectCode(replay, "AUTH_SESSION_REUSE");

    expect(await (await invoke("/v1/auth-sessions/contains", {
      family_id: child.family_id,
      token_hash: child.token_hash,
    })).json())
      .toEqual({ contains: false, code: "AUTH_SESSION_REUSE" });
    expect(await (await invoke("/v1/auth-sessions/list-family", { family_id: old.family_id })).json())
      .toEqual({ token_hashes: [] });
  });

  it("returns complete user and family membership lists beyond the former boundary", async () => {
    const records = Array.from({ length: 513 }, (_, index) => session(1_000 + index, {
      user_id: "1001",
      token_version: "1",
      family_id: "large-family",
    }));
    for (const record of records) await store(record);

    const byUser = await (await invoke("/v1/auth-sessions/list-user", { user_id: "1001" }))
      .json<{ token_hashes: string[] }>();
    const byFamily = await (await invoke("/v1/auth-sessions/list-family", {
      family_id: "large-family",
    })).json<{ token_hashes: string[] }>();
    expect(byUser.token_hashes).toHaveLength(513);
    expect(byFamily.token_hashes).toHaveLength(513);
    expect(new Set(byFamily.token_hashes)).toEqual(new Set(records.map((record) => record.token_hash)));
  });

  it("reports a readable D1 write outage as unavailable instead of a semantic conflict", async () => {
    const batchUnavailable = {
      prepare: env.DB.prepare.bind(env.DB),
      batch: async () => {
        throw new Error("forced batch outage");
      },
      exec: env.DB.exec.bind(env.DB),
      dump: env.DB.dump?.bind(env.DB),
    } as unknown as D1Database;
    const databaseEnv = { ...env, DB: batchUnavailable } as Env;

    const notStored = session(60, { binding_hash: "" });
    const failedStore = await invoke("/v1/auth-sessions/store", notStored, databaseEnv);
    expect(failedStore.status).toBe(503);
    await expectCode(failedStore, "AUTH_SESSION_UNAVAILABLE");

    const old = session(61, { family_id: "outage-family", token_version: "0", binding_hash: "" });
    const next = session(62, {
      family_id: old.family_id,
      token_version: old.token_version,
      binding_hash: old.binding_hash,
    });
    await store(old);
    const failedRotate = await invoke(
      "/v1/auth-sessions/rotate",
      { old_token_hash: old.token_hash, ...next },
      databaseEnv,
    );
    expect(failedRotate.status).toBe(503);
    await expectCode(failedRotate, "AUTH_SESSION_UNAVAILABLE");
  });

  it("rejects hour 24 at the D1 schema boundary", async () => {
    const invalid = session(63, {
      created_at: "2026-09-10T24:00:00.000Z",
      expires_at: "2030-01-01T00:00:00.000Z",
    });
    await expect(env.DB.prepare(
      `INSERT INTO auth_sessions(
         token_hash,user_id,token_version,family_id,binding_hash,status,
         created_at,expires_at,updated_at
       ) VALUES(?,?,?,?,?,'active',?,?,?)`,
    ).bind(
      invalid.token_hash,
      invalid.user_id,
      invalid.token_version,
      invalid.family_id,
      invalid.binding_hash,
      invalid.created_at,
      invalid.expires_at,
      invalid.created_at,
    ).run()).rejects.toThrow("CHECK constraint failed");
  });

  it("rejects malformed hashes, IDs, times, unknown fields, oversized bodies, and unavailable D1", async () => {
    for (const bad of [
      { ...session(50), token_hash: "not-a-hash" },
      { ...session(50), user_id: "9007199254740993.1" },
      { ...session(50), token_version: "9223372036854775808" },
      { ...session(50), token_version: "00" },
      { ...session(50), binding_hash: hex(50) },
      { ...session(50), family_id: "bad family" },
      { ...session(50), created_at: "2026-09-10T00:00:00Z" },
      { ...session(50), expires_at: "2026-09-09T00:00:00.000Z" },
      { ...session(50), unexpected: true },
    ]) {
      const response = await invoke("/v1/auth-sessions/store", bad);
      expect(response.status).toBe(400);
      await expectCode(response, "INVALID_REQUEST");
    }

    const oversized = await controlPlane(
      new Request("http://sub2api.internal/v1/auth-sessions/contains", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "X-Sub2API-Bridge-Version": BRIDGE_VERSION,
          "X-Sub2API-Container-Id": "auth-session-test",
          "content-length": String(70 * 1024),
        },
        body: JSON.stringify({ token_hash: hex(99) }),
      }),
      env,
    );
    expect(oversized.status).toBe(400);
    await expectCode(oversized, "INVALID_REQUEST");

    const brokenDB = {
      prepare() {
        throw new Error("forced test failure");
      },
      batch() {
        throw new Error("forced test failure");
      },
      exec() {
        throw new Error("forced test failure");
      },
      dump: env.DB.dump?.bind(env.DB),
    } as unknown as D1Database;
    const unavailable = await invoke(
      "/v1/auth-sessions/contains",
      { family_id: "unavailable-family", token_hash: hex(100) },
      { ...env, DB: brokenDB } as Env,
    );
    expect(unavailable.status).toBe(503);
    await expectCode(unavailable, "AUTH_SESSION_UNAVAILABLE");
  });
});
