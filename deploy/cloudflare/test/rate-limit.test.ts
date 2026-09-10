import {
  env,
  evictDurableObject,
  runDurableObjectAlarm,
  runInDurableObject,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { UserRateLimitDO } from "../src/rate-limit";

const post = (stub: DurableObjectStub, path: string, body: object) =>
  stub.fetch(`https://rate-limit${path}`, {
    method: "POST",
    body: JSON.stringify(body),
  });

async function expectStatus(response: Promise<Response>, status: number): Promise<void> {
  const resolved = await response;
  expect(resolved.status).toBe(status);
  await resolved.text();
}

describe("dedicated principal RPM durable objects", () => {
  it("isolates canonical user and API-key namespaces and survives eviction", async () => {
    const user = env.USER_RATE_LIMIT.getByName("user:9101");
    const key = env.API_KEY_RATE_LIMIT.getByName("api-key:9101");
    const common = {
      admission_id: "request-rate-dedicated",
      request_id: "request-rate-dedicated",
      account_id: "4001",
      rpm_limit: 1,
      reservation_ttl_seconds: 30,
      admission_fingerprint: "9".repeat(64),
    };
    await expectStatus(post(user, "/rate/reserve", {
      ...common, scope: "user", principal_id: "9101",
    }), 200);
    await expectStatus(post(key, "/rate/reserve", {
      ...common, scope: "api_key", principal_id: "9101",
    }), 200);
    await evictDurableObject(user);
    await expectStatus(post(user, "/rate/commit", {
      ...common, scope: "user", principal_id: "9101",
    }), 200);
    await expectStatus(post(key, "/rate/commit", {
      ...common, scope: "api_key", principal_id: "9101",
    }), 200);
    await expectStatus(post(user, "/rate/reserve", {
      ...common, scope: "user", principal_id: "9101",
      admission_fingerprint: "8".repeat(64),
    }), 409);
  });

  it("expires pending state by alarm and keeps replay tombstones", async () => {
    const user = env.USER_RATE_LIMIT.getByName("user:9201");
    const body = {
      scope: "user",
      principal_id: "9201",
      admission_id: "request-rate-expire",
      request_id: "request-rate-expire",
      account_id: "4001",
      rpm_limit: 2,
      reservation_ttl_seconds: 30,
      admission_fingerprint: "7".repeat(64),
    };
    await expectStatus(post(user, "/rate/reserve", body), 200);
    await runInDurableObject(
      user as DurableObjectStub<UserRateLimitDO>,
      async (_instance, state) => {
        state.storage.sql.exec(
          "UPDATE rate_admissions SET reservation_expires_at_ms=?",
          Date.now() - 1,
        );
        await state.storage.setAlarm(Date.now() + 60_000);
      },
    );
    expect(await runDurableObjectAlarm(user)).toBe(true);
    await expectStatus(post(user, "/rate/reserve", body), 409);
    const inspect = await post(user, "/rate/inspect", {
      scope: "user", principal_id: "9201", rpm_limit: 2,
    });
    expect(await inspect.json()).toMatchObject({ used: 0, available: true });
  });

  it("accepts exact close after natural expiry or window closure and rejects a mismatch", async () => {
    const user = env.USER_RATE_LIMIT.getByName("user:9251");
    const expired = {
      scope: "user",
      principal_id: "9251",
      admission_id: "request-rate-natural-expiry",
      request_id: "request-rate-natural-expiry",
      account_id: "4001",
      rpm_limit: 2,
      reservation_ttl_seconds: 30,
      admission_fingerprint: "5".repeat(64),
    };
    await expectStatus(post(user, "/rate/reserve", expired), 200);
    await runInDurableObject(
      user as DurableObjectStub<UserRateLimitDO>,
      async (_instance, state) => {
        state.storage.sql.exec(
          "UPDATE rate_admissions SET reservation_expires_at_ms=? WHERE admission_id=?",
          Date.now() - 1,
          expired.admission_id,
        );
        await state.storage.setAlarm(Date.now() + 60_000);
      },
    );
    expect(await runDurableObjectAlarm(user)).toBe(true);
    expect(await (await post(user, "/rate/rollback", expired)).json()).toEqual({
      released: false,
      duplicate: true,
    });
    await expectStatus(post(user, "/rate/rollback", {
      ...expired,
      admission_fingerprint: "4".repeat(64),
    }), 409);

    const closed = {
      ...expired,
      admission_id: "request-rate-window-closed",
      request_id: "request-rate-window-closed",
      admission_fingerprint: "3".repeat(64),
    };
    await expectStatus(post(user, "/rate/reserve", closed), 200);
    await expectStatus(post(user, "/rate/commit", closed), 200);
    await runInDurableObject(
      user as DurableObjectStub<UserRateLimitDO>,
      async (_instance, state) => {
        state.storage.sql.exec(
          "UPDATE rate_admissions SET window_end_ms=?,reservation_expires_at_ms=? WHERE admission_id=?",
          Date.now() - 1,
          Date.now() - 1,
          closed.admission_id,
        );
        await state.storage.setAlarm(Date.now() + 60_000);
      },
    );
    expect(await runDurableObjectAlarm(user)).toBe(true);
    expect(await (await post(user, "/rate/release", closed)).json()).toEqual({
      released: false,
      duplicate: true,
    });
  });

  it("keeps a finalized RPM admission immune to delayed rollback", async () => {
    const user = env.USER_RATE_LIMIT.getByName("user:9301");
    const body = {
      scope: "user",
      principal_id: "9301",
      admission_id: "request-rate-finalized",
      request_id: "request-rate-finalized",
      account_id: "4001",
      rpm_limit: 2,
      reservation_ttl_seconds: 30,
      admission_fingerprint: "6".repeat(64),
    };
    await expectStatus(post(user, "/rate/reserve", body), 200);
    await expectStatus(post(user, "/rate/commit", body), 200);
    await expectStatus(post(user, "/rate/settle", body), 200);
    await expectStatus(post(user, "/rate/settle", body), 200);
    const rollback = await post(user, "/rate/rollback", body);
    expect(rollback.status).toBe(409);
    expect(await rollback.json()).toMatchObject({ error: "RATE_ADMISSION_FINALIZED" });
    const inspect = await post(user, "/rate/inspect", {
      scope: "user", principal_id: "9301", rpm_limit: 2,
    });
    expect(await inspect.json()).toMatchObject({ used: 1, available: true });
  });
});
