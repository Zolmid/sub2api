import { env } from "cloudflare:test";
import {
  evictDurableObject,
  runDurableObjectAlarm,
  runInDurableObject,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { AccountLeaseDO } from "../src/lease";

type Lease = {
  account_id: string;
  lease_id: string;
  request_id: string;
  owner: string;
  epoch: string;
  expires_at: string;
};

type AcquireResponse = { lease: Lease; created: boolean };

const stubFor = (name: string) =>
  env.ACCOUNT_LEASE.get(env.ACCOUNT_LEASE.idFromName(name));

const post = (stub: DurableObjectStub, path: string, body: object) =>
  stub.fetch(`https://lease${path}`, {
    method: "POST",
    body: JSON.stringify(body),
  });

const acquire = async (
  stub: DurableObjectStub,
  requestID: string,
  owner: string,
  maxConcurrency = 1,
  ttlSeconds = 30,
): Promise<AcquireResponse> => {
  const response = await post(stub, "/acquire", {
    account_id: "4001",
    request_id: requestID,
    owner,
    max_concurrency: maxConcurrency,
    ttl_seconds: ttlSeconds,
    admission_fingerprint: "a".repeat(64),
  });
  expect(response.status).toBe(200);
  return response.json<AcquireResponse>();
};

describe("AccountLeaseDO", () => {
  it("preserves decimal identity and idempotency across DO eviction", async () => {
    const stub = stubFor("lease-idempotency");
    const first = await acquire(stub, "request-idempotent", "container-a");
    expect(first.created).toBe(true);
    expect(first.lease.account_id).toBe("4001");

    const second = await acquire(stub, "request-idempotent", "container-a");
    expect(second.created).toBe(false);
    expect(second.lease).toEqual(first.lease);

    await evictDurableObject(stub);
    const recovered = await acquire(stub, "request-idempotent", "container-a");
    expect(recovered.created).toBe(false);
    expect(recovered.lease).toEqual(first.lease);
  });

  it("serializes simultaneous acquisition at max concurrency one", async () => {
    const firstHandle = stubFor("lease-concurrent");
    const secondHandle = stubFor("lease-concurrent");
    const responses = await Promise.all([
      post(firstHandle, "/acquire", {
        account_id: "4001",
        request_id: "request-concurrent-a",
        owner: "container-a",
        max_concurrency: 1,
        ttl_seconds: 30,
        admission_fingerprint: "b".repeat(64),
      }),
      post(secondHandle, "/acquire", {
        account_id: "4001",
        request_id: "request-concurrent-b",
        owner: "container-b",
        max_concurrency: 1,
        ttl_seconds: 30,
        admission_fingerprint: "c".repeat(64),
      }),
    ]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 429]);
  });

  it("rejects stale identities while allowing exact duplicate release", async () => {
    const stub = stubFor("lease-fencing");
    const { lease } = await acquire(stub, "request-fenced", "container-a");

    expect(
      (
        await post(stub, "/renew", {
          ...lease,
          owner: "container-b",
          ttl_seconds: 30,
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await post(stub, "/release", {
          ...lease,
          epoch: String(Number(lease.epoch) + 1),
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await post(stub, "/release", {
          ...lease,
          account_id: "4002",
        })
      ).status,
    ).toBe(409);

    const released = await post(stub, "/release", lease);
    expect(released.status).toBe(200);
    expect(await released.json()).toEqual({ released: true, duplicate: false });

    const duplicate = await post(stub, "/release", lease);
    expect(duplicate.status).toBe(200);
    expect(await duplicate.json()).toEqual({ released: false, duplicate: true });
    expect((await post(stub, "/renew", { ...lease, ttl_seconds: 30 })).status).toBe(
      409,
    );
  });

  it("fences acquire compensation by owner and admission fingerprint", async () => {
    const stub = stubFor("lease-abort-fencing");
    await acquire(stub, "request-abort-fenced", "container-a");
    const abort = {
      account_id: "4001",
      request_id: "request-abort-fenced",
      owner: "container-a",
      admission_fingerprint: "a".repeat(64),
    };
    expect((await post(stub, "/abort", {
      ...abort,
      owner: "container-b",
    })).status).toBe(409);
    expect((await post(stub, "/abort", {
      ...abort,
      admission_fingerprint: "b".repeat(64),
    })).status).toBe(409);
    const inspected = await post(stub, "/inspect", { account_id: "4001" });
    expect(await inspected.json()).toMatchObject({ in_flight: 1 });

    expect(await (await post(stub, "/abort", abort)).json()).toEqual({
      released: true,
      duplicate: false,
    });
    expect(await (await post(stub, "/abort", abort)).json()).toEqual({
      released: false,
      duplicate: true,
    });
  });

  it("keeps the earliest alarm when a later lease is renewed", async () => {
    const stub = stubFor("lease-earliest-alarm");
    const first = await acquire(stub, "request-early", "container-a", 2, 5);
    const second = await acquire(stub, "request-late", "container-b", 2, 30);
    const renewed = await post(stub, "/renew", {
      ...second.lease,
      ttl_seconds: 60,
    });
    expect(renewed.status).toBe(200);

    const alarm = await runInDurableObject(
      stub as DurableObjectStub<AccountLeaseDO>,
      async (_instance, state) => state.storage.getAlarm(),
    );
    expect(alarm).not.toBeNull();
    expect(alarm!).toBeLessThanOrEqual(Date.parse(first.lease.expires_at) + 10);
    expect(alarm!).toBeLessThan(Date.parse(second.lease.expires_at));
  });

  it("uses alarm cleanup as a bounded recovery path", async () => {
    const stub = stubFor("lease-alarm-cleanup");
    const { lease } = await acquire(stub, "request-expiring", "container-a", 1, 30);
    await runInDurableObject(
      stub as DurableObjectStub<AccountLeaseDO>,
      async (_instance, state) => {
        state.storage.sql.exec("UPDATE leases SET expires_at=?", Date.now() - 1);
        await state.storage.setAlarm(Date.now() + 60_000);
      },
    );
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const count = await runInDurableObject(
      stub as DurableObjectStub<AccountLeaseDO>,
      (_instance, state) =>
        state.storage.sql.exec<{ count: number }>("SELECT count(*) count FROM leases")
          .one().count,
    );
    expect(count).toBe(0);
    const exactClose = await post(stub, "/release", lease);
    expect(exactClose.status).toBe(200);
    expect(await exactClose.json()).toEqual({ released: false, duplicate: true });
    expect((await post(stub, "/release", { ...lease, owner: "container-b" })).status).toBe(409);
  });

  it("rejects a renew that arrives after expiry and a competing lease won", async () => {
    const stub = stubFor("lease-late-renew");
    const first = await acquire(stub, "request-late", "container-a", 1, 30);
    await runInDurableObject(
      stub as DurableObjectStub<AccountLeaseDO>,
      (_instance, state) => {
        state.storage.sql.exec("UPDATE leases SET expires_at=?", Date.now() - 1);
      },
    );
    const second = await acquire(stub, "request-winner", "container-b", 1, 30);
    expect(Number(second.lease.epoch)).toBeGreaterThan(Number(first.lease.epoch));
    expect(
      (await post(stub, "/renew", { ...first.lease, ttl_seconds: 30 })).status,
    ).toBe(409);
  });

  it("keeps versioned health and cooldown observations authoritative after eviction", async () => {
    const stub = stubFor("lease-observation-state");
    const now = Date.now();
    const update = {
      account_id: "4001",
      kind: "cooldown_until_ms",
      evidence: "confirmed",
      source: "provider-probe",
      value: now + 30_000,
      observed_at_ms: now,
      fresh_until_ms: now + 60_000,
      version: 2,
    };
    const applied = await post(stub, "/state/update", update);
    expect(applied.status).toBe(200);
    await applied.text();
    const stale = await post(stub, "/state/update", {
        ...update,
        value: null,
        observed_at_ms: now - 1,
        version: 1,
      });
    expect(stale.status).toBe(200);
    await stale.text();
    let inspected = await post(stub, "/inspect", { account_id: "4001" });
    expect((await inspected.json<{ cooldown: { value: number } }>()).cooldown.value).toBe(
      update.value,
    );

    const conflict = await post(stub, "/state/update", {
      ...update,
      value: now + 40_000,
      observed_at_ms: now + 1,
    });
    expect(conflict.status).toBe(409);
    await conflict.text();
    await evictDurableObject(stub);
    inspected = await post(stub, "/inspect", { account_id: "4001" });
    const recovered = await inspected.json<{
      cooldown: { value: number; source: string; version: number };
    }>();
    expect(recovered.cooldown).toMatchObject({
      value: update.value,
      source: "provider-probe",
      version: 2,
    });

    const health = {
      ...update,
      kind: "health_bps",
      value: 8_500,
      version: 4,
      observed_at_ms: now + 2,
    };
    expect((await post(stub, "/state/update", health)).status).toBe(200);
    expect((await post(stub, "/state/update", {
      ...health,
      value: 1_000,
      version: 3,
      observed_at_ms: now + 3,
    })).status).toBe(200);
    const healthInspect = await post(stub, "/inspect", { account_id: "4001" });
    expect((await healthInspect.json<{ health: { value: number } }>()).health.value).toBe(8_500);
  });

  it("enforces fixed-window RPM idempotency, conflicts, and eviction recovery", async () => {
    const stub = stubFor("rate-account-4001");
    const body = {
      scope: "account",
      principal_id: "4001",
      admission_id: "admission-rate-a",
      request_id: "request-rate-a",
      account_id: "4001",
      rpm_limit: 1,
      reservation_ttl_seconds: 30,
      admission_fingerprint: "d".repeat(64),
    };
    const first = await post(stub, "/rate/reserve", body);
    expect(first.status).toBe(200);
    const firstBody = await first.json<{
      created: boolean;
      reserved: boolean;
      window_start_ms: number;
      window_end_ms: number;
    }>();
    expect(firstBody).toMatchObject({ created: true, reserved: true });
    expect(firstBody.window_start_ms % 60_000).toBe(0);
    expect(firstBody.window_end_ms - firstBody.window_start_ms).toBe(60_000);
    expect(await (await post(stub, "/rate/reserve", body)).json()).toMatchObject({
      created: false,
      reserved: true,
    });
    const conflict = await post(stub, "/rate/reserve", { ...body, request_id: "conflict" });
    expect(conflict.status).toBe(409);
    await conflict.text();
    const limited = await post(stub, "/rate/reserve", {
        ...body,
        admission_id: "admission-rate-b",
        request_id: "request-rate-b",
      });
    expect(limited.status).toBe(429);
    await limited.text();

    await evictDurableObject(stub);
    const committed = await post(stub, "/rate/commit", body);
    expect(committed.status).toBe(200);
    await committed.text();
    expect(await (await post(stub, "/rate/commit", body)).json()).toEqual({
      committed: true,
      duplicate: true,
    });
    const committedRelease = await post(stub, "/rate/release", body);
    expect(committedRelease.status).toBe(409);
    await committedRelease.text();
  });

  it("releases pending RPM reservations and expires abandoned ones by alarm", async () => {
    const stub = stubFor("rate-user-9001");
    const body = {
      scope: "user",
      principal_id: "9001",
      admission_id: "admission-pending",
      request_id: "request-pending",
      account_id: "4001",
      rpm_limit: 2,
      reservation_ttl_seconds: 30,
      admission_fingerprint: "e".repeat(64),
    };
    expect((await post(stub, "/rate/reserve", body)).status).toBe(200);
    expect(await (await post(stub, "/rate/release", body)).json()).toEqual({
      released: true,
      duplicate: false,
    });
    expect(await (await post(stub, "/rate/release", body)).json()).toEqual({
      released: false,
      duplicate: true,
    });

    const abandoned = { ...body, admission_id: "admission-abandoned", request_id: "request-abandoned" };
    const reserved = await post(stub, "/rate/reserve", abandoned);
    expect(reserved.status).toBe(200);
    await reserved.text();
    await runInDurableObject(
      stub as DurableObjectStub<AccountLeaseDO>,
      async (_instance, state) => {
        state.storage.sql.exec(
          "UPDATE rate_admissions SET reservation_expires_at_ms=? WHERE admission_id=?",
          Date.now() - 1,
          abandoned.admission_id,
        );
        await state.storage.setAlarm(Date.now() + 60_000);
      },
    );
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const inspected = await post(stub, "/rate/inspect", {
      scope: "user",
      principal_id: "9001",
      rpm_limit: 2,
    });
    expect(await inspected.json()).toMatchObject({ used: 0, available: true, evidence: "confirmed" });
    expect((await post(stub, "/rate/reserve", abandoned)).status).toBe(409);
  });

  it("fails closed for invalid principal identities and counter limits", async () => {
    const stub = stubFor("rate-invalid");
    const base = {
      scope: "api_key",
      principal_id: "7001",
      admission_id: "admission-invalid",
      request_id: "request-invalid",
      account_id: "4001",
      reservation_ttl_seconds: 30,
      admission_fingerprint: "f".repeat(64),
    };
    expect((await post(stub, "/rate/reserve", { ...base, rpm_limit: 0 })).status).toBe(400);
    expect((await post(stub, "/rate/reserve", { ...base, rpm_limit: 100_001 })).status).toBe(400);
    expect(
      (await post(stub, "/rate/reserve", { ...base, principal_id: "07001", rpm_limit: 1 })).status,
    ).toBe(400);
  });
});
