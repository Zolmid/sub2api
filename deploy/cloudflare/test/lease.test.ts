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
    const stub = stubFor("lease-concurrent");
    const responses = await Promise.all([
      post(stub, "/acquire", {
        account_id: "4001",
        request_id: "request-concurrent-a",
        owner: "container-a",
        max_concurrency: 1,
        ttl_seconds: 30,
      }),
      post(stub, "/acquire", {
        account_id: "4001",
        request_id: "request-concurrent-b",
        owner: "container-b",
        max_concurrency: 1,
        ttl_seconds: 30,
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
    await acquire(stub, "request-expiring", "container-a", 1, 30);
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
  });
});
