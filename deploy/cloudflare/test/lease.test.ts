import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const post = async (path: string, body: object) => {
  const stub = env.ACCOUNT_LEASE.get(env.ACCOUNT_LEASE.idFromName("account:4001"));
  return stub.fetch(`https://lease${path}`, { method: "POST", body: JSON.stringify(body) });
};

describe("AccountLeaseDO", () => {
  it("preserves decimal account identity and makes same request idempotent", async () => {
    const one = await post("/acquire", { account_id: "4001", request_id: "request-a", owner: "container-a", max_concurrency: 1, ttl_seconds: 3 });
    expect(one.status).toBe(200); const first = await one.json<{ lease: { account_id: string; lease_id: string; epoch: string }; created: boolean }>();
    const two = await post("/acquire", { account_id: "4001", request_id: "request-a", owner: "container-a", max_concurrency: 1, ttl_seconds: 3 }); const second = await two.json<typeof first>();
    expect(first.lease.account_id).toBe("4001"); expect(first.created).toBe(true); expect(second.created).toBe(false); expect(second.lease.lease_id).toBe(first.lease.lease_id);
    await post("/release", { account_id: "4001", request_id: "request-a", lease_id: first.lease.lease_id, owner: "container-a", epoch: first.lease.epoch });
  });
  it("enforces max=1 and fences wrong account/owner/epoch", async () => {
    const acquired = await post("/acquire", { account_id: "4001", request_id: "request-b", owner: "container-b", max_concurrency: 1, ttl_seconds: 3 }); const body = await acquired.json<{ lease: { lease_id: string; epoch: string } }>();
    expect((await post("/acquire", { account_id: "4001", request_id: "request-c", owner: "container-c", max_concurrency: 1, ttl_seconds: 3 })).status).toBe(429);
    expect((await post("/renew", { account_id: "4002", request_id: "request-b", lease_id: body.lease.lease_id, owner: "container-b", epoch: body.lease.epoch, ttl_seconds: 3 })).status).toBe(409);
    expect((await post("/release", { account_id: "4001", request_id: "request-b", lease_id: body.lease.lease_id, owner: "different", epoch: body.lease.epoch })).status).toBe(200);
  });
});
