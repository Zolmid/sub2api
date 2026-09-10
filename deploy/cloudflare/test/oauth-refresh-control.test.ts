import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { BRIDGE_VERSION } from "../src/contracts";
import { routeIngress, routePrivateControlPlane } from "../src/index";

const NOW = 1_700_000_000_000;
let sequence = 0;

type Account = { id: string; envelope: string };

async function account(): Promise<Account> {
  sequence += 1;
  const id = String(8_100_000_000_000_000 + sequence);
  const envelope = `control-envelope-${sequence}`;
  await env.DB.prepare(`INSERT INTO accounts(
    id,name,platform,type,status,schedulable,priority,max_concurrency,
    credential_envelope,extra_json,created_at
  ) VALUES(?,?,?,'oauth','active',1,0,1,?,'{}','test')`)
    .bind(id, `control-${sequence}`, "test", envelope).run();
  return { id, envelope };
}

function privateRequest(path: string, body: unknown, owner = "oauth-control-test"): Request {
  return new Request(`https://sub2api.internal${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Sub2API-Bridge-Version": BRIDGE_VERSION,
      "X-Sub2API-Container-Id": owner,
    },
    body: JSON.stringify(body),
  });
}

const call = (path: string, body: unknown, owner?: string) =>
  routePrivateControlPlane(privateRequest(path, body, owner), env);

async function acquire(record: Account, operationId: string, nowMs = NOW, leaseMs = 1_000) {
  return call("/v1/private/oauth-refresh/acquire-begin", {
    accountId: record.id, operationId, nowMs, leaseMs,
  });
}

describe("private OAuth refresh coordinator", () => {
  it("uses bound DO RPC for account single-flight, D1 CAS, and deterministic replay", async () => {
    const record = await account();
    const first = await acquire(record, "refresh-control-commit");
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ result: "ready", fence: 1 });
    const blocked = await acquire(record, "refresh-control-blocked", NOW + 1);
    expect(blocked.status).toBe(409);
    expect(await blocked.json()).toMatchObject({ result: "busy" });

    const premature = await call("/v1/private/oauth-refresh/commit-success", {
      accountId: record.id, operationId: "refresh-control-commit", nowMs: NOW + 1,
      nextCredentialEnvelope: "must-not-commit-before-provider-boundary",
    });
    expect(premature.status).toBe(409);
    expect(await premature.json()).toEqual({ result: "conflict" });

    expect((await call("/v1/private/oauth-refresh/mark-provider-started", {
      accountId: record.id, operationId: "refresh-control-commit", nowMs: NOW + 1,
    })).status).toBe(200);
    const nextEnvelope = "control-next-envelope";
    const committed = await call("/v1/private/oauth-refresh/commit-success", {
      accountId: record.id, operationId: "refresh-control-commit", nowMs: NOW + 2,
      nextCredentialEnvelope: nextEnvelope,
    });
    expect(committed.status).toBe(200);
    expect(await committed.json()).toEqual({ result: "committed", state: "succeeded" });
    expect(await env.DB.prepare(`SELECT credential_version,credential_envelope FROM accounts WHERE id=?`)
      .bind(record.id).first()).toEqual({ credential_version: 2, credential_envelope: nextEnvelope });
    expect(await env.DB.prepare(`SELECT count(*) AS count FROM oauth_refresh_commit_witnesses WHERE operation_id=?`)
      .bind("refresh-control-commit").first()).toEqual({ count: 1 });

    const replay = await call("/v1/private/oauth-refresh/commit-success", {
      accountId: record.id, operationId: "refresh-control-commit", nowMs: NOW + 3,
      nextCredentialEnvelope: nextEnvelope,
    });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual({ result: "already_completed", state: "succeeded" });

    const stub = env.OAUTH_REFRESH_AUTHORITY.getByName(record.id);
    await runInDurableObject(stub, async (_instance, state) => {
      const stored = state.storage.sql.exec(`SELECT account_id,owner,operation_id,credential_version
        FROM oauth_refresh_lease`).toArray();
      expect(JSON.stringify(stored)).not.toContain(record.envelope);
      expect(JSON.stringify(stored)).not.toContain(nextEnvelope);
    });
  });

  it("terminalizes an exact expired pre-provider predecessor before replacement begins", async () => {
    const record = await account();
    expect((await acquire(record, "refresh-control-pre-old")).status).toBe(200);
    const replacement = await acquire(record, "refresh-control-pre-new", NOW + 1_000);
    expect(replacement.status).toBe(200);
    expect(await replacement.json()).toMatchObject({ result: "ready", fence: 2 });
    expect(await env.DB.prepare(`SELECT state,terminal_at_ms FROM oauth_refresh_attempts WHERE operation_id=?`)
      .bind("refresh-control-pre-old").first()).toEqual({ state: "failed_retryable", terminal_at_ms: NOW + 1_000 });
  });

  it("terminalizes a provider-started predecessor to manual review and never retries it blindly", async () => {
    const record = await account();
    expect((await acquire(record, "refresh-control-start-old")).status).toBe(200);
    expect((await call("/v1/private/oauth-refresh/mark-provider-started", {
      accountId: record.id, operationId: "refresh-control-start-old", nowMs: NOW + 1,
    })).status).toBe(200);
    const replacement = await acquire(record, "refresh-control-start-new", NOW + 1_000);
    expect(replacement.status).toBe(409);
    expect(await replacement.json()).toMatchObject({ result: "manual_review" });
    expect(await env.DB.prepare(`SELECT state FROM oauth_refresh_attempts WHERE operation_id=?`)
      .bind("refresh-control-start-old").first()).toEqual({ state: "manual_review" });
    const stale = await call("/v1/private/oauth-refresh/mark-provider-started", {
      accountId: record.id, operationId: "refresh-control-start-old", nowMs: NOW + 1_001,
    });
    expect(stale.status).toBe(409);
    const blocked = await acquire(record, "refresh-control-start-after-review", NOW + 1_001);
    expect(blocked.status).toBe(409);
    expect(await blocked.json()).toMatchObject({ result: "manual_review" });
  });

  it("fails closed through invalid-grant recovery and releases only its terminal lease", async () => {
    const record = await account();
    expect((await acquire(record, "refresh-control-invalid-grant")).status).toBe(200);
    expect((await call("/v1/private/oauth-refresh/mark-provider-started", {
      accountId: record.id, operationId: "refresh-control-invalid-grant", nowMs: NOW + 1,
    })).status).toBe(200);
    const recovered = await call("/v1/private/oauth-refresh/recover-invalid-grant", {
      accountId: record.id, operationId: "refresh-control-invalid-grant", nowMs: NOW + 2,
    });
    expect(recovered.status).toBe(409);
    expect(await recovered.json()).toMatchObject({ result: "manual_review" });
    expect(await env.OAUTH_REFRESH_AUTHORITY.getByName(record.id).acquire({
      accountId: record.id, credentialVersion: 1, operationId: "refresh-control-released-proof",
      owner: "released-proof", nowMs: NOW + 3, leaseMs: 1_000,
    })).toMatchObject({ kind: "acquired", fence: 2 });
    expect((await acquire(record, "refresh-control-invalid-grant-next", NOW + 3)).status).toBe(409);
  });

  it("rejects wrong-object/account RPC, malformed or oversized payloads, and public private ingress", async () => {
    const a = await account();
    const b = await account();
    const wrongObject = env.OAUTH_REFRESH_AUTHORITY.getByName("test-object-bound-to-a");
    await wrongObject.acquire({
      accountId: a.id, credentialVersion: 1, operationId: "refresh-control-direct-a",
      owner: "rpc-owner", nowMs: NOW, leaseMs: 1_000,
    });
    await expect(wrongObject.acquire({
      accountId: b.id, credentialVersion: 1, operationId: "refresh-control-direct-b",
      owner: "rpc-owner", nowMs: NOW + 1_000, leaseMs: 1_000,
    })).resolves.toEqual({ kind: "account_mismatch" });

    const malformed = await call("/v1/private/oauth-refresh/acquire-begin", {
      accountId: "01", operationId: "bad", nowMs: NOW, leaseMs: 1_000, ignored: true,
    });
    expect(malformed.status).toBe(400);
    const secret = "s".repeat(65_537);
    const oversized = await call("/v1/private/oauth-refresh/commit-success", {
      accountId: a.id, operationId: "refresh-control-direct-a", nowMs: NOW,
      nextCredentialEnvelope: secret,
    });
    expect(oversized.status).toBe(400);
    expect(await oversized.text()).not.toContain(secret);

    const publicResponse = await routeIngress(new Request(
      "https://example.test/v1/private/oauth-refresh/acquire-begin", { method: "POST" },
    ), env);
    expect(publicResponse.status).toBe(404);
    const wrongBridge = await routePrivateControlPlane(new Request(
      "https://sub2api.internal/v1/private/oauth-refresh/acquire-begin", { method: "POST" },
    ), env);
    expect(wrongBridge?.status).toBe(404);
  });
});
