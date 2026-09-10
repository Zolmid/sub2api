import { describe, expect, it, beforeEach } from "vitest";
import { env } from "cloudflare:test";
import { EmailRuntime, type Clock, canonicalUtc } from "../src/email-runtime";

class FixedClock implements Clock {
  constructor(private readonly value: Date) {}
  now(): Date {
    return new Date(this.value);
  }
}

const keys = (suffix: number) => ({
  token: {
    current: { id: `token-${suffix}`, material: new Uint8Array(32).fill(suffix) },
    previous: [{ id: `token-old-${suffix}`, material: new Uint8Array(32).fill(suffix + 40) }],
  },
  delivery: {
    current: { id: `delivery-${suffix}`, material: new Uint8Array(32).fill(suffix + 80) },
    previous: [
      { id: `delivery-old-${suffix}`, material: new Uint8Array(32).fill(suffix + 120) },
    ],
  },
});

const input = (id: string) => ({
  id,
  accountId: "account-1",
  purpose: "verify-email",
  idempotencyKey: `request-${id}`,
  deliveryReference: "opaque-reference",
  expiresAt: "2026-09-10T00:10:00.000Z",
  maxAttempts: 2,
  maxDeliveryAttempts: 2,
});

const service = (suffix: number) =>
  new EmailRuntime(env.DB, keys(suffix), new FixedClock(new Date("2026-09-10T00:00:00.000Z")));

beforeEach(async () => {
  await env.DB.exec("DELETE FROM email_delivery_witnesses");
  await env.DB.exec("DELETE FROM email_issue_witnesses");
  await env.DB.exec("DELETE FROM email_runtime_outbox");
  await env.DB.exec("DELETE FROM email_runtime_audit");
  await env.DB.exec("DELETE FROM email_issue_idempotency");
  await env.DB.exec("DELETE FROM email_delivery_jobs");
  await env.DB.exec("DELETE FROM email_challenges");
});

describe("email runtime (D1)", () => {
  it("keeps canonical time strict", () => {
    expect(canonicalUtc("2026-09-10T00:00:00.000Z")).toBe("2026-09-10T00:00:00.000Z");
    expect(() => canonicalUtc("2026-09-10T00:00:00Z")).toThrow();
    expect(() => canonicalUtc("2026-09-10 00:00:00.000Z")).toThrow();
  });

  it("validates input object and rejects unknown fields, prototypes, and invalid Unicode", async () => {
    const runtime = service(1);
    const base = input("email-input-001");
    await expect(runtime.issueChallenge({ ...base, unexpected: "field" })).rejects.toMatchObject({
      code: "invalid_input",
    });
    const proto = Object.create({ extra: "proto" });
    Object.assign(proto, base);
    await expect(runtime.issueChallenge(proto)).rejects.toMatchObject({ code: "invalid_input" });
  });

  it("never stores plaintext token or delivery reference", async () => {
    const runtime = service(2);
    const request = { ...input("email-plaintext-001"), deliveryReference: "recipient@example.invalid" };
    const issued = await runtime.issueChallenge(request);

    const stored = await env.DB.prepare(
      "SELECT token_verifier,token_ciphertext,delivery_ciphertext FROM email_challenges WHERE id=?"
    )
      .bind(request.id)
      .first<Record<string, string>>();

    expect(JSON.stringify(stored)).not.toContain(issued.token!);
    expect(JSON.stringify(stored)).not.toContain(request.deliveryReference);
  });

  it("recovers token and delivery after delivery-key rotation", async () => {
    const first = service(3);
    const req = input("email-rotate-001");
    const issued = await first.issueChallenge(req);

    const rotated = new EmailRuntime(
      env.DB,
      {
        token: keys(4).token,
        delivery: {
          current: keys(4).delivery.current,
          previous: [keys(3).delivery.current],
        },
      },
      new FixedClock(new Date("2026-09-10T00:00:00.000Z"))
    );

    const [claim] = await rotated.claimDeliveryJobs("worker-1");
    expect(claim?.token).toBe(issued.token);
    expect(claim?.deliveryReference).toBe("opaque-reference");
  });

  it("persists audit and outbox HMAC key IDs for post-rotation verification", async () => {
    const runtime = service(5);
    await runtime.issueChallenge(input("email-key-id-001"));

    const audit = await env.DB.prepare(
      "SELECT evidence_hmac_key_id FROM email_runtime_audit WHERE event='issued'"
    )
      .first<{ evidence_hmac_key_id: string }>();
    expect(audit?.evidence_hmac_key_id).toBe("token-5");

    const outbox = await env.DB.prepare(
      "SELECT payload_hmac_key_id FROM email_runtime_outbox WHERE event='issued'"
    )
      .first<{ payload_hmac_key_id: string }>();
    expect(outbox?.payload_hmac_key_id).toBe("token-5");
  });

  it("verifies issue audit/outbox MACs and full linkage after token-key rotation", async () => {
    const first = service(6);
    const request = input("email-replay-001");
    await first.issueChallenge(request);

    const rotated = new EmailRuntime(
      env.DB,
      {
        token: {
          current: keys(7).token.current,
          previous: [keys(6).token.current],
        },
        delivery: keys(6).delivery,
      },
      new FixedClock(new Date("2026-09-10T00:00:00.000Z"))
    );

    await expect(rotated.issueChallenge(request)).resolves.toMatchObject({ replayed: true });
    const links = await env.DB.prepare(
      "SELECT a.evidence_hmac_key_id,o.payload_hmac_key_id,a.challenge_id AS audit_challenge,o.challenge_id AS outbox_challenge,a.job_id AS audit_job,o.job_id AS outbox_job FROM email_runtime_audit a JOIN email_runtime_outbox o ON o.audit_id=a.audit_id WHERE a.event='issued'"
    ).first<Record<string, unknown>>();
    expect(links).toMatchObject({
      evidence_hmac_key_id: "token-6",
      payload_hmac_key_id: "token-6",
      audit_challenge: request.id,
      outbox_challenge: request.id,
      audit_job: null,
      outbox_job: null,
    });
  });

  it("fails closed when rotated issue replay sees a bad audit MAC or outbox linkage", async () => {
    const first = service(60);
    const request = input("email-replay-evidence-001");
    await first.issueChallenge(request);
    const rotatedKeys = {
      token: { current: keys(63).token.current, previous: [keys(60).token.current] },
      delivery: keys(60).delivery,
    };
    const replayDb = (field: "audit_hmac" | "outbox_challenge_id") =>
      ({
        prepare: (sql: string) => {
          const statement = env.DB.prepare(sql);
          if (!sql.includes("FROM email_issue_witnesses")) {
            return statement;
          }
          return {
            bind: (...args: unknown[]) => {
              const bound = statement.bind(...args);
              return {
                first: async <T>() => {
                  const row = await bound.first<Record<string, unknown>>();
                  return row
                    ? ({
                        ...row,
                        [field]: field === "audit_hmac"
                          ? "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                          : "wrong-challenge",
                      } as T)
                    : null;
                },
              };
            },
          } as unknown as D1PreparedStatement;
        },
        batch: env.DB.batch.bind(env.DB),
      }) as unknown as D1Database;

    await expect(
      new EmailRuntime(replayDb("audit_hmac"), rotatedKeys, new FixedClock(new Date("2026-09-10T00:00:00.000Z"))).issueChallenge(request)
    ).rejects.toMatchObject({ code: "idempotency_corrupt" });
    await expect(
      new EmailRuntime(replayDb("outbox_challenge_id"), rotatedKeys, new FixedClock(new Date("2026-09-10T00:00:00.000Z"))).issueChallenge(request)
    ).rejects.toMatchObject({ code: "idempotency_corrupt" });
  });

  it("replays concurrent identical issuance when a challenge uniqueness error wins first", async () => {
    const first = service(61);
    const second = service(61);
    const request = input("email-issue-race-001");

    const results = await Promise.all([first.issueChallenge(request), second.issueChallenge(request)]);
    expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
    expect(new Set(results.map((result) => result.id))).toEqual(new Set([request.id]));
  });

  it("classifies concurrent semantic changes as collisions and unrelated unique faults as corrupt", async () => {
    const first = service(62);
    const second = service(62);
    const request = input("email-semantic-race-001");
    const settled = await Promise.allSettled([
      first.issueChallenge(request),
      second.issueChallenge({ ...request, deliveryReference: "different-reference" }),
    ]);
    expect(settled.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejection = settled.find((result) => result.status === "rejected") as PromiseRejectedResult;
    expect(rejection.reason).toMatchObject({ code: "idempotency_collision" });

    await expect(
      first.issueChallenge({ ...input("email-unrelated-unique-001"), idempotencyKey: "request-a" })
    ).resolves.toMatchObject({ replayed: false });
    await expect(
      first.issueChallenge({ ...input("email-unrelated-unique-001"), idempotencyKey: "request-b" })
    ).rejects.toMatchObject({ code: "corrupt_state" });
  });

  it("rejects changed semantic bounds in idempotent replay", async () => {
    const runtime = service(8);
    const request = input("email-collision-001");
    await runtime.issueChallenge(request);

    await expect(runtime.issueChallenge({ ...request, maxAttempts: 3 })).rejects.toMatchObject({
      code: "idempotency_collision",
    });
  });

  it("detects idempotency witness corruption", async () => {
    const runtime = service(9);
    const request = input("email-corrupt-001");
    await runtime.issueChallenge(request);

    await expect(
      env.DB.exec(
        "UPDATE email_issue_witnesses SET evidence_hmac='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE idempotency_key='request-email-corrupt-001'"
      )
    ).rejects.toThrow(/email issue witness is immutable/);
  });

  it("consumes a valid token exactly once under race", async () => {
    const runtime = service(10);
    const request = input("email-once-001");
    const issued = await runtime.issueChallenge(request);

    await expect(
      runtime.verifyChallenge({
        id: request.id,
        accountId: request.accountId,
        purpose: request.purpose,
        token: issued.token!,
      })
    ).resolves.toBeUndefined();

    await expect(
      runtime.verifyChallenge({
        id: request.id,
        accountId: request.accountId,
        purpose: request.purpose,
        token: issued.token!,
      })
    ).rejects.toMatchObject({ code: "challenge_consumed" });
  });

  it("bounds wrong-token attempts and expires deterministically", async () => {
    const runtime = service(11);
    const request = input("email-attempts-001");
    const issued = await runtime.issueChallenge(request);

    const wrong = (prefix: string) => (issued.token![0] === prefix ? "C" : prefix) + issued.token!.slice(1);

    await expect(
      runtime.verifyChallenge({
        id: request.id,
        accountId: request.accountId,
        purpose: request.purpose,
        token: wrong("A"),
      })
    ).rejects.toMatchObject({ code: "invalid_token" });

    await expect(
      runtime.verifyChallenge({
        id: request.id,
        accountId: request.accountId,
        purpose: request.purpose,
        token: wrong("B"),
      })
    ).rejects.toMatchObject({ code: "invalid_token" });

    const challenge = await env.DB.prepare(
      "SELECT state,failed_attempts FROM email_challenges WHERE id=?"
    )
      .bind(request.id)
      .first<Record<string, unknown>>();
    expect(challenge).toMatchObject({ state: "expired", failed_attempts: 2 });

    expect(await runtime.claimDeliveryJobs("worker-1")).toEqual([]);
  });

  it("enforces key ID separation between token-HMAC and delivery-AEAD", async () => {
    const badRing = {
      token: { current: { id: "shared", material: new Uint8Array(32).fill(1) } },
      delivery: { current: { id: "shared", material: new Uint8Array(32).fill(2) } },
    };
    expect(
      () => new EmailRuntime(env.DB, badRing, new FixedClock(new Date("2026-09-10T00:00:00.000Z")))
    ).toThrow();
  });

  it("enforces key material separation between token and delivery", async () => {
    const shared = new Uint8Array(32).fill(42);
    const badRing = {
      token: { current: { id: "token-x", material: shared } },
      delivery: { current: { id: "delivery-y", material: shared } },
    };
    expect(
      () => new EmailRuntime(env.DB, badRing, new FixedClock(new Date("2026-09-10T00:00:00.000Z")))
    ).toThrow();
  });


  it("creates immutable claim witnesses and advances the fence on expired-lease reclaim", async () => {
    const runtime = service(12);
    const request = input("email-witness-001");
    await runtime.issueChallenge(request);

    const [claim1] = await runtime.claimDeliveryJobs("worker-1");
    expect(claim1).toBeDefined();

    const witness1 = await env.DB.prepare("SELECT * FROM email_delivery_witnesses WHERE job_id=? AND fence=?")
      .bind(claim1!.id, claim1!.fence)
      .first<Record<string, unknown>>();
    expect(witness1).toBeDefined();
    expect(witness1!.fence).toBe("2");

    const expiredClock = new FixedClock(new Date("2026-09-10T00:02:00.000Z"));
    const expiredRuntime = new EmailRuntime(env.DB, keys(12), expiredClock);

    const [claim2] = await expiredRuntime.claimDeliveryJobs("worker-2");
    expect(claim2?.id).toBe(claim1!.id);
    expect(claim2?.fence).toBe("3");

    const witness2 = await env.DB.prepare("SELECT * FROM email_delivery_witnesses WHERE job_id=? AND fence=?")
      .bind(claim1!.id, claim2!.fence)
      .first<Record<string, unknown>>();
    expect(witness2!.job_version).not.toBe(witness1!.job_version);
    expect(witness2!.fence).toBe("3");
  });

  it("completes delivery idempotently after ambiguous commit", async () => {
    const runtime = service(13);
    const request = input("email-complete-001");
    await runtime.issueChallenge(request);

    const [claim] = await runtime.claimDeliveryJobs("worker-1");
    expect(claim).toBeDefined();

    await runtime.completeDelivery(claim!.id, "worker-1", claim!.fence);

    const job1 = await env.DB.prepare("SELECT state,version FROM email_delivery_jobs WHERE id=?")
      .bind(claim!.id)
      .first<{ state: string; version: string }>();
    expect(job1!.state).toBe("delivered");

    await expect(runtime.completeDelivery(claim!.id, "worker-1", claim!.fence)).resolves.toBeUndefined();
    const delivered = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM email_runtime_audit WHERE job_id=? AND event='delivered'"
    )
      .bind(claim!.id)
      .first<{ count: number }>();
    expect(delivered?.count).toBe(1);
  });

  it("enforces claim limit and ordering", async () => {
    const runtime = service(14);
    await runtime.issueChallenge({ ...input("email-claim-001"), expiresAt: "2026-09-10T00:10:00.000Z" });
    await runtime.issueChallenge({ ...input("email-claim-002"), expiresAt: "2026-09-10T00:10:00.000Z" });
    await runtime.issueChallenge({ ...input("email-claim-003"), expiresAt: "2026-09-10T00:10:00.000Z" });

    const claims = await runtime.claimDeliveryJobs("worker-1", 2);
    expect(claims).toHaveLength(2);
    expect(claims[0]!.challengeId).toBe("email-claim-001");
    expect(claims[1]!.challengeId).toBe("email-claim-002");
  });

  it("prevents concurrent same-worker claim", async () => {
    const runtime = service(15);
    await runtime.issueChallenge(input("email-concurrent-001"));

    const [claim1] = await runtime.claimDeliveryJobs("worker-1");
    expect(claim1).toBeDefined();

    const [claim2] = await runtime.claimDeliveryJobs("worker-1");
    expect(claim2).toBeUndefined();
  });

  it("rolls back loser artifacts in a concurrent D1 claim race", async () => {
    const first = service(151);
    const second = service(151);
    await first.issueChallenge(input("email-d1-race-001"));

    const [a, b] = await Promise.all([
      first.claimDeliveryJobs("worker-a"),
      second.claimDeliveryJobs("worker-b"),
    ]);
    const claims = [...a, ...b];
    expect(claims).toHaveLength(1);

    const jobId = claims[0]!.id;
    const audit = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM email_runtime_audit WHERE job_id=? AND event='claimed'"
    )
      .bind(jobId)
      .first<{ count: number }>();
    const outbox = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM email_runtime_outbox WHERE job_id=? AND event='claimed'"
    )
      .bind(jobId)
      .first<{ count: number }>();
    const witnesses = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM email_delivery_witnesses WHERE job_id=?"
    )
      .bind(jobId)
      .first<{ count: number }>();
    expect(audit?.count).toBe(1);
    expect(outbox?.count).toBe(1);
    expect(witnesses?.count).toBe(1);
  });

  it("reclaims expired lease with higher fence", async () => {
    const runtime = service(16);
    await runtime.issueChallenge(input("email-reclaim-001"));

    const [claim1] = await runtime.claimDeliveryJobs("worker-1");
    expect(claim1!.fence).toBe("2");

    const expiredClock = new FixedClock(new Date("2026-09-10T00:02:00.000Z"));
    const expiredRuntime = new EmailRuntime(env.DB, keys(16), expiredClock);

    const [claim2] = await expiredRuntime.claimDeliveryJobs("worker-2");
    expect(claim2!.id).toBe(claim1!.id);
    expect(claim2!.fence).toBe("3");
  });

  it("fences an expired claim even when the same worker name reclaims it", async () => {
    const runtime = service(161);
    await runtime.issueChallenge(input("email-fence-race-001"));
    const [first] = await runtime.claimDeliveryJobs("worker-1");
    const reclaimed = new EmailRuntime(
      env.DB,
      keys(161),
      new FixedClock(new Date("2026-09-10T00:02:00.000Z"))
    );
    const [second] = await reclaimed.claimDeliveryJobs("worker-1");

    await expect(reclaimed.completeDelivery(first!.id, "worker-1", first!.fence)).rejects.toMatchObject({
      code: "stale_fence",
      retryable: true,
      terminal: false,
    });
    await expect(reclaimed.completeDelivery(second!.id, "worker-1", second!.fence)).resolves.toBeUndefined();
  });

  it("rejects wrong owner, wrong fence, and expired lease", async () => {
    const runtime = service(17);
    await runtime.issueChallenge(input("email-fence-001"));

    const [claim] = await runtime.claimDeliveryJobs("worker-1");
    expect(claim).toBeDefined();

    await expect(runtime.renewDelivery(claim!.id, "worker-2", claim!.fence)).rejects.toMatchObject({
      code: "stale_fence",
    });
    await expect(runtime.renewDelivery(claim!.id, "worker-1", "999")).rejects.toMatchObject({
      code: "stale_fence",
    });

    const expiredClock = new FixedClock(new Date("2026-09-10T00:02:00.000Z"));
    const expiredRuntime = new EmailRuntime(env.DB, keys(17), expiredClock);

    await expect(
      expiredRuntime.renewDelivery(claim!.id, "worker-1", claim!.fence)
    ).rejects.toMatchObject({ code: "stale_fence" });
  });

  it("implements bounded exponential backoff on failure", async () => {
    const runtime = service(18);
    const request = { ...input("email-backoff-001"), maxDeliveryAttempts: 5 };
    await runtime.issueChallenge(request);

    const [claim1] = await runtime.claimDeliveryJobs("worker-1");
    const result1 = await runtime.failDelivery(claim1!.id, "worker-1", claim1!.fence, "provider-timeout");
    expect(result1).toBe("pending");

    const job1 = await env.DB.prepare("SELECT attempt,not_before FROM email_delivery_jobs WHERE id=?")
      .bind(claim1!.id)
      .first<{ attempt: number; not_before: string }>();
    expect(job1!.attempt).toBe(1);

    const backoffClock = new FixedClock(new Date(Date.parse(job1!.not_before) + 1000));
    const backoffRuntime = new EmailRuntime(env.DB, keys(18), backoffClock);

    const [claim2] = await backoffRuntime.claimDeliveryJobs("worker-1");
    expect(claim2!.id).toBe(claim1!.id);
  });

  it("moves to dead state on max-attempt exhaustion", async () => {
    const runtime = service(19);
    const request = { ...input("email-dead-001"), maxDeliveryAttempts: 2 };
    await runtime.issueChallenge(request);

    const [claim1] = await runtime.claimDeliveryJobs("worker-1");
    await runtime.failDelivery(claim1!.id, "worker-1", claim1!.fence, "error-1");

    const job1 = await env.DB.prepare("SELECT not_before FROM email_delivery_jobs WHERE id=?")
      .bind(claim1!.id)
      .first<{ not_before: string }>();

    const clock2 = new FixedClock(new Date(Date.parse(job1!.not_before) + 1000));
    const runtime2 = new EmailRuntime(env.DB, keys(19), clock2);

    const [claim2] = await runtime2.claimDeliveryJobs("worker-1");
    const result2 = await runtime2.failDelivery(claim2!.id, "worker-1", claim2!.fence, "error-2");
    expect(result2).toBe("dead");

    const job2 = await env.DB.prepare("SELECT state,attempt FROM email_delivery_jobs WHERE id=?")
      .bind(claim1!.id)
      .first<{ state: string; attempt: number }>();
    expect(job2!.state).toBe("dead");
    expect(job2!.attempt).toBe(2);

    expect(await runtime2.claimDeliveryJobs("worker-1")).toEqual([]);
    await expect(runtime2.failDelivery(claim2!.id, "worker-1", claim2!.fence, "error-2")).resolves.toBe(
      "dead"
    );
  });

  it("replays a retry schedule without consuming a second delivery attempt", async () => {
    const runtime = service(191);
    await runtime.issueChallenge({ ...input("email-fail-replay-001"), maxDeliveryAttempts: 3 });
    const [claim] = await runtime.claimDeliveryJobs("worker-1");
    await expect(runtime.failDelivery(claim!.id, "worker-1", claim!.fence, "provider-timeout")).resolves.toBe(
      "pending"
    );
    await expect(runtime.failDelivery(claim!.id, "worker-1", claim!.fence, "provider-timeout")).resolves.toBe(
      "pending"
    );
    const job = await env.DB.prepare("SELECT attempt FROM email_delivery_jobs WHERE id=?")
      .bind(claim!.id)
      .first<{ attempt: number }>();
    expect(job?.attempt).toBe(1);
  });

  it("cancels job when challenge expires", async () => {
    const runtime = service(20);
    await runtime.issueChallenge(input("email-expire-001"));

    const [claim] = await runtime.claimDeliveryJobs("worker-1");
    expect(claim).toBeDefined();

    const expiredClock = new FixedClock(new Date("2026-09-10T00:11:00.000Z"));
    const expiredRuntime = new EmailRuntime(env.DB, keys(20), expiredClock);

    await expect(
      expiredRuntime.renewDelivery(claim!.id, "worker-1", claim!.fence)
    ).rejects.toMatchObject({ code: "challenge_expired" });

    const job = await env.DB.prepare("SELECT state FROM email_delivery_jobs WHERE id=?")
      .bind(claim!.id)
      .first<{ state: string }>();
    expect(job!.state).toBe("cancelled");
  });

  it("cancels pending job when challenge is consumed", async () => {
    const runtime = service(21);
    const request = input("email-consume-001");
    const issued = await runtime.issueChallenge(request);

    await runtime.verifyChallenge({
      id: request.id,
      accountId: request.accountId,
      purpose: request.purpose,
      token: issued.token!,
    });

    expect(await runtime.claimDeliveryJobs("worker-1")).toEqual([]);

    const job = await env.DB.prepare("SELECT state FROM email_delivery_jobs WHERE challenge_id=?")
      .bind(request.id)
      .first<{ state: string }>();
    expect(job!.state).toBe("cancelled");
  });

  it("consumes a claimed job atomically with its cancellation", async () => {
    const runtime = service(211);
    const request = input("email-consume-claimed-001");
    const issued = await runtime.issueChallenge(request);
    const [claim] = await runtime.claimDeliveryJobs("worker-1");
    expect(claim).toBeDefined();

    await runtime.verifyChallenge({
      id: request.id,
      accountId: request.accountId,
      purpose: request.purpose,
      token: issued.token!,
    });

    const state = await env.DB.prepare(
      "SELECT c.state AS challenge_state,j.state AS job_state FROM email_challenges c JOIN email_delivery_jobs j ON j.challenge_id=c.id WHERE c.id=?"
    )
      .bind(request.id)
      .first<Record<string, string>>();
    expect(state).toEqual({ challenge_state: "consumed", job_state: "cancelled" });
  });

  it("expires and cancels a selected job in one guarded transition", async () => {
    const runtime = service(212);
    const request = input("email-expire-claim-001");
    await runtime.issueChallenge(request);
    const expired = new EmailRuntime(
      env.DB,
      keys(212),
      new FixedClock(new Date("2026-09-10T00:11:00.000Z"))
    );

    expect(await expired.claimDeliveryJobs("worker-1")).toEqual([]);
    const state = await env.DB.prepare(
      "SELECT c.state AS challenge_state,j.state AS job_state FROM email_challenges c JOIN email_delivery_jobs j ON j.challenge_id=c.id WHERE c.id=?"
    )
      .bind(request.id)
      .first<Record<string, string>>();
    expect(state).toEqual({ challenge_state: "expired", job_state: "cancelled" });
  });

  it("refuses a stale selected pending job after its retry defers not_before and version", async () => {
    const issuer = service(213);
    const request = input("email-stale-selection-001");
    await issuer.issueChallenge(request);
    let injected = false;
    const staleSelectingDb = {
      prepare: (...args: Parameters<typeof env.DB.prepare>) => env.DB.prepare(...args),
      batch: async (statements: D1PreparedStatement[]) => {
        if (!injected) {
          injected = true;
          await env.DB.prepare(
            "UPDATE email_delivery_jobs SET not_before=?,version='2',updated_at=? WHERE challenge_id=?"
          )
            .bind("2026-09-10T00:05:00.000Z", "2026-09-10T00:00:00.000Z", request.id)
            .run();
        }
        return env.DB.batch(statements);
      },
    } as unknown as D1Database;
    const claimant = new EmailRuntime(
      staleSelectingDb,
      keys(213),
      new FixedClock(new Date("2026-09-10T00:00:00.000Z"))
    );

    await expect(claimant.claimDeliveryJobs("worker-1")).resolves.toEqual([]);
    const job = await env.DB.prepare("SELECT state,not_before,version,fence FROM email_delivery_jobs WHERE challenge_id=?")
      .bind(request.id)
      .first<Record<string, string>>();
    expect(job).toEqual({ state: "pending", not_before: "2026-09-10T00:05:00.000Z", version: "2", fence: "1" });
  });

  it("enforces terminal state no-regression", async () => {
    const runtime = service(22);
    await runtime.issueChallenge(input("email-terminal-001"));

    const [claim] = await runtime.claimDeliveryJobs("worker-1");
    await runtime.completeDelivery(claim!.id, "worker-1", claim!.fence);

    await expect(
      env.DB.prepare("UPDATE email_delivery_jobs SET state='pending' WHERE id=?").bind(claim!.id).run()
    ).rejects.toThrow(/illegal email job transition/);
  });

  it("enforces challenge version monotonic increment", async () => {
    const runtime = service(23);
    const request = input("email-version-001");
    await runtime.issueChallenge(request);

    await expect(
      env.DB.prepare("UPDATE email_challenges SET version='1' WHERE id=?").bind(request.id).run()
    ).rejects.toThrow(/illegal email challenge transition/);
  });

  it("enforces immutable challenge identity fields", async () => {
    const runtime = service(24);
    await runtime.issueChallenge(input("email-immutable-001"));

    await expect(
      env.DB.prepare("UPDATE email_challenges SET account_id='other',version='2' WHERE id=?")
        .bind("email-immutable-001")
        .run()
    ).rejects.toThrow(/email challenge immutable identity violated/);
  });

  it("enforces immutable audit and outbox", async () => {
    const runtime = service(25);
    await runtime.issueChallenge(input("email-audit-001"));

    const audit = await env.DB.prepare("SELECT audit_id FROM email_runtime_audit LIMIT 1")
      .first<{ audit_id: string }>();

    await expect(
      env.DB.prepare("UPDATE email_runtime_audit SET event='cancelled' WHERE audit_id=?")
        .bind(audit!.audit_id)
        .run()
    ).rejects.toThrow(/email audit is immutable/);

    await expect(
      env.DB.prepare("DELETE FROM email_runtime_audit WHERE audit_id=?").bind(audit!.audit_id).run()
    ).rejects.toThrow(/email audit is immutable/);
  });

  it("validates stored row decimal bounds", async () => {
    const runtime = service(26);
    await runtime.issueChallenge(input("email-bounds-001"));

    await expect(
      env.DB.prepare("UPDATE email_challenges SET version='9223372036854775808' WHERE id=?")
        .bind("email-bounds-001")
        .run()
    ).rejects.toThrow(/illegal email challenge transition|SQLITE_CONSTRAINT/);
  });

  it("validates base64url canonical form", async () => {
    const runtime = service(27);
    await runtime.issueChallenge(input("email-base64-001"));

    await expect(
      env.DB.exec(
        "UPDATE email_challenges SET token_verifier='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' WHERE id='email-base64-001'"
      )
    ).rejects.toThrow(/illegal email challenge transition|SQLITE_CONSTRAINT/);
  });

  it("distinguishes true stale CAS from storage/constraint failures", async () => {
    const runtime = service(28);
    await runtime.issueChallenge(input("email-error-001"));

    const [claim] = await runtime.claimDeliveryJobs("worker-1");
    await runtime.completeDelivery(claim!.id, "worker-1", claim!.fence);

    await expect(runtime.renewDelivery(claim!.id, "worker-1", claim!.fence)).rejects.toMatchObject({
      code: "stale_fence",
    });
  });

  it("enforces CHECK constraint on key ID uniqueness", async () => {
    await expect(
      env.DB.prepare(
        "INSERT INTO email_challenges(id,account_id,purpose,token_hmac_key_id,token_verifier,token_envelope_key_id,token_nonce,token_ciphertext,delivery_envelope_key_id,delivery_nonce,delivery_ciphertext,state,failed_attempts,max_attempts,expires_at,created_at,version) VALUES('dup-key-001','acct','purpose','same','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','same','AAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','other','AAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAAAAAAA','issued',0,2,'2026-09-10T01:00:00.000Z','2026-09-10T00:00:00.000Z','1')"
      ).run()
    ).rejects.toThrow(/CHECK constraint failed/);
  });
});
