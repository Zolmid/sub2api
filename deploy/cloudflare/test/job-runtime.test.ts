import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  claimJob,
  claimOutbox,
  createAndEnqueueJob,
  drainOutbox,
  getJob,
  listDrainableOutbox,
  makeQueueEnvelope,
  markOutboxPublished,
  moveToManualReview,
  parseQueueEnvelope,
  processQueueBatch,
  recoverExpiredJob,
  recordPermanentFailure,
  recordRetryableFailure,
  renewJobLease,
  replayTerminalJob,
  releaseOutbox,
  startJob,
  succeedJob,
  type ClaimResult,
  type CreateJobInput,
  type JobRecord,
  type QueueEnvelope,
  type QueueMessageLike,
} from "../src/job-runtime";

const db = env.DB;

function id(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}`;
}

function createInput(overrides: Partial<CreateJobInput> = {}): CreateJobInput {
  const suffix = crypto.randomUUID();
  return {
    jobId: `job-${suffix}`,
    operationId: `create-${suffix}`,
    route: "maintenance.v1",
    jobType: "generic-test",
    idempotencyKey: `idem-${suffix}`,
    payloadCodec: "json",
    payloadBody: JSON.stringify({ private: "person@example.test", token: "db-only" }),
    payloadDigest: `sha256:${suffix}`,
    maxAttempts: 3,
    baseDelayMs: 10,
    maxDelayMs: 100,
    nowMs: 100,
    actor: "test-producer",
    ...overrides,
  };
}

async function create(overrides: Partial<CreateJobInput> = {}) {
  const input = createInput(overrides);
  const result = await createAndEnqueueJob(db, input);
  expect(result.kind).toBe("applied");
  expect(result.job).not.toBeNull();
  return { input, job: result.job as JobRecord, envelope: makeQueueEnvelope(input.jobId, input.route, 1) };
}

async function claim(
  envelope: QueueEnvelope,
  nowMs: number,
  suffix = crypto.randomUUID(),
): Promise<ClaimResult> {
  return claimJob(db, envelope, {
    operationId: `claim-${suffix}`,
    owner: `worker-${suffix}`,
    leaseToken: `lease-${suffix}`,
    deliveryId: `delivery-${suffix}`,
    nowMs,
    leaseMs: 1_000,
  });
}

async function running(envelope: QueueEnvelope, nowMs: number) {
  const claimed = await claim(envelope, nowMs);
  expect(claimed.kind).toBe("claimed");
  const job = claimed.job as JobRecord;
  const started = await startJob(db, {
    jobId: job.jobId,
    expectedVersion: job.version,
    operationId: id("start"),
    owner: job.leaseOwner as string,
    leaseToken: job.leaseToken as string,
    nowMs: nowMs + 1,
  });
  expect(started.kind).toBe("applied");
  return started.job as JobRecord;
}

async function counts(jobId: string) {
  const transitions = await db.prepare(
    "SELECT count(*) count FROM background_job_transitions WHERE job_id=?",
  ).bind(jobId).first<{ count: number }>();
  const outbox = await db.prepare(
    "SELECT count(*) count FROM background_job_outbox WHERE job_id=?",
  ).bind(jobId).first<{ count: number }>();
  return { transitions: transitions?.count ?? -1, outbox: outbox?.count ?? -1 };
}

describe("D1 background job runtime", () => {
  it("commits create, transition, and enqueue atomically and recovers a pending outbox", async () => {
    const { input, job } = await create();
    expect(job).toMatchObject({ status: "queued", version: 1, attemptCount: 0 });
    expect(await counts(job.jobId)).toEqual({ transitions: 1, outbox: 1 });

    // Crash window: the D1 commit happened but no Queue publish happened.
    const pending = await listDrainableOutbox(db, input.nowMs);
    const item = pending.find((row) => row.jobId === job.jobId);
    expect(item?.state).toBe("pending");
    const published: QueueEnvelope[] = [];
    const drained = await drainOutbox(db, { send: async (value) => { published.push(value); } }, {
      owner: id("drainer"), nowMs: input.nowMs, leaseMs: 50, failureDelayMs: 10,
      now: () => input.nowMs,
    });
    expect(drained.find((row) => row.outboxId === item?.outboxId)?.outcome).toBe("published");
    expect(published).toContainEqual(makeQueueEnvelope(job.jobId, input.route, 1));
  });

  it("accepts one claim and makes ten duplicate deliveries harmless", async () => {
    const { job, envelope } = await create();
    expect((await claim(envelope, 100)).kind).toBe("claimed");
    for (let duplicate = 0; duplicate < 10; duplicate += 1) {
      const result = await claim(envelope, 100, `${duplicate}-${crypto.randomUUID()}`);
      expect(result).toMatchObject({ kind: "noop", disposition: "ack", reason: "stale_delivery" });
    }
    const transitions = await db.prepare(
      "SELECT count(*) count FROM background_job_transitions WHERE job_id=? AND event_type='claimed'",
    ).bind(job.jobId).first<{ count: number }>();
    expect(transitions?.count).toBe(1);
    expect((await getJob(db, job.jobId))?.attemptCount).toBe(1);
  });

  it("renews claimed and running leases with versioned fencing and an immutable ledger event", async () => {
    const created = await create();
    const claimed = await claim(created.envelope, 100);
    const original = claimed.job as JobRecord;
    const renewalOperation = id("renew-claimed");
    const renewed = await renewJobLease(db, {
      jobId: original.jobId,
      expectedVersion: original.version,
      operationId: renewalOperation,
      owner: original.leaseOwner as string,
      leaseToken: original.leaseToken as string,
      nowMs: 200,
      leaseExpiresAtMs: 1_500,
    });
    expect(renewed).toMatchObject({
      kind: "applied",
      reason: "lease_renewed",
      job: {
        status: "claimed",
        version: original.version + 1,
        attemptCount: original.attemptCount,
        leaseExpiresAtMs: 1_500,
        updatedAtMs: 200,
      },
    });
    const renewedClaim = renewed.job as JobRecord;
    const beforeRejected = await counts(original.jobId);
    await expect(renewJobLease(db, {
      jobId: original.jobId,
      expectedVersion: original.version,
      operationId: renewalOperation,
      owner: original.leaseOwner as string,
      leaseToken: original.leaseToken as string,
      nowMs: 201,
      leaseExpiresAtMs: 1_600,
    })).resolves.toMatchObject({ kind: "noop", reason: "stale_or_nonextending_lease" });
    await expect(renewJobLease(db, {
      jobId: original.jobId,
      expectedVersion: renewedClaim.version,
      operationId: id("wrong-owner"),
      owner: "wrong-owner",
      leaseToken: renewedClaim.leaseToken as string,
      nowMs: 201,
      leaseExpiresAtMs: 1_600,
    })).resolves.toMatchObject({ kind: "noop" });
    await expect(renewJobLease(db, {
      jobId: original.jobId,
      expectedVersion: renewedClaim.version,
      operationId: id("nonextending"),
      owner: renewedClaim.leaseOwner as string,
      leaseToken: renewedClaim.leaseToken as string,
      nowMs: 201,
      leaseExpiresAtMs: 1_500,
    })).resolves.toMatchObject({ kind: "noop", reason: "stale_or_nonextending_lease" });
    expect(await counts(original.jobId)).toEqual(beforeRejected);

    const started = await startJob(db, {
      jobId: renewedClaim.jobId,
      expectedVersion: renewedClaim.version,
      operationId: id("start-after-renewal"),
      owner: renewedClaim.leaseOwner as string,
      leaseToken: renewedClaim.leaseToken as string,
      nowMs: 202,
    });
    const runningJob = started.job as JobRecord;
    const runningRenewal = await renewJobLease(db, {
      jobId: runningJob.jobId,
      expectedVersion: runningJob.version,
      operationId: id("renew-running"),
      owner: runningJob.leaseOwner as string,
      leaseToken: runningJob.leaseToken as string,
      nowMs: 300,
      leaseExpiresAtMs: 1_700,
    });
    expect(runningRenewal).toMatchObject({
      kind: "applied", reason: "lease_renewed",
      job: { status: "running", version: runningJob.version + 1, leaseExpiresAtMs: 1_700 },
    });
    const current = runningRenewal.job as JobRecord;
    await expect(renewJobLease(db, {
      jobId: current.jobId,
      expectedVersion: current.version,
      operationId: id("expired-renewal"),
      owner: current.leaseOwner as string,
      leaseToken: current.leaseToken as string,
      nowMs: 1_700,
      leaseExpiresAtMs: 1_800,
    })).resolves.toMatchObject({ kind: "noop" });
    await expect(renewJobLease(db, {
      jobId: current.jobId,
      expectedVersion: current.version,
      operationId: id("overflow-renewal"),
      owner: current.leaseOwner as string,
      leaseToken: current.leaseToken as string,
      nowMs: 301,
      leaseExpiresAtMs: 4_102_444_800_001,
    })).rejects.toThrow("INVALID_TIME");

    const duplicateTarget = await create();
    const duplicateClaim = await claim(duplicateTarget.envelope, 100);
    const duplicateJob = duplicateClaim.job as JobRecord;
    await expect(renewJobLease(db, {
      jobId: duplicateJob.jobId,
      expectedVersion: duplicateJob.version,
      operationId: renewalOperation,
      owner: duplicateJob.leaseOwner as string,
      leaseToken: duplicateJob.leaseToken as string,
      nowMs: 200,
      leaseExpiresAtMs: 1_500,
    })).rejects.toThrow();
    expect(await getJob(db, duplicateJob.jobId)).toMatchObject({
      version: duplicateJob.version,
      leaseExpiresAtMs: duplicateJob.leaseExpiresAtMs,
    });

    const events = await db.prepare(`SELECT event_type,from_status,to_status,from_version,to_version
      FROM background_job_transitions WHERE job_id=? AND event_type='lease_renewed'
      ORDER BY to_version`).bind(original.jobId).all<Record<string, unknown>>();
    expect(events.results).toEqual([
      expect.objectContaining({ event_type: "lease_renewed", from_status: "claimed", to_status: "claimed" }),
      expect.objectContaining({ event_type: "lease_renewed", from_status: "running", to_status: "running" }),
    ]);
  });

  it("loses an optimistic CAS race without orphan transition or outbox rows", async () => {
    const { job, envelope } = await create();
    const active = await running(envelope, 100);
    const before = await counts(job.jobId);
    const base = {
      jobId: active.jobId,
      expectedVersion: active.version,
      owner: active.leaseOwner as string,
      leaseToken: active.leaseToken as string,
      nowMs: 102,
      errorCode: "retryable_provider_error",
      effectState: "started_known_failure" as const,
    };
    const [left, right] = await Promise.all([
      recordRetryableFailure(db, { ...base, operationId: id("race-left") }),
      recordRetryableFailure(db, { ...base, operationId: id("race-right") }),
    ]);
    expect([left.kind, right.kind].sort()).toEqual(["applied", "noop"]);
    const after = await counts(job.jobId);
    expect(after.transitions - before.transitions).toBe(1);
    expect(after.outbox - before.outbox).toBe(1);

    const stale = await recordRetryableFailure(db, { ...base, operationId: id("stale") });
    expect(stale.kind).toBe("noop");
    expect(await counts(job.jobId)).toEqual(after);
  });

  it("cannot regress a terminal job through late completion or failure", async () => {
    const { job, envelope } = await create();
    const active = await running(envelope, 100);
    const succeeded = await succeedJob(db, {
      jobId: active.jobId,
      expectedVersion: active.version,
      operationId: id("succeed"),
      owner: active.leaseOwner as string,
      leaseToken: active.leaseToken as string,
      nowMs: 102,
      resultDigest: "sha256:result",
    });
    expect(succeeded.job?.status).toBe("succeeded");
    const terminal = succeeded.job as JobRecord;
    const before = await counts(job.jobId);
    const lateFailure = await recordPermanentFailure(db, {
      jobId: terminal.jobId,
      expectedVersion: terminal.version,
      operationId: id("late-failure"),
      owner: active.leaseOwner as string,
      leaseToken: active.leaseToken as string,
      nowMs: 103,
      errorCode: "late",
      effectState: "started_known_failure",
    });
    const lateSuccess = await succeedJob(db, {
      jobId: terminal.jobId,
      expectedVersion: active.version,
      operationId: id("late-success"),
      owner: active.leaseOwner as string,
      leaseToken: active.leaseToken as string,
      nowMs: 103,
      resultDigest: "sha256:different",
    });
    expect(lateFailure).toMatchObject({ kind: "noop", reason: "terminal" });
    expect(lateSuccess.kind).toBe("noop");
    expect(await counts(job.jobId)).toEqual(before);
    expect(await getJob(db, job.jobId)).toMatchObject({
      status: "succeeded", version: terminal.version, resultDigest: "sha256:result",
    });
    await expect(db.prepare(
      "UPDATE background_jobs SET status='retry_wait',version=version+1 WHERE job_id=?",
    ).bind(job.jobId).run()).rejects.toThrow("background job transition");
  });

  it("recovers publish-before-mark as a duplicate publication", async () => {
    const { input, job } = await create();
    const listed = (await listDrainableOutbox(db, input.nowMs)).find((row) => row.jobId === job.jobId);
    expect(listed).toBeDefined();
    const owner = id("publisher");
    const claimed = await claimOutbox(db, {
      outboxId: listed!.outboxId,
      expectedVersion: listed!.version,
      owner,
      nowMs: 100,
      leaseMs: 10,
    });
    expect(claimed?.state).toBe("publishing");
    const sent = [claimed!.envelope]; // Queue accepted it; process crashed before mark.
    expect((await listDrainableOutbox(db, 109)).some((row) => row.outboxId === listed!.outboxId)).toBe(false);
    const drained = await drainOutbox(db, { send: async (envelope) => { sent.push(envelope); } }, {
      owner: id("recovery"), nowMs: 110, leaseMs: 10, failureDelayMs: 1,
      now: () => 110,
    });
    expect(drained.find((row) => row.outboxId === listed!.outboxId)?.outcome).toBe("published");
    const targetPublishes = sent.filter((envelope) => envelope.jobId === job.jobId);
    expect(targetPublishes).toHaveLength(2);
    expect(targetPublishes[0]).toEqual(targetPublishes[1]);
  });

  it("uses a fresh post-publication clock and fences a publisher whose lease expired during send", async () => {
    const first = await create();
    const firstOutbox = (await listDrainableOutbox(db, 100))
      .find((row) => row.jobId === first.job.jobId)!;
    let freshReads = 0;
    const published = await drainOutbox(db, { send: async () => undefined }, {
      owner: id("fresh-publisher"), nowMs: 100, leaseMs: 100, failureDelayMs: 5,
      now: () => { freshReads += 1; return 125; },
    });
    expect(published.find((row) => row.outboxId === firstOutbox.outboxId)?.outcome).toBe("published");
    expect(freshReads).toBe(1);
    const persisted = await db.prepare(
      "SELECT state,published_at_ms FROM background_job_outbox WHERE outbox_id=?",
    ).bind(firstOutbox.outboxId).first<{ state: string; published_at_ms: number }>();
    expect(persisted).toEqual({ state: "published", published_at_ms: 125 });

    const second = await create();
    const secondOutbox = (await listDrainableOutbox(db, 100))
      .find((row) => row.jobId === second.job.jobId)!;
    const sent: QueueEnvelope[] = [];
    const expired = await drainOutbox(db, { send: async (envelope) => { sent.push(envelope); } }, {
      owner: id("slow-publisher"), nowMs: 100, leaseMs: 10, failureDelayMs: 5,
      now: () => 110,
    });
    expect(expired.find((row) => row.outboxId === secondOutbox.outboxId)?.outcome)
      .toBe("published_unmarked");
    const reclaimable = (await listDrainableOutbox(db, 110))
      .find((row) => row.outboxId === secondOutbox.outboxId)!;
    const reclaimed = await claimOutbox(db, {
      outboxId: reclaimable.outboxId,
      expectedVersion: reclaimable.version,
      owner: id("recovery-publisher"),
      nowMs: 110,
      leaseMs: 10,
    });
    expect(reclaimed?.envelope).toEqual(sent[0]);
  });

  it("reports a failed publish whose expired publisher lease could not be released", async () => {
    const created = await create();
    const outbox = (await listDrainableOutbox(db, 100))
      .find((row) => row.jobId === created.job.jobId)!;
    const outcomes = await drainOutbox(db, { send: async () => { throw new Error("queue down"); } }, {
      owner: id("failed-publisher"), nowMs: 100, leaseMs: 10, failureDelayMs: 5,
      now: () => 110,
    });
    expect(outcomes.find((row) => row.outboxId === outbox.outboxId)?.outcome)
      .toBe("publish_failed_unreleased");
    expect((await listDrainableOutbox(db, 110)).find((row) => row.outboxId === outbox.outboxId))
      .toMatchObject({ state: "publishing" });
  });

  it("makes consumer-commit-before-ack safe on redelivery", async () => {
    const { job, envelope } = await create();
    const active = await running(envelope, 100);
    await succeedJob(db, {
      jobId: active.jobId,
      expectedVersion: active.version,
      operationId: id("commit-success"),
      owner: active.leaseOwner as string,
      leaseToken: active.leaseToken as string,
      nowMs: 102,
      resultDigest: "sha256:done",
    });
    // No Queue ack was observed. The original envelope arrives again.
    const duplicate = await claim(envelope, 103);
    expect(duplicate).toMatchObject({ kind: "noop", disposition: "ack", reason: "stale_delivery" });
    expect(await getJob(db, job.jobId)).toMatchObject({ status: "succeeded", attemptCount: 1 });
  });

  it("settles a partial Queue batch per message", async () => {
    const first = await create();
    const second = await create();
    const calls = new Map<string, string[]>();
    const message = (messageId: string, body: unknown): QueueMessageLike => ({
      id: messageId,
      body,
      ack: () => calls.set(messageId, [...(calls.get(messageId) ?? []), "ack"]),
      retry: () => calls.set(messageId, [...(calls.get(messageId) ?? []), "retry"]),
    });
    const outcomes = await processQueueBatch([
      message("ok", first.envelope),
      message("temporary", second.envelope),
      message("invalid", { ...first.envelope, email: "must-not-be-here" }),
    ], async (envelope, messageId) => {
      if (messageId === "temporary") throw new Error("temporary failure");
      const result = await claim(envelope, 100);
      return { disposition: result.disposition, reason: result.reason };
    });
    expect(outcomes).toEqual([
      { disposition: "ack", reason: "claimed" },
      { disposition: "retry", reason: "handler_error" },
      { disposition: "ack", reason: "invalid_envelope" },
    ]);
    expect(calls).toEqual(new Map([
      ["ok", ["ack"]], ["temporary", ["retry"]], ["invalid", ["ack"]],
    ]));
  });

  it("uses bounded deterministic retry and reaches dead-letter", async () => {
    const created = await create({ maxAttempts: 2, baseDelayMs: 10, maxDelayMs: 10 });
    const first = await claim(created.envelope, 100);
    const firstJob = first.job as JobRecord;
    const retry = await recordRetryableFailure(db, {
      jobId: firstJob.jobId,
      expectedVersion: firstJob.version,
      operationId: id("retry-one"),
      owner: firstJob.leaseOwner as string,
      leaseToken: firstJob.leaseToken as string,
      nowMs: 101,
      errorCode: "not_started",
      effectState: "not_started",
    });
    expect(retry).toMatchObject({ kind: "applied", reason: "retry_scheduled", outboxCreated: true });
    expect(retry.job).toMatchObject({ status: "retry_wait", availableAtMs: 111, attemptCount: 1 });
    const secondEnvelope = makeQueueEnvelope(created.job.jobId, created.input.route, retry.job!.version);
    const second = await claim(secondEnvelope, 111);
    const runningSecond = await startJob(db, {
      jobId: second.job!.jobId,
      expectedVersion: second.job!.version,
      operationId: id("start-two"),
      owner: second.job!.leaseOwner as string,
      leaseToken: second.job!.leaseToken as string,
      nowMs: 112,
    });
    const dead = await recordRetryableFailure(db, {
      jobId: runningSecond.job!.jobId,
      expectedVersion: runningSecond.job!.version,
      operationId: id("retry-two"),
      owner: runningSecond.job!.leaseOwner as string,
      leaseToken: runningSecond.job!.leaseToken as string,
      nowMs: 113,
      errorCode: "known_failure",
      effectState: "started_known_failure",
    });
    expect(dead).toMatchObject({ kind: "applied", reason: "dead_lettered", outboxCreated: false });
    expect(dead.job).toMatchObject({ status: "dead_letter", attemptCount: 2 });
  });

  it("recovers never-started claims but quarantines expired running work", async () => {
    const neverStarted = await create();
    const firstClaim = await claim(neverStarted.envelope, 100);
    const recovered = await recoverExpiredJob(db, {
      jobId: neverStarted.job.jobId,
      expectedVersion: firstClaim.job!.version,
      operationId: id("recover-claim"),
      actor: "reconciler",
      nowMs: 1_100,
    });
    expect(recovered).toMatchObject({
      kind: "applied", reason: "claim_recovered", outboxCreated: true,
      job: { status: "retry_wait" },
    });

    const startedSource = await create();
    const active = await running(startedSource.envelope, 100);
    const quarantined = await recoverExpiredJob(db, {
      jobId: startedSource.job.jobId,
      expectedVersion: active.version,
      operationId: id("recover-running"),
      actor: "reconciler",
      nowMs: 1_100,
    });
    expect(quarantined).toMatchObject({
      kind: "applied", reason: "manual_review", outboxCreated: false,
      job: { status: "manual_review", errorCode: "unknown_result_after_lease_expiry" },
    });
  });

  it("keeps unknown side effects in manual review and replays terminals as new audited jobs", async () => {
    const source = await create({ maxAttempts: 1 });
    const active = await running(source.envelope, 100);
    const review = await moveToManualReview(db, {
      jobId: active.jobId,
      expectedVersion: active.version,
      operationId: id("manual"),
      owner: active.leaseOwner as string,
      leaseToken: active.leaseToken as string,
      nowMs: 102,
      reasonCode: "provider_result_unknown",
      evidenceRef: "provider:request-opaque",
    });
    expect(review.job?.status).toBe("manual_review");
    const blindRetry = await recordRetryableFailure(db, {
      jobId: active.jobId,
      expectedVersion: review.job!.version,
      operationId: id("blind"),
      owner: active.leaseOwner as string,
      leaseToken: active.leaseToken as string,
      nowMs: 103,
      errorCode: "unknown",
      effectState: "started_known_failure",
    });
    expect(blindRetry).toMatchObject({ kind: "noop", reason: "terminal" });

    const replay = await replayTerminalJob(db, {
      sourceJobId: source.job.jobId,
      expectedSourceVersion: review.job!.version,
      newJobId: id("replay-job"),
      operationId: id("replay-op"),
      replayKey: id("replay-key"),
      idempotencyKey: id("replay-idem"),
      actor: "operator-42",
      reasonCode: "verified_safe_to_retry",
      evidenceKind: "provider_query_no_effect",
      evidenceRef: "provider:query-opaque",
      nowMs: 104,
    });
    expect(replay).toMatchObject({ kind: "applied", reason: "replayed", outboxCreated: true });
    expect(replay.job).toMatchObject({ status: "queued", version: 1, replayOfJobId: source.job.jobId });
    expect(await getJob(db, source.job.jobId)).toMatchObject({ status: "manual_review", version: review.job!.version });
    const events = await db.prepare(
      "SELECT event_type,actor,reason_code,evidence_ref FROM background_job_transitions WHERE job_id=?",
    ).bind(replay.job!.jobId).all<Record<string, unknown>>();
    expect(events.results).toEqual([expect.objectContaining({
      event_type: "replayed", actor: "operator-42", reason_code: "verified_safe_to_retry",
    })]);
  });

  it("explicitly replays a dead-letter without changing its history", async () => {
    const source = await create({ maxAttempts: 1 });
    const claimed = await claim(source.envelope, 100);
    const dead = await recordRetryableFailure(db, {
      jobId: source.job.jobId,
      expectedVersion: claimed.job!.version,
      operationId: id("dead"),
      owner: claimed.job!.leaseOwner as string,
      leaseToken: claimed.job!.leaseToken as string,
      nowMs: 101,
      errorCode: "attempts_exhausted",
      effectState: "not_started",
    });
    expect(dead.job?.status).toBe("dead_letter");
    const before = await counts(source.job.jobId);
    const replay = await replayTerminalJob(db, {
      sourceJobId: source.job.jobId,
      expectedSourceVersion: dead.job!.version,
      newJobId: id("dlq-replay"),
      operationId: id("dlq-replay-op"),
      replayKey: id("dlq-key"),
      idempotencyKey: id("dlq-idem"),
      actor: "operator-7",
      reasonCode: "operator_replay",
      evidenceKind: "operator_confirmed_no_effect",
      evidenceRef: "ticket:opaque-7",
      nowMs: 102,
    });
    expect(replay.job).toMatchObject({ status: "queued", attemptCount: 0, replayOfJobId: source.job.jobId });
    expect(await counts(source.job.jobId)).toEqual(before);
    expect(await getJob(db, source.job.jobId)).toMatchObject({ status: "dead_letter" });
  });

  it("keeps Queue envelopes opaque and rejects sensitive or unknown keys", async () => {
    const { job, envelope } = await create();
    expect(Object.keys(envelope).sort()).toEqual(["jobId", "jobVersion", "route", "v"]);
    for (const key of ["credentials", "providerToken", "email", "body", "resetToken", "paymentData", "payload"]) {
      expect(parseQueueEnvelope({ ...envelope, [key]: "secret" })).toBeNull();
    }
    const hostile = new Proxy({}, { ownKeys: () => { throw new Error("hostile"); } });
    expect(parseQueueEnvelope(hostile)).toBeNull();
    const row = await db.prepare(
      "SELECT envelope_json FROM background_job_outbox WHERE job_id=?",
    ).bind(job.jobId).first<{ envelope_json: string }>();
    expect(row?.envelope_json).toBe(JSON.stringify(envelope));
    expect(row?.envelope_json).not.toContain("person@example.test");
    expect(row?.envelope_json).not.toContain("db-only");
  });

  it("requires the canonical version-one outbox witness for create idempotency", async () => {
    const publishedInput = createInput();
    const publishedCreate = await createAndEnqueueJob(db, publishedInput);
    const publishedOutbox = (await listDrainableOutbox(db, publishedInput.nowMs))
      .find((row) => row.jobId === publishedInput.jobId)!;
    const claimed = await claimOutbox(db, {
      outboxId: publishedOutbox.outboxId,
      expectedVersion: publishedOutbox.version,
      owner: id("idempotent-publisher"),
      nowMs: publishedInput.nowMs,
      leaseMs: 10,
    });
    await expect(markOutboxPublished(db, {
      outboxId: claimed!.outboxId,
      expectedVersion: claimed!.version,
      owner: claimed!.publishOwner as string,
      nowMs: publishedInput.nowMs,
    })).resolves.toBe(true);
    expect(publishedCreate.kind).toBe("applied");
    await expect(createAndEnqueueJob(db, publishedInput)).resolves.toMatchObject({
      kind: "noop", reason: "idempotent_create", outboxCreated: false,
    });

    const missing = createInput();
    await db.batch([
      db.prepare(`INSERT INTO background_jobs(
        job_id,route,job_type,idempotency_key,payload_codec,payload_body,payload_digest,
        status,version,attempt_count,max_attempts,base_delay_ms,max_delay_ms,
        available_at_ms,created_at_ms,updated_at_ms
      ) VALUES(?,?,?,?,?,?,?,'queued',1,0,?,?,?,?,?,?)`).bind(
        missing.jobId, missing.route, missing.jobType, missing.idempotencyKey,
        missing.payloadCodec, missing.payloadBody, missing.payloadDigest,
        missing.maxAttempts, missing.baseDelayMs, missing.maxDelayMs,
        missing.nowMs, missing.nowMs, missing.nowMs,
      ),
      db.prepare(`INSERT INTO background_job_transitions(
        transition_id,job_id,event_type,from_status,to_status,from_version,to_version,
        actor,reason_code,evidence_ref,created_at_ms
      ) VALUES(?,?,'created',NULL,'queued',0,1,?,NULL,NULL,?)`).bind(
        missing.operationId, missing.jobId, missing.actor, missing.nowMs,
      ),
    ]);
    await expect(createAndEnqueueJob(db, missing)).resolves.toMatchObject({
      kind: "conflict", reason: "initial_outbox_corrupt", outboxCreated: false,
    });
    expect(await counts(missing.jobId)).toEqual({ transitions: 1, outbox: 0 });
  });

  it("rejects hostile mutation and deletion of durable identities, history, and outbox envelopes", async () => {
    const { job } = await create();
    const outbox = (await listDrainableOutbox(db, 100)).find((row) => row.jobId === job.jobId);
    expect(outbox).toBeDefined();
    await expect(db.prepare(`UPDATE background_jobs SET status='claimed',version=version+1,attempt_count=attempt_count+1
      WHERE job_id=?`).bind(job.jobId).run()).rejects.toThrow("CHECK constraint failed");
    await expect(db.prepare(`INSERT INTO background_job_transitions(
      transition_id,job_id,event_type,from_status,to_status,from_version,to_version,actor,created_at_ms
    ) VALUES(?,?, 'started','queued','running',1,2,'hostile',100)`).bind(
      id("bad-transition"), job.jobId,
    ).run()).rejects.toThrow("invalid background job transition ledger entry");
    await expect(db.prepare(`INSERT INTO background_job_outbox(
      outbox_id,job_id,job_version,envelope_json,state,version,available_at_ms,created_at_ms
    ) VALUES(?,?,2,'{}','pending',1,100,100)`).bind(id("bad-envelope"), job.jobId).run())
      .rejects.toThrow("invalid background job outbox envelope");
    await expect(db.prepare("UPDATE background_jobs SET payload_digest='sha256:tampered',version=version+1 WHERE job_id=?")
      .bind(job.jobId).run()).rejects.toThrow("invalid background job transition");
    await expect(db.prepare("DELETE FROM background_jobs WHERE job_id=?").bind(job.jobId).run())
      .rejects.toThrow("background job is immutable");
    await expect(db.prepare("DELETE FROM background_job_transitions WHERE job_id=?").bind(job.jobId).run())
      .rejects.toThrow("background job transition is immutable");
    await expect(db.prepare("UPDATE background_job_outbox SET envelope_json='{}',version=version+1 WHERE outbox_id=?")
      .bind(outbox!.outboxId).run()).rejects.toThrow("invalid background job outbox transition");
    await expect(db.prepare("DELETE FROM background_job_outbox WHERE outbox_id=?").bind(outbox!.outboxId).run())
      .rejects.toThrow("background job outbox is immutable");
  });

  it("rejects version exhaustion before a job or outbox counter can overflow", async () => {
    const maximum = 2_147_483_647;
    const jobId = id("max-job");
    const outboxId = id("max-outbox");
    await db.prepare(`INSERT INTO background_jobs(
      job_id,route,job_type,idempotency_key,payload_codec,payload_body,payload_digest,status,
      version,attempt_count,max_attempts,base_delay_ms,max_delay_ms,available_at_ms,created_at_ms,updated_at_ms
    ) VALUES(?,?,? ,?,'json','{}',?,'queued',?,0,1,0,0,100,100,100)`).bind(
      jobId, "maintenance.v1", "generic-test", id("max-idem"), "sha256:max", maximum,
    ).run();
    await db.prepare(`INSERT INTO background_job_outbox(
      outbox_id,job_id,job_version,envelope_json,state,version,available_at_ms,created_at_ms
    ) VALUES(?,?,?,?, 'pending',?,100,100)`).bind(
      outboxId, jobId, maximum, JSON.stringify(makeQueueEnvelope(jobId, "maintenance.v1", maximum)), maximum,
    ).run();
    await expect(claimJob(db, makeQueueEnvelope(jobId, "maintenance.v1", maximum), {
      operationId: id("max-claim"), owner: "max-worker", leaseToken: "max-lease", deliveryId: "max-delivery",
      nowMs: 100, leaseMs: 10,
    })).rejects.toThrow("VERSION_EXHAUSTED");
    await expect(claimOutbox(db, {
      outboxId, expectedVersion: maximum, owner: "max-publisher", nowMs: 100, leaseMs: 10,
    })).rejects.toThrow("OUTBOX_VERSION_EXHAUSTED");
    expect(await getJob(db, jobId)).toMatchObject({ version: maximum, status: "queued", attemptCount: 0 });
  });

  it("fences stale outbox owners and expired leases without a terminal regression", async () => {
    const { job } = await create();
    const listed = (await listDrainableOutbox(db, 100)).find((row) => row.jobId === job.jobId);
    const first = await claimOutbox(db, {
      outboxId: listed!.outboxId, expectedVersion: listed!.version, owner: "publisher-a", nowMs: 100, leaseMs: 10,
    });
    expect(first?.state).toBe("publishing");
    await expect(markOutboxPublished(db, {
      outboxId: first!.outboxId, expectedVersion: first!.version, owner: "publisher-b", nowMs: 101,
    })).resolves.toBe(false);
    await expect(markOutboxPublished(db, {
      outboxId: first!.outboxId, expectedVersion: first!.version, owner: "publisher-a", nowMs: 110,
    })).resolves.toBe(false);
    const recovered = await claimOutbox(db, {
      outboxId: first!.outboxId, expectedVersion: first!.version, owner: "publisher-b", nowMs: 110, leaseMs: 10,
    });
    expect(recovered).toMatchObject({ state: "publishing", version: first!.version + 1 });
    await expect(releaseOutbox(db, {
      outboxId: first!.outboxId, expectedVersion: first!.version, owner: "publisher-a", nowMs: 110,
      availableAtMs: 111, errorCode: "stale_owner",
    })).resolves.toBe(false);
    await expect(markOutboxPublished(db, {
      outboxId: recovered!.outboxId, expectedVersion: recovered!.version, owner: "publisher-b", nowMs: 110,
    })).resolves.toBe(true);
    await expect(db.prepare("UPDATE background_job_outbox SET state='pending',version=version+1 WHERE outbox_id=?")
      .bind(recovered!.outboxId).run()).rejects.toThrow("invalid background job outbox transition");
  });

  it("treats every replay request semantic mismatch as a conflict", async () => {
    const source = await create({ maxAttempts: 1 });
    const claimed = await claim(source.envelope, 100);
    const terminal = await recordRetryableFailure(db, {
      jobId: source.job.jobId, expectedVersion: claimed.job!.version, operationId: id("replay-dead"),
      owner: claimed.job!.leaseOwner as string, leaseToken: claimed.job!.leaseToken as string,
      nowMs: 101, errorCode: "exhausted", effectState: "not_started",
    });
    const request = {
      sourceJobId: source.job.jobId, expectedSourceVersion: terminal.job!.version,
      newJobId: id("exact-replay"), operationId: id("exact-replay-op"), replayKey: id("exact-replay-key"),
      idempotencyKey: id("exact-replay-idem"), actor: "operator-exact", reasonCode: "evidence_checked",
      evidenceKind: "provider_query_no_effect" as const, evidenceRef: "provider:exact", nowMs: 102,
    };
    expect((await replayTerminalJob(db, request)).kind).toBe("applied");
    const replayOutbox = (await listDrainableOutbox(db, request.nowMs))
      .find((row) => row.jobId === request.newJobId)!;
    const replayClaim = await claimOutbox(db, {
      outboxId: replayOutbox.outboxId,
      expectedVersion: replayOutbox.version,
      owner: id("replay-publisher"),
      nowMs: request.nowMs,
      leaseMs: 10,
    });
    await expect(markOutboxPublished(db, {
      outboxId: replayClaim!.outboxId,
      expectedVersion: replayClaim!.version,
      owner: replayClaim!.publishOwner as string,
      nowMs: request.nowMs,
    })).resolves.toBe(true);
    await expect(replayTerminalJob(db, request)).resolves.toMatchObject({ kind: "noop", reason: "idempotent_replay" });
    for (const mismatch of [
      { actor: "different-actor" },
      { nowMs: 103 },
      { expectedSourceVersion: terminal.job!.version - 1 },
      { operationId: id("different-operation") },
      { evidenceRef: "provider:different" },
    ]) {
      await expect(replayTerminalJob(db, { ...request, ...mismatch })).resolves.toMatchObject({
        kind: "conflict", reason: "replay_conflict",
      });
    }
    expect(await getJob(db, source.job.jobId)).toMatchObject({ status: "dead_letter", version: terminal.job!.version });
  });

  it("requires the canonical version-one outbox witness for replay idempotency", async () => {
    const source = await create({ maxAttempts: 1 });
    const claimed = await claim(source.envelope, 100);
    const terminal = await recordRetryableFailure(db, {
      jobId: source.job.jobId,
      expectedVersion: claimed.job!.version,
      operationId: id("missing-replay-dead"),
      owner: claimed.job!.leaseOwner as string,
      leaseToken: claimed.job!.leaseToken as string,
      nowMs: 101,
      errorCode: "exhausted",
      effectState: "not_started",
    });
    const request = {
      sourceJobId: source.job.jobId,
      expectedSourceVersion: terminal.job!.version,
      newJobId: id("missing-replay"),
      operationId: id("missing-replay-operation"),
      replayKey: id("missing-replay-key"),
      idempotencyKey: id("missing-replay-idem"),
      actor: "operator-missing",
      reasonCode: "evidence_checked",
      evidenceKind: "provider_query_no_effect" as const,
      evidenceRef: "provider:missing",
      nowMs: 102,
    };
    const evidence = `${request.evidenceKind}:${request.evidenceRef}`;
    await db.batch([
      db.prepare(`INSERT INTO background_jobs(
        job_id,route,job_type,idempotency_key,payload_codec,payload_body,payload_digest,
        status,version,attempt_count,max_attempts,base_delay_ms,max_delay_ms,
        available_at_ms,replay_of_job_id,replay_key,replay_actor,replay_reason_code,
        replay_evidence_ref,replay_source_version,replay_source_status,replay_evidence_kind,
        created_at_ms,updated_at_ms
      ) SELECT ?,route,job_type,?,payload_codec,payload_body,payload_digest,
        'queued',1,0,max_attempts,base_delay_ms,max_delay_ms,?,?,?,?,?,?,?,?,?,?,?
        FROM background_jobs WHERE job_id=?`).bind(
        request.newJobId, request.idempotencyKey, request.nowMs, request.sourceJobId,
        request.replayKey, request.actor, request.reasonCode, evidence,
        request.expectedSourceVersion, terminal.job!.status, request.evidenceKind,
        request.nowMs, request.nowMs, request.sourceJobId,
      ),
      db.prepare(`INSERT INTO background_job_transitions(
        transition_id,job_id,event_type,from_status,to_status,from_version,to_version,
        actor,reason_code,evidence_ref,created_at_ms
      ) VALUES(?,?,'replayed',NULL,'queued',0,1,?,?,?,?)`).bind(
        request.operationId, request.newJobId, request.actor, request.reasonCode,
        evidence, request.nowMs,
      ),
    ]);
    await expect(replayTerminalJob(db, request)).resolves.toMatchObject({
      kind: "conflict", reason: "initial_outbox_corrupt", outboxCreated: false,
    });
    expect(await counts(request.newJobId)).toEqual({ transitions: 1, outbox: 0 });
  });

  it("rolls back a state change when a preseeded transition or outbox conflict fires", async () => {
    const transitionTarget = await create();
    const active = await running(transitionTarget.envelope, 100);
    const blocker = createInput({ operationId: id("taken-transition") });
    await createAndEnqueueJob(db, blocker);
    const beforeTransition = await counts(transitionTarget.job.jobId);
    await expect(recordRetryableFailure(db, {
      jobId: active.jobId, expectedVersion: active.version, operationId: blocker.operationId,
      owner: active.leaseOwner as string, leaseToken: active.leaseToken as string,
      nowMs: 102, errorCode: "retryable", effectState: "started_known_failure",
    })).rejects.toThrow();
    expect(await getJob(db, active.jobId)).toMatchObject({ status: "running", version: active.version });
    expect(await counts(active.jobId)).toEqual(beforeTransition);

    const outboxTarget = await create();
    const runningTarget = await running(outboxTarget.envelope, 100);
    await db.prepare(`INSERT INTO background_job_outbox(
      outbox_id,job_id,job_version,envelope_json,state,version,available_at_ms,created_at_ms
    ) VALUES(?,?,?,?, 'pending',1,102,102)`).bind(
      id("preseeded-outbox"), runningTarget.jobId, runningTarget.version + 1,
      JSON.stringify(makeQueueEnvelope(runningTarget.jobId, runningTarget.route, runningTarget.version + 1)),
    ).run();
    const beforeOutbox = await counts(runningTarget.jobId);
    await expect(recordRetryableFailure(db, {
      jobId: runningTarget.jobId, expectedVersion: runningTarget.version, operationId: id("outbox-conflict"),
      owner: runningTarget.leaseOwner as string, leaseToken: runningTarget.leaseToken as string,
      nowMs: 102, errorCode: "retryable", effectState: "started_known_failure",
    })).rejects.toThrow();
    expect(await getJob(db, runningTarget.jobId)).toMatchObject({ status: "running", version: runningTarget.version });
    expect(await counts(runningTarget.jobId)).toEqual(beforeOutbox);
  });
});
