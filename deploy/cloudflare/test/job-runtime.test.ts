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
  moveToManualReview,
  parseQueueEnvelope,
  processQueueBatch,
  recoverExpiredJob,
  recordPermanentFailure,
  recordRetryableFailure,
  replayTerminalJob,
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
    });
    expect(drained.find((row) => row.outboxId === listed!.outboxId)?.outcome).toBe("published");
    const targetPublishes = sent.filter((envelope) => envelope.jobId === job.jobId);
    expect(targetPublishes).toHaveLength(2);
    expect(targetPublishes[0]).toEqual(targetPublishes[1]);
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
});
