import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  claimJob,
  createAndEnqueueJob,
  getJob,
  startJob,
  type CreateJobInput,
  type QueueEnvelope,
} from "../src/job-runtime";
import {
  consumeJobQueueBatch,
  recoverExpiredBackgroundJobs,
  type JobExecutor,
  type JobExecutorMap,
} from "../src/job-worker";

const db = env.DB;
const NOW = 1_000;

function createInput(overrides: Partial<CreateJobInput> = {}): CreateJobInput {
  const id = crypto.randomUUID();
  return {
    jobId: `worker-job-${id}`,
    operationId: `worker-create-${id}`,
    route: "maintenance.v1",
    jobType: "worker-test",
    idempotencyKey: `worker-idempotency-${id}`,
    payloadCodec: "json",
    payloadBody: JSON.stringify({ reference: "private-in-d1-only" }),
    payloadDigest: `sha256:${id}`,
    maxAttempts: 2,
    baseDelayMs: 10,
    maxDelayMs: 10,
    nowMs: NOW,
    actor: "job-worker-test",
    ...overrides,
  };
}

async function create(overrides: Partial<CreateJobInput> = {}) {
  const input = createInput(overrides);
  const result = await createAndEnqueueJob(db, input);
  if (!result.job) throw new Error("job was not created");
  return {
    input,
    envelope: { v: 1, jobId: input.jobId, route: input.route, jobVersion: 1 } as const,
  };
}

function message(id: string, body: unknown) {
  const calls: string[] = [];
  return {
    value: {
      id,
      body,
      ack: () => calls.push("ack"),
      retry: () => calls.push("retry"),
    },
    calls,
  };
}

async function deliver(
  messages: readonly ReturnType<typeof message>[],
  executors: JobExecutorMap = {},
): Promise<void> {
  await consumeJobQueueBatch(
    { messages: messages.map((entry) => entry.value) },
    { db, executors, clock: () => NOW },
  );
}

const success: JobExecutor = async ({ payloadBody }) => {
  expect(payloadBody).toContain("private-in-d1-only");
  return { kind: "succeeded", resultDigest: "sha256:job-result" };
};

describe("background job Queue worker", () => {
  it("runs a claimed job once and acknowledges delayed duplicate delivery", async () => {
    const created = await create();
    const first = message("delivery-first", created.envelope);
    const duplicate = message("delivery-duplicate", created.envelope);
    let executions = 0;
    await deliver([first, duplicate], {
      "maintenance.v1": async (input) => {
        executions += 1;
        return success(input);
      },
    });

    expect(executions).toBe(1);
    expect(first.calls).toEqual(["ack"]);
    expect(duplicate.calls).toEqual(["ack"]);
    expect(await getJob(db, created.input.jobId)).toMatchObject({
      status: "succeeded",
      attemptCount: 1,
      resultDigest: "sha256:job-result",
    });
  });

  it("persists retryable, permanent, and manual-review executor outcomes before ack", async () => {
    const retry = await create();
    const permanent = await create();
    const review = await create();
    const retryMessage = message("delivery-retry", retry.envelope);
    const permanentMessage = message("delivery-permanent", permanent.envelope);
    const reviewMessage = message("delivery-review", review.envelope);
    await deliver([retryMessage], {
      "maintenance.v1": async () => ({ kind: "retryable_failure", errorCode: "provider_busy" }),
    });
    await deliver([permanentMessage], {
      "maintenance.v1": async () => ({ kind: "permanent_failure", errorCode: "invalid_request" }),
    });
    await deliver([reviewMessage], {
      "maintenance.v1": async () => ({
        kind: "manual_review",
        reasonCode: "provider_result_unknown",
        evidenceRef: "provider:opaque-request",
      }),
    });

    expect(retryMessage.calls).toEqual(["ack"]);
    expect(permanentMessage.calls).toEqual(["ack"]);
    expect(reviewMessage.calls).toEqual(["ack"]);
    expect(await getJob(db, retry.input.jobId)).toMatchObject({ status: "retry_wait" });
    expect(await getJob(db, permanent.input.jobId)).toMatchObject({ status: "failed" });
    expect(await getJob(db, review.input.jobId)).toMatchObject({
      status: "manual_review",
      errorCode: "provider_result_unknown",
    });
  });

  it("quarantines an unknown route instead of acknowledging and dropping it", async () => {
    const created = await create({ route: "unregistered.v1" });
    const delivery = message("delivery-unknown-route", created.envelope);
    await deliver([delivery]);

    expect(delivery.calls).toEqual(["ack"]);
    expect(await getJob(db, created.input.jobId)).toMatchObject({
      status: "manual_review",
      errorCode: "unknown_route",
    });
    expect(
      await db.prepare(`SELECT reason_code,evidence_ref FROM background_job_transitions
        WHERE job_id=? AND event_type='manual_review'`).bind(created.input.jobId)
        .first<{ reason_code: string; evidence_ref: string }>(),
    ).toEqual({ reason_code: "unknown_route", evidence_ref: "route:unregistered.v1" });
  });

  it("retries ambiguous executor infrastructure errors without executing a duplicate", async () => {
    const created = await create();
    const first = message("delivery-infra-first", created.envelope);
    const duplicate = message("delivery-infra-duplicate", created.envelope);
    let executions = 0;
    const unstable: JobExecutor = async () => {
      executions += 1;
      throw new Error("transport lost after dispatch");
    };
    await deliver([first], { "maintenance.v1": unstable });
    await deliver([duplicate], { "maintenance.v1": unstable });

    expect(executions).toBe(1);
    expect(first.calls).toEqual(["retry"]);
    expect(duplicate.calls).toEqual(["ack"]);
    expect(await getJob(db, created.input.jobId)).toMatchObject({ status: "running" });
  });

  it("recovers expired claims but manually reviews crashes after start", async () => {
    const neverStarted = await create();
    const claim = await claimJob(db, neverStarted.envelope, {
      operationId: `claim-${crypto.randomUUID()}`,
      owner: "crash-test",
      leaseToken: "crash-lease",
      deliveryId: "crash-claim",
      nowMs: NOW,
      leaseMs: 1,
    });
    const started = await create();
    const runningClaim = await claimJob(db, started.envelope, {
      operationId: `claim-${crypto.randomUUID()}`,
      owner: "start-crash-test",
      leaseToken: "start-crash-lease",
      deliveryId: "crash-start",
      nowMs: NOW,
      leaseMs: 1,
    });
    if (!claim.job || !runningClaim.job) throw new Error("claims failed");
    await startJob(db, {
      jobId: runningClaim.job.jobId,
      expectedVersion: runningClaim.job.version,
      operationId: `start-${crypto.randomUUID()}`,
      owner: "start-crash-test",
      leaseToken: "start-crash-lease",
      nowMs: NOW,
    });

    await recoverExpiredBackgroundJobs(db, () => NOW + 2);

    expect(await getJob(db, neverStarted.input.jobId)).toMatchObject({ status: "retry_wait" });
    expect(await getJob(db, started.input.jobId)).toMatchObject({
      status: "manual_review",
      errorCode: "unknown_result_after_lease_expiry",
    });
  });

  it("acks malformed opaque envelopes without touching a job", async () => {
    const malformed = message("delivery-malformed", {
      v: 1,
      jobId: "not-a-job",
      route: "maintenance.v1",
      jobVersion: 1,
      payload: "must-not-be-queued",
    } satisfies Record<string, unknown>);
    await deliver([malformed]);
    expect(malformed.calls).toEqual(["ack"]);
  });
});
