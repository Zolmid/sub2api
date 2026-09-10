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
import {
  BACKGROUND_JOB_ROUTES,
  MAX_JOB_EXECUTION_PAYLOAD_BYTES,
  MAX_JOB_EXECUTION_RESPONSE_BYTES,
  createGatewayJobExecutors,
  createWorkerJobExecutors,
} from "../src/job-executors";

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
  it("exposes a non-empty exact production executor registry", () => {
    const executors = createGatewayJobExecutors(env, async () =>
      Response.json({ v: 1, kind: "succeeded", resultDigest: "sha256:unused" })
    );
    expect(Object.keys(executors).sort()).toEqual([
      BACKGROUND_JOB_ROUTES.EMAIL_DELIVERY_V1,
      BACKGROUND_JOB_ROUTES.OAUTH_REFRESH_V1,
      BACKGROUND_JOB_ROUTES.PAYMENT_RECONCILIATION_V1,
    ].sort());
    expect(Object.keys(createWorkerJobExecutors(env)).sort()).toEqual([
      BACKGROUND_JOB_ROUTES.EMAIL_DELIVERY_V1,
      BACKGROUND_JOB_ROUTES.OAUTH_REFRESH_V1,
      BACKGROUND_JOB_ROUTES.PAYMENT_RECONCILIATION_V1,
      BACKGROUND_JOB_ROUTES.SUBSCRIPTION_EXPIRY_MAINTENANCE_V1,
    ].sort());
    expect(executors["maintenance.v1"]).toBeUndefined();
    expect(executors["oauth-refresh.v1.extra"]).toBeUndefined();
  });

  it("dispatches registered jobs with a strict bounded Container RPC envelope", async () => {
    const created = await create({
      route: BACKGROUND_JOB_ROUTES.OAUTH_REFRESH_V1,
      jobType: "oauth-refresh",
      idempotencyKey: "oauth-refresh-idempotency",
      payloadBody: JSON.stringify({ account_id: "42", secret: "private-in-d1-only" }),
      payloadDigest: "sha256:oauth-refresh-payload",
    });
    const delivery = message("delivery-registered-dispatch", created.envelope);
    const seen: unknown[] = [];
    const executors = createGatewayJobExecutors(env, async (request) => {
      expect(request.method).toBe("POST");
      expect(new URL(request.url).pathname).toBe("/internal/cloudflare/jobs/execute");
      expect(request.headers.get("content-type")).toBe("application/json");
      seen.push(await request.json());
      return Response.json({
        v: 1,
        kind: "succeeded",
        resultDigest: "sha256:container-result",
      });
    });

    await deliver([delivery], executors);

    expect(delivery.calls).toEqual(["ack"]);
    expect(seen).toEqual([{
      v: 1,
      method: "sub2api.cloudflare.jobs.execute",
      params: {
        job: {
          id: created.input.jobId,
          version: 4,
          route: BACKGROUND_JOB_ROUTES.OAUTH_REFRESH_V1,
          type: "oauth-refresh",
          idempotencyKey: "oauth-refresh-idempotency",
        },
        payload: {
          codec: "json",
          body: JSON.stringify({ account_id: "42", secret: "private-in-d1-only" }),
          digest: "sha256:oauth-refresh-payload",
        },
      },
    }]);
    expect(await getJob(db, created.input.jobId)).toMatchObject({
      status: "succeeded",
      resultDigest: "sha256:container-result",
    });
  });

  it("maps every explicit Container outcome and only retries validated retryable failures", async () => {
    const outcomes = [
      {
        route: BACKGROUND_JOB_ROUTES.OAUTH_REFRESH_V1,
        body: { v: 1, kind: "succeeded", resultDigest: "sha256:oauth-result" },
        expected: { status: "succeeded", resultDigest: "sha256:oauth-result" },
      },
      {
        route: BACKGROUND_JOB_ROUTES.EMAIL_DELIVERY_V1,
        body: { v: 1, kind: "retryable_failure", errorCode: "provider_busy" },
        expected: { status: "retry_wait", errorCode: "provider_busy" },
      },
      {
        route: BACKGROUND_JOB_ROUTES.PAYMENT_RECONCILIATION_V1,
        body: { v: 1, kind: "permanent_failure", errorCode: "invalid_reconciliation" },
        expected: { status: "failed", errorCode: "invalid_reconciliation" },
      },
    ] as const;

    for (const outcome of outcomes) {
      const created = await create({ route: outcome.route });
      const delivery = message(`delivery-${outcome.route}`, created.envelope);
      await deliver([delivery], createGatewayJobExecutors(env, async () =>
        Response.json(outcome.body)
      ));
      expect(delivery.calls).toEqual(["ack"]);
      expect(await getJob(db, created.input.jobId)).toMatchObject(outcome.expected);
    }
  });

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

  it.each([
    {
      name: "invalid shape",
      dispatch: async () => Response.json({
        v: 1,
        kind: "succeeded",
        resultDigest: "sha256:bad-extra",
        extra: true,
      }),
      reasonCode: "container_response_invalid",
    },
    {
      name: "oversized body",
      dispatch: async () => new Response("x".repeat(MAX_JOB_EXECUTION_RESPONSE_BYTES + 1)),
      reasonCode: "container_response_too_large",
    },
    {
      name: "non-json body",
      dispatch: async () => new Response("not json"),
      reasonCode: "container_response_non_json",
    },
    {
      name: "network failure",
      dispatch: async () => {
        throw new Error("transport lost with private-in-d1-only");
      },
      reasonCode: "container_dispatch_failed",
    },
    {
      name: "ambiguous 5xx",
      dispatch: async () =>
        Response.json(
          { v: 1, kind: "retryable_failure", errorCode: "provider_busy" },
          { status: 503 },
        ),
      reasonCode: "container_http_status",
    },
  ])("fails closed to manual review on $name Container responses", async ({ dispatch, reasonCode }) => {
    const created = await create({
      route: BACKGROUND_JOB_ROUTES.EMAIL_DELIVERY_V1,
      payloadBody: JSON.stringify({ token: "private-in-d1-only" }),
    });
    const delivery = message(`delivery-fail-closed-${reasonCode}-${crypto.randomUUID()}`, created.envelope);

    await deliver([delivery], createGatewayJobExecutors(env, dispatch));

    expect(delivery.calls).toEqual(["ack"]);
    expect(await getJob(db, created.input.jobId)).toMatchObject({
      status: "manual_review",
      errorCode: reasonCode,
    });
    const transition = await db.prepare(`SELECT reason_code,evidence_ref
      FROM background_job_transitions WHERE job_id=? AND event_type='manual_review'
      ORDER BY created_at_ms DESC LIMIT 1`).bind(created.input.jobId)
      .first<{ reason_code: string; evidence_ref: string }>();
    expect(transition?.reason_code).toBe(reasonCode);
    expect(JSON.stringify(transition)).not.toContain("private-in-d1-only");
  });

  it("rejects oversized payloads before Container dispatch without leaking the body", async () => {
    const payloadBody = JSON.stringify({
      token: "private-in-d1-only",
      blob: "x".repeat(MAX_JOB_EXECUTION_PAYLOAD_BYTES),
    });
    const created = await create({
      route: BACKGROUND_JOB_ROUTES.PAYMENT_RECONCILIATION_V1,
      payloadBody,
    });
    const delivery = message("delivery-oversized-payload", created.envelope);
    let dispatches = 0;

    await deliver([delivery], createGatewayJobExecutors(env, async () => {
      dispatches += 1;
      return Response.json({ v: 1, kind: "succeeded", resultDigest: "sha256:unexpected" });
    }));

    expect(dispatches).toBe(0);
    expect(delivery.calls).toEqual(["ack"]);
    expect(await getJob(db, created.input.jobId)).toMatchObject({
      status: "manual_review",
      errorCode: "payload_too_large",
    });
    const transition = await db.prepare(`SELECT reason_code,evidence_ref
      FROM background_job_transitions WHERE job_id=? AND event_type='manual_review'
      ORDER BY created_at_ms DESC LIMIT 1`).bind(created.input.jobId)
      .first<{ reason_code: string; evidence_ref: string }>();
    expect(JSON.stringify(transition)).not.toContain("private-in-d1-only");
    expect(JSON.stringify(transition)).not.toContain("xxxxx");
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
