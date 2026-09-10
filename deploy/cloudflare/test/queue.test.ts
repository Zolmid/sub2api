import { env } from "cloudflare:test";
import {
  createExecutionContext,
  createMessageBatch,
  createScheduledController,
  getQueueResult,
  waitOnExecutionContext,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { drainOutbox } from "../src/control-plane";
import type { BillingIdentity } from "../src/billing";
import {
  USAGE_EVENT_TYPE,
  USAGE_SCHEMA_VERSION,
  canonical,
  sha256,
  type Completion,
  type UsageEnvelope,
} from "../src/contracts";
import worker from "../src/index";
import {
  createAndEnqueueJob,
  getJob,
  type QueueEnvelope,
} from "../src/job-runtime";

const completion = (requestID: string, outputTokens = "4"): Completion => ({
  schema_version: USAGE_SCHEMA_VERSION,
  event_type: USAGE_EVENT_TYPE,
  event_id: `${requestID}:usage:v2`,
  request_id: requestID,
  api_key_id: "3001",
  account_id: "4001",
  lease_id: `lease-${requestID}`,
  lease_epoch: "1",
  outcome: "succeeded",
  usage_state: "confirmed",
  input_tokens: "11",
  image_input_tokens: "0",
  output_tokens: outputTokens,
  image_output_tokens: "0",
  cache_creation_tokens: "0",
  cache_creation_5m_tokens: "0",
  cache_creation_1h_tokens: "0",
  cache_read_tokens: "0",
  service_tier: "",
  reasoning_effort: "",
  model: "fixture-model",
  upstream_model: "mock-upstream-model",
  upstream_request_id: "fixture-completion",
  duration_ms: "0",
});

const envelopeFor = async (value: Completion): Promise<UsageEnvelope> => {
  const payload = canonical(value);
  return {
    event_id: value.event_id,
    payload,
    payload_hash: await sha256(payload),
  };
};

const insertRequest = async (
  value: Completion,
  state: "admitted" | "succeeded" = "succeeded",
): Promise<void> => {
  const pricing = await env.DB.prepare(
    `SELECT a.version_id,v.digest,r.model_pattern
     FROM pricing_active_version a
     JOIN pricing_versions v ON v.version_id=a.version_id
     JOIN pricing_rules r ON r.version_id=a.version_id
     WHERE r.model_pattern='fixture-model'`,
  ).first<{ version_id: string; digest: string; model_pattern: string }>();
  if (!pricing) throw new Error("fixture pricing is unavailable");
  const identity: BillingIdentity = {
    request_id: value.request_id,
    user_id: "1001",
    api_key_id: value.api_key_id,
    group_id: "2001",
    account_id: value.account_id,
    lease_id: value.lease_id,
    lease_epoch: value.lease_epoch,
    owner: "container-queue-test",
    model: value.model,
    upstream_model: value.upstream_model,
    pricing_version_id: pricing.version_id,
    pricing_digest: pricing.digest,
    pricing_model: value.model,
    pricing_rule_pattern: pricing.model_pattern,
    pricing_rule_match_kind: "exact",
    rate_multiplier_bps: "10000",
    reservation_e8_usd: "100000000000",
  };
  const billing = env.BILLING_PRINCIPAL.getByName("user:1001");
  const reserved = await billing.reserve({
    ...identity,
    operation_id: `${value.request_id}:reserve`,
  });
  if (reserved.kind !== "ok" || reserved.state !== "reserved") {
    throw new Error(`failed to reserve billing for ${value.request_id}`);
  }
  const started = await billing.start({
    ...identity,
    operation_id: `${value.request_id}:start`,
  });
  if (started.kind !== "ok" || started.state !== "started") {
    throw new Error(`failed to start billing for ${value.request_id}`);
  }
  if (state === "succeeded") {
    const envelope = await envelopeFor(value);
    const charged = (
      BigInt(value.input_tokens) * 125n +
      BigInt(value.output_tokens) * 1000n
    ).toString();
    const settled = await billing.complete({
      ...identity,
      operation_id: `${value.request_id}:complete`,
      final: true,
      usage_present: true,
      charged_e8_usd: charged,
      event_id: value.event_id,
      payload_hash: envelope.payload_hash,
      payload_json: envelope.payload,
      outcome: value.outcome,
      upstream_request_id: value.upstream_request_id,
    });
    if (settled.kind !== "ok" || settled.state !== "completed") {
      throw new Error(`failed to settle billing for ${value.request_id}`);
    }
    const authoritative = await env.DB.prepare(
      `SELECT g.state AS request_state,g.event_id,o.request_id AS outbox_request_id,
              o.payload_json,o.payload_hash
       FROM gateway_requests g
       JOIN outbox_events o ON o.event_id=g.event_id
       WHERE g.request_id=?`,
    ).bind(value.request_id).first<{
      request_state: string;
      event_id: string;
      outbox_request_id: string;
      payload_json: string;
      payload_hash: string;
    }>();
    if (
      !authoritative ||
      authoritative.request_state !== value.outcome ||
      authoritative.event_id !== value.event_id ||
      authoritative.outbox_request_id !== value.request_id ||
      authoritative.payload_json !== envelope.payload ||
      authoritative.payload_hash !== envelope.payload_hash
    ) {
      throw new Error(`billing did not create authoritative usage for ${value.request_id}`);
    }
  }
};

const deliver = async (envelopes: UsageEnvelope[]) => {
  const batch = createMessageBatch<UsageEnvelope>(
    "usage-test",
    envelopes.map((body, index) => ({
      id: `message-${body.event_id}-${index}`,
      timestamp: new Date(),
      attempts: 1,
      body,
    })),
  );
  const ctx = createExecutionContext();
  await worker.queue(batch, env);
  return getQueueResult(batch, ctx);
};

describe("usage Queue consumer", () => {
  it("publishes pending background jobs through the configured scheduled path", async () => {
    const suffix = crypto.randomUUID();
    const jobId = `scheduled-job-${suffix}`;
    const created = await createAndEnqueueJob(env.DB, {
      jobId,
      operationId: `scheduled-create-${suffix}`,
      route: "scheduled.test.v1",
      jobType: "scheduled-test",
      idempotencyKey: `scheduled-idem-${suffix}`,
      payloadCodec: "json",
      payloadBody: "{}",
      payloadDigest: `sha256:${suffix}`,
      maxAttempts: 1,
      baseDelayMs: 1,
      maxDelayMs: 1,
      nowMs: 1_000,
      actor: "scheduled-path-test",
    });
    expect(created.kind).toBe("applied");
    expect(
      await env.DB.prepare(
        "SELECT state FROM background_job_outbox WHERE job_id=?",
      ).bind(jobId).first("state"),
    ).toBe("pending");

    const ctx = createExecutionContext();
    await worker.scheduled(
      createScheduledController({
        scheduledTime: new Date(),
        cron: "*/1 * * * *",
      }),
      env,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(
      await env.DB.prepare(
        "SELECT state FROM background_job_outbox WHERE job_id=?",
      ).bind(jobId).first("state"),
    ).toBe("published");
  });

  it("rejects an unknown Queue instead of treating it as usage", async () => {
    const value = completion(`request-unknown-queue-${crypto.randomUUID()}`);
    const envelope = await envelopeFor(value);
    const batch = createMessageBatch<UsageEnvelope>("unexpected-queue", [{
      id: `unexpected-${crypto.randomUUID()}`,
      timestamp: new Date(),
      attempts: 1,
      body: envelope,
    }]);

    await expect(worker.queue(batch, env)).rejects.toThrow("UNEXPECTED_QUEUE");
    expect((await getQueueResult(batch, createExecutionContext())).explicitAcks).toHaveLength(0);
  });

  it("does not consume background jobs from a near-match Queue name", async () => {
    const suffix = crypto.randomUUID();
    const created = await createAndEnqueueJob(env.DB, {
      jobId: `queue-near-match-${suffix}`,
      operationId: `queue-near-match-create-${suffix}`,
      route: "unregistered.v1",
      jobType: "queue-near-match",
      idempotencyKey: `queue-near-match-idem-${suffix}`,
      payloadCodec: "json",
      payloadBody: "{}",
      payloadDigest: `sha256:${suffix}`,
      maxAttempts: 1,
      baseDelayMs: 1,
      maxDelayMs: 1,
      nowMs: 1_000,
      actor: "queue-near-match-test",
    });
    if (!created.job) throw new Error("background job was not created");
    const batch = createMessageBatch<QueueEnvelope>(
      "sub2api-background-jobs-local",
      [{
        id: `near-match-${suffix}`,
        timestamp: new Date(),
        attempts: 1,
        body: {
          v: 1,
          jobId: created.job.jobId,
          route: "unregistered.v1",
          jobVersion: 1,
        },
      }],
    );

    await expect(worker.queue(batch, env)).rejects.toThrow("UNEXPECTED_QUEUE");
    expect((await getQueueResult(batch, createExecutionContext())).explicitAcks).toHaveLength(0);
    expect(await getJob(env.DB, created.job.jobId)).toMatchObject({
      status: "queued",
      attemptCount: 0,
    });
  });

  it("keeps usage handling isolated when the Worker also receives a background-job Queue batch", async () => {
    const suffix = crypto.randomUUID();
    const created = await createAndEnqueueJob(env.DB, {
      jobId: `queue-isolation-${suffix}`,
      operationId: `queue-isolation-create-${suffix}`,
      route: "unregistered.v1",
      jobType: "queue-isolation",
      idempotencyKey: `queue-isolation-idem-${suffix}`,
      payloadCodec: "json",
      payloadBody: "{}",
      payloadDigest: `sha256:${suffix}`,
      maxAttempts: 1,
      baseDelayMs: 1,
      maxDelayMs: 1,
      nowMs: 1_000,
      actor: "queue-isolation-test",
    });
    if (!created.job) throw new Error("background job was not created");
    const batch = createMessageBatch<UsageEnvelope | QueueEnvelope>(
      "sub2api-background-jobs",
      [{
        id: `background-${suffix}`,
        timestamp: new Date(),
        attempts: 1,
        body: { v: 1, jobId: created.job.jobId, route: "unregistered.v1", jobVersion: 1 },
      }],
    );
    await worker.queue(batch, env);

    expect((await getQueueResult(batch, createExecutionContext())).explicitAcks).toHaveLength(1);
    expect(await getJob(env.DB, created.job.jobId)).toMatchObject({
      status: "manual_review",
      errorCode: "unknown_route",
    });
  });

  it("atomically applies ten identical deliveries once", async () => {
    const value = completion("request-queue-ten");
    await insertRequest(value);
    const envelope = await envelopeFor(value);
    const result = await deliver(Array.from({ length: 10 }, () => envelope));

    expect(result.retryMessages).toHaveLength(0);
    expect(result.explicitAcks).toHaveLength(10);
    expect(
      await env.DB.prepare("SELECT count(*) count FROM usage_events WHERE event_id=?")
        .bind(value.event_id)
        .first("count"),
    ).toBe(1);
    const usage = await env.DB.prepare(
      `SELECT schema_version,event_type,input_tokens,output_tokens,
              cache_read_tokens,duration_ms,upstream_request_id
       FROM usage_events WHERE event_id=?`,
    )
      .bind(value.event_id)
      .first<Record<string, string>>();
    expect(usage).toEqual({
      schema_version: USAGE_SCHEMA_VERSION,
      event_type: USAGE_EVENT_TYPE,
      input_tokens: "11",
      output_tokens: "4",
      cache_read_tokens: "0",
      duration_ms: "0",
      upstream_request_id: "fixture-completion",
    });
  });

  it("durably audits a same-ID different-payload conflict", async () => {
    const original = completion("request-queue-conflict", "4");
    await insertRequest(original);
    expect((await deliver([await envelopeFor(original)])).retryMessages).toHaveLength(
      0,
    );

    const conflicting = completion("request-queue-conflict", "5");
    const result = await deliver([await envelopeFor(conflicting)]);
    expect(result.retryMessages).toHaveLength(0);
    expect(result.explicitAcks).toHaveLength(1);
    expect(
      await env.DB.prepare(
        "SELECT count(*) count FROM outbox_conflicts WHERE source='queue' AND event_id=?",
      )
        .bind(original.event_id)
        .first("count"),
    ).toBe(1);
    expect(
      await env.DB.prepare("SELECT output_tokens FROM usage_events WHERE event_id=?")
        .bind(original.event_id)
        .first("output_tokens"),
    ).toBe("4");
  });

  it("rejects an altered payload before the first usage projection", async () => {
    const authoritative = completion("request-queue-outbox-authority", "4");
    await insertRequest(authoritative);
    const altered = completion("request-queue-outbox-authority", "999");

    const rejected = await deliver([await envelopeFor(altered)]);
    expect(rejected.retryMessages).toHaveLength(0);
    expect(rejected.explicitAcks).toHaveLength(1);
    expect(
      await env.DB.prepare("SELECT count(*) count FROM usage_events WHERE event_id=?")
        .bind(authoritative.event_id)
        .first("count"),
    ).toBe(0);
    expect(
      await env.DB.prepare(
        "SELECT count(*) count FROM outbox_conflicts WHERE source='queue' AND event_id=?",
      )
        .bind(authoritative.event_id)
        .first("count"),
    ).toBe(1);

    const accepted = await deliver([await envelopeFor(authoritative)]);
    expect(accepted.retryMessages).toHaveLength(0);
    expect(
      await env.DB.prepare("SELECT output_tokens FROM usage_events WHERE event_id=?")
        .bind(authoritative.event_id)
        .first("output_tokens"),
    ).toBe("4");
  });

  it("retries out-of-order and invalid messages without inventing usage", async () => {
    const early = completion("request-queue-early");
    await insertRequest(early, "admitted");
    const earlyResult = await deliver([await envelopeFor(early)]);
    expect(earlyResult.retryMessages).toHaveLength(1);

    const invalid = await envelopeFor(completion("request-queue-invalid"));
    invalid.payload_hash = "0".repeat(64);
    const invalidResult = await deliver([invalid]);
    expect(invalidResult.retryMessages).toHaveLength(1);
    expect(
      await env.DB.prepare(
        "SELECT count(*) count FROM usage_events WHERE request_id IN (?,?)",
      )
        .bind(early.request_id, "request-queue-invalid")
        .first("count"),
    ).toBe(0);
  });

  it("recovers a pending outbox row without waking the Container", async () => {
    const value = completion("request-outbox-recovery");
    await insertRequest(value);
    expect(
      await env.DB.prepare("SELECT state FROM outbox_events WHERE event_id=?")
        .bind(value.event_id)
        .first("state"),
    ).toBe("pending");

    await drainOutbox(env);
    expect(
      await env.DB.prepare("SELECT state FROM outbox_events WHERE event_id=?")
        .bind(value.event_id)
        .first("state"),
    ).toBe("published");
  });
});
