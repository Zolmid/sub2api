import { env } from "cloudflare:test";
import {
  createExecutionContext,
  createMessageBatch,
  getQueueResult,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { drainOutbox } from "../src/control-plane";
import {
  BRIDGE_VERSION,
  USAGE_EVENT_TYPE,
  canonical,
  sha256,
  type Completion,
  type UsageEnvelope,
} from "../src/contracts";
import worker from "../src/index";

const completion = (requestID: string, outputTokens = "4"): Completion => ({
  schema_version: BRIDGE_VERSION,
  event_type: USAGE_EVENT_TYPE,
  event_id: `${requestID}:usage:v1`,
  request_id: requestID,
  api_key_id: "3001",
  account_id: "4001",
  lease_id: `lease-${requestID}`,
  lease_epoch: "1",
  outcome: "succeeded",
  usage_state: "confirmed",
  input_tokens: "11",
  output_tokens: outputTokens,
  cache_read_tokens: "0",
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
  withOutbox = state === "succeeded",
): Promise<void> => {
  await env.DB.prepare(
    `INSERT INTO gateway_requests(
       request_id,api_key_id,account_id,lease_id,lease_epoch,owner,
       model,upstream_model,state,event_id,completed_at,created_at
     ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
  )
    .bind(
      value.request_id,
      value.api_key_id,
      value.account_id,
      value.lease_id,
      value.lease_epoch,
      "container-queue-test",
      value.model,
      value.upstream_model,
      state,
      state === "succeeded" ? value.event_id : null,
      state === "succeeded" ? "2026-09-06T00:00:01Z" : null,
      "2026-09-06T00:00:00Z",
    )
    .run();
  if (withOutbox) {
    const envelope = await envelopeFor(value);
    await env.DB.prepare(
      `INSERT INTO outbox_events(
         event_id,request_id,payload_json,payload_hash,state,attempts,
         published_at,created_at
       ) VALUES(?,?,?,?,?,0,?,?)`,
    )
      .bind(
        value.event_id,
        value.request_id,
        envelope.payload,
        envelope.payload_hash,
        "published",
        "2026-09-06T00:00:02Z",
        "2026-09-06T00:00:01Z",
      )
      .run();
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
      schema_version: BRIDGE_VERSION,
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
    await insertRequest(value, "succeeded", false);
    const envelope = await envelopeFor(value);
    await env.DB.prepare(
      `INSERT INTO outbox_events(
         event_id,request_id,payload_json,payload_hash,state,attempts,created_at
       ) VALUES(?,?,?,?,?,0,?)`,
    )
      .bind(
        value.event_id,
        value.request_id,
        envelope.payload,
        envelope.payload_hash,
        "pending",
        "2026-09-06T00:00:02Z",
      )
      .run();

    await drainOutbox(env);
    expect(
      await env.DB.prepare("SELECT state FROM outbox_events WHERE event_id=?")
        .bind(value.event_id)
        .first("state"),
    ).toBe("published");
  });
});
