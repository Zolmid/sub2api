import { env } from "cloudflare:test";
import {
  createExecutionContext,
  createScheduledController,
  waitOnExecutionContext,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { BACKGROUND_JOB_ROUTES, createWorkerJobExecutors } from "../src/job-executors";
import { createAndEnqueueJob, getJob, type CreateJobInput } from "../src/job-runtime";
import { consumeJobQueueBatch } from "../src/job-worker";
import worker from "../src/index";
import {
  SUBSCRIPTION_EXPIRY_JOB_ROUTE,
  enqueueSubscriptionExpiryMaintenance,
  subscriptionExpiryJobInput,
} from "../src/subscription-expiry-job";
import { sha256 } from "../src/contracts";

const db = env.DB;
const BUCKET = Date.parse("2026-01-03T00:00:00.000Z");

function message(id: string, body: unknown) {
  const calls: string[] = [];
  return {
    value: { id, body, ack: () => calls.push("ack"), retry: () => calls.push("retry") },
    calls,
  };
}

async function deliver(body: unknown, executors = createWorkerJobExecutors(env)) {
  const delivery = message(`subscription-expiry-delivery:${crypto.randomUUID()}`, body);
  await consumeJobQueueBatch({ messages: [delivery.value] }, { db, executors });
  expect(delivery.calls).toEqual(["ack"]);
}

async function seedExpiredSubscriptions(count: number): Promise<void> {
  const groupID = "880001";
  const at = "2026-01-01T00:00:00.000Z";
  await db.prepare(`INSERT INTO groups(
    id,name,platform,status,is_exclusive,subscription_type,created_at,updated_at,deleted_at
  ) VALUES(?,?,?,?,0,?,?,?,NULL)`).bind(
    groupID, "subscription-expiry-job", "openai", "active", "subscription", at, at,
  ).run();
  const statements: D1PreparedStatement[] = [];
  for (let index = 1; index <= count; index += 1) {
    const id = String(880100 + index);
    statements.push(
      db.prepare(`INSERT INTO users(
        id,status,role,concurrency,balance_e8_usd,allowed_group_ids_json,restrict_public_groups,
        created_at,updated_at,email,password_hash,username,notes,rpm_limit,deleted_at
      ) VALUES(?,?,?,?,?,'[]',0,?,?,?,?,?,?,0,NULL)`).bind(
        id, "active", "user", 1, "0", at, at, `${id}@expiry.test`, "", `expiry-${id}`, "",
      ),
      db.prepare(`INSERT INTO user_subscriptions(
        id,user_id,group_id,plan_id,starts_at,expires_at,status,daily_usage_e8_usd,
        weekly_usage_e8_usd,monthly_usage_e8_usd,assigned_at,notes,version,created_at,updated_at,deleted_at
      ) VALUES(?,?,?,NULL,?,'2026-01-02T00:00:00.000Z','active','0','0','0',?,'',1,?,?,NULL)`)
        .bind(id, id, groupID, at, at, at, at),
    );
  }
  await db.batch(statements);
}

describe("subscription expiry background job", () => {
  it("deduplicates duplicate scheduled events into one durable job and outbox intent", async () => {
    const controller = createScheduledController({
      scheduledTime: new Date(BUCKET),
      cron: "*/2 * * * *",
    });
    for (let index = 0; index < 2; index += 1) {
      const ctx = createExecutionContext();
      await worker.scheduled(controller, env, ctx);
      await waitOnExecutionContext(ctx);
    }
    expect(await db.prepare(`SELECT count(*) AS count FROM background_jobs
      WHERE route=?`).bind(SUBSCRIPTION_EXPIRY_JOB_ROUTE).first<{ count: number }>()).toEqual({ count: 1 });
    expect(await db.prepare(`SELECT count(*) AS count FROM background_job_outbox o
      JOIN background_jobs j ON j.job_id=o.job_id WHERE j.route=?`)
      .bind(SUBSCRIPTION_EXPIRY_JOB_ROUTE).first<{ count: number }>()).toEqual({ count: 1 });
  });

  it("uses the exact Worker-local route and leaves other routes at the Container boundary", async () => {
    const local = await enqueueSubscriptionExpiryMaintenance(db, BUCKET);
    if (!local.job) throw new Error("subscription job missing");
    let containerDispatches = 0;
    const executors = createWorkerJobExecutors(env, async () => {
      containerDispatches += 1;
      return Response.json({ v: 1, kind: "succeeded", resultDigest: "sha256:container" });
    });
    await deliver({ v: 1, jobId: local.job.jobId, route: local.job.route, jobVersion: 1 }, executors);
    expect(containerDispatches).toBe(0);
    expect(await getJob(db, local.job.jobId)).toMatchObject({ status: "succeeded" });

    const containerInput: CreateJobInput = {
      ...(await subscriptionExpiryJobInput(BUCKET + 120_000)),
      jobId: "container-boundary-job",
      operationId: "container-boundary-create",
      route: BACKGROUND_JOB_ROUTES.OAUTH_REFRESH_V1,
      jobType: "oauth-refresh",
      idempotencyKey: "container-boundary-idempotency",
      payloadBody: "{}",
      payloadDigest: "sha256:container-boundary",
    };
    const containerJob = await createAndEnqueueJob(db, containerInput);
    if (!containerJob.job) throw new Error("container job missing");
    await deliver({ v: 1, jobId: containerJob.job.jobId, route: containerJob.job.route, jobVersion: 1 }, executors);
    expect(containerDispatches).toBe(1);
    expect(executors["subscription-expiry-maintenance.v1.extra"]).toBeUndefined();
  });

  it("converges a full batch through one durable cursor follow-up without double expiry effects", async () => {
    await seedExpiredSubscriptions(101);
    const first = await enqueueSubscriptionExpiryMaintenance(db, BUCKET);
    if (!first.job) throw new Error("initial expiry job missing");
    const executors = createWorkerJobExecutors(env);
    await deliver({ v: 1, jobId: first.job.jobId, route: first.job.route, jobVersion: 1 }, executors);
    expect(await getJob(db, first.job.jobId)).toMatchObject({ status: "succeeded" });
    const followUp = await db.prepare(`SELECT job_id,route FROM background_jobs
      WHERE route=? AND job_id<>?`).bind(SUBSCRIPTION_EXPIRY_JOB_ROUTE, first.job.jobId)
      .first<{ job_id: string; route: string }>();
    expect(followUp).toBeTruthy();
    await deliver({ v: 1, jobId: followUp!.job_id, route: followUp!.route, jobVersion: 1 }, executors);
    expect(await db.prepare("SELECT count(*) AS count FROM user_subscriptions WHERE status='expired'")
      .first<{ count: number }>()).toEqual({ count: 101 });
    expect(await db.prepare(`SELECT count(*) AS count FROM subscription_operation_effects e
      JOIN subscription_operations o ON o.operation_id=e.operation_id
      WHERE o.operation_kind='expiry_sweep'`).first<{ count: number }>()).toEqual({ count: 101 });
  });

  it.each(["digest", "malformed"] as const)("fails closed for a %s local payload", async (kind) => {
    const valid = await subscriptionExpiryJobInput(BUCKET);
    const input: CreateJobInput = kind === "digest"
      ? { ...valid, payloadDigest: "sha256:tampered" }
      : { ...valid, payloadBody: "{}", payloadDigest: `sha256:${await sha256("{}")}` };
    const created = await createAndEnqueueJob(db, input);
    if (!created.job) throw new Error("invalid payload job missing");
    await deliver({ v: 1, jobId: created.job.jobId, route: created.job.route, jobVersion: 1 });
    expect(await getJob(db, created.job.jobId)).toMatchObject({
      status: "manual_review",
      errorCode: "subscription_expiry_payload_invalid",
    });
  });
});
