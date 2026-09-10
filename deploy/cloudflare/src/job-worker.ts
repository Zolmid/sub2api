import {
  claimJob,
  drainOutbox,
  getRunningJobExecution,
  listExpiredJobs,
  moveToManualReview,
  processQueueBatch,
  recordPermanentFailure,
  recordRetryableFailure,
  recoverExpiredJob,
  renewJobLease,
  startJob,
  succeedJob,
  type JobRecord,
  type QueueMessageDecision,
  type QueueMessageLike,
} from "./job-runtime";

/** Kept identical in production and local Wrangler configuration. */
export const BACKGROUND_JOB_QUEUE_NAME = "sub2api-background-jobs";

const JOB_LEASE_MS = 120_000;
const OUTBOX_LEASE_MS = 30_000;
const OUTBOX_FAILURE_DELAY_MS = 5_000;
const OUTBOX_DRAIN_LIMIT = 20;
const RECOVERY_LIMIT = 20;

export type JobExecutorResult =
  | Readonly<{ kind: "succeeded"; resultDigest: string }>
  | Readonly<{ kind: "retryable_failure"; errorCode: string }>
  | Readonly<{ kind: "permanent_failure"; errorCode: string }>
  | Readonly<{ kind: "manual_review"; reasonCode: string; evidenceRef: string }>;

export type JobExecutor = (
  input: Readonly<{
    job: JobRecord;
    payloadBody: string;
  }>,
) => Promise<JobExecutorResult>;

export type JobExecutorMap = Readonly<Record<string, JobExecutor>>;

export type JobQueueBatchLike = Readonly<{
  messages: readonly QueueMessageLike[];
}>;

export type JobWorkerDependencies = Readonly<{
  db: D1Database;
  executors?: JobExecutorMap;
  clock?: () => number;
}>;

function operation(prefix: string): string {
  return `${prefix}:${crypto.randomUUID()}`;
}

function runtimeClock(clock: (() => number) | undefined): number {
  const nowMs = (clock ?? Date.now)();
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw new Error("INVALID_RUNTIME_CLOCK");
  }
  return nowMs;
}

async function finish(
  db: D1Database,
  job: JobRecord,
  owner: string,
  leaseToken: string,
  clock: (() => number) | undefined,
  result: JobExecutorResult,
): Promise<QueueMessageDecision> {
  const authority = {
    jobId: job.jobId,
    expectedVersion: job.version,
    operationId: operation("job-finish"),
    owner,
    leaseToken,
    nowMs: runtimeClock(clock),
  };
  const mutation = result.kind === "succeeded"
    ? await succeedJob(db, { ...authority, resultDigest: result.resultDigest })
    : result.kind === "retryable_failure"
    ? await recordRetryableFailure(db, {
      ...authority,
      errorCode: result.errorCode,
      effectState: "started_known_failure",
    })
    : result.kind === "permanent_failure"
    ? await recordPermanentFailure(db, {
      ...authority,
      errorCode: result.errorCode,
      effectState: "started_known_failure",
    })
    : await moveToManualReview(db, {
      ...authority,
      reasonCode: result.reasonCode,
      evidenceRef: result.evidenceRef,
    });
  return mutation.kind === "applied" || mutation.reason === "terminal"
    ? { disposition: "ack", reason: mutation.reason }
    : { disposition: "ack", reason: "stale_or_out_of_order" };
}

async function consumeJobMessage(
  envelope: Parameters<typeof claimJob>[1],
  messageId: string,
  dependencies: JobWorkerDependencies,
): Promise<QueueMessageDecision> {
  const { db, executors = {}, clock } = dependencies;
  const nowMs = runtimeClock(clock);
  const owner = operation("job-worker");
  const leaseToken = operation("job-lease");
  const claimed = await claimJob(db, envelope, {
    operationId: operation("job-claim"),
    owner,
    leaseToken,
    deliveryId: messageId,
    nowMs,
    leaseMs: JOB_LEASE_MS,
  });
  if (claimed.kind !== "claimed" || !claimed.job) {
    return { disposition: claimed.disposition, reason: claimed.reason };
  }

  const renewNowMs = runtimeClock(clock);
  const renewed = await renewJobLease(db, {
    jobId: claimed.job.jobId,
    expectedVersion: claimed.job.version,
    operationId: operation("job-renew"),
    owner,
    leaseToken,
    nowMs: renewNowMs,
    leaseExpiresAtMs: renewNowMs + JOB_LEASE_MS * 2,
  });
  if (renewed.kind !== "applied" || !renewed.job) {
    return { disposition: "ack", reason: "lease_lost_before_start" };
  }

  const started = await startJob(db, {
    jobId: renewed.job.jobId,
    expectedVersion: renewed.job.version,
    operationId: operation("job-start"),
    owner,
    leaseToken,
    nowMs: runtimeClock(clock),
  });
  if (started.kind !== "applied" || !started.job) {
    return { disposition: "ack", reason: "start_lost_or_terminal" };
  }

  const execution = await getRunningJobExecution(db, {
    jobId: started.job.jobId,
    expectedVersion: started.job.version,
    operationId: operation("job-read"),
    owner,
    leaseToken,
    nowMs: runtimeClock(clock),
  });
  if (!execution) return { disposition: "ack", reason: "execution_lease_lost" };

  const executor = executors[execution.job.route];
  if (!executor) {
    return finish(db, execution.job, owner, leaseToken, clock, {
      kind: "manual_review",
      reasonCode: "unknown_route",
      evidenceRef: `route:${execution.job.route}`,
    });
  }
  return finish(
    db,
    execution.job,
    owner,
    leaseToken,
    clock,
    await executor(execution),
  );
}

/**
 * Per-message acknowledgement makes redelivery safe: a durable state change is
 * committed before ack, and an infrastructure exception retries the message.
 */
export async function consumeJobQueueBatch(
  batch: JobQueueBatchLike,
  dependencies: JobWorkerDependencies,
): Promise<readonly QueueMessageDecision[]> {
  return processQueueBatch(batch.messages, (envelope, messageId) =>
    consumeJobMessage(envelope, messageId, dependencies)
  );
}

/** Publish only opaque envelopes from durable outbox rows. */
export async function drainBackgroundJobOutbox(
  env: Pick<Env, "DB" | "JOB_QUEUE">,
  clock: () => number = Date.now,
): Promise<void> {
  const nowMs = runtimeClock(clock);
  await drainOutbox(env.DB, env.JOB_QUEUE, {
    owner: operation("job-outbox"),
    nowMs,
    leaseMs: OUTBOX_LEASE_MS,
    failureDelayMs: OUTBOX_FAILURE_DELAY_MS,
    limit: OUTBOX_DRAIN_LIMIT,
    now: () => runtimeClock(clock),
  });
}

/**
 * A never-started claim can be retried; a running lease expiry is quarantined
 * because its external effect may already have happened.
 */
export async function recoverExpiredBackgroundJobs(
  db: D1Database,
  clock: () => number = Date.now,
): Promise<void> {
  const nowMs = runtimeClock(clock);
  const jobs = await listExpiredJobs(db, nowMs, RECOVERY_LIMIT);
  for (const job of jobs) {
    await recoverExpiredJob(db, {
      jobId: job.jobId,
      expectedVersion: job.version,
      operationId: operation("job-recover"),
      actor: "job-scheduled-recovery",
      nowMs,
    });
  }
}
