import { canonical, sha256 } from "./contracts";
import { createAndEnqueueJob, type CreateJobInput, type JobRecord } from "./job-runtime";
import type { JobExecutor, JobExecutorResult } from "./job-worker";
import { SubscriptionRuntime } from "./subscription-runtime";

export const SUBSCRIPTION_EXPIRY_JOB_ROUTE = "subscription-expiry-maintenance.v1";
export const SUBSCRIPTION_EXPIRY_JOB_TYPE = "subscription-expiry-maintenance";
export const SUBSCRIPTION_EXPIRY_JOB_VERSION = 1 as const;
export const SUBSCRIPTION_EXPIRY_BUCKET_MS = 120_000;
export const SUBSCRIPTION_EXPIRY_BATCH_LIMIT = 100;

type ExpiryPayload = Readonly<{
  v: typeof SUBSCRIPTION_EXPIRY_JOB_VERSION;
  bucket_ms: number;
  cutoff: string;
  after_id: string | null;
  limit: typeof SUBSCRIPTION_EXPIRY_BATCH_LIMIT;
}>;

const ID_RE = /^[1-9][0-9]{0,18}$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length &&
    keys.every((key) => typeof key === "string" && expected.includes(key)) &&
    expected.every((key) => Object.prototype.propertyIsEnumerable.call(value, key));
}

function bucketStart(scheduledAtMs: number): number {
  if (!Number.isSafeInteger(scheduledAtMs) || scheduledAtMs < 0) {
    throw new Error("INVALID_SUBSCRIPTION_EXPIRY_SCHEDULE");
  }
  return Math.floor(scheduledAtMs / SUBSCRIPTION_EXPIRY_BUCKET_MS) * SUBSCRIPTION_EXPIRY_BUCKET_MS;
}

function payloadFor(bucketMs: number, afterID: string | null): ExpiryPayload {
  return {
    v: SUBSCRIPTION_EXPIRY_JOB_VERSION,
    bucket_ms: bucketMs,
    cutoff: new Date(bucketMs).toISOString(),
    after_id: afterID,
    limit: SUBSCRIPTION_EXPIRY_BATCH_LIMIT,
  };
}

function cursorID(afterID: string | null): string {
  return afterID ?? "start";
}

function jobID(bucketMs: number, afterID: string | null): string {
  return `subscription-expiry:${bucketMs}:${cursorID(afterID)}`;
}

function operationID(bucketMs: number, afterID: string | null): string {
  return `subscription-expiry-create:${bucketMs}:${cursorID(afterID)}`;
}

function sweepOperationID(bucketMs: number, afterID: string | null): string {
  return `subscription-expiry-sweep:${bucketMs}:${cursorID(afterID)}`;
}

function samePayload(value: ExpiryPayload, expected: ExpiryPayload): boolean {
  return value.v === expected.v && value.bucket_ms === expected.bucket_ms &&
    value.cutoff === expected.cutoff && value.after_id === expected.after_id &&
    value.limit === expected.limit;
}

function parsePayload(body: string): ExpiryPayload | null {
  try {
    const parsed: unknown = JSON.parse(body);
    if (!isPlainObject(parsed) || !exactKeys(parsed, ["v", "bucket_ms", "cutoff", "after_id", "limit"])) {
      return null;
    }
    const { v, bucket_ms: bucketMs, cutoff, after_id: afterID, limit } = parsed;
    if (v !== SUBSCRIPTION_EXPIRY_JOB_VERSION || typeof bucketMs !== "number" ||
      !Number.isSafeInteger(bucketMs) || bucketMs < 0 ||
      bucketMs !== bucketStart(bucketMs) ||
      typeof cutoff !== "string" ||
      new Date(cutoff).toISOString() !== cutoff ||
      (afterID !== null && (typeof afterID !== "string" || !ID_RE.test(afterID))) ||
      limit !== SUBSCRIPTION_EXPIRY_BATCH_LIMIT) {
      return null;
    }
    const payload: ExpiryPayload = { v, bucket_ms: bucketMs, cutoff, after_id: afterID, limit };
    return samePayload(payload, payloadFor(payload.bucket_ms, payload.after_id)) ? payload : null;
  } catch {
    return null;
  }
}

function jobMatchesPayload(job: JobRecord, payload: ExpiryPayload): boolean {
  return job.route === SUBSCRIPTION_EXPIRY_JOB_ROUTE &&
    job.jobType === SUBSCRIPTION_EXPIRY_JOB_TYPE &&
    job.idempotencyKey === jobID(payload.bucket_ms, payload.after_id) &&
    job.jobId === jobID(payload.bucket_ms, payload.after_id);
}

function invalidPayload(job: JobRecord): JobExecutorResult {
  return {
    kind: "manual_review",
    reasonCode: "subscription_expiry_payload_invalid",
    evidenceRef: `job:${job.jobId}`,
  };
}

export async function subscriptionExpiryJobInput(
  scheduledAtMs: number,
  afterID: string | null = null,
): Promise<CreateJobInput> {
  const bucketMs = bucketStart(scheduledAtMs);
  if (afterID !== null && !ID_RE.test(afterID)) throw new Error("INVALID_SUBSCRIPTION_EXPIRY_CURSOR");
  const payload = payloadFor(bucketMs, afterID);
  const payloadBody = canonical(payload);
  return {
    jobId: jobID(bucketMs, afterID),
    operationId: operationID(bucketMs, afterID),
    route: SUBSCRIPTION_EXPIRY_JOB_ROUTE,
    jobType: SUBSCRIPTION_EXPIRY_JOB_TYPE,
    idempotencyKey: jobID(bucketMs, afterID),
    payloadCodec: "json",
    payloadBody,
    payloadDigest: `sha256:${await sha256(payloadBody)}`,
    maxAttempts: 5,
    baseDelayMs: 5_000,
    maxDelayMs: 300_000,
    nowMs: bucketMs,
    actor: "subscription-expiry-scheduled",
  };
}

/** Creates one durable intent for a scheduled bucket; Queue publication stays separate. */
export async function enqueueSubscriptionExpiryMaintenance(
  db: D1Database,
  scheduledAtMs: number,
  afterID: string | null = null,
) {
  return createAndEnqueueJob(db, await subscriptionExpiryJobInput(scheduledAtMs, afterID));
}

/**
 * This route is Worker-local because it performs only the private D1 subscription
 * transition. A full batch creates its next durable cursor job before success.
 */
export function createSubscriptionExpiryMaintenanceExecutor(db: D1Database): JobExecutor {
  return async ({ job, payloadBody }) => {
    if (job.payloadCodec !== "json" || job.payloadDigest !== `sha256:${await sha256(payloadBody)}`) {
      return invalidPayload(job);
    }
    const payload = parsePayload(payloadBody);
    if (!payload || !jobMatchesPayload(job, payload)) return invalidPayload(job);

    let swept: { expired_ids: string[]; count: number };
    try {
      swept = await new SubscriptionRuntime(db).sweepExpired({
        operation_id: sweepOperationID(payload.bucket_ms, payload.after_id),
        cutoff: payload.cutoff,
        after_id: payload.after_id,
        limit: payload.limit,
      });
    } catch {
      // The sweep operation ID is deterministic, so a retry can safely read a
      // committed effect instead of applying it twice.
      return { kind: "retryable_failure", errorCode: "subscription_expiry_sweep_failed" };
    }

    if (swept.count === payload.limit) {
      const nextAfterID = swept.expired_ids.at(-1);
      if (!nextAfterID) return { kind: "retryable_failure", errorCode: "subscription_expiry_cursor_missing" };
      try {
        const next = await enqueueSubscriptionExpiryMaintenance(db, payload.bucket_ms, nextAfterID);
        if (next.kind === "conflict") {
          return {
            kind: "manual_review",
            reasonCode: "subscription_expiry_followup_conflict",
            evidenceRef: `job:${nextAfterID}`,
          };
        }
      } catch {
        return { kind: "retryable_failure", errorCode: "subscription_expiry_followup_failed" };
      }
    }

    return {
      kind: "succeeded",
      resultDigest: `sha256:${await sha256(canonical({ bucket_ms: payload.bucket_ms, after_id: payload.after_id, swept }))}`,
    };
  };
}
