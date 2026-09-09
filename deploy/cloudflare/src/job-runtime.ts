/** Durable, generic D1 authority for at-least-once Cloudflare Queue work. */

const MAX_TIME_MS = 4_102_444_800_000;
const MAX_BATCH = 100;
const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;

export const JOB_ENVELOPE_VERSION = 1 as const;

export type JobStatus =
  | "queued"
  | "claimed"
  | "running"
  | "retry_wait"
  | "succeeded"
  | "failed"
  | "dead_letter"
  | "manual_review";

export type PayloadCodec = "json" | "app_encrypted_v1";

export type QueueEnvelope = Readonly<{
  v: typeof JOB_ENVELOPE_VERSION;
  jobId: string;
  route: string;
  jobVersion: number;
}>;

export type JobRecord = Readonly<{
  jobId: string;
  route: string;
  jobType: string;
  idempotencyKey: string;
  payloadCodec: PayloadCodec;
  payloadDigest: string;
  status: JobStatus;
  version: number;
  attemptCount: number;
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  availableAtMs: number;
  leaseOwner: string | null;
  leaseToken: string | null;
  deliveryId: string | null;
  leaseExpiresAtMs: number | null;
  resultDigest: string | null;
  errorCode: string | null;
  replayOfJobId: string | null;
  replayKey: string | null;
  createdAtMs: number;
  updatedAtMs: number;
  completedAtMs: number | null;
}>;

type JobRow = {
  job_id: string;
  route: string;
  job_type: string;
  idempotency_key: string;
  payload_codec: PayloadCodec;
  payload_body: string;
  payload_digest: string;
  status: JobStatus;
  version: number;
  attempt_count: number;
  max_attempts: number;
  base_delay_ms: number;
  max_delay_ms: number;
  available_at_ms: number;
  lease_owner: string | null;
  lease_token: string | null;
  delivery_id: string | null;
  lease_expires_at_ms: number | null;
  result_digest: string | null;
  error_code: string | null;
  replay_of_job_id: string | null;
  replay_key: string | null;
  created_at_ms: number;
  updated_at_ms: number;
  completed_at_ms: number | null;
};

export type MutationResult = Readonly<{
  kind: "applied" | "noop" | "conflict";
  reason: string;
  job: JobRecord | null;
  outboxCreated: boolean;
}>;

export type CreateJobInput = Readonly<{
  jobId: string;
  operationId: string;
  route: string;
  jobType: string;
  idempotencyKey: string;
  payloadCodec: PayloadCodec;
  payloadBody: string;
  payloadDigest: string;
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  nowMs: number;
  actor: string;
}>;

export type AuthorityInput = Readonly<{
  jobId: string;
  expectedVersion: number;
  operationId: string;
  owner: string;
  leaseToken: string;
  nowMs: number;
}>;

export type ClaimInput = Readonly<{
  operationId: string;
  owner: string;
  leaseToken: string;
  deliveryId: string;
  nowMs: number;
  leaseMs: number;
}>;

export type ClaimResult = Readonly<{
  kind: "claimed" | "noop" | "invalid_envelope";
  reason: string;
  disposition: "ack" | "retry";
  job: JobRecord | null;
}>;

export type FailureInput = AuthorityInput & Readonly<{
  errorCode: string;
  effectState: "not_started" | "started_known_failure";
}>;

export type ManualReviewInput = AuthorityInput & Readonly<{
  reasonCode: string;
  evidenceRef: string;
}>;

export type ReplayInput = Readonly<{
  sourceJobId: string;
  expectedSourceVersion: number;
  newJobId: string;
  operationId: string;
  replayKey: string;
  idempotencyKey: string;
  actor: string;
  reasonCode: string;
  evidenceKind:
    | "provider_idempotency"
    | "provider_query_no_effect"
    | "operator_confirmed_no_effect";
  evidenceRef: string;
  nowMs: number;
}>;

export type OutboxRecord = Readonly<{
  outboxId: string;
  jobId: string;
  jobVersion: number;
  envelope: QueueEnvelope;
  state: "pending" | "publishing" | "published";
  version: number;
  availableAtMs: number;
  publishOwner: string | null;
  publishLeaseExpiresAtMs: number | null;
}>;

type OutboxRow = {
  outbox_id: string;
  job_id: string;
  job_version: number;
  envelope_json: string;
  state: "pending" | "publishing" | "published";
  version: number;
  available_at_ms: number;
  publish_owner: string | null;
  publish_lease_expires_at_ms: number | null;
};

type SQLValue = string | number | null;

function safeText(value: string, maximum: number): boolean {
  return value.length >= 1 && value.length <= maximum && value.trim() === value &&
    OPAQUE.test(value);
}

function safeTime(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_TIME_MS;
}

function positiveVersion(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 1;
}

function assertText(value: string, maximum: number, field: string): void {
  if (!safeText(value, maximum)) throw new Error(`INVALID_${field}`);
}

function assertTime(value: number): void {
  if (!safeTime(value)) throw new Error("INVALID_TIME");
}

function assertAuthority(input: AuthorityInput): void {
  assertText(input.jobId, 160, "JOB_ID");
  assertText(input.operationId, 160, "OPERATION_ID");
  assertText(input.owner, 160, "OWNER");
  assertText(input.leaseToken, 160, "LEASE_TOKEN");
  if (!positiveVersion(input.expectedVersion)) throw new Error("INVALID_VERSION");
  assertTime(input.nowMs);
}

function jobRecord(row: JobRow): JobRecord {
  return {
    jobId: row.job_id,
    route: row.route,
    jobType: row.job_type,
    idempotencyKey: row.idempotency_key,
    payloadCodec: row.payload_codec,
    payloadDigest: row.payload_digest,
    status: row.status,
    version: row.version,
    attemptCount: row.attempt_count,
    maxAttempts: row.max_attempts,
    baseDelayMs: row.base_delay_ms,
    maxDelayMs: row.max_delay_ms,
    availableAtMs: row.available_at_ms,
    leaseOwner: row.lease_owner,
    leaseToken: row.lease_token,
    deliveryId: row.delivery_id,
    leaseExpiresAtMs: row.lease_expires_at_ms,
    resultDigest: row.result_digest,
    errorCode: row.error_code,
    replayOfJobId: row.replay_of_job_id,
    replayKey: row.replay_key,
    createdAtMs: row.created_at_ms,
    updatedAtMs: row.updated_at_ms,
    completedAtMs: row.completed_at_ms,
  };
}

const JOB_COLUMNS = `job_id,route,job_type,idempotency_key,payload_codec,
  payload_body,payload_digest,status,version,attempt_count,max_attempts,
  base_delay_ms,max_delay_ms,available_at_ms,lease_owner,lease_token,
  delivery_id,lease_expires_at_ms,result_digest,error_code,replay_of_job_id,
  replay_key,created_at_ms,updated_at_ms,completed_at_ms`;

async function loadJobRow(db: D1Database, jobId: string): Promise<JobRow | null> {
  return db.prepare(`SELECT ${JOB_COLUMNS} FROM background_jobs WHERE job_id=?`)
    .bind(jobId).first<JobRow>();
}

export async function getJob(db: D1Database, jobId: string): Promise<JobRecord | null> {
  assertText(jobId, 160, "JOB_ID");
  const row = await loadJobRow(db, jobId);
  return row ? jobRecord(row) : null;
}

export function makeQueueEnvelope(jobId: string, route: string, jobVersion: number): QueueEnvelope {
  assertText(jobId, 160, "JOB_ID");
  assertText(route, 96, "ROUTE");
  if (!positiveVersion(jobVersion)) throw new Error("INVALID_VERSION");
  return { v: JOB_ENVELOPE_VERSION, jobId, route, jobVersion };
}

export function parseQueueEnvelope(value: unknown): QueueEnvelope | null {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== 4 || !keys.every((key) =>
      typeof key === "string" && ["v", "jobId", "route", "jobVersion"].includes(key)
    )) return null;
    if (!keys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined && "value" in descriptor && descriptor.enumerable;
    })) return null;
    const row = value as Record<string, unknown>;
    if (row.v !== JOB_ENVELOPE_VERSION || typeof row.jobId !== "string" ||
      typeof row.route !== "string" || typeof row.jobVersion !== "number" ||
      !safeText(row.jobId, 160) || !safeText(row.route, 96) ||
      !positiveVersion(row.jobVersion)) return null;
    return makeQueueEnvelope(row.jobId, row.route, row.jobVersion);
  } catch {
    return null;
  }
}

function envelopeJSON(jobId: string, route: string, version: number): string {
  return JSON.stringify(makeQueueEnvelope(jobId, route, version));
}

function changes(result: D1Result): number {
  const count = result.meta.changes;
  if (!Number.isInteger(count) || count < 0) {
    throw new Error("D1_BATCH_METADATA_MISSING");
  }
  return count;
}

function verifyBatch(results: D1Result[], expectedStatements: number): boolean {
  if (results.length !== expectedStatements) throw new Error("D1_BATCH_RESULT_INCOMPLETE");
  const counts = results.map(changes);
  if (counts.every((count) => count === 1)) return true;
  if (counts.every((count) => count === 0)) return false;
  throw new Error("D1_ATOMIC_GUARD_INCONSISTENT");
}

export function retryDelayMs(attemptCount: number, baseDelayMs: number, maxDelayMs: number): number {
  if (!Number.isInteger(attemptCount) || attemptCount < 1 || attemptCount > 100 ||
    !Number.isInteger(baseDelayMs) || baseDelayMs < 0 ||
    !Number.isInteger(maxDelayMs) || maxDelayMs < baseDelayMs) {
    throw new Error("INVALID_RETRY_POLICY");
  }
  let delay = baseDelayMs;
  for (let attempt = 1; attempt < attemptCount && delay < maxDelayMs; attempt += 1) {
    delay = Math.min(maxDelayMs, delay * 2);
  }
  return delay;
}

function validateCreate(input: CreateJobInput): void {
  assertText(input.jobId, 160, "JOB_ID");
  assertText(input.operationId, 160, "OPERATION_ID");
  assertText(input.route, 96, "ROUTE");
  assertText(input.jobType, 96, "JOB_TYPE");
  assertText(input.idempotencyKey, 192, "IDEMPOTENCY_KEY");
  assertText(input.payloadDigest, 160, "PAYLOAD_DIGEST");
  assertText(input.actor, 160, "ACTOR");
  assertTime(input.nowMs);
  if (input.payloadCodec !== "json" && input.payloadCodec !== "app_encrypted_v1") {
    throw new Error("INVALID_PAYLOAD_CODEC");
  }
  if (input.payloadBody.length < 1 || input.payloadBody.length > 1_048_576) {
    throw new Error("INVALID_PAYLOAD_BODY");
  }
  if (input.payloadCodec === "json") {
    try { JSON.parse(input.payloadBody); } catch { throw new Error("INVALID_PAYLOAD_BODY"); }
  }
  if (!Number.isInteger(input.maxAttempts) || input.maxAttempts < 1 || input.maxAttempts > 100 ||
    !Number.isInteger(input.baseDelayMs) || input.baseDelayMs < 0 || input.baseDelayMs > 86_400_000 ||
    !Number.isInteger(input.maxDelayMs) || input.maxDelayMs < input.baseDelayMs ||
    input.maxDelayMs > 604_800_000) throw new Error("INVALID_RETRY_POLICY");
}

export async function createAndEnqueueJob(
  db: D1Database,
  input: CreateJobInput,
): Promise<MutationResult> {
  validateCreate(input);
  const outboxId = crypto.randomUUID();
  const results = await db.batch([
    db.prepare(`INSERT OR IGNORE INTO background_jobs(
      job_id,route,job_type,idempotency_key,payload_codec,payload_body,payload_digest,
      status,version,attempt_count,max_attempts,base_delay_ms,max_delay_ms,
      available_at_ms,created_at_ms,updated_at_ms
    ) VALUES(?,?,?,?,?,?,?,'queued',1,0,?,?,?,?,?,?)`).bind(
      input.jobId, input.route, input.jobType, input.idempotencyKey,
      input.payloadCodec, input.payloadBody, input.payloadDigest,
      input.maxAttempts, input.baseDelayMs, input.maxDelayMs,
      input.nowMs, input.nowMs, input.nowMs,
    ),
    db.prepare(`INSERT INTO background_job_transitions(
      transition_id,job_id,event_type,from_status,to_status,from_version,to_version,
      actor,reason_code,evidence_ref,created_at_ms
    ) SELECT ?,?,'created',NULL,'queued',0,1,?,NULL,NULL,? WHERE changes()=1`).bind(
      input.operationId, input.jobId, input.actor, input.nowMs,
    ),
    db.prepare(`INSERT INTO background_job_outbox(
      outbox_id,job_id,job_version,envelope_json,state,version,available_at_ms,created_at_ms
    ) SELECT ?,?,?,?,'pending',1,?,? WHERE changes()=1`).bind(
      outboxId, input.jobId, 1, envelopeJSON(input.jobId, input.route, 1),
      input.nowMs, input.nowMs,
    ),
  ]);
  const applied = verifyBatch(results, 3);
  const row = await loadJobRow(db, input.jobId) ??
    await db.prepare(`SELECT ${JOB_COLUMNS} FROM background_jobs WHERE route=? AND idempotency_key=?`)
      .bind(input.route, input.idempotencyKey).first<JobRow>();
  if (applied) return { kind: "applied", reason: "created", job: row ? jobRecord(row) : null, outboxCreated: true };
  const same = row !== null && row.route === input.route && row.job_type === input.jobType &&
    row.idempotency_key === input.idempotencyKey && row.payload_codec === input.payloadCodec &&
    row.payload_body === input.payloadBody && row.payload_digest === input.payloadDigest &&
    row.max_attempts === input.maxAttempts && row.base_delay_ms === input.baseDelayMs &&
    row.max_delay_ms === input.maxDelayMs;
  return {
    kind: same ? "noop" : "conflict",
    reason: same ? "idempotent_create" : "idempotency_conflict",
    job: row ? jobRecord(row) : null,
    outboxCreated: false,
  };
}

type TransitionSpec = Readonly<{
  jobId: string;
  expectedVersion: number;
  operationId: string;
  fromStatus: JobStatus;
  toStatus: JobStatus;
  eventType: string;
  actor: string;
  reasonCode?: string;
  evidenceRef?: string;
  nowMs: number;
  updateSQL: string;
  updateBindings: readonly SQLValue[];
  outbox?: Readonly<{ route: string; availableAtMs: number }>;
}>;

async function applyTransition(db: D1Database, spec: TransitionSpec): Promise<MutationResult> {
  const nextVersion = spec.expectedVersion + 1;
  const statements = [
    db.prepare(spec.updateSQL).bind(...spec.updateBindings),
    db.prepare(`INSERT INTO background_job_transitions(
      transition_id,job_id,event_type,from_status,to_status,from_version,to_version,
      actor,reason_code,evidence_ref,created_at_ms
    ) SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE changes()=1`).bind(
      spec.operationId, spec.jobId, spec.eventType, spec.fromStatus, spec.toStatus,
      spec.expectedVersion, nextVersion, spec.actor, spec.reasonCode ?? null,
      spec.evidenceRef ?? null, spec.nowMs,
    ),
  ];
  if (spec.outbox) {
    statements.push(db.prepare(`INSERT INTO background_job_outbox(
      outbox_id,job_id,job_version,envelope_json,state,version,available_at_ms,created_at_ms
    ) SELECT ?,?,?,?,'pending',1,?,? WHERE changes()=1`).bind(
      crypto.randomUUID(), spec.jobId, nextVersion,
      envelopeJSON(spec.jobId, spec.outbox.route, nextVersion),
      spec.outbox.availableAtMs, spec.nowMs,
    ));
  }
  const applied = verifyBatch(await db.batch(statements), statements.length);
  const current = await loadJobRow(db, spec.jobId);
  return {
    kind: applied ? "applied" : "noop",
    reason: applied ? spec.eventType : "stale_or_out_of_order",
    job: current ? jobRecord(current) : null,
    outboxCreated: applied && spec.outbox !== undefined,
  };
}

function authorityMatches(row: JobRow, input: AuthorityInput): boolean {
  return row.version === input.expectedVersion && row.lease_owner === input.owner &&
    row.lease_token === input.leaseToken && row.lease_expires_at_ms !== null &&
    row.lease_expires_at_ms > input.nowMs && input.nowMs >= row.updated_at_ms;
}

export async function claimJob(
  db: D1Database,
  rawEnvelope: unknown,
  input: ClaimInput,
): Promise<ClaimResult> {
  const envelope = parseQueueEnvelope(rawEnvelope);
  if (!envelope) return { kind: "invalid_envelope", reason: "invalid_envelope", disposition: "ack", job: null };
  assertText(input.operationId, 160, "OPERATION_ID");
  assertText(input.owner, 160, "OWNER");
  assertText(input.leaseToken, 160, "LEASE_TOKEN");
  assertText(input.deliveryId, 160, "DELIVERY_ID");
  assertTime(input.nowMs);
  if (!Number.isInteger(input.leaseMs) || input.leaseMs < 1 || input.leaseMs > 86_400_000 ||
    input.nowMs + input.leaseMs > MAX_TIME_MS) throw new Error("INVALID_LEASE");
  const row = await loadJobRow(db, envelope.jobId);
  if (!row || row.route !== envelope.route) {
    return { kind: "noop", reason: "unknown_job_or_route", disposition: "ack", job: row ? jobRecord(row) : null };
  }
  if (row.version !== envelope.jobVersion) {
    return { kind: "noop", reason: "stale_delivery", disposition: "ack", job: jobRecord(row) };
  }
  if (row.status !== "queued" && row.status !== "retry_wait") {
    return { kind: "noop", reason: "already_claimed_or_terminal", disposition: "ack", job: jobRecord(row) };
  }
  if (row.available_at_ms > input.nowMs) {
    return { kind: "noop", reason: "not_due", disposition: "retry", job: jobRecord(row) };
  }
  const result = await applyTransition(db, {
    jobId: row.job_id,
    expectedVersion: row.version,
    operationId: input.operationId,
    fromStatus: row.status,
    toStatus: "claimed",
    eventType: "claimed",
    actor: input.owner,
    nowMs: input.nowMs,
    updateSQL: `UPDATE background_jobs SET status='claimed',version=version+1,
      attempt_count=attempt_count+1,lease_owner=?,lease_token=?,delivery_id=?,
      lease_expires_at_ms=?,updated_at_ms=?
      WHERE job_id=? AND route=? AND version=? AND status=?
        AND available_at_ms<=? AND attempt_count<max_attempts`,
    updateBindings: [input.owner, input.leaseToken, input.deliveryId,
      input.nowMs + input.leaseMs, input.nowMs, row.job_id, row.route,
      row.version, row.status, input.nowMs],
  });
  return result.kind === "applied"
    ? { kind: "claimed", reason: "claimed", disposition: "ack", job: result.job }
    : { kind: "noop", reason: "concurrent_claim", disposition: "ack", job: result.job };
}

export async function startJob(db: D1Database, input: AuthorityInput): Promise<MutationResult> {
  assertAuthority(input);
  const row = await loadJobRow(db, input.jobId);
  if (!row || row.status !== "claimed" || !authorityMatches(row, input)) {
    return { kind: "noop", reason: row && ["succeeded", "failed", "dead_letter", "manual_review"].includes(row.status) ? "terminal" : "stale_or_out_of_order", job: row ? jobRecord(row) : null, outboxCreated: false };
  }
  return applyTransition(db, {
    jobId: row.job_id, expectedVersion: row.version, operationId: input.operationId,
    fromStatus: "claimed", toStatus: "running", eventType: "started",
    actor: input.owner, nowMs: input.nowMs,
    updateSQL: `UPDATE background_jobs SET status='running',version=version+1,updated_at_ms=?
      WHERE job_id=? AND version=? AND status='claimed' AND lease_owner=?
        AND lease_token=? AND lease_expires_at_ms>?`,
    updateBindings: [input.nowMs, row.job_id, row.version, input.owner, input.leaseToken, input.nowMs],
  });
}

export async function succeedJob(
  db: D1Database,
  input: AuthorityInput & Readonly<{ resultDigest: string }>,
): Promise<MutationResult> {
  assertAuthority(input);
  assertText(input.resultDigest, 160, "RESULT_DIGEST");
  const row = await loadJobRow(db, input.jobId);
  if (!row || row.status !== "running" || !authorityMatches(row, input)) {
    return { kind: "noop", reason: row && ["succeeded", "failed", "dead_letter", "manual_review"].includes(row.status) ? "terminal" : "stale_or_out_of_order", job: row ? jobRecord(row) : null, outboxCreated: false };
  }
  return applyTransition(db, {
    jobId: row.job_id, expectedVersion: row.version, operationId: input.operationId,
    fromStatus: "running", toStatus: "succeeded", eventType: "succeeded",
    actor: input.owner, nowMs: input.nowMs,
    updateSQL: `UPDATE background_jobs SET status='succeeded',version=version+1,
      result_digest=?,error_code=NULL,lease_owner=NULL,lease_token=NULL,delivery_id=NULL,
      lease_expires_at_ms=NULL,updated_at_ms=?,completed_at_ms=?
      WHERE job_id=? AND version=? AND status='running' AND lease_owner=?
        AND lease_token=? AND lease_expires_at_ms>?`,
    updateBindings: [input.resultDigest, input.nowMs, input.nowMs, row.job_id,
      row.version, input.owner, input.leaseToken, input.nowMs],
  });
}

function validFailureState(row: JobRow, input: FailureInput): boolean {
  return (row.status === "claimed" && input.effectState === "not_started") ||
    (row.status === "running" && input.effectState === "started_known_failure");
}

export async function recordRetryableFailure(
  db: D1Database,
  input: FailureInput,
): Promise<MutationResult> {
  assertAuthority(input);
  assertText(input.errorCode, 96, "ERROR_CODE");
  const row = await loadJobRow(db, input.jobId);
  if (!row || !validFailureState(row, input) || !authorityMatches(row, input)) {
    return { kind: "noop", reason: row && ["succeeded", "failed", "dead_letter", "manual_review"].includes(row.status) ? "terminal" : "stale_or_out_of_order", job: row ? jobRecord(row) : null, outboxCreated: false };
  }
  const exhausted = row.attempt_count >= row.max_attempts;
  const delay = exhausted ? 0 : retryDelayMs(row.attempt_count, row.base_delay_ms, row.max_delay_ms);
  if (!exhausted && input.nowMs + delay > MAX_TIME_MS) throw new Error("RETRY_TIME_EXHAUSTED");
  const toStatus: JobStatus = exhausted ? "dead_letter" : "retry_wait";
  return applyTransition(db, {
    jobId: row.job_id, expectedVersion: row.version, operationId: input.operationId,
    fromStatus: row.status, toStatus,
    eventType: exhausted ? "dead_lettered" : "retry_scheduled",
    actor: input.owner, reasonCode: input.errorCode, nowMs: input.nowMs,
    updateSQL: `UPDATE background_jobs SET status=?,version=version+1,error_code=?,
      available_at_ms=?,lease_owner=NULL,lease_token=NULL,delivery_id=NULL,
      lease_expires_at_ms=NULL,updated_at_ms=?,completed_at_ms=?
      WHERE job_id=? AND version=? AND status=? AND lease_owner=? AND lease_token=?
        AND lease_expires_at_ms>?`,
    updateBindings: [toStatus, input.errorCode, input.nowMs + delay, input.nowMs,
      exhausted ? input.nowMs : null, row.job_id, row.version, row.status,
      input.owner, input.leaseToken, input.nowMs],
    outbox: exhausted ? undefined : { route: row.route, availableAtMs: input.nowMs + delay },
  });
}

export async function recordPermanentFailure(
  db: D1Database,
  input: FailureInput,
): Promise<MutationResult> {
  assertAuthority(input);
  assertText(input.errorCode, 96, "ERROR_CODE");
  const row = await loadJobRow(db, input.jobId);
  if (!row || !validFailureState(row, input) || !authorityMatches(row, input)) {
    return { kind: "noop", reason: row && ["succeeded", "failed", "dead_letter", "manual_review"].includes(row.status) ? "terminal" : "stale_or_out_of_order", job: row ? jobRecord(row) : null, outboxCreated: false };
  }
  return applyTransition(db, {
    jobId: row.job_id, expectedVersion: row.version, operationId: input.operationId,
    fromStatus: row.status, toStatus: "failed", eventType: "failed",
    actor: input.owner, reasonCode: input.errorCode, nowMs: input.nowMs,
    updateSQL: `UPDATE background_jobs SET status='failed',version=version+1,error_code=?,
      lease_owner=NULL,lease_token=NULL,delivery_id=NULL,lease_expires_at_ms=NULL,
      updated_at_ms=?,completed_at_ms=?
      WHERE job_id=? AND version=? AND status=? AND lease_owner=? AND lease_token=?
        AND lease_expires_at_ms>?`,
    updateBindings: [input.errorCode, input.nowMs, input.nowMs, row.job_id,
      row.version, row.status, input.owner, input.leaseToken, input.nowMs],
  });
}

export async function deadLetterJob(db: D1Database, input: FailureInput): Promise<MutationResult> {
  assertAuthority(input);
  assertText(input.errorCode, 96, "ERROR_CODE");
  const row = await loadJobRow(db, input.jobId);
  if (!row || !validFailureState(row, input) || !authorityMatches(row, input)) {
    return { kind: "noop", reason: "stale_or_out_of_order", job: row ? jobRecord(row) : null, outboxCreated: false };
  }
  return applyTransition(db, {
    jobId: row.job_id, expectedVersion: row.version, operationId: input.operationId,
    fromStatus: row.status, toStatus: "dead_letter", eventType: "dead_lettered",
    actor: input.owner, reasonCode: input.errorCode, nowMs: input.nowMs,
    updateSQL: `UPDATE background_jobs SET status='dead_letter',version=version+1,error_code=?,
      lease_owner=NULL,lease_token=NULL,delivery_id=NULL,lease_expires_at_ms=NULL,
      updated_at_ms=?,completed_at_ms=?
      WHERE job_id=? AND version=? AND status=? AND lease_owner=? AND lease_token=?
        AND lease_expires_at_ms>?`,
    updateBindings: [input.errorCode, input.nowMs, input.nowMs, row.job_id,
      row.version, row.status, input.owner, input.leaseToken, input.nowMs],
  });
}

export async function moveToManualReview(
  db: D1Database,
  input: ManualReviewInput,
): Promise<MutationResult> {
  assertAuthority(input);
  assertText(input.reasonCode, 96, "REASON_CODE");
  assertText(input.evidenceRef, 256, "EVIDENCE_REF");
  const row = await loadJobRow(db, input.jobId);
  if (!row || row.status !== "running" || !authorityMatches(row, input)) {
    return { kind: "noop", reason: row && ["succeeded", "failed", "dead_letter", "manual_review"].includes(row.status) ? "terminal" : "stale_or_out_of_order", job: row ? jobRecord(row) : null, outboxCreated: false };
  }
  return applyTransition(db, {
    jobId: row.job_id, expectedVersion: row.version, operationId: input.operationId,
    fromStatus: "running", toStatus: "manual_review", eventType: "manual_review",
    actor: input.owner, reasonCode: input.reasonCode, evidenceRef: input.evidenceRef,
    nowMs: input.nowMs,
    updateSQL: `UPDATE background_jobs SET status='manual_review',version=version+1,
      error_code=?,lease_owner=NULL,lease_token=NULL,delivery_id=NULL,
      lease_expires_at_ms=NULL,updated_at_ms=?,completed_at_ms=?
      WHERE job_id=? AND version=? AND status='running' AND lease_owner=?
        AND lease_token=? AND lease_expires_at_ms>?`,
    updateBindings: [input.reasonCode, input.nowMs, input.nowMs, row.job_id,
      row.version, input.owner, input.leaseToken, input.nowMs],
  });
}

export async function recoverExpiredJob(
  db: D1Database,
  input: Readonly<{
    jobId: string;
    expectedVersion: number;
    operationId: string;
    actor: string;
    nowMs: number;
  }>,
): Promise<MutationResult> {
  assertText(input.jobId, 160, "JOB_ID");
  assertText(input.operationId, 160, "OPERATION_ID");
  assertText(input.actor, 160, "ACTOR");
  assertTime(input.nowMs);
  if (!positiveVersion(input.expectedVersion)) throw new Error("INVALID_VERSION");
  const row = await loadJobRow(db, input.jobId);
  if (!row || row.version !== input.expectedVersion || row.lease_expires_at_ms === null ||
    row.lease_expires_at_ms > input.nowMs || (row.status !== "claimed" && row.status !== "running")) {
    return { kind: "noop", reason: "not_expired_or_stale", job: row ? jobRecord(row) : null, outboxCreated: false };
  }
  if (row.status === "running") {
    return applyTransition(db, {
      jobId: row.job_id, expectedVersion: row.version, operationId: input.operationId,
      fromStatus: "running", toStatus: "manual_review", eventType: "manual_review",
      actor: input.actor, reasonCode: "unknown_result_after_lease_expiry",
      evidenceRef: "runtime:lease_expired", nowMs: input.nowMs,
      updateSQL: `UPDATE background_jobs SET status='manual_review',version=version+1,
        error_code='unknown_result_after_lease_expiry',lease_owner=NULL,lease_token=NULL,
        delivery_id=NULL,lease_expires_at_ms=NULL,updated_at_ms=?,completed_at_ms=?
        WHERE job_id=? AND version=? AND status='running' AND lease_expires_at_ms<=?`,
      updateBindings: [input.nowMs, input.nowMs, row.job_id, row.version, input.nowMs],
    });
  }
  const exhausted = row.attempt_count >= row.max_attempts;
  const delay = exhausted ? 0 : retryDelayMs(row.attempt_count, row.base_delay_ms, row.max_delay_ms);
  if (!exhausted && input.nowMs + delay > MAX_TIME_MS) throw new Error("RETRY_TIME_EXHAUSTED");
  const toStatus: JobStatus = exhausted ? "dead_letter" : "retry_wait";
  return applyTransition(db, {
    jobId: row.job_id, expectedVersion: row.version, operationId: input.operationId,
    fromStatus: "claimed", toStatus,
    eventType: exhausted ? "dead_lettered" : "claim_recovered",
    actor: input.actor, reasonCode: "claim_lease_expired", nowMs: input.nowMs,
    updateSQL: `UPDATE background_jobs SET status=?,version=version+1,
      error_code='claim_lease_expired',available_at_ms=?,lease_owner=NULL,
      lease_token=NULL,delivery_id=NULL,lease_expires_at_ms=NULL,updated_at_ms=?,completed_at_ms=?
      WHERE job_id=? AND version=? AND status='claimed' AND lease_expires_at_ms<=?`,
    updateBindings: [toStatus, input.nowMs + delay, input.nowMs,
      exhausted ? input.nowMs : null, row.job_id, row.version, input.nowMs],
    outbox: exhausted ? undefined : { route: row.route, availableAtMs: input.nowMs + delay },
  });
}

export async function replayTerminalJob(
  db: D1Database,
  input: ReplayInput,
): Promise<MutationResult> {
  assertText(input.sourceJobId, 160, "SOURCE_JOB_ID");
  assertText(input.newJobId, 160, "JOB_ID");
  assertText(input.operationId, 160, "OPERATION_ID");
  assertText(input.replayKey, 160, "REPLAY_KEY");
  assertText(input.idempotencyKey, 192, "IDEMPOTENCY_KEY");
  assertText(input.actor, 160, "ACTOR");
  assertText(input.reasonCode, 96, "REASON_CODE");
  assertText(input.evidenceRef, 256, "EVIDENCE_REF");
  assertTime(input.nowMs);
  if (!positiveVersion(input.expectedSourceVersion) || ![
    "provider_idempotency", "provider_query_no_effect", "operator_confirmed_no_effect",
  ].includes(input.evidenceKind)) throw new Error("INVALID_REPLAY");
  const source = await loadJobRow(db, input.sourceJobId);
  if (!source || source.version !== input.expectedSourceVersion ||
    (source.status !== "dead_letter" && source.status !== "manual_review")) {
    return { kind: "noop", reason: "source_not_replayable_or_stale", job: null, outboxCreated: false };
  }
  const evidence = `${input.evidenceKind}:${input.evidenceRef}`;
  if (evidence.length > 256) throw new Error("INVALID_EVIDENCE_REF");
  const results = await db.batch([
    db.prepare(`INSERT OR IGNORE INTO background_jobs(
      job_id,route,job_type,idempotency_key,payload_codec,payload_body,payload_digest,
      status,version,attempt_count,max_attempts,base_delay_ms,max_delay_ms,
      available_at_ms,replay_of_job_id,replay_key,replay_actor,replay_reason_code,
      replay_evidence_ref,created_at_ms,updated_at_ms
    ) SELECT ?,route,job_type,?,payload_codec,payload_body,payload_digest,
      'queued',1,0,max_attempts,base_delay_ms,max_delay_ms,?,?,?,?,?,?,?,?
      FROM background_jobs
      WHERE job_id=? AND version=? AND status IN ('dead_letter','manual_review')`).bind(
      input.newJobId, input.idempotencyKey, input.nowMs, input.sourceJobId,
      input.replayKey, input.actor, input.reasonCode, evidence, input.nowMs,
      input.nowMs, input.sourceJobId, input.expectedSourceVersion,
    ),
    db.prepare(`INSERT INTO background_job_transitions(
      transition_id,job_id,event_type,from_status,to_status,from_version,to_version,
      actor,reason_code,evidence_ref,created_at_ms
    ) SELECT ?,?,'replayed',NULL,'queued',0,1,?,?,?,? WHERE changes()=1`).bind(
      input.operationId, input.newJobId, input.actor, input.reasonCode, evidence, input.nowMs,
    ),
    db.prepare(`INSERT INTO background_job_outbox(
      outbox_id,job_id,job_version,envelope_json,state,version,available_at_ms,created_at_ms
    ) SELECT ?,?,?,?,'pending',1,?,? WHERE changes()=1`).bind(
      crypto.randomUUID(), input.newJobId, 1,
      envelopeJSON(input.newJobId, source.route, 1), input.nowMs, input.nowMs,
    ),
  ]);
  const applied = verifyBatch(results, 3);
  const created = await loadJobRow(db, input.newJobId);
  const idempotent = created?.replay_of_job_id === input.sourceJobId &&
    created.replay_key === input.replayKey;
  return {
    kind: applied ? "applied" : idempotent ? "noop" : "conflict",
    reason: applied ? "replayed" : idempotent ? "idempotent_replay" : "replay_conflict",
    job: created ? jobRecord(created) : null,
    outboxCreated: applied,
  };
}

function outboxRecord(row: OutboxRow): OutboxRecord {
  let parsed: unknown;
  try { parsed = JSON.parse(row.envelope_json); } catch { throw new Error("CORRUPT_OUTBOX_ENVELOPE"); }
  const envelope = parseQueueEnvelope(parsed);
  if (!envelope || envelope.jobId !== row.job_id || envelope.jobVersion !== row.job_version) {
    throw new Error("CORRUPT_OUTBOX_ENVELOPE");
  }
  return {
    outboxId: row.outbox_id,
    jobId: row.job_id,
    jobVersion: row.job_version,
    envelope,
    state: row.state,
    version: row.version,
    availableAtMs: row.available_at_ms,
    publishOwner: row.publish_owner,
    publishLeaseExpiresAtMs: row.publish_lease_expires_at_ms,
  };
}

const OUTBOX_COLUMNS = `outbox_id,job_id,job_version,envelope_json,state,version,
  available_at_ms,publish_owner,publish_lease_expires_at_ms`;

export async function listDrainableOutbox(
  db: D1Database,
  nowMs: number,
  limit = 25,
): Promise<readonly OutboxRecord[]> {
  assertTime(nowMs);
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_BATCH) throw new Error("INVALID_LIMIT");
  const result = await db.prepare(`SELECT ${OUTBOX_COLUMNS} FROM background_job_outbox
    WHERE available_at_ms<=? AND (
      state='pending' OR (state='publishing' AND publish_lease_expires_at_ms<=?)
    ) ORDER BY available_at_ms,outbox_id LIMIT ?`).bind(nowMs, nowMs, limit).all<OutboxRow>();
  return result.results.map(outboxRecord);
}

export async function claimOutbox(
  db: D1Database,
  input: Readonly<{
    outboxId: string;
    expectedVersion: number;
    owner: string;
    nowMs: number;
    leaseMs: number;
  }>,
): Promise<OutboxRecord | null> {
  assertText(input.outboxId, 160, "OUTBOX_ID");
  assertText(input.owner, 160, "OWNER");
  assertTime(input.nowMs);
  if (!positiveVersion(input.expectedVersion) || !Number.isInteger(input.leaseMs) ||
    input.leaseMs < 1 || input.leaseMs > 86_400_000 ||
    input.nowMs + input.leaseMs > MAX_TIME_MS) throw new Error("INVALID_OUTBOX_CLAIM");
  const updated = await db.prepare(`UPDATE background_job_outbox
    SET state='publishing',version=version+1,publish_owner=?,publish_lease_expires_at_ms=?,last_error_code=NULL
    WHERE outbox_id=? AND version=? AND available_at_ms<=? AND (
      state='pending' OR (state='publishing' AND publish_lease_expires_at_ms<=?)
    )`).bind(input.owner, input.nowMs + input.leaseMs, input.outboxId,
      input.expectedVersion, input.nowMs, input.nowMs).run();
  if (changes(updated) !== 1) return null;
  const row = await db.prepare(`SELECT ${OUTBOX_COLUMNS} FROM background_job_outbox WHERE outbox_id=?`)
    .bind(input.outboxId).first<OutboxRow>();
  return row ? outboxRecord(row) : null;
}

export async function markOutboxPublished(
  db: D1Database,
  input: Readonly<{
    outboxId: string;
    expectedVersion: number;
    owner: string;
    nowMs: number;
  }>,
): Promise<boolean> {
  assertText(input.outboxId, 160, "OUTBOX_ID");
  assertText(input.owner, 160, "OWNER");
  assertTime(input.nowMs);
  if (!positiveVersion(input.expectedVersion)) throw new Error("INVALID_VERSION");
  const result = await db.prepare(`UPDATE background_job_outbox
    SET state='published',version=version+1,publish_owner=NULL,
      publish_lease_expires_at_ms=NULL,published_at_ms=?,last_error_code=NULL
    WHERE outbox_id=? AND version=? AND state='publishing' AND publish_owner=?`)
    .bind(input.nowMs, input.outboxId, input.expectedVersion, input.owner).run();
  return changes(result) === 1;
}

export async function releaseOutbox(
  db: D1Database,
  input: Readonly<{
    outboxId: string;
    expectedVersion: number;
    owner: string;
    availableAtMs: number;
    errorCode: string;
  }>,
): Promise<boolean> {
  assertText(input.outboxId, 160, "OUTBOX_ID");
  assertText(input.owner, 160, "OWNER");
  assertText(input.errorCode, 96, "ERROR_CODE");
  assertTime(input.availableAtMs);
  if (!positiveVersion(input.expectedVersion)) throw new Error("INVALID_VERSION");
  const result = await db.prepare(`UPDATE background_job_outbox
    SET state='pending',version=version+1,publish_owner=NULL,
      publish_lease_expires_at_ms=NULL,available_at_ms=?,last_error_code=?
    WHERE outbox_id=? AND version=? AND state='publishing' AND publish_owner=?`)
    .bind(input.availableAtMs, input.errorCode, input.outboxId,
      input.expectedVersion, input.owner).run();
  return changes(result) === 1;
}

export type OutboxPublisher = Readonly<{
  send(envelope: QueueEnvelope): Promise<void>;
}>;

export type DrainResult = Readonly<{
  outboxId: string;
  outcome: "published" | "publish_failed" | "published_unmarked" | "claim_lost";
}>;

export async function drainOutbox(
  db: D1Database,
  publisher: OutboxPublisher,
  input: Readonly<{
    owner: string;
    nowMs: number;
    leaseMs: number;
    failureDelayMs: number;
    limit?: number;
  }>,
): Promise<readonly DrainResult[]> {
  assertText(input.owner, 160, "OWNER");
  assertTime(input.nowMs);
  if (!Number.isInteger(input.failureDelayMs) || input.failureDelayMs < 0 ||
    input.nowMs + input.failureDelayMs > MAX_TIME_MS) throw new Error("INVALID_FAILURE_DELAY");
  const rows = await listDrainableOutbox(db, input.nowMs, input.limit ?? 25);
  const outcomes: DrainResult[] = [];
  for (const row of rows) {
    const claimed = await claimOutbox(db, {
      outboxId: row.outboxId, expectedVersion: row.version, owner: input.owner,
      nowMs: input.nowMs, leaseMs: input.leaseMs,
    });
    if (!claimed) {
      outcomes.push({ outboxId: row.outboxId, outcome: "claim_lost" });
      continue;
    }
    try {
      await publisher.send(claimed.envelope);
    } catch {
      await releaseOutbox(db, {
        outboxId: claimed.outboxId, expectedVersion: claimed.version,
        owner: input.owner, availableAtMs: input.nowMs + input.failureDelayMs,
        errorCode: "queue_publish_failed",
      });
      outcomes.push({ outboxId: claimed.outboxId, outcome: "publish_failed" });
      continue;
    }
    let marked = false;
    try {
      marked = await markOutboxPublished(db, {
        outboxId: claimed.outboxId, expectedVersion: claimed.version,
        owner: input.owner, nowMs: input.nowMs,
      });
    } catch {
      // Publish already succeeded. Let the durable publisher lease expire so
      // the same opaque envelope can be sent again safely.
    }
    outcomes.push({ outboxId: claimed.outboxId, outcome: marked ? "published" : "published_unmarked" });
  }
  return outcomes;
}

export type QueueMessageLike = Readonly<{
  id: string;
  body: unknown;
  ack(): void;
  retry(): void;
}>;

export type QueueMessageDecision = Readonly<{
  disposition: "ack" | "retry";
  reason: string;
}>;

export async function processQueueBatch(
  messages: readonly QueueMessageLike[],
  handler: (envelope: QueueEnvelope, messageId: string) => Promise<QueueMessageDecision>,
): Promise<readonly QueueMessageDecision[]> {
  const outcomes: QueueMessageDecision[] = [];
  for (const message of messages) {
    const envelope = parseQueueEnvelope(message.body);
    if (!envelope) {
      message.ack();
      outcomes.push({ disposition: "ack", reason: "invalid_envelope" });
      continue;
    }
    try {
      const decision = await handler(envelope, message.id);
      if (decision.disposition === "ack") message.ack();
      else message.retry();
      outcomes.push(decision);
    } catch {
      message.retry();
      outcomes.push({ disposition: "retry", reason: "handler_error" });
    }
  }
  return outcomes;
}
