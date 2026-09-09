/**
 * Pure, deterministic, persistence-neutral background-job state machine.
 *
 * All exported functions accept runtime-unknown values and fail closed. Time,
 * delivery identity, and jitter seed come from the caller. Payloads and results
 * contain opaque digests/references only.
 */

export const JOB_STATE_LIMITS = Object.freeze({
  maxNamespaceLength: 96,
  maxTypeLength: 96,
  maxIdempotencyKeyLength: 160,
  maxDigestLength: 160,
  maxReferenceLength: 512,
  maxOwnerLength: 160,
  maxDeliveryIdLength: 160,
  maxJitterSeedLength: 256,
  maxAuditFacts: 32,
  maxAttempts: 100,
  maxLeaseMs: 86_400_000,
  maxDelayMs: Number.MAX_SAFE_INTEGER,
} as const);

export type JobStatus =
  | "pending"
  | "leased"
  | "running"
  | "cancel_requested"
  | "retry_wait"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "dead_letter"
  | "manual_review";

export type TerminalStatus = Extract<
  JobStatus,
  "succeeded" | "failed" | "cancelled" | "dead_letter" | "manual_review"
>;

export type JobKey = Readonly<{
  namespace: string;
  type: string;
  idempotencyKey: string;
}>;

export type OpaquePayload = Readonly<{
  digest: string;
  reference?: string | null;
}>;

export type RetryPolicy = Readonly<{
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  /** Optional deterministic positive jitter, in basis points. */
  jitterBasisPoints?: number;
  /** Required when jitterBasisPoints is non-zero. */
  jitterSeed?: string;
}>;

export type Lease = Readonly<{
  owner: string;
  deliveryId: string;
  fence: number;
  acquiredAtMs: number;
  expiresAtMs: number;
}>;

export type FailureKind =
  | "never_started_retryable"
  | "started_known_failure"
  | "started_unknown_result";

export type Attempt = Readonly<{
  number: number;
  owner: string;
  deliveryId: string;
  fence: number;
  leasedAtMs: number;
  startedAtMs?: number;
  finishedAtMs?: number;
  failureKind?: FailureKind;
}>;

export type Result = Readonly<{
  digest: string;
  reference?: string | null;
}>;

export type AuditCode =
  | "submitted"
  | "leased"
  | "renewed"
  | "started"
  | "cancel_requested"
  | "succeeded"
  | "retry_scheduled"
  | "failed"
  | "cancelled"
  | "dead_lettered"
  | "manual_review";

export type AuditFact = Readonly<{
  atMs: number;
  code: AuditCode;
  fence?: number;
  attempt?: number;
}>;

export type Job = Readonly<{
  key: JobKey;
  payload: OpaquePayload;
  retryPolicy: RetryPolicy;
  status: JobStatus;
  createdAtMs: number;
  updatedAtMs: number;
  nextAttemptAtMs: number;
  attempts: readonly Attempt[];
  nextFence: number;
  lease?: Lease;
  result?: Result;
  audit: readonly AuditFact[];
}>;

export type Submission = Readonly<{
  key: JobKey;
  payload: OpaquePayload;
  retryPolicy: RetryPolicy;
  nowMs: number;
}>;

export type Authority = Readonly<{
  owner: string;
  deliveryId: string;
  fence: number;
}>;

export type AcquireInput = Readonly<{
  owner: string;
  deliveryId: string;
  nowMs: number;
  leaseMs: number;
}>;

export type RenewInput = Authority & Readonly<{ nowMs: number; leaseMs: number }>;
export type StartInput = Authority & Readonly<{ nowMs: number }>;
export type CompleteInput = Authority & Readonly<{ nowMs: number; result: Result }>;
export type FailInput = Authority &
  Readonly<{ nowMs: number; kind: FailureKind; retryable?: boolean }>;
export type CancelInput = Readonly<{ nowMs: number }>;
export type RecoverInput = Readonly<{ nowMs: number }>;

export type OutcomeCode =
  | "SUBMITTED"
  | "IDEMPOTENT_SUBMISSION"
  | "IDEMPOTENCY_CONFLICT"
  | "LEASE_ACQUIRED"
  | "LEASE_RENEWED"
  | "STARTED"
  | "SUCCEEDED"
  | "RETRY_SCHEDULED"
  | "FAILED"
  | "CANCELLED"
  | "CANCEL_REQUESTED"
  | "DEAD_LETTERED"
  | "MANUAL_REVIEW_REQUIRED"
  | "DUPLICATE_DELIVERY"
  | "DUPLICATE_COMPLETION"
  | "LEASE_HELD"
  | "NOT_READY"
  | "STALE_AUTHORITY"
  | "OUT_OF_ORDER_EVENT"
  | "LEASE_EXPIRED"
  | "FENCE_EXHAUSTED"
  | "TIME_EXHAUSTED"
  | "INVALID_INPUT"
  | "INVALID_JOB"
  | "INVALID_TRANSITION"
  | "TERMINAL_IMMUTABLE";

export type SubmissionOutcome = Readonly<{
  code: OutcomeCode;
  changed: boolean;
  job?: Job;
}>;

export type TransitionOutcome = Readonly<{
  code: OutcomeCode;
  changed: boolean;
  /** Omitted when the supplied persisted job is invalid. */
  job?: Job;
}>;

type UnknownRecord = Record<string, unknown>;

const JOB_KEYS = [
  "key",
  "payload",
  "retryPolicy",
  "status",
  "createdAtMs",
  "updatedAtMs",
  "nextAttemptAtMs",
  "attempts",
  "nextFence",
  "lease",
  "result",
  "audit",
] as const;
const TERMINAL_STATUSES = new Set<JobStatus>([
  "succeeded",
  "failed",
  "cancelled",
  "dead_letter",
  "manual_review",
]);
const JOB_STATUSES = new Set<JobStatus>([
  "pending",
  "leased",
  "running",
  "cancel_requested",
  "retry_wait",
  ...TERMINAL_STATUSES,
]);
const FAILURE_KINDS = new Set<FailureKind>([
  "never_started_retryable",
  "started_known_failure",
  "started_unknown_result",
]);
const AUDIT_CODES = new Set<AuditCode>([
  "submitted",
  "leased",
  "renewed",
  "started",
  "cancel_requested",
  "succeeded",
  "retry_scheduled",
  "failed",
  "cancelled",
  "dead_lettered",
  "manual_review",
]);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/u;
const ANY_WHITESPACE = /\s/u;
const UINT32_MAX = 0xffff_ffff;

const isPlainRecord = (value: unknown): value is UnknownRecord => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length > JOB_KEYS.length) return false;
  return keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && "value" in descriptor &&
      descriptor.enumerable;
  });
};

const hasOnlyKeys = (value: UnknownRecord, allowed: readonly string[]): boolean => {
  const allowedSet = new Set(allowed);
  const keys = Reflect.ownKeys(value);
  return keys.length <= allowed.length && keys.every((key) =>
    typeof key === "string" && allowedSet.has(key));
};

const hasOwn = (value: object, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(value, key);

const hasRequiredKeys = (
  value: UnknownRecord,
  required: readonly string[],
): boolean => required.every((key) => hasOwn(value, key));

const isSafeTime = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

const isPositiveSafeInteger = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value > 0;

const hasWellFormedUtf16 = (value: string): boolean => {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
};

const hasBoundedLength = (value: string, max: number): boolean =>
  value.length <= max && [...value].length <= max && hasWellFormedUtf16(value);

const isBoundedIdentifier = (value: unknown, max: number): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  hasBoundedLength(value, max) &&
  value.trim() === value &&
  !CONTROL_CHARACTERS.test(value) &&
  !ANY_WHITESPACE.test(value);

const isBoundedReference = (value: unknown, max: number): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  hasBoundedLength(value, max) &&
  value.trim() === value &&
  !CONTROL_CHARACTERS.test(value);

const isJobKey = (value: unknown): value is JobKey =>
  isPlainRecord(value) &&
  hasOnlyKeys(value, ["namespace", "type", "idempotencyKey"]) &&
  hasRequiredKeys(value, ["namespace", "type", "idempotencyKey"]) &&
  isBoundedIdentifier(value.namespace, JOB_STATE_LIMITS.maxNamespaceLength) &&
  isBoundedIdentifier(value.type, JOB_STATE_LIMITS.maxTypeLength) &&
  isBoundedIdentifier(
    value.idempotencyKey,
    JOB_STATE_LIMITS.maxIdempotencyKeyLength,
  );

const isOpaque = (value: unknown): value is OpaquePayload | Result =>
  isPlainRecord(value) &&
  hasOnlyKeys(value, ["digest", "reference"]) &&
  hasRequiredKeys(value, ["digest"]) &&
  isBoundedIdentifier(value.digest, JOB_STATE_LIMITS.maxDigestLength) &&
  (!hasOwn(value, "reference") ||
    value.reference === null ||
    isBoundedReference(value.reference, JOB_STATE_LIMITS.maxReferenceLength));

const isRetryPolicy = (value: unknown): value is RetryPolicy => {
  if (!isPlainRecord(value) ||
      !hasOnlyKeys(value, [
        "maxAttempts",
        "baseDelayMs",
        "maxDelayMs",
        "jitterBasisPoints",
        "jitterSeed",
      ]) ||
      !hasRequiredKeys(value, ["maxAttempts", "baseDelayMs", "maxDelayMs"])) {
    return false;
  }
  const hasJitter = hasOwn(value, "jitterBasisPoints");
  const hasSeed = hasOwn(value, "jitterSeed");
  const jitter = hasJitter ? value.jitterBasisPoints : 0;
  return (
    Number.isInteger(value.maxAttempts) &&
    Number(value.maxAttempts) >= 1 &&
    Number(value.maxAttempts) <= JOB_STATE_LIMITS.maxAttempts &&
    isSafeTime(value.baseDelayMs) &&
    isSafeTime(value.maxDelayMs) &&
    value.maxDelayMs <= JOB_STATE_LIMITS.maxDelayMs &&
    value.baseDelayMs <= value.maxDelayMs &&
    Number.isInteger(jitter) &&
    Number(jitter) >= 0 &&
    Number(jitter) <= 10_000 &&
    (!hasJitter || value.jitterBasisPoints !== undefined) &&
    (!hasSeed ||
      isBoundedIdentifier(
        value.jitterSeed,
        JOB_STATE_LIMITS.maxJitterSeedLength,
      )) &&
    (jitter === 0 ||
      hasSeed &&
      isBoundedIdentifier(
        value.jitterSeed,
        JOB_STATE_LIMITS.maxJitterSeedLength,
      ))
  );
};

const hasAuthorityFields = (value: UnknownRecord): boolean =>
  hasRequiredKeys(value, ["owner", "deliveryId", "fence"]) &&
  isBoundedIdentifier(value.owner, JOB_STATE_LIMITS.maxOwnerLength) &&
  isBoundedIdentifier(value.deliveryId, JOB_STATE_LIMITS.maxDeliveryIdLength) &&
  isPositiveSafeInteger(value.fence);

const isLease = (value: unknown): value is Lease =>
  isPlainRecord(value) &&
  hasOnlyKeys(value, [
    "owner",
    "deliveryId",
    "fence",
    "acquiredAtMs",
    "expiresAtMs",
  ]) &&
  hasRequiredKeys(value, [
    "owner",
    "deliveryId",
    "fence",
    "acquiredAtMs",
    "expiresAtMs",
  ]) &&
  hasAuthorityFields(value) &&
  isSafeTime(value.acquiredAtMs) &&
  isSafeTime(value.expiresAtMs) &&
  value.expiresAtMs > value.acquiredAtMs;

const isAttempt = (value: unknown): value is Attempt => {
  if (!isPlainRecord(value) ||
      !hasOnlyKeys(value, [
    "number",
    "owner",
    "deliveryId",
    "fence",
    "leasedAtMs",
    "startedAtMs",
    "finishedAtMs",
    "failureKind",
  ]) || !isPositiveSafeInteger(value.number) ||
      !hasRequiredKeys(value, [
        "number",
        "owner",
        "deliveryId",
        "fence",
        "leasedAtMs",
      ]) ||
      !hasAuthorityFields(value) || !isSafeTime(value.leasedAtMs) ||
      (hasOwn(value, "startedAtMs") && !isSafeTime(value.startedAtMs)) ||
      (hasOwn(value, "finishedAtMs") && !isSafeTime(value.finishedAtMs)) ||
      (hasOwn(value, "failureKind") &&
        !FAILURE_KINDS.has(value.failureKind as FailureKind))) {
    return false;
  }
  const startedAtMs = value.startedAtMs as number | undefined;
  const finishedAtMs = value.finishedAtMs as number | undefined;
  const failureKind = value.failureKind as FailureKind | undefined;
  return (
    (startedAtMs === undefined || startedAtMs >= value.leasedAtMs) &&
    (finishedAtMs === undefined || finishedAtMs >= value.leasedAtMs) &&
    (startedAtMs === undefined ||
      finishedAtMs === undefined ||
      finishedAtMs >= startedAtMs) &&
    (failureKind === undefined || finishedAtMs !== undefined) &&
    (failureKind !== "never_started_retryable" ||
      startedAtMs === undefined) &&
    (failureKind !== "started_known_failure" ||
      startedAtMs !== undefined) &&
    (failureKind !== "started_unknown_result" ||
      startedAtMs !== undefined)
  );
};

const isAuditFact = (value: unknown): value is AuditFact =>
  isPlainRecord(value) &&
  hasOnlyKeys(value, ["atMs", "code", "fence", "attempt"]) &&
  hasRequiredKeys(value, ["atMs", "code"]) &&
  isSafeTime(value.atMs) &&
  AUDIT_CODES.has(value.code as AuditCode) &&
  (!hasOwn(value, "fence") || isPositiveSafeInteger(value.fence)) &&
  (!hasOwn(value, "attempt") || isPositiveSafeInteger(value.attempt));

const isSubmission = (value: unknown): value is Submission =>
  isPlainRecord(value) &&
  hasOnlyKeys(value, ["key", "payload", "retryPolicy", "nowMs"]) &&
  hasRequiredKeys(value, ["key", "payload", "retryPolicy", "nowMs"]) &&
  isJobKey(value.key) &&
  isOpaque(value.payload) &&
  isRetryPolicy(value.retryPolicy) &&
  isSafeTime(value.nowMs);

const isAcquireInput = (value: unknown): value is AcquireInput =>
  isPlainRecord(value) &&
  hasOnlyKeys(value, ["owner", "deliveryId", "nowMs", "leaseMs"]) &&
  hasRequiredKeys(value, ["owner", "deliveryId", "nowMs", "leaseMs"]) &&
  isBoundedIdentifier(value.owner, JOB_STATE_LIMITS.maxOwnerLength) &&
  isBoundedIdentifier(value.deliveryId, JOB_STATE_LIMITS.maxDeliveryIdLength) &&
  isSafeTime(value.nowMs) &&
  isPositiveSafeInteger(value.leaseMs) &&
  value.leaseMs <= JOB_STATE_LIMITS.maxLeaseMs;

const isRenewInput = (value: unknown): value is RenewInput =>
  isPlainRecord(value) &&
  hasOnlyKeys(value, ["owner", "deliveryId", "fence", "nowMs", "leaseMs"]) &&
  hasRequiredKeys(value, [
    "owner",
    "deliveryId",
    "fence",
    "nowMs",
    "leaseMs",
  ]) &&
  hasAuthorityFields(value) &&
  isSafeTime(value.nowMs) &&
  isPositiveSafeInteger(value.leaseMs) &&
  value.leaseMs <= JOB_STATE_LIMITS.maxLeaseMs;

const isStartInput = (value: unknown): value is StartInput =>
  isPlainRecord(value) &&
  hasOnlyKeys(value, ["owner", "deliveryId", "fence", "nowMs"]) &&
  hasRequiredKeys(value, ["owner", "deliveryId", "fence", "nowMs"]) &&
  hasAuthorityFields(value) &&
  isSafeTime(value.nowMs);

const isCompleteInput = (value: unknown): value is CompleteInput =>
  isPlainRecord(value) &&
  hasOnlyKeys(value, ["owner", "deliveryId", "fence", "nowMs", "result"]) &&
  hasRequiredKeys(value, [
    "owner",
    "deliveryId",
    "fence",
    "nowMs",
    "result",
  ]) &&
  hasAuthorityFields(value) &&
  isSafeTime(value.nowMs) &&
  isOpaque(value.result);

const isFailInput = (value: unknown): value is FailInput => {
  if (!isPlainRecord(value) ||
      !hasOnlyKeys(value, [
        "owner",
        "deliveryId",
        "fence",
        "nowMs",
        "kind",
        "retryable",
      ]) ||
      !hasRequiredKeys(value, [
        "owner",
        "deliveryId",
        "fence",
        "nowMs",
        "kind",
      ]) ||
      !hasAuthorityFields(value) ||
      !isSafeTime(value.nowMs) ||
      !FAILURE_KINDS.has(value.kind as FailureKind)) {
    return false;
  }
  if (value.kind === "never_started_retryable") {
    return hasOwn(value, "retryable") && value.retryable === true;
  }
  if (value.kind === "started_known_failure") {
    return hasOwn(value, "retryable") && typeof value.retryable === "boolean";
  }
  return !hasOwn(value, "retryable");
};

const isTimeInput = (value: unknown): value is CancelInput | RecoverInput =>
  isPlainRecord(value) &&
  hasOnlyKeys(value, ["nowMs"]) &&
  hasRequiredKeys(value, ["nowMs"]) &&
  isSafeTime(value.nowMs);

const attemptIsFinishedRetry = (attempt: Attempt): boolean =>
  attempt.finishedAtMs !== undefined &&
  (attempt.failureKind === "never_started_retryable" ||
    attempt.failureKind === "started_known_failure");

const lastAuditMatchesStatus = (job: Job): boolean => {
  const last = job.audit[job.audit.length - 1];
  if (!last || last.atMs !== job.updatedAtMs) return false;
  const lastAttempt = job.attempts[job.attempts.length - 1];
  const matchesCurrentAuthority = lastAttempt !== undefined &&
    last.attempt === job.attempts.length &&
    last.fence === lastAttempt.fence;
  switch (job.status) {
    case "pending":
      return last.code === "submitted" &&
        last.attempt === undefined && last.fence === undefined;
    case "leased":
      return (last.code === "leased" || last.code === "renewed") &&
        matchesCurrentAuthority;
    case "running":
      return (last.code === "started" || last.code === "renewed") &&
        matchesCurrentAuthority;
    case "cancel_requested":
      return last.code === "cancel_requested" && matchesCurrentAuthority;
    case "retry_wait":
      return last.code === "retry_scheduled" && matchesCurrentAuthority;
    case "succeeded":
      return last.code === "succeeded" && matchesCurrentAuthority;
    case "failed":
      return last.code === "failed" && matchesCurrentAuthority;
    case "cancelled":
      return last.code === "cancelled" &&
        (lastAttempt === undefined
          ? last.attempt === undefined && last.fence === undefined
          : last.attempt === job.attempts.length &&
            (last.fence === undefined || last.fence === lastAttempt.fence));
    case "dead_letter":
      return last.code === "dead_lettered" && matchesCurrentAuthority;
    case "manual_review":
      return last.code === "manual_review" && matchesCurrentAuthority;
    default: return true;
  }
};

const hasValidStateInvariant = (job: Job): boolean => {
  const lastAttempt = job.attempts[job.attempts.length - 1];
  const hasLease = job.lease !== undefined;
  const hasResult = job.result !== undefined;
  switch (job.status) {
    case "pending":
      return job.attempts.length === 0 && !hasLease && !hasResult &&
        job.nextAttemptAtMs === job.createdAtMs;
    case "leased":
      return hasLease && !hasResult && lastAttempt !== undefined &&
        lastAttempt.startedAtMs === undefined &&
        lastAttempt.finishedAtMs === undefined &&
        lastAttempt.failureKind === undefined;
    case "running":
      return hasLease && !hasResult && lastAttempt?.startedAtMs !== undefined &&
        lastAttempt.finishedAtMs === undefined &&
        lastAttempt.failureKind === undefined;
    case "cancel_requested":
      return hasLease && !hasResult && lastAttempt?.startedAtMs !== undefined &&
        lastAttempt.finishedAtMs === undefined &&
        lastAttempt.failureKind === undefined;
    case "retry_wait":
      return !hasLease && !hasResult && lastAttempt !== undefined &&
        attemptIsFinishedRetry(lastAttempt) &&
        job.attempts.length < job.retryPolicy.maxAttempts &&
        job.nextAttemptAtMs >= job.updatedAtMs;
    case "succeeded":
      return !hasLease && hasResult && lastAttempt?.startedAtMs !== undefined &&
        lastAttempt.finishedAtMs !== undefined &&
        lastAttempt.failureKind === undefined;
    case "failed":
      return !hasLease && !hasResult &&
        lastAttempt?.failureKind === "started_known_failure" &&
        lastAttempt.finishedAtMs !== undefined;
    case "cancelled":
      return !hasLease && !hasResult &&
        (lastAttempt === undefined ||
          (lastAttempt.finishedAtMs !== undefined &&
            (lastAttempt.startedAtMs === undefined &&
                lastAttempt.failureKind === undefined ||
              attemptIsFinishedRetry(lastAttempt))));
    case "dead_letter":
      return !hasLease && !hasResult && lastAttempt !== undefined &&
        attemptIsFinishedRetry(lastAttempt) &&
        job.attempts.length === job.retryPolicy.maxAttempts;
    case "manual_review":
      return !hasLease && !hasResult &&
        lastAttempt?.failureKind === "started_unknown_result" &&
        lastAttempt.startedAtMs !== undefined &&
        lastAttempt.finishedAtMs !== undefined;
  }
};

const isJob = (value: unknown): value is Job => {
  if (!isPlainRecord(value) || !hasOnlyKeys(value, JOB_KEYS) ||
      !hasRequiredKeys(value, [
        "key",
        "payload",
        "retryPolicy",
        "status",
        "createdAtMs",
        "updatedAtMs",
        "nextAttemptAtMs",
        "attempts",
        "nextFence",
        "audit",
      ]) ||
      !isJobKey(value.key) || !isOpaque(value.payload) ||
      !isRetryPolicy(value.retryPolicy) ||
      !JOB_STATUSES.has(value.status as JobStatus) ||
      !isSafeTime(value.createdAtMs) || !isSafeTime(value.updatedAtMs) ||
      !isSafeTime(value.nextAttemptAtMs) ||
      !Array.isArray(value.attempts) || !Array.isArray(value.audit) ||
      !isPositiveSafeInteger(value.nextFence) ||
      value.updatedAtMs < value.createdAtMs ||
      value.attempts.length > value.retryPolicy.maxAttempts ||
      value.audit.length < 1 ||
      value.audit.length > JOB_STATE_LIMITS.maxAuditFacts ||
      (hasOwn(value, "lease") && !isLease(value.lease)) ||
      (hasOwn(value, "result") && !isOpaque(value.result))) {
    return false;
  }

  const job = value as unknown as Job;
  let previousFence = 0;
  let previousFinishedAt = job.createdAtMs;
  let previousAuditTime = job.createdAtMs;
  for (let index = 0; index < job.attempts.length; index += 1) {
    const attempt = job.attempts[index];
    if (!isAttempt(attempt) || attempt.number !== index + 1 ||
        attempt.fence <= previousFence || attempt.fence >= job.nextFence ||
        attempt.leasedAtMs < job.createdAtMs ||
        attempt.leasedAtMs < previousFinishedAt ||
        attempt.leasedAtMs > job.updatedAtMs ||
        (attempt.startedAtMs !== undefined &&
          attempt.startedAtMs > job.updatedAtMs) ||
        (attempt.finishedAtMs !== undefined &&
          attempt.finishedAtMs > job.updatedAtMs) ||
        (index < job.attempts.length - 1 &&
          !attemptIsFinishedRetry(attempt))) {
      return false;
    }
    previousFence = attempt.fence;
    previousFinishedAt = attempt.finishedAtMs ?? previousFinishedAt;
  }
  if (job.nextFence !== previousFence + 1) return false;

  for (const fact of job.audit) {
    if (!isAuditFact(fact) || fact.atMs < previousAuditTime ||
        fact.atMs > job.updatedAtMs ||
        (fact.attempt !== undefined && fact.attempt > job.attempts.length) ||
        (fact.fence !== undefined && fact.fence >= job.nextFence) ||
        (fact.fence !== undefined && fact.attempt === undefined) ||
        (fact.attempt !== undefined && fact.fence !== undefined &&
          job.attempts[fact.attempt - 1]?.fence !== fact.fence) ||
        (fact.code === "submitted" &&
          (fact.attempt !== undefined || fact.fence !== undefined)) ||
        (fact.code !== "submitted" && fact.code !== "cancelled" &&
          (fact.attempt === undefined || fact.fence === undefined))) {
      return false;
    }
    previousAuditTime = fact.atMs;
  }

  if (job.lease) {
    const attempt = job.attempts[job.attempts.length - 1];
    if (!attempt || job.lease.owner !== attempt.owner ||
        job.lease.deliveryId !== attempt.deliveryId ||
        job.lease.fence !== attempt.fence ||
        job.lease.acquiredAtMs !== attempt.leasedAtMs ||
        job.lease.acquiredAtMs > job.updatedAtMs ||
        job.lease.expiresAtMs <= job.updatedAtMs) {
      return false;
    }
  }
  return hasValidStateInvariant(job) && lastAuditMatchesStatus(job);
};

const safely = <T>(
  guard: (value: unknown) => value is T,
  value: unknown,
): T | undefined => {
  try {
    return guard(value) ? value : undefined;
  } catch {
    return undefined;
  }
};

const invalidJob = (): TransitionOutcome => ({
  code: "INVALID_JOB",
  changed: false,
});

const invalidInput = (job?: Job): TransitionOutcome => ({
  code: "INVALID_INPUT",
  changed: false,
  ...(job ? { job } : {}),
});

const sameKey = (left: JobKey, right: JobKey): boolean =>
  left.namespace === right.namespace &&
  left.type === right.type &&
  left.idempotencyKey === right.idempotencyKey;

const sameOptionalProperty = (
  left: object,
  right: object,
  key: string,
): boolean =>
  hasOwn(left, key) === hasOwn(right, key) &&
  (left as UnknownRecord)[key] === (right as UnknownRecord)[key];

const samePayload = (left: OpaquePayload, right: OpaquePayload): boolean =>
  left.digest === right.digest &&
  sameOptionalProperty(left, right, "reference");

const sameRetryPolicy = (left: RetryPolicy, right: RetryPolicy): boolean =>
  left.maxAttempts === right.maxAttempts &&
  left.baseDelayMs === right.baseDelayMs &&
  left.maxDelayMs === right.maxDelayMs &&
  sameOptionalProperty(left, right, "jitterBasisPoints") &&
  sameOptionalProperty(left, right, "jitterSeed");

const addCapped = (left: number, right: number): number =>
  left > Number.MAX_SAFE_INTEGER - right ? Number.MAX_SAFE_INTEGER : left + right;

const withAudit = (
  job: Job,
  atMs: number,
  code: AuditCode,
  fence?: number,
): Job => {
  const fact: AuditFact = {
    atMs,
    code,
    ...(fence === undefined ? {} : { fence }),
    ...(job.attempts.length === 0 ? {} : { attempt: job.attempts.length }),
  };
  return {
    ...job,
    updatedAtMs: atMs,
    audit: [...job.audit, fact].slice(-JOB_STATE_LIMITS.maxAuditFacts),
  };
};

const authorityMatches = (lease: Lease, input: Authority): boolean =>
  lease.owner === input.owner &&
  lease.deliveryId === input.deliveryId &&
  lease.fence === input.fence;

const completionAuthorityMatches = (job: Job, input: CompleteInput): boolean => {
  const attempt = job.attempts[job.attempts.length - 1];
  return attempt !== undefined &&
    attempt.owner === input.owner &&
    attempt.deliveryId === input.deliveryId &&
    attempt.fence === input.fence;
};

const outOfOrder = (
  job: Job,
  nowMs: number,
): TransitionOutcome | undefined =>
  nowMs < job.updatedAtMs
    ? { code: "OUT_OF_ORDER_EVENT", changed: false, job }
    : undefined;

const finishAttempt = (
  job: Job,
  atMs: number,
  failureKind?: FailureKind,
): readonly Attempt[] =>
  job.attempts.map((attempt, index) =>
    index === job.attempts.length - 1
      ? {
          ...attempt,
          finishedAtMs: atMs,
          ...(failureKind ? { failureKind } : {}),
        }
      : attempt,
  );

const withoutLease = (job: Job): Omit<Job, "lease"> => {
  const { lease: omittedLease, ...rest } = job;
  void omittedLease;
  return rest;
};

/** Creates a job or returns a stable idempotency outcome. */
function submitCore(
  existingValue: unknown,
  inputValue: unknown,
): SubmissionOutcome {
  const existing = existingValue === undefined
    ? undefined
    : safely(isJob, existingValue);
  if (existingValue !== undefined && !existing) {
    return { code: "INVALID_JOB", changed: false };
  }
  const input = safely(isSubmission, inputValue);
  if (!input) {
    return {
      code: "INVALID_INPUT",
      changed: false,
      ...(existing ? { job: existing } : {}),
    };
  }
  if (existing) {
    if (input.nowMs < existing.updatedAtMs) {
      return { code: "OUT_OF_ORDER_EVENT", changed: false, job: existing };
    }
    if (!sameKey(existing.key, input.key) ||
        !samePayload(existing.payload, input.payload) ||
        !sameRetryPolicy(existing.retryPolicy, input.retryPolicy)) {
      return { code: "IDEMPOTENCY_CONFLICT", changed: false, job: existing };
    }
    return { code: "IDEMPOTENT_SUBMISSION", changed: false, job: existing };
  }
  const job: Job = {
    key: { ...input.key },
    payload: { ...input.payload },
    retryPolicy: { ...input.retryPolicy },
    status: "pending",
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
    nextAttemptAtMs: input.nowMs,
    attempts: [],
    nextFence: 1,
    audit: [{ atMs: input.nowMs, code: "submitted" }],
  };
  return { code: "SUBMITTED", changed: true, job };
}

/** Deterministic capped exponential delay; undefined means malformed input. */
function retryDelayMsCore(
  policyValue: unknown,
  attemptNumberValue: unknown,
): number | undefined {
  const policy = safely(isRetryPolicy, policyValue);
  if (!policy || !isPositiveSafeInteger(attemptNumberValue) ||
      attemptNumberValue > policy.maxAttempts) {
    return undefined;
  }
  if (policy.baseDelayMs === 0) return 0;
  const exponent = attemptNumberValue - 1;
  const multiplier = exponent > 52 ? undefined : 2 ** exponent;
  const delay = multiplier === undefined ||
      policy.baseDelayMs > Math.floor(policy.maxDelayMs / multiplier)
    ? policy.maxDelayMs
    : policy.baseDelayMs * multiplier;
  const jitter = policy.jitterBasisPoints ?? 0;
  if (jitter === 0) return delay;
  const seed = hash32(`${policy.jitterSeed}:${attemptNumberValue}`);
  const span = Math.floor(delay / 10_000) * jitter +
    Math.floor(((delay % 10_000) * jitter) / 10_000);
  const offset = span === 0
    ? 0
    : span >= UINT32_MAX
      ? seed
      : seed % (span + 1);
  return Math.min(policy.maxDelayMs, addCapped(delay, offset));
}

function hash32(value: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash;
}

function acquireCore(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  const job = safely(isJob, jobValue);
  if (!job) return invalidJob();
  const input = safely(isAcquireInput, inputValue);
  if (!input) return invalidInput(job);
  const stale = outOfOrder(job, input.nowMs);
  if (stale) return stale;
  if (TERMINAL_STATUSES.has(job.status)) {
    return { code: "TERMINAL_IMMUTABLE", changed: false, job };
  }
  if (job.lease) {
    if (input.nowMs >= job.lease.expiresAtMs) {
      return { code: "LEASE_EXPIRED", changed: false, job };
    }
    if (job.lease.owner === input.owner &&
        job.lease.deliveryId === input.deliveryId) {
      return { code: "DUPLICATE_DELIVERY", changed: false, job };
    }
    return { code: "LEASE_HELD", changed: false, job };
  }
  if (job.status === "retry_wait" && input.nowMs < job.nextAttemptAtMs) {
    return { code: "NOT_READY", changed: false, job };
  }
  if (job.status !== "pending" && job.status !== "retry_wait") {
    return { code: "INVALID_TRANSITION", changed: false, job };
  }
  if (job.nextFence === Number.MAX_SAFE_INTEGER) {
    return { code: "FENCE_EXHAUSTED", changed: false, job };
  }
  if (input.nowMs > Number.MAX_SAFE_INTEGER - input.leaseMs) {
    return { code: "TIME_EXHAUSTED", changed: false, job };
  }
  const lease: Lease = {
    owner: input.owner,
    deliveryId: input.deliveryId,
    fence: job.nextFence,
    acquiredAtMs: input.nowMs,
    expiresAtMs: addCapped(input.nowMs, input.leaseMs),
  };
  const attempt: Attempt = {
    number: job.attempts.length + 1,
    owner: input.owner,
    deliveryId: input.deliveryId,
    fence: lease.fence,
    leasedAtMs: input.nowMs,
  };
  const next = withAudit({
    ...job,
    status: "leased",
    lease,
    attempts: [...job.attempts, attempt],
    nextFence: lease.fence + 1,
  }, input.nowMs, "leased", lease.fence);
  return { code: "LEASE_ACQUIRED", changed: true, job: next };
}

function renewCore(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  const job = safely(isJob, jobValue);
  if (!job) return invalidJob();
  const input = safely(isRenewInput, inputValue);
  if (!input) return invalidInput(job);
  const stale = outOfOrder(job, input.nowMs);
  if (stale) return stale;
  if (TERMINAL_STATUSES.has(job.status)) {
    return { code: "TERMINAL_IMMUTABLE", changed: false, job };
  }
  if (job.status === "cancel_requested") {
    return { code: "INVALID_TRANSITION", changed: false, job };
  }
  if (!job.lease || !authorityMatches(job.lease, input)) {
    return { code: "STALE_AUTHORITY", changed: false, job };
  }
  if (input.nowMs >= job.lease.expiresAtMs) {
    return { code: "LEASE_EXPIRED", changed: false, job };
  }
  if (input.nowMs > Number.MAX_SAFE_INTEGER - input.leaseMs) {
    return { code: "TIME_EXHAUSTED", changed: false, job };
  }
  const lease: Lease = {
    ...job.lease,
    expiresAtMs: Math.max(
      job.lease.expiresAtMs,
      addCapped(input.nowMs, input.leaseMs),
    ),
  };
  const next = withAudit({ ...job, lease }, input.nowMs, "renewed", lease.fence);
  return { code: "LEASE_RENEWED", changed: true, job: next };
}

function startCore(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  const job = safely(isJob, jobValue);
  if (!job) return invalidJob();
  const input = safely(isStartInput, inputValue);
  if (!input) return invalidInput(job);
  const stale = outOfOrder(job, input.nowMs);
  if (stale) return stale;
  if (TERMINAL_STATUSES.has(job.status)) {
    return { code: "TERMINAL_IMMUTABLE", changed: false, job };
  }
  if (!job.lease || !authorityMatches(job.lease, input)) {
    return { code: "STALE_AUTHORITY", changed: false, job };
  }
  if (input.nowMs >= job.lease.expiresAtMs) {
    return { code: "LEASE_EXPIRED", changed: false, job };
  }
  if (job.status === "running") {
    return { code: "DUPLICATE_DELIVERY", changed: false, job };
  }
  if (job.status !== "leased") {
    return { code: "INVALID_TRANSITION", changed: false, job };
  }
  const attempts = job.attempts.map((attempt, index) =>
    index === job.attempts.length - 1
      ? { ...attempt, startedAtMs: input.nowMs }
      : attempt,
  );
  const next = withAudit(
    { ...job, status: "running", attempts },
    input.nowMs,
    "started",
    input.fence,
  );
  return { code: "STARTED", changed: true, job: next };
}

function completeCore(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  const job = safely(isJob, jobValue);
  if (!job) return invalidJob();
  const input = safely(isCompleteInput, inputValue);
  if (!input) return invalidInput(job);
  const stale = outOfOrder(job, input.nowMs);
  if (stale) return stale;
  if (job.status === "succeeded" &&
      job.result?.digest === input.result.digest &&
      job.result.reference === input.result.reference) {
    return completionAuthorityMatches(job, input)
      ? { code: "DUPLICATE_COMPLETION", changed: false, job }
      : { code: "STALE_AUTHORITY", changed: false, job };
  }
  if (TERMINAL_STATUSES.has(job.status)) {
    return { code: "TERMINAL_IMMUTABLE", changed: false, job };
  }
  if (!job.lease || !authorityMatches(job.lease, input)) {
    return { code: "STALE_AUTHORITY", changed: false, job };
  }
  if (input.nowMs >= job.lease.expiresAtMs) {
    return { code: "LEASE_EXPIRED", changed: false, job };
  }
  if (job.status !== "running" && job.status !== "cancel_requested") {
    return { code: "INVALID_TRANSITION", changed: false, job };
  }
  const attempts = finishAttempt(job, input.nowMs);
  const next = withAudit({
    ...withoutLease(job),
    status: "succeeded",
    result: { ...input.result },
    attempts,
  }, input.nowMs, "succeeded", input.fence);
  return { code: "SUCCEEDED", changed: true, job: next };
}

function failCore(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  const job = safely(isJob, jobValue);
  if (!job) return invalidJob();
  const input = safely(isFailInput, inputValue);
  if (!input) return invalidInput(job);
  const stale = outOfOrder(job, input.nowMs);
  if (stale) return stale;
  if (TERMINAL_STATUSES.has(job.status)) {
    return { code: "TERMINAL_IMMUTABLE", changed: false, job };
  }
  if (!job.lease || !authorityMatches(job.lease, input)) {
    return { code: "STALE_AUTHORITY", changed: false, job };
  }
  if (input.nowMs >= job.lease.expiresAtMs) {
    return { code: "LEASE_EXPIRED", changed: false, job };
  }
  const started = job.status === "running" || job.status === "cancel_requested";
  if ((input.kind === "never_started_retryable" && started) ||
      (input.kind !== "never_started_retryable" && !started)) {
    return { code: "INVALID_TRANSITION", changed: false, job };
  }
  const attempts = finishAttempt(job, input.nowMs, input.kind);
  if (input.kind === "started_unknown_result") {
    const next = withAudit({
      ...withoutLease(job),
      status: "manual_review",
      attempts,
    }, input.nowMs, "manual_review", input.fence);
    return { code: "MANUAL_REVIEW_REQUIRED", changed: true, job: next };
  }
  if (job.status === "cancel_requested") {
    const next = withAudit({
      ...withoutLease(job),
      status: "cancelled",
      attempts,
    }, input.nowMs, "cancelled", input.fence);
    return { code: "CANCELLED", changed: true, job: next };
  }
  if (input.retryable && attempts.length < job.retryPolicy.maxAttempts) {
    const delay = retryDelayMsCore(job.retryPolicy, attempts.length);
    if (delay === undefined) return invalidJob();
    if (input.nowMs > Number.MAX_SAFE_INTEGER - delay) {
      return { code: "TIME_EXHAUSTED", changed: false, job };
    }
    const nextAttemptAtMs = addCapped(input.nowMs, delay);
    const next = withAudit({
      ...withoutLease(job),
      status: "retry_wait",
      attempts,
      nextAttemptAtMs,
    }, input.nowMs, "retry_scheduled", input.fence);
    return { code: "RETRY_SCHEDULED", changed: true, job: next };
  }
  const status: TerminalStatus = input.retryable ? "dead_letter" : "failed";
  const code: OutcomeCode = input.retryable ? "DEAD_LETTERED" : "FAILED";
  const next = withAudit({
    ...withoutLease(job),
    status,
    attempts,
  }, input.nowMs, input.retryable ? "dead_lettered" : "failed", input.fence);
  return { code, changed: true, job: next };
}

function cancelCore(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  const job = safely(isJob, jobValue);
  if (!job) return invalidJob();
  const input = safely(isTimeInput, inputValue);
  if (!input) return invalidInput(job);
  const stale = outOfOrder(job, input.nowMs);
  if (stale) return stale;
  if (TERMINAL_STATUSES.has(job.status)) {
    return { code: "TERMINAL_IMMUTABLE", changed: false, job };
  }
  if ((job.status === "running" || job.status === "cancel_requested") &&
      job.lease && input.nowMs >= job.lease.expiresAtMs) {
    const attempts = finishAttempt(
      job,
      input.nowMs,
      "started_unknown_result",
    );
    const next = withAudit({
      ...withoutLease(job),
      status: "manual_review",
      attempts,
    }, input.nowMs, "manual_review", job.lease.fence);
    return { code: "MANUAL_REVIEW_REQUIRED", changed: true, job: next };
  }
  if (job.status === "cancel_requested") {
    return { code: "CANCEL_REQUESTED", changed: false, job };
  }
  if (job.status === "running") {
    const next = withAudit(
      { ...job, status: "cancel_requested" },
      input.nowMs,
      "cancel_requested",
      job.lease?.fence,
    );
    return { code: "CANCEL_REQUESTED", changed: true, job: next };
  }
  const attempts = job.lease
    ? finishAttempt(job, input.nowMs)
    : job.attempts;
  const next = withAudit({
    ...withoutLease(job),
    status: "cancelled",
    attempts,
  }, input.nowMs, "cancelled");
  return { code: "CANCELLED", changed: true, job: next };
}

/** Recovers expiry without guessing whether already-started side effects ran. */
function recoverExpiredCore(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  const job = safely(isJob, jobValue);
  if (!job) return invalidJob();
  const input = safely(isTimeInput, inputValue);
  if (!input) return invalidInput(job);
  const stale = outOfOrder(job, input.nowMs);
  if (stale) return stale;
  if (TERMINAL_STATUSES.has(job.status)) {
    return { code: "TERMINAL_IMMUTABLE", changed: false, job };
  }
  if (!job.lease || input.nowMs < job.lease.expiresAtMs) {
    return { code: "INVALID_TRANSITION", changed: false, job };
  }
  if (job.status === "running" || job.status === "cancel_requested") {
    const attempts = finishAttempt(
      job,
      input.nowMs,
      "started_unknown_result",
    );
    const next = withAudit({
      ...withoutLease(job),
      status: "manual_review",
      attempts,
    }, input.nowMs, "manual_review", job.lease.fence);
    return { code: "MANUAL_REVIEW_REQUIRED", changed: true, job: next };
  }
  if (job.status !== "leased") {
    return { code: "INVALID_TRANSITION", changed: false, job };
  }
  const attempts = finishAttempt(
    job,
    input.nowMs,
    "never_started_retryable",
  );
  if (attempts.length >= job.retryPolicy.maxAttempts) {
    const next = withAudit({
      ...withoutLease(job),
      status: "dead_letter",
      attempts,
    }, input.nowMs, "dead_lettered", job.lease.fence);
    return { code: "DEAD_LETTERED", changed: true, job: next };
  }
  const delay = retryDelayMsCore(job.retryPolicy, attempts.length);
  if (delay === undefined) return invalidJob();
  if (input.nowMs > Number.MAX_SAFE_INTEGER - delay) {
    return { code: "TIME_EXHAUSTED", changed: false, job };
  }
  const nextAttemptAtMs = addCapped(input.nowMs, delay);
  const next = withAudit({
    ...withoutLease(job),
    status: "retry_wait",
    attempts,
    nextAttemptAtMs,
  }, input.nowMs, "retry_scheduled", job.lease.fence);
  return { code: "RETRY_SCHEDULED", changed: true, job: next };
}

/** Creates a job or returns a stable idempotency outcome without throwing. */
export function submit(
  existingValue: unknown,
  inputValue: unknown,
): SubmissionOutcome {
  try {
    return submitCore(existingValue, inputValue);
  } catch {
    return {
      code: existingValue === undefined ? "INVALID_INPUT" : "INVALID_JOB",
      changed: false,
    };
  }
}

/** Deterministic capped exponential delay; undefined means malformed input. */
export function retryDelayMs(
  policyValue: unknown,
  attemptNumberValue: unknown,
): number | undefined {
  try {
    return retryDelayMsCore(policyValue, attemptNumberValue);
  } catch {
    return undefined;
  }
}

export function acquire(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  try {
    return acquireCore(jobValue, inputValue);
  } catch {
    return invalidJob();
  }
}

export function renew(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  try {
    return renewCore(jobValue, inputValue);
  } catch {
    return invalidJob();
  }
}

export function start(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  try {
    return startCore(jobValue, inputValue);
  } catch {
    return invalidJob();
  }
}

export function complete(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  try {
    return completeCore(jobValue, inputValue);
  } catch {
    return invalidJob();
  }
}

export function fail(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  try {
    return failCore(jobValue, inputValue);
  } catch {
    return invalidJob();
  }
}

export function cancel(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  try {
    return cancelCore(jobValue, inputValue);
  } catch {
    return invalidJob();
  }
}

export function recoverExpired(
  jobValue: unknown,
  inputValue: unknown,
): TransitionOutcome {
  try {
    return recoverExpiredCore(jobValue, inputValue);
  } catch {
    return invalidJob();
  }
}
