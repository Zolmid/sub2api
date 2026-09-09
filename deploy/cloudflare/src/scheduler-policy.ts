/**
 * A pure, deterministic account-selection policy. It intentionally has no
 * bindings, storage access, clock access, or credential-bearing fields.
 */

export type Evidence<T> =
  | { kind: "confirmed"; value: T }
  | { kind: "estimated"; value: T }
  | { kind: "unknown" };

export type SchedulerCapability = Readonly<{
  platforms: readonly string[];
  accountTypes: readonly string[];
  models: readonly string[];
}>;

export type SchedulerAccount = Readonly<{
  /** Canonical positive decimal ID only; names and credentials are excluded. */
  accountId: string;
  /** Stable non-secret row/key identity used only after accountId tie-breaking. */
  stableId: string;
  priority: number;
  active: Evidence<boolean>;
  schedulable: Evidence<boolean>;
  groups: Evidence<readonly string[]>;
  capabilities: Evidence<SchedulerCapability>;
  accountConcurrencyLimit: Evidence<number>;
  accountConcurrencyInFlight: Evidence<number>;
  accountRpmLimit: Evidence<number>;
  accountRpmUsed: Evidence<number>;
  userRpmLimit: Evidence<number>;
  userRpmUsed: Evidence<number>;
  /** Confirmed or estimated exhaustion excludes the account. Unknown does not mean zero. */
  quotaExhausted: Evidence<boolean>;
  /** A 0..1 remaining-quota estimate; unknown contributes zero ranking points. */
  quotaRemainingRatio: Evidence<number>;
  /** null means no deadline is known to be active. Future deadlines exclude the account. */
  temporarilyUnschedulableUntilMs: Evidence<number | null>;
  cooldownUntilMs: Evidence<number | null>;
  /** A 0..1 health observation; unknown contributes zero ranking points. */
  healthRatio: Evidence<number>;
}>;

export type SchedulerRequest = Readonly<{
  nowMs: number;
  requiredGroup: string;
  platform: string;
  accountType: string;
  model: string;
  /** Optional caller-owned affinity key. It is never persisted by this module. */
  stickinessKey?: string;
  accounts: readonly SchedulerAccount[];
}>;

export type RejectionCode =
  | "INVALID_REQUEST"
  | "DUPLICATE_ACCOUNT_ID"
  | "INVALID_ACCOUNT"
  | "INVALID_ACCOUNT_ID"
  | "INVALID_STABLE_ID"
  | "INVALID_PRIORITY"
  | "INVALID_EVIDENCE"
  | "ACTIVE_FALSE"
  | "ACTIVE_UNCONFIRMED"
  | "ACTIVE_UNKNOWN"
  | "SCHEDULABLE_FALSE"
  | "SCHEDULABLE_UNCONFIRMED"
  | "SCHEDULABLE_UNKNOWN"
  | "INVALID_GROUPS"
  | "GROUP_UNCONFIRMED"
  | "GROUP_UNKNOWN"
  | "GROUP_MISMATCH"
  | "INVALID_CAPABILITIES"
  | "CAPABILITY_UNCONFIRMED"
  | "CAPABILITY_UNKNOWN"
  | "PLATFORM_UNSUPPORTED"
  | "ACCOUNT_TYPE_UNSUPPORTED"
  | "MODEL_UNSUPPORTED"
  | "INVALID_CAPACITY_METRIC"
  | "ACCOUNT_CONCURRENCY_UNCONFIRMED"
  | "ACCOUNT_CONCURRENCY_UNKNOWN"
  | "ACCOUNT_CONCURRENCY_EXHAUSTED"
  | "ACCOUNT_RPM_UNCONFIRMED"
  | "ACCOUNT_RPM_UNKNOWN"
  | "ACCOUNT_RPM_EXHAUSTED"
  | "USER_RPM_UNCONFIRMED"
  | "USER_RPM_UNKNOWN"
  | "USER_RPM_EXHAUSTED"
  | "INVALID_QUOTA_EXHAUSTED"
  | "QUOTA_EXHAUSTED_CONFIRMED"
  | "QUOTA_EXHAUSTED_ESTIMATED"
  | "INVALID_QUOTA_METRIC"
  | "TEMPORARILY_UNSCHEDULABLE"
  | "COOLDOWN_ACTIVE"
  | "INVALID_DEADLINE"
  | "INVALID_HEALTH_METRIC";

type EvidenceKind = Evidence<unknown>["kind"];

export type EvidenceFlags = Readonly<{
  health: EvidenceKind;
  quotaRemaining: EvidenceKind;
  quotaExhaustion: EvidenceKind;
  cooldown: EvidenceKind;
  temporaryUnschedulable: EvidenceKind;
  accountConcurrency: "confirmed";
  accountRpm: "confirmed";
  userRpm: "confirmed";
}>;

export type ScoreComponents = Readonly<{
  priority: number;
  health: number;
  load: number;
  quota: number;
  cooldownReadiness: number;
  total: number;
}>;

export type EligibleCandidate = Readonly<{
  accountId: string;
  stableId: string;
  score: ScoreComponents;
  evidence: EvidenceFlags;
}>;

export type RejectedCandidate = Readonly<{
  accountId: string | null;
  stableId: string | null;
  reason: RejectionCode;
}>;

export type SchedulerDecision = Readonly<{
  selectedAccountId: string | null;
  eligible: readonly EligibleCandidate[];
  rejected: readonly RejectedCandidate[];
  requestErrors: readonly RejectionCode[];
  selection: "top" | "sticky" | "none";
}>;

const MAX_ACCOUNTS = 256;
const MAX_LIST_ENTRIES = 64;
const MAX_PRIORITY = 1_000_000;
const MAX_CAPACITY = 1_000_000;
const MAX_ACCOUNT_ID_LENGTH = 19;
const MAX_SELECTOR_LENGTH = 128;
const MAX_STABLE_ID_LENGTH = 128;
const MAX_STICKINESS_KEY_LENGTH = 256;
const MAX_TIMESTAMP_MS = 4_102_444_800_000;
const PRIORITY_WEIGHT = 1_000_000;
const HEALTH_WEIGHT = 20;
const LOAD_WEIGHT = 10;
const QUOTA_WEIGHT = 5;
const COOLDOWN_READINESS_WEIGHT = 2;
const STICKY_TOLERANCE_POINTS = 50_000;
const ID_PATTERN = /^[1-9][0-9]*$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;

type UnknownRecord = Record<string, unknown>;

type ParsedEvidence =
  | { valid: true; kind: "unknown" }
  | { valid: true; kind: "confirmed" | "estimated"; value: unknown }
  | { valid: false };

type ValidatedRequest = Readonly<{
  nowMs: number;
  requiredGroup: string;
  platform: string;
  accountType: string;
  model: string;
  stickinessKey?: string;
  accounts: readonly unknown[];
}>;

type NormalizedAccount = Readonly<{
  accountId: string;
  stableId: string;
  priority: number;
  concurrencyLimit: number;
  concurrencyInFlight: number;
  healthBps: number;
  quotaBps: number;
  healthEvidence: EvidenceKind;
  quotaRemainingEvidence: EvidenceKind;
  quotaExhaustionEvidence: EvidenceKind;
  cooldownEvidence: EvidenceKind;
  temporaryUnschedulableEvidence: EvidenceKind;
}>;

type AccountEvaluation =
  | { eligible: true; account: NormalizedAccount }
  | { eligible: false; rejected: RejectedCandidate };

function emptyDecision(requestError?: RejectionCode): SchedulerDecision {
  return {
    selectedAccountId: null,
    eligible: [],
    rejected: [],
    requestErrors: requestError === undefined ? [] : [requestError],
    selection: "none",
  };
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeText(value: unknown, maximumLength: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximumLength &&
    value.trim() === value &&
    !CONTROL_CHARACTER_PATTERN.test(value)
  );
}

function isCanonicalAccountId(value: unknown): value is string {
  return isSafeText(value, MAX_ACCOUNT_ID_LENGTH) && ID_PATTERN.test(value);
}

function isFiniteIntegerInRange(
  value: unknown,
  minimum: number,
  maximum: number,
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function metricToBasisPoints(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    return null;
  }
  const result = Math.round(value * 10_000);
  return Number.isSafeInteger(result) ? result : null;
}

function parseEvidence(value: unknown): ParsedEvidence {
  if (!isRecord(value)) return { valid: false };
  if (value.kind === "unknown") {
    return Object.hasOwn(value, "value")
      ? { valid: false }
      : { valid: true, kind: "unknown" };
  }
  if (value.kind !== "confirmed" && value.kind !== "estimated") {
    return { valid: false };
  }
  if (!Object.hasOwn(value, "value")) return { valid: false };
  return { valid: true, kind: value.kind, value: value.value };
}

function validateStringList(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || value.length > MAX_LIST_ENTRIES) return null;
  const unique = new Set<string>();
  const result: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) return null;
    const entry = value[index];
    if (!isSafeText(entry, MAX_SELECTOR_LENGTH) || unique.has(entry)) return null;
    unique.add(entry);
    result.push(entry);
  }
  return result;
}

function validateCapabilities(value: unknown): SchedulerCapability | null {
  if (!isRecord(value)) return null;
  const platforms = validateStringList(value.platforms);
  const accountTypes = validateStringList(value.accountTypes);
  const models = validateStringList(value.models);
  if (platforms === null || accountTypes === null || models === null) return null;
  return { platforms, accountTypes, models };
}

function validateRequest(value: unknown): ValidatedRequest | null {
  if (!isRecord(value)) return null;
  if (!isFiniteIntegerInRange(value.nowMs, 0, MAX_TIMESTAMP_MS)) return null;
  if (!isSafeText(value.requiredGroup, MAX_SELECTOR_LENGTH)) return null;
  if (!isSafeText(value.platform, MAX_SELECTOR_LENGTH)) return null;
  if (!isSafeText(value.accountType, MAX_SELECTOR_LENGTH)) return null;
  if (!isSafeText(value.model, MAX_SELECTOR_LENGTH)) return null;
  if (
    value.stickinessKey !== undefined &&
    !isSafeText(value.stickinessKey, MAX_STICKINESS_KEY_LENGTH)
  ) {
    return null;
  }
  if (!Array.isArray(value.accounts) || value.accounts.length > MAX_ACCOUNTS) return null;
  return {
    nowMs: value.nowMs,
    requiredGroup: value.requiredGroup,
    platform: value.platform,
    accountType: value.accountType,
    model: value.model,
    ...(value.stickinessKey === undefined ? {} : { stickinessKey: value.stickinessKey }),
    accounts: value.accounts,
  };
}

function compareBytewise(left: string, right: string): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = left.charCodeAt(index) - right.charCodeAt(index);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

/** FNV-1a with Math.imul is deterministic in Workers, browsers, and Node. */
function hash32(value: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function rejectedCandidate(value: unknown, reason: RejectionCode): RejectedCandidate {
  if (!isRecord(value)) return { accountId: null, stableId: null, reason };
  return {
    accountId: isCanonicalAccountId(value.accountId) ? value.accountId : null,
    stableId: isSafeText(value.stableId, MAX_STABLE_ID_LENGTH) ? value.stableId : null,
    reason,
  };
}

function booleanGate(
  value: unknown,
  falseCode: RejectionCode,
  estimatedCode: RejectionCode,
  unknownCode: RejectionCode,
): RejectionCode | null {
  const evidence = parseEvidence(value);
  if (!evidence.valid) return "INVALID_EVIDENCE";
  if (evidence.kind === "unknown") return unknownCode;
  if (typeof evidence.value !== "boolean") return "INVALID_EVIDENCE";
  if (!evidence.value) return falseCode;
  return evidence.kind === "confirmed" ? null : estimatedCode;
}

function confirmedCapacity(
  value: unknown,
  unconfirmedCode: RejectionCode,
  unknownCode: RejectionCode,
): number | RejectionCode {
  const evidence = parseEvidence(value);
  if (!evidence.valid) return "INVALID_CAPACITY_METRIC";
  if (evidence.kind === "unknown") return unknownCode;
  if (!isFiniteIntegerInRange(evidence.value, 0, MAX_CAPACITY)) {
    return "INVALID_CAPACITY_METRIC";
  }
  if (evidence.kind !== "confirmed") return unconfirmedCode;
  return evidence.value;
}

function capacityPair(
  limitValue: unknown,
  usedValue: unknown,
  unconfirmedCode: RejectionCode,
  unknownCode: RejectionCode,
  exhaustedCode: RejectionCode,
): { limit: number; used: number } | RejectionCode {
  const limit = confirmedCapacity(limitValue, unconfirmedCode, unknownCode);
  if (typeof limit === "string") return limit;
  const used = confirmedCapacity(usedValue, unconfirmedCode, unknownCode);
  if (typeof used === "string") return used;
  return used < limit ? { limit, used } : exhaustedCode;
}

function rankedMetric(
  value: unknown,
  invalidCode: RejectionCode,
): { kind: EvidenceKind; basisPoints: number } | RejectionCode {
  const evidence = parseEvidence(value);
  if (!evidence.valid) return invalidCode;
  if (evidence.kind === "unknown") return { kind: "unknown", basisPoints: 0 };
  const basisPoints = metricToBasisPoints(evidence.value);
  return basisPoints === null ? invalidCode : { kind: evidence.kind, basisPoints };
}

function deadline(
  value: unknown,
  nowMs: number,
  activeCode: RejectionCode,
): { kind: EvidenceKind } | RejectionCode {
  const evidence = parseEvidence(value);
  if (!evidence.valid) return "INVALID_DEADLINE";
  if (evidence.kind === "unknown") return { kind: "unknown" };
  if (
    evidence.value !== null &&
    !isFiniteIntegerInRange(evidence.value, 0, MAX_TIMESTAMP_MS)
  ) {
    return "INVALID_DEADLINE";
  }
  if (evidence.value !== null && evidence.value > nowMs) return activeCode;
  return { kind: evidence.kind };
}

function evaluateAccount(value: unknown, request: ValidatedRequest): AccountEvaluation {
  if (!isRecord(value)) {
    return { eligible: false, rejected: rejectedCandidate(value, "INVALID_ACCOUNT") };
  }
  if (!isCanonicalAccountId(value.accountId)) {
    return { eligible: false, rejected: rejectedCandidate(value, "INVALID_ACCOUNT_ID") };
  }
  if (!isSafeText(value.stableId, MAX_STABLE_ID_LENGTH)) {
    return { eligible: false, rejected: rejectedCandidate(value, "INVALID_STABLE_ID") };
  }
  if (!isFiniteIntegerInRange(value.priority, 0, MAX_PRIORITY)) {
    return { eligible: false, rejected: rejectedCandidate(value, "INVALID_PRIORITY") };
  }

  const active = booleanGate(
    value.active,
    "ACTIVE_FALSE",
    "ACTIVE_UNCONFIRMED",
    "ACTIVE_UNKNOWN",
  );
  if (active !== null) {
    return { eligible: false, rejected: rejectedCandidate(value, active) };
  }
  const schedulable = booleanGate(
    value.schedulable,
    "SCHEDULABLE_FALSE",
    "SCHEDULABLE_UNCONFIRMED",
    "SCHEDULABLE_UNKNOWN",
  );
  if (schedulable !== null) {
    return { eligible: false, rejected: rejectedCandidate(value, schedulable) };
  }

  const groupsEvidence = parseEvidence(value.groups);
  if (!groupsEvidence.valid) {
    return { eligible: false, rejected: rejectedCandidate(value, "INVALID_GROUPS") };
  }
  if (groupsEvidence.kind === "unknown") {
    return { eligible: false, rejected: rejectedCandidate(value, "GROUP_UNKNOWN") };
  }
  const groups = validateStringList(groupsEvidence.value);
  if (groups === null) {
    return { eligible: false, rejected: rejectedCandidate(value, "INVALID_GROUPS") };
  }
  if (groupsEvidence.kind !== "confirmed") {
    return { eligible: false, rejected: rejectedCandidate(value, "GROUP_UNCONFIRMED") };
  }
  if (!groups.includes(request.requiredGroup)) {
    return { eligible: false, rejected: rejectedCandidate(value, "GROUP_MISMATCH") };
  }

  const capabilityEvidence = parseEvidence(value.capabilities);
  if (!capabilityEvidence.valid) {
    return { eligible: false, rejected: rejectedCandidate(value, "INVALID_CAPABILITIES") };
  }
  if (capabilityEvidence.kind === "unknown") {
    return { eligible: false, rejected: rejectedCandidate(value, "CAPABILITY_UNKNOWN") };
  }
  const capabilities = validateCapabilities(capabilityEvidence.value);
  if (capabilities === null) {
    return { eligible: false, rejected: rejectedCandidate(value, "INVALID_CAPABILITIES") };
  }
  if (capabilityEvidence.kind !== "confirmed") {
    return { eligible: false, rejected: rejectedCandidate(value, "CAPABILITY_UNCONFIRMED") };
  }
  if (!capabilities.platforms.includes(request.platform)) {
    return { eligible: false, rejected: rejectedCandidate(value, "PLATFORM_UNSUPPORTED") };
  }
  if (!capabilities.accountTypes.includes(request.accountType)) {
    return { eligible: false, rejected: rejectedCandidate(value, "ACCOUNT_TYPE_UNSUPPORTED") };
  }
  if (!capabilities.models.includes(request.model)) {
    return { eligible: false, rejected: rejectedCandidate(value, "MODEL_UNSUPPORTED") };
  }

  const concurrency = capacityPair(
    value.accountConcurrencyLimit,
    value.accountConcurrencyInFlight,
    "ACCOUNT_CONCURRENCY_UNCONFIRMED",
    "ACCOUNT_CONCURRENCY_UNKNOWN",
    "ACCOUNT_CONCURRENCY_EXHAUSTED",
  );
  if (typeof concurrency === "string") {
    return { eligible: false, rejected: rejectedCandidate(value, concurrency) };
  }
  const accountRpm = capacityPair(
    value.accountRpmLimit,
    value.accountRpmUsed,
    "ACCOUNT_RPM_UNCONFIRMED",
    "ACCOUNT_RPM_UNKNOWN",
    "ACCOUNT_RPM_EXHAUSTED",
  );
  if (typeof accountRpm === "string") {
    return { eligible: false, rejected: rejectedCandidate(value, accountRpm) };
  }
  const userRpm = capacityPair(
    value.userRpmLimit,
    value.userRpmUsed,
    "USER_RPM_UNCONFIRMED",
    "USER_RPM_UNKNOWN",
    "USER_RPM_EXHAUSTED",
  );
  if (typeof userRpm === "string") {
    return { eligible: false, rejected: rejectedCandidate(value, userRpm) };
  }

  const quotaExhausted = parseEvidence(value.quotaExhausted);
  if (
    !quotaExhausted.valid ||
    (quotaExhausted.kind !== "unknown" && typeof quotaExhausted.value !== "boolean")
  ) {
    return {
      eligible: false,
      rejected: rejectedCandidate(value, "INVALID_QUOTA_EXHAUSTED"),
    };
  }
  if (quotaExhausted.kind === "confirmed" && quotaExhausted.value) {
    return {
      eligible: false,
      rejected: rejectedCandidate(value, "QUOTA_EXHAUSTED_CONFIRMED"),
    };
  }
  if (quotaExhausted.kind === "estimated" && quotaExhausted.value) {
    return {
      eligible: false,
      rejected: rejectedCandidate(value, "QUOTA_EXHAUSTED_ESTIMATED"),
    };
  }

  const quota = rankedMetric(value.quotaRemainingRatio, "INVALID_QUOTA_METRIC");
  if (typeof quota === "string") {
    return { eligible: false, rejected: rejectedCandidate(value, quota) };
  }
  const health = rankedMetric(value.healthRatio, "INVALID_HEALTH_METRIC");
  if (typeof health === "string") {
    return { eligible: false, rejected: rejectedCandidate(value, health) };
  }

  const temporary = deadline(
    value.temporarilyUnschedulableUntilMs,
    request.nowMs,
    "TEMPORARILY_UNSCHEDULABLE",
  );
  if (typeof temporary === "string") {
    return { eligible: false, rejected: rejectedCandidate(value, temporary) };
  }
  const cooldown = deadline(value.cooldownUntilMs, request.nowMs, "COOLDOWN_ACTIVE");
  if (typeof cooldown === "string") {
    return { eligible: false, rejected: rejectedCandidate(value, cooldown) };
  }

  return {
    eligible: true,
    account: {
      accountId: value.accountId,
      stableId: value.stableId,
      priority: value.priority,
      concurrencyLimit: concurrency.limit,
      concurrencyInFlight: concurrency.used,
      healthBps: health.basisPoints,
      quotaBps: quota.basisPoints,
      healthEvidence: health.kind,
      quotaRemainingEvidence: quota.kind,
      quotaExhaustionEvidence: quotaExhausted.kind,
      cooldownEvidence: cooldown.kind,
      temporaryUnschedulableEvidence: temporary.kind,
    },
  };
}

function score(account: NormalizedAccount): EligibleCandidate {
  const loadBps = Math.floor(
    (account.concurrencyInFlight * 10_000) / account.concurrencyLimit,
  );
  const readinessBps =
    account.cooldownEvidence === "confirmed"
      ? 10_000
      : account.cooldownEvidence === "estimated"
        ? 5_000
        : 0;
  // Traditional Sub2API treats lower numeric priority as better.
  const priority = (MAX_PRIORITY - account.priority) * PRIORITY_WEIGHT;
  const health = account.healthBps * HEALTH_WEIGHT;
  const load = (10_000 - loadBps) * LOAD_WEIGHT;
  const quota = account.quotaBps * QUOTA_WEIGHT;
  const cooldownReadiness = readinessBps * COOLDOWN_READINESS_WEIGHT;
  const components: ScoreComponents = {
    priority,
    health,
    load,
    quota,
    cooldownReadiness,
    total: priority + health + load + quota + cooldownReadiness,
  };
  return {
    accountId: account.accountId,
    stableId: account.stableId,
    score: components,
    evidence: {
      health: account.healthEvidence,
      quotaRemaining: account.quotaRemainingEvidence,
      quotaExhaustion: account.quotaExhaustionEvidence,
      cooldown: account.cooldownEvidence,
      temporaryUnschedulable: account.temporaryUnschedulableEvidence,
      accountConcurrency: "confirmed",
      accountRpm: "confirmed",
      userRpm: "confirmed",
    },
  };
}

function rankedCompare(left: EligibleCandidate, right: EligibleCandidate): number {
  if (left.score.total !== right.score.total) return right.score.total - left.score.total;
  const accountIdOrder = compareBytewise(left.accountId, right.accountId);
  return accountIdOrder !== 0 ? accountIdOrder : compareBytewise(left.stableId, right.stableId);
}

function decideValidated(request: ValidatedRequest): SchedulerDecision {
  const ids = new Set<string>();
  for (let index = 0; index < request.accounts.length; index += 1) {
    const value = request.accounts[index];
    if (!isRecord(value) || !isCanonicalAccountId(value.accountId)) continue;
    if (ids.has(value.accountId)) return emptyDecision("DUPLICATE_ACCOUNT_ID");
    ids.add(value.accountId);
  }

  const eligible: EligibleCandidate[] = [];
  const rejected: RejectedCandidate[] = [];
  for (let index = 0; index < request.accounts.length; index += 1) {
    const evaluation = evaluateAccount(request.accounts[index], request);
    if (evaluation.eligible) eligible.push(score(evaluation.account));
    else rejected.push(evaluation.rejected);
  }
  eligible.sort(rankedCompare);
  rejected.sort(
    (left, right) =>
      compareBytewise(left.accountId ?? "", right.accountId ?? "") ||
      compareBytewise(left.stableId ?? "", right.stableId ?? "") ||
      compareBytewise(left.reason, right.reason),
  );

  if (eligible.length === 0) {
    return {
      selectedAccountId: null,
      eligible,
      rejected,
      requestErrors: [],
      selection: "none",
    };
  }
  const top = eligible[0];
  if (request.stickinessKey === undefined) {
    return {
      selectedAccountId: top.accountId,
      eligible,
      rejected,
      requestErrors: [],
      selection: "top",
    };
  }

  const stickyPool = eligible.filter(
    (candidate) => top.score.total - candidate.score.total <= STICKY_TOLERANCE_POINTS,
  );
  const sticky = stickyPool.reduce((best, candidate) => {
    const bestHash = hash32(
      `${request.stickinessKey}\u0000${best.accountId}\u0000${best.stableId}`,
    );
    const candidateHash = hash32(
      `${request.stickinessKey}\u0000${candidate.accountId}\u0000${candidate.stableId}`,
    );
    if (candidateHash !== bestHash) return candidateHash > bestHash ? candidate : best;
    return rankedCompare(candidate, best) < 0 ? candidate : best;
  });
  return {
    selectedAccountId: sticky.accountId,
    eligible,
    rejected,
    requestErrors: [],
    selection: sticky.accountId === top.accountId ? "top" : "sticky",
  };
}

/**
 * Selects an eligible account without side effects. Runtime input is unknown on
 * purpose: persisted or decoded data is validated before any policy admission.
 * Caller-provided nowMs is the only time source.
 */
export function decideSchedulerPolicy(value: unknown): SchedulerDecision {
  try {
    const request = validateRequest(value);
    return request === null ? emptyDecision("INVALID_REQUEST") : decideValidated(request);
  } catch {
    return emptyDecision("INVALID_REQUEST");
  }
}
