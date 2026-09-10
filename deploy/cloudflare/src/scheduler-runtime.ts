import {
  decideSchedulerPolicy,
  type Evidence,
  type SchedulerAccount,
  type SchedulerCapability,
  type SchedulerDecision,
  type SchedulerRequest,
} from "./scheduler-policy";
import type { RateScope } from "./rate-limit";

const MAX_RUNTIME_ACCOUNTS = 256;
const MAX_TIMESTAMP_MS = 4_102_444_800_000;
const ID_PATTERN = /^[1-9][0-9]{0,19}$/;
const OPAQUE_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
const MAX_FACT_AGE_MS = 5 * 60_000;
const MAX_CLOCK_SKEW_MS = 5_000;

export type SchedulerRuntimeEnv = Pick<
  Env,
  "DB" | "ACCOUNT_LEASE" | "USER_RATE_LIMIT" | "API_KEY_RATE_LIMIT"
>;

export type SchedulerRuntimeInput = Readonly<{
  nowMs: number;
  userId: string;
  apiKeyId: string;
  requiredGroup: string;
  platform: string;
  accountType: string;
  model: string;
  stickinessKey?: string;
}>;

export type PrincipalRateSnapshot = Readonly<{
  scope: RateScope;
  principalId: string;
  limit: Evidence<number>;
  used: Evidence<number>;
  source: string | null;
  observedAtMs: number | null;
  freshUntilMs: number | null;
}>;

export type ObservationProvenance = Readonly<{
  evidence: string;
  source: string | null;
  observedAtMs: number | null;
  freshUntilMs: number | null;
  version: number | null;
}>;

export type AccountSchedulerProvenance = Readonly<{
  accountId: string;
  capabilities: ObservationProvenance;
  quota: ObservationProvenance;
  health: ObservationProvenance;
  cooldown: ObservationProvenance;
  temporaryUnschedulable: ObservationProvenance;
}>;

export type SchedulerRuntimeSnapshot = Readonly<{
  policyRequest: SchedulerRequest;
  apiKeyRate: PrincipalRateSnapshot;
  accountProvenance: readonly AccountSchedulerProvenance[];
  runtimeErrors: readonly string[];
}>;

export type SchedulerRuntimeDecision = Readonly<{
  decision: SchedulerDecision;
  snapshot: SchedulerRuntimeSnapshot;
  ready: boolean;
}>;

type AccountRuntimeRow = {
  account_id: string;
  status: string;
  schedulable: number;
  priority: number;
  max_concurrency: number;
  capabilities_json: string | null;
  capabilities_evidence: string | null;
  capabilities_source: string | null;
  capabilities_observed_at_ms: number | null;
  capabilities_fresh_until_ms: number | null;
  quota_exhausted: number | null;
  quota_remaining_bps: number | null;
  quota_evidence: string | null;
  quota_source: string | null;
  quota_observed_at_ms: number | null;
  quota_fresh_until_ms: number | null;
  version: number | null;
};

type PrincipalLimitRow = {
  rpm_limit: number;
  evidence: string;
  source: string;
  observed_at_ms: number;
  fresh_until_ms: number;
};

type DOEvidence = {
  evidence: "confirmed" | "estimated" | "unknown";
  value: number | null;
  source: string | null;
  observed_at_ms: number | null;
  fresh_until_ms: number | null;
  version: number | null;
};

type AccountInspect = {
  account_id: string;
  in_flight: number;
  concurrency_evidence: "confirmed";
  observed_at_ms: number;
  health: DOEvidence;
  cooldown: DOEvidence;
  temporary_unschedulable: DOEvidence;
};

type LeaseWire = {
  account_id: string;
  lease_id: string;
  request_id: string;
  owner: string;
  epoch: string;
  expires_at: string;
};

type RateReservation = {
  scope: RateScope;
  stub: DurableObjectStub;
  body: Record<string, unknown>;
  created: boolean;
  committed: boolean;
};

export type ReserveSchedulerResourcesInput = Readonly<{
  accountId: string;
  userId: string;
  apiKeyId: string;
  admissionId: string;
  requestId: string;
  owner: string;
  maxConcurrency: number;
  accountRpmLimit: number;
  userRpmLimit: number;
  apiKeyRpmLimit: number;
  leaseTtlSeconds: number;
  reservationTtlSeconds: number;
  admissionFingerprint: string;
}>;

export type SchedulerBillingStep = Readonly<{
  reserve: (lease: LeaseWire) => Promise<
    | { ok: true }
    | { ok: false; status: number; failedStep: string; authorityUnknown?: boolean }
  >;
  release: (lease: LeaseWire) => Promise<boolean>;
}>;

export type ReserveSchedulerResourcesResult =
  | Readonly<{
      ok: true;
      lease: LeaseWire;
      acquisitionOrder: readonly [
        "account_lease",
        "account_rpm",
        "user_rpm",
        "api_key_rpm",
        "billing_reservation",
      ];
    }>
  | Readonly<{
      ok: false;
      failedStep: string;
      status: number;
      committedScopes: readonly RateScope[];
      compensationFailures: readonly string[];
    }>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCanonicalID(value: unknown): value is string {
  return typeof value === "string" && ID_PATTERN.test(value);
}

function isSafeText(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= maximum &&
    value.trim() === value && !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(value);
}

function isTimestamp(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= MAX_TIMESTAMP_MS;
}

function confirmed<T>(value: T): Evidence<T> {
  return { kind: "confirmed", value };
}

function unknown<T>(): Evidence<T> {
  return { kind: "unknown" };
}

function evidence<T>(kind: string | null, value: T | null, freshUntil: number | null, now: number): Evidence<T> {
  if (freshUntil === null || freshUntil < now || value === null) return unknown<T>();
  if (kind === "confirmed") return confirmed(value);
  if (kind === "estimated") return { kind: "estimated", value };
  return unknown<T>();
}

function freshFact(
  evidenceKind: string | null,
  source: string | null,
  observedAt: number | null,
  freshUntil: number | null,
  now: number,
): boolean {
  return evidenceKind === "confirmed" && isSafeText(source, 64) &&
    isTimestamp(observedAt) && isTimestamp(freshUntil) &&
    observedAt <= now + MAX_CLOCK_SKEW_MS && freshUntil > now && freshUntil >= observedAt &&
    now - observedAt <= MAX_FACT_AGE_MS &&
    freshUntil - observedAt <= MAX_FACT_AGE_MS;
}

function parseCapabilityList(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || value.length > 64) return null;
  const result: string[] = [];
  const seen = new Set<string>();
  for (const item of value) {
    if (!isSafeText(item, 128) || seen.has(item)) return null;
    seen.add(item);
    result.push(item);
  }
  return result;
}

function parseCapabilities(value: string | null): SchedulerCapability | null {
  if (value === null) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (!isRecord(parsed)) return null;
    if (Object.keys(parsed).sort().join(",") !== "accountTypes,models,platforms") return null;
    const platforms = parseCapabilityList(parsed.platforms);
    const accountTypes = parseCapabilityList(parsed.accountTypes);
    const models = parseCapabilityList(parsed.models);
    return platforms && accountTypes && models ? { platforms, accountTypes, models } : null;
  } catch {
    return null;
  }
}

function validateInput(value: SchedulerRuntimeInput): void {
  if (
    !isTimestamp(value.nowMs) ||
    !isCanonicalID(value.userId) ||
    !isCanonicalID(value.apiKeyId) ||
    !isCanonicalID(value.requiredGroup) ||
    !isSafeText(value.platform, 128) ||
    !isSafeText(value.accountType, 128) ||
    !isSafeText(value.model, 128) ||
    (value.stickinessKey !== undefined && !isSafeText(value.stickinessKey, 256))
  ) {
    throw new Error("INVALID_SCHEDULER_RUNTIME_INPUT");
  }
}

function accountStub(env: SchedulerRuntimeEnv, accountId: string): DurableObjectStub {
  return env.ACCOUNT_LEASE.get(env.ACCOUNT_LEASE.idFromName(`account:${accountId}`));
}

function rateStub(env: SchedulerRuntimeEnv, scope: RateScope, principalId: string): DurableObjectStub {
  return scope === "account"
    ? accountStub(env, principalId)
    : scope === "user"
      ? env.USER_RATE_LIMIT.get(env.USER_RATE_LIMIT.idFromName(`user:${principalId}`))
      : env.API_KEY_RATE_LIMIT.get(env.API_KEY_RATE_LIMIT.idFromName(`api-key:${principalId}`));
}

async function post(stub: DurableObjectStub, path: string, body: unknown): Promise<Response> {
  return stub.fetch(`https://scheduler-runtime${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function responseRecord(response: Response): Promise<Record<string, unknown> | null> {
  try {
    const value: unknown = await response.json();
    return isRecord(value) ? value : null;
  } catch {
    return null;
  }
}

function validDOEvidence(value: unknown): value is DOEvidence {
  if (!isRecord(value)) return false;
  return (
    (value.evidence === "confirmed" || value.evidence === "estimated" || value.evidence === "unknown") &&
    (value.value === null || isTimestamp(value.value)) &&
    (value.source === null || isSafeText(value.source, 64)) &&
    (value.observed_at_ms === null || isTimestamp(value.observed_at_ms)) &&
    (value.fresh_until_ms === null || isTimestamp(value.fresh_until_ms)) &&
    (value.version === null || (Number.isSafeInteger(value.version) && Number(value.version) >= 1))
  );
}

async function inspectAccount(env: SchedulerRuntimeEnv, accountId: string): Promise<AccountInspect | null> {
  const response = await post(accountStub(env, accountId), "/inspect", { account_id: accountId });
  if (!response.ok) return null;
  const value = await responseRecord(response);
  if (
    !value || value.account_id !== accountId || !Number.isSafeInteger(value.in_flight) ||
    Number(value.in_flight) < 0 || value.concurrency_evidence !== "confirmed" ||
    !isTimestamp(value.observed_at_ms) || !validDOEvidence(value.health) ||
    !validDOEvidence(value.cooldown) || !validDOEvidence(value.temporary_unschedulable)
  ) {
    return null;
  }
  return value as AccountInspect;
}

async function loadLimit(
  env: SchedulerRuntimeEnv,
  scope: RateScope,
  principalId: string,
  now: number,
): Promise<PrincipalRateSnapshot> {
  const row = await env.DB.prepare(
    `SELECT rpm_limit,evidence,source,observed_at_ms,fresh_until_ms
     FROM scheduler_principal_limits WHERE scope=? AND principal_id=?`,
  ).bind(scope, principalId).first<PrincipalLimitRow>();
  const base = {
    scope,
    principalId,
    source: row?.source ?? null,
    observedAtMs: row?.observed_at_ms ?? null,
    freshUntilMs: row?.fresh_until_ms ?? null,
  };
  if (!row || !freshFact(row.evidence, row.source, row.observed_at_ms, row.fresh_until_ms, now) ||
      !Number.isInteger(row.rpm_limit) || row.rpm_limit < 1 || row.rpm_limit > 100_000) {
    return { ...base, limit: unknown(), used: unknown() };
  }
  const response = await post(rateStub(env, scope, principalId), "/rate/inspect", {
    scope,
    principal_id: principalId,
    rpm_limit: row.rpm_limit,
  });
  const body = response.ok ? await responseRecord(response) : null;
  if (!body || body.evidence !== "confirmed" || !Number.isSafeInteger(body.used) || Number(body.used) < 0) {
    return { ...base, limit: confirmed(row.rpm_limit), used: unknown() };
  }
  return { ...base, limit: confirmed(row.rpm_limit), used: confirmed(Number(body.used)) };
}

function doMetric(value: DOEvidence, divisor = 1): Evidence<number> {
  if (value.value === null || value.evidence === "unknown") return unknown();
  const result = value.value / divisor;
  return value.evidence === "confirmed" ? confirmed(result) : { kind: "estimated", value: result };
}

function doDeadline(value: DOEvidence): Evidence<number | null> {
  if (value.evidence === "unknown") return unknown();
  return value.evidence === "confirmed"
    ? confirmed(value.value)
    : { kind: "estimated", value: value.value };
}

function doProvenance(value: DOEvidence | undefined): ObservationProvenance {
  return {
    evidence: value?.evidence ?? "unknown",
    source: value?.source ?? null,
    observedAtMs: value?.observed_at_ms ?? null,
    freshUntilMs: value?.fresh_until_ms ?? null,
    version: value?.version ?? null,
  };
}

export async function buildSchedulerSnapshot(
  env: SchedulerRuntimeEnv,
  input: SchedulerRuntimeInput,
): Promise<SchedulerRuntimeSnapshot> {
  validateInput(input);
  const errors: string[] = [];
  const identity = await env.DB.prepare(
    `SELECT k.id api_key_id
     FROM api_keys k JOIN users u ON u.id=k.user_id
     JOIN groups g ON g.id=k.group_id
     WHERE k.id=? AND k.user_id=? AND k.group_id=?
       AND k.status='active' AND k.deleted_at IS NULL
       AND u.status='active' AND u.deleted_at IS NULL
       AND g.status='active' AND g.deleted_at IS NULL`,
  ).bind(input.apiKeyId, input.userId, input.requiredGroup).first<{ api_key_id: string }>();
  if (!identity) errors.push("PRINCIPAL_NOT_ACTIVE");

  const rows = (await env.DB.prepare(
    `SELECT a.id account_id,a.status,a.schedulable,a.priority,a.max_concurrency,
            r.capabilities_json,r.capabilities_evidence,r.capabilities_source,
            r.capabilities_observed_at_ms,r.capabilities_fresh_until_ms,
            r.quota_exhausted,r.quota_remaining_bps,r.quota_evidence,
            r.quota_source,r.quota_observed_at_ms,r.quota_fresh_until_ms,r.version
     FROM accounts a
     JOIN account_groups ag ON ag.account_id=a.id
     JOIN groups g ON g.id=ag.group_id
     LEFT JOIN scheduler_account_runtime r ON r.account_id=a.id
     WHERE ag.group_id=? AND a.deleted_at IS NULL AND g.deleted_at IS NULL
     ORDER BY a.id LIMIT ?`,
  ).bind(input.requiredGroup, MAX_RUNTIME_ACCOUNTS + 1).all<AccountRuntimeRow>()).results;
  if (rows.length > MAX_RUNTIME_ACCOUNTS) errors.push("TOO_MANY_ACCOUNTS");

  const [userRate, apiKeyRate] = await Promise.all([
    loadLimit(env, "user", input.userId, input.nowMs),
    loadLimit(env, "api_key", input.apiKeyId, input.nowMs),
  ]);
  if (userRate.limit.kind !== "confirmed" || userRate.used.kind !== "confirmed") {
    errors.push("USER_RPM_UNCONFIRMED");
  }
  if (apiKeyRate.limit.kind !== "confirmed" || apiKeyRate.used.kind !== "confirmed") {
    errors.push("API_KEY_RPM_UNCONFIRMED");
  } else if (apiKeyRate.used.value >= apiKeyRate.limit.value) {
    errors.push("API_KEY_RPM_EXHAUSTED");
  }

  const accountResults = await Promise.all(rows.slice(0, MAX_RUNTIME_ACCOUNTS).map(async (row): Promise<{
    account: SchedulerAccount;
    provenance: AccountSchedulerProvenance;
  }> => {
    const [live, accountRate] = await Promise.all([
      inspectAccount(env, row.account_id),
      loadLimit(env, "account", row.account_id, input.nowMs),
    ]);
    const capabilities = parseCapabilities(row.capabilities_json);
    const capabilityFresh = freshFact(
      row.capabilities_evidence,
      row.capabilities_source,
      row.capabilities_observed_at_ms,
      row.capabilities_fresh_until_ms,
      input.nowMs,
    );
    const quotaFresh = freshFact(
      row.quota_evidence,
      row.quota_source,
      row.quota_observed_at_ms,
      row.quota_fresh_until_ms,
      input.nowMs,
    );
    const capabilityEvidence = evidence(
      row.capabilities_evidence,
      capabilityFresh ? capabilities : null,
      row.capabilities_fresh_until_ms,
      input.nowMs,
    );
    const quotaExhausted = evidence(
      row.quota_evidence,
      quotaFresh && row.quota_exhausted !== null ? row.quota_exhausted === 1 : null,
      row.quota_fresh_until_ms,
      input.nowMs,
    );
    const quotaRemaining = evidence(
      row.quota_evidence,
      quotaFresh && row.quota_remaining_bps !== null
        ? row.quota_remaining_bps / 10_000
        : null,
      row.quota_fresh_until_ms,
      input.nowMs,
    );
    const liveFresh = !!live &&
      input.nowMs - live.observed_at_ms <= MAX_FACT_AGE_MS &&
      [live.health, live.cooldown, live.temporary_unschedulable].every((item) =>
        item.evidence === "confirmed" && isSafeText(item.source, 64) &&
        isTimestamp(item.observed_at_ms) && isTimestamp(item.fresh_until_ms) &&
        item.observed_at_ms <= input.nowMs + MAX_CLOCK_SKEW_MS &&
        item.fresh_until_ms > input.nowMs &&
        input.nowMs - item.observed_at_ms <= MAX_FACT_AGE_MS &&
        item.fresh_until_ms - item.observed_at_ms <= MAX_FACT_AGE_MS);
    const complete = capabilityFresh && capabilities !== null && quotaFresh &&
      liveFresh && accountRate.limit.kind === "confirmed" &&
      accountRate.used.kind === "confirmed";
    return { account: {
      accountId: row.account_id,
      stableId: row.account_id,
      priority: row.priority,
      active: confirmed(row.status === "active"),
      schedulable: confirmed(row.schedulable === 1),
      groups: confirmed([input.requiredGroup]),
      capabilities: capabilityEvidence,
      accountConcurrencyLimit: confirmed(row.max_concurrency),
      accountConcurrencyInFlight: liveFresh ? confirmed(live!.in_flight) : unknown(),
      accountRpmLimit: accountRate.limit,
      accountRpmUsed: accountRate.used,
      userRpmLimit: userRate.limit,
      userRpmUsed: userRate.used,
      quotaExhausted,
      quotaRemainingRatio: quotaRemaining,
      temporarilyUnschedulableUntilMs: liveFresh ? doDeadline(live!.temporary_unschedulable) : unknown(),
      cooldownUntilMs: liveFresh ? doDeadline(live!.cooldown) : unknown(),
      healthRatio: liveFresh ? doMetric(live!.health, 10_000) : unknown(),
    }, provenance: {
      accountId: row.account_id,
      capabilities: {
        evidence: capabilityEvidence.kind,
        source: row.capabilities_source,
        observedAtMs: row.capabilities_observed_at_ms,
        freshUntilMs: row.capabilities_fresh_until_ms,
        version: row.version,
      },
      quota: {
        evidence: quotaExhausted.kind,
        source: row.quota_source,
        observedAtMs: row.quota_observed_at_ms,
        freshUntilMs: row.quota_fresh_until_ms,
        version: row.version,
      },
      health: doProvenance(live?.health),
      cooldown: doProvenance(live?.cooldown),
      temporaryUnschedulable: doProvenance(live?.temporary_unschedulable),
    } };
  }));
  const accounts = accountResults.map((result) => result.account);

  return {
    policyRequest: {
      nowMs: input.nowMs,
      requiredGroup: input.requiredGroup,
      platform: input.platform,
      accountType: input.accountType,
      model: input.model,
      ...(input.stickinessKey === undefined ? {} : { stickinessKey: input.stickinessKey }),
      accounts,
    },
    apiKeyRate,
    accountProvenance: accountResults.map((result) => result.provenance),
    runtimeErrors: [...new Set(errors)].sort(),
  };
}

export async function decideSchedulerRuntime(
  env: SchedulerRuntimeEnv,
  input: SchedulerRuntimeInput,
): Promise<SchedulerRuntimeDecision> {
  const snapshot = await buildSchedulerSnapshot(env, input);
  const decision = decideSchedulerPolicy(snapshot.policyRequest);
  return {
    decision,
    snapshot,
    ready: snapshot.runtimeErrors.length === 0 && decision.selectedAccountId !== null,
  };
}

function validReserveInput(input: ReserveSchedulerResourcesInput): boolean {
  return isCanonicalID(input.accountId) && isCanonicalID(input.userId) && isCanonicalID(input.apiKeyId) &&
    OPAQUE_PATTERN.test(input.admissionId) && OPAQUE_PATTERN.test(input.requestId) && OPAQUE_PATTERN.test(input.owner) &&
    Number.isInteger(input.maxConcurrency) && input.maxConcurrency >= 1 && input.maxConcurrency <= 10_000 &&
    [input.accountRpmLimit, input.userRpmLimit, input.apiKeyRpmLimit].every(
      (value) => Number.isInteger(value) && value >= 1 && value <= 100_000,
    ) && Number.isInteger(input.leaseTtlSeconds) && input.leaseTtlSeconds >= 3 && input.leaseTtlSeconds <= 3_600 &&
    Number.isInteger(input.reservationTtlSeconds) && input.reservationTtlSeconds >= 3 &&
    input.reservationTtlSeconds <= 60 && FINGERPRINT_PATTERN.test(input.admissionFingerprint);
}

async function releaseLease(stub: DurableObjectStub, lease: LeaseWire): Promise<boolean> {
  try {
    const response = await post(stub, "/release", lease);
    await response.text();
    return response.ok;
  } catch {
    return false;
  }
}

async function abortLease(
  stub: DurableObjectStub,
  input: ReserveSchedulerResourcesInput,
): Promise<boolean> {
  try {
    const response = await post(stub, "/abort", {
      account_id: input.accountId,
      request_id: input.requestId,
      owner: input.owner,
      admission_fingerprint: input.admissionFingerprint,
    });
    await response.text();
    return response.ok;
  } catch {
    return false;
  }
}

function validRateReservationResponse(
  value: Record<string, unknown> | null,
): value is Record<string, unknown> & {
  created: boolean;
  reserved: boolean;
  committed: boolean;
} {
  return value !== null &&
    typeof value.created === "boolean" &&
    typeof value.reserved === "boolean" &&
    typeof value.committed === "boolean" &&
    value.reserved !== value.committed &&
    (!value.created || (value.reserved && !value.committed));
}

async function releaseRates(items: readonly RateReservation[]): Promise<string[]> {
  const failures: string[] = [];
  for (const item of [...items].reverse()) {
    if (item.created) {
      try {
        const response = await post(item.stub, "/rate/rollback", item.body);
        await response.text();
        if (!response.ok) failures.push(`${item.scope}_rpm_release`);
      } catch {
        failures.push(`${item.scope}_rpm_release`);
      }
    }
  }
  return failures;
}

/**
 * Cross-DO admission is ordered but not atomic. Newly-created state is
 * compensated in exact reverse order and all residual state has bounded TTL.
 */
export async function reserveSchedulerResources(
  env: SchedulerRuntimeEnv,
  input: ReserveSchedulerResourcesInput,
  billing: SchedulerBillingStep,
): Promise<ReserveSchedulerResourcesResult> {
  if (!validReserveInput(input)) {
    return {
      ok: false,
      failedStep: "validation",
      status: 400,
      committedScopes: [],
      compensationFailures: [],
    };
  }
  const leaseStub = accountStub(env, input.accountId);
  let leaseResponse: Response;
  try {
    leaseResponse = await post(leaseStub, "/acquire", {
      account_id: input.accountId,
      request_id: input.requestId,
      owner: input.owner,
      max_concurrency: input.maxConcurrency,
      ttl_seconds: input.leaseTtlSeconds,
      admission_fingerprint: input.admissionFingerprint,
    });
  } catch {
    const compensationFailures = await abortLease(leaseStub, input)
      ? [] : ["account_lease_release"];
    return {
      ok: false, failedStep: "account_lease", status: 503,
      committedScopes: [], compensationFailures,
    };
  }
  const leaseBody = leaseResponse.ok ? await responseRecord(leaseResponse) : null;
  const lease = leaseBody && isRecord(leaseBody.lease) ? leaseBody.lease as LeaseWire : null;
  const leaseCreated = leaseBody?.created === true;
  if (
    !lease ||
    lease.account_id !== input.accountId ||
    lease.request_id !== input.requestId ||
    lease.owner !== input.owner ||
    !isSafeText(lease.lease_id, 128) ||
    !/^[1-9][0-9]{0,19}$/.test(lease.epoch) ||
    !isSafeText(lease.expires_at, 64) ||
    !Number.isFinite(Date.parse(lease.expires_at)) ||
    Date.parse(lease.expires_at) <= Date.now()
  ) {
    if (!leaseResponse.ok) await leaseResponse.text();
    const compensationFailures = leaseResponse.ok && !await abortLease(leaseStub, input)
      ? ["account_lease_release"] : [];
    return {
      ok: false,
      failedStep: "account_lease",
      status: leaseResponse.ok ? 503 : leaseResponse.status,
      committedScopes: [],
      compensationFailures,
    };
  }

  const definitions: Array<[RateScope, string, number, string]> = [
    ["account", input.accountId, input.accountRpmLimit, "account_rpm"],
    ["user", input.userId, input.userRpmLimit, "user_rpm"],
    ["api_key", input.apiKeyId, input.apiKeyRpmLimit, "api_key_rpm"],
  ];
  const reservations: RateReservation[] = [];
  for (const [scope, principalId, limit, step] of definitions) {
    const stub = rateStub(env, scope, principalId);
    const body = {
      scope,
      principal_id: principalId,
      admission_id: input.admissionId,
      request_id: input.requestId,
      account_id: input.accountId,
      rpm_limit: limit,
      reservation_ttl_seconds: input.reservationTtlSeconds,
      admission_fingerprint: input.admissionFingerprint,
    };
    let response: Response | null = null;
    try {
      response = await post(stub, "/rate/reserve", body);
    } catch {
      // The reverse compensation below handles all earlier acquisitions.
    }
    const decoded = response?.ok ? await responseRecord(response) : null;
    if (!response?.ok || !validRateReservationResponse(decoded)) {
      if (response && !response.ok) await response.text();
      const acquired = [...reservations];
      // A thrown or malformed successful response may have committed this
      // exact reservation. Include it first in reverse compensation.
      if (!response || response.ok) {
        acquired.push({ scope, stub, body, created: true, committed: false });
      }
      const compensationFailures = await releaseRates(acquired);
      if (leaseCreated && !await releaseLease(leaseStub, lease)) {
        compensationFailures.push("account_lease_release");
      }
      return {
        ok: false,
        failedStep: step,
        status: response?.ok ? 503 : (response?.status ?? 503),
        committedScopes: [],
        compensationFailures,
      };
    }
    reservations.push({
      scope,
      stub,
      body,
      created: decoded.created === true,
      committed: decoded.committed === true,
    });
  }

  const committed: RateScope[] = [];
  for (const item of reservations) {
    if (item.committed) {
      committed.push(item.scope);
      continue;
    }
    let response: Response | null = null;
    try {
      response = await post(item.stub, "/rate/commit", item.body);
    } catch {
      // The reverse compensation below handles all acquired resources.
    }
    if (!response?.ok) {
      if (response) await response.text();
      const compensationFailures = await releaseRates(reservations);
      if (leaseCreated && !await releaseLease(leaseStub, lease)) {
        compensationFailures.push("account_lease_release");
      }
      return {
        ok: false,
        failedStep: `${item.scope}_rpm_commit`,
        status: response?.status ?? 503,
        committedScopes: committed,
        compensationFailures,
      };
    }
    item.committed = true;
    committed.push(item.scope);
  }

  let billingResult:
    | { ok: true }
    | { ok: false; status: number; failedStep: string; authorityUnknown?: boolean };
  try {
    billingResult = await billing.reserve(lease);
  } catch {
    billingResult = {
      ok: false,
      status: 503,
      failedStep: "billing_reservation",
      authorityUnknown: true,
    };
  }
  if (!billingResult.ok) {
    const compensationFailures: string[] = [];
    // Billing is the final acquisition. If its response was unavailable, close
    // that exact identity before reversing the RPM and lease acquisitions.
    if (billingResult.authorityUnknown && !await billing.release(lease)) {
      compensationFailures.push("billing_reservation_release");
    }
    compensationFailures.push(...await releaseRates(reservations));
    if (leaseCreated && !await releaseLease(leaseStub, lease)) {
      compensationFailures.push("account_lease_release");
    }
    return {
      ok: false,
      failedStep: billingResult.failedStep,
      status: billingResult.status,
      committedScopes: committed,
      compensationFailures,
    };
  }
  return {
    ok: true,
    lease,
    acquisitionOrder: [
      "account_lease",
      "account_rpm",
      "user_rpm",
      "api_key_rpm",
      "billing_reservation",
    ],
  };
}

export async function settleSchedulerRates(
  env: SchedulerRuntimeEnv,
  input: Readonly<{
    accountId: string;
    userId: string;
    apiKeyId: string;
    admissionId: string;
    requestId: string;
    admissionFingerprint: string;
  }>,
): Promise<string[]> {
  const failures: string[] = [];
  const definitions: Array<[RateScope, string]> = [
    ["api_key", input.apiKeyId],
    ["user", input.userId],
    ["account", input.accountId],
  ];
  for (const [scope, principalId] of definitions) {
    try {
      const response = await post(rateStub(env, scope, principalId), "/rate/settle", {
        scope,
        principal_id: principalId,
        admission_id: input.admissionId,
        request_id: input.requestId,
        account_id: input.accountId,
        admission_fingerprint: input.admissionFingerprint,
      });
      await response.text();
      if (!response.ok) failures.push(`${scope}_rpm_settle`);
    } catch {
      failures.push(`${scope}_rpm_settle`);
    }
  }
  return failures;
}

export async function rollbackSchedulerRates(
  env: SchedulerRuntimeEnv,
  input: Readonly<{
    accountId: string;
    userId: string;
    apiKeyId: string;
    admissionId: string;
    requestId: string;
    admissionFingerprint: string;
  }>,
): Promise<string[]> {
  const failures: string[] = [];
  const definitions: Array<[RateScope, string]> = [
    ["api_key", input.apiKeyId],
    ["user", input.userId],
    ["account", input.accountId],
  ];
  for (const [scope, principalId] of definitions) {
    try {
      const response = await post(rateStub(env, scope, principalId), "/rate/rollback", {
        scope,
        principal_id: principalId,
        admission_id: input.admissionId,
        request_id: input.requestId,
        account_id: input.accountId,
        admission_fingerprint: input.admissionFingerprint,
      });
      await response.text();
      if (!response.ok) failures.push(`${scope}_rpm_rollback`);
    } catch {
      failures.push(`${scope}_rpm_rollback`);
    }
  }
  return failures;
}
