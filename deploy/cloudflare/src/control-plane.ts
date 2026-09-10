import type { Completion, UsageEnvelope } from "./contracts";
import { decryptAPIKeyCredentials, type CredentialRuntime } from "./credentials";
import { managementControlPlane } from "./management";
import { privateDataPlane } from "./private-data";
import { calculateAdmittedE8Charge, loadAdmittedPriceCard, lookupAdmissionPriceCard, normalizePricingModel } from "./pricing";
import type { BillingIdentity } from "./billing";
import {
  decideSchedulerRuntime,
  rollbackSchedulerRates,
  reserveSchedulerResources,
  settleSchedulerRates,
} from "./scheduler-runtime";
import type { SchedulerAccount } from "./scheduler-policy";
import { isTOTPControlPath, totpControlPlane } from "./totp-control";
import {
  authSessionsControlPlane,
  isAuthSessionsPath,
} from "./auth-sessions";
import {
  isSubscriptionControlPath,
  subscriptionControlPlane,
} from "./subscription-control";
import {
  isSettingsControlPath,
  settingsControlPlane,
} from "./settings-control";
import {
  isPaymentControlPath,
  paymentControlPlane,
} from "./payment-control";
import {
  BRIDGE_VERSION,
  INTERNAL_HOST,
  MAX_CONTROL_BODY_BYTES,
  USAGE_EVENT_TYPE,
  USAGE_SCHEMA_VERSION,
  canonical,
  error,
  isBoundedString,
  isCanonicalPositiveDecimal,
  isCanonicalUnsignedDecimal,
  json,
  now,
  readJson,
  sha256,
} from "./contracts";
import {
  AuthCacheRuntime,
  type AuthCacheAuthorization,
} from "./auth-cache-runtime";

const PUBLISH_TIMEOUT_MS = 2_000;
const MAX_OUTBOX_ATTEMPTS = 10;
const OUTBOX_DRAIN_LIMIT = 25;
const ADMISSION_RECOVERY_LIMIT = 25;
const ADMISSION_RECOVERY_AGE_MS = 15 * 60_000;

// Worker globals are isolate-local only. Bind a cache runtime to the current
// D1 binding so tests and future isolate instances never share authority or
// request data; AuthCacheRuntime itself probes D1 before every cache hit.
const authCacheRuntimes = new WeakMap<D1Database, AuthCacheRuntime>();

function authCacheRuntime(db: D1Database): AuthCacheRuntime {
  let runtime = authCacheRuntimes.get(db);
  if (!runtime) {
    runtime = new AuthCacheRuntime(db);
    authCacheRuntimes.set(db, runtime);
  }
  return runtime;
}

type RuntimeEnv = Omit<
  Env,
  | "ENVIRONMENT"
  | "ALLOW_TEST_FIXTURE"
  | "SUB2API_CF_UPSTREAM_ALLOWED_HOSTS"
> & CredentialRuntime;

type Alias = {
  alias: string;
  upstream_model: string;
  status: string;
  updated_at: string;
};

type AuthRow = {
  key_hash: string;
  key_id: string;
  key_user_id: string;
  group_id: string | null;
  key_name: string;
  key_status: string;
  ip_whitelist_json: string;
  ip_blacklist_json: string;
  expires_at: string | null;
  user_id: string;
  user_status: string;
  role: string;
  concurrency: number;
  balance_e8_usd: string;
  allowed_group_ids_json: string;
  restrict_public_groups: number;
  group_name: string | null;
  platform: string | null;
  group_status: string | null;
  is_exclusive: number | null;
  subscription_type: string | null;
};

type Account = {
  id: string;
  name: string;
  platform: string;
  type: string;
  max_concurrency: number;
  credential_envelope: string;
  extra_json: string;
};

type GatewayIdentity = {
  request_id: string;
  api_key_id: string;
  account_id: string;
  lease_id: string;
  lease_epoch: string;
  owner: string;
  model: string;
  upstream_model: string;
  pricing_version_id: string | null;
  pricing_digest: string | null;
  pricing_rule_pattern: string | null;
  pricing_model: string | null;
  pricing_rule_match_kind: "exact" | "family" | null;
  rate_multiplier_bps: string | null;
  state: string;
};

type BillingRow = BillingIdentity & {
  state: "reserved" | "started" | "completed" | "released" | "unknown";
  version: number;
  completion_event_id: string | null;
  completion_payload_hash: string | null;
  scheduler_release_state: "pending" | "released";
  scheduler_release_attempts: number;
};

const billingColumns = "request_id,user_id,api_key_id,group_id,account_id,lease_id,lease_epoch,owner,model,upstream_model,pricing_version_id,pricing_digest,pricing_model,pricing_rule_pattern,pricing_rule_match_kind,rate_multiplier_bps,reservation_e8_usd,charged_e8_usd,usage_present,state,version,completion_event_id,completion_payload_hash,completion_outcome,upstream_request_id,scheduler_release_state,scheduler_release_attempts";
const billingIdentity = (row: BillingRow): BillingIdentity => ({
  request_id: row.request_id, user_id: row.user_id, api_key_id: row.api_key_id, group_id: row.group_id,
  account_id: row.account_id, lease_id: row.lease_id, lease_epoch: row.lease_epoch, owner: row.owner,
  model: row.model, upstream_model: row.upstream_model, pricing_version_id: row.pricing_version_id,
  pricing_digest: row.pricing_digest, pricing_model: row.pricing_model, pricing_rule_pattern: row.pricing_rule_pattern,
  pricing_rule_match_kind: row.pricing_rule_match_kind, rate_multiplier_bps: row.rate_multiplier_bps,
  reservation_e8_usd: row.reservation_e8_usd,
});

function billingStub(env: Env, userID: string) {
  return env.BILLING_PRINCIPAL.getByName(`user:${userID}`);
}

const hasBridgeVersion = (request: Request): boolean =>
  request.headers.get("X-Sub2API-Bridge-Version") === BRIDGE_VERSION;

export async function controlPlane(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (
    url.hostname !== INTERNAL_HOST ||
    !hasBridgeVersion(request) ||
    request.method !== "POST"
  ) {
    return error("NOT_FOUND", 404);
  }

  try {
    if (isTOTPControlPath(url.pathname)) {
      return await totpControlPlane(request, env, url.pathname);
    }
    if (isAuthSessionsPath(url.pathname)) {
      return await authSessionsControlPlane(request, env, url.pathname);
    }
    if (isSubscriptionControlPath(url.pathname)) {
      return await subscriptionControlPlane(request, env, url.pathname);
    }
    if (isSettingsControlPath(url.pathname)) {
      return await settingsControlPlane(request, env, url.pathname);
    }
    if (isPaymentControlPath(url.pathname)) {
      return await paymentControlPlane(request, env, url.pathname);
    }
    switch (url.pathname) {
      case "/v1/auth/resolve":
        return await resolveAPIKey(request, env);
      case "/v1/auth/touch":
        return await touchAPIKey(request, env);
      case "/v1/requests/admit":
        return await admitRequest(request, env);
      case "/v1/requests/start":
        return await startRequest(request, env);
      case "/v1/leases/renew":
        return await relayLeaseAction(request, env, "/renew");
      case "/v1/leases/release":
        return await relayLeaseAction(request, env, "/release");
      case "/v1/requests/complete":
        return await completeRequest(request, env);
      case "/v1/requests/reconcile":
        return await reconcileRequest(request, env);
      case "/v1/private/auth-users/get":
      case "/v1/private/api-keys/list-by-owner":
      case "/v1/private/api-keys/count-by-owner":
      case "/v1/private/api-keys/exists":
        return await privateDataPlane(request, env, url.pathname);
      case "/v1/manage/users/create":
      case "/v1/manage/users/get":
      case "/v1/manage/users/list":
      case "/v1/manage/users/balance-history":
      case "/v1/manage/users/update":
      case "/v1/manage/users/role-change":
      case "/v1/manage/users/delete":
      case "/v1/manage/users/balance-adjust":
      case "/v1/manage/groups/create":
      case "/v1/manage/groups/get":
      case "/v1/manage/groups/list":
      case "/v1/manage/groups/update":
      case "/v1/manage/groups/delete":
      case "/v1/manage/api-keys/create":
      case "/v1/manage/api-keys/get":
      case "/v1/manage/api-keys/list":
      case "/v1/manage/api-keys/update":
      case "/v1/manage/api-keys/rebind-group":
      case "/v1/manage/api-keys/revoke":
      case "/v1/manage/api-keys/rotate":
      case "/v1/manage/accounts/create":
      case "/v1/manage/accounts/get":
      case "/v1/manage/accounts/list":
      case "/v1/manage/accounts/update":
      case "/v1/manage/accounts/delete":
        return await managementControlPlane(request, env, url.pathname);
      default:
        return error("NOT_FOUND", 404);
    }
  } catch {
    // The control plane never returns database or credential details to the
    // Container. Callers can retry an availability error safely.
    return error("CONTROL_PLANE_UNAVAILABLE", 503);
  }
}

async function fetchAuthRowByID(keyID: string, env: Env): Promise<AuthRow | null> {
  return env.DB.prepare(
    `SELECT
       k.key_hash,
       k.id key_id,
       k.user_id key_user_id,
       k.group_id,
       k.name key_name,
       k.status key_status,
       k.ip_whitelist_json,
       k.ip_blacklist_json,
       k.expires_at,
       u.id user_id,
       u.status user_status,
       u.role,
       u.concurrency,
       u.balance_e8_usd,
       u.allowed_group_ids_json,
       u.restrict_public_groups,
       g.name group_name,
       g.platform,
       g.status group_status,
       g.is_exclusive,
       g.subscription_type
     FROM api_keys k
     JOIN users u ON u.id=k.user_id
     LEFT JOIN groups g ON g.id=k.group_id
     WHERE k.id=? AND k.deleted_at IS NULL AND u.deleted_at IS NULL
       AND g.deleted_at IS NULL`,
  )
    .bind(keyID)
    .first<AuthRow>();
}

function parseStringArray(value: string, decimalOnly = false): string[] | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) return null;
    if (
      !parsed.every(
        (item) =>
          isBoundedString(item, 512, 0) &&
          (!decimalOnly || isCanonicalPositiveDecimal(item)),
      )
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function hasPositiveBalance(value: string): boolean {
  if (!isCanonicalUnsignedDecimal(value) || value.length > 40) return false;
  try {
    return BigInt(value) > 0n;
  } catch {
    return false;
  }
}

function isUnexpired(value: string | null): boolean {
  if (value === null) return true;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && timestamp > Date.now();
}

function permittedAuth(
  row: AuthRow,
  requestedGroup?: string,
  requirePositiveBalance = true,
): boolean {
  return (
    row.key_status === "active" &&
    row.user_status === "active" &&
    row.group_status === "active" &&
    isCanonicalPositiveDecimal(row.key_id) &&
    isCanonicalPositiveDecimal(row.key_user_id) &&
    row.key_user_id === row.user_id &&
    isCanonicalPositiveDecimal(row.user_id) &&
    isCanonicalPositiveDecimal(row.group_id) &&
    (requestedGroup === undefined || row.group_id === requestedGroup) &&
    (!requirePositiveBalance || hasPositiveBalance(row.balance_e8_usd)) &&
    isUnexpired(row.expires_at)
  );
}

function sameStringList(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function matchesResolvedAuthorization(
  row: AuthRow,
  authorization: AuthCacheAuthorization,
  allowedGroups: readonly string[],
): boolean {
  return (
    row.key_hash === authorization.credential_digest &&
    row.key_id === authorization.api_key_id &&
    row.key_user_id === authorization.user_id &&
    row.user_id === authorization.user_id &&
    row.group_id === authorization.group_id &&
    row.expires_at === authorization.expires_at &&
    sameStringList(allowedGroups, authorization.allowed_group_ids) &&
    (row.restrict_public_groups === 1) === authorization.restrict_public_groups
  );
}

async function resolveAPIKey(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{ key?: unknown }>(request);
  if (!body || !isBoundedString(body.key, 8_192)) {
    return error("API_KEY_NOT_FOUND", 404);
  }

  // The runtime receives the raw key only to hash it transiently. Its minimal
  // D1 probe is the entitlement/revision linearization point; no raw key is
  // stored, logged, or used as a cache key here.
  const resolution = await authCacheRuntime(env.DB).resolve({ credential: body.key });
  if (!resolution.ok) {
    return resolution.code === "AUTH_UNAVAILABLE"
      ? error("CONTROL_PLANE_UNAVAILABLE", 503)
      : error("API_KEY_NOT_FOUND", 404);
  }

  // Fetch response-only fields by the authorized ID, then reject a changed
  // identity, entitlement snapshot, status, expiry, or balance. This keeps
  // the Go-facing payload intact without authorizing from a stale projection.
  const row = await fetchAuthRowByID(resolution.authorization.api_key_id, env);
  if (!row || !permittedAuth(row)) return error("API_KEY_NOT_FOUND", 404);

  const whitelist = parseStringArray(row.ip_whitelist_json);
  const blacklist = parseStringArray(row.ip_blacklist_json);
  const allowedGroups = parseStringArray(row.allowed_group_ids_json, true);
  if (
    !whitelist ||
    !blacklist ||
    !allowedGroups ||
    row.group_id === null ||
    !matchesResolvedAuthorization(row, resolution.authorization, allowedGroups)
  ) {
    return error("API_KEY_NOT_FOUND", 404);
  }

  return json({
    api_key: {
      id: row.key_id,
      user_id: row.user_id,
      name: row.key_name,
      status: row.key_status,
      group_id: row.group_id,
      ip_whitelist: whitelist,
      ip_blacklist: blacklist,
      expires_at: row.expires_at,
    },
    user: {
      id: row.user_id,
      status: row.user_status,
      role: row.role,
      concurrency: row.concurrency,
      balance_positive: true,
      allowed_group_ids: allowedGroups,
      restrict_public_groups: row.restrict_public_groups === 1,
    },
    group: {
      id: row.group_id,
      name: row.group_name,
      platform: row.platform,
      status: row.group_status,
      is_exclusive: row.is_exclusive === 1,
      subscription_type: row.subscription_type,
    },
  });
}

async function touchAPIKey(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{ api_key_id?: unknown; used_at?: unknown }>(request);
  if (
    !body ||
    !isCanonicalPositiveDecimal(body.api_key_id) ||
    body.api_key_id.length > 20 ||
    !isBoundedString(body.used_at, 64) ||
    !Number.isFinite(Date.parse(body.used_at))
  ) {
    return error("INVALID_REQUEST");
  }
  const usedAt = new Date(body.used_at).toISOString();
  await env.DB.prepare(
    `UPDATE api_keys SET last_used_at=?
     WHERE id=? AND deleted_at IS NULL
       AND (last_used_at IS NULL OR last_used_at<?)`,
  )
    .bind(usedAt, body.api_key_id, usedAt)
    .run();
  return new Response(null, { status: 204 });
}

async function resolveAlias(model: string, env: Env): Promise<Alias | null> {
  let cached: Alias | null = null;
  try {
    cached = await env.CONFIG_CACHE.get<Alias>(`model:${model}`, "json");
  } catch {
    // D1 is authoritative and remains available without KV.
  }

  const authoritative = await env.DB.prepare(
    `SELECT alias,upstream_model,status,updated_at
     FROM model_aliases WHERE alias=?`,
  )
    .bind(model)
    .first<Alias>();
  if (
    !authoritative ||
    authoritative.status !== "active" ||
    !isBoundedString(authoritative.upstream_model, 256)
  ) {
    return null;
  }

  if (canonical(cached) !== canonical(authoritative)) {
    try {
      await env.CONFIG_CACHE.put(
        `model:${model}`,
        JSON.stringify(authoritative),
        { expirationTtl: 300 },
      );
    } catch {
      // A cache write cannot make an authoritative D1 result unavailable.
    }
  }
  return authoritative;
}

async function decryptCredentials(
  envelope: string,
  env: Env,
): Promise<Record<string, string> | null> {
  return decryptAPIKeyCredentials(envelope, env as unknown as RuntimeEnv);
}

function parseObject(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

type SchedulerSemanticIdentity = Pick<
  BillingIdentity,
  | "request_id"
  | "user_id"
  | "api_key_id"
  | "group_id"
  | "account_id"
  | "owner"
  | "model"
  | "upstream_model"
  | "pricing_version_id"
  | "pricing_digest"
  | "pricing_model"
  | "pricing_rule_pattern"
  | "pricing_rule_match_kind"
  | "rate_multiplier_bps"
  | "reservation_e8_usd"
>;

function sameSchedulerSemanticIdentity(
  left: SchedulerSemanticIdentity,
  right: SchedulerSemanticIdentity,
): boolean {
  return left.request_id === right.request_id &&
    left.user_id === right.user_id &&
    left.api_key_id === right.api_key_id &&
    left.group_id === right.group_id &&
    left.account_id === right.account_id &&
    left.owner === right.owner &&
    left.model === right.model &&
    left.upstream_model === right.upstream_model &&
    left.pricing_version_id === right.pricing_version_id &&
    left.pricing_digest === right.pricing_digest &&
    left.pricing_model === right.pricing_model &&
    left.pricing_rule_pattern === right.pricing_rule_pattern &&
    left.pricing_rule_match_kind === right.pricing_rule_match_kind &&
    left.rate_multiplier_bps === right.rate_multiplier_bps &&
    left.reservation_e8_usd === right.reservation_e8_usd;
}

async function schedulerFingerprint(value: SchedulerSemanticIdentity): Promise<string> {
  return sha256(canonical({
    scheduler_admission_version: 1,
    request_id: value.request_id,
    user_id: value.user_id,
    api_key_id: value.api_key_id,
    group_id: value.group_id,
    account_id: value.account_id,
    owner: value.owner,
    model: value.model,
    upstream_model: value.upstream_model,
    pricing_version_id: value.pricing_version_id,
    pricing_digest: value.pricing_digest,
    pricing_model: value.pricing_model,
    pricing_rule_pattern: value.pricing_rule_pattern,
    pricing_rule_match_kind: value.pricing_rule_match_kind,
    rate_multiplier_bps: value.rate_multiplier_bps,
    reservation_e8_usd: value.reservation_e8_usd,
  }));
}

function confirmedRate(
  account: SchedulerAccount,
  field: "accountRpmLimit" | "userRpmLimit",
): number | null {
  const value = account[field];
  return value.kind === "confirmed" && Number.isInteger(value.value)
    ? value.value
    : null;
}

async function releaseSchedulerReservation(
  env: Env,
  row: BillingRow,
  rollbackRates = false,
): Promise<string[]> {
  if (row.scheduler_release_state === "released") return [];
  const fingerprint = await schedulerFingerprint(row);
  const finishRates = rollbackRates ? rollbackSchedulerRates : settleSchedulerRates;
  let failures: string[];
  try {
    failures = await finishRates(env, {
      accountId: row.account_id,
      userId: row.user_id,
      apiKeyId: row.api_key_id,
      admissionId: row.request_id,
      requestId: row.request_id,
      admissionFingerprint: fingerprint,
    });
  } catch {
    failures = ["scheduler_rate_release"];
  }
  const stub = env.ACCOUNT_LEASE.get(
    env.ACCOUNT_LEASE.idFromName(`account:${row.account_id}`),
  );
  let released = false;
  for (let attempt = 0; attempt < 2 && !released; attempt += 1) {
    try {
      const response = await stub.fetch("https://lease/release", {
        method: "POST",
        body: JSON.stringify({
          account_id: row.account_id,
          request_id: row.request_id,
          lease_id: row.lease_id,
          owner: row.owner,
          epoch: row.lease_epoch,
        }),
      });
      await response.text();
      released = response.ok;
    } catch {
      // Exact identity makes this bounded retry safe.
    }
  }
  if (!released) failures.push("account_lease_release");

  const attemptedAt = now();
  try {
    await env.DB.prepare(
      `UPDATE billing_reservations
       SET scheduler_release_attempts=scheduler_release_attempts+1,
           scheduler_release_last_at=?,
           scheduler_release_state=CASE WHEN ?=1 THEN 'released' ELSE scheduler_release_state END,
           scheduler_released_at=CASE
             WHEN ?=1 THEN COALESCE(scheduler_released_at,?)
             ELSE scheduler_released_at
           END
       WHERE request_id=? AND scheduler_release_state='pending'`,
    ).bind(
      attemptedAt,
      failures.length === 0 ? 1 : 0,
      failures.length === 0 ? 1 : 0,
      attemptedAt,
      row.request_id,
    ).run();
    const persisted = await env.DB.prepare(
      "SELECT scheduler_release_state FROM billing_reservations WHERE request_id=?",
    ).bind(row.request_id).first<{
      scheduler_release_state: "pending" | "released";
    }>();
    if (persisted?.scheduler_release_state === "released") return [];
    if (failures.length === 0) failures.push("scheduler_release_persistence");
  } catch {
    failures.push("scheduler_release_persistence");
  }
  return failures;
}

async function admitRequest(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{
    request_id?: unknown;
    api_key_id?: unknown;
    group_id?: unknown;
    model?: unknown;
    lease_ttl_seconds?: unknown;
  }>(request);
  const owner = request.headers.get("X-Sub2API-Container-Id");
  if (
    !body ||
    !isBoundedString(body.request_id, 256) ||
    !isCanonicalPositiveDecimal(body.api_key_id) ||
    body.api_key_id.length > 20 ||
    !isCanonicalPositiveDecimal(body.group_id) ||
    body.group_id.length > 20 ||
    !isBoundedString(body.model, 256) ||
    !isBoundedString(owner, 256) ||
    !Number.isInteger(body.lease_ttl_seconds) ||
    Number(body.lease_ttl_seconds) < 3 ||
    Number(body.lease_ttl_seconds) > 3600
  ) {
    return error("ADMISSION_REJECTED", 429);
  }

  // Re-read all revocable authority at admission time. The earlier auth resolve
  // is not trusted across a disable, expiry, group, or balance change window.
  const auth = await fetchAuthRowByID(body.api_key_id, env);
  // D1 reservation, not this preflight snapshot, is the exact monetary
  // authority. Allow idempotent replays at zero available balance and let the
  // guarded reserve return the authoritative insufficient-balance outcome.
  if (!auth || !permittedAuth(auth, body.group_id, false)) {
    return error("ADMISSION_REJECTED", 429);
  }

  const mapped = await resolveAlias(body.model, env);
  if (!mapped) return error("ADMISSION_REJECTED", 429);
  const existingBilling = await env.DB.prepare(
    `SELECT ${billingColumns} FROM billing_reservations WHERE request_id=?`,
  ).bind(body.request_id).first<BillingRow>();
  if (existingBilling && (
    existingBilling.user_id !== auth.user_id ||
    existingBilling.api_key_id !== body.api_key_id ||
    existingBilling.group_id !== body.group_id ||
    existingBilling.owner !== owner ||
    existingBilling.model !== body.model ||
    existingBilling.upstream_model !== mapped.upstream_model ||
    (existingBilling.state !== "reserved" && existingBilling.state !== "started")
  )) {
    return error("ADMISSION_REJECTED", 409);
  }
  let priceCard;
  const pricingModel = normalizePricingModel(body.model);
  const rate = await env.DB.prepare("SELECT rate_multiplier_bps FROM groups WHERE id=? AND status='active' AND deleted_at IS NULL")
    .bind(body.group_id).first<{ rate_multiplier_bps: string }>();
  try {
    priceCard = existingBilling
      ? await loadAdmittedPriceCard(
          env,
          existingBilling.pricing_version_id,
          existingBilling.pricing_digest,
          existingBilling.pricing_model,
          existingBilling.pricing_rule_pattern,
          existingBilling.pricing_rule_match_kind,
        )
      : await lookupAdmissionPriceCard(env, body.model);
  } catch {
    return error("PRICING_UNAVAILABLE", 503);
  }
  if (!pricingModel || !rate || !isCanonicalPositiveDecimal(rate.rate_multiplier_bps) || rate.rate_multiplier_bps.length > 8) {
    return error("PRICING_UNAVAILABLE", 503);
  }

  const scheduling = await decideSchedulerRuntime(env, {
    nowMs: Date.now(),
    userId: auth.user_id,
    apiKeyId: body.api_key_id,
    requiredGroup: body.group_id,
    platform: "openai",
    accountType: "apikey",
    model: body.model,
    stickinessKey: body.request_id,
  });
  if (!existingBilling && (!scheduling.ready || scheduling.decision.selectedAccountId === null)) {
    return error("ADMISSION_REJECTED", 429);
  }
  const selectedAccountID = existingBilling?.account_id ?? scheduling.decision.selectedAccountId;
  if (selectedAccountID === null) return error("ADMISSION_REJECTED", 429);
  const selected = scheduling.snapshot.policyRequest.accounts.find(
    (candidate) => candidate.accountId === selectedAccountID,
  );
  if (!selected) return error("ADMISSION_REJECTED", 429);

  const account = await env.DB.prepare(
    `SELECT
       a.id,a.name,a.platform,a.type,a.max_concurrency,
       a.credential_envelope,a.extra_json
     FROM accounts a
     JOIN account_groups ag ON ag.account_id=a.id
     WHERE a.id=? AND ag.group_id=?
       AND a.status='active'
       AND a.schedulable=1
       AND a.deleted_at IS NULL
       AND a.platform='openai'
       AND a.type='apikey'
     LIMIT 1`,
  )
    .bind(selectedAccountID, body.group_id)
    .first<Account>();
  if (
    !account ||
    !isCanonicalPositiveDecimal(account.id) ||
    account.id.length > 20 ||
    !Number.isInteger(account.max_concurrency) ||
    account.max_concurrency < 1
  ) {
    return error("ADMISSION_REJECTED", 429);
  }

  const credential = await decryptCredentials(account.credential_envelope, env);
  const extra = parseObject(account.extra_json);
  if (!credential || !extra) return error("ADMISSION_REJECTED", 429);

  const accountRpmLimit = confirmedRate(selected, "accountRpmLimit");
  const userRpmLimit = confirmedRate(selected, "userRpmLimit");
  const apiKeyRpmLimit = scheduling.snapshot.apiKeyRate.limit.kind === "confirmed"
    ? scheduling.snapshot.apiKeyRate.limit.value
    : null;
  if (accountRpmLimit === null || userRpmLimit === null || apiKeyRpmLimit === null) {
    return error("ADMISSION_REJECTED", 429);
  }
  const semantic: SchedulerSemanticIdentity = {
    request_id: body.request_id,
    user_id: auth.user_id,
    api_key_id: body.api_key_id,
    group_id: body.group_id,
    account_id: account.id,
    owner,
    model: body.model,
    upstream_model: mapped.upstream_model,
    pricing_version_id: priceCard.version_id,
    pricing_digest: priceCard.digest,
    pricing_model: pricingModel,
    pricing_rule_pattern: priceCard.rule.model_pattern,
    pricing_rule_match_kind: priceCard.rule.match_kind,
    rate_multiplier_bps: existingBilling?.rate_multiplier_bps ?? rate.rate_multiplier_bps,
    reservation_e8_usd: priceCard.max_reservation_e8_usd,
  };
  if (existingBilling && !sameSchedulerSemanticIdentity(existingBilling, semantic)) {
    return error("ADMISSION_REJECTED", 409);
  }
  const fingerprint = await schedulerFingerprint(semantic);
  const schedulerReservation = await reserveSchedulerResources(env, {
    accountId: account.id,
    userId: auth.user_id,
    apiKeyId: body.api_key_id,
    admissionId: body.request_id,
    requestId: body.request_id,
    owner,
    maxConcurrency: account.max_concurrency,
    accountRpmLimit,
    userRpmLimit,
    apiKeyRpmLimit,
    leaseTtlSeconds: Number(body.lease_ttl_seconds),
    reservationTtlSeconds: Math.min(Number(body.lease_ttl_seconds), 60),
    admissionFingerprint: fingerprint,
  }, {
    reserve: async (lease) => {
      const identity: BillingIdentity = {
        ...semantic,
        lease_id: lease.lease_id,
        lease_epoch: lease.epoch,
      };
      let reservation;
      try {
        reservation = await billingStub(env, auth.user_id).reserve({
          ...identity,
          operation_id: `${body.request_id}:reserve`,
        });
      } catch {
        // The scheduler owns compensation for this unknown-authority outcome.
        throw new Error("billing reservation authority unknown");
      }
      if (reservation.kind !== "ok" ||
          (reservation.state !== "reserved" && reservation.state !== "started")) {
        if (reservation.kind === "stale_pricing") {
          return { ok: false, status: 503, failedStep: "billing_stale_pricing" };
        }
        if (reservation.kind === "insufficient") {
          return { ok: false, status: 402, failedStep: "billing_insufficient" };
        }
        return {
          ok: false,
          status: reservation.kind === "unavailable" ? 503 : 409,
          failedStep: reservation.kind === "unavailable"
            ? "billing_unavailable"
            : "billing_conflict",
          authorityUnknown: reservation.kind === "unavailable",
        };
      }
      return { ok: true };
    },
    release: async (lease) => {
      const identity: BillingIdentity = {
        ...semantic,
        lease_id: lease.lease_id,
        lease_epoch: lease.epoch,
      };
      try {
        const released = await billingStub(env, auth.user_id).release({
          ...identity,
          operation_id: `${body.request_id}:admission-compensate`,
        });
        return released.kind === "ok";
      } catch {
        return false;
      }
    },
  });
  if (!schedulerReservation.ok) {
    if (schedulerReservation.compensationFailures.length > 0) {
      return error("ADMISSION_RECONCILIATION_REQUIRED", 503);
    }
    if (schedulerReservation.failedStep === "billing_insufficient") {
      return error("INSUFFICIENT_BALANCE", 402);
    }
    if (schedulerReservation.failedStep === "billing_stale_pricing") {
      return error("PRICING_UNAVAILABLE", 503);
    }
    if (schedulerReservation.status === 409) return error("ADMISSION_REJECTED", 409);
    return schedulerReservation.status === 503
      ? error("ADMISSION_UNAVAILABLE", 503)
      : error("ADMISSION_REJECTED", 429);
  }

  return json({
    account: {
      id: account.id,
      name: account.name,
      platform: account.platform,
      type: account.type,
      concurrency: account.max_concurrency,
      credentials: credential,
      extra,
    },
    upstream_model: mapped.upstream_model,
    price_card: priceCard,
    lease: schedulerReservation.lease,
  });
}

async function relayLeaseAction(
  request: Request,
  env: Env,
  path: "/renew" | "/release",
): Promise<Response> {
  const data = await readJson<Record<string, unknown>>(request);
  const owner = request.headers.get("X-Sub2API-Container-Id");
  if (
    !data ||
    !isCanonicalPositiveDecimal(data.account_id) ||
    data.account_id.length > 20 ||
    !isBoundedString(data.request_id, 256) ||
    !isBoundedString(data.lease_id, 256) ||
    !isCanonicalPositiveDecimal(data.epoch) ||
    data.epoch.length > 20 ||
    !isBoundedString(owner, 256) ||
    data.owner !== owner ||
    (path === "/renew" &&
      (!Number.isInteger(data.ttl_seconds) ||
        Number(data.ttl_seconds) < 3 ||
        Number(data.ttl_seconds) > 3600))
  ) {
    return error("LEASE_IDENTITY_REJECTED", 409);
  }

  if (path === "/release") {
    let billing = await env.DB.prepare(`SELECT ${billingColumns} FROM billing_reservations WHERE request_id=?`)
      .bind(data.request_id).first<BillingRow>();
    if (!billing || billing.account_id !== data.account_id || billing.lease_id !== data.lease_id ||
      billing.lease_epoch !== data.epoch || billing.owner !== owner) {
      return error("LEASE_IDENTITY_REJECTED", 409);
    }
    const expireStarted = async (row: BillingRow) => billingStub(env, row.user_id).expire({
      ...billingIdentity(row),
      operation_id: `${row.request_id}:release-started:${row.version}`,
      expected_reservation_version: String(row.version),
      reason: "crash",
      evidence_digest: await sha256(canonical({
        scheduler_release_version: 1,
        request_id: row.request_id,
        reservation_version: String(row.version),
        reason: "request-release",
      })),
    });
    let released = billing.state === "started"
      ? await expireStarted(billing)
      : await billingStub(env, billing.user_id).release({
          ...billingIdentity(billing),
          operation_id: `${billing.request_id}:release`,
        });
    if (released.kind === "out_of_order") {
      const current = await env.DB.prepare(
        `SELECT ${billingColumns} FROM billing_reservations WHERE request_id=?`,
      ).bind(data.request_id).first<BillingRow>();
      if (current && current.state === "started" &&
          sameSchedulerSemanticIdentity(current, billing) &&
          current.lease_id === billing.lease_id && current.lease_epoch === billing.lease_epoch) {
        billing = current;
        released = await expireStarted(current);
      }
    }
    if (released.kind !== "ok") return error("RESERVATION_TRANSITION_REJECTED", 409);
    const failures = await releaseSchedulerReservation(
      env,
      billing,
      billing.state === "reserved" || billing.state === "released",
    );
    return failures.length === 0
      ? json({ released: true })
      : error("ADMISSION_RECONCILIATION_REQUIRED", 503);
  }

  return env.ACCOUNT_LEASE.get(
    env.ACCOUNT_LEASE.idFromName(`account:${data.account_id}`),
  ).fetch(`https://lease${path}`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

async function startRequest(request: Request, env: Env): Promise<Response> {
  const body = await readJson<Record<string, unknown>>(request);
  const owner = request.headers.get("X-Sub2API-Container-Id");
  if (!body || !isBoundedString(body.request_id, 256) ||
    !isCanonicalPositiveDecimal(body.api_key_id) || !isCanonicalPositiveDecimal(body.account_id) ||
    !isBoundedString(body.lease_id, 256) || !isCanonicalPositiveDecimal(body.lease_epoch) ||
    !isBoundedString(body.model, 256) || !isBoundedString(body.upstream_model, 256) ||
    !isBoundedString(owner, 256)) return error("INVALID_REQUEST");
  const billing = await env.DB.prepare(`SELECT ${billingColumns} FROM billing_reservations WHERE request_id=?`)
    .bind(body.request_id).first<BillingRow>();
  const gateway = await env.DB.prepare("SELECT model,upstream_model FROM gateway_requests WHERE request_id=?")
    .bind(body.request_id).first<{model:string;upstream_model:string}>();
  if (!billing || !gateway || billing.api_key_id !== body.api_key_id ||
    billing.account_id !== body.account_id || billing.lease_id !== body.lease_id ||
    billing.lease_epoch !== body.lease_epoch || billing.owner !== owner ||
    gateway.model !== body.model || gateway.upstream_model !== body.upstream_model) {
    return error("REQUEST_IDENTITY_MISMATCH", 409);
  }
  const result = await billingStub(env, billing.user_id).start({
    ...billingIdentity(billing),
    operation_id: `${billing.request_id}:start`,
  });
  return result.kind === "ok"
    ? new Response(null, { status: 204 })
    : error(result.kind === "out_of_order" ? "REQUEST_OUT_OF_ORDER" : "REQUEST_IDENTITY_MISMATCH", 409);
}

const completionKeys = new Set([
  "schema_version",
  "event_type",
  "event_id",
  "request_id",
  "api_key_id",
  "account_id",
  "lease_id",
  "lease_epoch",
  "outcome",
  "usage_state",
  "input_tokens",
  "image_input_tokens",
  "output_tokens",
  "image_output_tokens",
  "cache_creation_tokens",
  "cache_creation_5m_tokens",
  "cache_creation_1h_tokens",
  "cache_read_tokens",
  "service_tier",
  "reasoning_effort",
  "model",
  "upstream_model",
  "upstream_request_id",
  "duration_ms",
]);

export function validCompletion(value: unknown): value is Completion {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const body = value as Partial<Completion>;
  if (Object.keys(value).some((key) => !completionKeys.has(key))) return false;
  return (
    body.schema_version === USAGE_SCHEMA_VERSION &&
    body.event_type === USAGE_EVENT_TYPE &&
    isBoundedString(body.request_id, 256) &&
    body.event_id === `${body.request_id}:usage:v2` &&
    isCanonicalPositiveDecimal(body.api_key_id) &&
    body.api_key_id.length <= 20 &&
    isCanonicalPositiveDecimal(body.account_id) &&
    body.account_id.length <= 20 &&
    isBoundedString(body.lease_id, 256) &&
    isCanonicalPositiveDecimal(body.lease_epoch) &&
    body.lease_epoch.length <= 20 &&
    (body.outcome === "succeeded" || body.outcome === "failed") &&
    (body.usage_state === "confirmed" || body.usage_state === "unknown") &&
    isCanonicalUnsignedDecimal(body.input_tokens) &&
    body.input_tokens.length <= 20 &&
    isCanonicalUnsignedDecimal(body.image_input_tokens) &&
    body.image_input_tokens.length <= 20 &&
    isCanonicalUnsignedDecimal(body.output_tokens) &&
    body.output_tokens.length <= 20 &&
    isCanonicalUnsignedDecimal(body.image_output_tokens) &&
    body.image_output_tokens.length <= 20 &&
    isCanonicalUnsignedDecimal(body.cache_creation_tokens) &&
    body.cache_creation_tokens.length <= 20 &&
    isCanonicalUnsignedDecimal(body.cache_creation_5m_tokens) &&
    body.cache_creation_5m_tokens.length <= 20 &&
    isCanonicalUnsignedDecimal(body.cache_creation_1h_tokens) &&
    body.cache_creation_1h_tokens.length <= 20 &&
    isCanonicalUnsignedDecimal(body.cache_read_tokens) &&
    body.cache_read_tokens.length <= 20 &&
    isBoundedString(body.service_tier, 32, 0) &&
    isBoundedString(body.reasoning_effort, 32, 0) &&
    isCanonicalUnsignedDecimal(body.duration_ms) &&
    body.duration_ms.length <= 20 &&
    isBoundedString(body.model, 256) &&
    isBoundedString(body.upstream_model, 256) &&
    (body.upstream_request_id === undefined ||
      isBoundedString(body.upstream_request_id, 512))
  );
}

async function recordConflict(
  env: Env,
  source: "completion" | "queue",
  eventID: string,
  existingHash: string,
  incomingHash: string,
): Promise<void> {
  await env.DB.prepare(
    `INSERT OR IGNORE INTO outbox_conflicts(
       source,event_id,existing_hash,incoming_hash,observed_at
     ) VALUES(?,?,?,?,?)`,
  )
    .bind(source, eventID, existingHash, incomingHash, now())
    .run();
}

async function completeRequest(request: Request, env: Env): Promise<Response> {
  const body = await readJson<unknown>(request);
  const owner = request.headers.get("X-Sub2API-Container-Id");
  if (!validCompletion(body) || !isBoundedString(owner, 256)) {
    return error("INVALID_REQUEST");
  }
  if (body.usage_state === "unknown" && (body.input_tokens !== "0" || body.image_input_tokens !== "0" || body.output_tokens !== "0" || body.image_output_tokens !== "0" || body.cache_creation_tokens !== "0" || body.cache_creation_5m_tokens !== "0" || body.cache_creation_1h_tokens !== "0" || body.cache_read_tokens !== "0")) return error("INVALID_USAGE", 409);

  const gatewayIdentity = await env.DB.prepare(
    `SELECT request_id,api_key_id,account_id,lease_id,lease_epoch,owner,
            model,upstream_model,pricing_version_id,pricing_digest,
            pricing_rule_pattern,state
     FROM gateway_requests WHERE request_id=?`,
  ).bind(body.request_id).first<GatewayIdentity>();
  if (!gatewayIdentity || gatewayIdentity.api_key_id !== body.api_key_id ||
    gatewayIdentity.account_id !== body.account_id || gatewayIdentity.lease_id !== body.lease_id ||
    gatewayIdentity.lease_epoch !== body.lease_epoch || gatewayIdentity.owner !== owner ||
    gatewayIdentity.model !== body.model || gatewayIdentity.upstream_model !== body.upstream_model) {
    return error("REQUEST_IDENTITY_MISMATCH", 409);
  }

  const payload = canonical(body);
  const payloadHash = await sha256(payload);
  const billing = await env.DB.prepare(`SELECT ${billingColumns} FROM billing_reservations WHERE request_id=?`)
    .bind(body.request_id).first<BillingRow>();
  if (!billing || billing.api_key_id !== body.api_key_id ||
    billing.account_id !== body.account_id || billing.lease_id !== body.lease_id ||
    billing.lease_epoch !== body.lease_epoch || billing.owner !== owner) {
    return error("REQUEST_IDENTITY_MISMATCH", 409);
  }
  if (billing.completion_event_id !== null || billing.completion_payload_hash !== null) {
    if (billing.completion_event_id !== body.event_id || billing.completion_payload_hash !== payloadHash) {
      await recordConflict(env, "completion", body.event_id, billing.completion_payload_hash ?? "missing", payloadHash);
      return error("EVENT_CONFLICT", 409);
    }
    if (billing.state === "completed" || billing.state === "unknown") {
      await releaseSchedulerReservation(env, billing);
      return new Response(null, { status: 204 });
    }
  }
  let chargedE8USD = "0";
  if (body.usage_state === "confirmed") {
    try {
      const card = await loadAdmittedPriceCard(
        env, billing.pricing_version_id, billing.pricing_digest, billing.pricing_model, billing.pricing_rule_pattern, billing.pricing_rule_match_kind,
      );
      const charge = calculateAdmittedE8Charge(card, {
        input_tokens: body.input_tokens, image_input_tokens: body.image_input_tokens ?? "0",
        output_tokens: body.output_tokens, image_output_tokens: body.image_output_tokens ?? "0",
        cache_creation_tokens: body.cache_creation_tokens ?? "0", cache_creation_5m_tokens: body.cache_creation_5m_tokens ?? "0",
        cache_creation_1h_tokens: body.cache_creation_1h_tokens ?? "0", cache_read_tokens: body.cache_read_tokens,
        service_tier: body.service_tier ?? "", reasoning_effort: body.reasoning_effort ?? "", rate_multiplier_bps: billing.rate_multiplier_bps,
      });
      // The reservation schema deliberately bounds monetary fields. An exact
      // over-cap calculation is preserved in the immutable usage payload; a
      // bounded one-unit-over sentinel drives the reservation to unknown for
      // explicit reconciliation without truncating or charging it.
      chargedE8USD = charge.exceeds_reservation_cap
        ? (BigInt(billing.reservation_e8_usd) + 1n).toString()
        : charge.total_e8_usd;
    } catch {
      return error("INVALID_USAGE", 409);
    }
  }
  const settlement = await billingStub(env, billing.user_id).complete({
    ...billingIdentity(billing),
    operation_id: `${billing.request_id}:complete`,
    final: true,
    usage_present: body.usage_state === "confirmed",
    charged_e8_usd: chargedE8USD,
    event_id: body.event_id,
    payload_hash: payloadHash,
    payload_json: payload,
    outcome: body.outcome,
    upstream_request_id: body.upstream_request_id,
  });
  if (settlement.kind !== "ok") {
    return error(settlement.kind === "out_of_order" ? "REQUEST_OUT_OF_ORDER" : "REQUEST_IDENTITY_MISMATCH", 409);
  }
  await releaseSchedulerReservation(env, billing);

  if (!settlement.replayed) {
    try {
      await withTimeout(
        publish(env, body.event_id, payload, payloadHash),
        PUBLISH_TIMEOUT_MS,
      );
    } catch {
      await recordPublishFailure(env, body.event_id).catch(() => undefined);
    }
  }
  return new Response(null, { status: 204 });
}

async function reconcileRequest(request: Request, env: Env): Promise<Response> {
  const body = await readJson<Record<string, unknown>>(request);
  const owner = request.headers.get("X-Sub2API-Container-Id");
  if (!body || Object.keys(body).some((key) => !["request_id", "operation_id", "actor_id", "expected_reservation_version", "decision", "charged_e8_usd", "evidence_digest"].includes(key)) ||
    !isBoundedString(body.request_id, 256) || !isBoundedString(body.operation_id, 300) ||
    !isBoundedString(body.actor_id, 256) || !isCanonicalPositiveDecimal(body.expected_reservation_version) ||
    (body.decision !== "charge" && body.decision !== "refund") ||
    typeof body.evidence_digest !== "string" || !/^[0-9a-f]{64}$/.test(body.evidence_digest) ||
    !isBoundedString(owner, 256) ||
    (body.decision === "charge" && (!isCanonicalUnsignedDecimal(body.charged_e8_usd) || body.charged_e8_usd.length > 18)) ||
    (body.decision === "refund" && body.charged_e8_usd !== undefined)) return error("INVALID_RECONCILIATION", 409);
  const billing = await env.DB.prepare(`SELECT ${billingColumns} FROM billing_reservations WHERE request_id=?`).bind(body.request_id).first<BillingRow>();
  if (!billing || billing.owner !== owner || billing.state !== "unknown") return error("REQUEST_OUT_OF_ORDER", 409);
  const result = await billingStub(env, billing.user_id).reconcile({
    ...billingIdentity(billing), operation_id: body.operation_id, actor_id: body.actor_id,
    expected_reservation_version: body.expected_reservation_version, decision: body.decision,
    ...(body.decision === "charge" ? { charged_e8_usd: body.charged_e8_usd } : {}), evidence_digest: body.evidence_digest,
  });
  if (result.kind !== "ok") {
    return error(result.kind === "out_of_order" ? "REQUEST_OUT_OF_ORDER" : "RECONCILIATION_REJECTED", 409);
  }
  const schedulerFailures = await releaseSchedulerReservation(env, billing);
  return schedulerFailures.length === 0
    ? new Response(null, { status: 204 })
    : error("ADMISSION_RECONCILIATION_REQUIRED", 503);
}

export async function recoverStaleAdmissions(
  env: Env,
  timeMs = Date.now(),
): Promise<void> {
  const cutoff = new Date(timeMs - ADMISSION_RECOVERY_AGE_MS).toISOString();
  const rows = (await env.DB.prepare(
    `SELECT ${billingColumns}
     FROM billing_reservations AS reservation
     WHERE reservation.scheduler_release_state='pending'
       AND (
         (
           reservation.state IN ('reserved','started')
           AND COALESCE(reservation.started_at,reservation.created_at)<=?
         )
         OR reservation.state IN ('completed','released','unknown')
       )
     ORDER BY
       CASE WHEN reservation.state IN ('reserved','started') THEN 0 ELSE 1 END,
       reservation.created_at,reservation.request_id
     LIMIT ?`,
  ).bind(cutoff, ADMISSION_RECOVERY_LIMIT).all<BillingRow>()).results;
  let failures = 0;
  for (const row of rows) {
    try {
      if (row.state === "reserved" || row.state === "started") {
        const evidenceDigest = await sha256(canonical({
          scheduler_recovery_version: 1,
          request_id: row.request_id,
          reservation_version: String(row.version),
          reason: "crash",
        }));
        const result = await billingStub(env, row.user_id).expire({
          ...billingIdentity(row),
          operation_id: `${row.request_id}:scheduler-recovery:${row.version}`,
          expected_reservation_version: String(row.version),
          reason: "crash",
          evidence_digest: evidenceDigest,
        });
        if (result.kind !== "ok") {
          if (result.kind === "unavailable") failures += 1;
          continue;
        }
      }
      const schedulerFailures = await releaseSchedulerReservation(
        env,
        row,
        row.state === "reserved" || row.state === "released",
      );
      if (schedulerFailures.length > 0) failures += 1;
    } catch {
      // A later scheduled delivery retries the same bounded, idempotent work.
      failures += 1;
    }
  }
  if (failures > 0) {
    throw new Error(`scheduler admission recovery incomplete: ${failures}`);
  }
}

function withTimeout<T>(promise: Promise<T>, milliseconds: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("operation timed out")),
      milliseconds,
    );
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (cause) => {
        clearTimeout(timer);
        reject(cause);
      },
    );
  });
}

async function recordPublishFailure(env: Env, eventID: string): Promise<void> {
  await env.DB.prepare(
    `UPDATE outbox_events
     SET attempts=attempts+1,
         last_attempt_at=?,
         state=CASE WHEN attempts+1>=? THEN 'dead' ELSE state END
     WHERE event_id=? AND state='pending'`,
  )
    .bind(now(), MAX_OUTBOX_ATTEMPTS, eventID)
    .run();
}

export async function publish(
  env: Env,
  eventID: string,
  payload: string,
  payloadHash: string,
): Promise<void> {
  await env.USAGE_QUEUE.send({
    event_id: eventID,
    payload,
    payload_hash: payloadHash,
  } satisfies UsageEnvelope);
  await env.DB.prepare(
    `UPDATE outbox_events
     SET state='published',published_at=?,last_attempt_at=?
     WHERE event_id=? AND payload_hash=? AND state='pending'`,
  )
    .bind(now(), now(), eventID, payloadHash)
    .run();
}

export async function drainOutbox(env: Env): Promise<void> {
  const events = await env.DB.prepare(
    `SELECT event_id,payload_json,payload_hash
     FROM outbox_events
     WHERE state='pending' AND attempts<?
     ORDER BY created_at,event_id
     LIMIT ?`,
  )
    .bind(MAX_OUTBOX_ATTEMPTS, OUTBOX_DRAIN_LIMIT)
    .all<{ event_id: string; payload_json: string; payload_hash: string }>();

  for (const event of events.results) {
    try {
      await withTimeout(
        publish(env, event.event_id, event.payload_json, event.payload_hash),
        PUBLISH_TIMEOUT_MS,
      );
    } catch {
      await recordPublishFailure(env, event.event_id).catch(() => undefined);
    }
  }
}

function retryMessage(message: Message<UsageEnvelope>): void {
  const delaySeconds = Math.min(300, 2 ** Math.min(message.attempts, 8));
  message.retry({ delaySeconds });
}

function parseUsageEnvelope(value: unknown): UsageEnvelope | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const envelope = value as Partial<UsageEnvelope>;
  if (
    !isBoundedString(envelope.event_id, 512) ||
    !isBoundedString(envelope.payload, MAX_CONTROL_BODY_BYTES) ||
    typeof envelope.payload_hash !== "string" ||
    !/^[a-f0-9]{64}$/.test(envelope.payload_hash)
  ) {
    return null;
  }
  return envelope as UsageEnvelope;
}

async function consumeUsageMessage(
  message: Message<UsageEnvelope>,
  env: Env,
): Promise<void> {
  const envelope = parseUsageEnvelope(message.body);
  if (!envelope) {
    retryMessage(message);
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(envelope.payload) as unknown;
  } catch {
    retryMessage(message);
    return;
  }
  if (
    !validCompletion(parsed) ||
    parsed.event_id !== envelope.event_id ||
    canonical(parsed) !== envelope.payload ||
    (await sha256(envelope.payload)) !== envelope.payload_hash
  ) {
    retryMessage(message);
    return;
  }

  // The durable outbox is the authoritative event payload. A caller with
  // Queue producer access must not be able to alter token counts while keeping
  // the request identity and event ID valid.
  const authoritative = await env.DB.prepare(
    `SELECT request_id,payload_json,payload_hash
     FROM outbox_events WHERE event_id=?`,
  )
    .bind(parsed.event_id)
    .first<{
      request_id: string;
      payload_json: string;
      payload_hash: string;
    }>();
  if (!authoritative) {
    retryMessage(message);
    return;
  }
  if (
    authoritative.request_id !== parsed.request_id ||
    authoritative.payload_json !== envelope.payload ||
    authoritative.payload_hash !== envelope.payload_hash
  ) {
    await recordConflict(
      env,
      "queue",
      parsed.event_id,
      authoritative.payload_hash,
      envelope.payload_hash,
    );
    message.ack();
    return;
  }

  const existing = await env.DB.prepare(
    "SELECT payload_hash FROM usage_events WHERE event_id=?",
  )
    .bind(parsed.event_id)
    .first<{ payload_hash: string }>();
  if (existing) {
    if (existing.payload_hash !== envelope.payload_hash) {
      await recordConflict(
        env,
        "queue",
        parsed.event_id,
        existing.payload_hash,
        envelope.payload_hash,
      );
    }
    message.ack();
    return;
  }

  const consumedAt = now();
  const results = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO usage_events(
         event_id,request_id,payload_hash,schema_version,event_type,
         api_key_id,account_id,lease_id,lease_epoch,model,upstream_model,
         upstream_request_id,outcome,usage_state,input_tokens,output_tokens,
         cache_read_tokens,duration_ms,created_at
       )
       SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
       FROM gateway_requests
       WHERE request_id=? AND api_key_id=? AND account_id=?
         AND lease_id=? AND lease_epoch=? AND event_id=? AND state=?
         AND NOT EXISTS(
           SELECT 1 FROM usage_events WHERE event_id=?
         )`,
    ).bind(
      parsed.event_id,
      parsed.request_id,
      envelope.payload_hash,
      parsed.schema_version,
      parsed.event_type,
      parsed.api_key_id,
      parsed.account_id,
      parsed.lease_id,
      parsed.lease_epoch,
      parsed.model,
      parsed.upstream_model,
      parsed.upstream_request_id ?? null,
      parsed.outcome,
      parsed.usage_state,
      parsed.input_tokens,
      parsed.output_tokens,
      parsed.cache_read_tokens,
      parsed.duration_ms,
      consumedAt,
      parsed.request_id,
      parsed.api_key_id,
      parsed.account_id,
      parsed.lease_id,
      parsed.lease_epoch,
      parsed.event_id,
      parsed.outcome,
      parsed.event_id,
    ),
    env.DB.prepare(
      `INSERT OR IGNORE INTO outbox_conflicts(
         source,event_id,existing_hash,incoming_hash,observed_at
       )
       SELECT 'queue',event_id,payload_hash,?,?
       FROM usage_events
       WHERE event_id=? AND payload_hash<>?`,
    ).bind(
      envelope.payload_hash,
      consumedAt,
      parsed.event_id,
      envelope.payload_hash,
    ),
  ]);

  if (
    (results[0].meta.changes ?? 0) === 1 ||
    (results[1].meta.changes ?? 0) === 1
  ) {
    message.ack();
    return;
  }

  const raced = await env.DB.prepare(
    "SELECT payload_hash FROM usage_events WHERE event_id=?",
  )
    .bind(parsed.event_id)
    .first<{ payload_hash: string }>();
  if (raced) {
    if (raced.payload_hash !== envelope.payload_hash) {
      await recordConflict(
        env,
        "queue",
        parsed.event_id,
        raced.payload_hash,
        envelope.payload_hash,
      );
    }
    message.ack();
    return;
  }

  // Most often this is an out-of-order delivery before the completion batch
  // became visible. A bounded Queue retry is safer than inventing usage state.
  retryMessage(message);
}

export async function consumeUsageBatch(
  batch: MessageBatch<UsageEnvelope>,
  env: Env,
): Promise<void> {
  for (const message of batch.messages) {
    try {
      await consumeUsageMessage(message, env);
    } catch {
      retryMessage(message);
    }
  }
}
