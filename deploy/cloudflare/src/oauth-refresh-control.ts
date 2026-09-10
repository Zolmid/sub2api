import {
  BRIDGE_VERSION,
  INTERNAL_HOST,
  error,
  isBoundedString,
  json,
  readJson,
} from "./contracts";
import {
  beginRefreshAttempt,
  commitRefreshSuccess,
  expireRefreshAttempt,
  fingerprintCredentialEnvelope,
  initializeCredentialFingerprint,
  markProviderStarted,
  recoverInvalidGrantRace,
  type OAuthRefreshAuthorityDO,
  type RefreshAuthorityInput,
  type RefreshLease,
  type RefreshResult,
} from "./oauth-refresh-runtime";

const MAX_TIME_MS = 4_102_444_800_000;
const MIN_LEASE_MS = 1_000;
const MAX_LEASE_MS = 300_000;
const MAX_ACCOUNT_ID = "9223372036854775807";
const MAX_OPERATION_ID = 120;
const MAX_CONTAINER_ID = 160;
const MAX_ENVELOPE_BYTES = 65_536;
const MAX_PRIVATE_BODY_BYTES = 70_000;
const ACCOUNT_ID = /^[1-9][0-9]{0,18}$/;
const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;

type JsonObject = Record<string, unknown>;
type AccountRow = {
  id: string;
  type: string;
  status: string;
  credential_envelope: string;
  credential_version: number;
  credential_fingerprint: string | null;
};
type AttemptRow = {
  operation_id: string;
  account_id: string;
  expected_credential_version: number;
  expected_credential_fingerprint: string;
  owner: string;
  fence: number;
  lease_expires_at_ms: number;
  state: "pre_provider" | "provider_started" | "succeeded" | "failed_retryable" | "manual_review" | "superseded";
};
type RefreshEnv = Env & {
  OAUTH_REFRESH_AUTHORITY: DurableObjectNamespace<OAuthRefreshAuthorityDO>;
};

const own = (value: object, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(value, key);
const object = (value: unknown): value is JsonObject =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const exactKeys = (value: JsonObject, required: readonly string[]): boolean =>
  Object.keys(value).length === required.length &&
  required.every((key) => own(value, key));

function validAccountId(value: unknown): value is string {
  return typeof value === "string" && ACCOUNT_ID.test(value) &&
    (value.length < MAX_ACCOUNT_ID.length || value <= MAX_ACCOUNT_ID);
}

function validOpaque(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= maximum &&
    value.trim() === value && OPAQUE.test(value);
}

function validTime(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) &&
    value >= 0 && value <= MAX_TIME_MS;
}

function validLease(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) &&
    value >= MIN_LEASE_MS && value <= MAX_LEASE_MS;
}

function validEnvelope(value: unknown): value is string {
  return typeof value === "string" &&
    new TextEncoder().encode(value).byteLength >= 1 &&
    new TextEncoder().encode(value).byteLength <= MAX_ENVELOPE_BYTES;
}

function invalid(): Response {
  return error("INVALID_OAUTH_REFRESH_REQUEST", 400);
}

function unavailable(): Response {
  return error("OAUTH_REFRESH_UNAVAILABLE", 503);
}

function resultResponse(result: RefreshResult, extra: JsonObject = {}): Response {
  if (result.kind === "non_refreshable") return error("OAUTH_REFRESH_NOT_FOUND", 404);
  if (result.kind === "busy" || result.kind === "conflict" ||
    result.kind === "stale_credential" || result.kind === "not_expired" ||
    result.kind === "manual_review" || result.kind === "retry_required") {
    return json({ result: result.kind, ...(result.state ? { state: result.state } : {}), ...extra }, 409);
  }
  return json({ result: result.kind, ...(result.state ? { state: result.state } : {}), ...extra });
}

async function payload(request: Request): Promise<JsonObject | null> {
  const parsed = await readJson<unknown>(request, MAX_PRIVATE_BODY_BYTES);
  return object(parsed) ? parsed : null;
}

async function loadAccount(db: D1Database, accountId: string): Promise<AccountRow | null> {
  return db.prepare(`SELECT id,type,status,credential_envelope,credential_version,credential_fingerprint
    FROM accounts WHERE id=?`).bind(accountId).first<AccountRow>();
}

async function refreshableAccount(db: D1Database, accountId: string, nowMs: number): Promise<AccountRow | null> {
  let account = await loadAccount(db, accountId);
  if (!account || account.type !== "oauth" || account.status !== "active") return null;
  if (account.credential_fingerprint === null) {
    const initialized = await initializeCredentialFingerprint(db, {
      accountId, expectedCredentialVersion: account.credential_version,
      expectedCredentialEnvelope: account.credential_envelope, nowMs,
    });
    if (initialized === "stale_credential") return null;
    account = await loadAccount(db, accountId);
  }
  return account?.credential_fingerprint ? account : null;
}

async function loadAttempt(db: D1Database, accountId: string, operationId: string): Promise<AttemptRow | null> {
  return db.prepare(`SELECT operation_id,account_id,expected_credential_version,
    expected_credential_fingerprint,owner,fence,lease_expires_at_ms,state
    FROM oauth_refresh_attempts WHERE operation_id=? AND account_id=?`)
    .bind(operationId, accountId).first<AttemptRow>();
}

async function hasManualReview(db: D1Database, accountId: string): Promise<boolean> {
  return (await db.prepare(`SELECT 1 FROM oauth_refresh_attempts
    WHERE account_id=? AND state='manual_review' LIMIT 1`).bind(accountId).first()) !== null;
}

function authority(attempt: AttemptRow, nowMs: number): RefreshAuthorityInput {
  return {
    accountId: attempt.account_id, expectedCredentialVersion: attempt.expected_credential_version,
    expectedCredentialFingerprint: attempt.expected_credential_fingerprint,
    operationId: attempt.operation_id, owner: attempt.owner, fence: attempt.fence, nowMs,
  };
}

function owner(request: Request): string | null {
  const value = request.headers.get("X-Sub2API-Container-Id");
  return validOpaque(value, MAX_CONTAINER_ID) ? value : null;
}

function authorityForOwner(attempt: AttemptRow | null, currentOwner: string, nowMs: number): RefreshAuthorityInput | null {
  return attempt && attempt.owner === currentOwner ? authority(attempt, nowMs) : null;
}

function authorityStub(env: RefreshEnv, accountId: string) {
  return env.OAUTH_REFRESH_AUTHORITY.getByName(accountId);
}

async function release(
  env: RefreshEnv,
  input: RefreshAuthorityInput,
  completedCredentialVersion: number | null,
): Promise<"finished" | "stale"> {
  return authorityStub(env, input.accountId).finish({
    accountId: input.accountId, operationId: input.operationId, owner: input.owner,
    fence: input.fence, nowMs: input.nowMs, completedCredentialVersion,
  });
}

async function compensate(env: RefreshEnv, input: RefreshAuthorityInput): Promise<void> {
  try {
    await release(env, input, null);
  } catch {
    // The original storage failure remains sanitized; no exception or metadata
    // is returned to the Container.
  }
}

async function acquireBegin(request: Request, env: RefreshEnv, currentOwner: string): Promise<Response> {
  const value = await payload(request);
  if (!value || !exactKeys(value, ["accountId", "operationId", "nowMs", "leaseMs"]) ||
    !validAccountId(value.accountId) || !validOpaque(value.operationId, MAX_OPERATION_ID) ||
    !validTime(value.nowMs) || !validLease(value.leaseMs) || value.nowMs > MAX_TIME_MS - value.leaseMs) return invalid();
  const account = await refreshableAccount(env.DB, value.accountId, value.nowMs);
  if (!account) return error("OAUTH_REFRESH_NOT_FOUND", 404);
  if (await hasManualReview(env.DB, account.id)) {
    return resultResponse({ kind: "manual_review", state: "manual_review" });
  }
  const lease = await authorityStub(env, account.id).acquire({
    accountId: account.id, credentialVersion: account.credential_version,
    operationId: value.operationId, owner: currentOwner, nowMs: value.nowMs, leaseMs: value.leaseMs,
  });
  if (lease.kind === "busy") return json({ result: "busy", retryAfterMs: lease.retryAfterMs }, 409);
  if (lease.kind === "account_mismatch") return unavailable();
  if (lease.kind === "already_refreshed") return json({ result: "already_refreshed" });
  const input: RefreshAuthorityInput = {
    accountId: account.id, expectedCredentialVersion: account.credential_version,
    expectedCredentialFingerprint: account.credential_fingerprint!, operationId: value.operationId,
    owner: currentOwner, fence: lease.fence, nowMs: value.nowMs,
  };
  if (lease.predecessor) {
    const predecessor = await loadAttempt(env.DB, account.id, lease.predecessor.operationId);
    if (!predecessor || predecessor.account_id !== lease.predecessor.accountId ||
      predecessor.expected_credential_version !== lease.predecessor.credentialVersion ||
      predecessor.owner !== lease.predecessor.owner || predecessor.fence !== lease.predecessor.fence ||
      predecessor.lease_expires_at_ms !== lease.predecessor.leaseExpiresAtMs) {
      await compensate(env, input);
      return unavailable();
    }
    const expired = await expireRefreshAttempt(env.DB, authority(predecessor, value.nowMs));
    if (expired.kind === "manual_review") {
      await compensate(env, input);
      return resultResponse(expired);
    }
    if (expired.kind !== "retry_required") {
      await compensate(env, input);
      return unavailable();
    }
  }
  const began = await beginRefreshAttempt(env.DB, { ...input, leaseExpiresAtMs: lease.leaseExpiresAtMs });
  if (began.kind !== "ready") await compensate(env, input);
  return resultResponse(began, began.kind === "ready" ? { fence: lease.fence, leaseExpiresAtMs: lease.leaseExpiresAtMs } : {});
}

async function markStarted(request: Request, env: RefreshEnv, currentOwner: string): Promise<Response> {
  const value = await payload(request);
  if (!value || !exactKeys(value, ["accountId", "operationId", "nowMs"]) ||
    !validAccountId(value.accountId) || !validOpaque(value.operationId, MAX_OPERATION_ID) || !validTime(value.nowMs)) return invalid();
  const input = authorityForOwner(await loadAttempt(env.DB, value.accountId, value.operationId), currentOwner, value.nowMs);
  if (!input) return error("OAUTH_REFRESH_NOT_FOUND", 404);
  return resultResponse(await markProviderStarted(env.DB, input));
}

async function commitSuccess(request: Request, env: RefreshEnv, currentOwner: string): Promise<Response> {
  const value = await payload(request);
  if (!value || !exactKeys(value, ["accountId", "operationId", "nowMs", "nextCredentialEnvelope"]) ||
    !validAccountId(value.accountId) || !validOpaque(value.operationId, MAX_OPERATION_ID) ||
    !validTime(value.nowMs) || !validEnvelope(value.nextCredentialEnvelope)) return invalid();
  const input = authorityForOwner(await loadAttempt(env.DB, value.accountId, value.operationId), currentOwner, value.nowMs);
  if (!input) return error("OAUTH_REFRESH_NOT_FOUND", 404);
  const attempt = await loadAttempt(env.DB, value.accountId, value.operationId);
  if (attempt?.state === "succeeded") {
    await release(env, input, input.expectedCredentialVersion + 1);
    return resultResponse({ kind: "already_completed", state: "succeeded" });
  }
  const account = await loadAccount(env.DB, input.accountId);
  if (!account || account.type !== "oauth" || account.status !== "active" ||
    account.credential_version !== input.expectedCredentialVersion ||
    account.credential_fingerprint !== input.expectedCredentialFingerprint) return resultResponse({ kind: "stale_credential" });
  const result = await commitRefreshSuccess(env.DB, {
    ...input, expectedCredentialEnvelope: account.credential_envelope,
    nextCredentialEnvelope: value.nextCredentialEnvelope,
    nextCredentialFingerprint: await fingerprintCredentialEnvelope(value.nextCredentialEnvelope),
  });
  if (result.kind === "committed" || result.kind === "already_completed") {
    const finished = await release(env, input, input.expectedCredentialVersion + 1);
    if (finished === "stale" && result.kind === "committed") return unavailable();
  }
  if (result.kind === "ready") return resultResponse({ kind: "conflict" });
  return resultResponse(result);
}

async function recoverInvalidGrant(request: Request, env: RefreshEnv, currentOwner: string): Promise<Response> {
  const value = await payload(request);
  if (!value || !exactKeys(value, ["accountId", "operationId", "nowMs"]) ||
    !validAccountId(value.accountId) || !validOpaque(value.operationId, MAX_OPERATION_ID) || !validTime(value.nowMs)) return invalid();
  const input = authorityForOwner(await loadAttempt(env.DB, value.accountId, value.operationId), currentOwner, value.nowMs);
  if (!input) return error("OAUTH_REFRESH_NOT_FOUND", 404);
  const result = await recoverInvalidGrantRace(env.DB, input);
  if (result.kind === "manual_review" || result.kind === "already_refreshed") await release(env, input, null);
  if (result.kind === "ready") return resultResponse({ kind: "conflict" });
  return resultResponse(result);
}

type Operation = (request: Request, env: RefreshEnv, currentOwner: string) => Promise<Response>;
const routes: Readonly<Record<string, Operation>> = {
  "/v1/private/oauth-refresh/acquire-begin": acquireBegin,
  "/v1/private/oauth-refresh/mark-provider-started": markStarted,
  "/v1/private/oauth-refresh/commit-success": commitSuccess,
  "/v1/private/oauth-refresh/recover-invalid-grant": recoverInvalidGrant,
};

/** Strict Container-to-Worker coordinator; it never invokes an OAuth provider. */
export async function oauthRefreshControlPlane(request: Request, unsafeEnv: Env): Promise<Response | null> {
  const url = new URL(request.url);
  const operation = routes[url.pathname];
  if (!operation) return null;
  const currentOwner = owner(request);
  if (url.hostname !== INTERNAL_HOST || request.method !== "POST" ||
    request.headers.get("X-Sub2API-Bridge-Version") !== BRIDGE_VERSION || !currentOwner ||
    !isBoundedString(currentOwner, MAX_CONTAINER_ID)) return error("NOT_FOUND", 404);
  try {
    return await operation(request, unsafeEnv as RefreshEnv, currentOwner);
  } catch {
    return unavailable();
  }
}
