import { DurableObject } from "cloudflare:workers";

/**
 * OAuth refresh authority. Worker provider adapters may hold encrypted
 * envelopes transiently for D1 CAS, but the DO, audit, outbox, witness,
 * results, and errors contain metadata and hashes only.
 */

const MAX_TIME_MS = 4_102_444_800_000;
const MIN_LEASE_MS = 1_000;
const MAX_LEASE_MS = 300_000;
export const MAX_REFRESH_COUNTER = 2_147_483_647;
const MAX_INT64_ACCOUNT_ID = "9223372036854775807";
const MAX_OPERATION_ID = 120;
const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;
const ACCOUNT_ID = /^[1-9][0-9]{0,18}$/u;
const FINGERPRINT = /^[0-9a-f]{64}$/u;

export type RefreshAttemptState =
  | "pre_provider" | "provider_started" | "succeeded"
  | "failed_retryable" | "manual_review" | "superseded";

type AttemptRow = {
  operation_id: string;
  account_id: string;
  expected_credential_version: number;
  expected_credential_fingerprint: string;
  owner: string;
  fence: number;
  lease_expires_at_ms: number;
  request_digest: string;
  state: RefreshAttemptState;
  terminal_at_ms: number | null;
  created_at_ms: number;
  updated_at_ms: number;
};

type AccountRow = {
  id: string;
  type: string;
  status: string;
  credential_envelope: string;
  credential_version: number;
  credential_fingerprint: string | null;
};

type WitnessRow = {
  operation_id: string;
};

export type RefreshLeaseRequest = Readonly<{
  accountId: string;
  credentialVersion: number;
  operationId: string;
  owner: string;
  nowMs: number;
  leaseMs: number;
}>;

export type RefreshLease =
  | Readonly<{ kind: "acquired"; fence: number; leaseExpiresAtMs: number; takeover: boolean }>
  | Readonly<{ kind: "busy"; retryAfterMs: number }>
  | Readonly<{ kind: "already_refreshed" }>;

export type RefreshFinish = Readonly<{
  accountId: string;
  operationId: string;
  owner: string;
  fence: number;
  nowMs: number;
  /** null releases a failed/abandoned lease; a success must be exactly +1. */
  completedCredentialVersion: number | null;
}>;

export type RefreshBeginInput = Readonly<{
  accountId: string;
  expectedCredentialVersion: number;
  expectedCredentialFingerprint: string;
  operationId: string;
  owner: string;
  fence: number;
  nowMs: number;
  leaseExpiresAtMs: number;
}>;

export type RefreshAuthorityInput = Readonly<{
  accountId: string;
  expectedCredentialVersion: number;
  expectedCredentialFingerprint: string;
  operationId: string;
  owner: string;
  fence: number;
  nowMs: number;
}>;

export type RefreshSuccessInput = RefreshAuthorityInput & Readonly<{
  expectedCredentialEnvelope: string;
  nextCredentialEnvelope: string;
  nextCredentialFingerprint: string;
}>;

export type RefreshResult = Readonly<{
  kind: "ready" | "already_started" | "committed" | "already_completed"
    | "busy" | "stale_credential" | "already_refreshed" | "non_refreshable"
    | "conflict" | "not_expired" | "manual_review" | "retry_required";
  state?: RefreshAttemptState;
}>;

export type OAuthRefreshLeaseState = Readonly<{
  accountId: string | null;
  owner: string | null;
  operationId: string | null;
  credentialVersion: number | null;
  fence: number;
  acquiredAtMs: number | null;
  leaseExpiresAtMs: number | null;
  lastCompletedCredentialVersion: number | null;
}>;

export type LeaseCoreResult =
  | RefreshLease
  | Readonly<{ kind: "finished" }>
  | Readonly<{ kind: "stale" }>;

function safeTime(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_TIME_MS;
}

function boundedCounter(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 1 && value <= MAX_REFRESH_COUNTER;
}

function assertAccountId(value: string): void {
  if (!ACCOUNT_ID.test(value) ||
    (value.length === MAX_INT64_ACCOUNT_ID.length && value > MAX_INT64_ACCOUNT_ID)) {
    throw new Error("INVALID_ACCOUNT_ID");
  }
}

function assertOpaque(value: string, maximum: number, field: string): void {
  if (value.length < 1 || value.length > maximum || value.trim() !== value || !OPAQUE.test(value)) {
    throw new Error(`INVALID_${field}`);
  }
}

function assertFingerprint(value: string, field: string): void {
  if (!FINGERPRINT.test(value)) throw new Error(`INVALID_${field}`);
}

function assertTime(value: number, field = "TIME"): void {
  if (!safeTime(value)) throw new Error(`INVALID_${field}`);
}

function assertLease(leaseMs: number): void {
  if (!Number.isSafeInteger(leaseMs) || leaseMs < MIN_LEASE_MS || leaseMs > MAX_LEASE_MS) {
    throw new Error("INVALID_LEASE");
  }
}

function assertAuthority(input: RefreshAuthorityInput): void {
  assertAccountId(input.accountId);
  assertOpaque(input.operationId, MAX_OPERATION_ID, "OPERATION_ID");
  assertOpaque(input.owner, 160, "OWNER");
  if (!boundedCounter(input.expectedCredentialVersion) || !boundedCounter(input.fence)) {
    throw new Error("INVALID_VERSION_OR_FENCE");
  }
  assertFingerprint(input.expectedCredentialFingerprint, "EXPECTED_FINGERPRINT");
  assertTime(input.nowMs);
}

function assertBegin(input: RefreshBeginInput): void {
  assertAuthority(input);
  assertTime(input.leaseExpiresAtMs, "LEASE_EXPIRY");
  if (input.leaseExpiresAtMs < input.nowMs + MIN_LEASE_MS) throw new Error("INVALID_LEASE_EXPIRY");
}

function assertEnvelope(value: string, field: string): void {
  if (value.length < 1 || value.length > 65_536) throw new Error(`INVALID_${field}`);
}

async function digest(value: string): Promise<string> {
  const output = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(output), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function semanticBeginContent(input: RefreshBeginInput): string {
  return JSON.stringify({
    account_id: input.accountId,
    expected_credential_fingerprint: input.expectedCredentialFingerprint,
    expected_credential_version: input.expectedCredentialVersion,
    fence: input.fence,
    lease_expires_at_ms: input.leaseExpiresAtMs,
    owner: input.owner,
  });
}

function attemptResult(row: AttemptRow): RefreshResult {
  if (row.state === "pre_provider") return { kind: "ready", state: row.state };
  if (row.state === "provider_started") return { kind: "already_started", state: row.state };
  if (row.state === "succeeded") return { kind: "already_completed", state: row.state };
  if (row.state === "failed_retryable") return { kind: "retry_required", state: row.state };
  if (row.state === "superseded") return { kind: "already_refreshed", state: row.state };
  return { kind: "manual_review", state: row.state };
}

async function loadAttempt(
  db: D1Database,
  input: Pick<RefreshAuthorityInput, "operationId" | "accountId" | "expectedCredentialVersion" | "expectedCredentialFingerprint">,
): Promise<AttemptRow | null> {
  return db.prepare(`SELECT operation_id,account_id,expected_credential_version,
    expected_credential_fingerprint,owner,fence,lease_expires_at_ms,request_digest,
    state,terminal_at_ms,created_at_ms,updated_at_ms FROM oauth_refresh_attempts
    WHERE operation_id=? AND account_id=? AND expected_credential_version=?
      AND expected_credential_fingerprint=?`)
    .bind(input.operationId, input.accountId, input.expectedCredentialVersion,
      input.expectedCredentialFingerprint).first<AttemptRow>();
}

async function loadAttemptByOperation(db: D1Database, operationId: string): Promise<Pick<AttemptRow, "request_digest"> | null> {
  return db.prepare("SELECT request_digest FROM oauth_refresh_attempts WHERE operation_id=?")
    .bind(operationId).first<Pick<AttemptRow, "request_digest">>();
}

async function loadAccount(db: D1Database, accountId: string): Promise<AccountRow | null> {
  return db.prepare(`SELECT id,type,status,credential_envelope,credential_version,
    credential_fingerprint FROM accounts WHERE id=?`).bind(accountId).first<AccountRow>();
}

function matchesAuthority(row: AttemptRow, input: RefreshAuthorityInput): boolean {
  return row.account_id === input.accountId &&
    row.expected_credential_version === input.expectedCredentialVersion &&
    row.expected_credential_fingerprint === input.expectedCredentialFingerprint &&
    row.owner === input.owner && row.fence === input.fence;
}

function timeAuthoritative(row: AttemptRow, nowMs: number): boolean {
  return nowMs >= row.updated_at_ms && nowMs < row.lease_expires_at_ms;
}

function refreshable(row: AccountRow): boolean {
  return row.type === "oauth" && row.status === "active";
}

function isExpectedUnique(error: unknown, table: string): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes(`UNIQUE constraint failed: ${table}.`);
}

export async function fingerprintCredentialEnvelope(envelope: string): Promise<string> {
  assertEnvelope(envelope, "CREDENTIAL_ENVELOPE");
  return digest(envelope);
}

export async function initializeCredentialFingerprint(
  db: D1Database,
  input: Readonly<{ accountId: string; expectedCredentialVersion: number; expectedCredentialEnvelope: string; nowMs: number }>,
): Promise<"initialized" | "already_initialized" | "stale_credential"> {
  assertAccountId(input.accountId);
  if (!boundedCounter(input.expectedCredentialVersion)) throw new Error("INVALID_VERSION");
  assertEnvelope(input.expectedCredentialEnvelope, "CREDENTIAL_ENVELOPE");
  assertTime(input.nowMs);
  const fingerprint = await fingerprintCredentialEnvelope(input.expectedCredentialEnvelope);
  const before = await loadAccount(db, input.accountId);
  if (!before || before.credential_version !== input.expectedCredentialVersion ||
    before.credential_envelope !== input.expectedCredentialEnvelope) return "stale_credential";
  if (before.credential_fingerprint !== null && before.credential_fingerprint !== fingerprint) return "stale_credential";
  const wasMatched = before.credential_fingerprint === fingerprint;
  const auditId = `fingerprint:${input.accountId}:${input.expectedCredentialVersion}:${fingerprint}`;
  try {
    await db.batch([
      db.prepare(`UPDATE accounts SET credential_fingerprint=?
        WHERE id=? AND credential_version=? AND credential_envelope=?
          AND credential_fingerprint IS NULL`)
        .bind(fingerprint, input.accountId, input.expectedCredentialVersion, input.expectedCredentialEnvelope),
      // Deliberately not OR IGNORE: a pre-existing deterministic audit id rolls
      // back the preceding account write unless it is the exact completed init.
      db.prepare(`INSERT INTO oauth_refresh_fingerprint_audit(
        audit_id,account_id,credential_version,credential_fingerprint,created_at_ms
      ) SELECT ?,id,credential_version,?,? FROM accounts
        WHERE id=? AND credential_version=? AND credential_fingerprint=?`)
        .bind(auditId, fingerprint, input.nowMs, input.accountId,
          input.expectedCredentialVersion, fingerprint),
    ]);
  } catch (error) {
    if (!isExpectedUnique(error, "oauth_refresh_fingerprint_audit")) throw error;
    const [account, audit] = await Promise.all([
      loadAccount(db, input.accountId),
      db.prepare(`SELECT audit_id FROM oauth_refresh_fingerprint_audit
        WHERE audit_id=? AND account_id=? AND credential_version=? AND credential_fingerprint=?`)
        .bind(auditId, input.accountId, input.expectedCredentialVersion, fingerprint).first(),
    ]);
    if (account?.credential_version === input.expectedCredentialVersion &&
      account.credential_envelope === input.expectedCredentialEnvelope &&
      account.credential_fingerprint === fingerprint && audit) return "already_initialized";
    throw new Error("FINGERPRINT_AUDIT_CONFLICT");
  }
  const account = await loadAccount(db, input.accountId);
  if (!account || account.credential_version !== input.expectedCredentialVersion ||
    account.credential_envelope !== input.expectedCredentialEnvelope) return "stale_credential";
  const audit = await db.prepare(`SELECT audit_id FROM oauth_refresh_fingerprint_audit
    WHERE audit_id=? AND account_id=? AND credential_version=? AND credential_fingerprint=?`)
    .bind(auditId, input.accountId, input.expectedCredentialVersion, fingerprint).first();
  if (account.credential_fingerprint === fingerprint && audit) return wasMatched ? "already_initialized" : "initialized";
  if (account.credential_fingerprint === fingerprint) {
    throw new Error("FINGERPRINT_AUDIT_MISSING");
  }
  return "stale_credential";
}

/**
 * Call order for a new operation: DO acquire -> terminalize any expired old
 * D1 attempt -> beginRefreshAttempt with that exact returned fence/expiry.
 * The D1 partial unique index rejects any second live operation for an account.
 */
export async function beginRefreshAttempt(db: D1Database, input: RefreshBeginInput): Promise<RefreshResult> {
  assertBegin(input);
  const requestDigest = await digest(semanticBeginContent(input));
  const sameOperation = await loadAttemptByOperation(db, input.operationId);
  if (sameOperation) {
    if (sameOperation.request_digest !== requestDigest) return { kind: "conflict" };
    const existing = await loadAttempt(db, input);
    return existing ? attemptResult(existing) : { kind: "conflict" };
  }

  const account = await loadAccount(db, input.accountId);
  if (!account || !refreshable(account)) return { kind: "non_refreshable" };
  if (account.credential_version !== input.expectedCredentialVersion ||
    account.credential_fingerprint !== input.expectedCredentialFingerprint) {
    return account.credential_version > input.expectedCredentialVersion ||
      account.credential_fingerprint !== input.expectedCredentialFingerprint
      ? { kind: "already_refreshed" } : { kind: "stale_credential" };
  }
  const live = await db.prepare(`SELECT operation_id FROM oauth_refresh_attempts
    WHERE account_id=? AND state IN ('pre_provider','provider_started')`)
    .bind(input.accountId).first();
  if (live) return { kind: "busy" };
  try {
    await db.batch([
      db.prepare(`INSERT INTO oauth_refresh_attempts(
        operation_id,account_id,expected_credential_version,expected_credential_fingerprint,
        owner,fence,lease_expires_at_ms,request_digest,state,terminal_at_ms,created_at_ms,updated_at_ms
      ) VALUES(?,?,?,?,?,?,?,?, 'pre_provider',NULL,?,?)`)
        .bind(input.operationId, input.accountId, input.expectedCredentialVersion,
          input.expectedCredentialFingerprint, input.owner, input.fence, input.leaseExpiresAtMs,
          requestDigest, input.nowMs, input.nowMs),
      db.prepare(`INSERT INTO oauth_refresh_audit(
        audit_id,operation_id,account_id,event,detail_digest,created_at_ms
      ) VALUES(?,?,?,'refresh_pre_provider',?,?)`)
        .bind(`begin:${input.operationId}`, input.operationId, input.accountId, requestDigest, input.nowMs),
    ]);
  } catch (error) {
    if (!isExpectedUnique(error, "oauth_refresh_attempts")) throw error;
    const active = await db.prepare(`SELECT 1 FROM oauth_refresh_attempts WHERE account_id=?
      AND state IN ('pre_provider','provider_started')`)
      .bind(input.accountId).first();
    return active ? { kind: "busy" } : { kind: "conflict" };
  }
  return { kind: "ready", state: "pre_provider" };
}

/** Mark immediately before a provider request. Later expiry is never retried blindly. */
export async function markProviderStarted(db: D1Database, input: RefreshAuthorityInput): Promise<RefreshResult> {
  assertAuthority(input);
  const attempt = await loadAttempt(db, input);
  if (!attempt || !matchesAuthority(attempt, input) || !timeAuthoritative(attempt, input.nowMs)) return { kind: "busy" };
  if (attempt.state === "provider_started") return { kind: "already_started", state: attempt.state };
  if (attempt.state !== "pre_provider") return attemptResult(attempt);
  const results = await db.batch([
    db.prepare(`UPDATE oauth_refresh_attempts SET state='provider_started',updated_at_ms=?
      WHERE operation_id=? AND account_id=? AND expected_credential_version=?
        AND expected_credential_fingerprint=? AND owner=? AND fence=?
        AND state='pre_provider' AND updated_at_ms<=? AND ?<lease_expires_at_ms`)
      .bind(input.nowMs, input.operationId, input.accountId, input.expectedCredentialVersion,
        input.expectedCredentialFingerprint, input.owner, input.fence, input.nowMs, input.nowMs),
    db.prepare(`INSERT INTO oauth_refresh_audit(
      audit_id,operation_id,account_id,event,detail_digest,created_at_ms
    ) SELECT ?,operation_id,account_id,'provider_started',request_digest,?
      FROM oauth_refresh_attempts WHERE operation_id=? AND account_id=?
        AND expected_credential_version=? AND expected_credential_fingerprint=?
        AND owner=? AND fence=? AND state='provider_started'
        AND changes()=1
        AND NOT EXISTS(SELECT 1 FROM oauth_refresh_audit WHERE audit_id=?)`)
      .bind(`provider-started:${input.operationId}`, input.nowMs, input.operationId, input.accountId,
        input.expectedCredentialVersion, input.expectedCredentialFingerprint, input.owner, input.fence,
        `provider-started:${input.operationId}`),
  ]);
  const current = await loadAttempt(db, input);
  if (!current || !matchesAuthority(current, input)) return { kind: "busy" };
  return results[0].meta.changes === 1 && current.state === "provider_started"
    ? { kind: "ready", state: "provider_started" } : attemptResult(current);
}

export async function expireRefreshAttempt(db: D1Database, input: RefreshAuthorityInput): Promise<RefreshResult> {
  assertAuthority(input);
  const attempt = await loadAttempt(db, input);
  if (!attempt || !matchesAuthority(attempt, input) || input.nowMs < attempt.updated_at_ms) return { kind: "busy" };
  if (input.nowMs < attempt.lease_expires_at_ms) return { kind: "not_expired", state: attempt.state };
  if (attempt.state !== "pre_provider" && attempt.state !== "provider_started") return attemptResult(attempt);
  const next: RefreshAttemptState = attempt.state === "pre_provider" ? "failed_retryable" : "manual_review";
  await db.batch([
    db.prepare(`UPDATE oauth_refresh_attempts SET state=?,terminal_at_ms=?,updated_at_ms=?
      WHERE operation_id=? AND account_id=? AND expected_credential_version=?
        AND expected_credential_fingerprint=? AND owner=? AND fence=? AND state=?
        AND updated_at_ms<=? AND lease_expires_at_ms<=?`)
      .bind(next, input.nowMs, input.nowMs, input.operationId, input.accountId,
        input.expectedCredentialVersion, input.expectedCredentialFingerprint, input.owner, input.fence,
        attempt.state, input.nowMs, input.nowMs),
    db.prepare(`INSERT INTO oauth_refresh_audit(
      audit_id,operation_id,account_id,event,detail_digest,created_at_ms
    ) SELECT ?,operation_id,account_id,?,request_digest,? FROM oauth_refresh_attempts
      WHERE operation_id=? AND account_id=? AND expected_credential_version=?
        AND expected_credential_fingerprint=? AND state=?
        AND changes()=1
        AND NOT EXISTS(SELECT 1 FROM oauth_refresh_audit WHERE audit_id=?)`)
      .bind(`expired:${input.operationId}`,
        next === "manual_review" ? "provider_result_unknown" : "expired_before_provider",
        input.nowMs, input.operationId, input.accountId, input.expectedCredentialVersion,
        input.expectedCredentialFingerprint, next, `expired:${input.operationId}`),
  ]);
  const current = await loadAttempt(db, input);
  return current && matchesAuthority(current, input) ? attemptResult(current) : { kind: "busy" };
}

async function exactWitnessExists(db: D1Database, input: RefreshSuccessInput): Promise<boolean> {
  if (input.expectedCredentialVersion >= MAX_REFRESH_COUNTER) throw new Error("COUNTER_OVERFLOW");
  const nextVersion = input.expectedCredentialVersion + 1;
  const row = await db.prepare(`SELECT w.operation_id FROM oauth_refresh_commit_witnesses w
    JOIN oauth_refresh_attempts a ON a.operation_id=w.operation_id
    JOIN oauth_refresh_audit au ON au.audit_id=w.audit_id
    JOIN oauth_refresh_invalidation_outbox o ON o.event_id=w.outbox_event_id
    WHERE w.operation_id=? AND w.account_id=? AND w.expected_credential_version=?
      AND w.expected_credential_fingerprint=? AND w.committed_credential_version=?
      AND w.committed_credential_fingerprint=? AND a.account_id=w.account_id
      AND a.expected_credential_version=w.expected_credential_version
      AND a.expected_credential_fingerprint=w.expected_credential_fingerprint
      AND a.owner=? AND a.fence=? AND a.state='succeeded'
      AND au.operation_id=w.operation_id AND au.account_id=w.account_id
      AND au.event='credential_cas_succeeded' AND au.detail_digest=a.request_digest AND o.operation_id=w.operation_id
      AND o.account_id=w.account_id AND o.credential_version=w.committed_credential_version
      AND o.event_type='oauth_credentials_invalidated'`)
    .bind(input.operationId, input.accountId, input.expectedCredentialVersion,
      input.expectedCredentialFingerprint, nextVersion, input.nextCredentialFingerprint,
      input.owner, input.fence)
    .first<WitnessRow>();
  return row !== null;
}

/** The final witness insert triggers an in-transaction all-or-nothing assertion. */
export async function commitRefreshSuccess(db: D1Database, input: RefreshSuccessInput): Promise<RefreshResult> {
  assertAuthority(input);
  assertEnvelope(input.expectedCredentialEnvelope, "EXPECTED_CREDENTIAL_ENVELOPE");
  assertEnvelope(input.nextCredentialEnvelope, "NEXT_CREDENTIAL_ENVELOPE");
  assertFingerprint(input.nextCredentialFingerprint, "NEXT_FINGERPRINT");
  if (await fingerprintCredentialEnvelope(input.expectedCredentialEnvelope) !== input.expectedCredentialFingerprint ||
    await fingerprintCredentialEnvelope(input.nextCredentialEnvelope) !== input.nextCredentialFingerprint ||
    input.expectedCredentialFingerprint === input.nextCredentialFingerprint) {
    throw new Error("CREDENTIAL_FINGERPRINT_MISMATCH");
  }
  if (input.expectedCredentialVersion >= MAX_REFRESH_COUNTER) throw new Error("COUNTER_OVERFLOW");
  if (await exactWitnessExists(db, input)) return { kind: "already_completed", state: "succeeded" };
  const attempt = await loadAttempt(db, input);
  if (!attempt || !matchesAuthority(attempt, input) || !timeAuthoritative(attempt, input.nowMs)) return { kind: "busy" };
  if (attempt.state === "succeeded") return { kind: "conflict" };
  if (attempt.state !== "provider_started") return attemptResult(attempt);
  const nextVersion = input.expectedCredentialVersion + 1;
  const auditId = `success:${input.operationId}`;
  const outboxId = `invalidate:${input.operationId}`;
  try {
    await db.batch([
      db.prepare(`UPDATE accounts SET credential_envelope=?,credential_fingerprint=?,
        credential_version=credential_version+1 WHERE id=? AND type='oauth' AND status='active'
        AND credential_version=? AND credential_fingerprint=? AND credential_envelope=?
        AND EXISTS(SELECT 1 FROM oauth_refresh_attempts WHERE operation_id=?
          AND account_id=? AND expected_credential_version=?
          AND expected_credential_fingerprint=? AND owner=? AND fence=?
          AND state='provider_started' AND updated_at_ms<=? AND ?<lease_expires_at_ms)`)
        .bind(input.nextCredentialEnvelope, input.nextCredentialFingerprint, input.accountId,
          input.expectedCredentialVersion, input.expectedCredentialFingerprint, input.expectedCredentialEnvelope,
          input.operationId, input.accountId, input.expectedCredentialVersion,
          input.expectedCredentialFingerprint, input.owner, input.fence, input.nowMs, input.nowMs),
      db.prepare(`UPDATE oauth_refresh_attempts SET state='succeeded',terminal_at_ms=?,updated_at_ms=?
        WHERE operation_id=? AND account_id=? AND expected_credential_version=?
          AND expected_credential_fingerprint=? AND owner=? AND fence=?
          AND state='provider_started' AND updated_at_ms<=? AND ?<lease_expires_at_ms
          AND EXISTS(SELECT 1 FROM accounts WHERE id=? AND credential_version=?
            AND credential_fingerprint=?)`)
        .bind(input.nowMs, input.nowMs, input.operationId, input.accountId,
          input.expectedCredentialVersion, input.expectedCredentialFingerprint, input.owner, input.fence,
          input.nowMs, input.nowMs, input.accountId, nextVersion, input.nextCredentialFingerprint),
      db.prepare(`INSERT INTO oauth_refresh_audit(
        audit_id,operation_id,account_id,event,detail_digest,created_at_ms
      ) SELECT ?,operation_id,account_id,'credential_cas_succeeded',request_digest,?
        FROM oauth_refresh_attempts WHERE operation_id=? AND account_id=?
          AND expected_credential_version=? AND expected_credential_fingerprint=? AND state='succeeded'`)
        .bind(auditId, input.nowMs, input.operationId, input.accountId,
          input.expectedCredentialVersion, input.expectedCredentialFingerprint),
      db.prepare(`INSERT INTO oauth_refresh_invalidation_outbox(
        event_id,operation_id,account_id,credential_version,event_type,state,created_at_ms
      ) SELECT ?,operation_id,account_id,?,'oauth_credentials_invalidated','pending',?
        FROM oauth_refresh_attempts WHERE operation_id=? AND account_id=?
          AND expected_credential_version=? AND expected_credential_fingerprint=? AND state='succeeded'`)
        .bind(outboxId, nextVersion, input.nowMs, input.operationId, input.accountId,
          input.expectedCredentialVersion, input.expectedCredentialFingerprint),
      db.prepare(`INSERT INTO oauth_refresh_commit_witnesses(
        operation_id,account_id,expected_credential_version,expected_credential_fingerprint,
        committed_credential_version,committed_credential_fingerprint,audit_id,outbox_event_id,created_at_ms
      ) VALUES(?,?,?,?,?,?,?,?,?)`)
        .bind(input.operationId, input.accountId, input.expectedCredentialVersion,
          input.expectedCredentialFingerprint, nextVersion, input.nextCredentialFingerprint,
          auditId, outboxId, input.nowMs),
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!isExpectedUnique(error, "oauth_refresh_commit_witnesses") &&
      !isExpectedUnique(error, "oauth_refresh_audit") &&
      !isExpectedUnique(error, "oauth_refresh_invalidation_outbox") &&
      !message.includes("oauth refresh commit witness invariant")) throw error;
    if (await exactWitnessExists(db, input)) return { kind: "already_completed", state: "succeeded" };
    const account = await loadAccount(db, input.accountId);
    return account && (account.credential_version > input.expectedCredentialVersion ||
      account.credential_fingerprint !== input.expectedCredentialFingerprint)
      ? { kind: "already_refreshed" } : { kind: "stale_credential" };
  }
  return { kind: "committed", state: "succeeded" };
}

export async function recoverInvalidGrantRace(db: D1Database, input: RefreshAuthorityInput): Promise<RefreshResult> {
  assertAuthority(input);
  const attempt = await loadAttempt(db, input);
  if (!attempt || !matchesAuthority(attempt, input) || input.nowMs < attempt.updated_at_ms) return { kind: "busy" };
  if (attempt.state !== "provider_started") return attemptResult(attempt);
  await db.batch([
    db.prepare(`UPDATE oauth_refresh_attempts SET state=CASE WHEN EXISTS(
        SELECT 1 FROM accounts WHERE id=? AND (credential_version>? OR credential_fingerprint<>?)
      ) THEN 'superseded' ELSE 'manual_review' END,terminal_at_ms=?,updated_at_ms=?
      WHERE operation_id=? AND account_id=? AND expected_credential_version=?
        AND expected_credential_fingerprint=? AND owner=? AND fence=?
        AND state='provider_started' AND updated_at_ms<=?`)
      .bind(input.accountId, input.expectedCredentialVersion, input.expectedCredentialFingerprint,
        input.nowMs, input.nowMs, input.operationId, input.accountId,
        input.expectedCredentialVersion, input.expectedCredentialFingerprint, input.owner, input.fence, input.nowMs),
    db.prepare(`INSERT INTO oauth_refresh_audit(
      audit_id,operation_id,account_id,event,detail_digest,created_at_ms
    ) SELECT ?,operation_id,account_id,CASE WHEN state='superseded'
      THEN 'invalid_grant_credential_advanced' ELSE 'invalid_grant_manual_review' END,request_digest,? FROM oauth_refresh_attempts
      WHERE operation_id=? AND account_id=? AND expected_credential_version=?
        AND expected_credential_fingerprint=? AND state IN ('superseded','manual_review')
        AND changes()=1
        AND NOT EXISTS(SELECT 1 FROM oauth_refresh_audit WHERE audit_id=?)`)
      .bind(`invalid-grant:${input.operationId}`,
        input.nowMs, input.operationId, input.accountId, input.expectedCredentialVersion,
        input.expectedCredentialFingerprint, `invalid-grant:${input.operationId}`),
  ]);
  const current = await loadAttempt(db, input);
  return current && matchesAuthority(current, input) ? attemptResult(current) : { kind: "busy" };
}

function initialLeaseState(): OAuthRefreshLeaseState {
  return {
    accountId: null, owner: null, operationId: null, credentialVersion: null, fence: 0,
    acquiredAtMs: null, leaseExpiresAtMs: null, lastCompletedCredentialVersion: null,
  };
}

function assertLeaseState(state: OAuthRefreshLeaseState): void {
  if (state.fence !== 0 && !boundedCounter(state.fence)) throw new Error("CORRUPT_DO_STATE");
  if (state.accountId === null) {
    if (state.owner !== null || state.operationId !== null || state.credentialVersion !== null ||
      state.acquiredAtMs !== null || state.leaseExpiresAtMs !== null ||
      state.lastCompletedCredentialVersion !== null || state.fence !== 0) throw new Error("CORRUPT_DO_STATE");
    return;
  }
  assertAccountId(state.accountId);
  if (state.lastCompletedCredentialVersion !== null && !boundedCounter(state.lastCompletedCredentialVersion)) {
    throw new Error("CORRUPT_DO_STATE");
  }
  const inactive = state.owner === null && state.operationId === null && state.credentialVersion === null &&
    state.acquiredAtMs === null && state.leaseExpiresAtMs === null;
  if (inactive) return;
  if (state.owner === null || state.operationId === null || state.credentialVersion === null ||
    state.acquiredAtMs === null || state.leaseExpiresAtMs === null || !boundedCounter(state.fence)) {
    throw new Error("CORRUPT_DO_STATE");
  }
  assertOpaque(state.owner, 160, "PERSISTED_OWNER");
  assertOpaque(state.operationId, MAX_OPERATION_ID, "PERSISTED_OPERATION_ID");
  if (!boundedCounter(state.credentialVersion) || !safeTime(state.acquiredAtMs) ||
    !safeTime(state.leaseExpiresAtMs) || state.leaseExpiresAtMs <= state.acquiredAtMs) {
    throw new Error("CORRUPT_DO_STATE");
  }
}

export function transitionOAuthRefreshLease(
  prior: OAuthRefreshLeaseState,
  action: Readonly<{ kind: "acquire"; input: RefreshLeaseRequest }> |
    Readonly<{ kind: "finish"; input: RefreshFinish }>,
): Readonly<{ state: OAuthRefreshLeaseState; result: LeaseCoreResult }> {
  assertLeaseState(prior);
  if (action.kind === "acquire") {
    const input = action.input;
    assertAccountId(input.accountId);
    assertOpaque(input.operationId, MAX_OPERATION_ID, "OPERATION_ID");
    assertOpaque(input.owner, 160, "OWNER");
    if (!boundedCounter(input.credentialVersion)) throw new Error("INVALID_VERSION");
    assertTime(input.nowMs);
    assertLease(input.leaseMs);
    if (input.nowMs > MAX_TIME_MS - input.leaseMs) throw new Error("INVALID_LEASE_EXPIRY");
    if (prior.accountId !== null && prior.accountId !== input.accountId) throw new Error("DO_ACCOUNT_MISMATCH");
    if (prior.lastCompletedCredentialVersion !== null &&
      input.credentialVersion <= prior.lastCompletedCredentialVersion) {
      return { state: prior, result: { kind: "already_refreshed" } };
    }
    const active = prior.owner !== null;
    if (active && input.nowMs < prior.acquiredAtMs!) throw new Error("STALE_DO_TIME");
    if (active && prior.leaseExpiresAtMs! > input.nowMs) {
      if (prior.owner === input.owner && prior.operationId === input.operationId &&
        prior.credentialVersion === input.credentialVersion) {
        return { state: prior, result: { kind: "acquired", fence: prior.fence,
          leaseExpiresAtMs: prior.leaseExpiresAtMs!, takeover: false } };
      }
      return { state: prior, result: { kind: "busy",
        retryAfterMs: Math.max(1, prior.leaseExpiresAtMs! - input.nowMs) } };
    }
    if (prior.fence >= MAX_REFRESH_COUNTER) throw new Error("COUNTER_OVERFLOW");
    const fence = prior.fence + 1;
    const expires = input.nowMs + input.leaseMs;
    const state: OAuthRefreshLeaseState = {
      accountId: input.accountId, owner: input.owner, operationId: input.operationId,
      credentialVersion: input.credentialVersion, fence, acquiredAtMs: input.nowMs,
      leaseExpiresAtMs: expires, lastCompletedCredentialVersion: prior.lastCompletedCredentialVersion,
    };
    return { state, result: { kind: "acquired", fence, leaseExpiresAtMs: expires, takeover: active } };
  }
  const input = action.input;
  assertAccountId(input.accountId);
  assertOpaque(input.operationId, MAX_OPERATION_ID, "OPERATION_ID");
  assertOpaque(input.owner, 160, "OWNER");
  if (!boundedCounter(input.fence)) throw new Error("INVALID_FENCE");
  assertTime(input.nowMs);
  if (prior.accountId !== input.accountId || prior.owner === null ||
    prior.owner !== input.owner || prior.operationId !== input.operationId ||
    prior.fence !== input.fence || input.nowMs < prior.acquiredAtMs! ||
    input.nowMs >= prior.leaseExpiresAtMs!) return { state: prior, result: { kind: "stale" } };
  if (input.completedCredentialVersion !== null) {
    if (!boundedCounter(input.completedCredentialVersion)) throw new Error("INVALID_COMPLETION_VERSION");
    if (prior.credentialVersion === MAX_REFRESH_COUNTER) throw new Error("COUNTER_OVERFLOW");
    if (input.completedCredentialVersion !== prior.credentialVersion! + 1) {
      throw new Error("INVALID_COMPLETION_VERSION");
    }
  }
  const state: OAuthRefreshLeaseState = {
    accountId: prior.accountId, owner: null, operationId: null, credentialVersion: null,
    fence: prior.fence, acquiredAtMs: null, leaseExpiresAtMs: null,
    lastCompletedCredentialVersion: input.completedCredentialVersion ?? prior.lastCompletedCredentialVersion,
  };
  return { state, result: { kind: "finished" } };
}

/** Metadata-only Durable Object wrapper around the deterministic lease core. */
export class OAuthRefreshAuthorityDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS oauth_refresh_lease (
      id INTEGER PRIMARY KEY CHECK(id=1), account_id TEXT, owner TEXT, operation_id TEXT,
      credential_version INTEGER CHECK(credential_version BETWEEN 1 AND 2147483647),
      fence INTEGER NOT NULL CHECK(fence BETWEEN 0 AND 2147483647), acquired_at_ms INTEGER,
      lease_expires_at_ms INTEGER,
      last_completed_credential_version INTEGER CHECK(last_completed_credential_version BETWEEN 1 AND 2147483647)
    )`);
  }

  private state(): OAuthRefreshLeaseState {
    const row = this.ctx.storage.sql.exec<{
      account_id: string | null; owner: string | null; operation_id: string | null;
      credential_version: number | null; fence: number; acquired_at_ms: number | null;
      lease_expires_at_ms: number | null; last_completed_credential_version: number | null;
    }>(`SELECT account_id,owner,operation_id,credential_version,fence,acquired_at_ms,
      lease_expires_at_ms,last_completed_credential_version FROM oauth_refresh_lease WHERE id=1`).toArray()[0];
    if (!row) return initialLeaseState();
    const state: OAuthRefreshLeaseState = {
      accountId: row.account_id, owner: row.owner, operationId: row.operation_id,
      credentialVersion: row.credential_version, fence: row.fence, acquiredAtMs: row.acquired_at_ms,
      leaseExpiresAtMs: row.lease_expires_at_ms, lastCompletedCredentialVersion: row.last_completed_credential_version,
    };
    assertLeaseState(state);
    return state;
  }

  private save(state: OAuthRefreshLeaseState): void {
    this.ctx.storage.sql.exec(`INSERT INTO oauth_refresh_lease(
      id,account_id,owner,operation_id,credential_version,fence,acquired_at_ms,
      lease_expires_at_ms,last_completed_credential_version
    ) VALUES(1,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
      account_id=excluded.account_id,owner=excluded.owner,operation_id=excluded.operation_id,
      credential_version=excluded.credential_version,fence=excluded.fence,
      acquired_at_ms=excluded.acquired_at_ms,lease_expires_at_ms=excluded.lease_expires_at_ms,
      last_completed_credential_version=excluded.last_completed_credential_version`,
      state.accountId, state.owner, state.operationId, state.credentialVersion, state.fence,
      state.acquiredAtMs, state.leaseExpiresAtMs, state.lastCompletedCredentialVersion);
  }

  async acquire(input: RefreshLeaseRequest): Promise<RefreshLease> {
    return this.ctx.storage.transactionSync(() => {
      const prior = this.state();
      const transition = transitionOAuthRefreshLease(prior, { kind: "acquire", input });
      if (transition.state !== prior) this.save(transition.state);
      return transition.result as RefreshLease;
    });
  }

  async finish(input: RefreshFinish): Promise<"finished" | "stale"> {
    return this.ctx.storage.transactionSync(() => {
      const transition = transitionOAuthRefreshLease(this.state(), { kind: "finish", input });
      if (transition.result.kind === "finished") this.save(transition.state);
      return transition.result.kind === "finished" ? "finished" : "stale";
    });
  }
}
