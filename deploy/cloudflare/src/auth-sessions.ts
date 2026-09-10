import {
  canonical,
  error,
  isBoundedString,
  json,
  readJson,
  sha256,
} from "./contracts";

const MAX_I64_TEXT = "9223372036854775807";
const HASH_RE = /^[0-9a-f]{64}$/;
const BINDING_HASH_RE = /^[0-9a-f]{32}$/;
const FAMILY_RE = /^[A-Za-z0-9._:-]+$/;
const UTC_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)$/;
const ROUTE_PREFIX = "/v1/auth-sessions/";

type Session = Readonly<{
  token_hash: string;
  user_id: string;
  token_version: string;
  family_id: string;
  binding_hash: string;
  created_at: string;
  expires_at: string;
}>;

type SessionRow = Session & Readonly<{
  status: "active" | "consumed" | "revoked" | "expired";
  consumed_at: string | null;
  replaced_by_token_hash: string | null;
  revoked_at: string | null;
  revoke_reason: "single" | "user" | "family" | "token_reuse" | null;
  family_revoked_at: string | null;
  family_revocation_reason: "family" | "token_reuse" | null;
}>;

type FailureCode =
  | "AUTH_SESSION_NOT_FOUND"
  | "AUTH_SESSION_EXPIRED"
  | "AUTH_SESSION_REVOKED"
  | "AUTH_SESSION_REUSE"
  | "AUTH_SESSION_CONFLICT";

type ActiveState =
  | Readonly<{ ok: true; row: SessionRow }>
  | Readonly<{ ok: false; code: FailureCode; status: 404 | 409 }>;

const SESSION_FIELDS = [
  "token_hash",
  "user_id",
  "token_version",
  "family_id",
  "binding_hash",
  "created_at",
  "expires_at",
] as const;

export function isAuthSessionsPath(pathname: string): boolean {
  return pathname.startsWith(ROUTE_PREFIX);
}

function isHash(value: unknown): value is string {
  return typeof value === "string" && HASH_RE.test(value);
}

function isCanonicalPositiveDecimal(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (!/^[1-9][0-9]*$/.test(value)) return false;
  return value.length < MAX_I64_TEXT.length ||
    (value.length === MAX_I64_TEXT.length && value <= MAX_I64_TEXT);
}

function isCanonicalNonNegativeDecimal(value: unknown): value is string {
  if (value === "0") return true;
  return isCanonicalPositiveDecimal(value);
}

function isBindingHash(value: unknown): value is string {
  return value === "" || (typeof value === "string" && BINDING_HASH_RE.test(value));
}

function isFamilyID(value: unknown): value is string {
  return isBoundedString(value, 128) &&
    FAMILY_RE.test(value) &&
    value.trim() === value;
}

function isUtc(value: unknown): value is string {
  if (typeof value !== "string" || !UTC_RE.test(value)) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.valueOf()) && parsed.toISOString() === value;
}

function stamp(): string {
  return new Date().toISOString();
}

function readRecord(
  value: unknown,
  allowed: readonly string[],
): Record<string, unknown> | null {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) {
      return null;
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string" || !allowed.includes(key))) {
      return null;
    }
    const output: Record<string, unknown> = {};
    for (const key of keys as string[]) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !("value" in descriptor)) return null;
      output[key] = descriptor.value;
    }
    return output;
  } catch {
    return null;
  }
}

function readSession(value: Record<string, unknown>): Session | null {
  if (
    !SESSION_FIELDS.every((field) => Object.hasOwn(value, field)) ||
    !isHash(value.token_hash) ||
    !isCanonicalPositiveDecimal(value.user_id) ||
    !isCanonicalNonNegativeDecimal(value.token_version) ||
    !isFamilyID(value.family_id) ||
    !isBindingHash(value.binding_hash) ||
    !isUtc(value.created_at) ||
    !isUtc(value.expires_at) ||
    value.created_at >= value.expires_at
  ) {
    return null;
  }
  return {
    token_hash: value.token_hash,
    user_id: value.user_id,
    token_version: value.token_version,
    family_id: value.family_id,
    binding_hash: value.binding_hash,
    created_at: value.created_at,
    expires_at: value.expires_at,
  };
}

function sessionMatches(row: SessionRow, session: Session): boolean {
  return row.token_hash === session.token_hash &&
    row.user_id === session.user_id &&
    row.token_version === session.token_version &&
    row.family_id === session.family_id &&
    row.binding_hash === session.binding_hash &&
    row.created_at === session.created_at &&
    row.expires_at === session.expires_at;
}

function ok(body: Record<string, unknown> = {}): Response {
  return json({ success: true, code: "OK", ...body });
}

function failure(code: FailureCode, status: 404 | 409): Response {
  return error(code, status);
}

async function detailHash(value: unknown): Promise<string> {
  return sha256(canonical(value));
}

async function loadSession(
  db: D1Database,
  tokenHash: string,
): Promise<SessionRow | null> {
  return db.prepare(
    `SELECT
       s.token_hash,
       s.user_id,
       s.token_version,
       s.family_id,
       s.binding_hash,
       s.status,
       s.created_at,
       s.expires_at,
       s.consumed_at,
       s.replaced_by_token_hash,
       s.revoked_at,
       s.revoke_reason,
       f.revoked_at AS family_revoked_at,
       f.reason AS family_revocation_reason
     FROM auth_sessions s
     LEFT JOIN auth_session_family_revocations f ON f.family_id=s.family_id
     WHERE s.token_hash=?`,
  ).bind(tokenHash).first<SessionRow>();
}

function classify(row: SessionRow | null, nowUtc: string): ActiveState {
  if (!row) return { ok: false, code: "AUTH_SESSION_NOT_FOUND", status: 404 };
  if (row.family_revoked_at !== null) {
    return {
      ok: false,
      code: row.family_revocation_reason === "token_reuse"
        ? "AUTH_SESSION_REUSE"
        : "AUTH_SESSION_REVOKED",
      status: 409,
    };
  }
  if (row.status === "revoked" || row.status === "consumed") {
    return { ok: false, code: "AUTH_SESSION_REVOKED", status: 409 };
  }
  if (row.status === "expired" || row.expires_at <= nowUtc) {
    return { ok: false, code: "AUTH_SESSION_EXPIRED", status: 404 };
  }
  return { ok: true, row };
}

function auditStatement(
  db: D1Database,
  eventType: string,
  auditID: string,
  detail: string,
  createdAt: string,
  tokenHash: string | null,
  userID: string | null,
  familyID: string | null,
): D1PreparedStatement {
  return db.prepare(
    `INSERT INTO auth_session_audit_events(
       audit_id,event_type,token_hash,user_id,family_id,detail_hash,created_at
     ) VALUES(?,?,?,?,?,?,?)`,
  ).bind(auditID, eventType, tokenHash, userID, familyID, detail, createdAt);
}

async function exactWitnessExists(
  db: D1Database,
  oldTokenHash: string,
  session: Session,
  detail: string,
): Promise<boolean> {
  const row = await db.prepare(
    `SELECT w.old_token_hash
     FROM auth_session_rotation_witnesses w
     JOIN auth_sessions old ON old.token_hash=w.old_token_hash
     JOIN auth_sessions new ON new.token_hash=w.new_token_hash
     WHERE w.old_token_hash=? AND w.new_token_hash=? AND w.detail_hash=?
       AND old.replaced_by_token_hash=?
       AND new.user_id=? AND new.token_version=? AND new.family_id=?
       AND new.binding_hash=? AND new.created_at=? AND new.expires_at=?`,
  ).bind(
    oldTokenHash,
    session.token_hash,
    detail,
    session.token_hash,
    session.user_id,
    session.token_version,
    session.family_id,
    session.binding_hash,
    session.created_at,
    session.expires_at,
  ).first<{ old_token_hash: string }>();
  return row !== null;
}

async function revokeFamily(
  db: D1Database,
  familyID: string,
  reason: "family" | "token_reuse",
  observedTokenHash: string | null,
  incomingTokenHash: string | null,
  at: string,
): Promise<void> {
  const detail = await detailHash({
    family_id: familyID,
    incoming_token_hash: incomingTokenHash,
    observed_token_hash: observedTokenHash,
    reason,
  });
  await db.batch([
    db.prepare(
      `INSERT OR IGNORE INTO auth_session_family_revocations(
         family_id,reason,revoked_at,detail_hash
       ) VALUES(?,?,?,?)`,
    ).bind(familyID, reason, at, detail),
    db.prepare(
      `UPDATE auth_sessions
       SET status='revoked', revoked_at=?, revoke_reason=?, updated_at=?
       WHERE family_id=? AND status='active'`,
    ).bind(at, reason, at, familyID),
    auditStatement(
      db,
      reason === "token_reuse" ? "reuse_detected" : "revoke_family",
      `authsess:${reason}:${crypto.randomUUID()}`,
      detail,
      at,
      observedTokenHash,
      null,
      familyID,
    ),
  ]);
}

async function store(request: Request, db: D1Database): Promise<Response> {
  const body = readRecord(await readJson(request), SESSION_FIELDS);
  const session = body ? readSession(body) : null;
  if (!session) return error("INVALID_REQUEST");

  const detail = await detailHash({ action: "store", session });
  try {
    const results = await db.batch([
      db.prepare(
        `INSERT INTO auth_sessions(
           token_hash,user_id,token_version,family_id,binding_hash,status,
           created_at,expires_at,updated_at
         )
         SELECT ?,?,?,?,?,'active',?,?,?
         WHERE NOT EXISTS(
           SELECT 1 FROM auth_session_family_revocations WHERE family_id=?
         )`,
      ).bind(
        session.token_hash,
        session.user_id,
        session.token_version,
        session.family_id,
        session.binding_hash,
        session.created_at,
        session.expires_at,
        session.created_at,
        session.family_id,
      ),
      db.prepare(
        `INSERT INTO auth_session_audit_events(
           audit_id,event_type,token_hash,user_id,family_id,detail_hash,created_at
         )
         SELECT ?,'store',token_hash,user_id,family_id,?,?
         FROM auth_sessions
         WHERE token_hash=? AND user_id=? AND family_id=? AND status='active'`,
      ).bind(
        `authsess:store:${session.token_hash}`,
        detail,
        session.created_at,
        session.token_hash,
        session.user_id,
        session.family_id,
      ),
    ]);
    if ((results[0].meta.changes ?? 0) !== 1) {
      return failure("AUTH_SESSION_CONFLICT", 409);
    }
  } catch {
    try {
      const existing = await loadSession(db, session.token_hash);
      if (!existing) return error("AUTH_SESSION_UNAVAILABLE", 503);
      const active = classify(existing, stamp());
      return active.ok && sessionMatches(active.row, session)
        ? ok()
        : failure("AUTH_SESSION_CONFLICT", 409);
    } catch {
      return error("AUTH_SESSION_UNAVAILABLE", 503);
    }
  }

  return ok();
}

async function get(request: Request, db: D1Database): Promise<Response> {
  const body = readRecord(await readJson(request), ["token_hash"]);
  if (!body || !isHash(body.token_hash)) return error("INVALID_REQUEST");
  const active = classify(await loadSession(db, body.token_hash), stamp());
  if (!active.ok) return failure(active.code, active.status);
  const { status: _status, consumed_at: _consumed, replaced_by_token_hash: _replaced, revoked_at: _revoked, revoke_reason: _reason, family_revoked_at: _familyAt, family_revocation_reason: _familyReason, ...session } = active.row;
  return json({ session });
}

async function contains(request: Request, db: D1Database): Promise<Response> {
  const body = readRecord(await readJson(request), ["family_id", "token_hash"]);
  if (!body || !isFamilyID(body.family_id) || !isHash(body.token_hash)) {
    return error("INVALID_REQUEST");
  }
  const active = classify(await loadSession(db, body.token_hash), stamp());
  const belongsToFamily = active.ok && active.row.family_id === body.family_id;
  return json({
    contains: belongsToFamily,
    code: belongsToFamily ? "OK" : active.ok ? "AUTH_SESSION_NOT_FOUND" : active.code,
  });
}

async function deleteSession(request: Request, db: D1Database): Promise<Response> {
  const body = readRecord(await readJson(request), ["token_hash"]);
  if (!body || !isHash(body.token_hash)) return error("INVALID_REQUEST");
  const at = stamp();
  const active = classify(await loadSession(db, body.token_hash), at);
  if (!active.ok) return failure(active.code, active.status);
  const detail = await detailHash({ action: "delete", token_hash: body.token_hash });
  const results = await db.batch([
    db.prepare(
      `UPDATE auth_sessions
       SET status='revoked', revoked_at=?, revoke_reason='single', updated_at=?
       WHERE token_hash=? AND status='active' AND expires_at>?
         AND NOT EXISTS(
           SELECT 1 FROM auth_session_family_revocations
           WHERE family_id=auth_sessions.family_id
         )`,
    ).bind(at, at, body.token_hash, at),
    auditStatement(
      db,
      "delete",
      `authsess:delete:${String(body.token_hash)}`,
      detail,
      at,
      body.token_hash,
      active.row.user_id,
      active.row.family_id,
    ),
  ]);
  return (results[0].meta.changes ?? 0) === 1
    ? ok()
    : failure("AUTH_SESSION_CONFLICT", 409);
}

async function revokeUser(request: Request, db: D1Database): Promise<Response> {
  const body = readRecord(await readJson(request), ["user_id"]);
  if (!body || !isCanonicalPositiveDecimal(body.user_id)) return error("INVALID_REQUEST");
  const at = stamp();
  const detail = await detailHash({ action: "revoke_user", user_id: body.user_id });
  const results = await db.batch([
    db.prepare(
      `UPDATE auth_sessions
       SET status='revoked', revoked_at=?, revoke_reason='user', updated_at=?
       WHERE user_id=? AND status='active'`,
    ).bind(at, at, body.user_id),
    auditStatement(
      db,
      "revoke_user",
      `authsess:revoke-user:${crypto.randomUUID()}`,
      detail,
      at,
      null,
      body.user_id,
      null,
    ),
  ]);
  return ok({ revoked: String(results[0].meta.changes ?? 0) });
}

async function revokeFamilyEndpoint(request: Request, db: D1Database): Promise<Response> {
  const body = readRecord(await readJson(request), ["family_id"]);
  if (!body || !isFamilyID(body.family_id)) return error("INVALID_REQUEST");
  await revokeFamily(db, body.family_id, "family", null, null, stamp());
  return ok();
}

async function listBy(
  request: Request,
  db: D1Database,
  key: "user_id" | "family_id",
): Promise<Response> {
  const body = readRecord(await readJson(request), [key]);
  if (!body) return error("INVALID_REQUEST");
  if (key === "user_id" && !isCanonicalPositiveDecimal(body.user_id)) {
    return error("INVALID_REQUEST");
  }
  if (key === "family_id" && !isFamilyID(body.family_id)) {
    return error("INVALID_REQUEST");
  }
  const at = stamp();
  const rows = await db.prepare(
    `SELECT token_hash
     FROM auth_sessions
     WHERE ${key}=?
       AND status='active'
       AND expires_at>?
       AND NOT EXISTS(
         SELECT 1 FROM auth_session_family_revocations
         WHERE family_id=auth_sessions.family_id
       )
     ORDER BY created_at, token_hash`,
  ).bind(body[key], at).all<{ token_hash: string }>();
  return json({ token_hashes: rows.results.map((row) => row.token_hash) });
}

async function classifyRotationFailure(
  db: D1Database,
  oldTokenHash: string,
  session: Session,
  at: string,
  detail: string,
): Promise<Response> {
  if (await exactWitnessExists(db, oldTokenHash, session, detail)) return ok();
  const old = await loadSession(db, oldTokenHash);
  if (!old) return failure("AUTH_SESSION_NOT_FOUND", 404);
  if (old.family_revoked_at !== null) {
    return failure(
      old.family_revocation_reason === "token_reuse"
        ? "AUTH_SESSION_REUSE"
        : "AUTH_SESSION_REVOKED",
      409,
    );
  }
  if (old.status === "active" && old.expires_at <= at) {
    return failure("AUTH_SESSION_EXPIRED", 404);
  }
  if (old.status === "active") {
    const replacement = await loadSession(db, session.token_hash);
    if (
      old.user_id !== session.user_id ||
      old.token_version !== session.token_version ||
      old.family_id !== session.family_id ||
      old.binding_hash !== session.binding_hash ||
      replacement !== null
    ) {
      return failure("AUTH_SESSION_CONFLICT", 409);
    }
    return error("AUTH_SESSION_UNAVAILABLE", 503);
  }
  if (old.status === "revoked" || old.status === "expired") {
    return failure(
      old.status === "expired" ? "AUTH_SESSION_EXPIRED" : "AUTH_SESSION_REVOKED",
      old.status === "expired" ? 404 : 409,
    );
  }
  if (old.status === "consumed") {
    await revokeFamily(
      db,
      old.family_id,
      "token_reuse",
      oldTokenHash,
      session.token_hash,
      at,
    );
    return failure("AUTH_SESSION_REUSE", 409);
  }
  return failure("AUTH_SESSION_CONFLICT", 409);
}

async function rotate(request: Request, db: D1Database): Promise<Response> {
  const body = readRecord(await readJson(request), ["old_token_hash", ...SESSION_FIELDS]);
  if (!body || !isHash(body.old_token_hash)) return error("INVALID_REQUEST");
  const session = readSession(body);
  if (
    !session ||
    body.old_token_hash === session.token_hash
  ) {
    return error("INVALID_REQUEST");
  }
  const at = stamp();
  const detail = await detailHash({
    action: "rotate",
    old_token_hash: body.old_token_hash,
    session,
  });
  if (await exactWitnessExists(db, body.old_token_hash, session, detail)) return ok();

  try {
    await db.batch([
      db.prepare(
        `UPDATE auth_sessions
         SET status='consumed', consumed_at=?, replaced_by_token_hash=?, updated_at=?
         WHERE token_hash=? AND status='active' AND expires_at>?
           AND user_id=? AND family_id=? AND binding_hash=?
           AND token_version=?
           AND NOT EXISTS(
             SELECT 1 FROM auth_session_family_revocations
             WHERE family_id=auth_sessions.family_id
           )
           AND NOT EXISTS(
             SELECT 1 FROM auth_sessions existing
             WHERE existing.token_hash=?
           )`,
      ).bind(
        at,
        session.token_hash,
        at,
        body.old_token_hash,
        at,
        session.user_id,
        session.family_id,
        session.binding_hash,
        session.token_version,
        session.token_hash,
      ),
      db.prepare(
        `INSERT INTO auth_sessions(
           token_hash,user_id,token_version,family_id,binding_hash,status,
           created_at,expires_at,updated_at
         )
         SELECT ?,?,?,?,?,'active',?,?,?
         FROM auth_sessions old
         WHERE old.token_hash=?
           AND old.status='consumed'
           AND old.replaced_by_token_hash=?
           AND old.consumed_at=?`,
      ).bind(
        session.token_hash,
        session.user_id,
        session.token_version,
        session.family_id,
        session.binding_hash,
        session.created_at,
        session.expires_at,
        session.created_at,
        body.old_token_hash,
        session.token_hash,
        at,
      ),
      auditStatement(
        db,
        "rotate",
        `authsess:rotate:${String(body.old_token_hash)}:${session.token_hash}`,
        detail,
        at,
        body.old_token_hash,
        session.user_id,
        session.family_id,
      ),
      db.prepare(
        `INSERT INTO auth_session_rotation_witnesses(
           old_token_hash,new_token_hash,detail_hash,created_at
         ) VALUES(?,?,?,?)`,
      ).bind(body.old_token_hash, session.token_hash, detail, at),
    ]);
  } catch {
    try {
      return await classifyRotationFailure(db, body.old_token_hash, session, at, detail);
    } catch {
      return error("AUTH_SESSION_UNAVAILABLE", 503);
    }
  }
  return await exactWitnessExists(db, body.old_token_hash, session, detail)
    ? ok()
    : failure("AUTH_SESSION_CONFLICT", 409);
}

export async function authSessionsControlPlane(
  request: Request,
  env: Env,
  pathname: string,
): Promise<Response> {
  if (!isBoundedString(request.headers.get("X-Sub2API-Container-Id"), 256)) {
    return error("NOT_FOUND", 404);
  }
  try {
    switch (pathname) {
      case "/v1/auth-sessions/store":
        return await store(request, env.DB);
      case "/v1/auth-sessions/get":
        return await get(request, env.DB);
      case "/v1/auth-sessions/delete":
        return await deleteSession(request, env.DB);
      case "/v1/auth-sessions/revoke-user":
        return await revokeUser(request, env.DB);
      case "/v1/auth-sessions/revoke-family":
        return await revokeFamilyEndpoint(request, env.DB);
      case "/v1/auth-sessions/list-user":
        return await listBy(request, env.DB, "user_id");
      case "/v1/auth-sessions/list-family":
        return await listBy(request, env.DB, "family_id");
      case "/v1/auth-sessions/contains":
        return await contains(request, env.DB);
      case "/v1/auth-sessions/rotate":
        return await rotate(request, env.DB);
      default:
        return error("NOT_FOUND", 404);
    }
  } catch {
    return error("AUTH_SESSION_UNAVAILABLE", 503);
  }
}
