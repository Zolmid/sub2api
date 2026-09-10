import { DurableObject } from "cloudflare:workers";
import { error, json, readJson } from "./contracts";

export const RATE_WINDOW_MS = 60_000;
const MIN_RESERVATION_TTL_SECONDS = 3;
const MAX_RESERVATION_TTL_SECONDS = 60;
const MAX_RPM_LIMIT = 100_000;
const MAX_ACTIVE_RECORDS = 100_000;
const TOMBSTONE_RETENTION_MS = 24 * 60 * 60 * 1000;
const MAX_TOMBSTONES = 2_000;
const OPAQUE_PATTERN = /^[A-Za-z0-9._:-]+$/;
const ID_PATTERN = /^[1-9][0-9]{0,19}$/;

export type RateScope = "account" | "user" | "api_key";

export type RateIdentity = Readonly<{
  scope: RateScope;
  principal_id: string;
  admission_id: string;
  request_id: string;
  account_id: string;
  rpm_limit: number;
  admission_fingerprint: string;
}>;

export type RateAction = Readonly<Omit<RateIdentity, "rpm_limit">>;

export type RateReserve = RateIdentity & Readonly<{
  reservation_ttl_seconds: number;
}>;

export type RateInspect = Readonly<{
  scope: RateScope;
  principal_id: string;
  rpm_limit: number;
}>;

export type RateOperation = Readonly<{
  status: number;
  body: Record<string, unknown>;
  nextAlarm: number | null;
}>;

type AdmissionRow = {
  admission_id: string;
  request_id: string;
  account_id: string;
  rpm_limit: number;
  window_start_ms: number;
  window_end_ms: number;
  state: "reserved" | "committed";
  reservation_expires_at_ms: number;
};

type TombstoneRow = {
  admission_id: string;
  request_id: string;
  account_id: string;
  rpm_limit: number;
  outcome: "released" | "expired" | "window_closed";
};

type IdentityRow = {
  admission_id: string;
  request_id: string;
  account_id: string;
  rpm_limit: number;
  admission_fingerprint: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isCanonicalID(value: unknown): value is string {
  return typeof value === "string" && ID_PATTERN.test(value);
}

function isOpaque(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 128 &&
    OPAQUE_PATTERN.test(value)
  );
}

function isScope(value: unknown): value is RateScope {
  return value === "account" || value === "user" || value === "api_key";
}

function isLimit(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) >= 1 && Number(value) <= MAX_RPM_LIMIT;
}

function parseInspect(value: unknown): RateInspect | null {
  if (!isRecord(value)) return null;
  if (!isScope(value.scope) || !isCanonicalID(value.principal_id) || !isLimit(value.rpm_limit)) {
    return null;
  }
  return {
    scope: value.scope,
    principal_id: value.principal_id,
    rpm_limit: value.rpm_limit,
  };
}

function parseIdentity(value: unknown): RateIdentity | null {
  const inspect = parseInspect(value);
  if (
    inspect === null ||
    !isRecord(value) ||
    !isOpaque(value.admission_id) ||
    !isOpaque(value.request_id) ||
    !isCanonicalID(value.account_id) ||
    !isOpaque(value.admission_fingerprint)
  ) {
    return null;
  }
  return {
    ...inspect,
    admission_id: value.admission_id,
    request_id: value.request_id,
    account_id: value.account_id,
    admission_fingerprint: value.admission_fingerprint,
  };
}

function parseAction(value: unknown): RateAction | null {
  if (
    !isRecord(value) || !isScope(value.scope) ||
    !isCanonicalID(value.principal_id) || !isOpaque(value.admission_id) ||
    !isOpaque(value.request_id) || !isCanonicalID(value.account_id) ||
    !isOpaque(value.admission_fingerprint)
  ) return null;
  return {
    scope: value.scope,
    principal_id: value.principal_id,
    admission_id: value.admission_id,
    request_id: value.request_id,
    account_id: value.account_id,
    admission_fingerprint: value.admission_fingerprint,
  };
}

function sameIdentity(row: IdentityRow, value: RateIdentity | RateAction): boolean {
  return (
    row.admission_id === value.admission_id &&
    row.request_id === value.request_id &&
    row.account_id === value.account_id &&
    row.admission_fingerprint === value.admission_fingerprint &&
    (!("rpm_limit" in value) || row.rpm_limit === value.rpm_limit)
  );
}

/** SQLite-backed fixed-window state used inside an AccountLeaseDO instance. */
export class RateLimitStore {
  constructor(private readonly storage: DurableObjectStorage) {
    storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS rate_principal (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS rate_admissions (
        admission_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        rpm_limit INTEGER NOT NULL,
        window_start_ms INTEGER NOT NULL,
        window_end_ms INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('reserved','committed')),
        reservation_expires_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS rate_admissions_expiry_idx
        ON rate_admissions(reservation_expires_at_ms);
      CREATE TABLE IF NOT EXISTS rate_tombstones (
        admission_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        rpm_limit INTEGER NOT NULL,
        outcome TEXT NOT NULL CHECK(outcome IN ('released','expired','window_closed')),
        expires_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS rate_tombstones_expiry_idx
        ON rate_tombstones(expires_at_ms);
      CREATE TABLE IF NOT EXISTS rate_identities (
        admission_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        rpm_limit INTEGER NOT NULL,
        admission_fingerprint TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS rate_finalized (
        admission_id TEXT PRIMARY KEY,
        finalized_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
      );
    `);
  }

  private bind(value: Pick<RateInspect, "scope" | "principal_id">): boolean {
    const rows = this.storage.sql
      .exec<{ key: string; value: string }>("SELECT key,value FROM rate_principal")
      .toArray();
    const existing = new Map(rows.map((row) => [row.key, row.value]));
    if (existing.size > 0) {
      return existing.get("scope") === value.scope && existing.get("principal_id") === value.principal_id;
    }
    this.storage.sql.exec(
      "INSERT INTO rate_principal(key,value) VALUES('scope',?),('principal_id',?)",
      value.scope,
      value.principal_id,
    );
    return true;
  }

  cleanup(now: number): void {
    this.storage.sql.exec(
      `INSERT OR IGNORE INTO rate_tombstones(
         admission_id,request_id,account_id,rpm_limit,outcome,expires_at_ms
       )
       SELECT admission_id,request_id,account_id,rpm_limit,
              CASE WHEN window_end_ms<=? THEN 'window_closed' ELSE 'expired' END,
              ?
       FROM rate_admissions
       WHERE window_end_ms<=? OR (state='reserved' AND reservation_expires_at_ms<=?)`,
      now,
      now + TOMBSTONE_RETENTION_MS,
      now,
      now,
    );
    this.storage.sql.exec(
      "DELETE FROM rate_admissions WHERE window_end_ms<=? OR (state='reserved' AND reservation_expires_at_ms<=?)",
      now,
      now,
    );
    this.storage.sql.exec("DELETE FROM rate_tombstones WHERE expires_at_ms<=?", now);
    this.storage.sql.exec("DELETE FROM rate_finalized WHERE expires_at_ms<=?", now);
    this.storage.sql.exec(
      `DELETE FROM rate_tombstones WHERE admission_id IN (
         SELECT admission_id FROM rate_tombstones
         ORDER BY expires_at_ms DESC, admission_id DESC LIMIT -1 OFFSET ?
       )`,
      MAX_TOMBSTONES,
    );
    this.storage.sql.exec(
      `DELETE FROM rate_identities WHERE admission_id NOT IN (
         SELECT admission_id FROM rate_admissions
         UNION SELECT admission_id FROM rate_tombstones
         UNION SELECT admission_id FROM rate_finalized
       )`,
    );
  }

  nextAlarm(): number | null {
    const active = this.storage.sql
      .exec<{ deadline: number }>(
        `SELECT min(CASE WHEN state='reserved'
          THEN min(reservation_expires_at_ms,window_end_ms)
          ELSE window_end_ms END) deadline FROM rate_admissions`,
      )
      .toArray()[0]?.deadline;
    const tombstone = this.storage.sql
      .exec<{ deadline: number }>("SELECT min(expires_at_ms) deadline FROM rate_tombstones")
      .toArray()[0]?.deadline;
    const finalized = this.storage.sql
      .exec<{ deadline: number }>("SELECT min(expires_at_ms) deadline FROM rate_finalized")
      .toArray()[0]?.deadline;
    const deadlines = [active, tombstone, finalized].filter(
      (value): value is number => value != null,
    );
    return deadlines.length === 0 ? null : Math.min(...deadlines);
  }

  private identity(admissionID: string): IdentityRow | undefined {
    return this.storage.sql.exec<IdentityRow>(
      `SELECT admission_id,request_id,account_id,rpm_limit,admission_fingerprint
       FROM rate_identities WHERE admission_id=?`,
      admissionID,
    ).toArray()[0];
  }

  private result(status: number, body: Record<string, unknown>): RateOperation {
    return { status, body, nextAlarm: this.nextAlarm() };
  }

  inspect(value: unknown, now: number): RateOperation {
    const data = parseInspect(value);
    if (data === null) return this.result(400, { error: "INVALID_RATE_REQUEST" });
    this.cleanup(now);
    if (!this.bind(data)) return this.result(409, { error: "RATE_PRINCIPAL_CONFLICT" });
    const windowStart = Math.floor(now / RATE_WINDOW_MS) * RATE_WINDOW_MS;
    const used = this.storage.sql
      .exec<{ count: number }>(
        "SELECT count(*) count FROM rate_admissions WHERE window_start_ms=?",
        windowStart,
      )
      .one().count;
    if (!Number.isSafeInteger(used) || used < 0 || used > MAX_ACTIVE_RECORDS) {
      return this.result(503, { error: "RATE_STATE_INVALID" });
    }
    return this.result(200, {
      scope: data.scope,
      principal_id: data.principal_id,
      used,
      limit: data.rpm_limit,
      available: used < data.rpm_limit,
      window_start_ms: windowStart,
      window_end_ms: windowStart + RATE_WINDOW_MS,
      observed_at_ms: now,
      evidence: "confirmed",
    });
  }

  reserve(value: unknown, now: number): RateOperation {
    const identity = parseIdentity(value);
    if (
      identity === null ||
      !isRecord(value) ||
      !Number.isInteger(value.reservation_ttl_seconds) ||
      Number(value.reservation_ttl_seconds) < MIN_RESERVATION_TTL_SECONDS ||
      Number(value.reservation_ttl_seconds) > MAX_RESERVATION_TTL_SECONDS
    ) {
      return this.result(400, { error: "INVALID_RATE_REQUEST" });
    }
    this.cleanup(now);
    if (!this.bind(identity)) return this.result(409, { error: "RATE_PRINCIPAL_CONFLICT" });
    const existing = this.storage.sql
      .exec<AdmissionRow>(
        `SELECT admission_id,request_id,account_id,rpm_limit,window_start_ms,
                window_end_ms,state,reservation_expires_at_ms
         FROM rate_admissions WHERE admission_id=?`,
        identity.admission_id,
      )
      .toArray()[0];
    if (existing) {
      const storedIdentity = this.identity(identity.admission_id);
      if (!storedIdentity || !sameIdentity(storedIdentity, identity)) {
        return this.result(409, { error: "RATE_IDEMPOTENCY_CONFLICT" });
      }
      return this.result(200, {
        reserved: existing.state === "reserved",
        committed: existing.state === "committed",
        created: false,
        window_start_ms: existing.window_start_ms,
        window_end_ms: existing.window_end_ms,
      });
    }
    const tombstone = this.storage.sql
      .exec<TombstoneRow>(
        "SELECT admission_id,request_id,account_id,rpm_limit,outcome FROM rate_tombstones WHERE admission_id=?",
        identity.admission_id,
      )
      .toArray()[0];
    if (tombstone) {
      const storedIdentity = this.identity(identity.admission_id);
      return this.result(409, {
        error: storedIdentity && sameIdentity(storedIdentity, identity)
          ? "RATE_ADMISSION_CLOSED" : "RATE_IDEMPOTENCY_CONFLICT",
      });
    }
    const windowStart = Math.floor(now / RATE_WINDOW_MS) * RATE_WINDOW_MS;
    const used = this.storage.sql
      .exec<{ count: number }>(
        "SELECT count(*) count FROM rate_admissions WHERE window_start_ms=?",
        windowStart,
      )
      .one().count;
    if (!Number.isSafeInteger(used) || used < 0 || used >= MAX_ACTIVE_RECORDS) {
      return this.result(503, { error: "RATE_STATE_INVALID" });
    }
    if (used >= identity.rpm_limit) {
      return this.result(429, { error: "RATE_LIMITED", used, limit: identity.rpm_limit });
    }
    const windowEnd = windowStart + RATE_WINDOW_MS;
    const reservationExpires = Math.min(
      windowEnd,
      now + Number(value.reservation_ttl_seconds) * 1000,
    );
    this.storage.sql.exec(
      `INSERT INTO rate_identities(
         admission_id,request_id,account_id,rpm_limit,admission_fingerprint
       ) VALUES(?,?,?,?,?)`,
      identity.admission_id,
      identity.request_id,
      identity.account_id,
      identity.rpm_limit,
      identity.admission_fingerprint,
    );
    this.storage.sql.exec(
      `INSERT INTO rate_admissions(
         admission_id,request_id,account_id,rpm_limit,window_start_ms,
         window_end_ms,state,reservation_expires_at_ms
       ) VALUES(?,?,?,?,?,?,'reserved',?)`,
      identity.admission_id,
      identity.request_id,
      identity.account_id,
      identity.rpm_limit,
      windowStart,
      windowEnd,
      reservationExpires,
    );
    return this.result(200, {
      reserved: true,
      committed: false,
      created: true,
      window_start_ms: windowStart,
      window_end_ms: windowEnd,
    });
  }

  commit(value: unknown, now: number): RateOperation {
    return this.finish(value, now, "commit");
  }

  release(value: unknown, now: number): RateOperation {
    return this.finish(value, now, "release");
  }

  rollback(value: unknown, now: number): RateOperation {
    return this.finish(value, now, "rollback");
  }

  settle(value: unknown, now: number): RateOperation {
    return this.finish(value, now, "settle");
  }

  private finish(value: unknown, now: number, action: "commit" | "release" | "rollback" | "settle"): RateOperation {
    const identity = action === "commit" ? parseIdentity(value) : parseAction(value);
    if (identity === null) return this.result(400, { error: "INVALID_RATE_REQUEST" });
    this.cleanup(now);
    if (!this.bind(identity)) return this.result(409, { error: "RATE_PRINCIPAL_CONFLICT" });
    const existing = this.storage.sql
      .exec<AdmissionRow>(
        `SELECT admission_id,request_id,account_id,rpm_limit,window_start_ms,
                window_end_ms,state,reservation_expires_at_ms
         FROM rate_admissions WHERE admission_id=?`,
        identity.admission_id,
      )
      .toArray()[0];
    if (!existing) {
      const storedIdentity = this.identity(identity.admission_id);
      const tombstone = this.storage.sql
        .exec<TombstoneRow>(
          "SELECT admission_id,request_id,account_id,rpm_limit,outcome FROM rate_tombstones WHERE admission_id=?",
          identity.admission_id,
        )
        .toArray()[0];
      if (storedIdentity && sameIdentity(storedIdentity, identity) &&
          (action === "release" || action === "rollback") && tombstone) {
        return this.result(200, { released: false, duplicate: true });
      }
      if (storedIdentity && sameIdentity(storedIdentity, identity) && action === "settle") {
        const finalized = this.storage.sql.exec<{ found: number }>(
          "SELECT 1 found FROM rate_finalized WHERE admission_id=?",
          identity.admission_id,
        ).toArray()[0];
        if (finalized) return this.result(200, { settled: false, duplicate: true });
        if (tombstone?.outcome === "window_closed") {
          return this.result(200, { settled: false, duplicate: true });
        }
      }
      return this.result(409, {
        error: storedIdentity && !sameIdentity(storedIdentity, identity)
          ? "RATE_IDEMPOTENCY_CONFLICT"
          : "RATE_ADMISSION_NOT_ACTIVE",
      });
    }
    const storedIdentity = this.identity(identity.admission_id);
    if (!storedIdentity || !sameIdentity(storedIdentity, identity)) {
      return this.result(409, { error: "RATE_IDEMPOTENCY_CONFLICT" });
    }
    if (action === "rollback") {
      const finalized = this.storage.sql.exec<{ found: number }>(
        "SELECT 1 found FROM rate_finalized WHERE admission_id=?",
        identity.admission_id,
      ).toArray()[0];
      if (finalized) {
        return this.result(409, { error: "RATE_ADMISSION_FINALIZED" });
      }
    }
    if (action === "commit") {
      if (existing.state === "committed") {
        return this.result(200, { committed: true, duplicate: true });
      }
      this.storage.sql.exec(
        "UPDATE rate_admissions SET state='committed',reservation_expires_at_ms=window_end_ms WHERE admission_id=?",
        identity.admission_id,
      );
      return this.result(200, { committed: true, duplicate: false });
    }
    if (action === "settle") {
      if (existing.state !== "committed") {
        return this.result(409, { error: "RATE_ADMISSION_NOT_COMMITTED" });
      }
      const prior = this.storage.sql.exec<{ found: number }>(
        "SELECT 1 found FROM rate_finalized WHERE admission_id=?",
        identity.admission_id,
      ).toArray()[0];
      if (prior) return this.result(200, { settled: false, duplicate: true });
      this.storage.sql.exec(
        "INSERT INTO rate_finalized(admission_id,finalized_at_ms,expires_at_ms) VALUES(?,?,?)",
        identity.admission_id,
        now,
        Math.max(existing.window_end_ms, now + TOMBSTONE_RETENTION_MS),
      );
      return this.result(200, { settled: true, duplicate: false });
    }
    if (existing.state === "committed" && action !== "rollback") {
      return this.result(409, { error: "RATE_ADMISSION_COMMITTED" });
    }
    this.storage.sql.exec(
      `INSERT INTO rate_tombstones(
         admission_id,request_id,account_id,rpm_limit,outcome,expires_at_ms
       ) VALUES(?,?,?,?, 'released', ?)`,
      identity.admission_id,
      identity.request_id,
      identity.account_id,
      storedIdentity.rpm_limit,
      now + TOMBSTONE_RETENTION_MS,
    );
    this.storage.sql.exec("DELETE FROM rate_admissions WHERE admission_id=?", identity.admission_id);
    return this.result(200, { released: true, duplicate: false });
  }
}


abstract class PrincipalRateLimitDO extends DurableObject<Env> {
  private readonly store: RateLimitStore;
  protected abstract readonly scope: "user" | "api_key";

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.store = new RateLimitStore(ctx.storage);
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST") return error("NOT_FOUND", 404);
    const data = await readJson<Record<string, unknown>>(request);
    if (!data || data.scope !== this.scope) return error("INVALID_RATE_REQUEST");
    const now = Date.now();
    let result: RateOperation;
    switch (new URL(request.url).pathname) {
      case "/rate/inspect": result = this.store.inspect(data, now); break;
      case "/rate/reserve": result = this.store.reserve(data, now); break;
      case "/rate/commit": result = this.store.commit(data, now); break;
      case "/rate/release": result = this.store.release(data, now); break;
      case "/rate/rollback": result = this.store.rollback(data, now); break;
      case "/rate/settle": result = this.store.settle(data, now); break;
      default: return error("NOT_FOUND", 404);
    }
    await this.reschedule(result.nextAlarm);
    return json(result.body, result.status);
  }

  async alarm(): Promise<void> {
    const next = this.ctx.storage.transactionSync(() => {
      this.store.cleanup(Date.now());
      return this.store.nextAlarm();
    });
    await this.reschedule(next);
  }

  private async reschedule(next: number | null): Promise<void> {
    if (next === null) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(next);
  }
}

export class UserRateLimitDO extends PrincipalRateLimitDO {
  protected readonly scope = "user" as const;
}

export class APIKeyRateLimitDO extends PrincipalRateLimitDO {
  protected readonly scope = "api_key" as const;
}
