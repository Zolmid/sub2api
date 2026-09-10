import { DurableObject } from "cloudflare:workers";
import {
  error,
  isBoundedString,
  isCanonicalPositiveDecimal,
  json,
  readJson,
} from "./contracts";
import { RateLimitStore, type RateOperation } from "./rate-limit";

const MIN_TTL_SECONDS = 3;
const MAX_TTL_SECONDS = 3600;
const TOMBSTONE_RETENTION_MS = 24 * 60 * 60 * 1000;
const MAX_TOMBSTONES = 1000;
const MAX_OBSERVATION_SOURCE_LENGTH = 64;
const MAX_TIMESTAMP_MS = 4_102_444_800_000;

type ObservationKind = "health_bps" | "cooldown_until_ms" | "temporary_until_ms";
type EvidenceKind = "confirmed" | "estimated" | "unknown";

type ObservationUpdate = {
  account_id: string;
  kind: ObservationKind;
  evidence: EvidenceKind;
  source: string;
  value: number | null;
  observed_at_ms: number;
  fresh_until_ms: number;
  version: number;
};

type ObservationRow = Omit<ObservationUpdate, "account_id">;

type Lease = {
  account_id: string;
  lease_id: string;
  request_id: string;
  owner: string;
  epoch: string;
  expires_at: number;
};

type Acquire = {
  account_id: string;
  request_id: string;
  owner: string;
  max_concurrency: number;
  ttl_seconds: number;
  admission_fingerprint: string;
};

type LeaseAction = {
  account_id: string;
  request_id: string;
  lease_id: string;
  owner: string;
  epoch: string;
  ttl_seconds?: number;
};

type LeaseAbort = {
  account_id: string;
  request_id: string;
  owner: string;
  admission_fingerprint: string;
};

type OperationResult =
  | { kind: "ok"; lease: Lease; created?: boolean; earliest: number | null }
  | { kind: "duplicate"; earliest: number | null }
  | { kind: "unavailable"; earliest: number | null }
  | { kind: "rejected"; earliest: number | null };

/** One SQLite-backed business-concurrency object per decimal account ID. */
export class AccountLeaseDO extends DurableObject<Env> {
  private readonly rateLimits: RateLimitStore;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS lease_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS lease_state (
        key TEXT PRIMARY KEY,
        value INTEGER NOT NULL
      );
      INSERT OR IGNORE INTO lease_state(key, value) VALUES ('epoch', 0);
      CREATE TABLE IF NOT EXISTS leases (
        lease_id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        request_id TEXT NOT NULL UNIQUE,
        owner TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS leases_expiry_idx ON leases(expires_at);
      CREATE TABLE IF NOT EXISTS lease_admission_identity (
        request_id TEXT PRIMARY KEY,
        admission_fingerprint TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS released_leases (
        lease_id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        released_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS released_leases_time_idx
        ON released_leases(released_at);
      CREATE TABLE IF NOT EXISTS scheduler_observations (
        kind TEXT PRIMARY KEY
          CHECK(kind IN ('health_bps','cooldown_until_ms','temporary_until_ms')),
        evidence TEXT NOT NULL CHECK(evidence IN ('confirmed','estimated','unknown')),
        source TEXT NOT NULL,
        value INTEGER,
        observed_at_ms INTEGER NOT NULL,
        fresh_until_ms INTEGER NOT NULL,
        version INTEGER NOT NULL
      );
    `);
    this.rateLimits = new RateLimitStore(ctx.storage);
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST") return error("NOT_FOUND", 404);
    const data = await readJson<Record<string, unknown>>(request);
    if (!data) return error("INVALID_REQUEST");

    switch (new URL(request.url).pathname) {
      case "/acquire":
        return this.acquire(data as unknown as Acquire);
      case "/renew":
        return this.renew(data as LeaseAction);
      case "/release":
        return this.release(data as LeaseAction);
      case "/abort":
        return this.abort(data as LeaseAbort);
      case "/inspect":
        return this.inspect(data);
      case "/state/update":
        return this.updateObservation(data);
      case "/rate/inspect":
        return this.rateOperation(this.rateLimits.inspect(data, Date.now()));
      case "/rate/reserve":
        return this.rateOperation(this.rateLimits.reserve(data, Date.now()));
      case "/rate/commit":
        return this.rateOperation(this.rateLimits.commit(data, Date.now()));
      case "/rate/release":
        return this.rateOperation(this.rateLimits.release(data, Date.now()));
      case "/rate/rollback":
        return this.rateOperation(this.rateLimits.rollback(data, Date.now()));
      case "/rate/settle":
        return this.rateOperation(this.rateLimits.settle(data, Date.now()));
      default:
        return error("NOT_FOUND", 404);
    }
  }

  private isValidAccount(accountID: unknown): accountID is string {
    return isCanonicalPositiveDecimal(accountID) && accountID.length <= 20;
  }

  private isValidOpaque(value: unknown): value is string {
    return isBoundedString(value, 256);
  }

  private isValidIdentity(data: LeaseAction): boolean {
    return (
      this.isValidAccount(data.account_id) &&
      this.isValidOpaque(data.request_id) &&
      this.isValidOpaque(data.lease_id) &&
      this.isValidOpaque(data.owner) &&
      isCanonicalPositiveDecimal(data.epoch) &&
      data.epoch.length <= 20
    );
  }

  private isValidAbort(data: LeaseAbort): boolean {
    return (
      this.isValidAccount(data.account_id) &&
      this.isValidOpaque(data.request_id) &&
      this.isValidOpaque(data.owner) &&
      typeof data.admission_fingerprint === "string" &&
      /^[a-f0-9]{64}$/.test(data.admission_fingerprint)
    );
  }

  private isValidTTL(value: unknown): value is number {
    return (
      Number.isInteger(value) &&
      Number(value) >= MIN_TTL_SECONDS &&
      Number(value) <= MAX_TTL_SECONDS
    );
  }

  private bindAccount(accountID: string): boolean {
    const existing = this.ctx.storage.sql
      .exec<{ value: string }>(
        "SELECT value FROM lease_meta WHERE key='account_id'",
      )
      .toArray()[0];
    if (existing) return existing.value === accountID;
    this.ctx.storage.sql.exec(
      "INSERT INTO lease_meta(key,value) VALUES('account_id',?)",
      accountID,
    );
    return true;
  }

  private cleanup(time: number): void {
    // An expired lease is still a closed lease, not an unknown identity. Keep
    // its full fence briefly so a delayed terminal release cannot be mistaken
    // for a request to release some later lease with the same request ID.
    this.ctx.storage.sql.exec(
      `INSERT OR IGNORE INTO released_leases(
         lease_id,account_id,request_id,owner,epoch,released_at
       )
       SELECT lease_id,account_id,request_id,owner,epoch,?
       FROM leases WHERE expires_at<=?`,
      time,
      time,
    );
    this.ctx.storage.sql.exec("DELETE FROM leases WHERE expires_at<=?", time);
    this.ctx.storage.sql.exec(
      "DELETE FROM released_leases WHERE released_at<?",
      time - TOMBSTONE_RETENTION_MS,
    );
    this.ctx.storage.sql.exec(
      `DELETE FROM released_leases
       WHERE lease_id IN (
         SELECT lease_id FROM released_leases
         ORDER BY released_at DESC
         LIMIT -1 OFFSET ?
       )`,
      MAX_TOMBSTONES,
    );
    this.ctx.storage.sql.exec(
      `DELETE FROM lease_admission_identity
       WHERE expires_at<=? AND request_id NOT IN (SELECT request_id FROM leases)`,
      time,
    );
  }

  private earliest(): number | null {
    const leaseExpiry = this.ctx.storage.sql
      .exec<{ deadline: number }>("SELECT min(expires_at) deadline FROM leases")
      .toArray()[0]?.deadline;
    const releaseTombstoneExpiry = this.ctx.storage.sql
      .exec<{ deadline: number }>(
        "SELECT min(released_at + ?) deadline FROM released_leases",
        TOMBSTONE_RETENTION_MS,
      )
      .toArray()[0]?.deadline;
    const admissionIdentityExpiry = this.ctx.storage.sql
      .exec<{ deadline: number }>(
        "SELECT min(expires_at) deadline FROM lease_admission_identity",
      )
      .toArray()[0]?.deadline;
    const deadlines = [leaseExpiry, releaseTombstoneExpiry, admissionIdentityExpiry]
      .filter((value): value is number => value != null);
    return deadlines.length === 0 ? null : Math.min(...deadlines);
  }

  private findActive(data: LeaseAction): Lease | null {
    return (
      this.ctx.storage.sql
        .exec<Lease>(
          `SELECT account_id,lease_id,request_id,owner,
                  CAST(epoch AS TEXT) epoch,expires_at
           FROM leases
           WHERE account_id=? AND request_id=? AND lease_id=?
             AND owner=? AND epoch=?`,
          data.account_id,
          data.request_id,
          data.lease_id,
          data.owner,
          data.epoch,
        )
        .toArray()[0] ?? null
    );
  }

  private isReleasedDuplicate(data: LeaseAction): boolean {
    return (
      this.ctx.storage.sql
        .exec<{ found: number }>(
          `SELECT 1 found FROM released_leases
           WHERE account_id=? AND request_id=? AND lease_id=?
             AND owner=? AND epoch=?`,
          data.account_id,
          data.request_id,
          data.lease_id,
          data.owner,
          data.epoch,
        )
        .toArray()[0]?.found === 1
    );
  }

  private async reschedule(time: number | null): Promise<void> {
    const rateTime = this.rateLimits.nextAlarm();
    const next = time === null
      ? rateTime
      : rateTime === null
        ? time
        : Math.min(time, rateTime);
    if (next === null) {
      await this.ctx.storage.deleteAlarm();
    } else {
      await this.ctx.storage.setAlarm(next);
    }
  }

  private async rateOperation(result: RateOperation): Promise<Response> {
    await this.reschedule(result.nextAlarm);
    return json(result.body, result.status);
  }

  private isTimestamp(value: unknown): value is number {
    return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= MAX_TIMESTAMP_MS;
  }

  private parseObservation(data: Record<string, unknown>): ObservationUpdate | null {
    const kind = data.kind;
    const evidence = data.evidence;
    const value = data.value;
    if (
      !this.isValidAccount(data.account_id) ||
      (kind !== "health_bps" && kind !== "cooldown_until_ms" && kind !== "temporary_until_ms") ||
      (evidence !== "confirmed" && evidence !== "estimated" && evidence !== "unknown") ||
      typeof data.source !== "string" ||
      data.source.length < 1 ||
      data.source.length > MAX_OBSERVATION_SOURCE_LENGTH ||
      data.source.trim() !== data.source ||
      !/^[A-Za-z0-9._:-]+$/.test(data.source) ||
      !this.isTimestamp(data.observed_at_ms) ||
      !this.isTimestamp(data.fresh_until_ms) ||
      data.fresh_until_ms < data.observed_at_ms ||
      !Number.isSafeInteger(data.version) ||
      Number(data.version) < 1
    ) {
      return null;
    }
    if (evidence === "unknown" && value !== null) return null;
    if (evidence !== "unknown") {
      if (kind === "health_bps") {
        if (!Number.isInteger(value) || Number(value) < 0 || Number(value) > 10_000) return null;
      } else if (value !== null && !this.isTimestamp(value)) {
        return null;
      }
    }
    return {
      account_id: data.account_id,
      kind,
      evidence,
      source: data.source,
      value: value as number | null,
      observed_at_ms: data.observed_at_ms,
      fresh_until_ms: data.fresh_until_ms,
      version: Number(data.version),
    };
  }

  private observationWire(row: ObservationRow | undefined, now: number): Record<string, unknown> {
    if (!row) {
      return {
        evidence: "unknown",
        value: null,
        source: null,
        observed_at_ms: null,
        fresh_until_ms: null,
        version: null,
      };
    }
    return {
      evidence: row.fresh_until_ms >= now ? row.evidence : "unknown",
      value: row.fresh_until_ms >= now && row.evidence !== "unknown" ? row.value : null,
      source: row.source,
      observed_at_ms: row.observed_at_ms,
      fresh_until_ms: row.fresh_until_ms,
      version: row.version,
    };
  }

  private async inspect(data: Record<string, unknown>): Promise<Response> {
    if (!this.isValidAccount(data.account_id)) return error("INVALID_REQUEST");
    const now = Date.now();
    const result = this.ctx.storage.transactionSync(() => {
      this.cleanup(now);
      this.rateLimits.cleanup(now);
      if (!this.bindAccount(data.account_id as string)) return null;
      const observations = this.ctx.storage.sql
        .exec<ObservationRow>(
          "SELECT kind,evidence,source,value,observed_at_ms,fresh_until_ms,version FROM scheduler_observations",
        )
        .toArray();
      const byKind = new Map(observations.map((row) => [row.kind, row]));
      const inFlight = this.ctx.storage.sql
        .exec<{ count: number }>("SELECT count(*) count FROM leases")
        .one().count;
      return {
        account_id: data.account_id,
        in_flight: inFlight,
        concurrency_evidence: "confirmed",
        observed_at_ms: now,
        health: this.observationWire(byKind.get("health_bps"), now),
        cooldown: this.observationWire(byKind.get("cooldown_until_ms"), now),
        temporary_unschedulable: this.observationWire(byKind.get("temporary_until_ms"), now),
      };
    });
    await this.reschedule(this.earliest());
    return result === null ? error("LEASE_IDENTITY_REJECTED", 409) : json(result);
  }

  private async updateObservation(data: Record<string, unknown>): Promise<Response> {
    const update = this.parseObservation(data);
    if (!update) return error("INVALID_SCHEDULER_OBSERVATION");
    const result = this.ctx.storage.transactionSync<
      | { kind: "applied" }
      | { kind: "duplicate" }
      | { kind: "stale" }
      | { kind: "conflict" }
      | { kind: "identity" }
    >(() => {
      if (!this.bindAccount(update.account_id)) return { kind: "identity" };
      const existing = this.ctx.storage.sql
        .exec<ObservationRow>(
          `SELECT kind,evidence,source,value,observed_at_ms,fresh_until_ms,version
           FROM scheduler_observations WHERE kind=?`,
          update.kind,
        )
        .toArray()[0];
      if (existing) {
        if (update.version < existing.version) {
          return { kind: "stale" };
        }
        if (update.version === existing.version) {
          const duplicate = existing.evidence === update.evidence &&
            existing.source === update.source &&
            existing.value === update.value &&
            existing.observed_at_ms === update.observed_at_ms &&
            existing.fresh_until_ms === update.fresh_until_ms;
          return { kind: duplicate ? "duplicate" : "conflict" };
        }
        if (update.observed_at_ms < existing.observed_at_ms) {
          return { kind: "stale" };
        }
      }
      this.ctx.storage.sql.exec(
        `INSERT INTO scheduler_observations(
           kind,evidence,source,value,observed_at_ms,fresh_until_ms,version
         ) VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(kind) DO UPDATE SET
           evidence=excluded.evidence,source=excluded.source,value=excluded.value,
           observed_at_ms=excluded.observed_at_ms,fresh_until_ms=excluded.fresh_until_ms,
           version=excluded.version`,
        update.kind,
        update.evidence,
        update.source,
        update.value,
        update.observed_at_ms,
        update.fresh_until_ms,
        update.version,
      );
      return { kind: "applied" };
    });
    if (result.kind === "identity") return error("LEASE_IDENTITY_REJECTED", 409);
    if (result.kind === "conflict") return error("SCHEDULER_OBSERVATION_CONFLICT", 409);
    return json({
      applied: result.kind === "applied",
      duplicate: result.kind === "duplicate",
      stale: result.kind === "stale",
    });
  }

  private wire(lease: Lease): Record<string, string> {
    return {
      account_id: lease.account_id,
      lease_id: lease.lease_id,
      request_id: lease.request_id,
      owner: lease.owner,
      epoch: lease.epoch,
      expires_at: new Date(lease.expires_at).toISOString(),
    };
  }

  private async acquire(data: Acquire): Promise<Response> {
    if (
      !this.isValidAccount(data.account_id) ||
      !this.isValidOpaque(data.request_id) ||
      !this.isValidOpaque(data.owner) ||
      typeof data.admission_fingerprint !== "string" ||
      !/^[a-f0-9]{64}$/.test(data.admission_fingerprint) ||
      !Number.isInteger(data.max_concurrency) ||
      data.max_concurrency < 1 ||
      data.max_concurrency > 10_000 ||
      !this.isValidTTL(data.ttl_seconds)
    ) {
      return error("INVALID_REQUEST");
    }

    const result = this.ctx.storage.transactionSync<OperationResult>(() => {
      const time = Date.now();
      this.cleanup(time);
      if (!this.bindAccount(data.account_id)) {
        return { kind: "rejected", earliest: this.earliest() };
      }

      const existing = this.ctx.storage.sql
        .exec<Lease>(
          `SELECT account_id,lease_id,request_id,owner,
                  CAST(epoch AS TEXT) epoch,expires_at
           FROM leases WHERE request_id=?`,
          data.request_id,
        )
        .toArray()[0];
      if (existing) {
        const identity = this.ctx.storage.sql.exec<{ admission_fingerprint: string }>(
          "SELECT admission_fingerprint FROM lease_admission_identity WHERE request_id=?",
          data.request_id,
        ).toArray()[0];
        if (
          existing.account_id !== data.account_id ||
          existing.owner !== data.owner ||
          identity?.admission_fingerprint !== data.admission_fingerprint
        ) {
          return { kind: "rejected", earliest: this.earliest() };
        }
        return {
          kind: "ok",
          lease: existing,
          created: false,
          earliest: this.earliest(),
        };
      }

      if (this.ctx.storage.sql.exec<{ found: number }>(
        "SELECT 1 found FROM lease_admission_identity WHERE request_id=?",
        data.request_id,
      ).toArray()[0]) {
        return { kind: "rejected", earliest: this.earliest() };
      }

      const count = this.ctx.storage.sql
        .exec<{ count: number }>("SELECT count(*) count FROM leases")
        .one().count;
      if (count >= data.max_concurrency) {
        return { kind: "unavailable", earliest: this.earliest() };
      }

      this.ctx.storage.sql.exec(
        "UPDATE lease_state SET value=value+1 WHERE key='epoch'",
      );
      const epoch = this.ctx.storage.sql
        .exec<{ value: string }>(
          "SELECT CAST(value AS TEXT) value FROM lease_state WHERE key='epoch'",
        )
        .one().value;
      const lease: Lease = {
        account_id: data.account_id,
        lease_id: crypto.randomUUID(),
        request_id: data.request_id,
        owner: data.owner,
        epoch,
        expires_at: time + data.ttl_seconds * 1000,
      };
      this.ctx.storage.sql.exec(
        `INSERT INTO leases(
           lease_id,account_id,request_id,owner,epoch,expires_at
         ) VALUES(?,?,?,?,?,?)`,
        lease.lease_id,
        lease.account_id,
        lease.request_id,
        lease.owner,
        lease.epoch,
        lease.expires_at,
      );
      this.ctx.storage.sql.exec(
        "INSERT INTO lease_admission_identity(request_id,admission_fingerprint,expires_at) VALUES(?,?,?)",
        data.request_id,
        data.admission_fingerprint,
        time + TOMBSTONE_RETENTION_MS,
      );
      return {
        kind: "ok",
        lease,
        created: true,
        earliest: this.earliest(),
      };
    });

    await this.reschedule(result.earliest);
    if (result.kind === "unavailable") {
      return error("LEASE_UNAVAILABLE", 429);
    }
    if (result.kind !== "ok") {
      return error("LEASE_IDENTITY_REJECTED", 409);
    }
    return json({ lease: this.wire(result.lease), created: result.created });
  }

  private async renew(data: LeaseAction): Promise<Response> {
    if (!this.isValidIdentity(data) || !this.isValidTTL(data.ttl_seconds)) {
      return error("LEASE_IDENTITY_REJECTED", 409);
    }

    const result = this.ctx.storage.transactionSync<OperationResult>(() => {
      const time = Date.now();
      this.cleanup(time);
      if (!this.bindAccount(data.account_id)) {
        return { kind: "rejected", earliest: this.earliest() };
      }
      const lease = this.findActive(data);
      if (!lease) return { kind: "rejected", earliest: this.earliest() };

      lease.expires_at = time + Number(data.ttl_seconds) * 1000;
      this.ctx.storage.sql.exec(
        "UPDATE leases SET expires_at=? WHERE lease_id=?",
        lease.expires_at,
        lease.lease_id,
      );
      return { kind: "ok", lease, earliest: this.earliest() };
    });

    await this.reschedule(result.earliest);
    if (result.kind !== "ok") {
      return error("LEASE_IDENTITY_REJECTED", 409);
    }
    return json({ lease: this.wire(result.lease) });
  }

  private async release(data: LeaseAction): Promise<Response> {
    if (!this.isValidIdentity(data)) {
      return error("LEASE_IDENTITY_REJECTED", 409);
    }

    const result = this.ctx.storage.transactionSync<OperationResult>(() => {
      const time = Date.now();
      this.cleanup(time);
      if (!this.bindAccount(data.account_id)) {
        return { kind: "rejected", earliest: this.earliest() };
      }
      const lease = this.findActive(data);
      if (lease) {
        this.ctx.storage.sql.exec(
          `INSERT INTO released_leases(
             lease_id,account_id,request_id,owner,epoch,released_at
           ) VALUES(?,?,?,?,?,?)`,
          lease.lease_id,
          lease.account_id,
          lease.request_id,
          lease.owner,
          lease.epoch,
          time,
        );
        this.ctx.storage.sql.exec(
          "DELETE FROM leases WHERE lease_id=?",
          lease.lease_id,
        );
        return { kind: "ok", lease, earliest: this.earliest() };
      }
      if (this.isReleasedDuplicate(data)) {
        return { kind: "duplicate", earliest: this.earliest() };
      }
      return { kind: "rejected", earliest: this.earliest() };
    });

    await this.reschedule(result.earliest);
    if (result.kind === "ok") {
      return json({ released: true, duplicate: false });
    }
    if (result.kind === "duplicate") {
      return json({ released: false, duplicate: true });
    }
    return error("LEASE_IDENTITY_REJECTED", 409);
  }

  /** Compensates an acquire whose response authority is unknown. */
  private async abort(data: LeaseAbort): Promise<Response> {
    if (!this.isValidAbort(data)) {
      return error("LEASE_IDENTITY_REJECTED", 409);
    }

    const result = this.ctx.storage.transactionSync<OperationResult>(() => {
      const time = Date.now();
      this.cleanup(time);
      if (!this.bindAccount(data.account_id)) {
        return { kind: "rejected", earliest: this.earliest() };
      }
      const identity = this.ctx.storage.sql.exec<{ admission_fingerprint: string }>(
        "SELECT admission_fingerprint FROM lease_admission_identity WHERE request_id=?",
        data.request_id,
      ).toArray()[0];
      if (!identity) {
        return { kind: "duplicate", earliest: this.earliest() };
      }
      if (identity.admission_fingerprint !== data.admission_fingerprint) {
        return { kind: "rejected", earliest: this.earliest() };
      }
      const lease = this.ctx.storage.sql.exec<Lease>(
        `SELECT account_id,lease_id,request_id,owner,
                CAST(epoch AS TEXT) epoch,expires_at
         FROM leases WHERE account_id=? AND request_id=?`,
        data.account_id,
        data.request_id,
      ).toArray()[0];
      if (!lease) {
        return { kind: "duplicate", earliest: this.earliest() };
      }
      if (lease.owner !== data.owner) {
        return { kind: "rejected", earliest: this.earliest() };
      }
      this.ctx.storage.sql.exec(
        `INSERT INTO released_leases(
           lease_id,account_id,request_id,owner,epoch,released_at
         ) VALUES(?,?,?,?,?,?)`,
        lease.lease_id,
        lease.account_id,
        lease.request_id,
        lease.owner,
        lease.epoch,
        time,
      );
      this.ctx.storage.sql.exec("DELETE FROM leases WHERE lease_id=?", lease.lease_id);
      return { kind: "ok", lease, earliest: this.earliest() };
    });

    await this.reschedule(result.earliest);
    if (result.kind === "ok") {
      return json({ released: true, duplicate: false });
    }
    if (result.kind === "duplicate") {
      return json({ released: false, duplicate: true });
    }
    return error("LEASE_IDENTITY_REJECTED", 409);
  }

  async alarm(): Promise<void> {
    const earliest = this.ctx.storage.transactionSync<number | null>(() => {
      const now = Date.now();
      this.cleanup(now);
      this.rateLimits.cleanup(now);
      return this.earliest();
    });
    await this.reschedule(earliest);
  }
}
