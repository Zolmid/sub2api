import { DurableObject } from "cloudflare:workers";
import {
  error,
  isBoundedString,
  isCanonicalPositiveDecimal,
  json,
  readJson,
} from "./contracts";

const MIN_TTL_SECONDS = 3;
const MAX_TTL_SECONDS = 3600;
const TOMBSTONE_RETENTION_MS = 24 * 60 * 60 * 1000;
const MAX_TOMBSTONES = 1000;

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
};

type LeaseAction = {
  account_id: string;
  request_id: string;
  lease_id: string;
  owner: string;
  epoch: string;
  ttl_seconds?: number;
};

type OperationResult =
  | { kind: "ok"; lease: Lease; created?: boolean; earliest: number | null }
  | { kind: "duplicate"; earliest: number | null }
  | { kind: "unavailable"; earliest: number | null }
  | { kind: "rejected"; earliest: number | null };

/** One SQLite-backed business-concurrency object per decimal account ID. */
export class AccountLeaseDO extends DurableObject<Env> {
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
    `);
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
  }

  private earliest(): number | null {
    return (
      this.ctx.storage.sql
        .exec<{ expires_at: number }>(
          "SELECT expires_at FROM leases ORDER BY expires_at LIMIT 1",
        )
        .toArray()[0]?.expires_at ?? null
    );
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
    if (time === null) {
      await this.ctx.storage.deleteAlarm();
    } else {
      await this.ctx.storage.setAlarm(time);
    }
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
        if (
          existing.account_id !== data.account_id ||
          existing.owner !== data.owner
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

  async alarm(): Promise<void> {
    const earliest = this.ctx.storage.transactionSync<number | null>(() => {
      this.cleanup(Date.now());
      return this.earliest();
    });
    await this.reschedule(earliest);
  }
}
