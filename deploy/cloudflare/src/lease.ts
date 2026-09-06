import { DurableObject } from "cloudflare:workers";
import { error, json, readJson } from "./contracts";

type Acquire = { request_id: string; owner: string; max_concurrency: number; ttl_seconds: number };
type Lease = { lease_id: string; request_id: string; owner: string; epoch: string; expires_at: number };

/** One SQLite-backed DO per account; there is no fetch or await inside SQL critical sections. */
export class AccountLeaseDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS leases (lease_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, owner TEXT NOT NULL, epoch INTEGER NOT NULL, expires_at INTEGER NOT NULL, UNIQUE(request_id, owner)); CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value INTEGER NOT NULL); INSERT OR IGNORE INTO state VALUES ('epoch', 0)");
  }
  async fetch(request: Request): Promise<Response> {
    const data = await readJson<Record<string, unknown>>(request); if (!data) return error("INVALID_REQUEST");
    const path = new URL(request.url).pathname;
    if (path === "/acquire") return this.acquire(data as unknown as Acquire);
    if (path === "/renew") return this.renew(data);
    if (path === "/release") return this.release(data);
    return error("NOT_FOUND", 404);
  }
  private cleanup(): void { this.ctx.storage.sql.exec("DELETE FROM leases WHERE expires_at <= ?", Date.now()); }
  private async acquire(data: Acquire): Promise<Response> {
    if (!data.request_id || !data.owner || !Number.isInteger(data.max_concurrency) || data.max_concurrency < 1 || !Number.isInteger(data.ttl_seconds) || data.ttl_seconds < 3) return error("INVALID_REQUEST");
    this.cleanup();
    const existing = this.ctx.storage.sql.exec<Lease>("SELECT lease_id,request_id,owner,CAST(epoch AS TEXT) epoch,expires_at FROM leases WHERE request_id=? AND owner=?", data.request_id, data.owner).one();
    if (existing) return json({ lease: this.wire(existing) });
    const count = this.ctx.storage.sql.exec<{ count: number }>("SELECT count(*) count FROM leases").one().count;
    if (count >= data.max_concurrency) return error("LEASE_UNAVAILABLE", 429);
    this.ctx.storage.sql.exec("UPDATE state SET value=value+1 WHERE key='epoch'");
    const epoch = this.ctx.storage.sql.exec<{ value: number }>("SELECT value FROM state WHERE key='epoch'").one().value;
    const lease: Lease = { lease_id: crypto.randomUUID(), request_id: data.request_id, owner: data.owner, epoch: String(epoch), expires_at: Date.now() + data.ttl_seconds * 1000 };
    this.ctx.storage.sql.exec("INSERT INTO leases(lease_id,request_id,owner,epoch,expires_at) VALUES(?,?,?,?,?)", lease.lease_id, lease.request_id, lease.owner, epoch, lease.expires_at);
    await this.ctx.storage.setAlarm(lease.expires_at); return json({ lease: this.wire(lease) });
  }
  private valid(data: Record<string, unknown>): data is Record<string, string> { return ["request_id", "lease_id", "owner", "epoch"].every((key) => typeof data[key] === "string" && data[key]); }
  private lookup(data: Record<string, unknown>): Lease | null { this.cleanup(); return this.ctx.storage.sql.exec<Lease>("SELECT lease_id,request_id,owner,CAST(epoch AS TEXT) epoch,expires_at FROM leases WHERE lease_id=? AND request_id=? AND owner=? AND epoch=?", data.lease_id, data.request_id, data.owner, data.epoch).one() ?? null; }
  private async renew(data: Record<string, unknown>): Promise<Response> {
    const ttl = Number(data.ttl_seconds); if (!this.valid(data) || !Number.isInteger(ttl) || ttl < 3) return error("LEASE_IDENTITY_REJECTED", 409);
    const lease = this.lookup(data); if (!lease) return error("LEASE_IDENTITY_REJECTED", 409);
    lease.expires_at = Date.now() + ttl * 1000; this.ctx.storage.sql.exec("UPDATE leases SET expires_at=? WHERE lease_id=?", lease.expires_at, lease.lease_id); await this.ctx.storage.setAlarm(lease.expires_at); return json({ lease: this.wire(lease) });
  }
  private async release(data: Record<string, unknown>): Promise<Response> {
    if (!this.valid(data)) return error("LEASE_IDENTITY_REJECTED", 409);
    const lease = this.lookup(data); if (!lease) return json({ released: false });
    this.ctx.storage.sql.exec("DELETE FROM leases WHERE lease_id=?", lease.lease_id); return json({ released: true });
  }
  async alarm(): Promise<void> { this.cleanup(); const next = this.ctx.storage.sql.exec<{ expires_at: number }>("SELECT expires_at FROM leases ORDER BY expires_at LIMIT 1").one(); if (next) await this.ctx.storage.setAlarm(next.expires_at); }
  private wire(lease: Lease) { return { ...lease, account_id: this.ctx.id.toString(), expires_at: new Date(lease.expires_at).toISOString() }; }
}
