import type { Completion } from "./contracts";
import { BRIDGE_VERSION, canonical, decimal, error, INTERNAL_HOST, json, now, readJson, sha256 } from "./contracts";

type Alias = { alias: string; upstream_model: string; status: string };
const bridge = (request: Request) => request.headers.get("X-Sub2API-Bridge-Version") === BRIDGE_VERSION;

export async function controlPlane(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (new URL(request.url).hostname !== INTERNAL_HOST || !bridge(request) || request.method !== "POST") return error("NOT_FOUND", 404);
  const path = new URL(request.url).pathname;
  if (path === "/v1/auth/resolve") return resolve(request, env);
  if (path === "/v1/auth/touch") return touch(request, env);
  if (path === "/v1/requests/admit") return admit(request, env);
  if (path === "/v1/leases/renew") return lease(request, env, "/renew");
  if (path === "/v1/leases/release") return lease(request, env, "/release");
  if (path === "/v1/requests/complete") return complete(request, env, ctx);
  return error("NOT_FOUND", 404);
}

async function resolve(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{ key?: string }>(request); if (!body?.key) return error("API_KEY_NOT_FOUND", 404);
  const keyHash = await sha256(body.key);
  const row = await env.DB.prepare("SELECT k.id key_id,k.user_id,k.group_id,k.name key_name,k.status key_status,k.ip_whitelist_json,k.ip_blacklist_json,k.expires_at,u.id user_id,u.status user_status,u.role,u.concurrency,u.balance_microusd,u.allowed_group_ids_json,u.restrict_public_groups,g.id group_id2,g.name group_name,g.platform,g.status group_status,g.is_exclusive,g.subscription_type FROM api_keys k JOIN users u ON u.id=k.user_id LEFT JOIN groups g ON g.id=k.group_id WHERE k.key_hash=?").bind(keyHash).first<Record<string, unknown>>();
  if (!row || row.key_status !== "active" || row.user_status !== "active" || (row.group_id && row.group_status !== "active")) return error("API_KEY_NOT_FOUND", 404);
  return json({ api_key: { id: row.key_id, user_id: row.user_id, name: row.key_name, status: row.key_status, group_id: row.group_id, ip_whitelist: JSON.parse(String(row.ip_whitelist_json)), ip_blacklist: JSON.parse(String(row.ip_blacklist_json)), expires_at: row.expires_at }, user: { id: row.user_id, status: row.user_status, role: row.role, concurrency: row.concurrency, balance_positive: BigInt(String(row.balance_microusd)) > 0n, allowed_group_ids: JSON.parse(String(row.allowed_group_ids_json)), restrict_public_groups: Boolean(row.restrict_public_groups) }, group: row.group_id ? { id: row.group_id2, name: row.group_name, platform: row.platform, status: row.group_status, is_exclusive: Boolean(row.is_exclusive), subscription_type: row.subscription_type } : null });
}
async function touch(request: Request, env: Env): Promise<Response> { const body = await readJson<{ api_key_id?: string; used_at?: string }>(request); if (!body || !decimal(body.api_key_id) || !body.used_at) return error("INVALID_REQUEST"); await env.DB.prepare("UPDATE api_keys SET last_used_at=? WHERE id=?").bind(body.used_at, body.api_key_id).run(); return new Response(null, { status: 204 }); }
async function alias(model: string, env: Env): Promise<Alias | null> {
  try { const cached = await env.CONFIG_CACHE.get<Alias>(`model:${model}`, "json"); if (cached?.status === "active") return cached; } catch { /* cache is non-authoritative */ }
  const authoritative = await env.DB.prepare("SELECT alias,upstream_model,status FROM model_aliases WHERE alias=?").bind(model).first<Alias>();
  if (authoritative?.status === "active") { try { await env.CONFIG_CACHE.put(`model:${model}`, JSON.stringify(authoritative), { expirationTtl: 300 }); } catch { /* D1 result remains valid */ } }
  return authoritative?.status === "active" ? authoritative : null;
}
async function credentials(envelope: string, env: Env): Promise<Record<string, unknown> | null> {
  const runtime = env as Env & { ENVIRONMENT: string; ALLOW_TEST_FIXTURE: string; CREDENTIAL_ENCRYPTION_KEY?: string };
  if (String(runtime.ENVIRONMENT) === "local" && String(runtime.ALLOW_TEST_FIXTURE) === "true" && envelope === "fixture:v1:mock-upstream") return { fixture: "mock-upstream" };
  // Production format is aes-gcm:v1:<base64(iv)>:<base64(ciphertext)> and is fail-closed.
  if (!runtime.CREDENTIAL_ENCRYPTION_KEY || !envelope.startsWith("aes-gcm:v1:")) return null;
  try { const [, , iv64, ciphertext64] = envelope.split(":"); const key = await crypto.subtle.importKey("raw", Uint8Array.from(atob(runtime.CREDENTIAL_ENCRYPTION_KEY), c => c.charCodeAt(0)), "AES-GCM", false, ["decrypt"]); const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Uint8Array.from(atob(iv64), c => c.charCodeAt(0)) }, key, Uint8Array.from(atob(ciphertext64), c => c.charCodeAt(0))); return JSON.parse(new TextDecoder().decode(clear)); } catch { return null; }
}
async function admit(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{ request_id?: string; api_key_id?: string; group_id?: string; model?: string; lease_ttl_seconds?: number }>(request);
  if (!body?.request_id || !decimal(body.api_key_id) || !decimal(body.group_id) || !body.model || !Number.isInteger(body.lease_ttl_seconds)) return error("ADMISSION_REJECTED", 429);
  const mapped = await alias(body.model, env); if (!mapped) return error("ADMISSION_REJECTED", 429);
  const account = await env.DB.prepare("SELECT a.id,a.name,a.platform,a.type,a.max_concurrency,a.credential_envelope,a.extra_json FROM accounts a JOIN account_groups ag ON ag.account_id=a.id WHERE ag.group_id=? AND a.status='active' AND a.schedulable=1 ORDER BY a.priority DESC,a.id ASC LIMIT 1").bind(body.group_id).first<Record<string, string | number>>();
  if (!account || !(await credentials(String(account.credential_envelope), env))) return error("ADMISSION_REJECTED", 429);
  const id = env.ACCOUNT_LEASE.idFromName(`account:${account.id}`); const stub = env.ACCOUNT_LEASE.get(id); const owner = request.headers.get("X-Sub2API-Container-Id"); if (!owner) return error("ADMISSION_REJECTED", 429);
  const response = await stub.fetch("https://lease/acquire", { method: "POST", body: JSON.stringify({ request_id: body.request_id, owner, max_concurrency: account.max_concurrency, ttl_seconds: body.lease_ttl_seconds }) }); if (!response.ok) return error("ADMISSION_REJECTED", 429);
  const leased = await response.json<{ lease: Record<string, string> }>();
  try { await env.DB.prepare("INSERT INTO gateway_requests(request_id,api_key_id,account_id,lease_id,lease_epoch,model,upstream_model,state,created_at) VALUES(?,?,?,?,?,?,?,?,?)").bind(body.request_id, body.api_key_id, account.id, leased.lease.lease_id, leased.lease.epoch, body.model, mapped.upstream_model, "admitted", now()).run(); } catch { await stub.fetch("https://lease/release", { method: "POST", body: JSON.stringify({ ...leased.lease, owner }) }); return error("ADMISSION_REJECTED", 429); }
  return json({ account: { id: account.id, name: account.name, platform: account.platform, type: account.type, concurrency: account.max_concurrency, credentials: await credentials(String(account.credential_envelope), env), extra: JSON.parse(String(account.extra_json)) }, lease: leased.lease });
}
async function lease(request: Request, env: Env, operation: string): Promise<Response> { const body = await readJson<Record<string, string | number>>(request); const owner = request.headers.get("X-Sub2API-Container-Id"); if (!body || !decimal(body.account_id) || !owner || body.owner !== owner) return error("LEASE_IDENTITY_REJECTED", 409); return env.ACCOUNT_LEASE.get(env.ACCOUNT_LEASE.idFromName(`account:${body.account_id}`)).fetch(`https://lease${operation}`, { method: "POST", body: JSON.stringify({ ...body, owner }) }); }
async function complete(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const body = await readJson<Completion>(request); if (!body || !body.event_id || !body.request_id || !decimal(body.api_key_id) || !decimal(body.account_id) || ![body.input_tokens, body.output_tokens, body.cache_read_tokens, body.duration_ms].every(decimal)) return error("INVALID_REQUEST");
  const payload = canonical(body); const hash = await sha256(payload); const existing = await env.DB.prepare("SELECT payload_hash FROM outbox_events WHERE event_id=?").bind(body.event_id).first<{ payload_hash: string }>();
  if (existing && existing.payload_hash !== hash) return error("EVENT_CONFLICT", 409);
  if (!existing) await env.DB.batch([env.DB.prepare("UPDATE gateway_requests SET state=?,event_id=?,completed_at=? WHERE request_id=? AND state='admitted'").bind(body.outcome, body.event_id, now(), body.request_id), env.DB.prepare("INSERT INTO outbox_events(event_id,request_id,payload_json,payload_hash,state,created_at) VALUES(?,?,?,?,?,?)").bind(body.event_id, body.request_id, payload, hash, "pending", now())]);
  ctx.waitUntil(publish(env, body.event_id, payload, hash)); return new Response(null, { status: 204 });
}
export async function publish(env: Env, eventId: string, payload: string, hash: string): Promise<void> { await env.USAGE_QUEUE.send({ event_id: eventId, payload, payload_hash: hash }); await env.DB.prepare("UPDATE outbox_events SET state='published',published_at=? WHERE event_id=? AND payload_hash=?").bind(now(), eventId, hash).run(); }
