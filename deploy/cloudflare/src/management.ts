import {
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
  encryptAPIKeyCredentials,
  validateAPIKeyCredentials,
  type CredentialRuntime,
} from "./credentials";

const ID_MAX = 20;
const PAGE_MAX = 100;
const OPERATION_MAX = 128;
const statuses = new Set(["active", "disabled"]);
const roles = new Set(["user", "admin"]);
const readablePrivacyModes = new Set(["training_off", "training_set_failed", "training_set_cf_blocked"]);
const MAX_PUBLIC_BALANCE_E8_USD = 900719925474099100n;

type User = {
  id: string; email: string; username: string; notes: string; status: string;
  role: string; concurrency: number; rpm_limit: number; balance_e8_usd: string; balance_microusd?: string;
  allowed_group_ids: string[]; restrict_public_groups: boolean;
  created_at: string; updated_at: string; deleted_at: string | null;
};
type Group = {
  id: string; name: string; platform: string; status: string; is_exclusive: boolean;
  subscription_type: string; created_at: string; updated_at: string; deleted_at: string | null;
};
type APIKey = {
  id: string; user_id: string; group_id: string; name: string; status: string;
  ip_whitelist: string[]; ip_blacklist: string[]; expires_at: string | null;
  last_used_at: string | null; created_at: string; updated_at: string; deleted_at: string | null;
};
type Account = {
  id: string; name: string; platform: string; type: "apikey"; status: string;
  schedulable: boolean; priority: number; max_concurrency: number; extra: Record<string, unknown>;
  group_ids: string[]; created_at: string; updated_at: string; deleted_at: string | null;
};

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const only = (body: Record<string, unknown>, keys: string[]) =>
  Object.keys(body).every((key) => keys.includes(key));
const id = (value: unknown): value is string =>
  isCanonicalPositiveDecimal(value) && value.length <= ID_MAX;
const operationID = (value: unknown): value is string =>
  isBoundedString(value, OPERATION_MAX) && /^[A-Za-z0-9._:-]+$/.test(value);
const status = (value: unknown): value is string => typeof value === "string" && statuses.has(value);
const role = (value: unknown): value is string => typeof value === "string" && roles.has(value);
const stringArray = (value: unknown, maximum = 100, decimal = false): string[] | null => {
  if (!Array.isArray(value) || value.length > maximum) return null;
  if (!value.every((item) => decimal ? id(item) : isBoundedString(item, 128))) return null;
  const values = value as string[];
  return new Set(values).size === values.length ? values : null;
};
const sortedDecimalIDs = (values: string[] | null): string[] | null => values === null
  ? null
  : [...values].sort((left, right) => left.length - right.length || (left < right ? -1 : left > right ? 1 : 0));
const date = (value: unknown): string | null | undefined => {
  if (value === null) return null;
  if (!isBoundedString(value, 64) || !Number.isFinite(Date.parse(value))) return undefined;
  return new Date(value).toISOString();
};
const email = (value: unknown) =>
  isBoundedString(value, 255, 3) && /^[\x21-\x7e]+$/.test(value) && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
const cursorOK = (value: unknown): value is string =>
  isCanonicalUnsignedDecimal(value) && value.length <= ID_MAX;
const sqlJSON = (value: unknown) => canonical(value);

function legacyMicrousd(value: string): string | undefined {
  try {
    const amount = BigInt(value);
    return amount % 100n === 0n ? (amount / 100n).toString() : undefined;
  } catch { return undefined; }
}
function amountE8(body: Record<string, unknown>, e8Key: string, legacyKey: string): string | null {
  const e8 = body[e8Key]; const legacy = body[legacyKey];
  if (e8 === undefined && legacy === undefined) return null;
  if (e8 !== undefined && (!isCanonicalUnsignedDecimal(e8) || e8.length > 40)) return null;
  if (legacy !== undefined && (!isCanonicalUnsignedDecimal(legacy) || legacy.length > 38)) return null;
  const legacyAsE8 = legacy === undefined ? undefined : (BigInt(legacy as string) * 100n).toString();
  if (e8 !== undefined && legacyAsE8 !== undefined && e8 !== legacyAsE8) return null;
  return (e8 ?? legacyAsE8)! as string;
}

function publicAmountE8(body: Record<string, unknown>, e8Key: string, legacyKey: string): string | null {
  const amount = amountE8(body, e8Key, legacyKey);
  if (amount === null) return null;
  try { return BigInt(amount) <= MAX_PUBLIC_BALANCE_E8_USD ? amount : null; } catch { return null; }
}

function legacyDisplayUSD(value: bigint): number | undefined {
  const display = Number(value) / 100_000_000;
  return Number.isFinite(display) ? display : undefined;
}

function parsedArray(value: string, decimal = false): string[] | null {
  try { return stringArray(JSON.parse(value), 100, decimal); } catch { return null; }
}
function parsedObject(value: string): Record<string, unknown> | null {
  try { const parsed = JSON.parse(value); return isObject(parsed) ? parsed : null; } catch { return null; }
}
function userRow(row: Record<string, unknown>): User | null {
  const groups = parsedArray(String(row.allowed_group_ids_json), true);
  if (groups === null) return null;
  return {
    id: String(row.id), email: String(row.email), username: String(row.username), notes: String(row.notes),
    status: String(row.status), role: String(row.role), concurrency: Number(row.concurrency),
    rpm_limit: Number(row.rpm_limit), balance_e8_usd: String(row.balance_e8_usd),
    ...(legacyMicrousd(String(row.balance_e8_usd)) === undefined ? {} : { balance_microusd: legacyMicrousd(String(row.balance_e8_usd)) }),
    allowed_group_ids: groups, restrict_public_groups: Number(row.restrict_public_groups) === 1,
    created_at: String(row.created_at), updated_at: String(row.updated_at),
    deleted_at: row.deleted_at === null ? null : String(row.deleted_at),
  };
}
function groupRow(row: Record<string, unknown>): Group {
  return {
    id: String(row.id), name: String(row.name), platform: String(row.platform), status: String(row.status),
    is_exclusive: Number(row.is_exclusive) === 1, subscription_type: String(row.subscription_type),
    created_at: String(row.created_at), updated_at: String(row.updated_at),
    deleted_at: row.deleted_at === null ? null : String(row.deleted_at),
  };
}
function keyRow(row: Record<string, unknown>): APIKey | null {
  const whitelist = parsedArray(String(row.ip_whitelist_json));
  const blacklist = parsedArray(String(row.ip_blacklist_json));
  if (whitelist === null || blacklist === null) return null;
  return {
    id: String(row.id), user_id: String(row.user_id), group_id: String(row.group_id), name: String(row.name),
    status: String(row.status), ip_whitelist: whitelist, ip_blacklist: blacklist,
    expires_at: row.expires_at === null ? null : String(row.expires_at),
    last_used_at: row.last_used_at === null ? null : String(row.last_used_at),
    created_at: String(row.created_at), updated_at: String(row.updated_at),
    deleted_at: row.deleted_at === null ? null : String(row.deleted_at),
  };
}
function accountRow(row: Record<string, unknown>, groupIDs: string[]): Account | null {
  const extra = parsedObject(String(row.extra_json));
  if (!extra || String(row.type) !== "apikey") return null;
  return {
    id: String(row.id), name: String(row.name), platform: String(row.platform), type: "apikey",
    status: String(row.status), schedulable: Number(row.schedulable) === 1, priority: Number(row.priority),
    max_concurrency: Number(row.max_concurrency), extra, group_ids: groupIDs,
    created_at: String(row.created_at), updated_at: String(row.updated_at),
    deleted_at: row.deleted_at === null ? null : String(row.deleted_at),
  };
}

function accountReadProjection(account: Account): Account {
  const privacyMode = account.extra.privacy_mode;
  const extra = typeof privacyMode === "string" && readablePrivacyModes.has(privacyMode)
    ? { privacy_mode: privacyMode }
    : {};
  return {
    id: account.id, name: account.name, platform: account.platform, type: account.type,
    status: account.status, schedulable: account.schedulable, priority: account.priority,
    max_concurrency: account.max_concurrency, extra, group_ids: account.group_ids,
    created_at: account.created_at, updated_at: account.updated_at, deleted_at: account.deleted_at,
  };
}

function accountExtraOK(extra: Record<string, unknown>): boolean {
  const keys = Object.keys(extra);
  return keys.length === 0 || (keys.length === 1 && typeof extra.privacy_mode === "string" && readablePrivacyModes.has(extra.privacy_mode));
}

function accountOperationReadProjection(response: Record<string, unknown>): Record<string, unknown> | null {
  const account = response.account;
  if (!isObject(account) || !isObject(account.extra) || !Array.isArray(account.group_ids)) return null;
  return { account: accountReadProjection(account as Account) };
}

async function first(env: Env, query: string, value: string): Promise<Record<string, unknown> | null> {
  return env.DB.prepare(query).bind(value).first<Record<string, unknown>>();
}
async function getUser(env: Env, value: string) { const row = await first(env, "SELECT id,email,username,notes,status,role,concurrency,rpm_limit,balance_e8_usd,allowed_group_ids_json,restrict_public_groups,created_at,updated_at,deleted_at FROM users WHERE id=?", value); return row ? userRow(row) : null; }
async function getGroup(env: Env, value: string) { const row = await first(env, "SELECT id,name,platform,status,is_exclusive,subscription_type,created_at,updated_at,deleted_at FROM groups WHERE id=?", value); return row ? groupRow(row) : null; }
async function getKey(env: Env, value: string) { const row = await first(env, "SELECT id,user_id,group_id,name,status,ip_whitelist_json,ip_blacklist_json,expires_at,last_used_at,created_at,updated_at,deleted_at FROM api_keys WHERE id=?", value); return row ? keyRow(row) : null; }
async function getAccount(env: Env, value: string): Promise<Account | null> {
  const row = await first(env, "SELECT id,name,platform,type,status,schedulable,priority,max_concurrency,extra_json,created_at,updated_at,deleted_at FROM accounts WHERE id=?", value);
  if (!row) return null;
  const groups = await env.DB.prepare("SELECT group_id FROM account_groups WHERE account_id=? ORDER BY length(group_id),group_id").bind(value).all<{ group_id: string }>();
  return accountRow(row, groups.results.map((item) => item.group_id));
}
async function groupsExist(env: Env, values: string[], active = false): Promise<boolean> {
  if (values.length === 0) return true;
  const marks = values.map(() => "?").join(",");
  const row = await env.DB.prepare("SELECT count(*) count FROM groups WHERE id IN (" + marks + ") AND deleted_at IS NULL" + (active ? " AND status='active'" : "")).bind(...values).first<{ count: number }>();
  return row?.count === values.length;
}
async function managedOperation(
  env: Env, route: string, operation: string, fingerprint: unknown, response: Record<string, unknown>,
  statements: D1PreparedStatement[],
): Promise<{ response: Record<string, unknown>; replay: boolean } | null> {
  const requestHash = await sha256(canonical(fingerprint));
  const prior = await env.DB.prepare("SELECT route,request_hash,response_json FROM management_operations WHERE operation_id=?").bind(operation).first<{ route: string; request_hash: string; response_json: string }>();
  if (prior) {
    if (prior.route !== route || prior.request_hash !== requestHash) return null;
    const stored = parsedObject(prior.response_json);
    return stored ? { response: stored, replay: true } : null;
  }
  try {
    const [primary, ...following] = statements;
    if (!primary) return null;
    await env.DB.batch([
      primary,
      env.DB.prepare(
        "INSERT INTO management_operations(operation_id,route,request_hash,response_json,created_at) SELECT ?,?,?,?,? WHERE changes()=1",
      ).bind(operation, route, requestHash, canonical(response), now()),
      ...following,
    ]);
    const written = await env.DB.prepare(
      "SELECT route,request_hash,response_json FROM management_operations WHERE operation_id=?",
    ).bind(operation).first<{ route: string; request_hash: string; response_json: string }>();
    if (written?.route !== route || written.request_hash !== requestHash) return null;
    return { response, replay: false };
  } catch {
    const raced = await env.DB.prepare("SELECT route,request_hash,response_json FROM management_operations WHERE operation_id=?").bind(operation).first<{ route: string; request_hash: string; response_json: string }>();
    const stored = raced?.route === route && raced.request_hash === requestHash
      ? parsedObject(raced.response_json)
      : null;
    return stored ? { response: stored, replay: true } : null;
  }
}
type OperationLookup =
  | { kind: "replay"; response: Record<string, unknown> }
  | { kind: "conflict" }
  | null;
async function lookupOperation(
  env: Env, route: string, operation: string, fingerprint: unknown,
): Promise<OperationLookup> {
  const requestHash = await sha256(canonical(fingerprint));
  const prior = await env.DB.prepare(
    "SELECT route,request_hash,response_json FROM management_operations WHERE operation_id=?",
  ).bind(operation).first<{ route: string; request_hash: string; response_json: string }>();
  if (!prior) return null;
  if (prior.route !== route || prior.request_hash !== requestHash) return { kind: "conflict" };
  const response = parsedObject(prior.response_json);
  return response ? { kind: "replay", response } : { kind: "conflict" };
}
async function recordNoopOperation(
  env: Env, route: string, operation: string, fingerprint: unknown,
  response: Record<string, unknown>,
): Promise<Record<string, unknown> | null> {
  const requestHash = await sha256(canonical(fingerprint));
  try {
    await env.DB.prepare(
      "INSERT INTO management_operations(operation_id,route,request_hash,response_json,created_at) VALUES(?,?,?,?,?)",
    ).bind(operation, route, requestHash, canonical(response), now()).run();
    return response;
  } catch {
    const prior = await env.DB.prepare(
      "SELECT route,request_hash,response_json FROM management_operations WHERE operation_id=?",
    ).bind(operation).first<{ route: string; request_hash: string; response_json: string }>();
    if (prior?.route !== route || prior.request_hash !== requestHash) return null;
    return parsedObject(prior.response_json);
  }
}
async function replyMutation(env: Env, route: string, operation: string, fingerprint: unknown, response: Record<string, unknown>, statements: D1PreparedStatement[]) {
  const saved = await managedOperation(env, route, operation, fingerprint, response, statements);
  return saved ? json(saved.response) : error("CONFLICT", 409);
}
async function replyNoopMutation(env: Env, route: string, operation: string, fingerprint: unknown, response: Record<string, unknown>) {
  const saved = await recordNoopOperation(env, route, operation, fingerprint, response);
  return saved ? json(saved) : error("CONFLICT", 409);
}

export async function managementControlPlane(request: Request, env: Env, route: string): Promise<Response> {
  if (!isBoundedString(request.headers.get("X-Sub2API-Container-Id"), 256)) return error("NOT_FOUND", 404);
  const body = await readJson<unknown>(request);
  if (!isObject(body)) return error("INVALID_REQUEST");
  if (route.endsWith("/balance-history")) return balanceHistory(env, body);
  if (route.endsWith("/get")) return get(env, route, body);
  if (route.endsWith("/list")) return list(env, route, body);
  return mutate(env, route, body);
}

async function balanceHistory(env: Env, body: Record<string, unknown>): Promise<Response> {
  if (!only(body, ["id", "page", "page_size", "type"]) || !id(body.id) ||
    !Number.isInteger(body.page) || Number(body.page) < 1 || Number(body.page) > 1_000_000 ||
    !Number.isInteger(body.page_size) || Number(body.page_size) < 1 || Number(body.page_size) > PAGE_MAX ||
    (body.type !== undefined && !isBoundedString(body.type, 64))) return error("INVALID_REQUEST");
  const user = await getUser(env, body.id as string);
  if (!user || user.deleted_at !== null) return error("NOT_FOUND", 404);

  const page = Number(body.page);
  const pageSize = Number(body.page_size);
  const type = body.type === undefined ? "" : body.type as string;
  if (!["", "admin_balance", "balance", "affiliate_balance", "concurrency", "admin_concurrency", "subscription"].includes(type)) return error("INVALID_REQUEST");
  const matchesLedger = type === "" || type === "admin_balance";
  const total = matchesLedger
    ? await env.DB.prepare("SELECT count(*) AS total FROM balance_ledger WHERE target_user_id=?").bind(user.id).first<{ total: number }>()
    : { total: 0 };
  const recharged = await env.DB.prepare("SELECT delta_e8_usd FROM balance_ledger WHERE target_user_id=?").bind(user.id).all<{ delta_e8_usd: string }>();
  let totalRechargedE8USD = 0n;
  for (const entry of recharged.results) {
    if (isCanonicalUnsignedDecimal(entry.delta_e8_usd) && entry.delta_e8_usd !== "0") totalRechargedE8USD += BigInt(entry.delta_e8_usd);
  }
  const rows = matchesLedger
    ? await env.DB.prepare("SELECT CAST(rowid AS TEXT) AS id, adjustment_type, reason, delta_e8_usd, balance_before_e8_usd, balance_after_e8_usd, created_at FROM balance_ledger WHERE target_user_id=? ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?").bind(user.id, pageSize, (page - 1) * pageSize).all<Record<string, unknown>>()
    : { results: [] as Record<string, unknown>[] };
  const items = rows.results.map((row) => ({
    id: String(row.id),
    adjustment_type: String(row.adjustment_type),
    reason: String(row.reason),
    delta_e8_usd: String(row.delta_e8_usd),
    balance_before_e8_usd: String(row.balance_before_e8_usd),
    balance_after_e8_usd: String(row.balance_after_e8_usd),
    ...(legacyMicrousd(String(row.delta_e8_usd)) === undefined ? {} : { delta_microusd: legacyMicrousd(String(row.delta_e8_usd)) }),
    ...(legacyMicrousd(String(row.balance_before_e8_usd)) === undefined ? {} : { balance_before_microusd: legacyMicrousd(String(row.balance_before_e8_usd)) }),
    ...(legacyMicrousd(String(row.balance_after_e8_usd)) === undefined ? {} : { balance_after_microusd: legacyMicrousd(String(row.balance_after_e8_usd)) }),
    created_at: String(row.created_at),
  }));
  const legacyTotal = legacyDisplayUSD(totalRechargedE8USD);
  return json({ items, total: String(total?.total ?? 0), total_recharged_e8_usd: totalRechargedE8USD.toString(), ...(legacyTotal === undefined ? {} : { total_recharged: legacyTotal }) });
}

async function get(env: Env, route: string, body: Record<string, unknown>): Promise<Response> {
  if (!only(body, ["id"]) || !id(body.id)) return error("INVALID_REQUEST");
  if (route.includes("/users/")) { const user = await getUser(env, body.id); return user ? json({ user }) : error("NOT_FOUND", 404); }
  if (route.includes("/groups/")) { const group = await getGroup(env, body.id); return group ? json({ group }) : error("NOT_FOUND", 404); }
  if (route.includes("/api-keys/")) { const api_key = await getKey(env, body.id); return api_key ? json({ api_key }) : error("NOT_FOUND", 404); }
  const account = await getAccount(env, body.id); return account ? json({ account: accountReadProjection(account) }) : error("NOT_FOUND", 404);
}

const pageQuery = (table: string, columns: string, where = "") =>
  "SELECT " + columns + " FROM " + table + " WHERE (length(id)>length(?) OR (length(id)=length(?) AND id>?))" + where + " ORDER BY length(id),id LIMIT ?";
async function list(env: Env, route: string, body: Record<string, unknown>): Promise<Response> {
  if (!only(body, ["cursor", "limit"])) return error("INVALID_REQUEST");
  const cursor = body.cursor === undefined ? "0" : body.cursor;
  const limit = body.limit === undefined ? 50 : body.limit;
  if (!cursorOK(cursor) || !Number.isInteger(limit) || Number(limit) < 1 || Number(limit) > PAGE_MAX) return error("INVALID_REQUEST");
  const size = Number(limit);
  if (route.includes("/users/")) {
    const rows = await env.DB.prepare(pageQuery("users", "id,email,username,notes,status,role,concurrency,rpm_limit,balance_e8_usd,allowed_group_ids_json,restrict_public_groups,created_at,updated_at,deleted_at")).bind(cursor,cursor,cursor,size+1).all<Record<string, unknown>>();
    const users = rows.results.slice(0,size).map(userRow); if (users.some((item) => !item)) return error("CONTROL_PLANE_UNAVAILABLE",503);
    return json({ users, next_cursor: rows.results.length > size ? users.at(-1)?.id ?? null : null });
  }
  if (route.includes("/groups/")) {
    const rows = await env.DB.prepare(pageQuery("groups", "id,name,platform,status,is_exclusive,subscription_type,created_at,updated_at,deleted_at")).bind(cursor,cursor,cursor,size+1).all<Record<string, unknown>>();
    const groups = rows.results.slice(0,size).map(groupRow); return json({ groups, next_cursor: rows.results.length > size ? groups.at(-1)?.id ?? null : null });
  }
  if (route.includes("/api-keys/")) {
    const rows = await env.DB.prepare(pageQuery("api_keys", "id,user_id,group_id,name,status,ip_whitelist_json,ip_blacklist_json,expires_at,last_used_at,created_at,updated_at,deleted_at")).bind(cursor,cursor,cursor,size+1).all<Record<string, unknown>>();
    const api_keys = rows.results.slice(0,size).map(keyRow); if (api_keys.some((item) => !item)) return error("CONTROL_PLANE_UNAVAILABLE",503);
    return json({ api_keys, next_cursor: rows.results.length > size ? api_keys.at(-1)?.id ?? null : null });
  }
  const rows = await env.DB.prepare(pageQuery("accounts", "id", " AND type='apikey'")).bind(cursor,cursor,cursor,size+1).all<{ id: string }>();
  const loaded = await Promise.all(rows.results.slice(0,size).map((row) => getAccount(env,row.id)));
  if (loaded.some((item) => item === null)) return error("CONTROL_PLANE_UNAVAILABLE",503);
  const accounts = (loaded as Account[]).map(accountReadProjection);
  return json({ accounts, next_cursor: rows.results.length > size ? accounts.at(-1)?.id ?? null : null });
}

async function mutate(env: Env, route: string, body: Record<string, unknown>): Promise<Response> {
  if (!operationID(body.operation_id)) return error("INVALID_REQUEST");
  if (route.includes("/users/")) return userMutation(env,route,body,body.operation_id);
  if (route.includes("/groups/")) return groupMutation(env,route,body,body.operation_id);
  if (route.includes("/api-keys/")) return keyMutation(env,route,body,body.operation_id);
  return accountMutation(env,route,body,body.operation_id);
}

const userCreateKeys = [
  "operation_id", "semantic_digest", "id", "email", "password_hash",
  "username", "notes", "status", "role", "concurrency", "rpm_limit",
  "balance_e8_usd", "balance_microusd", "allowed_group_ids", "restrict_public_groups",
];
const userUpdateKeys = [
  "operation_id", "id", "email", "password_hash", "username", "notes",
  "status", "concurrency", "rpm_limit", "allowed_group_ids",
  "restrict_public_groups",
];
const userPatchKeys = userUpdateKeys.filter((key) => key !== "operation_id" && key !== "id");
const liveGroupPredicate =
  "NOT EXISTS (SELECT 1 FROM json_each(?) requested LEFT JOIN groups g ON g.id=requested.value WHERE g.id IS NULL OR g.deleted_at IS NOT NULL)";

function validPasswordHash(value: unknown): value is string {
  return isBoundedString(value, 255, 20);
}

function validUserCreate(body: Record<string, unknown>, groups: string[] | null): boolean {
  return email(body.email) &&
    validPasswordHash(body.password_hash) &&
    isBoundedString(body.semantic_digest, 64, 64) &&
    /^[0-9a-f]{64}$/.test(body.semantic_digest) &&
    isBoundedString(body.username, 100, 0) &&
    isBoundedString(body.notes, 4096, 0) &&
    body.status === "active" && body.role === "user" &&
    Number.isInteger(body.concurrency) && Number(body.concurrency) >= 1 && Number(body.concurrency) <= 100000 &&
    Number.isInteger(body.rpm_limit) && Number(body.rpm_limit) >= 0 && Number(body.rpm_limit) <= 1000000 &&
    publicAmountE8(body, "balance_e8_usd", "balance_microusd") !== null &&
    groups !== null && typeof body.restrict_public_groups === "boolean";
}

function validUserPatch(body: Record<string, unknown>, groups: string[] | null): boolean {
  if (!userPatchKeys.some((key) => body[key] !== undefined)) return false;
  if (body.email !== undefined && !email(body.email)) return false;
  if (body.password_hash !== undefined && !validPasswordHash(body.password_hash)) return false;
  if (body.username !== undefined && !isBoundedString(body.username, 100, 0)) return false;
  if (body.notes !== undefined && !isBoundedString(body.notes, 4096, 0)) return false;
  if (body.status !== undefined && !status(body.status)) return false;
  if (body.concurrency !== undefined &&
    (!Number.isInteger(body.concurrency) || Number(body.concurrency) < 1 || Number(body.concurrency) > 100000)) return false;
  if (body.rpm_limit !== undefined &&
    (!Number.isInteger(body.rpm_limit) || Number(body.rpm_limit) < 0 || Number(body.rpm_limit) > 1000000)) return false;
  if (body.allowed_group_ids !== undefined && groups === null) return false;
  return body.restrict_public_groups === undefined || typeof body.restrict_public_groups === "boolean";
}

async function liveEmailExists(env: Env, value: string, excludingID?: string): Promise<boolean> {
  const query = excludingID === undefined
    ? "SELECT id FROM users WHERE lower(trim(email))=lower(trim(?)) AND deleted_at IS NULL LIMIT 1"
    : "SELECT id FROM users WHERE lower(trim(email))=lower(trim(?)) AND id<>? AND deleted_at IS NULL LIMIT 1";
  const statement = env.DB.prepare(query);
  const row = excludingID === undefined
    ? await statement.bind(value).first<{ id: string }>()
    : await statement.bind(value, excludingID).first<{ id: string }>();
  return row !== null;
}

async function userMutation(env: Env, route: string, body: Record<string, unknown>, operation: string): Promise<Response> {
  if (route.endsWith("/balance-adjust")) return balanceAdjustment(env, route, body, operation);
  if (route.endsWith("/create")) return createUserMutation(env, route, body, operation);
  if (route.endsWith("/role-change")) return roleChangeUserMutation(env, route, body, operation);
  if (route.endsWith("/delete")) return deleteUserMutation(env, route, body, operation);
  return updateUserMutation(env, route, body, operation);
}

async function balanceAdjustment(env: Env, route: string, body: Record<string, unknown>, operation: string): Promise<Response> {
  const admittedAmount = amountE8(body, "amount_e8_usd", "amount_microusd");
  if (!only(body, ["operation_id", "actor_user_id", "target_user_id", "operation", "amount_e8_usd", "amount_microusd", "reason"]) ||
    !id(body.actor_user_id) || !id(body.target_user_id) ||
    (body.operation !== "set" && body.operation !== "add" && body.operation !== "subtract") ||
    admittedAmount === null || admittedAmount === "0" ||
    !isBoundedString(body.reason, 4096, 0)) return error("INVALID_REQUEST");
  const fingerprint = {
    operation_id: operation,
    actor_user_id: body.actor_user_id,
    target_user_id: body.target_user_id,
    operation: body.operation,
    amount_e8_usd: admittedAmount,
    reason: body.reason,
  };
  const prior = await lookupOperation(env, route, operation, fingerprint);
  if (prior) return prior.kind === "replay" ? json({ ...prior.response, replayed: true }) : error("IDEMPOTENCY_CONFLICT", 409);
  const [actor, target] = await Promise.all([getUser(env, body.actor_user_id as string), getUser(env, body.target_user_id as string)]);
  if (!actor || actor.deleted_at !== null || actor.status !== "active" || actor.role !== "admin") return error("ACTOR_FORBIDDEN", 403);
  if (!target || target.deleted_at !== null) return error("TARGET_NOT_FOUND", 404);
  const balanceVersion = await env.DB.prepare("SELECT balance_version FROM users WHERE id=?")
    .bind(target.id).first<{balance_version:number}>();
  if (!balanceVersion || !Number.isSafeInteger(balanceVersion.balance_version)) return error("STALE_BALANCE", 409);
  let before: bigint; let amount: bigint;
  try { before = BigInt(target.balance_e8_usd); amount = BigInt(admittedAmount); } catch { return error("INVALID_REQUEST"); }
  const after = body.operation === "set" ? amount : body.operation === "add" ? before + amount : before - amount;
  if (after < 0n) return error("BALANCE_NEGATIVE", 409);
  if (after > MAX_PUBLIC_BALANCE_E8_USD) return error("BALANCE_OVERFLOW", 409);
  const delta = after - before;
  const response = { balance: { ledger_id: operation, actor_user_id: actor.id, target_user_id: target.id, adjustment_type: body.operation, reason: body.reason, delta_e8_usd: delta.toString(), balance_before_e8_usd: before.toString(), balance_after_e8_usd: after.toString(), ...(legacyMicrousd(delta.toString()) === undefined ? {} : { delta_microusd: legacyMicrousd(delta.toString()) }), ...(legacyMicrousd(before.toString()) === undefined ? {} : { balance_before_microusd: legacyMicrousd(before.toString()) }), ...(legacyMicrousd(after.toString()) === undefined ? {} : { balance_after_microusd: legacyMicrousd(after.toString()) }) } };
  const stamp = now();
  const saved = await managedOperation(env, route, operation, fingerprint, response, [
    env.DB.prepare("UPDATE users SET balance_e8_usd=?,balance_version=balance_version+1,updated_at=? WHERE id=? AND deleted_at IS NULL AND balance_e8_usd=? AND balance_version=? AND EXISTS(SELECT 1 FROM users AS actor WHERE actor.id=? AND actor.deleted_at IS NULL AND actor.status='active' AND actor.role='admin')").bind(after.toString(), stamp, target.id, before.toString(), balanceVersion.balance_version, actor.id),
    env.DB.prepare("INSERT INTO balance_ledger(id,operation_id,actor_user_id,target_user_id,adjustment_type,reason,delta_e8_usd,balance_before_e8_usd,balance_after_e8_usd,created_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM management_operations WHERE operation_id=?)").bind(operation, operation, actor.id, target.id, body.operation, body.reason, delta.toString(), before.toString(), after.toString(), stamp, operation),
  ]);
  if (saved) return json({ ...saved.response, replayed: saved.replay });
  const raced = await lookupOperation(env, route, operation, fingerprint);
  if (raced?.kind === "replay") return json({ ...raced.response, replayed: true });
  if (raced?.kind === "conflict") return error("IDEMPOTENCY_CONFLICT", 409);
  const [currentActor, current] = await Promise.all([getUser(env, actor.id), getUser(env, target.id)]);
  if (!currentActor || currentActor.deleted_at !== null || currentActor.status !== "active" || currentActor.role !== "admin") return error("ACTOR_FORBIDDEN", 403);
  if (!current || current.deleted_at !== null) return error("TARGET_NOT_FOUND", 404);
  return error("STALE_BALANCE", 409);
}

async function createUserMutation(
  env: Env,
  route: string,
  body: Record<string, unknown>,
  operation: string,
): Promise<Response> {
  const groups = stringArray(body.allowed_group_ids, 100, true);
  const balanceE8USD = publicAmountE8(body, "balance_e8_usd", "balance_microusd");
  if (!only(body, userCreateKeys) || !id(body.id) || !validUserCreate(body, groups)) {
    return error("INVALID_REQUEST");
  }

  const fingerprint = {
    operation_id: operation,
    semantic_digest: body.semantic_digest,
    email: body.email,
    username: body.username,
    notes: body.notes,
    status: body.status,
    role: body.role,
    concurrency: body.concurrency,
    rpm_limit: body.rpm_limit,
    balance_e8_usd: balanceE8USD,
    allowed_group_ids: groups,
    restrict_public_groups: body.restrict_public_groups,
  };
  const prior = await lookupOperation(env, route, operation, fingerprint);
  if (prior) {
    return prior.kind === "replay"
      ? json({ ...prior.response, replayed: true })
      : error("IDEMPOTENCY_CONFLICT", 409);
  }
  if (await getUser(env, body.id)) return error("CONFLICT", 409);
  if (await liveEmailExists(env, body.email as string)) return error("EMAIL_EXISTS", 409);
  if (!(await groupsExist(env, groups!))) return error("REFERENCE_REJECTED", 409);

  const stamp = now();
  const user: User = {
    id: body.id,
    email: body.email as string,
    username: body.username as string,
    notes: body.notes as string,
    status: "active",
    role: "user",
    concurrency: body.concurrency as number,
    rpm_limit: body.rpm_limit as number,
    balance_e8_usd: balanceE8USD!,
    allowed_group_ids: groups!,
    restrict_public_groups: body.restrict_public_groups as boolean,
    created_at: stamp,
    updated_at: stamp,
    deleted_at: null,
  };
  const statement = env.DB.prepare(
    "INSERT INTO users(id,status,role,concurrency,balance_e8_usd,allowed_group_ids_json,restrict_public_groups,created_at,email,password_hash,username,notes,rpm_limit,updated_at,deleted_at) " +
    "SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE " + liveGroupPredicate,
  ).bind(
    user.id, user.status, user.role, user.concurrency, user.balance_e8_usd,
    sqlJSON(user.allowed_group_ids), user.restrict_public_groups ? 1 : 0,
    user.created_at, user.email, body.password_hash, user.username, user.notes,
    user.rpm_limit, user.updated_at, user.deleted_at, sqlJSON(user.allowed_group_ids),
  );
  const saved = await managedOperation(env, route, operation, fingerprint, { user }, [statement]);
  if (saved) return json({ ...saved.response, replayed: saved.replay });

  if (await liveEmailExists(env, user.email)) return error("EMAIL_EXISTS", 409);
  if (!(await groupsExist(env, user.allowed_group_ids))) return error("REFERENCE_REJECTED", 409);
  const raced = await lookupOperation(env, route, operation, fingerprint);
  if (raced?.kind === "replay") return json({ ...raced.response, replayed: true });
  if (raced?.kind === "conflict") return error("IDEMPOTENCY_CONFLICT", 409);
  return error("CONFLICT", 409);
}

async function updateUserMutation(
  env: Env,
  route: string,
  body: Record<string, unknown>,
  operation: string,
): Promise<Response> {
  const groupsProvided = body.allowed_group_ids !== undefined;
  const groups = groupsProvided ? stringArray(body.allowed_group_ids, 100, true) : null;
  if (!only(body, userUpdateKeys) || !id(body.id) || !validUserPatch(body, groups)) {
    return error("INVALID_REQUEST");
  }
  const fingerprint = body.password_hash === undefined
    ? body
    : { ...body, password_hash: "sha256:" + await sha256(body.password_hash as string) };
  const prior = await lookupOperation(env, route, operation, fingerprint);
  if (prior) {
    return prior.kind === "replay" ? json(prior.response) : error("IDEMPOTENCY_CONFLICT", 409);
  }

  const old = await getUser(env, body.id);
  if (!old) return error("NOT_FOUND", 404);
  if (old.deleted_at !== null) return error("CONFLICT", 409);
  if (groupsProvided && !(await groupsExist(env, groups!))) return error("REFERENCE_REJECTED", 409);
  if (body.email !== undefined && await liveEmailExists(env, body.email as string, old.id)) {
    return error("EMAIL_EXISTS", 409);
  }

  const stamp = now();
  const user: User = {
    ...old,
    email: (body.email ?? old.email) as string,
    username: (body.username ?? old.username) as string,
    notes: (body.notes ?? old.notes) as string,
    status: (body.status ?? old.status) as string,
    concurrency: (body.concurrency ?? old.concurrency) as number,
    rpm_limit: (body.rpm_limit ?? old.rpm_limit) as number,
    allowed_group_ids: groupsProvided ? groups! : old.allowed_group_ids,
    restrict_public_groups: (body.restrict_public_groups ?? old.restrict_public_groups) as boolean,
    updated_at: stamp,
  };
  const statement = patchUserStatement(env, body, user, stamp, groupsProvided);
  const saved = await managedOperation(env, route, operation, fingerprint, { user }, [statement]);
  if (saved) return json(saved.response);

  const current = await getUser(env, user.id);
  if (!current) return error("NOT_FOUND", 404);
  if (current.deleted_at !== null) return error("CONFLICT", 409);
  if (current.role === "admin" && (body.status ?? current.status) === "disabled") {
    return error("ROLE_PROTECTED", 409);
  }
  if (groupsProvided && !(await groupsExist(env, groups!))) return error("REFERENCE_REJECTED", 409);
  if (body.email !== undefined && await liveEmailExists(env, body.email as string, current.id)) {
    return error("EMAIL_EXISTS", 409);
  }
  const raced = await lookupOperation(env, route, operation, fingerprint);
  if (raced?.kind === "replay") return json(raced.response);
  if (raced?.kind === "conflict") return error("IDEMPOTENCY_CONFLICT", 409);
  return error("CONFLICT", 409);
}

const roleChangeKeys = [
  "operation_id", "actor_user_id", "actor_auth_method", "actor_session_id",
  "id", "role", "email", "password_hash", "password_semantic_digest",
  "username", "notes", "status",
  "concurrency", "rpm_limit", "allowed_group_ids", "restrict_public_groups",
];

function validRoleChangePatch(body: Record<string, unknown>, groups: string[] | null): boolean {
  if (body.email !== undefined && !email(body.email)) return false;
  if (body.password_hash !== undefined && !validPasswordHash(body.password_hash)) return false;
  const hasPassword = body.password_hash !== undefined;
  const hasPasswordDigest = body.password_semantic_digest !== undefined;
  if (hasPassword !== hasPasswordDigest) return false;
  if (hasPasswordDigest &&
    (!isBoundedString(body.password_semantic_digest, 64, 64) ||
      !/^[0-9a-f]{64}$/.test(body.password_semantic_digest as string))) return false;
  if (body.username !== undefined && !isBoundedString(body.username, 100, 0)) return false;
  if (body.notes !== undefined && !isBoundedString(body.notes, 4096, 0)) return false;
  if (body.status !== undefined && !status(body.status)) return false;
  if (body.concurrency !== undefined &&
    (!Number.isInteger(body.concurrency) || Number(body.concurrency) < 1 || Number(body.concurrency) > 100000)) return false;
  if (body.rpm_limit !== undefined &&
    (!Number.isInteger(body.rpm_limit) || Number(body.rpm_limit) < 0 || Number(body.rpm_limit) > 1000000)) return false;
  if (body.allowed_group_ids !== undefined && groups === null) return false;
  return body.restrict_public_groups === undefined || typeof body.restrict_public_groups === "boolean";
}

async function roleChangeAuthorization(
  env: Env,
  body: Record<string, unknown>,
): Promise<Response | null> {
  if (body.actor_auth_method !== "jwt") {
    return error(
      body.actor_auth_method === "admin_api_key"
        ? "STEP_UP_ADMIN_API_KEY_FORBIDDEN"
        : "STEP_UP_JWT_REQUIRED",
      403,
    );
  }
  if (!isBoundedString(body.actor_session_id, 128, 8)) {
    return error("STEP_UP_SESSION_REQUIRED", 401);
  }
  const actorID = body.actor_user_id as string;
  const grant = await env.TOTP_SECURITY.get(
    env.TOTP_SECURITY.idFromName(`user:${actorID}`),
  ).hasStepUp(actorID, body.actor_session_id);
  if (!grant.ok) {
    return grant.code === "TOTP_NOT_SETUP"
      ? error("STEP_UP_TOTP_NOT_ENABLED", 403)
      : error("STEP_UP_UNAVAILABLE", 503);
  }
  return grant.granted ? null : error("STEP_UP_REQUIRED", 403);
}

function roleChangeFingerprint(
  body: Record<string, unknown>,
  groups: string[] | null,
): Record<string, unknown> {
  const fingerprint: Record<string, unknown> = {
    operation_id: body.operation_id,
    actor_user_id: body.actor_user_id,
    id: body.id,
    role: body.role,
    password_semantic_digest: body.password_semantic_digest ?? null,
  };
  for (const key of [
    "email", "username", "notes", "status", "concurrency", "rpm_limit",
    "restrict_public_groups",
  ]) {
    if (body[key] !== undefined) fingerprint[key] = body[key];
  }
  if (body.allowed_group_ids !== undefined) fingerprint.allowed_group_ids = groups;
  return fingerprint;
}

async function hasOtherLiveAdmin(env: Env, targetID: string): Promise<boolean> {
  const row = await env.DB.prepare(
    "SELECT id FROM users WHERE id<>? AND role='admin' AND status='active' AND deleted_at IS NULL LIMIT 1",
  ).bind(targetID).first<{ id: string }>();
  return row !== null;
}

async function roleChangeUserMutation(
  env: Env,
  route: string,
  body: Record<string, unknown>,
  operation: string,
): Promise<Response> {
  const groupsProvided = body.allowed_group_ids !== undefined;
  const groups = groupsProvided ? stringArray(body.allowed_group_ids, 100, true) : null;
  if (!only(body, roleChangeKeys) || !id(body.actor_user_id) || !id(body.id) ||
    !role(body.role) || !validRoleChangePatch(body, groups)) {
    return error("INVALID_REQUEST");
  }
  const authorization = await roleChangeAuthorization(env, body);
  if (authorization) return authorization;

  const fingerprint = roleChangeFingerprint(body, groups);
  const prior = await lookupOperation(env, route, operation, fingerprint);
  if (prior) {
    return prior.kind === "replay"
      ? json({ ...prior.response, replayed: true })
      : error("IDEMPOTENCY_CONFLICT", 409);
  }

  const old = await getUser(env, body.id);
  if (!old) return error("NOT_FOUND", 404);
  if (old.deleted_at !== null) return error("CONFLICT", 409);
  const nextRole = body.role as string;
  const nextStatus = (body.status ?? old.status) as string;
  if (groupsProvided && !(await groupsExist(env, groups!))) return error("REFERENCE_REJECTED", 409);
  if (body.email !== undefined && await liveEmailExists(env, body.email as string, old.id)) {
    return error("EMAIL_EXISTS", 409);
  }

  const stamp = now();
  const user: User = {
    ...old,
    email: (body.email ?? old.email) as string,
    username: (body.username ?? old.username) as string,
    notes: (body.notes ?? old.notes) as string,
    status: nextStatus,
    role: nextRole,
    concurrency: (body.concurrency ?? old.concurrency) as number,
    rpm_limit: (body.rpm_limit ?? old.rpm_limit) as number,
    allowed_group_ids: groupsProvided ? groups! : old.allowed_group_ids,
    restrict_public_groups: (body.restrict_public_groups ?? old.restrict_public_groups) as boolean,
    updated_at: stamp,
  };
  const saved = await managedOperation(env, route, operation, fingerprint, { user }, [
    guardedRoleUserStatement(env, body, old, user, stamp, groupsProvided),
    env.DB.prepare(
      `INSERT INTO admin_role_change_audit(
         operation_id,actor_user_id,target_user_id,old_role,new_role,created_at
       ) SELECT ?,?,?,?,?,?
       WHERE ?<>? AND EXISTS(
         SELECT 1 FROM management_operations WHERE operation_id=?
       )`,
    ).bind(
      operation, body.actor_user_id, user.id, old.role, user.role, stamp,
      old.role, user.role, operation,
    ),
  ]);
  if (saved) return json({ ...saved.response, replayed: saved.replay });

  const raced = await lookupOperation(env, route, operation, fingerprint);
  if (raced?.kind === "replay") return json({ ...raced.response, replayed: true });
  if (raced?.kind === "conflict") return error("IDEMPOTENCY_CONFLICT", 409);
  const [actor, current] = await Promise.all([
    getUser(env, body.actor_user_id as string),
    getUser(env, user.id),
  ]);
  if (!actor || actor.deleted_at !== null || actor.status !== "active" || actor.role !== "admin") {
    return error("ACTOR_FORBIDDEN", 403);
  }
  if (!current) return error("NOT_FOUND", 404);
  if (current.deleted_at !== null) return error("CONFLICT", 409);
  const wouldRemoveCurrentLiveAdmin = current.role === "admin" && current.status === "active" &&
    (nextRole !== "admin" || nextStatus !== "active");
  if (wouldRemoveCurrentLiveAdmin && !(await hasOtherLiveAdmin(env, current.id))) {
    return error("LAST_ADMIN_REQUIRED", 409);
  }
  if (groupsProvided && !(await groupsExist(env, groups!))) return error("REFERENCE_REJECTED", 409);
  if (body.email !== undefined && await liveEmailExists(env, body.email as string, current.id)) {
    return error("EMAIL_EXISTS", 409);
  }
  return error("CONFLICT", 409);
}

function guardedRoleUserStatement(
  env: Env,
  body: Record<string, unknown>,
  old: User,
  user: User,
  stamp: string,
  groupsProvided: boolean,
): D1PreparedStatement {
  const sets: string[] = ["role=?"];
  const values: unknown[] = [user.role];
  const set = (column: string, value: unknown) => {
    sets.push(column + "=?");
    values.push(value);
  };
  if (body.email !== undefined) set("email", user.email);
  if (body.password_hash !== undefined) set("password_hash", body.password_hash);
  if (body.username !== undefined) set("username", user.username);
  if (body.notes !== undefined) set("notes", user.notes);
  if (body.status !== undefined) set("status", user.status);
  if (body.concurrency !== undefined) set("concurrency", user.concurrency);
  if (body.rpm_limit !== undefined) set("rpm_limit", user.rpm_limit);
  if (groupsProvided) set("allowed_group_ids_json", sqlJSON(user.allowed_group_ids));
  if (body.restrict_public_groups !== undefined) {
    set("restrict_public_groups", user.restrict_public_groups ? 1 : 0);
  }
  set("updated_at", stamp);

  let where = `id=? AND deleted_at IS NULL AND role=? AND status=? AND updated_at=?
    AND EXISTS(
      SELECT 1 FROM users AS actor
      WHERE actor.id=? AND actor.deleted_at IS NULL
        AND actor.status='active' AND actor.role='admin'
    )
    AND (
      role<>'admin' OR status<>'active' OR (?='admin' AND ?='active')
      OR EXISTS(
        SELECT 1 FROM users AS other
        WHERE other.id<>users.id AND other.deleted_at IS NULL
          AND other.status='active' AND other.role='admin'
      )
    )`;
  values.push(
    user.id, old.role, old.status, old.updated_at, body.actor_user_id,
    user.role, user.status,
  );
  if (groupsProvided) {
    where += " AND " + liveGroupPredicate;
    values.push(sqlJSON(user.allowed_group_ids));
  }
  return env.DB.prepare("UPDATE users SET " + sets.join(",") + " WHERE " + where).bind(...values);
}

async function deleteUserMutation(
  env: Env,
  route: string,
  body: Record<string, unknown>,
  operation: string,
): Promise<Response> {
  if (!only(body, ["operation_id", "id"]) || !id(body.id)) return error("INVALID_REQUEST");
  const prior = await lookupOperation(env, route, operation, body);
  if (prior) {
    return prior.kind === "replay" ? json(prior.response) : error("IDEMPOTENCY_CONFLICT", 409);
  }

  const old = await getUser(env, body.id);
  if (!old) return error("NOT_FOUND", 404);
  if (old.deleted_at !== null) {
    return replyNoopMutation(env, route, operation, body, { user: old });
  }
  if (old.role === "admin") return error("ROLE_PROTECTED", 409);

  const stamp = now();
  const user: User = { ...old, status: "disabled", updated_at: stamp, deleted_at: stamp };
  const saved = await managedOperation(env, route, operation, body, { user }, [
    env.DB.prepare(
      "UPDATE users SET status='disabled',updated_at=?,deleted_at=? WHERE id=? AND deleted_at IS NULL AND role!='admin'",
    ).bind(stamp, stamp, user.id),
    env.DB.prepare(
      "UPDATE api_keys SET key_hash=lower(hex(randomblob(32))),status='disabled',updated_at=?,deleted_at=? " +
      "WHERE user_id=? AND deleted_at IS NULL AND EXISTS(SELECT 1 FROM management_operations WHERE operation_id=?)",
    ).bind(stamp, stamp, user.id, operation),
  ]);
  if (saved) return json(saved.response);

  const current = await getUser(env, user.id);
  if (current?.role === "admin" && current.deleted_at === null) return error("ROLE_PROTECTED", 409);
  const raced = await lookupOperation(env, route, operation, body);
  if (raced?.kind === "replay") return json(raced.response);
  if (raced?.kind === "conflict") return error("IDEMPOTENCY_CONFLICT", 409);
  return error("CONFLICT", 409);
}

function patchUserStatement(
  env: Env,
  body: Record<string, unknown>,
  user: User,
  stamp: string,
  groupsProvided: boolean,
): D1PreparedStatement {
  const sets: string[] = [];
  const values: unknown[] = [];
  const set = (column: string, value: unknown) => {
    sets.push(column + "=?");
    values.push(value);
  };
  if (body.email !== undefined) set("email", user.email);
  if (body.password_hash !== undefined) set("password_hash", body.password_hash);
  if (body.username !== undefined) set("username", user.username);
  if (body.notes !== undefined) set("notes", user.notes);
  if (body.status !== undefined) set("status", user.status);
  if (body.concurrency !== undefined) set("concurrency", user.concurrency);
  if (body.rpm_limit !== undefined) set("rpm_limit", user.rpm_limit);
  if (groupsProvided) set("allowed_group_ids_json", sqlJSON(user.allowed_group_ids));
  if (body.restrict_public_groups !== undefined) {
    set("restrict_public_groups", user.restrict_public_groups ? 1 : 0);
  }
  set("updated_at", stamp);

  let where = "id=? AND deleted_at IS NULL AND NOT (role='admin' AND COALESCE(?,status)='disabled')";
  values.push(user.id, body.status ?? null);
  if (groupsProvided) {
    where += " AND " + liveGroupPredicate;
    values.push(sqlJSON(user.allowed_group_ids));
  }
  return env.DB.prepare("UPDATE users SET " + sets.join(",") + " WHERE " + where).bind(...values);
}

async function groupMutation(env: Env, route: string, body: Record<string, unknown>, operation: string): Promise<Response> {
  const create = route.endsWith("/create");
  const remove = route.endsWith("/delete");
  const keys = create
    ? ["operation_id", "id", "name", "platform", "status", "is_exclusive", "subscription_type"]
    : remove
      ? ["operation_id", "id"]
      : ["operation_id", "id", "name", "platform", "status", "is_exclusive", "subscription_type"];
  if (!only(body, keys) || !id(body.id)) return error("INVALID_REQUEST");

  // Browser retries generate a fresh candidate ID. The operation identity and
  // semantic fields, not that disposable candidate, define a create replay.
  const fingerprint = create ? { ...body, id: "browser-created" } : body;
  const prior = await lookupOperation(env, route, operation, fingerprint);
  if (prior) {
    if (prior.kind === "conflict") return error("CONFLICT", 409);
    return json(create ? { ...prior.response, replayed: true } : prior.response);
  }

  const old = await getGroup(env, body.id);
  if (create && old) return error("CONFLICT", 409);
  if (!create && !old) return error("NOT_FOUND", 404);
  if (old !== null && old.deleted_at !== null) {
    if (remove) return replyNoopMutation(env, route, operation, fingerprint, { group: old });
    return error("CONFLICT", 409);
  }

  const stamp = now();
  const group: Group = remove
    ? { ...old!, status: "disabled", deleted_at: stamp, updated_at: stamp }
    : {
        id: body.id,
        name: (body.name ?? old?.name) as string,
        platform: (body.platform ?? old?.platform) as string,
        status: (body.status ?? old?.status) as string,
        is_exclusive: (body.is_exclusive ?? old?.is_exclusive) as boolean,
        subscription_type: (body.subscription_type ?? old?.subscription_type) as string,
        created_at: old?.created_at ?? stamp,
        updated_at: stamp,
        deleted_at: old?.deleted_at ?? null,
      };
  if (
    !isBoundedString(group.name, 100) ||
    group.name.trim() !== group.name ||
    group.platform !== "openai" ||
    group.subscription_type !== "standard" ||
    !status(group.status) ||
    typeof group.is_exclusive !== "boolean"
  ) return error("INVALID_REQUEST");

  const statement = create
    ? env.DB.prepare("INSERT INTO groups(id,name,platform,status,is_exclusive,subscription_type,created_at,updated_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?)")
        .bind(group.id, group.name, group.platform, group.status, group.is_exclusive ? 1 : 0, group.subscription_type, group.created_at, group.updated_at, group.deleted_at)
    : env.DB.prepare("UPDATE groups SET name=?,platform=?,status=?,is_exclusive=?,subscription_type=?,updated_at=?,deleted_at=? WHERE id=? AND deleted_at IS NULL")
        .bind(group.name, group.platform, group.status, group.is_exclusive ? 1 : 0, group.subscription_type, group.updated_at, group.deleted_at, group.id);
  if (create) {
    const saved = await managedOperation(env, route, operation, fingerprint, { group }, [statement]);
    return saved ? json({ ...saved.response, replayed: saved.replay }) : error("CONFLICT", 409);
  }
  return replyMutation(env, route, operation, fingerprint, { group }, [statement]);
}

async function activeKeyReferences(env: Env, value: APIKey) {
  const user=await getUser(env,value.user_id);const group=await getGroup(env,value.group_id);
  return !!user&&!!group&&user.status==="active"&&user.deleted_at===null&&group.status==="active"&&group.deleted_at===null&&(!group.is_exclusive&&!user.restrict_public_groups||user.allowed_group_ids.includes(group.id));
}
async function keyMutation(env: Env, route: string, body: Record<string, unknown>, operation: string): Promise<Response> {
  if (route.endsWith("/rebind-group")) return rebindKeyGroup(env, route, body, operation);
  const create=route.endsWith("/create");const rotate=route.endsWith("/rotate");const revoke=route.endsWith("/revoke");const keys=create?["operation_id","id","user_id","group_id","name","status","raw_key","ip_whitelist","ip_blacklist","expires_at"]:rotate?["operation_id","id","raw_key"]:revoke?["operation_id","id","expected_user_id"]:["operation_id","id","name","status","ip_whitelist","ip_blacklist","expires_at"];
  if(!only(body,keys)||!id(body.id)||(body.expected_user_id!==undefined&&!id(body.expected_user_id)))return error("INVALID_REQUEST");const fingerprint=(create||rotate)?{...body,raw_key:"sha256:"+await sha256(String(body.raw_key))}:body;const prior=await lookupOperation(env,route,operation,fingerprint);if(prior)return prior.kind==="replay"?json(prior.response):error("CONFLICT",409);const old=await getKey(env,body.id);if(create&&old)return error("CONFLICT",409);if(!create&&!old)return error("NOT_FOUND",404);if(revoke&&body.expected_user_id!==undefined&&old!.user_id!==body.expected_user_id)return error("NOT_FOUND",404);if(old!==null&&old.deleted_at!==null){if(revoke)return replyNoopMutation(env,route,operation,fingerprint,{api_key:old});return error("CONFLICT",409);}if((create||rotate)&&(!isBoundedString(body.raw_key,128,16)||!/^[A-Za-z0-9_-]+$/.test(body.raw_key)))return error("INVALID_REQUEST");
  if(rotate){const rawKey=body.raw_key as string;const hash=await sha256(rawKey);const duplicate=await env.DB.prepare("SELECT id FROM api_keys WHERE key_hash=? AND id<>?").bind(hash,body.id).first();if(duplicate)return error("CONFLICT",409);const response={api_key:old!};const saved=await managedOperation(env,route,operation,{...body,raw_key:"sha256:"+hash},response,[env.DB.prepare("UPDATE api_keys SET key_hash=?,updated_at=? WHERE id=? AND deleted_at IS NULL").bind(hash,now(),body.id)]);return saved?json(saved.response):error("CONFLICT",409);}
  const stamp=now();
  if(revoke){const api_key:APIKey={...old!,status:"disabled",deleted_at:stamp,updated_at:stamp};const tombstone=await sha256("api-key-tombstone:"+crypto.randomUUID());const expected=body.expected_user_id;const statement=expected===undefined?env.DB.prepare("UPDATE api_keys SET key_hash=?,status='disabled',updated_at=?,deleted_at=? WHERE id=? AND deleted_at IS NULL").bind(tombstone,stamp,stamp,api_key.id):env.DB.prepare("UPDATE api_keys SET key_hash=?,status='disabled',updated_at=?,deleted_at=? WHERE id=? AND user_id=? AND deleted_at IS NULL").bind(tombstone,stamp,stamp,api_key.id,expected);return replyMutation(env,route,operation,body,{api_key},[statement]);}
  const expires=body.expires_at===undefined?old?.expires_at:date(body.expires_at);const api_key:APIKey={id:body.id,user_id:(body.user_id??old?.user_id)as string,group_id:(body.group_id??old?.group_id)as string,name:(body.name??old?.name)as string,status:(body.status??old?.status)as string,ip_whitelist:(body.ip_whitelist??old?.ip_whitelist??[])as string[],ip_blacklist:(body.ip_blacklist??old?.ip_blacklist??[])as string[],expires_at:expires as string|null,last_used_at:old?.last_used_at??null,created_at:old?.created_at??stamp,updated_at:stamp,deleted_at:old?.deleted_at??null};
  const white=stringArray(api_key.ip_whitelist);const black=stringArray(api_key.ip_blacklist);if(!id(api_key.user_id)||!id(api_key.group_id)||!isBoundedString(api_key.name,100)||!status(api_key.status)||!white||!black||expires===undefined||!(await activeKeyReferences(env,api_key)))return error("REFERENCE_REJECTED",409);api_key.ip_whitelist=white;api_key.ip_blacklist=black;
  if(create){const rawKey=body.raw_key as string;const hash=await sha256(rawKey);const duplicate=await env.DB.prepare("SELECT id FROM api_keys WHERE key_hash=?").bind(hash).first();if(duplicate)return error("CONFLICT",409);const response={api_key};const saved=await managedOperation(env,route,operation,{...body,raw_key:"sha256:"+hash},response,[env.DB.prepare("INSERT INTO api_keys(id,user_id,group_id,name,status,key_hash,ip_whitelist_json,ip_blacklist_json,expires_at,last_used_at,created_at,updated_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(api_key.id,api_key.user_id,api_key.group_id,api_key.name,api_key.status,hash,sqlJSON(white),sqlJSON(black),api_key.expires_at,null,api_key.created_at,api_key.updated_at,api_key.deleted_at)]);return saved?json(saved.response):error("CONFLICT",409);}
  const statement=env.DB.prepare("UPDATE api_keys SET name=?,status=?,ip_whitelist_json=?,ip_blacklist_json=?,expires_at=?,updated_at=?,deleted_at=? WHERE id=? AND deleted_at IS NULL").bind(api_key.name,api_key.status,sqlJSON(white),sqlJSON(black),api_key.expires_at,api_key.updated_at,api_key.deleted_at,api_key.id);return replyMutation(env,route,operation,body,{api_key},[statement]);
}

// This is intentionally distinct from the generic API-key patch. Rebinding an
// exclusive group can grant a user access, so it owns its exact allowlist,
// liveness checks, operation replay, and one D1 transaction.
async function rebindKeyGroup(env: Env, route: string, body: Record<string, unknown>, operation: string): Promise<Response> {
  if (!only(body, ["operation_id", "id", "group_id"]) || !id(body.id) || !id(body.group_id)) return error("INVALID_REQUEST");
  const fingerprint = body;
  const prior = await lookupOperation(env, route, operation, fingerprint);
  if (prior) return prior.kind === "replay" ? json(prior.response) : error("CONFLICT", 409);

  const api_key = await getKey(env, body.id);
  if (!api_key || api_key.deleted_at !== null || api_key.status !== "active") return error("NOT_FOUND", 404);
  const user = await getUser(env, api_key.user_id);
  const group = await getGroup(env, body.group_id);
  if (!user || user.deleted_at !== null || user.status !== "active" || !group || group.deleted_at !== null ||
      group.status !== "active" || group.platform !== "openai" || group.subscription_type !== "standard") {
    return error("REFERENCE_REJECTED", 409);
  }
  if (api_key.group_id === group.id) {
    return replyNoopMutation(env, route, operation, fingerprint, {
      api_key, group, auto_granted_group_access: false,
    });
  }

  const grantsAccess = group.is_exclusive && !user.allowed_group_ids.includes(group.id);
  const stamp = now();
  const rebound: APIKey = { ...api_key, group_id: group.id, updated_at: stamp };
  const response: Record<string, unknown> = {
    api_key: rebound,
    group,
    auto_granted_group_access: grantsAccess,
  };
  if (grantsAccess) {
    response.granted_group_id = group.id;
    response.granted_group_name = group.name;
  }
  const keyUpdate = env.DB.prepare(
    "UPDATE api_keys SET group_id=?,updated_at=? WHERE id=? AND deleted_at IS NULL AND status='active' AND EXISTS(SELECT 1 FROM users WHERE id=? AND deleted_at IS NULL AND status='active') AND EXISTS(SELECT 1 FROM groups WHERE id=? AND deleted_at IS NULL AND status='active' AND platform='openai' AND subscription_type='standard' AND is_exclusive=?)",
  ).bind(group.id, stamp, api_key.id, api_key.user_id, group.id, group.is_exclusive ? 1 : 0);
  const statements: D1PreparedStatement[] = [keyUpdate];
  if (grantsAccess) {
    statements.push(env.DB.prepare(
      "UPDATE users SET allowed_group_ids_json=json_insert(allowed_group_ids_json, '$[#]', ?),updated_at=? WHERE id=? AND deleted_at IS NULL AND status='active' AND json_valid(allowed_group_ids_json) AND json_type(allowed_group_ids_json)='array' AND json_array_length(allowed_group_ids_json)<100 AND NOT EXISTS(SELECT 1 FROM json_each(users.allowed_group_ids_json) WHERE value=?) AND EXISTS(SELECT 1 FROM management_operations WHERE operation_id=?)",
    ).bind(group.id, stamp, user.id, group.id, operation));
    // managedOperation records the operation immediately after the primary key
    // update. If this conditional user update touches no row, deliberately
    // collide with that record so D1 rolls the whole sequential batch back.
    // This asserts the non-primary row count without a schema change.
    statements.push(env.DB.prepare(
      "INSERT INTO management_operations(operation_id,route,request_hash,response_json,created_at) SELECT operation_id,route,request_hash,response_json,created_at FROM management_operations WHERE operation_id=? AND changes()=0",
    ).bind(operation));
  }
  return replyMutation(env, route, operation, fingerprint, response, statements);
}

async function accountMutation(env: Env, route: string, body: Record<string, unknown>, operation: string): Promise<Response> {
  if (route.endsWith("/create")) return createAccountMutation(env, route, body, operation);
  if (route.endsWith("/delete")) return deleteAccountMutation(env, route, body, operation);
  return updateAccountMutation(env, route, body, operation);
}

const accountCreateKeys = [
  "operation_id", "id", "name", "platform", "status", "schedulable",
  "priority", "max_concurrency", "credentials", "extra", "group_ids",
];
const accountUpdateKeys = accountCreateKeys.filter((key) => key !== "credentials").concat("credentials");
const accountPatchKeys = accountUpdateKeys.filter((key) => key !== "operation_id" && key !== "id");
const liveCompatibleAccountGroupPredicate =
  "NOT EXISTS (SELECT 1 FROM json_each(?) requested LEFT JOIN groups g ON g.id=requested.value " +
  "WHERE g.id IS NULL OR g.deleted_at IS NOT NULL OR g.status<>'active' OR g.platform<>'openai' OR g.subscription_type<>'standard')";

function validAccountFields(account: Account, groups: string[] | null): boolean {
  return isBoundedString(account.name, 100) &&
    account.name.trim() === account.name &&
    account.platform === "openai" &&
    status(account.status) &&
    typeof account.schedulable === "boolean" &&
    Number.isInteger(account.priority) && account.priority >= -100000 && account.priority <= 100000 &&
    Number.isInteger(account.max_concurrency) && account.max_concurrency >= 1 && account.max_concurrency <= 100000 &&
    isObject(account.extra) && accountExtraOK(account.extra) &&
    groups !== null && groups.length > 0;
}

function validAccountPatch(body: Record<string, unknown>, groups: string[] | null): boolean {
  if (!accountPatchKeys.some((key) => body[key] !== undefined)) return false;
  if (body.name !== undefined && !isBoundedString(body.name, 100)) return false;
  if (body.platform !== undefined && body.platform !== "openai") return false;
  if (body.status !== undefined && !status(body.status)) return false;
  if (body.schedulable !== undefined && typeof body.schedulable !== "boolean") return false;
  if (body.priority !== undefined &&
    (!Number.isInteger(body.priority) || Number(body.priority) < -100000 || Number(body.priority) > 100000)) return false;
  if (body.max_concurrency !== undefined &&
    (!Number.isInteger(body.max_concurrency) || Number(body.max_concurrency) < 1 || Number(body.max_concurrency) > 100000)) return false;
  if (body.extra !== undefined && (!isObject(body.extra) || !accountExtraOK(body.extra))) return false;
  return body.group_ids === undefined || (groups !== null && groups.length > 0);
}

async function compatibleAccountGroupsExist(env: Env, groups: string[]): Promise<boolean> {
  if (groups.length === 0) return false;
  const marks = groups.map(() => "?").join(",");
  const row = await env.DB.prepare(
    "SELECT count(*) count FROM groups WHERE id IN (" + marks + ") AND deleted_at IS NULL " +
    "AND status='active' AND platform='openai' AND subscription_type='standard'",
  ).bind(...groups).first<{ count: number }>();
  return row?.count === groups.length;
}

function accountCredentialCandidate(
  value: unknown,
  runtime: CredentialRuntime,
): Record<string, string> | null {
  if (!isObject(value) || !only(value, ["api_key", "base_url"])) return null;
  return validateAPIKeyCredentials(value, runtime);
}

async function accountMutationReply(
  env: Env,
  route: string,
  operation: string,
  fingerprint: unknown,
  response: Record<string, unknown>,
  statements: D1PreparedStatement[],
): Promise<Response | null> {
  const saved = await managedOperation(env, route, operation, fingerprint, response, statements);
  if (!saved) return null;
  const safe = accountOperationReadProjection(saved.response);
  return safe ? json({ ...safe, replayed: saved.replay }) : error("CONTROL_PLANE_UNAVAILABLE", 503);
}

async function createAccountMutation(
  env: Env,
  route: string,
  body: Record<string, unknown>,
  operation: string,
): Promise<Response> {
  const groups = sortedDecimalIDs(stringArray(body.group_ids, 100, true));
  const runtime = env as unknown as CredentialRuntime;
  const credentials = accountCredentialCandidate(body.credentials, runtime);
  const stamp = now();
  const account: Account = {
    id: body.id as string,
    name: body.name as string,
    platform: body.platform as string,
    type: "apikey",
    status: body.status as string,
    schedulable: body.schedulable as boolean,
    priority: body.priority as number,
    max_concurrency: body.max_concurrency as number,
    extra: body.extra as Record<string, unknown>,
    group_ids: groups ?? [],
    created_at: stamp,
    updated_at: stamp,
    deleted_at: null,
  };
  if (!only(body, accountCreateKeys) || !id(body.id) || !credentials || !validAccountFields(account, groups)) {
    return error("INVALID_REQUEST");
  }

  // The candidate ID is transport allocation, not create intent. Credentials
  // participate only through a digest and the canonical plaintext is never
  // written to management_operations.
  const fingerprint = {
    operation_id: operation,
    name: account.name,
    platform: account.platform,
    status: account.status,
    schedulable: account.schedulable,
    priority: account.priority,
    max_concurrency: account.max_concurrency,
    credential_digest: await sha256(canonical(credentials)),
    extra: account.extra,
    group_ids: account.group_ids,
  };
  const prior = await lookupOperation(env, route, operation, fingerprint);
  if (prior) {
    if (prior.kind !== "replay") return error("IDEMPOTENCY_CONFLICT", 409);
    const safe = accountOperationReadProjection(prior.response);
    return safe ? json({ ...safe, replayed: true }) : error("CONTROL_PLANE_UNAVAILABLE", 503);
  }
  if (await getAccount(env, account.id)) return error("CONFLICT", 409);
  if (!(await compatibleAccountGroupsExist(env, account.group_ids))) return error("REFERENCE_REJECTED", 409);

  const encrypted = await encryptAPIKeyCredentials(credentials, runtime);
  if (!encrypted) return error("INVALID_REQUEST");
  const statement = env.DB.prepare(
    "INSERT INTO accounts(id,name,platform,type,status,schedulable,priority,max_concurrency,credential_envelope,extra_json,created_at,updated_at,deleted_at) " +
    "SELECT ?,?,?,?,?,?,?,?,?,?,?,?,? WHERE " + liveCompatibleAccountGroupPredicate,
  ).bind(
    account.id, account.name, account.platform, account.type, account.status,
    account.schedulable ? 1 : 0, account.priority, account.max_concurrency,
    encrypted, sqlJSON(account.extra), account.created_at, account.updated_at,
    account.deleted_at, sqlJSON(account.group_ids),
  );
  const statements: D1PreparedStatement[] = [statement];
  for (const groupID of account.group_ids) {
    statements.push(env.DB.prepare(
      "INSERT INTO account_groups(account_id,group_id) SELECT ?,? WHERE EXISTS(SELECT 1 FROM management_operations WHERE operation_id=?)",
    ).bind(account.id, groupID, operation));
  }
  const response = await accountMutationReply(
    env, route, operation, fingerprint, { account: accountReadProjection(account) }, statements,
  );
  if (response) return response;

  if (!(await compatibleAccountGroupsExist(env, account.group_ids))) return error("REFERENCE_REJECTED", 409);
  const raced = await lookupOperation(env, route, operation, fingerprint);
  if (raced?.kind === "replay") {
    const safe = accountOperationReadProjection(raced.response);
    return safe ? json({ ...safe, replayed: true }) : error("CONTROL_PLANE_UNAVAILABLE", 503);
  }
  if (raced?.kind === "conflict") return error("IDEMPOTENCY_CONFLICT", 409);
  return error("CONFLICT", 409);
}

async function updateAccountMutation(
  env: Env,
  route: string,
  body: Record<string, unknown>,
  operation: string,
): Promise<Response> {
  const groupsProvided = body.group_ids !== undefined;
  const groups = groupsProvided ? sortedDecimalIDs(stringArray(body.group_ids, 100, true)) : null;
  const runtime = env as unknown as CredentialRuntime;
  const credentials = body.credentials === undefined
    ? undefined
    : accountCredentialCandidate(body.credentials, runtime);
  if (!only(body, accountUpdateKeys) || !id(body.id) || !validAccountPatch(body, groups) || credentials === null) {
    return error("INVALID_REQUEST");
  }
  const normalizedBody = groupsProvided ? { ...body, group_ids: groups } : body;
  const fingerprint = credentials === undefined
    ? normalizedBody
    : { ...normalizedBody, credentials: "sha256:" + await sha256(canonical(credentials)) };
  const prior = await lookupOperation(env, route, operation, fingerprint);
  if (prior) {
    if (prior.kind !== "replay") return error("IDEMPOTENCY_CONFLICT", 409);
    const safe = accountOperationReadProjection(prior.response);
    return safe ? json({ ...safe, replayed: true }) : error("CONTROL_PLANE_UNAVAILABLE", 503);
  }

  const old = await getAccount(env, body.id);
  if (!old) return error("NOT_FOUND", 404);
  if (old.deleted_at !== null) return error("CONFLICT", 409);
  if (groupsProvided && !(await compatibleAccountGroupsExist(env, groups!))) {
    return error("REFERENCE_REJECTED", 409);
  }
  const stamp = now();
  const account: Account = {
    ...old,
    name: (body.name ?? old.name) as string,
    platform: (body.platform ?? old.platform) as string,
    status: (body.status ?? old.status) as string,
    schedulable: (body.schedulable ?? old.schedulable) as boolean,
    priority: (body.priority ?? old.priority) as number,
    max_concurrency: (body.max_concurrency ?? old.max_concurrency) as number,
    extra: (body.extra ?? old.extra) as Record<string, unknown>,
    group_ids: groupsProvided ? groups! : old.group_ids,
    updated_at: stamp,
  };
  if (!validAccountFields(account, account.group_ids)) return error("INVALID_REQUEST");
  const encrypted = credentials === undefined
    ? undefined
    : await encryptAPIKeyCredentials(credentials, runtime);
  if (credentials !== undefined && !encrypted) return error("INVALID_REQUEST");

  let updateSQL =
    "UPDATE accounts SET name=?,platform=?,status=?,schedulable=?,priority=?,max_concurrency=?," +
    "credential_envelope=COALESCE(?,credential_envelope),extra_json=?,updated_at=?,deleted_at=? " +
    "WHERE id=? AND type='apikey' AND deleted_at IS NULL";
  const bindings: unknown[] = [
    account.name, account.platform, account.status, account.schedulable ? 1 : 0,
    account.priority, account.max_concurrency, encrypted ?? null,
    sqlJSON(account.extra), account.updated_at, account.deleted_at, account.id,
  ];
  if (groupsProvided) {
    updateSQL += " AND " + liveCompatibleAccountGroupPredicate;
    bindings.push(sqlJSON(account.group_ids));
  }
  const statements: D1PreparedStatement[] = [env.DB.prepare(updateSQL).bind(...bindings)];
  if (groupsProvided) {
    statements.push(env.DB.prepare(
      "DELETE FROM account_groups WHERE account_id=? AND EXISTS(SELECT 1 FROM management_operations WHERE operation_id=?)",
    ).bind(account.id, operation));
    for (const groupID of account.group_ids) {
      statements.push(env.DB.prepare(
        "INSERT INTO account_groups(account_id,group_id) SELECT ?,? WHERE EXISTS(SELECT 1 FROM management_operations WHERE operation_id=?)",
      ).bind(account.id, groupID, operation));
    }
  }
  const response = await accountMutationReply(
    env, route, operation, fingerprint, { account: accountReadProjection(account) }, statements,
  );
  if (response) return response;
  if (groupsProvided && !(await compatibleAccountGroupsExist(env, account.group_ids))) {
    return error("REFERENCE_REJECTED", 409);
  }
  const raced = await lookupOperation(env, route, operation, fingerprint);
  if (raced?.kind === "replay") {
    const safe = accountOperationReadProjection(raced.response);
    return safe ? json({ ...safe, replayed: true }) : error("CONTROL_PLANE_UNAVAILABLE", 503);
  }
  if (raced?.kind === "conflict") return error("IDEMPOTENCY_CONFLICT", 409);
  return error("CONFLICT", 409);
}

async function deleteAccountMutation(
  env: Env,
  route: string,
  body: Record<string, unknown>,
  operation: string,
): Promise<Response> {
  if (!only(body, ["operation_id", "id"]) || !id(body.id)) return error("INVALID_REQUEST");
  const fingerprint = body;
  const prior = await lookupOperation(env, route, operation, fingerprint);
  if (prior) {
    if (prior.kind !== "replay") return error("IDEMPOTENCY_CONFLICT", 409);
    const safe = accountOperationReadProjection(prior.response);
    return safe ? json({ ...safe, replayed: true }) : error("CONTROL_PLANE_UNAVAILABLE", 503);
  }
  const old = await getAccount(env, body.id);
  if (!old) return error("NOT_FOUND", 404);
  if (old.deleted_at !== null) {
    const stored = await recordNoopOperation(
      env, route, operation, fingerprint, { account: accountReadProjection(old) },
    );
    const safe = stored && accountOperationReadProjection(stored);
    return safe ? json({ ...safe, replayed: false }) : error("IDEMPOTENCY_CONFLICT", 409);
  }
  const stamp = now();
  const account: Account = {
    ...old,
    status: "disabled",
    schedulable: false,
    updated_at: stamp,
    deleted_at: stamp,
  };
  const response = await accountMutationReply(
    env,
    route,
    operation,
    fingerprint,
    { account: accountReadProjection(account) },
    [env.DB.prepare(
      "UPDATE accounts SET status='disabled',schedulable=0,updated_at=?,deleted_at=? " +
      "WHERE id=? AND type='apikey' AND deleted_at IS NULL",
    ).bind(stamp, stamp, account.id)],
  );
  if (response) return response;
  const raced = await lookupOperation(env, route, operation, fingerprint);
  if (raced?.kind === "replay") {
    const safe = accountOperationReadProjection(raced.response);
    return safe ? json({ ...safe, replayed: true }) : error("CONTROL_PLANE_UNAVAILABLE", 503);
  }
  if (raced?.kind === "conflict") return error("IDEMPOTENCY_CONFLICT", 409);
  return error("CONFLICT", 409);
}
