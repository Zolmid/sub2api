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

const ID_MAX = 20;
const PAGE_MAX = 100;
const OPERATION_MAX = 128;
const statuses = new Set(["active", "disabled"]);

type User = {
  id: string; email: string; username: string; notes: string; status: string;
  role: string; concurrency: number; rpm_limit: number; balance_microusd: string;
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
const stringArray = (value: unknown, maximum = 100, decimal = false): string[] | null => {
  if (!Array.isArray(value) || value.length > maximum) return null;
  if (!value.every((item) => decimal ? id(item) : isBoundedString(item, 128))) return null;
  const values = value as string[];
  return new Set(values).size === values.length ? values : null;
};
const date = (value: unknown): string | null | undefined => {
  if (value === null) return null;
  if (!isBoundedString(value, 64) || !Number.isFinite(Date.parse(value))) return undefined;
  return new Date(value).toISOString();
};
const email = (value: unknown) =>
  isBoundedString(value, 255, 3) && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
const cursorOK = (value: unknown): value is string =>
  isCanonicalUnsignedDecimal(value) && value.length <= ID_MAX;
const sqlJSON = (value: unknown) => canonical(value);

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
    rpm_limit: Number(row.rpm_limit), balance_microusd: String(row.balance_microusd),
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

async function first(env: Env, query: string, value: string): Promise<Record<string, unknown> | null> {
  return env.DB.prepare(query).bind(value).first<Record<string, unknown>>();
}
async function getUser(env: Env, value: string) { const row = await first(env, "SELECT id,email,username,notes,status,role,concurrency,rpm_limit,balance_microusd,allowed_group_ids_json,restrict_public_groups,created_at,updated_at,deleted_at FROM users WHERE id=?", value); return row ? userRow(row) : null; }
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
  const row = await env.DB.prepare("SELECT count(*) count FROM groups WHERE id IN (" + marks + ")" + (active ? " AND status='active' AND deleted_at IS NULL" : "")).bind(...values).first<{ count: number }>();
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
    const results = await env.DB.batch([...statements, env.DB.prepare("INSERT INTO management_operations(operation_id,route,request_hash,response_json,created_at) VALUES(?,?,?,?,?)").bind(operation, route, requestHash, canonical(response), now())]);
    // Every mutation starts with an INSERT or targeted UPDATE. A zero-row
    // update is an identity/race failure, never a successful management call.
    if ((results[0]?.meta.changes ?? 0) !== 1 || (results.at(-1)?.meta.changes ?? 0) !== 1) {
      await env.DB.prepare("DELETE FROM management_operations WHERE operation_id=? AND route=? AND request_hash=?").bind(operation, route, requestHash).run();
      return null;
    }
    return { response, replay: false };
  } catch {
    const raced = await env.DB.prepare("SELECT route,request_hash,response_json FROM management_operations WHERE operation_id=?").bind(operation).first<{ route: string; request_hash: string; response_json: string }>();
    const stored = raced?.route === route && raced.request_hash === requestHash
      ? parsedObject(raced.response_json)
      : null;
    return stored ? { response: stored, replay: true } : null;
  }
}
async function replayOperation(
  env: Env, route: string, operation: string, fingerprint: unknown,
): Promise<Record<string, unknown> | null> {
  const requestHash = await sha256(canonical(fingerprint));
  const prior = await env.DB.prepare(
    "SELECT route,request_hash,response_json FROM management_operations WHERE operation_id=?",
  ).bind(operation).first<{ route: string; request_hash: string; response_json: string }>();
  if (!prior || prior.route !== route || prior.request_hash !== requestHash) return null;
  return parsedObject(prior.response_json);
}
async function replyMutation(env: Env, route: string, operation: string, fingerprint: unknown, response: Record<string, unknown>, statements: D1PreparedStatement[]) {
  const saved = await managedOperation(env, route, operation, fingerprint, response, statements);
  return saved ? json(saved.response) : error("CONFLICT", 409);
}

export async function managementControlPlane(request: Request, env: Env, route: string): Promise<Response> {
  if (!isBoundedString(request.headers.get("X-Sub2API-Container-Id"), 256)) return error("NOT_FOUND", 404);
  const body = await readJson<unknown>(request);
  if (!isObject(body)) return error("INVALID_REQUEST");
  if (route.endsWith("/get")) return get(env, route, body);
  if (route.endsWith("/list")) return list(env, route, body);
  return mutate(env, route, body);
}

async function get(env: Env, route: string, body: Record<string, unknown>): Promise<Response> {
  if (!only(body, ["id"]) || !id(body.id)) return error("INVALID_REQUEST");
  if (route.includes("/users/")) { const user = await getUser(env, body.id); return user ? json({ user }) : error("NOT_FOUND", 404); }
  if (route.includes("/groups/")) { const group = await getGroup(env, body.id); return group ? json({ group }) : error("NOT_FOUND", 404); }
  if (route.includes("/api-keys/")) { const api_key = await getKey(env, body.id); return api_key ? json({ api_key }) : error("NOT_FOUND", 404); }
  const account = await getAccount(env, body.id); return account ? json({ account }) : error("NOT_FOUND", 404);
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
    const rows = await env.DB.prepare(pageQuery("users", "id,email,username,notes,status,role,concurrency,rpm_limit,balance_microusd,allowed_group_ids_json,restrict_public_groups,created_at,updated_at,deleted_at")).bind(cursor,cursor,cursor,size+1).all<Record<string, unknown>>();
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
  const accounts = (await Promise.all(rows.results.slice(0,size).map((row) => getAccount(env,row.id)))).filter((item): item is Account => item !== null);
  return json({ accounts, next_cursor: rows.results.length > size ? accounts.at(-1)?.id ?? null : null });
}

async function mutate(env: Env, route: string, body: Record<string, unknown>): Promise<Response> {
  if (!operationID(body.operation_id)) return error("INVALID_REQUEST");
  if (route.includes("/users/")) return userMutation(env,route,body,body.operation_id);
  if (route.includes("/groups/")) return groupMutation(env,route,body,body.operation_id);
  if (route.includes("/api-keys/")) return keyMutation(env,route,body,body.operation_id);
  return accountMutation(env,route,body,body.operation_id);
}

async function userMutation(env: Env, route: string, body: Record<string, unknown>, operation: string): Promise<Response> {
  const create = route.endsWith("/create"); const remove = route.endsWith("/delete");
  const keys = create ? ["operation_id","id","email","password_hash","username","notes","status","role","concurrency","rpm_limit","balance_microusd","allowed_group_ids","restrict_public_groups"] : remove ? ["operation_id","id"] : ["operation_id","id","email","password_hash","username","notes","status","role","concurrency","rpm_limit","balance_microusd","allowed_group_ids","restrict_public_groups"];
  if (!only(body,keys) || !id(body.id)) return error("INVALID_REQUEST");
  const old = await getUser(env,body.id);
  if (create && old) {
    const raw = body.password_hash;
    const replay = await replayOperation(env,route,operation,{...body,password_hash:raw === undefined ? undefined : "sha256:" + await sha256(String(raw))});
    return replay ? json(replay) : error("CONFLICT",409);
  }
  if (!create && !old) return error("NOT_FOUND",404);
  const stamp = now();
  const user: User = remove ? { ...old!, status:"disabled", deleted_at:stamp, updated_at:stamp } : {
    id:body.id, email:(body.email ?? old?.email) as string, username:(body.username ?? old?.username) as string, notes:(body.notes ?? old?.notes) as string,
    status:(body.status ?? old?.status) as string, role:(body.role ?? old?.role) as string, concurrency:(body.concurrency ?? old?.concurrency) as number,
    rpm_limit:(body.rpm_limit ?? old?.rpm_limit) as number, balance_microusd:(body.balance_microusd ?? old?.balance_microusd) as string,
    allowed_group_ids:(body.allowed_group_ids ?? old?.allowed_group_ids) as string[], restrict_public_groups:(body.restrict_public_groups ?? old?.restrict_public_groups) as boolean,
    created_at:old?.created_at ?? stamp, updated_at:stamp, deleted_at:old?.deleted_at ?? null,
  };
  const groups = stringArray(user.allowed_group_ids,100,true);
  const password = body.password_hash === undefined ? undefined : body.password_hash;
  if (!email(user.email) || !isBoundedString(user.username,100,0) || !isBoundedString(user.notes,4096,0) || !status(user.status) || !isBoundedString(user.role,20) || !Number.isInteger(user.concurrency) || user.concurrency < 1 || user.concurrency > 100000 || !Number.isInteger(user.rpm_limit) || user.rpm_limit < 0 || user.rpm_limit > 1000000 || !isCanonicalUnsignedDecimal(user.balance_microusd) || user.balance_microusd.length > 40 || !groups || typeof user.restrict_public_groups !== "boolean" || (password !== undefined && !isBoundedString(password,255,20)) || !(await groupsExist(env,groups))) return error("INVALID_REQUEST");
  user.allowed_group_ids=groups;
  const response={user};
  const fingerprint = password === undefined
    ? body
    : { ...body, password_hash: "sha256:" + await sha256(password) };
  const statement=create ? env.DB.prepare("INSERT INTO users(id,status,role,concurrency,balance_microusd,allowed_group_ids_json,restrict_public_groups,created_at,email,password_hash,username,notes,rpm_limit,updated_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(user.id,user.status,user.role,user.concurrency,user.balance_microusd,sqlJSON(groups),user.restrict_public_groups?1:0,user.created_at,user.email,password ?? "",user.username,user.notes,user.rpm_limit,user.updated_at,user.deleted_at) : env.DB.prepare("UPDATE users SET email=?,password_hash=COALESCE(?,password_hash),username=?,notes=?,status=?,role=?,concurrency=?,rpm_limit=?,balance_microusd=?,allowed_group_ids_json=?,restrict_public_groups=?,updated_at=?,deleted_at=? WHERE id=?").bind(user.email,password ?? null,user.username,user.notes,user.status,user.role,user.concurrency,user.rpm_limit,user.balance_microusd,sqlJSON(groups),user.restrict_public_groups?1:0,user.updated_at,user.deleted_at,user.id);
  return replyMutation(env,route,operation,fingerprint,response,[statement]);
}

async function groupMutation(env: Env, route: string, body: Record<string, unknown>, operation: string): Promise<Response> {
  const create=route.endsWith("/create"); const remove=route.endsWith("/delete"); const keys=create?["operation_id","id","name","platform","status","is_exclusive","subscription_type"]:remove?["operation_id","id"]:["operation_id","id","name","platform","status","is_exclusive","subscription_type"];
  if(!only(body,keys)||!id(body.id)) return error("INVALID_REQUEST"); const old=await getGroup(env,body.id); if(create&&old){const replay=await replayOperation(env,route,operation,body);return replay?json(replay):error("CONFLICT",409);}if(!create&&!old)return error("NOT_FOUND",404); const stamp=now();
  const group:Group=remove?{...old!,status:"disabled",deleted_at:stamp,updated_at:stamp}:{id:body.id,name:(body.name??old?.name)as string,platform:(body.platform??old?.platform)as string,status:(body.status??old?.status)as string,is_exclusive:(body.is_exclusive??old?.is_exclusive)as boolean,subscription_type:(body.subscription_type??old?.subscription_type)as string,created_at:old?.created_at??stamp,updated_at:stamp,deleted_at:old?.deleted_at??null};
  if(!isBoundedString(group.name,100)||!isBoundedString(group.platform,50)||!isBoundedString(group.subscription_type,20)||!status(group.status)||typeof group.is_exclusive!=="boolean")return error("INVALID_REQUEST");
  const statement=create?env.DB.prepare("INSERT INTO groups(id,name,platform,status,is_exclusive,subscription_type,created_at,updated_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?)").bind(group.id,group.name,group.platform,group.status,group.is_exclusive?1:0,group.subscription_type,group.created_at,group.updated_at,group.deleted_at):env.DB.prepare("UPDATE groups SET name=?,platform=?,status=?,is_exclusive=?,subscription_type=?,updated_at=?,deleted_at=? WHERE id=?").bind(group.name,group.platform,group.status,group.is_exclusive?1:0,group.subscription_type,group.updated_at,group.deleted_at,group.id);
  return replyMutation(env,route,operation,body,{group},[statement]);
}

async function activeKeyReferences(env: Env, value: APIKey) {
  const user=await getUser(env,value.user_id);const group=await getGroup(env,value.group_id);
  return !!user&&!!group&&user.status==="active"&&user.deleted_at===null&&group.status==="active"&&group.deleted_at===null&&(!group.is_exclusive&&!user.restrict_public_groups||user.allowed_group_ids.includes(group.id));
}
async function keyMutation(env: Env, route: string, body: Record<string, unknown>, operation: string): Promise<Response> {
  const create=route.endsWith("/create");const rotate=route.endsWith("/rotate");const revoke=route.endsWith("/revoke");const keys=create?["operation_id","id","user_id","group_id","name","status","raw_key","ip_whitelist","ip_blacklist","expires_at"]:rotate?["operation_id","id","raw_key"]:revoke?["operation_id","id"]:["operation_id","id","name","status","ip_whitelist","ip_blacklist","expires_at"];
  if(!only(body,keys)||!id(body.id))return error("INVALID_REQUEST");const old=await getKey(env,body.id);if(create&&old){const raw=body.raw_key;const replay=await replayOperation(env,route,operation,{...body,raw_key:"sha256:"+await sha256(String(raw))});return replay?json(replay):error("CONFLICT",409);}if(!create&&!old)return error("NOT_FOUND",404);if((create||rotate)&&(!isBoundedString(body.raw_key,128,16)||!/^[A-Za-z0-9_-]+$/.test(body.raw_key)))return error("INVALID_REQUEST");
  if(rotate){const rawKey=body.raw_key as string;const hash=await sha256(rawKey);const duplicate=await env.DB.prepare("SELECT id FROM api_keys WHERE key_hash=? AND id<>?").bind(hash,body.id).first();if(duplicate)return error("CONFLICT",409);const response={api_key:old!};const saved=await managedOperation(env,route,operation,{...body,raw_key:"sha256:"+hash},response,[env.DB.prepare("UPDATE api_keys SET key_hash=?,updated_at=? WHERE id=?").bind(hash,now(),body.id)]);return saved?json({...saved.response,...(saved.replay?{}:{raw_key:rawKey})}):error("CONFLICT",409);}
  const stamp=now();
  if(revoke){const api_key:APIKey={...old!,status:"disabled",deleted_at:stamp,updated_at:stamp};return replyMutation(env,route,operation,body,{api_key},[env.DB.prepare("UPDATE api_keys SET status='disabled',updated_at=?,deleted_at=? WHERE id=? AND deleted_at IS NULL").bind(stamp,stamp,api_key.id)]);}
  const expires=body.expires_at===undefined?old?.expires_at:date(body.expires_at);const api_key:APIKey={id:body.id,user_id:(body.user_id??old?.user_id)as string,group_id:(body.group_id??old?.group_id)as string,name:(body.name??old?.name)as string,status:(body.status??old?.status)as string,ip_whitelist:(body.ip_whitelist??old?.ip_whitelist??[])as string[],ip_blacklist:(body.ip_blacklist??old?.ip_blacklist??[])as string[],expires_at:expires as string|null,last_used_at:old?.last_used_at??null,created_at:old?.created_at??stamp,updated_at:stamp,deleted_at:old?.deleted_at??null};
  const white=stringArray(api_key.ip_whitelist);const black=stringArray(api_key.ip_blacklist);if(!id(api_key.user_id)||!id(api_key.group_id)||!isBoundedString(api_key.name,100)||!status(api_key.status)||!white||!black||expires===undefined||!(await activeKeyReferences(env,api_key)))return error("REFERENCE_REJECTED",409);api_key.ip_whitelist=white;api_key.ip_blacklist=black;
  if(create){const rawKey=body.raw_key as string;const hash=await sha256(rawKey);const duplicate=await env.DB.prepare("SELECT id FROM api_keys WHERE key_hash=?").bind(hash).first();if(duplicate)return error("CONFLICT",409);const response={api_key};const saved=await managedOperation(env,route,operation,{...body,raw_key:"sha256:"+hash},response,[env.DB.prepare("INSERT INTO api_keys(id,user_id,group_id,name,status,key_hash,ip_whitelist_json,ip_blacklist_json,expires_at,last_used_at,created_at,updated_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(api_key.id,api_key.user_id,api_key.group_id,api_key.name,api_key.status,hash,sqlJSON(white),sqlJSON(black),api_key.expires_at,null,api_key.created_at,api_key.updated_at,api_key.deleted_at)]);return saved?json({...saved.response,...(saved.replay?{}:{raw_key:rawKey})}):error("CONFLICT",409);}
  const statement=env.DB.prepare("UPDATE api_keys SET name=?,status=?,ip_whitelist_json=?,ip_blacklist_json=?,expires_at=?,updated_at=?,deleted_at=? WHERE id=?").bind(api_key.name,api_key.status,sqlJSON(white),sqlJSON(black),api_key.expires_at,api_key.updated_at,api_key.deleted_at,api_key.id);return replyMutation(env,route,operation,body,{api_key},[statement]);
}

async function accountMutation(env: Env, route: string, body: Record<string, unknown>, operation: string): Promise<Response> {
  const create=route.endsWith("/create");const remove=route.endsWith("/delete");const keys=create?["operation_id","id","name","platform","status","schedulable","priority","max_concurrency","credential_envelope","extra","group_ids"]:remove?["operation_id","id"]:["operation_id","id","name","platform","status","schedulable","priority","max_concurrency","credential_envelope","extra","group_ids"];
  if(!only(body,keys)||!id(body.id))return error("INVALID_REQUEST");const old=await getAccount(env,body.id);if(create&&old){const credential=body.credential_envelope;const replay=await replayOperation(env,route,operation,{...body,credential_envelope:"sha256:"+await sha256(String(credential))});return replay?json(replay):error("CONFLICT",409);}if(!create&&!old)return error("NOT_FOUND",404);const stamp=now();const groups=stringArray(body.group_ids??old?.group_ids,100,true);const credential=body.credential_envelope;
  if(remove){const account:Account={...old!,status:"disabled",schedulable:false,deleted_at:stamp,updated_at:stamp};return replyMutation(env,route,operation,body,{account},[env.DB.prepare("UPDATE accounts SET status='disabled',schedulable=0,updated_at=?,deleted_at=? WHERE id=? AND type='apikey' AND deleted_at IS NULL").bind(stamp,stamp,account.id)]);}
  const account:Account={id:body.id,name:(body.name??old?.name)as string,platform:(body.platform??old?.platform)as string,type:"apikey",status:(body.status??old?.status)as string,schedulable:(body.schedulable??old?.schedulable)as boolean,priority:(body.priority??old?.priority)as number,max_concurrency:(body.max_concurrency??old?.max_concurrency)as number,extra:(body.extra??old?.extra)as Record<string,unknown>,group_ids:groups??[],created_at:old?.created_at??stamp,updated_at:stamp,deleted_at:old?.deleted_at??null};
  if(!isBoundedString(account.name,100)||!isBoundedString(account.platform,50)||!status(account.status)||typeof account.schedulable!=="boolean"||!Number.isInteger(account.priority)||account.priority<-100000||account.priority>100000||!Number.isInteger(account.max_concurrency)||account.max_concurrency<1||account.max_concurrency>100000||!isObject(account.extra)||!groups||groups.length===0||!(await groupsExist(env,groups,true))||(create&&!isBoundedString(credential,16384))||(credential!==undefined&&!isBoundedString(credential,16384)))return error("INVALID_REQUEST");account.group_ids=groups;
  const statements:D1PreparedStatement[]=create?[env.DB.prepare("INSERT INTO accounts(id,name,platform,type,status,schedulable,priority,max_concurrency,credential_envelope,extra_json,created_at,updated_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(account.id,account.name,account.platform,"apikey",account.status,account.schedulable?1:0,account.priority,account.max_concurrency,credential,sqlJSON(account.extra),account.created_at,account.updated_at,account.deleted_at)]:[env.DB.prepare("UPDATE accounts SET name=?,platform=?,status=?,schedulable=?,priority=?,max_concurrency=?,credential_envelope=COALESCE(?,credential_envelope),extra_json=?,updated_at=?,deleted_at=? WHERE id=? AND type='apikey'").bind(account.name,account.platform,account.status,account.schedulable?1:0,account.priority,account.max_concurrency,credential??null,sqlJSON(account.extra),account.updated_at,account.deleted_at,account.id),env.DB.prepare("DELETE FROM account_groups WHERE account_id=?").bind(account.id)];
  for(const groupID of groups)statements.push(env.DB.prepare("INSERT INTO account_groups(account_id,group_id) VALUES(?,?)").bind(account.id,groupID));
  const fingerprint = credential === undefined
    ? body
    : { ...body, credential_envelope: "sha256:" + await sha256(credential) };
  return replyMutation(env,route,operation,fingerprint,{account},statements);
}
