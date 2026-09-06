import {
  error,
  isBoundedString,
  isCanonicalPositiveDecimal,
  json,
  readJson,
  sha256,
} from "./contracts";

const ID_MAX = 20;
const PAGE_MAX = 100;

type AuthUser = {
  id: string;
  email: string;
  username: string;
  password_hash: string;
  status: string;
  role: string;
  concurrency: number;
  rpm_limit: number;
  balance_microusd: string;
  allowed_group_ids: string[];
  restrict_public_groups: boolean;
  created_at: string;
  updated_at: string;
};

type APIKey = {
  id: string;
  user_id: string;
  group_id: string;
  name: string;
  status: string;
  ip_whitelist: string[];
  ip_blacklist: string[];
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
};

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const only = (body: Record<string, unknown>, keys: string[]) =>
  Object.keys(body).every((key) => keys.includes(key));
const id = (value: unknown): value is string =>
  isCanonicalPositiveDecimal(value) && value.length <= ID_MAX;

function parsedArray(value: unknown): string[] | null {
  if (typeof value !== "string") return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.length > 100) return null;
    if (!parsed.every((item) => typeof item === "string" && item.length <= 128)) return null;
    return new Set(parsed).size === parsed.length ? parsed : null;
  } catch {
    return null;
  }
}

function authUserRow(row: Record<string, unknown>): AuthUser | null {
  const groups = parsedArray(row.allowed_group_ids_json);
  if (groups === null || !groups.every(id)) return null;
  return {
    id: String(row.id),
    email: String(row.email),
    username: String(row.username),
    password_hash: String(row.password_hash),
    status: String(row.status),
    role: String(row.role),
    concurrency: Number(row.concurrency),
    rpm_limit: Number(row.rpm_limit),
    balance_microusd: String(row.balance_microusd),
    allowed_group_ids: groups,
    restrict_public_groups: Number(row.restrict_public_groups) === 1,
    created_at: String(row.created_at),
    updated_at: String(row.updated_at),
  };
}

function apiKeyRow(row: Record<string, unknown>): APIKey | null {
  const whitelist = parsedArray(row.ip_whitelist_json);
  const blacklist = parsedArray(row.ip_blacklist_json);
  if (whitelist === null || blacklist === null) return null;
  return {
    id: String(row.id),
    user_id: String(row.user_id),
    group_id: String(row.group_id),
    name: String(row.name),
    status: String(row.status),
    ip_whitelist: whitelist,
    ip_blacklist: blacklist,
    expires_at: row.expires_at === null ? null : String(row.expires_at),
    last_used_at: row.last_used_at === null ? null : String(row.last_used_at),
    created_at: String(row.created_at),
    updated_at: String(row.updated_at),
  };
}

async function authUser(request: Request, env: Env): Promise<Response> {
  const body = await readJson<unknown>(request);
  if (!isObject(body) || !only(body, ["id", "email"])) return error("INVALID_REQUEST");
  const hasID = body.id !== undefined;
  const hasEmail = body.email !== undefined;
  if (hasID === hasEmail) return error("INVALID_REQUEST");

  let rows: D1Result<Record<string, unknown>>;
  const columns = "id,email,username,password_hash,status,role,concurrency,rpm_limit,balance_microusd,allowed_group_ids_json,restrict_public_groups,created_at,updated_at";
  if (hasID) {
    if (!id(body.id)) return error("INVALID_REQUEST");
    rows = await env.DB.prepare(
      `SELECT ${columns} FROM users WHERE id=? AND deleted_at IS NULL LIMIT 2`,
    ).bind(body.id).all<Record<string, unknown>>();
  } else {
    if (!isBoundedString(body.email, 255, 3)) return error("INVALID_REQUEST");
    const normalized = body.email.trim().toLowerCase();
    rows = await env.DB.prepare(
      `SELECT ${columns} FROM users WHERE lower(trim(email))=? AND deleted_at IS NULL LIMIT 2`,
    ).bind(normalized).all<Record<string, unknown>>();
  }
  if (rows.results.length === 0) return error("NOT_FOUND", 404);
  if (rows.results.length !== 1) return error("CONTROL_PLANE_UNAVAILABLE", 503);
  const user = authUserRow(rows.results[0]);
  if (!user) return error("CONTROL_PLANE_UNAVAILABLE", 503);
  return json({ user });
}

const keyColumns = "id,user_id,group_id,name,status,ip_whitelist_json,ip_blacklist_json,expires_at,last_used_at,created_at,updated_at";

async function listAPIKeys(request: Request, env: Env): Promise<Response> {
  const body = await readJson<unknown>(request);
  const allowed = ["user_id", "page", "page_size", "sort_by", "sort_order", "search", "status", "group_id"];
  if (!isObject(body) || !only(body, allowed) || !id(body.user_id)) return error("INVALID_REQUEST");
  const page = body.page ?? 1;
  const pageSize = body.page_size ?? 20;
  const sortBy = body.sort_by ?? "created_at";
  const sortOrder = body.sort_order ?? "desc";
  const sortColumns: Record<string, string> = {
    created_at: "created_at",
    updated_at: "updated_at",
    name: "name",
    status: "status",
  };
  if (!Number.isInteger(page) || Number(page) < 1 || !Number.isInteger(pageSize) || Number(pageSize) < 1 || Number(pageSize) > PAGE_MAX) return error("INVALID_REQUEST");
  if (typeof sortBy !== "string" || sortColumns[sortBy] === undefined || (sortOrder !== "asc" && sortOrder !== "desc")) return error("NOT_MIGRATED", 501);

  const clauses = ["user_id=?", "deleted_at IS NULL"];
  const values: unknown[] = [body.user_id];
  if (body.search !== undefined) {
    if (!isBoundedString(body.search, 100, 1)) return error("INVALID_REQUEST");
    clauses.push("name LIKE ? ESCAPE '\\'");
    values.push(`%${body.search.replace(/[\\%_]/g, "\\$&")}%`);
  }
  if (body.status !== undefined) {
    if (body.status !== "active" && body.status !== "disabled") return error("INVALID_REQUEST");
    clauses.push("status=?");
    values.push(body.status);
  }
  if (body.group_id !== undefined) {
    if (!id(body.group_id)) return error("INVALID_REQUEST");
    clauses.push("group_id=?");
    values.push(body.group_id);
  }
  const where = clauses.join(" AND ");
  const totalRow = await env.DB.prepare(`SELECT count(*) total FROM api_keys WHERE ${where}`)
    .bind(...values).first<{ total: number }>();
  const offset = (Number(page) - 1) * Number(pageSize);
  const rows = await env.DB.prepare(
    `SELECT ${keyColumns} FROM api_keys WHERE ${where} ORDER BY ${sortColumns[sortBy]} ${sortOrder.toUpperCase()}, length(id) ${sortOrder.toUpperCase()}, id ${sortOrder.toUpperCase()} LIMIT ? OFFSET ?`,
  ).bind(...values, Number(pageSize), offset).all<Record<string, unknown>>();
  const apiKeys = rows.results.map(apiKeyRow);
  if (apiKeys.some((item) => item === null)) return error("CONTROL_PLANE_UNAVAILABLE", 503);
  return json({ api_keys: apiKeys, total: String(totalRow?.total ?? 0) });
}

async function countAPIKeys(request: Request, env: Env): Promise<Response> {
  const body = await readJson<unknown>(request);
  if (!isObject(body) || !only(body, ["user_id"]) || !id(body.user_id)) return error("INVALID_REQUEST");
  const row = await env.DB.prepare(
    "SELECT count(*) total FROM api_keys WHERE user_id=? AND deleted_at IS NULL",
  ).bind(body.user_id).first<{ total: number }>();
  return json({ count: String(row?.total ?? 0) });
}

async function apiKeyExists(request: Request, env: Env): Promise<Response> {
  const body = await readJson<unknown>(request);
  if (!isObject(body) || !only(body, ["raw_key"]) || !isBoundedString(body.raw_key, 128, 16) || !/^[A-Za-z0-9_-]+$/.test(body.raw_key)) return error("INVALID_REQUEST");
  const hash = await sha256(body.raw_key);
  const row = await env.DB.prepare(
    "SELECT 1 present FROM api_keys WHERE key_hash=? AND deleted_at IS NULL LIMIT 1",
  ).bind(hash).first<{ present: number }>();
  return json({ exists: row?.present === 1 });
}

export async function privateDataPlane(request: Request, env: Env, route: string): Promise<Response> {
  if (!isBoundedString(request.headers.get("X-Sub2API-Container-Id"), 256)) return error("NOT_FOUND", 404);
  switch (route) {
    case "/v1/private/auth-users/get":
      return authUser(request, env);
    case "/v1/private/api-keys/list-by-owner":
      return listAPIKeys(request, env);
    case "/v1/private/api-keys/count-by-owner":
      return countAPIKeys(request, env);
    case "/v1/private/api-keys/exists":
      return apiKeyExists(request, env);
    default:
      return error("NOT_FOUND", 404);
  }
}
