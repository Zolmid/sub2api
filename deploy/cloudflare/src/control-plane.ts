import type { Completion, UsageEnvelope } from "./contracts";
import { decryptAPIKeyCredentials, type CredentialRuntime } from "./credentials";
import { managementControlPlane } from "./management";
import { privateDataPlane } from "./private-data";
import { isTOTPControlPath, totpControlPlane } from "./totp-control";
import {
  BRIDGE_VERSION,
  INTERNAL_HOST,
  MAX_CONTROL_BODY_BYTES,
  USAGE_EVENT_TYPE,
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

const PUBLISH_TIMEOUT_MS = 2_000;
const MAX_OUTBOX_ATTEMPTS = 10;
const OUTBOX_DRAIN_LIMIT = 25;

type RuntimeEnv = Omit<
  Env,
  | "ENVIRONMENT"
  | "ALLOW_TEST_FIXTURE"
  | "SUB2API_CF_UPSTREAM_ALLOWED_HOSTS"
> & CredentialRuntime;

type Alias = {
  alias: string;
  upstream_model: string;
  status: string;
  updated_at: string;
};

type AuthRow = {
  key_id: string;
  key_user_id: string;
  group_id: string | null;
  key_name: string;
  key_status: string;
  ip_whitelist_json: string;
  ip_blacklist_json: string;
  expires_at: string | null;
  user_id: string;
  user_status: string;
  role: string;
  concurrency: number;
  balance_microusd: string;
  allowed_group_ids_json: string;
  restrict_public_groups: number;
  group_name: string | null;
  platform: string | null;
  group_status: string | null;
  is_exclusive: number | null;
  subscription_type: string | null;
};

type Account = {
  id: string;
  name: string;
  platform: string;
  type: string;
  max_concurrency: number;
  credential_envelope: string;
  extra_json: string;
};

type LeaseWire = {
  account_id: string;
  lease_id: string;
  request_id: string;
  owner: string;
  epoch: string;
  expires_at: string;
};

type LeaseEnvelope = {
  lease: LeaseWire;
  created: boolean;
};

type GatewayIdentity = {
  request_id: string;
  api_key_id: string;
  account_id: string;
  lease_id: string;
  lease_epoch: string;
  owner: string;
  model: string;
  upstream_model: string;
  state: string;
};

const hasBridgeVersion = (request: Request): boolean =>
  request.headers.get("X-Sub2API-Bridge-Version") === BRIDGE_VERSION;

export async function controlPlane(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (
    url.hostname !== INTERNAL_HOST ||
    !hasBridgeVersion(request) ||
    request.method !== "POST"
  ) {
    return error("NOT_FOUND", 404);
  }

  try {
    if (isTOTPControlPath(url.pathname)) {
      return await totpControlPlane(request, env, url.pathname);
    }
    switch (url.pathname) {
      case "/v1/auth/resolve":
        return await resolveAPIKey(request, env);
      case "/v1/auth/touch":
        return await touchAPIKey(request, env);
      case "/v1/requests/admit":
        return await admitRequest(request, env);
      case "/v1/leases/renew":
        return await relayLeaseAction(request, env, "/renew");
      case "/v1/leases/release":
        return await relayLeaseAction(request, env, "/release");
      case "/v1/requests/complete":
        return await completeRequest(request, env);
      case "/v1/private/auth-users/get":
      case "/v1/private/api-keys/list-by-owner":
      case "/v1/private/api-keys/count-by-owner":
      case "/v1/private/api-keys/exists":
        return await privateDataPlane(request, env, url.pathname);
      case "/v1/manage/users/create":
      case "/v1/manage/users/get":
      case "/v1/manage/users/list":
      case "/v1/manage/users/balance-history":
      case "/v1/manage/users/update":
      case "/v1/manage/users/delete":
      case "/v1/manage/users/balance-adjust":
      case "/v1/manage/groups/create":
      case "/v1/manage/groups/get":
      case "/v1/manage/groups/list":
      case "/v1/manage/groups/update":
      case "/v1/manage/groups/delete":
      case "/v1/manage/api-keys/create":
      case "/v1/manage/api-keys/get":
      case "/v1/manage/api-keys/list":
      case "/v1/manage/api-keys/update":
      case "/v1/manage/api-keys/rebind-group":
      case "/v1/manage/api-keys/revoke":
      case "/v1/manage/api-keys/rotate":
      case "/v1/manage/accounts/create":
      case "/v1/manage/accounts/get":
      case "/v1/manage/accounts/list":
      case "/v1/manage/accounts/update":
      case "/v1/manage/accounts/delete":
        return await managementControlPlane(request, env, url.pathname);
      default:
        return error("NOT_FOUND", 404);
    }
  } catch {
    // The control plane never returns database or credential details to the
    // Container. Callers can retry an availability error safely.
    return error("CONTROL_PLANE_UNAVAILABLE", 503);
  }
}

async function fetchAuthRowByHash(hash: string, env: Env): Promise<AuthRow | null> {
  return env.DB.prepare(
    `SELECT
       k.id key_id,
       k.user_id key_user_id,
       k.group_id,
       k.name key_name,
       k.status key_status,
       k.ip_whitelist_json,
       k.ip_blacklist_json,
       k.expires_at,
       u.id user_id,
       u.status user_status,
       u.role,
       u.concurrency,
       u.balance_microusd,
       u.allowed_group_ids_json,
       u.restrict_public_groups,
       g.name group_name,
       g.platform,
       g.status group_status,
       g.is_exclusive,
       g.subscription_type
     FROM api_keys k
     JOIN users u ON u.id=k.user_id
     LEFT JOIN groups g ON g.id=k.group_id
     WHERE k.key_hash=? AND k.deleted_at IS NULL AND u.deleted_at IS NULL
       AND g.deleted_at IS NULL`,
  )
    .bind(hash)
    .first<AuthRow>();
}

async function fetchAuthRowByID(keyID: string, env: Env): Promise<AuthRow | null> {
  return env.DB.prepare(
    `SELECT
       k.id key_id,
       k.user_id key_user_id,
       k.group_id,
       k.name key_name,
       k.status key_status,
       k.ip_whitelist_json,
       k.ip_blacklist_json,
       k.expires_at,
       u.id user_id,
       u.status user_status,
       u.role,
       u.concurrency,
       u.balance_microusd,
       u.allowed_group_ids_json,
       u.restrict_public_groups,
       g.name group_name,
       g.platform,
       g.status group_status,
       g.is_exclusive,
       g.subscription_type
     FROM api_keys k
     JOIN users u ON u.id=k.user_id
     LEFT JOIN groups g ON g.id=k.group_id
     WHERE k.id=? AND k.deleted_at IS NULL AND u.deleted_at IS NULL
       AND g.deleted_at IS NULL`,
  )
    .bind(keyID)
    .first<AuthRow>();
}

function parseStringArray(value: string, decimalOnly = false): string[] | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) return null;
    if (
      !parsed.every(
        (item) =>
          isBoundedString(item, 512, 0) &&
          (!decimalOnly || isCanonicalPositiveDecimal(item)),
      )
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function hasPositiveBalance(value: string): boolean {
  if (!isCanonicalUnsignedDecimal(value) || value.length > 40) return false;
  try {
    return BigInt(value) > 0n;
  } catch {
    return false;
  }
}

function isUnexpired(value: string | null): boolean {
  if (value === null) return true;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && timestamp > Date.now();
}

function permittedAuth(row: AuthRow, requestedGroup?: string): boolean {
  return (
    row.key_status === "active" &&
    row.user_status === "active" &&
    row.group_status === "active" &&
    isCanonicalPositiveDecimal(row.key_id) &&
    isCanonicalPositiveDecimal(row.key_user_id) &&
    row.key_user_id === row.user_id &&
    isCanonicalPositiveDecimal(row.user_id) &&
    isCanonicalPositiveDecimal(row.group_id) &&
    (requestedGroup === undefined || row.group_id === requestedGroup) &&
    hasPositiveBalance(row.balance_microusd) &&
    isUnexpired(row.expires_at)
  );
}

async function resolveAPIKey(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{ key?: unknown }>(request);
  if (!body || !isBoundedString(body.key, 8_192)) {
    return error("API_KEY_NOT_FOUND", 404);
  }

  const row = await fetchAuthRowByHash(await sha256(body.key), env);
  if (!row || !permittedAuth(row)) return error("API_KEY_NOT_FOUND", 404);

  const whitelist = parseStringArray(row.ip_whitelist_json);
  const blacklist = parseStringArray(row.ip_blacklist_json);
  const allowedGroups = parseStringArray(row.allowed_group_ids_json, true);
  if (!whitelist || !blacklist || !allowedGroups || row.group_id === null) {
    return error("API_KEY_NOT_FOUND", 404);
  }

  return json({
    api_key: {
      id: row.key_id,
      user_id: row.user_id,
      name: row.key_name,
      status: row.key_status,
      group_id: row.group_id,
      ip_whitelist: whitelist,
      ip_blacklist: blacklist,
      expires_at: row.expires_at,
    },
    user: {
      id: row.user_id,
      status: row.user_status,
      role: row.role,
      concurrency: row.concurrency,
      balance_positive: true,
      allowed_group_ids: allowedGroups,
      restrict_public_groups: row.restrict_public_groups === 1,
    },
    group: {
      id: row.group_id,
      name: row.group_name,
      platform: row.platform,
      status: row.group_status,
      is_exclusive: row.is_exclusive === 1,
      subscription_type: row.subscription_type,
    },
  });
}

async function touchAPIKey(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{ api_key_id?: unknown; used_at?: unknown }>(request);
  if (
    !body ||
    !isCanonicalPositiveDecimal(body.api_key_id) ||
    body.api_key_id.length > 20 ||
    !isBoundedString(body.used_at, 64) ||
    !Number.isFinite(Date.parse(body.used_at))
  ) {
    return error("INVALID_REQUEST");
  }
  const usedAt = new Date(body.used_at).toISOString();
  await env.DB.prepare(
    `UPDATE api_keys SET last_used_at=?
     WHERE id=? AND deleted_at IS NULL
       AND (last_used_at IS NULL OR last_used_at<?)`,
  )
    .bind(usedAt, body.api_key_id, usedAt)
    .run();
  return new Response(null, { status: 204 });
}

async function resolveAlias(model: string, env: Env): Promise<Alias | null> {
  let cached: Alias | null = null;
  try {
    cached = await env.CONFIG_CACHE.get<Alias>(`model:${model}`, "json");
  } catch {
    // D1 is authoritative and remains available without KV.
  }

  const authoritative = await env.DB.prepare(
    `SELECT alias,upstream_model,status,updated_at
     FROM model_aliases WHERE alias=?`,
  )
    .bind(model)
    .first<Alias>();
  if (
    !authoritative ||
    authoritative.status !== "active" ||
    !isBoundedString(authoritative.upstream_model, 256)
  ) {
    return null;
  }

  if (canonical(cached) !== canonical(authoritative)) {
    try {
      await env.CONFIG_CACHE.put(
        `model:${model}`,
        JSON.stringify(authoritative),
        { expirationTtl: 300 },
      );
    } catch {
      // A cache write cannot make an authoritative D1 result unavailable.
    }
  }
  return authoritative;
}

async function decryptCredentials(
  envelope: string,
  env: Env,
): Promise<Record<string, string> | null> {
  return decryptAPIKeyCredentials(envelope, env as unknown as RuntimeEnv);
}

function parseObject(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function validLeaseEnvelope(
  value: unknown,
  expected: { accountID: string; requestID: string; owner: string },
): value is LeaseEnvelope {
  if (!value || typeof value !== "object") return false;
  const envelope = value as Partial<LeaseEnvelope>;
  const lease = envelope.lease;
  if (!lease || typeof lease !== "object") return false;
  return (
    typeof envelope.created === "boolean" &&
    lease.account_id === expected.accountID &&
    lease.request_id === expected.requestID &&
    lease.owner === expected.owner &&
    isBoundedString(lease.lease_id, 256) &&
    isCanonicalPositiveDecimal(lease.epoch) &&
    lease.epoch.length <= 20 &&
    isBoundedString(lease.expires_at, 64) &&
    Number.isFinite(Date.parse(lease.expires_at)) &&
    Date.parse(lease.expires_at) > Date.now()
  );
}

async function releaseNewLease(
  stub: DurableObjectStub,
  lease: LeaseWire,
): Promise<void> {
  try {
    await stub.fetch("https://lease/release", {
      method: "POST",
      body: JSON.stringify(lease),
    });
  } catch {
    // Expiry remains the final recovery path if compensation itself fails.
  }
}

async function admitRequest(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{
    request_id?: unknown;
    api_key_id?: unknown;
    group_id?: unknown;
    model?: unknown;
    lease_ttl_seconds?: unknown;
  }>(request);
  const owner = request.headers.get("X-Sub2API-Container-Id");
  if (
    !body ||
    !isBoundedString(body.request_id, 256) ||
    !isCanonicalPositiveDecimal(body.api_key_id) ||
    body.api_key_id.length > 20 ||
    !isCanonicalPositiveDecimal(body.group_id) ||
    body.group_id.length > 20 ||
    !isBoundedString(body.model, 256) ||
    !isBoundedString(owner, 256) ||
    !Number.isInteger(body.lease_ttl_seconds) ||
    Number(body.lease_ttl_seconds) < 3 ||
    Number(body.lease_ttl_seconds) > 3600
  ) {
    return error("ADMISSION_REJECTED", 429);
  }

  // Re-read all revocable authority at admission time. The earlier auth resolve
  // is not trusted across a disable, expiry, group, or balance change window.
  const auth = await fetchAuthRowByID(body.api_key_id, env);
  if (!auth || !permittedAuth(auth, body.group_id)) {
    return error("ADMISSION_REJECTED", 429);
  }

  const mapped = await resolveAlias(body.model, env);
  if (!mapped) return error("ADMISSION_REJECTED", 429);

  const account = await env.DB.prepare(
    `SELECT
       a.id,a.name,a.platform,a.type,a.max_concurrency,
       a.credential_envelope,a.extra_json
     FROM accounts a
     JOIN account_groups ag ON ag.account_id=a.id
     WHERE ag.group_id=?
       AND a.status='active'
       AND a.schedulable=1
       AND a.deleted_at IS NULL
       AND a.platform='openai'
       AND a.type='apikey'
     ORDER BY a.priority ASC,a.id ASC
     LIMIT 1`,
  )
    .bind(body.group_id)
    .first<Account>();
  if (
    !account ||
    !isCanonicalPositiveDecimal(account.id) ||
    account.id.length > 20 ||
    !Number.isInteger(account.max_concurrency) ||
    account.max_concurrency < 1
  ) {
    return error("ADMISSION_REJECTED", 429);
  }

  const credential = await decryptCredentials(account.credential_envelope, env);
  const extra = parseObject(account.extra_json);
  if (!credential || !extra) return error("ADMISSION_REJECTED", 429);

  const stub = env.ACCOUNT_LEASE.get(
    env.ACCOUNT_LEASE.idFromName(`account:${account.id}`),
  );
  const acquired = await stub.fetch("https://lease/acquire", {
    method: "POST",
    body: JSON.stringify({
      account_id: account.id,
      request_id: body.request_id,
      owner,
      max_concurrency: account.max_concurrency,
      ttl_seconds: body.lease_ttl_seconds,
    }),
  });
  if (!acquired.ok) return error("ADMISSION_REJECTED", 429);

  const leaseValue = (await acquired.json()) as unknown;
  if (
    !validLeaseEnvelope(leaseValue, {
      accountID: account.id,
      requestID: body.request_id,
      owner,
    })
  ) {
    return error("ADMISSION_REJECTED", 429);
  }
  const leased = leaseValue;

  let inserted: D1Result;
  try {
    inserted = await env.DB.prepare(
      `INSERT OR IGNORE INTO gateway_requests(
         request_id,api_key_id,account_id,lease_id,lease_epoch,owner,
         model,upstream_model,state,created_at
       ) VALUES(?,?,?,?,?,?,?,?,?,?)`,
    )
      .bind(
        body.request_id,
        body.api_key_id,
        account.id,
        leased.lease.lease_id,
        leased.lease.epoch,
        owner,
        body.model,
        mapped.upstream_model,
        "admitted",
        now(),
      )
      .run();
  } catch (cause) {
    if (leased.created) await releaseNewLease(stub, leased.lease);
    throw cause;
  }

  if ((inserted.meta.changes ?? 0) === 0) {
    const existing = await env.DB.prepare(
      `SELECT request_id,api_key_id,account_id,lease_id,lease_epoch,
              owner,model,upstream_model,state
       FROM gateway_requests WHERE request_id=?`,
    )
      .bind(body.request_id)
      .first<GatewayIdentity>();
    const same =
      existing?.request_id === body.request_id &&
      existing.api_key_id === body.api_key_id &&
      existing.account_id === account.id &&
      existing.lease_id === leased.lease.lease_id &&
      existing.lease_epoch === leased.lease.epoch &&
      existing.owner === owner &&
      existing.model === body.model &&
      existing.upstream_model === mapped.upstream_model &&
      existing.state === "admitted";
    if (!same) {
      if (leased.created) await releaseNewLease(stub, leased.lease);
      return error("ADMISSION_REJECTED", 429);
    }
  }

  return json({
    account: {
      id: account.id,
      name: account.name,
      platform: account.platform,
      type: account.type,
      concurrency: account.max_concurrency,
      credentials: credential,
      extra,
    },
    upstream_model: mapped.upstream_model,
    lease: leased.lease,
  });
}

async function relayLeaseAction(
  request: Request,
  env: Env,
  path: "/renew" | "/release",
): Promise<Response> {
  const data = await readJson<Record<string, unknown>>(request);
  const owner = request.headers.get("X-Sub2API-Container-Id");
  if (
    !data ||
    !isCanonicalPositiveDecimal(data.account_id) ||
    data.account_id.length > 20 ||
    !isBoundedString(data.request_id, 256) ||
    !isBoundedString(data.lease_id, 256) ||
    !isCanonicalPositiveDecimal(data.epoch) ||
    data.epoch.length > 20 ||
    !isBoundedString(owner, 256) ||
    data.owner !== owner ||
    (path === "/renew" &&
      (!Number.isInteger(data.ttl_seconds) ||
        Number(data.ttl_seconds) < 3 ||
        Number(data.ttl_seconds) > 3600))
  ) {
    return error("LEASE_IDENTITY_REJECTED", 409);
  }

  return env.ACCOUNT_LEASE.get(
    env.ACCOUNT_LEASE.idFromName(`account:${data.account_id}`),
  ).fetch(`https://lease${path}`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

const completionKeys = new Set([
  "schema_version",
  "event_type",
  "event_id",
  "request_id",
  "api_key_id",
  "account_id",
  "lease_id",
  "lease_epoch",
  "outcome",
  "usage_state",
  "input_tokens",
  "output_tokens",
  "cache_read_tokens",
  "model",
  "upstream_model",
  "upstream_request_id",
  "duration_ms",
]);

export function validCompletion(value: unknown): value is Completion {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const body = value as Partial<Completion>;
  if (Object.keys(value).some((key) => !completionKeys.has(key))) return false;
  return (
    body.schema_version === BRIDGE_VERSION &&
    body.event_type === USAGE_EVENT_TYPE &&
    isBoundedString(body.request_id, 256) &&
    body.event_id === `${body.request_id}:usage:v1` &&
    isCanonicalPositiveDecimal(body.api_key_id) &&
    body.api_key_id.length <= 20 &&
    isCanonicalPositiveDecimal(body.account_id) &&
    body.account_id.length <= 20 &&
    isBoundedString(body.lease_id, 256) &&
    isCanonicalPositiveDecimal(body.lease_epoch) &&
    body.lease_epoch.length <= 20 &&
    (body.outcome === "succeeded" || body.outcome === "failed") &&
    (body.usage_state === "confirmed" || body.usage_state === "unknown") &&
    isCanonicalUnsignedDecimal(body.input_tokens) &&
    body.input_tokens.length <= 20 &&
    isCanonicalUnsignedDecimal(body.output_tokens) &&
    body.output_tokens.length <= 20 &&
    isCanonicalUnsignedDecimal(body.cache_read_tokens) &&
    body.cache_read_tokens.length <= 20 &&
    isCanonicalUnsignedDecimal(body.duration_ms) &&
    body.duration_ms.length <= 20 &&
    isBoundedString(body.model, 256) &&
    isBoundedString(body.upstream_model, 256) &&
    (body.upstream_request_id === undefined ||
      isBoundedString(body.upstream_request_id, 512))
  );
}

async function recordConflict(
  env: Env,
  source: "completion" | "queue",
  eventID: string,
  existingHash: string,
  incomingHash: string,
): Promise<void> {
  await env.DB.prepare(
    `INSERT OR IGNORE INTO outbox_conflicts(
       source,event_id,existing_hash,incoming_hash,observed_at
     ) VALUES(?,?,?,?,?)`,
  )
    .bind(source, eventID, existingHash, incomingHash, now())
    .run();
}

async function completeRequest(request: Request, env: Env): Promise<Response> {
  const body = await readJson<unknown>(request);
  const owner = request.headers.get("X-Sub2API-Container-Id");
  if (!validCompletion(body) || !isBoundedString(owner, 256)) {
    return error("INVALID_REQUEST");
  }

  const payload = canonical(body);
  const payloadHash = await sha256(payload);
  const prior = await env.DB.prepare(
    "SELECT payload_hash FROM outbox_events WHERE event_id=?",
  )
    .bind(body.event_id)
    .first<{ payload_hash: string }>();
  if (prior) {
    if (prior.payload_hash === payloadHash) return new Response(null, { status: 204 });
    await recordConflict(
      env,
      "completion",
      body.event_id,
      prior.payload_hash,
      payloadHash,
    );
    return error("EVENT_CONFLICT", 409);
  }

  const completedAt = now();
  const completionNonce = crypto.randomUUID();
  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE gateway_requests
       SET state=?,event_id=?,completed_at=?,completion_nonce=?
       WHERE request_id=? AND api_key_id=? AND account_id=?
         AND lease_id=? AND lease_epoch=? AND owner=? AND state='admitted'`,
    ).bind(
      body.outcome,
      body.event_id,
      completedAt,
      completionNonce,
      body.request_id,
      body.api_key_id,
      body.account_id,
      body.lease_id,
      body.lease_epoch,
      owner,
    ),
    env.DB.prepare(
      `INSERT INTO outbox_events(
         event_id,request_id,payload_json,payload_hash,state,
         attempts,created_at
       )
       SELECT ?,?,?,?,?,0,?
       FROM gateway_requests
       WHERE request_id=? AND completion_nonce=? AND event_id=?`,
    ).bind(
      body.event_id,
      body.request_id,
      payload,
      payloadHash,
      "pending",
      completedAt,
      body.request_id,
      completionNonce,
      body.event_id,
    ),
  ]);

  if (
    (results[0].meta.changes ?? 0) !== 1 ||
    (results[1].meta.changes ?? 0) !== 1
  ) {
    const raced = await env.DB.prepare(
      "SELECT payload_hash FROM outbox_events WHERE event_id=?",
    )
      .bind(body.event_id)
      .first<{ payload_hash: string }>();
    if (raced?.payload_hash === payloadHash) {
      return new Response(null, { status: 204 });
    }
    if (raced) {
      await recordConflict(
        env,
        "completion",
        body.event_id,
        raced.payload_hash,
        payloadHash,
      );
      return error("EVENT_CONFLICT", 409);
    }
    return error("REQUEST_IDENTITY_MISMATCH", 409);
  }

  try {
    await withTimeout(
      publish(env, body.event_id, payload, payloadHash),
      PUBLISH_TIMEOUT_MS,
    );
  } catch {
    await recordPublishFailure(env, body.event_id).catch(() => undefined);
  }
  return new Response(null, { status: 204 });
}

function withTimeout<T>(promise: Promise<T>, milliseconds: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("operation timed out")),
      milliseconds,
    );
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (cause) => {
        clearTimeout(timer);
        reject(cause);
      },
    );
  });
}

async function recordPublishFailure(env: Env, eventID: string): Promise<void> {
  await env.DB.prepare(
    `UPDATE outbox_events
     SET attempts=attempts+1,
         last_attempt_at=?,
         state=CASE WHEN attempts+1>=? THEN 'dead' ELSE state END
     WHERE event_id=? AND state='pending'`,
  )
    .bind(now(), MAX_OUTBOX_ATTEMPTS, eventID)
    .run();
}

export async function publish(
  env: Env,
  eventID: string,
  payload: string,
  payloadHash: string,
): Promise<void> {
  await env.USAGE_QUEUE.send({
    event_id: eventID,
    payload,
    payload_hash: payloadHash,
  } satisfies UsageEnvelope);
  await env.DB.prepare(
    `UPDATE outbox_events
     SET state='published',published_at=?,last_attempt_at=?
     WHERE event_id=? AND payload_hash=? AND state='pending'`,
  )
    .bind(now(), now(), eventID, payloadHash)
    .run();
}

export async function drainOutbox(env: Env): Promise<void> {
  const events = await env.DB.prepare(
    `SELECT event_id,payload_json,payload_hash
     FROM outbox_events
     WHERE state='pending' AND attempts<?
     ORDER BY created_at,event_id
     LIMIT ?`,
  )
    .bind(MAX_OUTBOX_ATTEMPTS, OUTBOX_DRAIN_LIMIT)
    .all<{ event_id: string; payload_json: string; payload_hash: string }>();

  for (const event of events.results) {
    try {
      await withTimeout(
        publish(env, event.event_id, event.payload_json, event.payload_hash),
        PUBLISH_TIMEOUT_MS,
      );
    } catch {
      await recordPublishFailure(env, event.event_id).catch(() => undefined);
    }
  }
}

function retryMessage(message: Message<UsageEnvelope>): void {
  const delaySeconds = Math.min(300, 2 ** Math.min(message.attempts, 8));
  message.retry({ delaySeconds });
}

function parseUsageEnvelope(value: unknown): UsageEnvelope | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const envelope = value as Partial<UsageEnvelope>;
  if (
    !isBoundedString(envelope.event_id, 512) ||
    !isBoundedString(envelope.payload, MAX_CONTROL_BODY_BYTES) ||
    typeof envelope.payload_hash !== "string" ||
    !/^[a-f0-9]{64}$/.test(envelope.payload_hash)
  ) {
    return null;
  }
  return envelope as UsageEnvelope;
}

async function consumeUsageMessage(
  message: Message<UsageEnvelope>,
  env: Env,
): Promise<void> {
  const envelope = parseUsageEnvelope(message.body);
  if (!envelope) {
    retryMessage(message);
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(envelope.payload) as unknown;
  } catch {
    retryMessage(message);
    return;
  }
  if (
    !validCompletion(parsed) ||
    parsed.event_id !== envelope.event_id ||
    canonical(parsed) !== envelope.payload ||
    (await sha256(envelope.payload)) !== envelope.payload_hash
  ) {
    retryMessage(message);
    return;
  }

  // The durable outbox is the authoritative event payload. A caller with
  // Queue producer access must not be able to alter token counts while keeping
  // the request identity and event ID valid.
  const authoritative = await env.DB.prepare(
    `SELECT request_id,payload_json,payload_hash
     FROM outbox_events WHERE event_id=?`,
  )
    .bind(parsed.event_id)
    .first<{
      request_id: string;
      payload_json: string;
      payload_hash: string;
    }>();
  if (!authoritative) {
    retryMessage(message);
    return;
  }
  if (
    authoritative.request_id !== parsed.request_id ||
    authoritative.payload_json !== envelope.payload ||
    authoritative.payload_hash !== envelope.payload_hash
  ) {
    await recordConflict(
      env,
      "queue",
      parsed.event_id,
      authoritative.payload_hash,
      envelope.payload_hash,
    );
    message.ack();
    return;
  }

  const existing = await env.DB.prepare(
    "SELECT payload_hash FROM usage_events WHERE event_id=?",
  )
    .bind(parsed.event_id)
    .first<{ payload_hash: string }>();
  if (existing) {
    if (existing.payload_hash !== envelope.payload_hash) {
      await recordConflict(
        env,
        "queue",
        parsed.event_id,
        existing.payload_hash,
        envelope.payload_hash,
      );
    }
    message.ack();
    return;
  }

  const consumedAt = now();
  const results = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO usage_events(
         event_id,request_id,payload_hash,schema_version,event_type,
         api_key_id,account_id,lease_id,lease_epoch,model,upstream_model,
         upstream_request_id,outcome,usage_state,input_tokens,output_tokens,
         cache_read_tokens,duration_ms,created_at
       )
       SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
       FROM gateway_requests
       WHERE request_id=? AND api_key_id=? AND account_id=?
         AND lease_id=? AND lease_epoch=? AND event_id=? AND state=?
         AND NOT EXISTS(
           SELECT 1 FROM usage_events WHERE event_id=?
         )`,
    ).bind(
      parsed.event_id,
      parsed.request_id,
      envelope.payload_hash,
      parsed.schema_version,
      parsed.event_type,
      parsed.api_key_id,
      parsed.account_id,
      parsed.lease_id,
      parsed.lease_epoch,
      parsed.model,
      parsed.upstream_model,
      parsed.upstream_request_id ?? null,
      parsed.outcome,
      parsed.usage_state,
      parsed.input_tokens,
      parsed.output_tokens,
      parsed.cache_read_tokens,
      parsed.duration_ms,
      consumedAt,
      parsed.request_id,
      parsed.api_key_id,
      parsed.account_id,
      parsed.lease_id,
      parsed.lease_epoch,
      parsed.event_id,
      parsed.outcome,
      parsed.event_id,
    ),
    env.DB.prepare(
      `INSERT OR IGNORE INTO outbox_conflicts(
         source,event_id,existing_hash,incoming_hash,observed_at
       )
       SELECT 'queue',event_id,payload_hash,?,?
       FROM usage_events
       WHERE event_id=? AND payload_hash<>?`,
    ).bind(
      envelope.payload_hash,
      consumedAt,
      parsed.event_id,
      envelope.payload_hash,
    ),
  ]);

  if (
    (results[0].meta.changes ?? 0) === 1 ||
    (results[1].meta.changes ?? 0) === 1
  ) {
    message.ack();
    return;
  }

  const raced = await env.DB.prepare(
    "SELECT payload_hash FROM usage_events WHERE event_id=?",
  )
    .bind(parsed.event_id)
    .first<{ payload_hash: string }>();
  if (raced) {
    if (raced.payload_hash !== envelope.payload_hash) {
      await recordConflict(
        env,
        "queue",
        parsed.event_id,
        raced.payload_hash,
        envelope.payload_hash,
      );
    }
    message.ack();
    return;
  }

  // Most often this is an out-of-order delivery before the completion batch
  // became visible. A bounded Queue retry is safer than inventing usage state.
  retryMessage(message);
}

export async function consumeUsageBatch(
  batch: MessageBatch<UsageEnvelope>,
  env: Env,
): Promise<void> {
  for (const message of batch.messages) {
    try {
      await consumeUsageMessage(message, env);
    } catch {
      retryMessage(message);
    }
  }
}
