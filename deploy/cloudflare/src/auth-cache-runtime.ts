import { canonical, sha256 } from "./contracts";

const MAX_I64_TEXT = "9223372036854775807";
const MAX_I64_MINUS_ONE_TEXT = "9223372036854775806";
const DIGEST_RE = /^[0-9a-f]{64}$/;
const EVENT_ID_RE = /^[0-9a-f]{32}$/;
const CACHE_KEY_RE = /^[0-9a-f]{64}:(?:[1-9][0-9]{0,18})?$/;
const UTC_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{3}))?Z$/;
const BAD_TEXT_RE = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/u;
const MAX_ATTEMPTS = 32;

export type AuthCacheAuthorization = Readonly<{
  api_key_id: string;
  user_id: string;
  group_id: string;
  expires_at: string | null;
  allowed_group_ids: readonly string[];
  restrict_public_groups: boolean;
}>;

export type AuthCacheResolution =
  | Readonly<{ ok: true; code: "OK"; authorization: AuthCacheAuthorization }>
  | Readonly<{
      ok: false;
      code: "AUTH_NOT_FOUND" | "AUTH_INVALID_INPUT" | "AUTH_UNAVAILABLE";
    }>;

export type AuthCacheReplicaEntry = Readonly<{
  cache_key: string;
  fingerprint: string;
  expires_at_ms: number;
  projection: unknown;
}>;

export interface AuthCacheReplica {
  write(entries: readonly AuthCacheReplicaEntry[]): Promise<void>;
}

export type AuthCacheOutboxEvent = Readonly<{
  event_id: string;
  entity_type: "api_key" | "user" | "group" | "subscription" | "credential";
  entity_id: string;
  credential_digest: string | null;
  old_credential_digest: string | null;
  new_credential_digest: string | null;
  revision: string;
}>;

export type AuthCacheOutboxClaim = Readonly<{
  event: AuthCacheOutboxEvent;
  claim_token: string;
  claim_version: string;
  claim_expires_at: string;
}>;

type D1Value = string | number | null;
type Row = Record<string, D1Value>;

type Probe = Readonly<{
  credential_digest: string;
  credential_revision: string;
  key_id: string | null;
  user_id: string | null;
  group_id: string | null;
  key_status: "active" | "disabled" | null;
  key_deleted_at: string | null;
  key_revision: string;
  user_status: "active" | "disabled" | null;
  user_deleted_at: string | null;
  user_revision: string;
  group_status: "active" | "disabled" | null;
  group_deleted_at: string | null;
  group_revision: string;
  subscription_revision: string;
}>;

type Projection = Readonly<{
  proof: Probe;
  allowed_group_ids: readonly string[];
  restrict_public_groups: boolean;
  is_exclusive: boolean;
  subscription_type: "standard" | "subscription";
  key_expires_at: string | null;
  live_subscription: null | Readonly<{
    id: string;
    status: "active" | "expired" | "suspended";
    starts_at: string;
    expires_at: string;
    version: string;
    revision: string;
  }>;
}>;

type CacheEntry = Readonly<{
  cache_key: string;
  fingerprint: string;
  expires_at_ms: number;
  projection: Projection;
  last: number;
}>;

type Config = Readonly<{
  capacity?: number;
  positive_ttl_ms?: number;
  negative_ttl_ms?: number;
  claim_lease_ms?: number;
  now?: () => number;
}>;

function isSafeText(value: unknown, minimum: number, maximum: number): value is string {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    BAD_TEXT_RE.test(value)
  ) {
    return false;
  }
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (next < 0xdc00 || next > 0xdfff) return false;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function isDecimalInRange(
  value: unknown,
  options: { allowZero: boolean; maximum: string },
): value is string {
  if (typeof value !== "string") return false;
  if (options.allowZero && value === "0") return true;
  if (!/^[1-9][0-9]*$/.test(value)) return false;
  return value.length < options.maximum.length ||
    (value.length === options.maximum.length && value <= options.maximum);
}

function isId(value: unknown): value is string {
  return isDecimalInRange(value, { allowZero: false, maximum: MAX_I64_TEXT });
}

function isSubscriptionIdentity(value: unknown): value is string {
  if (!isSafeText(value, 3, 39)) return false;
  const separator = value.indexOf(":");
  return separator > 0 &&
    separator === value.lastIndexOf(":") &&
    isId(value.slice(0, separator)) &&
    isId(value.slice(separator + 1));
}

function isRevision(value: unknown): value is string {
  return isDecimalInRange(value, { allowZero: true, maximum: MAX_I64_TEXT });
}

function readDecimal(value: D1Value): string | null {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) return null;
    return String(value);
  }
  return typeof value === "string" && isRevision(value) ? value : null;
}

export function safeUtc(value: unknown): string | null | false {
  if (value === null) return null;
  if (!isSafeText(value, 20, 24)) return false;
  const match = UTC_RE.exec(value);
  if (!match) return false;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.valueOf())) return false;
  return parsed.toISOString() === value ? value : false;
}

function utcFromMillis(value: number): string | null {
  if (!Number.isFinite(value)) return null;
  try {
    const utc = new Date(value).toISOString();
    return safeUtc(utc) === utc ? utc : null;
  } catch {
    return null;
  }
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

function readInput(value: unknown): { credential: string; requestedGroupId?: string } | null {
  const input = readRecord(value, ["credential", "requested_group_id"]);
  if (!input || !isSafeText(input.credential, 1, 8192)) return null;
  if (input.requested_group_id !== undefined && !isId(input.requested_group_id)) {
    return null;
  }
  return {
    credential: input.credential,
    ...(input.requested_group_id === undefined
      ? {}
      : { requestedGroupId: input.requested_group_id }),
  };
}

function parseAllowedGroupIds(value: unknown): readonly string[] | null {
  if (!isSafeText(value, 2, 8192)) return null;
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.length > 100 || !parsed.every(isId)) {
      return null;
    }
    return new Set(parsed).size === parsed.length ? parsed : null;
  } catch {
    return null;
  }
}

async function fingerprint(probe: Probe): Promise<string> {
  return sha256(canonical(probe));
}

function status(value: D1Value): "active" | "disabled" | null {
  return value === "active" || value === "disabled" ? value : null;
}

function subscriptionStatus(value: D1Value): "active" | "expired" | "suspended" | null {
  return value === "active" || value === "expired" || value === "suspended"
    ? value
    : null;
}

function readProbe(row: Row | null): Probe {
  if (!row || typeof row.credential_digest !== "string" || !DIGEST_RE.test(row.credential_digest)) {
    throw new Error("corrupt auth cache probe");
  }

  const probe: Probe = {
    credential_digest: row.credential_digest,
    credential_revision: requireRevision(row.credential_revision),
    key_id: nullableId(row.key_id),
    user_id: nullableId(row.user_id),
    group_id: nullableId(row.group_id),
    key_status: status(row.key_status),
    key_deleted_at: requireNullableUtc(row.key_deleted_at),
    key_revision: requireRevision(row.key_revision),
    user_status: status(row.user_status),
    user_deleted_at: requireNullableUtc(row.user_deleted_at),
    user_revision: requireRevision(row.user_revision),
    group_status: status(row.group_status),
    group_deleted_at: requireNullableUtc(row.group_deleted_at),
    group_revision: requireRevision(row.group_revision),
    subscription_revision: requireRevision(row.subscription_revision),
  };

  if (
    (probe.key_id === null) !==
      (probe.user_id === null || probe.group_id === null || probe.key_status === null) ||
    (probe.user_id === null) !== (probe.user_status === null) ||
    (probe.group_id === null) !== (probe.group_status === null)
  ) {
    throw new Error("inconsistent auth cache probe");
  }

  return probe;
}

function requireRevision(value: D1Value): string {
  const revision = readDecimal(value);
  if (revision === null) throw new Error("invalid auth cache revision");
  return revision;
}

function nullableId(value: D1Value): string | null {
  if (value === null) return null;
  if (typeof value === "string" && isId(value)) return value;
  throw new Error("invalid auth cache id");
}

function requireNullableUtc(value: D1Value): string | null {
  const timestamp = safeUtc(value);
  if (timestamp === false) throw new Error("invalid auth cache timestamp");
  return timestamp;
}

function readProjection(row: Row | null): Projection | null {
  const proof = readProbe(row);
  if (proof.key_id === null) return null;

  const allowedGroupIds = parseAllowedGroupIds(row?.allowed_group_ids_json);
  const keyExpiresAt = requireNullableUtc(row?.key_expires_at ?? null);
  const restrictPublicGroups = row?.restrict_public_groups;
  const isExclusive = row?.is_exclusive;
  const subscriptionType = row?.subscription_type;

  if (
    !allowedGroupIds ||
    (restrictPublicGroups !== 0 && restrictPublicGroups !== 1) ||
    (isExclusive !== 0 && isExclusive !== 1) ||
    (subscriptionType !== "standard" && subscriptionType !== "subscription")
  ) {
    throw new Error("corrupt auth cache projection");
  }

  const liveSubscription =
    row?.subscription_id === null
      ? null
      : {
          id: nullableId(row?.subscription_id ?? null) ?? fail("invalid subscription id"),
          status:
            subscriptionStatus(row?.subscription_status ?? null) ??
            fail("invalid subscription status"),
          starts_at: requireUtc(row?.subscription_starts_at ?? null),
          expires_at: requireUtc(row?.subscription_expires_at ?? null),
          version: requirePositiveRevision(row?.subscription_version ?? null),
          revision: requireRevision(row?.subscription_revision ?? null),
        };

  return {
    proof,
    allowed_group_ids: allowedGroupIds,
    restrict_public_groups: restrictPublicGroups === 1,
    is_exclusive: isExclusive === 1,
    subscription_type: subscriptionType,
    key_expires_at: keyExpiresAt,
    live_subscription: liveSubscription,
  };
}

function fail(message: string): never {
  throw new Error(message);
}

function requireUtc(value: D1Value): string {
  const timestamp = safeUtc(value);
  if (timestamp === false || timestamp === null) {
    throw new Error("invalid auth cache timestamp");
  }
  return timestamp;
}

function requirePositiveRevision(value: D1Value): string {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error("invalid version");
    return String(value);
  }
  if (!isDecimalInRange(value, { allowZero: false, maximum: MAX_I64_TEXT })) {
    throw new Error("invalid version");
  }
  return value;
}

function projectionShape(value: unknown): value is Projection {
  const projection = readRecord(value, [
    "proof",
    "allowed_group_ids",
    "restrict_public_groups",
    "is_exclusive",
    "subscription_type",
    "key_expires_at",
    "live_subscription",
  ]);
  if (!projection) return false;
  if (
    !Array.isArray(projection.allowed_group_ids) ||
    !projection.allowed_group_ids.every(isId) ||
    typeof projection.restrict_public_groups !== "boolean" ||
    typeof projection.is_exclusive !== "boolean" ||
    (projection.subscription_type !== "standard" &&
      projection.subscription_type !== "subscription") ||
    safeUtc(projection.key_expires_at) === false
  ) {
    return false;
  }

  try {
    readProbe(projection.proof as Row);
  } catch {
    return false;
  }

  if (projection.live_subscription === null) return true;
  const subscription = readRecord(projection.live_subscription, [
    "id",
    "status",
    "starts_at",
    "expires_at",
    "version",
    "revision",
  ]);
  return !!subscription &&
    isId(subscription.id) &&
    subscriptionStatus(subscription.status as D1Value) !== null &&
    safeUtc(subscription.starts_at) !== false &&
    safeUtc(subscription.expires_at) !== false &&
    isDecimalInRange(subscription.version, { allowZero: false, maximum: MAX_I64_TEXT }) &&
    isRevision(subscription.revision);
}

function eventShape(row: Row): AuthCacheOutboxEvent | null {
  const entityType = row.entity_type;
  const credentialDigest = row.credential_digest;
  const oldCredentialDigest = row.old_credential_digest;
  const newCredentialDigest = row.new_credential_digest;
  if (
    typeof row.event_id !== "string" ||
    !EVENT_ID_RE.test(row.event_id) ||
    (entityType !== "api_key" &&
      entityType !== "user" &&
      entityType !== "group" &&
      entityType !== "subscription" &&
      entityType !== "credential") ||
    !isSafeText(row.entity_id, 1, 64) ||
    ((entityType === "api_key" || entityType === "user" || entityType === "group") &&
      !isId(row.entity_id)) ||
    (entityType === "subscription" && !isSubscriptionIdentity(row.entity_id)) ||
    (credentialDigest !== null &&
      (typeof credentialDigest !== "string" || !DIGEST_RE.test(credentialDigest))) ||
    (oldCredentialDigest !== null &&
      (typeof oldCredentialDigest !== "string" || !DIGEST_RE.test(oldCredentialDigest))) ||
    (newCredentialDigest !== null &&
      (typeof newCredentialDigest !== "string" || !DIGEST_RE.test(newCredentialDigest))) ||
    !isDecimalInRange(row.revision, { allowZero: false, maximum: MAX_I64_TEXT })
  ) {
    return null;
  }
  if (
    entityType === "credential" &&
    (row.entity_id !== credentialDigest ||
      (oldCredentialDigest !== null && oldCredentialDigest !== credentialDigest) ||
      (newCredentialDigest !== null && newCredentialDigest !== credentialDigest) ||
      (oldCredentialDigest !== null && newCredentialDigest !== null))
  ) {
    return null;
  }
  if (
    (entityType === "user" || entityType === "group" || entityType === "subscription") &&
    (credentialDigest !== null || oldCredentialDigest !== null || newCredentialDigest !== null)
  ) {
    return null;
  }
  if (entityType === "api_key") {
    if (credentialDigest === null) return null;
    const insertShape = oldCredentialDigest === null && newCredentialDigest === credentialDigest;
    const updateShape = oldCredentialDigest === null && newCredentialDigest === null;
    const deleteShape = oldCredentialDigest === credentialDigest && newCredentialDigest === null;
    const rotateShape =
      oldCredentialDigest !== null &&
      newCredentialDigest === credentialDigest &&
      oldCredentialDigest !== newCredentialDigest;
    if (!insertShape && !updateShape && !deleteShape && !rotateShape) return null;
  }
  return {
    event_id: row.event_id,
    entity_type: entityType,
    entity_id: row.entity_id,
    credential_digest: credentialDigest,
    old_credential_digest: oldCredentialDigest,
    new_credential_digest: newCredentialDigest,
    revision: row.revision,
  };
}

function claimShape(row: Row | null): AuthCacheOutboxClaim | null {
  if (
    !row ||
    row.state !== "claimed" ||
    typeof row.claim_token !== "string" ||
    !EVENT_ID_RE.test(row.claim_token) ||
    typeof row.claim_expires_at !== "string" ||
    safeUtc(row.claim_expires_at) === false ||
    !isDecimalInRange(row.claim_version, { allowZero: false, maximum: MAX_I64_TEXT })
  ) {
    return null;
  }
  const event = eventShape(row);
  if (!event) return null;
  return {
    event,
    claim_token: row.claim_token,
    claim_version: row.claim_version,
    claim_expires_at: row.claim_expires_at,
  };
}

/** The minimal D1 probe is the linearization point for every auth decision. */
export class AuthCacheRuntime {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly capacity: number;
  private readonly positiveTtlMs: number;
  private readonly negativeTtlMs: number;
  private readonly claimLeaseMs: number;
  private readonly now: () => number;
  private sequence = 0;
  private probes = 0;
  private fullLoads = 0;

  constructor(private readonly db: D1Database, config: Config = {}) {
    this.capacity =
      Number.isInteger(config.capacity) && config.capacity! > 0 && config.capacity! <= 1024
        ? config.capacity!
        : 128;
    this.positiveTtlMs =
      Number.isInteger(config.positive_ttl_ms) && config.positive_ttl_ms! >= 0
        ? config.positive_ttl_ms!
        : 5_000;
    this.negativeTtlMs =
      Number.isInteger(config.negative_ttl_ms) && config.negative_ttl_ms! >= 0
        ? config.negative_ttl_ms!
        : 1_000;
    this.claimLeaseMs =
      Number.isInteger(config.claim_lease_ms) &&
      config.claim_lease_ms! >= 100 &&
      config.claim_lease_ms! <= 60_000
        ? config.claim_lease_ms!
        : 5_000;
    this.now = config.now ?? Date.now;
  }

  get diagnosticMinimalProbeCount() {
    return this.probes;
  }

  get diagnosticProbeCount() {
    return this.probes;
  }

  get diagnosticFullLoadCount() {
    return this.fullLoads;
  }

  get diagnosticL1Size() {
    return this.cache.size;
  }

  async resolve(candidate: unknown): Promise<AuthCacheResolution> {
    const request = readInput(candidate);
    if (!request) return { ok: false, code: "AUTH_INVALID_INPUT" };

    const digest = await sha256(request.credential);
    const cacheKey = `${digest}:${request.requestedGroupId ?? ""}`;
    let probe: Probe;
    try {
      probe = await this.probe(digest);
    } catch {
      return { ok: false, code: "AUTH_UNAVAILABLE" };
    }

    const currentFingerprint = await fingerprint(probe);
    const cached = this.cache.get(cacheKey);
    if (
      cached &&
      cached.expires_at_ms > this.now() &&
      cached.fingerprint === currentFingerprint &&
      (await this.cacheEntryMatches(cached, probe, currentFingerprint))
    ) {
      this.cache.set(cacheKey, { ...cached, last: ++this.sequence });
      return this.authorize(cached.projection, request.requestedGroupId);
    }

    this.cache.delete(cacheKey);
    return this.loadAuthoritative(cacheKey, digest, request.requestedGroupId, currentFingerprint);
  }

  private async probe(digest: string): Promise<Probe> {
    this.probes += 1;
    const row = await this.db
      .prepare(
        `SELECT
           ? AS credential_digest,
           CAST(COALESCE(cr.revision, 0) AS TEXT) AS credential_revision,
           k.id AS key_id,
           k.user_id AS user_id,
           k.group_id AS group_id,
           k.status AS key_status,
           k.deleted_at AS key_deleted_at,
           CAST(COALESCE(kr.revision, 0) AS TEXT) AS key_revision,
           u.status AS user_status,
           u.deleted_at AS user_deleted_at,
           CAST(COALESCE(ur.revision, 0) AS TEXT) AS user_revision,
           g.status AS group_status,
           g.deleted_at AS group_deleted_at,
           CAST(COALESCE(gr.revision, 0) AS TEXT) AS group_revision,
           CAST(COALESCE(sr.revision, 0) AS TEXT) AS subscription_revision
         FROM (SELECT ? AS digest) AS input
         LEFT JOIN auth_cache_credential_revisions AS cr
           ON cr.credential_digest = input.digest
         LEFT JOIN api_keys AS k
           ON k.key_hash = input.digest
         LEFT JOIN auth_cache_entity_revisions AS kr
           ON kr.entity_type = 'api_key' AND kr.entity_id = k.id
         LEFT JOIN users AS u
           ON u.id = k.user_id
         LEFT JOIN auth_cache_entity_revisions AS ur
           ON ur.entity_type = 'user' AND ur.entity_id = u.id
         LEFT JOIN groups AS g
           ON g.id = k.group_id
         LEFT JOIN auth_cache_entity_revisions AS gr
           ON gr.entity_type = 'group' AND gr.entity_id = g.id
         LEFT JOIN auth_cache_entity_revisions AS sr
           ON sr.entity_type = 'subscription'
          AND sr.entity_id = k.user_id || ':' || k.group_id`,
      )
      .bind(digest, digest)
      .first<Row>();
    return readProbe(row);
  }

  private async full(digest: string): Promise<Projection | null> {
    this.fullLoads += 1;
    const now = new Date(this.now()).toISOString();
    const row = await this.db
      .prepare(
        `WITH input(digest, now_utc) AS (VALUES(?, ?)),
         probe AS (
           SELECT
             input.digest AS credential_digest,
             CAST(COALESCE(cr.revision, 0) AS TEXT) AS credential_revision,
             k.id AS key_id,
             k.user_id AS user_id,
             k.group_id AS group_id,
             k.status AS key_status,
             k.deleted_at AS key_deleted_at,
             CAST(COALESCE(kr.revision, 0) AS TEXT) AS key_revision,
             u.status AS user_status,
             u.deleted_at AS user_deleted_at,
             CAST(COALESCE(ur.revision, 0) AS TEXT) AS user_revision,
             g.status AS group_status,
             g.deleted_at AS group_deleted_at,
             CAST(COALESCE(gr.revision, 0) AS TEXT) AS group_revision,
             CAST(COALESCE(sr.revision, 0) AS TEXT) AS subscription_revision,
             k.expires_at AS key_expires_at,
             u.allowed_group_ids_json AS allowed_group_ids_json,
             u.restrict_public_groups AS restrict_public_groups,
             g.is_exclusive AS is_exclusive,
             g.subscription_type AS subscription_type
           FROM input
           LEFT JOIN auth_cache_credential_revisions AS cr
             ON cr.credential_digest = input.digest
           LEFT JOIN api_keys AS k
             ON k.key_hash = input.digest
           LEFT JOIN auth_cache_entity_revisions AS kr
             ON kr.entity_type = 'api_key' AND kr.entity_id = k.id
           LEFT JOIN users AS u
             ON u.id = k.user_id
           LEFT JOIN auth_cache_entity_revisions AS ur
             ON ur.entity_type = 'user' AND ur.entity_id = u.id
           LEFT JOIN groups AS g
             ON g.id = k.group_id
           LEFT JOIN auth_cache_entity_revisions AS gr
             ON gr.entity_type = 'group' AND gr.entity_id = g.id
           LEFT JOIN auth_cache_entity_revisions AS sr
             ON sr.entity_type = 'subscription'
            AND sr.entity_id = k.user_id || ':' || k.group_id
         ),
         live_subscription AS (
           SELECT
             s.id,
             s.status,
             s.starts_at,
             s.expires_at,
             CAST(s.version AS TEXT) AS version
           FROM user_subscriptions AS s, input, probe
           WHERE s.user_id = probe.user_id
             AND s.group_id = probe.group_id
             AND s.deleted_at IS NULL
             AND s.status = 'active'
             AND s.starts_at <= input.now_utc
             AND input.now_utc < s.expires_at
           ORDER BY s.id
           LIMIT 1
         )
         SELECT
           probe.*,
           live_subscription.id AS subscription_id,
           live_subscription.status AS subscription_status,
           live_subscription.starts_at AS subscription_starts_at,
           live_subscription.expires_at AS subscription_expires_at,
           live_subscription.version AS subscription_version
         FROM probe
         LEFT JOIN live_subscription ON TRUE`,
      )
      .bind(digest, now)
      .first<Row>();
    return readProjection(row);
  }

  private async loadAuthoritative(
    cacheKey: string,
    digest: string,
    requestedGroupId: string | undefined,
    expectedFingerprint: string,
  ): Promise<AuthCacheResolution> {
    let expected = expectedFingerprint;
    for (let attempt = 0; attempt < 3; attempt++) {
      let projection: Projection | null;
      try {
        projection = await this.full(digest);
      } catch {
        return { ok: false, code: "AUTH_UNAVAILABLE" };
      }

      if (!projection) {
        const absentProof = await this.probe(digest);
        const absentFingerprint = await fingerprint(absentProof);
        if (absentFingerprint !== expected) {
          expected = absentFingerprint;
          continue;
        }
        return { ok: false, code: "AUTH_NOT_FOUND" };
      }

      const loadedFingerprint = await fingerprint(projection.proof);
      if (loadedFingerprint !== expected) {
        const freshProbe = await this.probe(digest);
        expected = await fingerprint(freshProbe);
        continue;
      }

      const result = this.authorize(projection, requestedGroupId);
      this.put(
        cacheKey,
        loadedFingerprint,
        projection,
        result.ok ? this.positiveTtlMs : this.negativeTtlMs,
      );
      return result;
    }
    return { ok: false, code: "AUTH_UNAVAILABLE" };
  }

  private async cacheEntryMatches(
    entry: CacheEntry,
    probe: Probe,
    expectedFingerprint: string,
  ): Promise<boolean> {
    try {
      return projectionShape(entry.projection) &&
        entry.fingerprint === expectedFingerprint &&
        (await fingerprint(entry.projection.proof)) === expectedFingerprint &&
        canonical(entry.projection.proof) === canonical(probe);
    } catch {
      return false;
    }
  }

  private authorize(
    projection: Projection,
    requestedGroupId: string | undefined,
  ): AuthCacheResolution {
    const proof = projection.proof;
    if (proof.key_id === null || proof.user_id === null || proof.group_id === null) {
      return { ok: false, code: "AUTH_NOT_FOUND" };
    }
    if (
      proof.key_status !== "active" ||
      proof.user_status !== "active" ||
      proof.group_status !== "active" ||
      proof.key_deleted_at !== null ||
      proof.user_deleted_at !== null ||
      proof.group_deleted_at !== null ||
      (requestedGroupId !== undefined && requestedGroupId !== proof.group_id)
    ) {
      return { ok: false, code: "AUTH_NOT_FOUND" };
    }

    if (
      projection.key_expires_at !== null &&
      Date.parse(projection.key_expires_at) <= this.now()
    ) {
      return { ok: false, code: "AUTH_NOT_FOUND" };
    }

    const allowedByPublicStandard =
      projection.subscription_type === "standard" &&
      !projection.is_exclusive &&
      !projection.restrict_public_groups;
    const allowedByRestrictedStandard =
      projection.subscription_type === "standard" &&
      !projection.is_exclusive &&
      projection.allowed_group_ids.includes(proof.group_id);
    const allowedByExclusiveStandard =
      projection.subscription_type === "standard" &&
      projection.is_exclusive &&
      projection.allowed_group_ids.includes(proof.group_id);
    const allowedBySubscription =
      projection.subscription_type === "subscription" &&
      projection.live_subscription !== null &&
      projection.live_subscription.status === "active" &&
      Date.parse(projection.live_subscription.starts_at) <= this.now() &&
      this.now() < Date.parse(projection.live_subscription.expires_at);

    if (
      !allowedByPublicStandard &&
      !allowedByRestrictedStandard &&
      !allowedByExclusiveStandard &&
      !allowedBySubscription
    ) {
      return { ok: false, code: "AUTH_NOT_FOUND" };
    }

    return {
      ok: true,
      code: "OK",
      authorization: {
        api_key_id: proof.key_id,
        user_id: proof.user_id,
        group_id: proof.group_id,
        expires_at: projection.key_expires_at,
        allowed_group_ids: projection.allowed_group_ids,
        restrict_public_groups: projection.restrict_public_groups,
      },
    };
  }

  private put(
    cacheKey: string,
    fingerprintValue: string,
    projection: Projection,
    ttlMs: number,
  ): void {
    if (!projectionShape(projection) || !CACHE_KEY_RE.test(cacheKey)) return;
    this.cache.set(cacheKey, {
      cache_key: cacheKey,
      fingerprint: fingerprintValue,
      expires_at_ms: this.now() + ttlMs,
      projection,
      last: ++this.sequence,
    });
    while (this.cache.size > this.capacity) {
      const evicted = [...this.cache.values()].sort((left, right) =>
        left.last - right.last || left.cache_key.localeCompare(right.cache_key),
      )[0];
      this.cache.delete(evicted.cache_key);
    }
  }

  invalidate(): void {
    this.cache.clear();
  }

  drain(): readonly AuthCacheReplicaEntry[] {
    const entries = [...this.cache.values()].map(({ last: _last, ...entry }) => entry);
    this.cache.clear();
    return entries;
  }

  async rebuild(value: unknown): Promise<boolean> {
    let candidates: string[];
    try {
      if (!Array.isArray(value) || value.length > this.capacity) return false;
      candidates = [];
      for (let index = 0; index < value.length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !("value" in descriptor)) return false;
        const entry = readRecord(descriptor.value, [
          "cache_key",
          "fingerprint",
          "expires_at_ms",
          "projection",
        ]);
        if (
          !entry ||
          !CACHE_KEY_RE.test(String(entry.cache_key)) ||
          typeof entry.fingerprint !== "string" ||
          !DIGEST_RE.test(entry.fingerprint) ||
          typeof entry.expires_at_ms !== "number" ||
          !Number.isSafeInteger(entry.expires_at_ms) ||
          !projectionShape(entry.projection)
        ) {
          return false;
        }
        candidates.push(String(entry.cache_key));
      }
    } catch {
      return false;
    }

    this.cache.clear();
    for (const cacheKey of candidates) {
      const digest = cacheKey.slice(0, 64);
      const groupSuffix = cacheKey.slice(65);
      let probe: Probe;
      try {
        probe = await this.probe(digest);
      } catch {
        return false;
      }
      const result = await this.loadAuthoritative(
        cacheKey,
        digest,
        groupSuffix === "" ? undefined : groupSuffix,
        await fingerprint(probe),
      );
      if (result.code === "AUTH_UNAVAILABLE") return false;
    }
    return true;
  }

  async drainOutbox(
    deliver: (event: AuthCacheOutboxEvent) => Promise<void>,
    limit = 25,
  ): Promise<number> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) return 0;

    const now = utcFromMillis(this.now());
    if (now === null) return 0;
    await this.recoverExpiredFinalAttempt(now);
    const rows = await this.db
      .prepare(
        `SELECT
           event_id,
           entity_type,
           entity_id,
           credential_digest,
           old_credential_digest,
           new_credential_digest,
           revision
         FROM auth_cache_outbox
         WHERE state IN ('pending', 'claimed')
           AND (state = 'pending' OR claim_expires_at <= ?)
           AND attempts < ?
         ORDER BY created_at, event_id
         LIMIT ?`,
      )
      .bind(now, MAX_ATTEMPTS, limit)
      .all<Row>();

    let published = 0;
    for (const row of rows.results) {
      if (typeof row.event_id !== "string" || !EVENT_ID_RE.test(row.event_id)) continue;
      const claim = await this.claimOutboxEvent(row.event_id);
      if (!claim) continue;

      try {
        await deliver(claim.event);
      } catch {
        await this.releaseClaim(claim.event.event_id, claim.claim_token, claim.claim_version);
        continue;
      }

      const marked = await this.markPublished(
        claim.event.event_id,
        claim.claim_token,
        claim.claim_version,
      );
      if (marked) published += 1;
    }
    return published;
  }

  async claimOutboxEvent(
    eventId: string,
  ): Promise<AuthCacheOutboxClaim | null> {
    const nowMs = this.now();
    const now = utcFromMillis(nowMs);
    const leaseUntil = utcFromMillis(nowMs + this.claimLeaseMs);
    if (
      !EVENT_ID_RE.test(eventId) ||
      now === null ||
      leaseUntil === null ||
      leaseUntil <= now
    ) {
      return null;
    }
    const token = crypto.randomUUID().replaceAll("-", "");
    const claimed = await this.db
      .prepare(
        `UPDATE auth_cache_outbox
         SET state = 'claimed',
             claim_token = ?,
             claim_expires_at = ?,
             claim_version = CAST(claim_version + 1 AS TEXT),
             attempts = attempts + 1
         WHERE event_id = ?
           AND state IN ('pending', 'claimed')
           AND (state = 'pending' OR claim_expires_at <= ?)
           AND attempts < ?`,
      )
      .bind(token, leaseUntil, eventId, now, MAX_ATTEMPTS)
      .run();
    if (claimed.meta.changes !== 1) return null;
    return this.readClaim(eventId, token, now);
  }

  async renewOutboxClaim(
    eventId: string,
    token: string,
    claimVersion: string,
  ): Promise<AuthCacheOutboxClaim | null> {
    const nowMs = this.now();
    const now = utcFromMillis(nowMs);
    if (!EVENT_ID_RE.test(eventId) || !EVENT_ID_RE.test(token)) return null;
    if (!isDecimalInRange(claimVersion, { allowZero: false, maximum: MAX_I64_TEXT })) {
      return null;
    }
    if (now === null) return null;
    const current = await this.readClaim(eventId, token, now);
    if (!current || current.claim_version !== claimVersion) return null;
    const leaseUntil = utcFromMillis(Math.max(
      nowMs + this.claimLeaseMs,
      Date.parse(current.claim_expires_at) + this.claimLeaseMs,
    ));
    if (leaseUntil === null) return null;
    const renewed = await this.db
      .prepare(
        `UPDATE auth_cache_outbox
         SET claim_expires_at = ?,
             claim_version = CAST(claim_version + 1 AS TEXT)
         WHERE event_id = ?
           AND state = 'claimed'
           AND claim_token = ?
           AND claim_version = ?
           AND claim_expires_at > ?`,
      )
      .bind(leaseUntil, eventId, token, claimVersion, now)
      .run();
    if (renewed.meta.changes !== 1) return null;
    return this.readClaim(eventId, token, now);
  }

  async markPublished(
    eventId: string,
    token: string,
    claimVersion: string,
  ): Promise<boolean> {
    const now = utcFromMillis(this.now());
    if (
      !EVENT_ID_RE.test(eventId) ||
      !EVENT_ID_RE.test(token) ||
      !isDecimalInRange(claimVersion, { allowZero: false, maximum: MAX_I64_TEXT }) ||
      now === null
    ) {
      return false;
    }
    const marked = await this.db
      .prepare(
        `UPDATE auth_cache_outbox
         SET state = 'published',
             claim_token = NULL,
             claim_expires_at = NULL,
             claim_version = CAST(claim_version + 1 AS TEXT),
             published_at = ?
         WHERE event_id = ?
           AND state = 'claimed'
           AND claim_token = ?
           AND claim_version = ?
           AND claim_expires_at > ?`,
      )
      .bind(now, eventId, token, claimVersion, now)
      .run();
    return marked.meta.changes === 1;
  }

  async releaseClaim(eventId: string, token: string, claimVersion: string): Promise<boolean> {
    const now = utcFromMillis(this.now());
    if (!EVENT_ID_RE.test(eventId) || !EVENT_ID_RE.test(token)) return false;
    if (!isDecimalInRange(claimVersion, { allowZero: false, maximum: MAX_I64_TEXT })) {
      return false;
    }
    if (now === null) return false;
    const released = await this.db
      .prepare(
        `UPDATE auth_cache_outbox
         SET state = CASE WHEN attempts >= ? THEN 'dead' ELSE 'pending' END,
             claim_token = NULL,
             claim_expires_at = NULL,
             claim_version = CAST(claim_version + 1 AS TEXT)
         WHERE event_id = ?
           AND state = 'claimed'
           AND claim_token = ?
           AND claim_version = ?
           AND claim_expires_at > ?`,
      )
      .bind(MAX_ATTEMPTS, eventId, token, claimVersion, now)
      .run();
    return released.meta.changes === 1;
  }

  private async recoverExpiredFinalAttempt(now: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE auth_cache_outbox
         SET state = 'dead',
             claim_token = NULL,
             claim_expires_at = NULL,
             claim_version = CAST(claim_version + 1 AS TEXT)
         WHERE state = 'claimed'
           AND attempts >= ?
           AND claim_expires_at <= ?`,
      )
      .bind(MAX_ATTEMPTS, now)
      .run();
  }

  async readClaim(
    eventId: string,
    token: string,
    now: string,
  ): Promise<AuthCacheOutboxClaim | null> {
    if (!EVENT_ID_RE.test(eventId) || !EVENT_ID_RE.test(token)) return null;
    const row = await this.db
      .prepare(
        `SELECT
           event_id,
           entity_type,
           entity_id,
           credential_digest,
           old_credential_digest,
           new_credential_digest,
           revision,
           state,
           claim_token,
           claim_version,
           claim_expires_at
         FROM auth_cache_outbox
         WHERE event_id = ?
           AND state = 'claimed'
           AND claim_token = ?
           AND claim_expires_at > ?`,
      )
      .bind(eventId, token, now)
      .first<Row>();
    return claimShape(row);
  }
}

export const AUTH_CACHE_MAX_I64_TEXT = MAX_I64_TEXT;
export const AUTH_CACHE_MAX_REVISION_TEXT = MAX_I64_MINUS_ONE_TEXT;
