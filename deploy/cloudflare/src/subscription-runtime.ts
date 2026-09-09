import { canonical, sha256 } from "./contracts";

const MAX_E8 = 9_223_372_036_854_775_807n;
const MAX_VERSION = 2_147_483_647;
const DAY_MS = 86_400_000;
const WEEK_MS = 7 * DAY_MS;
const MONTH_MS = 30 * DAY_MS;
const MAX_DATE_MS = Date.parse("2099-12-31T23:59:59.000Z");
const OPERATION_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const ID_RE = /^(?:[1-9][0-9]{0,18})$/;
const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\ufeff]/u;

export type SubscriptionStatus = "active" | "expired" | "suspended";
export type E8USD = string;

export type SubscriptionPlan = {
  id: string;
  group_id: string;
  name: string;
  description: string;
  price_e8_usd: E8USD;
  original_price_e8_usd: E8USD | null;
  daily_limit_e8_usd: E8USD | null;
  weekly_limit_e8_usd: E8USD | null;
  monthly_limit_e8_usd: E8USD | null;
  currency: string;
  validity_days: number;
  validity_unit: "day";
  features: string;
  product_name: string;
  for_sale: number;
  sort_order: number;
  version: number;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
};

export type UserSubscription = {
  id: string;
  user_id: string;
  group_id: string;
  plan_id: string | null;
  starts_at: string;
  expires_at: string;
  status: SubscriptionStatus;
  initial_daily_boundary: string | null;
  daily_window_start: string | null;
  weekly_window_start: string | null;
  monthly_window_start: string | null;
  weekly_anchor_kind: "activation" | "manual" | "legacy_initial" | null;
  monthly_anchor_kind: "activation" | "manual" | "legacy_initial" | null;
  daily_limit_e8_usd: E8USD | null;
  weekly_limit_e8_usd: E8USD | null;
  monthly_limit_e8_usd: E8USD | null;
  daily_usage_e8_usd: E8USD;
  weekly_usage_e8_usd: E8USD;
  monthly_usage_e8_usd: E8USD;
  assigned_by: string | null;
  assigned_at: string;
  notes: string;
  version: number;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
};

export type SubscriptionList = {
  items: UserSubscription[];
  next_after_id: string | null;
};

type OperationKind =
  | "create_plan"
  | "assign_or_extend"
  | "revoke"
  | "restore"
  | "extend"
  | "activate_windows"
  | "maintain_windows"
  | "reset_windows"
  | "reserve_usage"
  | "expiry_sweep";

type OperationRow = {
  operation_kind: OperationKind;
  request_hash: string;
  result_json: string;
};

type GroupRow = { id: string; subscription_type: string; deleted_at: string | null };
type PlanLimits = {
  id: string;
  group_id: string;
  daily_limit_e8_usd: string | null;
  weekly_limit_e8_usd: string | null;
  monthly_limit_e8_usd: string | null;
  deleted_at: string | null;
};

export class SubscriptionRuntimeError extends Error {
  constructor(readonly code: string, message = code) {
    super(message);
    this.name = "SubscriptionRuntimeError";
  }
}

function fail(code: string, message = code): never {
  throw new SubscriptionRuntimeError(code, message);
}

function plainObject(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  return value as Record<string, unknown>;
}

function exactObject(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Record<string, unknown> {
  try {
    const input = plainObject(value);
    if (!input) fail("INVALID_INPUT");
    const keys = Object.keys(input);
    const allowed = new Set([...required, ...optional]);
    if (keys.some((key) => !allowed.has(key))) fail("UNKNOWN_FIELD");
    if (required.some((key) => !Object.prototype.hasOwnProperty.call(input, key))) {
      fail("MISSING_FIELD");
    }
    const snapshot: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of keys) snapshot[key] = input[key];
    return snapshot;
  } catch (error) {
    if (error instanceof SubscriptionRuntimeError) throw error;
    fail("INVALID_INPUT");
  }
}

function operationID(value: unknown): string {
  if (typeof value !== "string" || !OPERATION_RE.test(value)) fail("INVALID_OPERATION_ID");
  return value;
}

function int64ID(value: unknown, nullable = false): string | null {
  if (nullable && value === null) return null;
  if (typeof value !== "string" || !ID_RE.test(value) || BigInt(value) > MAX_E8) {
    fail("INVALID_ID");
  }
  return value;
}

function e8(value: unknown, nullable = false): string | null {
  if (nullable && value === null) return null;
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    fail("INVALID_MONEY");
  }
  const parsed = BigInt(value);
  if (parsed > MAX_E8) fail("MONEY_OVERFLOW");
  return value;
}

function utcInstant(value: unknown): string {
  if (typeof value !== "string" || !RFC3339_UTC_RE.test(value)) fail("INVALID_TIMESTAMP");
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || milliseconds > MAX_DATE_MS) fail("INVALID_TIMESTAMP");
  const normalizedInput = value.includes(".")
    ? value.replace(/\.(\d{1,3})Z$/, (_, fraction: string) => `.${fraction.padEnd(3, "0")}Z`)
    : value.replace(/Z$/, ".000Z");
  const normalized = new Date(milliseconds).toISOString();
  if (normalized !== normalizedInput) fail("INVALID_TIMESTAMP");
  return normalized;
}

function safeText(value: unknown, maximumBytes: number, allowEmpty = true): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) fail("INVALID_TEXT");
  if (CONTROL_RE.test(value) || new TextEncoder().encode(value).byteLength > maximumBytes) {
    fail("INVALID_TEXT");
  }
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail("INVALID_TEXT");
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      fail("INVALID_TEXT");
    }
  }
  return value;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail("INVALID_INTEGER");
  }
  return value as number;
}

function booleanValue(value: unknown): boolean {
   if (typeof value !== "boolean") fail("INVALID_BOOLEAN");
  return value;
}

function statusValue(value: unknown, nullable = false): SubscriptionStatus | null {
  if (nullable && value === null) return null;
  if (value !== "active" && value !== "expired" && value !== "suspended") {
    fail("INVALID_STATUS");
  }
  return value;
}

function addDays(instant: string, days: number): string {
  const milliseconds = Date.parse(instant) + days * DAY_MS;
  if (!Number.isSafeInteger(milliseconds) || milliseconds > MAX_DATE_MS) {
    return new Date(MAX_DATE_MS).toISOString();
  }
  return new Date(milliseconds).toISOString();
}

function appendNotes(existing: string, incoming: string): string {
  if (incoming === "") return existing;
  return existing === "" ? incoming : `${existing}\n${incoming}`;
}

function nextVersion(version: number): number {
  if (!Number.isSafeInteger(version) || version < 1 || version >= MAX_VERSION) {
    fail("VERSION_OVERFLOW");
  }
  return version + 1;
}

function assertBoundary(boundary: string, now: string): void {
  if (Date.parse(boundary) > Date.parse(now)) fail("BOUNDARY_IN_FUTURE");
}

function advancedAnchor(
  previous: string,
  anchorKind: UserSubscription["weekly_anchor_kind"],
  initialBoundary: string | null,
  startsAt: string,
  expiresAt: string,
  now: string,
  periodMs: number,
): { value: string; kind: "activation" | "manual"; reset: boolean } {
  let anchor = previous;
  let kind = anchorKind;
  if (kind === "legacy_initial") {
    if (initialBoundary === null || previous !== initialBoundary || !(initialBoundary < startsAt)) {
      fail("CORRUPT_LEGACY_ANCHOR");
    }
    anchor = startsAt;
    kind = "activation";
  }
  if (kind !== "activation" && kind !== "manual") fail("CORRUPT_WINDOW_STATE");
  if (Date.parse(now) >= Date.parse(expiresAt)) return { value: anchor, kind, reset: false };
  const anchorMs = Date.parse(anchor);
  const expiryMs = Date.parse(expiresAt);
  const elapsed = Date.parse(now) - anchorMs;
  if (elapsed < periodMs || anchorMs + periodMs >= expiryMs) {
    return { value: anchor, kind, reset: false };
  }
  const periods = Math.floor(elapsed / periodMs);
  const lastFull = Math.floor((expiryMs - anchorMs - 1) / periodMs);
  const value = new Date(anchorMs + Math.min(periods, lastFull) * periodMs).toISOString();
  return { value, kind, reset: value !== previous };
}

function planResult(row: SubscriptionPlan): { plan: SubscriptionPlan } {
  return { plan: row };
}

function subscriptionResult(
  row: UserSubscription,
  extended?: boolean,
): { subscription: UserSubscription; extended?: boolean } {
  return extended === undefined ? { subscription: row } : { subscription: row, extended };
}

export class SubscriptionRuntime {
  constructor(private readonly db: D1Database) {}

  private async operationHash(kind: OperationKind, input: Record<string, unknown>): Promise<string> {
    return sha256(canonical({ operation_kind: kind, ...input }));
  }

  private async replay<T>(operationId: string, kind: OperationKind, hash: string): Promise<T | null> {
    const prior = await this.db.prepare(
      "SELECT operation_kind,request_hash,result_json FROM subscription_operations WHERE operation_id=?",
    ).bind(operationId).first<OperationRow>();
    if (!prior) return null;
    if (prior.operation_kind !== kind || prior.request_hash !== hash) fail("IDEMPOTENCY_CONFLICT");
    try {
      return JSON.parse(prior.result_json) as T;
    } catch {
      fail("CORRUPT_OPERATION_RESULT");
    }
  }

  private operationStatement(
    operationId: string,
    kind: OperationKind,
    hash: string,
    result: unknown,
    at: string,
    metadata: { entityId?: string; actorId?: string | null; userId?: string; groupId?: string; version?: number } = {},
  ): D1PreparedStatement {
    return this.db.prepare(`INSERT INTO subscription_operations(
      operation_id,operation_kind,request_hash,result_json,entity_id,actor_user_id,
      user_id,group_id,entity_version,created_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(
      operationId,
      kind,
      hash,
      JSON.stringify(result),
      metadata.entityId ?? null,
      metadata.actorId ?? null,
      metadata.userId ?? null,
      metadata.groupId ?? null,
      metadata.version ?? null,
      at,
    );
  }

  private async guardID(operationId: string, ordinal = 0): Promise<string> {
    return sha256(`${operationId}:${ordinal}`);
  }

  private guardInsert(guardId: string, at: string, conditional: boolean): D1PreparedStatement {
    return conditional
      ? this.db.prepare(
        "INSERT INTO subscription_runtime_guards(guard_id,created_at) SELECT ?,? WHERE changes()=1",
      ).bind(guardId, at)
      : this.db.prepare(
        "INSERT INTO subscription_runtime_guards(guard_id,created_at) VALUES(?,?)",
      ).bind(guardId, at);
  }

  private effectInsert(
    operationId: string,
    ordinal: number,
    guardId: string,
    entityKind: "plan" | "subscription",
    entityId: string,
    beforeVersion: number | null,
    afterVersion: number,
  ): D1PreparedStatement {
    return this.db.prepare(`INSERT INTO subscription_operation_effects(
      operation_id,ordinal,guard_id,entity_kind,entity_id,before_version,after_version
    ) VALUES(?,?,?,?,?,?,?)`).bind(
      operationId, ordinal, guardId, entityKind, entityId, beforeVersion, afterVersion,
    );
  }

  private async currentSubscription(id: string, includeDeleted = false): Promise<UserSubscription | null> {
    return this.db.prepare(
      `SELECT * FROM user_subscriptions WHERE id=?${includeDeleted ? "" : " AND deleted_at IS NULL"}`,
    ).bind(id).first<UserSubscription>();
  }

  private async livePair(userId: string, groupId: string): Promise<UserSubscription | null> {
    return this.db.prepare(
      "SELECT * FROM user_subscriptions WHERE user_id=? AND group_id=? AND deleted_at IS NULL",
    ).bind(userId, groupId).first<UserSubscription>();
  }

  private async ensureLiveUser(id: string): Promise<void> {
    const found = await this.db.prepare(
      "SELECT id FROM users WHERE id=? AND deleted_at IS NULL",
    ).bind(id).first("id");
    if (found === null) fail("USER_NOT_FOUND");
  }

  private async ensureLiveAdmin(id: string): Promise<void> {
    const found = await this.db.prepare(
      "SELECT id FROM users WHERE id=? AND deleted_at IS NULL AND role='admin'",
    ).bind(id).first("id");
    if (found === null) fail("ADMIN_NOT_FOUND");
  }

  private async ensureReplayAfterFailure<T>(
    operationId: string,
    kind: OperationKind,
    hash: string,
   ): Promise<T | null> {
    return this.replay<T>(operationId, kind, hash);
  }

  async createPlan(raw: unknown): Promise<{ plan: SubscriptionPlan }> {
    const input = exactObject(raw, [
      "operation_id", "id", "group_id", "name", "description", "price_e8_usd",
      "original_price_e8_usd", "daily_limit_e8_usd", "weekly_limit_e8_usd",
      "monthly_limit_e8_usd", "currency", "validity_days", "validity_unit",
      "features", "product_name", "for_sale", "sort_order", "actor_user_id", "at",
    ]);
    const parsed = {
      operation_id: operationID(input.operation_id),
      id: int64ID(input.id)!,
      group_id: int64ID(input.group_id)!,
      name: safeText(input.name, 100, false),
      description: safeText(input.description, 4096),
      price_e8_usd: e8(input.price_e8_usd)!,
      original_price_e8_usd: e8(input.original_price_e8_usd, true),
      daily_limit_e8_usd: e8(input.daily_limit_e8_usd, true),
      weekly_limit_e8_usd: e8(input.weekly_limit_e8_usd, true),
      monthly_limit_e8_usd: e8(input.monthly_limit_e8_usd, true),
      currency: typeof input.currency === "string" && /^[A-Z]{3}$/.test(input.currency)
        ? input.currency : fail("INVALID_CURRENCY"),
      validity_days: boundedInteger(input.validity_days, 1, 36500),
      validity_unit: input.validity_unit === "day" ? "day" as const : fail("INVALID_VALIDITY_UNIT"),
      features: safeText(input.features, 8192),
      product_name: safeText(input.product_name, 100),
      for_sale: booleanValue(input.for_sale),
      sort_order: boundedInteger(input.sort_order, -1_000_000, 1_000_000),
      actor_user_id: int64ID(input.actor_user_id)!,
      at: utcInstant(input.at),
    };
    const hash = await this.operationHash("create_plan", parsed);
    const replay = await this.replay<{ plan: SubscriptionPlan }>(parsed.operation_id, "create_plan", hash);
    if (replay) return replay;
    await this.ensureLiveAdmin(parsed.actor_user_id);
    const plan: SubscriptionPlan = {
      id: parsed.id, group_id: parsed.group_id, name: parsed.name,
      description: parsed.description, price_e8_usd: parsed.price_e8_usd,
      original_price_e8_usd: parsed.original_price_e8_usd,
      daily_limit_e8_usd: parsed.daily_limit_e8_usd,
      weekly_limit_e8_usd: parsed.weekly_limit_e8_usd,
      monthly_limit_e8_usd: parsed.monthly_limit_e8_usd,
      currency: parsed.currency, validity_days: parsed.validity_days,
      validity_unit: parsed.validity_unit, features: parsed.features,
      product_name: parsed.product_name, for_sale: parsed.for_sale ? 1 : 0,
      sort_order: parsed.sort_order, version: 1, created_at: parsed.at,
      updated_at: parsed.at, deleted_at: null,
    };
    const result = planResult(plan);
    const guard = await this.guardID(parsed.operation_id);
    try {
      await this.db.batch([
        this.operationStatement(parsed.operation_id, "create_plan", hash, result, parsed.at, {
          entityId: plan.id, actorId: parsed.actor_user_id, groupId: plan.group_id, version: 1,
        }),
        this.guardInsert(guard, parsed.at, false),
        this.db.prepare(`INSERT INTO subscription_plans(
          id,group_id,name,description,price_e8_usd,original_price_e8_usd,
          daily_limit_e8_usd,weekly_limit_e8_usd,monthly_limit_e8_usd,currency,
          validity_days,validity_unit,features,product_name,for_sale,sort_order,
          version,created_at,updated_at,deleted_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`).bind(
          plan.id, plan.group_id, plan.name, plan.description, plan.price_e8_usd,
          plan.original_price_e8_usd, plan.daily_limit_e8_usd, plan.weekly_limit_e8_usd,
          plan.monthly_limit_e8_usd, plan.currency, plan.validity_days, plan.validity_unit,
          plan.features, plan.product_name, plan.for_sale, plan.sort_order, 1, plan.created_at,
          plan.updated_at,
        ),
        this.effectInsert(parsed.operation_id, 0, guard, "plan", plan.id, null, 1),
      ]);
      return result;
    } catch {
      const committed = await this.ensureReplayAfterFailure<typeof result>(parsed.operation_id, "create_plan", hash);
      if (committed) return committed;
      fail("CREATE_PLAN_CONFLICT");
    }
  }

  async getPlan(raw: unknown): Promise<{ plan: SubscriptionPlan }> {
    const input = exactObject(raw, ["id", "include_deleted"]);
    const id = int64ID(input.id)!;
    const includeDeleted = booleanValue(input.include_deleted);
    const row = await this.db.prepare(
      `SELECT * FROM subscription_plans WHERE id=?${includeDeleted ? "" : " AND deleted_at IS NULL"}`,
    ).bind(id).first<SubscriptionPlan>();
    if (!row) fail("PLAN_NOT_FOUND");
    return planResult(row);
  }

  async listPlans(raw: unknown): Promise<{ items: SubscriptionPlan[]; next_after_id: string | null }> {
    const input = exactObject(raw, ["group_id", "for_sale", "include_deleted", "after_id", "limit"]);
    const groupId = int64ID(input.group_id, true);
    const forSale = input.for_sale === null ? null : booleanValue(input.for_sale);
    const includeDeleted = booleanValue(input.include_deleted);
    const afterId = int64ID(input.after_id, true);
    const limit = boundedInteger(input.limit, 1, 100);
    const clauses: string[] = [];
    const values: Array<string | number> = [];
    if (groupId) { clauses.push("group_id=?"); values.push(groupId); }
    if (forSale !== null) { clauses.push("for_sale=?"); values.push(forSale ? 1 : 0); }
    if (!includeDeleted) clauses.push("deleted_at IS NULL");
    if (afterId) {
      clauses.push("(length(id)>length(?) OR (length(id)=length(?) AND id>?))");
      values.push(afterId, afterId, afterId);
    }
    values.push(limit + 1);
    const query = `SELECT * FROM subscription_plans${clauses.length ? ` WHERE ${clauses.join(" AND ")}` : ""}
      ORDER BY length(id),id LIMIT ?`;
    const rows = (await this.db.prepare(query).bind(...values).all<SubscriptionPlan>()).results;
    return { items: rows.slice(0, limit), next_after_id: rows.length > limit ? rows[limit - 1].id : null };
  }

  async assignOrExtend(raw: unknown): Promise<{ subscription: UserSubscription; extended: boolean }> {
    const input = exactObject(raw, [
      "operation_id", "new_subscription_id", "user_id", "group_id", "plan_id",
      "validity_days", "assigned_by", "notes", "now", "daily_boundary",
    ]);
    const parsed = {
      operation_id: operationID(input.operation_id),
      new_subscription_id: int64ID(input.new_subscription_id)!,
      user_id: int64ID(input.user_id)!, group_id: int64ID(input.group_id)!,
      plan_id: int64ID(input.plan_id, true),
      validity_days: boundedInteger(input.validity_days, 1, 36500),
      assigned_by: int64ID(input.assigned_by, true),
      notes: safeText(input.notes, 4096), now: utcInstant(input.now),
      daily_boundary: utcInstant(input.daily_boundary),
    };
    assertBoundary(parsed.daily_boundary, parsed.now);
    const hash = await this.operationHash("assign_or_extend", parsed);
    const prior = await this.replay<{ subscription: UserSubscription; extended: boolean }>(
      parsed.operation_id, "assign_or_extend", hash,
    );
    if (prior) return prior;

    const group = await this.db.prepare(
      "SELECT id,subscription_type,deleted_at FROM groups WHERE id=?",
    ).bind(parsed.group_id).first<GroupRow>();
    if (!group || group.deleted_at !== null) fail("GROUP_NOT_FOUND");
    if (group.subscription_type !== "subscription") fail("GROUP_NOT_SUBSCRIPTION_TYPE");
    await this.ensureLiveUser(parsed.user_id);
    if (parsed.assigned_by !== null) await this.ensureLiveAdmin(parsed.assigned_by);
    let plan: PlanLimits | null = null;
    if (parsed.plan_id !== null) {
      plan = await this.db.prepare(`SELECT id,group_id,daily_limit_e8_usd,weekly_limit_e8_usd,
        monthly_limit_e8_usd,deleted_at FROM subscription_plans WHERE id=?`).bind(parsed.plan_id).first<PlanLimits>();
      if (!plan || plan.deleted_at !== null || plan.group_id !== parsed.group_id) fail("PLAN_NOT_FOUND");
    }

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const existing = await this.livePair(parsed.user_id, parsed.group_id);
      if (!existing) {
        const subscription: UserSubscription = {
          id: parsed.new_subscription_id, user_id: parsed.user_id, group_id: parsed.group_id,
          plan_id: parsed.plan_id, starts_at: parsed.now,
          expires_at: addDays(parsed.now, parsed.validity_days), status: "active",
          initial_daily_boundary: null, daily_window_start: null, weekly_window_start: null,
          monthly_window_start: null, weekly_anchor_kind: null, monthly_anchor_kind: null,
          daily_limit_e8_usd: plan?.daily_limit_e8_usd ?? null,
          weekly_limit_e8_usd: plan?.weekly_limit_e8_usd ?? null,
          monthly_limit_e8_usd: plan?.monthly_limit_e8_usd ?? null,
          daily_usage_e8_usd: "0", weekly_usage_e8_usd: "0", monthly_usage_e8_usd: "0",
          assigned_by: parsed.assigned_by, assigned_at: parsed.now, notes: parsed.notes,
          version: 1, created_at: parsed.now, updated_at: parsed.now, deleted_at: null,
        };
        const result = subscriptionResult(subscription, false) as { subscription: UserSubscription; extended: boolean };
        const guard = await this.guardID(parsed.operation_id);
        try {
          await this.db.batch([
            this.operationStatement(parsed.operation_id, "assign_or_extend", hash, result, parsed.now, {
              entityId: subscription.id, actorId: parsed.assigned_by, userId: parsed.user_id,
              groupId: parsed.group_id, version: 1,
            }),
            this.guardInsert(guard, parsed.now, false),
            this.db.prepare(`INSERT INTO user_subscriptions(
              id,user_id,group_id,plan_id,starts_at,expires_at,status,initial_daily_boundary,
              daily_window_start,weekly_window_start,monthly_window_start,weekly_anchor_kind,
              monthly_anchor_kind,daily_limit_e8_usd,weekly_limit_e8_usd,monthly_limit_e8_usd,
              daily_usage_e8_usd,weekly_usage_e8_usd,monthly_usage_e8_usd,assigned_by,
              assigned_at,notes,version,created_at,updated_at,deleted_at
            ) VALUES(?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL,?,?,?,?,?,?,?,?,?,?,?, ?,NULL)`).bind(
              subscription.id, subscription.user_id, subscription.group_id, subscription.plan_id,
              subscription.starts_at, subscription.expires_at, subscription.status,
              subscription.daily_limit_e8_usd, subscription.weekly_limit_e8_usd,
              subscription.monthly_limit_e8_usd, "0", "0", "0", subscription.assigned_by,
              subscription.assigned_at, subscription.notes, 1, subscription.created_at,
              subscription.updated_at,
            ),
            this.effectInsert(parsed.operation_id, 0, guard, "subscription", subscription.id, null, 1),
          ]);
          return result;
        } catch {
          const replay = await this.ensureReplayAfterFailure<typeof result>(parsed.operation_id, "assign_or_extend", hash);
          if (replay) return replay;
          continue;
        }
      }

      const version = nextVersion(existing.version);
      const expired = Date.parse(existing.expires_at) <= Date.parse(parsed.now);
      const expiresAt = addDays(expired ? parsed.now : existing.expires_at, parsed.validity_days);
      const subscription: UserSubscription = {
        ...existing,
        plan_id: parsed.plan_id ?? existing.plan_id,
        starts_at: expired ? parsed.now : existing.starts_at,
        expires_at: expiresAt,
        status: "active",
        initial_daily_boundary: expired ? parsed.daily_boundary : existing.initial_daily_boundary,
        daily_window_start: expired ? parsed.daily_boundary : existing.daily_window_start,
        weekly_window_start: expired ? parsed.now : existing.weekly_window_start,
        monthly_window_start: expired ? parsed.now : existing.monthly_window_start,
        weekly_anchor_kind: expired ? "activation" : existing.weekly_anchor_kind,
        monthly_anchor_kind: expired ? "activation" : existing.monthly_anchor_kind,
        daily_limit_e8_usd: plan?.daily_limit_e8_usd ?? existing.daily_limit_e8_usd,
        weekly_limit_e8_usd: plan?.weekly_limit_e8_usd ?? existing.weekly_limit_e8_usd,
        monthly_limit_e8_usd: plan?.monthly_limit_e8_usd ?? existing.monthly_limit_e8_usd,
        daily_usage_e8_usd: expired ? "0" : existing.daily_usage_e8_usd,
        weekly_usage_e8_usd: expired ? "0" : existing.weekly_usage_e8_usd,
        monthly_usage_e8_usd: expired ? "0" : existing.monthly_usage_e8_usd,
        notes: appendNotes(existing.notes, parsed.notes), version, updated_at: parsed.now,
      };
      const result = subscriptionResult(subscription, true) as { subscription: UserSubscription; extended: boolean };
      const guard = await this.guardID(parsed.operation_id);
      try {
        await this.db.batch([
          this.operationStatement(parsed.operation_id, "assign_or_extend", hash, result, parsed.now, {
            entityId: existing.id, actorId: parsed.assigned_by, userId: existing.user_id,
            groupId: existing.group_id, version,
          }),
          this.db.prepare(`UPDATE user_subscriptions SET
            plan_id=?,starts_at=?,expires_at=?,status=?,initial_daily_boundary=?,daily_window_start=?,
            weekly_window_start=?,monthly_window_start=?,weekly_anchor_kind=?,monthly_anchor_kind=?,
            daily_limit_e8_usd=?,weekly_limit_e8_usd=?,monthly_limit_e8_usd=?,daily_usage_e8_usd=?,
            weekly_usage_e8_usd=?,monthly_usage_e8_usd=?,notes=?,version=?,updated_at=?
            WHERE id=? AND deleted_at IS NULL AND version=?`).bind(
              subscription.plan_id, subscription.starts_at, subscription.expires_at, subscription.status,
              subscription.initial_daily_boundary, subscription.daily_window_start,
              subscription.weekly_window_start, subscription.monthly_window_start,
              subscription.weekly_anchor_kind, subscription.monthly_anchor_kind,
              subscription.daily_limit_e8_usd, subscription.weekly_limit_e8_usd,
              subscription.monthly_limit_e8_usd, subscription.daily_usage_e8_usd,
              subscription.weekly_usage_e8_usd, subscription.monthly_usage_e8_usd,
              subscription.notes, version, parsed.now, existing.id, existing.version,
            ),
          this.guardInsert(guard, parsed.now, true),
          this.effectInsert(parsed.operation_id, 0, guard, "subscription", existing.id, existing.version, version),
        ]);
        return result;
      } catch {
        const replay = await this.ensureReplayAfterFailure<typeof result>(parsed.operation_id, "assign_or_extend", hash);
        if (replay) return replay;
      }
    }
    fail("ASSIGN_CONFLICT");
  }

  async getSubscription(raw: unknown): Promise<{ subscription: UserSubscription }> {
    const input = exactObject(raw, ["id", "include_deleted"]);
    const row = await this.currentSubscription(int64ID(input.id)!, booleanValue(input.include_deleted));
    if (!row) fail("SUBSCRIPTION_NOT_FOUND");
    return subscriptionResult(row);
  }

  async listSubscriptions(raw: unknown): Promise<SubscriptionList> {
    const input = exactObject(raw, [
      "user_id", "group_id", "status", "include_deleted", "after_id", "limit",
    ]);
    const userId = int64ID(input.user_id, true);
    const groupId = int64ID(input.group_id, true);
    const status = statusValue(input.status, true);
    const includeDeleted = booleanValue(input.include_deleted);
    const afterId = int64ID(input.after_id, true);
    const limit = boundedInteger(input.limit, 1, 100);
    const clauses: string[] = [];
    const values: Array<string | number> = [];
    if (userId) { clauses.push("user_id=?"); values.push(userId); }
    if (groupId) { clauses.push("group_id=?"); values.push(groupId); }
    if (status) { clauses.push("status=?"); values.push(status); }
    if (!includeDeleted) clauses.push("deleted_at IS NULL");
    if (afterId) {
      clauses.push("(length(id)>length(?) OR (length(id)=length(?) AND id>?))");
      values.push(afterId, afterId, afterId);
    }
    values.push(limit + 1);
    const rows = (await this.db.prepare(
      `SELECT * FROM user_subscriptions${clauses.length ? ` WHERE ${clauses.join(" AND ")}` : ""}
       ORDER BY length(id),id LIMIT ?`,
    ).bind(...values).all<UserSubscription>()).results;
    return { items: rows.slice(0, limit), next_after_id: rows.length > limit ? rows[limit - 1].id : null };
  }

  private async singleSubscriptionMutation(
    kind: Exclude<OperationKind, "create_plan" | "assign_or_extend" | "expiry_sweep">,
    operationId: string,
    hash: string,
    at: string,
    before: UserSubscription,
    after: UserSubscription,
    statement: D1PreparedStatement,
    actorId: string | null = null,
  ): Promise<{ subscription: UserSubscription }> {
    const result = subscriptionResult(after);
    const replay = await this.replay<typeof result>(operationId, kind, hash);
    if (replay) return replay;
    const guard = await this.guardID(operationId);
    try {
      await this.db.batch([
        this.operationStatement(operationId, kind, hash, result, at, {
          entityId: after.id, actorId, userId: after.user_id, groupId: after.group_id,
          version: after.version,
        }),
        statement,
        this.guardInsert(guard, at, true),
        this.effectInsert(operationId, 0, guard, "subscription", after.id, before.version, after.version),
      ]);
      return result;
    } catch {
      const committed = await this.ensureReplayAfterFailure<typeof result>(operationId, kind, hash);
      if (committed) return committed;
      fail("STALE_VERSION");
    }
  }

  async revoke(raw: unknown): Promise<{ subscription: UserSubscription }> {
    const input = exactObject(raw, ["operation_id", "subscription_id", "expected_version", "actor_user_id", "at"]);
    const parsed = { operation_id: operationID(input.operation_id), subscription_id: int64ID(input.subscription_id)!,
      expected_version: boundedInteger(input.expected_version, 1, MAX_VERSION), actor_user_id: int64ID(input.actor_user_id)!, at: utcInstant(input.at) };
    const hash = await this.operationHash("revoke", parsed);
    const prior = await this.replay<{ subscription: UserSubscription }>(parsed.operation_id, "revoke", hash);
    if (prior) return prior;
    const before = await this.currentSubscription(parsed.subscription_id);
    if (!before) fail("SUBSCRIPTION_NOT_FOUND");
    await this.ensureLiveAdmin(parsed.actor_user_id);
    if (before.version !== parsed.expected_version) fail("STALE_VERSION");
    const after = { ...before, deleted_at: parsed.at, updated_at: parsed.at, version: nextVersion(before.version) };
    return this.singleSubscriptionMutation("revoke", parsed.operation_id, hash, parsed.at, before, after,
      this.db.prepare("UPDATE user_subscriptions SET deleted_at=?,updated_at=?,version=? WHERE id=? AND deleted_at IS NULL AND version=?")
        .bind(parsed.at, parsed.at, after.version, before.id, before.version), parsed.actor_user_id);
  }

  async restore(raw: unknown): Promise<{ subscription: UserSubscription }> {
    const input = exactObject(raw, ["operation_id", "subscription_id", "expected_version", "actor_user_id", "now"]);
    const parsed = { operation_id: operationID(input.operation_id), subscription_id: int64ID(input.subscription_id)!,
      expected_version: boundedInteger(input.expected_version, 1, MAX_VERSION), actor_user_id: int64ID(input.actor_user_id)!, now: utcInstant(input.now) };
    const hash = await this.operationHash("restore", parsed);
    const prior = await this.replay<{ subscription: UserSubscription }>(parsed.operation_id, "restore", hash);
    if (prior) return prior;
    const before = await this.currentSubscription(parsed.subscription_id, true);
    if (!before) fail("SUBSCRIPTION_NOT_FOUND");
    await this.ensureLiveAdmin(parsed.actor_user_id);
    if (before.deleted_at === null) fail("SUBSCRIPTION_NOT_REVOKED");
    if (before.version !== parsed.expected_version) fail("STALE_VERSION");
    const replacement = await this.livePair(before.user_id, before.group_id);
    if (replacement && replacement.id !== before.id) fail("RESTORE_CONFLICT");
    const status: SubscriptionStatus = before.status === "active" && before.expires_at <= parsed.now ? "expired" : before.status;
    const after = { ...before, deleted_at: null, status, updated_at: parsed.now, version: nextVersion(before.version) };
    return this.singleSubscriptionMutation("restore", parsed.operation_id, hash, parsed.now, before, after,
      this.db.prepare(`UPDATE user_subscriptions SET deleted_at=NULL,status=?,updated_at=?,version=?
        WHERE id=? AND deleted_at IS NOT NULL AND version=?`).bind(status, parsed.now, after.version, before.id, before.version),
      parsed.actor_user_id);
  }

  async extend(raw: unknown): Promise<{ subscription: UserSubscription }> {
    const input = exactObject(raw, ["operation_id", "subscription_id", "expected_version", "days", "actor_user_id", "now"]);
    const parsed = { operation_id: operationID(input.operation_id), subscription_id: int64ID(input.subscription_id)!,
      expected_version: boundedInteger(input.expected_version, 1, MAX_VERSION), days: boundedInteger(input.days, -36500, 36500),
      actor_user_id: int64ID(input.actor_user_id)!, now: utcInstant(input.now) };
    const hash = await this.operationHash("extend", parsed);
    const prior = await this.replay<{ subscription: UserSubscription }>(parsed.operation_id, "extend", hash);
    if (prior) return prior;
    const before = await this.currentSubscription(parsed.subscription_id);
    if (!before) fail("SUBSCRIPTION_NOT_FOUND");
    await this.ensureLiveAdmin(parsed.actor_user_id);
    if (before.version !== parsed.expected_version) fail("STALE_VERSION");
    const expired = before.expires_at <= parsed.now;
    if (expired && parsed.days < 0) fail("CANNOT_SHORTEN_EXPIRED");
    const expiresAt = addDays(expired ? parsed.now : before.expires_at, parsed.days);
    if (expiresAt <= parsed.now) fail("ADJUST_WOULD_EXPIRE");
    const status: SubscriptionStatus = before.status === "expired" ? "active" : before.status;
    const after = { ...before, expires_at: expiresAt, status, updated_at: parsed.now, version: nextVersion(before.version) };
    return this.singleSubscriptionMutation("extend", parsed.operation_id, hash, parsed.now, before, after,
      this.db.prepare(`UPDATE user_subscriptions SET expires_at=?,status=?,updated_at=?,version=?
        WHERE id=? AND deleted_at IS NULL AND version=?`).bind(expiresAt, status, parsed.now, after.version, before.id, before.version),
      parsed.actor_user_id);
  }

  async activateWindows(raw: unknown): Promise<{ subscription: UserSubscription }> {
    const input = exactObject(raw, ["operation_id", "subscription_id", "expected_version", "activated_at", "daily_boundary"]);
    const parsed = { operation_id: operationID(input.operation_id), subscription_id: int64ID(input.subscription_id)!,
      expected_version: boundedInteger(input.expected_version, 1, MAX_VERSION), activated_at: utcInstant(input.activated_at),
      daily_boundary: utcInstant(input.daily_boundary) };
    assertBoundary(parsed.daily_boundary, parsed.activated_at);
    const hash = await this.operationHash("activate_windows", parsed);
    const prior = await this.replay<{ subscription: UserSubscription }>(parsed.operation_id, "activate_windows", hash);
    if (prior) return prior;
    const before = await this.currentSubscription(parsed.subscription_id);
    if (!before) fail("SUBSCRIPTION_NOT_FOUND");
    if (before.version !== parsed.expected_version) fail("STALE_VERSION");
    if (before.daily_window_start !== null || before.weekly_window_start !== null || before.monthly_window_start !== null) {
      fail("WINDOWS_ALREADY_ACTIVATED");
    }
    const after = { ...before, initial_daily_boundary: parsed.daily_boundary,
      daily_window_start: parsed.daily_boundary, weekly_window_start: parsed.activated_at,
      monthly_window_start: parsed.activated_at, weekly_anchor_kind: "activation" as const,
      monthly_anchor_kind: "activation" as const, updated_at: parsed.activated_at,
      version: nextVersion(before.version) };
    return this.singleSubscriptionMutation("activate_windows", parsed.operation_id, hash, parsed.activated_at, before, after,
      this.db.prepare(`UPDATE user_subscriptions SET initial_daily_boundary=?,daily_window_start=?,
        weekly_window_start=?,monthly_window_start=?,weekly_anchor_kind='activation',monthly_anchor_kind='activation',
        updated_at=?,version=? WHERE id=? AND deleted_at IS NULL AND version=?
        AND daily_window_start IS NULL AND weekly_window_start IS NULL AND monthly_window_start IS NULL`).bind(
          parsed.daily_boundary, parsed.daily_boundary, parsed.activated_at, parsed.activated_at,
          parsed.activated_at, after.version, before.id, before.version,
        ));
  }

  async maintainWindows(raw: unknown): Promise<{ subscription: UserSubscription }> {
    const input = exactObject(raw, ["operation_id", "subscription_id", "expected_version", "now", "daily_boundary"]);
    const parsed = { operation_id: operationID(input.operation_id), subscription_id: int64ID(input.subscription_id)!,
      expected_version: boundedInteger(input.expected_version, 1, MAX_VERSION), now: utcInstant(input.now),
      daily_boundary: utcInstant(input.daily_boundary) };
    assertBoundary(parsed.daily_boundary, parsed.now);
    const hash = await this.operationHash("maintain_windows", parsed);
    const prior = await this.replay<{ subscription: UserSubscription }>(parsed.operation_id, "maintain_windows", hash);
    if (prior) return prior;
    const before = await this.currentSubscription(parsed.subscription_id);
    if (!before) fail("SUBSCRIPTION_NOT_FOUND");
    if (before.version !== parsed.expected_version) fail("STALE_VERSION");
    if (!before.daily_window_start || !before.weekly_window_start || !before.monthly_window_start) fail("WINDOWS_NOT_ACTIVATED");
    let dailyStart = before.daily_window_start;
    let dailyUsage = before.daily_usage_e8_usd;
    const liveAtNow = parsed.now < before.expires_at;
    const oneDay = Date.parse(before.expires_at) - Date.parse(before.starts_at) <= DAY_MS;
    if (liveAtNow && !oneDay && parsed.daily_boundary > before.daily_window_start) {
      dailyStart = parsed.daily_boundary;
      dailyUsage = "0";
    }
    const weekly = advancedAnchor(before.weekly_window_start, before.weekly_anchor_kind,
      before.initial_daily_boundary, before.starts_at, before.expires_at, parsed.now, WEEK_MS);
    const monthly = advancedAnchor(before.monthly_window_start, before.monthly_anchor_kind,
      before.initial_daily_boundary, before.starts_at, before.expires_at, parsed.now, MONTH_MS);
    const after = { ...before, daily_window_start: dailyStart, weekly_window_start: weekly.value,
      monthly_window_start: monthly.value, weekly_anchor_kind: weekly.kind,
      monthly_anchor_kind: monthly.kind, daily_usage_e8_usd: dailyUsage,
      weekly_usage_e8_usd: weekly.reset ? "0" : before.weekly_usage_e8_usd,
      monthly_usage_e8_usd: monthly.reset ? "0" : before.monthly_usage_e8_usd,
      updated_at: parsed.now, version: nextVersion(before.version) };
    return this.singleSubscriptionMutation("maintain_windows", parsed.operation_id, hash, parsed.now, before, after,
      this.db.prepare(`UPDATE user_subscriptions SET daily_window_start=?,weekly_window_start=?,monthly_window_start=?,
        weekly_anchor_kind=?,monthly_anchor_kind=?,daily_usage_e8_usd=?,weekly_usage_e8_usd=?,monthly_usage_e8_usd=?,
        updated_at=?,version=? WHERE id=? AND deleted_at IS NULL AND version=?`).bind(
          after.daily_window_start, after.weekly_window_start, after.monthly_window_start,
          after.weekly_anchor_kind, after.monthly_anchor_kind, after.daily_usage_e8_usd,
          after.weekly_usage_e8_usd, after.monthly_usage_e8_usd, parsed.now, after.version,
          before.id, before.version,
        ));
  }

  async resetWindows(raw: unknown): Promise<{ subscription: UserSubscription }> {
    const input = exactObject(raw, ["operation_id", "subscription_id", "expected_version", "reset_daily",
      "reset_weekly", "reset_monthly", "reset_at", "daily_boundary", "actor_user_id"]);
    const parsed = { operation_id: operationID(input.operation_id), subscription_id: int64ID(input.subscription_id)!,
      expected_version: boundedInteger(input.expected_version, 1, MAX_VERSION), reset_daily: booleanValue(input.reset_daily),
      reset_weekly: booleanValue(input.reset_weekly), reset_monthly: booleanValue(input.reset_monthly),
      reset_at: utcInstant(input.reset_at), daily_boundary: utcInstant(input.daily_boundary),
      actor_user_id: int64ID(input.actor_user_id)! };
    if (!parsed.reset_daily && !parsed.reset_weekly && !parsed.reset_monthly) fail("NO_WINDOWS_SELECTED");
    assertBoundary(parsed.daily_boundary, parsed.reset_at);
    const hash = await this.operationHash("reset_windows", parsed);
    const prior = await this.replay<{ subscription: UserSubscription }>(parsed.operation_id, "reset_windows", hash);
    if (prior) return prior;
    const before = await this.currentSubscription(parsed.subscription_id);
    if (!before) fail("SUBSCRIPTION_NOT_FOUND");
    await this.ensureLiveAdmin(parsed.actor_user_id);
    if (before.version !== parsed.expected_version) fail("STALE_VERSION");
    const after = { ...before,
      daily_window_start: parsed.reset_daily ? parsed.daily_boundary : before.daily_window_start,
      weekly_window_start: parsed.reset_weekly ? parsed.reset_at : before.weekly_window_start,
      monthly_window_start: parsed.reset_monthly ? parsed.reset_at : before.monthly_window_start,
      weekly_anchor_kind: parsed.reset_weekly ? "manual" as const : before.weekly_anchor_kind,
      monthly_anchor_kind: parsed.reset_monthly ? "manual" as const : before.monthly_anchor_kind,
      daily_usage_e8_usd: parsed.reset_daily ? "0" : before.daily_usage_e8_usd,
      weekly_usage_e8_usd: parsed.reset_weekly ? "0" : before.weekly_usage_e8_usd,
      monthly_usage_e8_usd: parsed.reset_monthly ? "0" : before.monthly_usage_e8_usd,
      updated_at: parsed.reset_at, version: nextVersion(before.version) };
    return this.singleSubscriptionMutation("reset_windows", parsed.operation_id, hash, parsed.reset_at, before, after,
      this.db.prepare(`UPDATE user_subscriptions SET daily_window_start=?,weekly_window_start=?,monthly_window_start=?,
        weekly_anchor_kind=?,monthly_anchor_kind=?,daily_usage_e8_usd=?,weekly_usage_e8_usd=?,monthly_usage_e8_usd=?,
        updated_at=?,version=? WHERE id=? AND deleted_at IS NULL AND version=?`).bind(
          after.daily_window_start, after.weekly_window_start, after.monthly_window_start,
          after.weekly_anchor_kind, after.monthly_anchor_kind, after.daily_usage_e8_usd,
          after.weekly_usage_e8_usd, after.monthly_usage_e8_usd, parsed.reset_at,
          after.version, before.id, before.version,
        ), parsed.actor_user_id);
  }

  async reserveUsage(raw: unknown): Promise<{ subscription: UserSubscription }> {
    const input = exactObject(raw, ["operation_id", "subscription_id", "expected_version", "amount_e8_usd", "at"]);
    const parsed = { operation_id: operationID(input.operation_id), subscription_id: int64ID(input.subscription_id)!,
      expected_version: boundedInteger(input.expected_version, 1, MAX_VERSION), amount_e8_usd: e8(input.amount_e8_usd)!,
      at: utcInstant(input.at) };
    const hash = await this.operationHash("reserve_usage", parsed);
    const prior = await this.replay<{ subscription: UserSubscription }>(parsed.operation_id, "reserve_usage", hash);
    if (prior) return prior;
    const before = await this.currentSubscription(parsed.subscription_id);
    if (!before) fail("SUBSCRIPTION_NOT_FOUND");
    if (before.version !== parsed.expected_version) fail("STALE_VERSION");
    if (before.status === "suspended") fail("SUBSCRIPTION_SUSPENDED");
    if (before.status === "expired" || before.expires_at <= parsed.at) fail("SUBSCRIPTION_EXPIRED");
    if (!before.daily_window_start || !before.weekly_window_start || !before.monthly_window_start) fail("WINDOWS_NOT_ACTIVATED");
    const amount = BigInt(parsed.amount_e8_usd);
    const values = [before.daily_usage_e8_usd, before.weekly_usage_e8_usd, before.monthly_usage_e8_usd]
      .map((value) => BigInt(e8(value)!));
    const next = values.map((value) => value + amount);
    if (next.some((value) => value > MAX_E8)) fail("MONEY_OVERFLOW");
    const limits = [before.daily_limit_e8_usd, before.weekly_limit_e8_usd, before.monthly_limit_e8_usd]
      .map((value) => value === null ? null : BigInt(e8(value)!));
    const codes = ["DAILY_LIMIT_EXCEEDED", "WEEKLY_LIMIT_EXCEEDED", "MONTHLY_LIMIT_EXCEEDED"];
    for (let index = 0; index < next.length; index += 1) {
      if (limits[index] !== null && next[index] > limits[index]!) fail(codes[index]);
    }
    const after = { ...before, daily_usage_e8_usd: next[0].toString(),
      weekly_usage_e8_usd: next[1].toString(), monthly_usage_e8_usd: next[2].toString(),
      updated_at: parsed.at, version: nextVersion(before.version) };
    return this.singleSubscriptionMutation("reserve_usage", parsed.operation_id, hash, parsed.at, before, after,
      this.db.prepare(`UPDATE user_subscriptions SET daily_usage_e8_usd=?,weekly_usage_e8_usd=?,
        monthly_usage_e8_usd=?,updated_at=?,version=? WHERE id=? AND deleted_at IS NULL AND status='active'
        AND expires_at>? AND version=?`).bind(after.daily_usage_e8_usd, after.weekly_usage_e8_usd,
          after.monthly_usage_e8_usd, parsed.at, after.version, before.id, parsed.at, before.version));
  }

  async sweepExpired(raw: unknown): Promise<{ expired_ids: string[]; count: number }> {
    const input = exactObject(raw, ["operation_id", "cutoff", "after_id", "limit"]);
    const parsed = { operation_id: operationID(input.operation_id), cutoff: utcInstant(input.cutoff),
      after_id: int64ID(input.after_id, true), limit: boundedInteger(input.limit, 1, 100) };
    const hash = await this.operationHash("expiry_sweep", parsed);
    const prior = await this.replay<{ expired_ids: string[]; count: number }>(parsed.operation_id, "expiry_sweep", hash);
    if (prior) return prior;
    const cursorClause = parsed.after_id
      ? "AND (length(id)>length(?) OR (length(id)=length(?) AND id>?))" : "";
    const bindings: Array<string | number> = [parsed.cutoff];
    if (parsed.after_id) bindings.push(parsed.after_id, parsed.after_id, parsed.after_id);
    bindings.push(parsed.limit);
    const rows = (await this.db.prepare(`SELECT * FROM user_subscriptions
      WHERE deleted_at IS NULL AND status='active' AND expires_at<=? ${cursorClause}
      ORDER BY length(id),id LIMIT ?`).bind(...bindings).all<UserSubscription>()).results;
    const result = { expired_ids: rows.map((row) => row.id), count: rows.length };
    const statements: D1PreparedStatement[] = [
      this.operationStatement(parsed.operation_id, "expiry_sweep", hash, result, parsed.cutoff),
    ];
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      const version = nextVersion(row.version);
      const guard = await this.guardID(parsed.operation_id, index);
      statements.push(
        this.db.prepare(`UPDATE user_subscriptions SET status='expired',updated_at=?,version=?
          WHERE id=? AND deleted_at IS NULL AND status='active' AND expires_at<=? AND version=?`)
          .bind(parsed.cutoff, version, row.id, parsed.cutoff, row.version),
        this.guardInsert(guard, parsed.cutoff, true),
        this.effectInsert(parsed.operation_id, index, guard, "subscription", row.id, row.version, version),
      );
    }
    if (rows.length === 0) {
      const guard = await this.guardID(parsed.operation_id);
      statements.push(this.guardInsert(guard, parsed.cutoff, false));
    }
    try {
      await this.db.batch(statements);
      return result;
    } catch {
      const committed = await this.ensureReplayAfterFailure<typeof result>(parsed.operation_id, "expiry_sweep", hash);
      if (committed) return committed;
      fail("SWEEP_CONFLICT");
    }
  }
}
