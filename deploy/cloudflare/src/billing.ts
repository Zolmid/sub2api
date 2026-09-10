import { DurableObject } from "cloudflare:workers";
import { isBoundedString, isCanonicalPositiveDecimal, isCanonicalUnsignedDecimal, now } from "./contracts";

export const MAX_PUBLIC_BALANCE_E8_USD = 900719925474099100n;
const MAX_VERSION = Number.MAX_SAFE_INTEGER - 1;
const DIGEST = /^[0-9a-f]{64}$/;
type State = "reserved" | "started" | "completed" | "released" | "unknown";
type OperationKind =
  | "reserve"
  | "start"
  | "partial_settle"
  | "final_settle"
  | "release"
  | "expire_refund"
  | "expire_unknown"
  | "reconcile_charge"
  | "reconcile_refund";

export type BillingIdentity = {
  request_id: string; user_id: string; api_key_id: string; group_id: string; account_id: string;
  lease_id: string; lease_epoch: string; owner: string; model: string; upstream_model: string;
  pricing_version_id: string; pricing_digest: string; pricing_model: string;
  pricing_rule_pattern: string; pricing_rule_match_kind: "exact" | "family";
  rate_multiplier_bps: string; reservation_e8_usd: string;
};
export type ReserveBillingInput = BillingIdentity & { operation_id: string };
export type CompleteBillingInput = BillingIdentity & {
  operation_id: string; final: boolean; usage_present: boolean; charged_e8_usd: string; event_id: string;
  payload_hash: string; payload_json: string; outcome: "succeeded" | "failed";
  upstream_request_id?: string;
};
export type ExpireBillingInput = BillingIdentity & {
  operation_id: string;
  expected_reservation_version: string;
  reason: "expired" | "crash";
  evidence_digest: string;
};
export type ReconcileBillingInput = BillingIdentity & {
  operation_id: string; actor_id: string; expected_reservation_version: string;
  decision: "charge" | "refund"; charged_e8_usd?: string; evidence_digest: string;
};
export type BillingResult =
  | { kind: "ok"; state: State; replayed: boolean }
  | { kind: "insufficient" } | { kind: "stale_pricing" } | { kind: "unavailable" }
  | { kind: "mismatch" } | { kind: "out_of_order" };

type ReservationRow = BillingIdentity & {
  charged_e8_usd: string | null; usage_present: number | null; state: State; version: number;
  completion_event_id: string | null; completion_payload_hash: string | null;
  completion_outcome: string | null; upstream_request_id: string | null;
};
type EventRow = {
  operation_id: string; operation_kind: OperationKind; request_id: string; user_id: string;
  from_state: State | null; to_state: State; reservation_version: number;
  event_id: string | null; payload_hash: string | null; outcome: string | null;
  upstream_request_id: string | null; evidence_digest: string | null;
};
type UserRow = { balance_e8_usd: string; balance_version: number };

function ownRecord(
  value: unknown,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[] = [],
): Record<string, unknown> | null {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const actual = Object.keys(descriptors);
    const allowed = [...requiredKeys, ...optionalKeys];
    if (requiredKeys.some((key) => !actual.includes(key)) ||
      actual.some((key) => !allowed.includes(key))) return null;
    for (const key of actual) {
      const descriptor = descriptors[key];
      if (!descriptor || !("value" in descriptor) || descriptor.get || descriptor.set) return null;
    }
    return Object.fromEntries(actual.map((key) => [key, descriptors[key].value]));
  } catch { return null; }
}
function text(value: unknown, max: number, min = 1): value is string { return isBoundedString(value, max, min); }
function positiveID(value: unknown): value is string { return isCanonicalPositiveDecimal(value) && value.length <= 20; }
function unsigned(value: unknown, max = 18): value is string {
  return isCanonicalUnsignedDecimal(value) && value.length <= max && BigInt(value) <= MAX_PUBLIC_BALANCE_E8_USD;
}
function positive(value: unknown, max = 18): value is string { return unsigned(value, max) && value !== "0"; }
function bps(value: unknown): value is string { return positive(value, 8); }
function safeVersion(value: unknown, minimum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum && value < MAX_VERSION;
}
function nextVersion(value: number): number | null { return safeVersion(value, 0) ? value + 1 : null; }
function sameIdentity(left: BillingIdentity, right: BillingIdentity): boolean {
  return left.request_id === right.request_id && left.user_id === right.user_id &&
    left.api_key_id === right.api_key_id && left.group_id === right.group_id &&
    left.account_id === right.account_id && left.lease_id === right.lease_id &&
    left.lease_epoch === right.lease_epoch && left.owner === right.owner &&
    left.model === right.model && left.upstream_model === right.upstream_model &&
    left.pricing_version_id === right.pricing_version_id && left.pricing_digest === right.pricing_digest &&
    left.pricing_model === right.pricing_model && left.pricing_rule_pattern === right.pricing_rule_pattern &&
    left.pricing_rule_match_kind === right.pricing_rule_match_kind &&
    left.rate_multiplier_bps === right.rate_multiplier_bps && left.reservation_e8_usd === right.reservation_e8_usd;
}
function validIdentity(value: Record<string, unknown>): boolean {
  return text(value.request_id, 256) && positiveID(value.user_id) && positiveID(value.api_key_id) &&
    positiveID(value.group_id) && positiveID(value.account_id) && text(value.lease_id, 256) &&
    positiveID(value.lease_epoch) && text(value.owner, 256) && text(value.model, 256) &&
    text(value.upstream_model, 256) && text(value.pricing_version_id, 128) &&
    typeof value.pricing_digest === "string" && DIGEST.test(value.pricing_digest) &&
    text(value.pricing_model, 256) && /^[a-z0-9._:/-]+$/.test(value.pricing_model) &&
    text(value.pricing_rule_pattern, 257) &&
    (value.pricing_rule_match_kind === "exact" || value.pricing_rule_match_kind === "family") &&
    bps(value.rate_multiplier_bps) && positive(value.reservation_e8_usd);
}
function parseReserve(value: unknown): ReserveBillingInput | null {
  const row = ownRecord(value, ["operation_id", "request_id", "user_id", "api_key_id", "group_id", "account_id", "lease_id", "lease_epoch", "owner", "model", "upstream_model", "pricing_version_id", "pricing_digest", "pricing_model", "pricing_rule_pattern", "pricing_rule_match_kind", "rate_multiplier_bps", "reservation_e8_usd"]);
  return row && text(row.operation_id, 300) && validIdentity(row) ? row as ReserveBillingInput : null;
}
function parseStartOrRelease(value: unknown): (BillingIdentity & { operation_id: string }) | null {
  const row = ownRecord(value, ["operation_id", "request_id", "user_id", "api_key_id", "group_id", "account_id", "lease_id", "lease_epoch", "owner", "model", "upstream_model", "pricing_version_id", "pricing_digest", "pricing_model", "pricing_rule_pattern", "pricing_rule_match_kind", "rate_multiplier_bps", "reservation_e8_usd"]);
  return row && text(row.operation_id, 300) && validIdentity(row) ? row as BillingIdentity & { operation_id: string } : null;
}
function parseComplete(value: unknown): CompleteBillingInput | null {
  const row = ownRecord(value, ["operation_id", "request_id", "user_id", "api_key_id", "group_id", "account_id", "lease_id", "lease_epoch", "owner", "model", "upstream_model", "pricing_version_id", "pricing_digest", "pricing_model", "pricing_rule_pattern", "pricing_rule_match_kind", "rate_multiplier_bps", "reservation_e8_usd", "final", "usage_present", "charged_e8_usd", "event_id", "payload_hash", "payload_json", "outcome"], ["upstream_request_id"]);
  if (!row || !text(row.operation_id, 300) || !validIdentity(row) || typeof row.final !== "boolean" || typeof row.usage_present !== "boolean" ||
    !unsigned(row.charged_e8_usd) || !text(row.event_id, 300) || typeof row.payload_hash !== "string" ||
    !DIGEST.test(row.payload_hash) || !text(row.payload_json, 65536, 2) ||
    (row.outcome !== "succeeded" && row.outcome !== "failed") ||
    (row.upstream_request_id !== undefined && !text(row.upstream_request_id, 512))) return null;
  if (!row.final && !row.usage_present) return null;
  return row as unknown as CompleteBillingInput;
}
function parseExpire(value: unknown): ExpireBillingInput | null {
  const row = ownRecord(value, ["operation_id", "request_id", "user_id", "api_key_id", "group_id", "account_id", "lease_id", "lease_epoch", "owner", "model", "upstream_model", "pricing_version_id", "pricing_digest", "pricing_model", "pricing_rule_pattern", "pricing_rule_match_kind", "rate_multiplier_bps", "reservation_e8_usd", "expected_reservation_version", "reason", "evidence_digest"]);
  if (!row || !text(row.operation_id, 300) || !validIdentity(row) ||
    !positive(row.expected_reservation_version) ||
    (row.reason !== "expired" && row.reason !== "crash") ||
    typeof row.evidence_digest !== "string" || !DIGEST.test(row.evidence_digest)) {
    return null;
  }
  return row as unknown as ExpireBillingInput;
}
function parseReconcile(value: unknown): ReconcileBillingInput | null {
  const row = ownRecord(value, ["operation_id", "request_id", "user_id", "api_key_id", "group_id", "account_id", "lease_id", "lease_epoch", "owner", "model", "upstream_model", "pricing_version_id", "pricing_digest", "pricing_model", "pricing_rule_pattern", "pricing_rule_match_kind", "rate_multiplier_bps", "reservation_e8_usd", "actor_id", "expected_reservation_version", "decision", "evidence_digest"], ["charged_e8_usd"]);
  if (!row || !text(row.operation_id, 300) || !validIdentity(row) || !text(row.actor_id, 256) ||
    !positive(row.expected_reservation_version) || (row.decision !== "charge" && row.decision !== "refund") ||
    typeof row.evidence_digest !== "string" || !DIGEST.test(row.evidence_digest)) return null;
  if (row.decision === "charge" && !unsigned(row.charged_e8_usd)) return null;
  if (row.decision === "refund" && row.charged_e8_usd !== undefined) return null;
  return row as unknown as ReconcileBillingInput;
}

/** Per-user coordinator. D1 stores all balances, reservation facts, and audit rows. */
export class BillingPrincipalDO extends DurableObject<Env> {
  private reservation(requestID: string): Promise<ReservationRow | null> {
    return this.env.DB.prepare(`SELECT request_id,user_id,api_key_id,group_id,account_id,lease_id,lease_epoch,owner,model,upstream_model,pricing_version_id,pricing_digest,pricing_model,pricing_rule_pattern,pricing_rule_match_kind,rate_multiplier_bps,reservation_e8_usd,charged_e8_usd,usage_present,state,version,completion_event_id,completion_payload_hash,completion_outcome,upstream_request_id FROM billing_reservations WHERE request_id=?`).bind(requestID).first<ReservationRow>();
  }
  private event(operationID: string): Promise<EventRow | null> {
    return this.env.DB.prepare("SELECT operation_id,operation_kind,request_id,user_id,from_state,to_state,reservation_version,event_id,payload_hash,outcome,upstream_request_id,evidence_digest FROM billing_reservation_events WHERE operation_id=?").bind(operationID).first<EventRow>();
  }
  private user(userID: string): Promise<UserRow | null> {
    return this.env.DB.prepare("SELECT balance_e8_usd,balance_version FROM users WHERE id=? AND status='active' AND deleted_at IS NULL").bind(userID).first<UserRow>();
  }
  private async run(statements: D1PreparedStatement[]): Promise<void> {
    const results = await this.env.DB.batch(statements);
    if (results.length !== statements.length) throw new Error("incomplete D1 batch result");
  }
  private validUser(user: UserRow | null): user is UserRow {
    return !!user && unsigned(user.balance_e8_usd) && safeVersion(user.balance_version, 0);
  }
  private async replay(input: BillingIdentity & { operation_id: string }, expected: { kind: OperationKind; from: State | null; to: State; eventID?: string; payloadHash?: string; outcome?: string; upstreamID?: string | null; evidenceDigest?: string | null }): Promise<BillingResult | null> {
    const prior = await this.event(input.operation_id);
    if (!prior) return null;
    if (prior.operation_kind !== expected.kind || prior.request_id !== input.request_id || prior.user_id !== input.user_id ||
      prior.from_state !== expected.from || prior.to_state !== expected.to ||
      prior.event_id !== (expected.eventID ?? null) || prior.payload_hash !== (expected.payloadHash ?? null) ||
      prior.outcome !== (expected.outcome ?? null) || prior.upstream_request_id !== (expected.upstreamID ?? null) ||
      prior.evidence_digest !== (expected.evidenceDigest ?? null)) return { kind: "mismatch" };
    const row = await this.reservation(input.request_id);
    if (!row) return { kind: "unavailable" };
    if (!sameIdentity(row, input)) return { kind: "mismatch" };
    if (expected.kind === "final_settle") {
      const outbox = await this.env.DB.prepare("SELECT payload_hash FROM outbox_events WHERE event_id=?").bind(expected.eventID).first<{ payload_hash: string }>();
      if (outbox?.payload_hash !== expected.payloadHash) return { kind: "unavailable" };
    }
    return { kind: "ok", state: row.state, replayed: true };
  }
  private guard(id: string): D1PreparedStatement { return this.env.DB.prepare("INSERT INTO billing_cas_guards(guard_id,changed_rows) VALUES(?,changes())").bind(id); }
  private eventInsert(operationID: string, kind: OperationKind, row: BillingIdentity, from: State | null, to: State, reservationVersion: number, extras: { eventID?: string; payloadHash?: string; outcome?: string; upstreamID?: string | null; evidenceDigest?: string } = {}): D1PreparedStatement {
    return this.env.DB.prepare(`INSERT INTO billing_reservation_events(operation_id,operation_kind,request_id,user_id,from_state,to_state,reservation_version,event_id,payload_hash,outcome,upstream_request_id,evidence_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(operationID,kind,row.request_id,row.user_id,from,to,reservationVersion,extras.eventID ?? null,extras.payloadHash ?? null,extras.outcome ?? null,extras.upstreamID ?? null,extras.evidenceDigest ?? null,now());
  }
  private ledgerInsert(operationID: string, kind: "reserve" | "refund_complete" | "refund_release" | "refund_expire" | "reconcile_charge" | "reconcile_refund", row: BillingIdentity, delta: bigint, before: string, after: string, beforeVersion: number, reservationVersion: number, reasonDigest?: string): D1PreparedStatement {
    return this.env.DB.prepare(`INSERT INTO billing_monetary_ledger(operation_id,request_id,user_id,operation_kind,delta_e8_usd,balance_before_e8_usd,balance_after_e8_usd,balance_version_before,balance_version_after,reservation_version,pricing_version_id,pricing_digest,reason_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(operationID,row.request_id,row.user_id,kind,delta.toString(),before,after,beforeVersion,beforeVersion + 1,reservationVersion,row.pricing_version_id,row.pricing_digest,reasonDigest ?? null,now());
  }

  async reserve(raw: unknown): Promise<BillingResult> {
    const input = parseReserve(raw); if (!input) return { kind: "mismatch" };
    const replay = await this.replay(input, { kind: "reserve", from: null, to: "reserved" }); if (replay) return replay;
    const existing = await this.reservation(input.request_id);
    if (existing) return sameIdentity(existing, input) ? { kind: "unavailable" } : { kind: "mismatch" };
    const user = await this.user(input.user_id); if (!this.validUser(user)) return { kind: "unavailable" };
    const nextBalanceVersion = nextVersion(user.balance_version); if (nextBalanceVersion === null) return { kind: "unavailable" };
    const before = BigInt(user.balance_e8_usd), reservation = BigInt(input.reservation_e8_usd);
    if (before < reservation) return { kind: "insufficient" };
    const after = before - reservation, guardBalance = crypto.randomUUID(), guardPricing = crypto.randomUUID();
    try {
      await this.run([
        this.env.DB.prepare("UPDATE users SET balance_e8_usd=?,balance_version=balance_version+1,updated_at=? WHERE id=? AND balance_e8_usd=? AND balance_version=? AND status='active' AND deleted_at IS NULL AND balance_version<?").bind(after.toString(),now(),input.user_id,user.balance_e8_usd,user.balance_version,MAX_VERSION),
        this.guard(guardBalance),
        this.env.DB.prepare(`INSERT INTO gateway_requests(request_id,api_key_id,account_id,lease_id,lease_epoch,owner,model,upstream_model,pricing_version_id,pricing_digest,pricing_rule_pattern,pricing_model,pricing_rule_match_kind,rate_multiplier_bps,state,created_at)
          SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'admitted', ?
          WHERE EXISTS (SELECT 1 FROM pricing_active_version a JOIN pricing_versions v ON v.version_id=a.version_id JOIN pricing_rules r ON r.version_id=v.version_id JOIN groups g ON g.id=?
            WHERE a.version_id=? AND v.digest=? AND r.model_pattern=? AND r.match_kind=? AND g.rate_multiplier_bps=?)`).bind(input.request_id,input.api_key_id,input.account_id,input.lease_id,input.lease_epoch,input.owner,input.model,input.upstream_model,input.pricing_version_id,input.pricing_digest,input.pricing_rule_pattern,input.pricing_model,input.pricing_rule_match_kind,input.rate_multiplier_bps,now(),input.group_id,input.pricing_version_id,input.pricing_digest,input.pricing_rule_pattern,input.pricing_rule_match_kind,input.rate_multiplier_bps),
        this.guard(guardPricing),
        this.env.DB.prepare(`INSERT INTO billing_reservations(request_id,user_id,api_key_id,group_id,account_id,lease_id,lease_epoch,owner,model,upstream_model,pricing_version_id,pricing_digest,pricing_model,pricing_rule_pattern,pricing_rule_match_kind,rate_multiplier_bps,reservation_e8_usd,state,version,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'reserved',1,?)`).bind(input.request_id,input.user_id,input.api_key_id,input.group_id,input.account_id,input.lease_id,input.lease_epoch,input.owner,input.model,input.upstream_model,input.pricing_version_id,input.pricing_digest,input.pricing_model,input.pricing_rule_pattern,input.pricing_rule_match_kind,input.rate_multiplier_bps,input.reservation_e8_usd,now()),
        this.eventInsert(input.operation_id,"reserve",input,null,"reserved",1),
        this.ledgerInsert(input.operation_id,"reserve",input,-reservation,user.balance_e8_usd,after.toString(),user.balance_version,1),
        this.env.DB.prepare("DELETE FROM billing_cas_guards WHERE guard_id IN (?,?)").bind(guardBalance,guardPricing),
      ]);
      return { kind: "ok", state: "reserved", replayed: false };
    } catch {
      const retry = await this.replay(input, { kind: "reserve", from: null, to: "reserved" }); if (retry) return retry;
      const active = await this.env.DB.prepare("SELECT a.version_id,v.digest FROM pricing_active_version a JOIN pricing_versions v ON v.version_id=a.version_id").first<{version_id:string;digest:string}>();
      return !active || active.version_id !== input.pricing_version_id || active.digest !== input.pricing_digest ? { kind: "stale_pricing" } : { kind: "unavailable" };
    }
  }

  async start(raw: unknown): Promise<BillingResult> {
    const input = parseStartOrRelease(raw); if (!input) return { kind: "mismatch" };
    const replay = await this.replay(input,{kind:"start",from:"reserved",to:"started"}); if (replay) return replay;
    const row = await this.reservation(input.request_id); if (!row || !sameIdentity(row,input)) return {kind:"mismatch"};
    if (row.state !== "reserved") return {kind:"out_of_order"}; const next = nextVersion(row.version); if (next === null) return {kind:"unavailable"};
    const guard = crypto.randomUUID();
    try { await this.run([
      this.env.DB.prepare("UPDATE billing_reservations SET state='started',version=version+1,started_at=? WHERE request_id=? AND state='reserved' AND version=? AND version<?").bind(now(),row.request_id,row.version,MAX_VERSION), this.guard(guard),
      this.eventInsert(input.operation_id,"start",input,"reserved","started",next), this.env.DB.prepare("DELETE FROM billing_cas_guards WHERE guard_id=?").bind(guard),
    ]); return {kind:"ok",state:"started",replayed:false}; } catch { return (await this.replay(input,{kind:"start",from:"reserved",to:"started"})) ?? {kind:"out_of_order"}; }
  }

  async complete(raw: unknown): Promise<BillingResult> {
    const input = parseComplete(raw); if (!input) return {kind:"mismatch"};
    const expected = {
      kind: input.final ? "final_settle" as const : "partial_settle" as const,
      from: "started" as const,
      to: input.final ? (input.usage_present ? "completed" as const : "unknown" as const) : "started" as const,
      eventID: input.event_id,
      payloadHash: input.payload_hash,
      outcome: input.outcome,
      upstreamID: input.upstream_request_id ?? null,
    };
    const replay = await this.replay(input,expected); if (replay) return replay;
    const row = await this.reservation(input.request_id); if (!row || !sameIdentity(row,input)) return {kind:"mismatch"};
    if (row.state !== "started") return {kind:"out_of_order"};
    const charged = BigInt(input.charged_e8_usd);
    const alreadyCharged = BigInt(row.charged_e8_usd ?? "0");
    const held = BigInt(row.reservation_e8_usd);
    if (charged < alreadyCharged) return {kind:"mismatch"};
    if (!input.final) {
      if (charged > held) return {kind:"mismatch"};
      return this.partial(input, row, {
        kind: "partial_settle",
        from: "started",
        to: "started",
        eventID: input.event_id,
        payloadHash: input.payload_hash,
        outcome: input.outcome,
        upstreamID: input.upstream_request_id ?? null,
      });
    }
    if (!input.usage_present || charged > held) {
      return this.unknown(input,row,{...expected,kind:"final_settle",to:"unknown"});
    }
    return this.refund(input,row,"completed","refund_complete",held-charged,{...expected,kind:"final_settle",to:"completed"});
  }
  private async partial(input: CompleteBillingInput, row: ReservationRow, expected: {kind:"partial_settle";from:"started";to:"started";eventID:string;payloadHash:string;outcome:"succeeded"|"failed";upstreamID:string|null}): Promise<BillingResult> {
    const next = nextVersion(row.version);
    if (next === null) return {kind:"unavailable"};
    const guard = crypto.randomUUID();
    try {
      await this.run([
        this.env.DB.prepare("UPDATE billing_reservations SET charged_e8_usd=?,usage_present=1,version=version+1 WHERE request_id=? AND state='started' AND version=? AND version<?")
          .bind(input.charged_e8_usd,row.request_id,row.version,MAX_VERSION),
        this.guard(guard),
        this.eventInsert(input.operation_id,"partial_settle",input,"started","started",next,{eventID:input.event_id,payloadHash:input.payload_hash,outcome:input.outcome,upstreamID:input.upstream_request_id}),
        this.env.DB.prepare("DELETE FROM billing_cas_guards WHERE guard_id=?").bind(guard),
      ]);
      return {kind:"ok",state:"started",replayed:false};
    } catch {
      return (await this.replay(input,expected)) ?? {kind:"out_of_order"};
    }
  }
  private async unknown(input: CompleteBillingInput, row: ReservationRow, expected: {kind:"final_settle";from:"started";to:"unknown";eventID:string;payloadHash:string;outcome:"succeeded"|"failed";upstreamID:string|null}): Promise<BillingResult> {
    const next = nextVersion(row.version); if (next === null) return {kind:"unavailable"}; const guard=crypto.randomUUID();
    try { await this.run([
      this.env.DB.prepare("UPDATE billing_reservations SET state='unknown',version=version+1,usage_present=0,completion_event_id=?,completion_payload_hash=?,completion_outcome=?,upstream_request_id=?,unknown_at=? WHERE request_id=? AND state='started' AND version=? AND version<?").bind(input.event_id,input.payload_hash,input.outcome,input.upstream_request_id ?? null,now(),row.request_id,row.version,MAX_VERSION), this.guard(guard),
      this.eventInsert(input.operation_id,"final_settle",input,"started","unknown",next,{eventID:input.event_id,payloadHash:input.payload_hash,outcome:input.outcome,upstreamID:input.upstream_request_id}),
      this.env.DB.prepare("UPDATE gateway_requests SET state=?,event_id=?,completed_at=? WHERE request_id=? AND state='admitted'").bind(input.outcome,input.event_id,now(),input.request_id),
      this.env.DB.prepare("INSERT INTO outbox_events(event_id,request_id,payload_json,payload_hash,state,attempts,created_at) VALUES(?,?,?,?, 'pending',0,?)").bind(input.event_id,input.request_id,input.payload_json,input.payload_hash,now()),
      this.env.DB.prepare("DELETE FROM billing_cas_guards WHERE guard_id=?").bind(guard),
    ]); return {kind:"ok",state:"unknown",replayed:false}; } catch { return (await this.replay(input,expected)) ?? {kind:"out_of_order"}; }
  }
  private async refund(input: CompleteBillingInput | (BillingIdentity & {operation_id:string}), row: ReservationRow, to: "completed" | "released", ledgerKind: "refund_complete" | "refund_release", refund: bigint, complete?: {kind:"final_settle";from:"started";to:"completed";eventID:string;payloadHash:string;outcome:"succeeded"|"failed";upstreamID:string|null}, reasonDigest?: string): Promise<BillingResult> {
    const user = await this.user(row.user_id); if (!this.validUser(user)) return {kind:"unavailable"}; const balanceNext=nextVersion(user.balance_version), reservationNext=nextVersion(row.version); if(balanceNext===null||reservationNext===null) return {kind:"unavailable"};
    const after=BigInt(user.balance_e8_usd)+refund; if(after>MAX_PUBLIC_BALANCE_E8_USD) return {kind:"unavailable"}; const g1=crypto.randomUUID(),g2=crypto.randomUUID();
    const operationKind: OperationKind = complete ? "final_settle" : "release";
    try { const statements: D1PreparedStatement[] = [
      this.env.DB.prepare("UPDATE users SET balance_e8_usd=?,balance_version=balance_version+1,updated_at=? WHERE id=? AND balance_e8_usd=? AND balance_version=? AND balance_version<?").bind(after.toString(),now(),row.user_id,user.balance_e8_usd,user.balance_version,MAX_VERSION),this.guard(g1),
      this.env.DB.prepare(`UPDATE billing_reservations SET state=?,version=version+1,charged_e8_usd=?,usage_present=?,completion_event_id=CASE WHEN ? IS NULL THEN completion_event_id ELSE ? END,completion_payload_hash=CASE WHEN ? IS NULL THEN completion_payload_hash ELSE ? END,completion_outcome=CASE WHEN ? IS NULL THEN completion_outcome ELSE ? END,upstream_request_id=CASE WHEN ? IS NULL THEN upstream_request_id ELSE ? END,${to === "completed" ? "completed_at" : "released_at"}=? WHERE request_id=? AND state=? AND version=? AND version<?`).bind(to,complete ? (input as CompleteBillingInput).charged_e8_usd : null,complete ? 1 : null,complete?.eventID ?? null,complete?.eventID ?? null,complete?.payloadHash ?? null,complete?.payloadHash ?? null,complete?.outcome ?? null,complete?.outcome ?? null,complete?.upstreamID ?? null,complete?.upstreamID ?? null,now(),row.request_id,row.state,row.version,MAX_VERSION),this.guard(g2),
      this.eventInsert(input.operation_id,operationKind,input,row.state,to,reservationNext,complete ? {eventID:complete.eventID,payloadHash:complete.payloadHash,outcome:complete.outcome,upstreamID:complete.upstreamID} : {}),
      this.ledgerInsert(input.operation_id,ledgerKind,input,refund,user.balance_e8_usd,after.toString(),user.balance_version,reservationNext,reasonDigest),
    ];
    if (complete) { const c=input as CompleteBillingInput; statements.push(this.env.DB.prepare("UPDATE gateway_requests SET state=?,event_id=?,completed_at=? WHERE request_id=? AND state='admitted'").bind(c.outcome,c.event_id,now(),c.request_id)); statements.push(this.env.DB.prepare("INSERT INTO outbox_events(event_id,request_id,payload_json,payload_hash,state,attempts,created_at) VALUES(?,?,?,?, 'pending',0,?)").bind(c.event_id,c.request_id,c.payload_json,c.payload_hash,now())); }
    statements.push(this.env.DB.prepare("DELETE FROM billing_cas_guards WHERE guard_id IN (?,?)").bind(g1,g2)); await this.run(statements); return {kind:"ok",state:to,replayed:false};
    } catch { if(complete) return (await this.replay(input,{kind:"final_settle",from:"started",to:"completed",eventID:complete.eventID,payloadHash:complete.payloadHash,outcome:complete.outcome,upstreamID:complete.upstreamID})) ?? {kind:"out_of_order"}; return (await this.replay(input,{kind:"release",from:"reserved",to:"released"})) ?? {kind:"out_of_order"}; }
  }
  async release(raw: unknown): Promise<BillingResult> {
    const input=parseStartOrRelease(raw); if(!input) return {kind:"mismatch"}; const row=await this.reservation(input.request_id); if(!row||!sameIdentity(row,input)) return {kind:"mismatch"};
    if(row.state==="reserved") { const replay=await this.replay(input,{kind:"release",from:"reserved",to:"released"}); if(replay)return replay; return this.refund(input,row,"released","refund_release",BigInt(row.reservation_e8_usd)); }
    if(row.state==="started") return {kind:"out_of_order"};
    return {kind:"ok",state:row.state,replayed:true};
  }
  async expire(raw: unknown): Promise<BillingResult> {
    const input = parseExpire(raw);
    if (!input) return {kind:"mismatch"};
    const row = await this.reservation(input.request_id);
    if (!row || !sameIdentity(row,input)) return {kind:"mismatch"};
    const prior = await this.event(input.operation_id);
    if (prior) {
      if (prior.operation_kind === "expire_refund") {
        return (await this.replay(input,{kind:"expire_refund",from:"reserved",to:"released",evidenceDigest:input.evidence_digest})) ?? {kind:"unavailable"};
      }
      if (prior.operation_kind === "expire_unknown") {
        return (await this.replay(input,{kind:"expire_unknown",from:"started",to:"unknown",evidenceDigest:input.evidence_digest})) ?? {kind:"unavailable"};
      }
      return {kind:"mismatch"};
    }
    const expectedVersion = Number(input.expected_reservation_version);
    if (!safeVersion(expectedVersion,1)) return {kind:"mismatch"};
    if (row.version !== expectedVersion || (row.state !== "reserved" && row.state !== "started")) return {kind:"out_of_order"};
    const reservationNext = nextVersion(row.version);
    if (reservationNext === null) return {kind:"unavailable"};
    if (row.state === "started") {
      const guard = crypto.randomUUID();
      try {
        await this.run([
          this.env.DB.prepare("UPDATE billing_reservations SET state='unknown',version=version+1,usage_present=0,unknown_at=? WHERE request_id=? AND state='started' AND version=? AND version<?")
            .bind(now(),row.request_id,row.version,MAX_VERSION),
          this.guard(guard),
          this.eventInsert(input.operation_id,"expire_unknown",input,"started","unknown",reservationNext,{evidenceDigest:input.evidence_digest}),
          this.env.DB.prepare("DELETE FROM billing_cas_guards WHERE guard_id=?").bind(guard),
        ]);
        return {kind:"ok",state:"unknown",replayed:false};
      } catch {
        return (await this.replay(input,{kind:"expire_unknown",from:"started",to:"unknown",evidenceDigest:input.evidence_digest})) ?? {kind:"out_of_order"};
      }
    }
    const user = await this.user(row.user_id);
    if (!this.validUser(user)) return {kind:"unavailable"};
    const balanceNext = nextVersion(user.balance_version);
    if (balanceNext === null) return {kind:"unavailable"};
    const refund = BigInt(row.reservation_e8_usd);
    const after = BigInt(user.balance_e8_usd) + refund;
    if (after > MAX_PUBLIC_BALANCE_E8_USD) return {kind:"unavailable"};
    const balanceGuard = crypto.randomUUID();
    const reservationGuard = crypto.randomUUID();
    try {
      await this.run([
        this.env.DB.prepare("UPDATE users SET balance_e8_usd=?,balance_version=balance_version+1,updated_at=? WHERE id=? AND balance_e8_usd=? AND balance_version=? AND balance_version<?")
          .bind(after.toString(),now(),row.user_id,user.balance_e8_usd,user.balance_version,MAX_VERSION),
        this.guard(balanceGuard),
        this.env.DB.prepare("UPDATE billing_reservations SET state='released',version=version+1,released_at=? WHERE request_id=? AND state='reserved' AND version=? AND version<?")
          .bind(now(),row.request_id,row.version,MAX_VERSION),
        this.guard(reservationGuard),
        this.eventInsert(input.operation_id,"expire_refund",input,"reserved","released",reservationNext,{evidenceDigest:input.evidence_digest}),
        this.ledgerInsert(input.operation_id,"refund_expire",input,refund,user.balance_e8_usd,after.toString(),user.balance_version,reservationNext,input.evidence_digest),
        this.env.DB.prepare("DELETE FROM billing_cas_guards WHERE guard_id IN (?,?)").bind(balanceGuard,reservationGuard),
      ]);
      return {kind:"ok",state:"released",replayed:false};
    } catch {
      return (await this.replay(input,{kind:"expire_refund",from:"reserved",to:"released",evidenceDigest:input.evidence_digest})) ?? {kind:"out_of_order"};
    }
  }
  async reconcile(raw: unknown): Promise<BillingResult> {
    const input=parseReconcile(raw); if(!input) return {kind:"mismatch"}; const row=await this.reservation(input.request_id); if(!row||!sameIdentity(row,input))return {kind:"mismatch"};
    const to=input.decision==="charge"?"completed" as const:"released" as const; const kind=input.decision==="charge"?"reconcile_charge" as const:"reconcile_refund" as const;
    const replay=await this.replay(input,{kind,from:"unknown",to,evidenceDigest:input.evidence_digest}); if(replay)return replay;
    const expectedVersion=Number(input.expected_reservation_version); if(!safeVersion(expectedVersion,1)||expectedVersion!==row.version||row.state!=="unknown")return {kind:"out_of_order"};
    const charge=input.decision==="charge"?BigInt(input.charged_e8_usd!):0n, held=BigInt(row.reservation_e8_usd), alreadyCharged=BigInt(row.charged_e8_usd ?? "0"); if(charge>held||charge<alreadyCharged)return {kind:"mismatch"};
    const user=await this.user(row.user_id); if(!this.validUser(user))return {kind:"unavailable"}; const bv=nextVersion(user.balance_version),rv=nextVersion(row.version); if(bv===null||rv===null)return {kind:"unavailable"}; const refund=held-charge,after=BigInt(user.balance_e8_usd)+refund;if(after>MAX_PUBLIC_BALANCE_E8_USD)return {kind:"unavailable"};const g1=crypto.randomUUID(),g2=crypto.randomUUID();
    try{await this.run([
      this.env.DB.prepare("UPDATE users SET balance_e8_usd=?,balance_version=balance_version+1,updated_at=? WHERE id=? AND balance_e8_usd=? AND balance_version=? AND balance_version<?").bind(after.toString(),now(),row.user_id,user.balance_e8_usd,user.balance_version,MAX_VERSION),this.guard(g1),
      this.env.DB.prepare("UPDATE billing_reservations SET state=?,version=version+1,charged_e8_usd=?,usage_present=CASE WHEN ?='completed' THEN 1 ELSE usage_present END,reconciled_at=? WHERE request_id=? AND state='unknown' AND version=? AND version<?").bind(to,input.decision==="charge"?charge.toString():null,to,now(),row.request_id,row.version,MAX_VERSION),this.guard(g2),
      this.eventInsert(input.operation_id,kind,input,"unknown",to,rv,{evidenceDigest:input.evidence_digest}),this.ledgerInsert(input.operation_id,kind,input,refund,user.balance_e8_usd,after.toString(),user.balance_version,rv,input.evidence_digest),this.env.DB.prepare("DELETE FROM billing_cas_guards WHERE guard_id IN (?,?)").bind(g1,g2),
    ]);return {kind:"ok",state:to,replayed:false};}catch{return (await this.replay(input,{kind,from:"unknown",to,evidenceDigest:input.evidence_digest}))??{kind:"out_of_order"};}
  }
  async dispatch(raw: unknown): Promise<BillingResult> {
    const request = ownRecord(raw,["action","input"]);
    if (!request || typeof request.action !== "string") return {kind:"mismatch"};
    switch (request.action) {
      case "reserve": return this.reserve(request.input);
      case "start": return this.start(request.input);
      case "complete": return this.complete(request.input);
      case "release": return this.release(request.input);
      case "expire": return this.expire(request.input);
      case "reconcile": return this.reconcile(request.input);
      default: return {kind:"mismatch"};
    }
  }
}
