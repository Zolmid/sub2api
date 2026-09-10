import { canonical, sha256 } from "./contracts";

const MAX = 9223372036854775807n;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$/;
const KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DEC = /^(?:0|[1-9][0-9]{0,18})$/;
const VER = /^[1-9][0-9]{0,18}$/;
const PS = ["created", "authorized", "succeeded", "failed", "manual_review", "refunded"] as const;
const RS = ["created", "succeeded", "failed", "manual_review"] as const;

export type PaymentState = (typeof PS)[number];
export type RefundState = (typeof RS)[number];
export type PaymentRecord = Readonly<{
  payment_id: string;
  account_id: string;
  amount_e8: string;
  refunded_e8: string;
  pending_refund_e8: string;
  currency: "USD";
  state: PaymentState;
  version: string;
  created_at: string;
  updated_at: string;
}>;
export type RefundRecord = Readonly<{
  refund_id: string;
  payment_id: string;
  amount_e8: string;
  state: RefundState;
  version: string;
  created_at: string;
  updated_at: string;
}>;
export type PaymentResult =
  | { ok: true; payment: PaymentRecord; refund?: RefundRecord }
  | {
      ok: false;
      code:
        | "INVALID_INPUT"
        | "CONFLICT"
        | "IDEMPOTENCY_COLLISION"
        | "NOT_FOUND"
        | "ILLEGAL_TRANSITION"
        | "OVER_REFUND"
        | "CORRUPT_STATE"
        | "UNAVAILABLE";
    };

type Row = Record<string, unknown>;
type Clock = () => number;
type Load<T> = { v?: T; e?: "NOT_FOUND" | "CORRUPT_STATE" | "UNAVAILABLE" };

const id = () => crypto.randomUUID().replaceAll("-", "");
const isId = (v: unknown): v is string => typeof v === "string" && ID.test(v);
const isKey = (v: unknown): v is string => typeof v === "string" && KEY.test(v);
const isMoney = (v: unknown, allowZero = false): v is string =>
  typeof v === "string" && DEC.test(v) && BigInt(v) <= MAX && (allowZero || v !== "0");
const isVer = (v: unknown): v is string => typeof v === "string" && VER.test(v) && BigInt(v) <= MAX;
const isUtc = (v: unknown): v is string => {
  if (typeof v !== "string" || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(v))
    return false;
  const d = new Date(v);
  return Number.isFinite(d.valueOf()) && d.toISOString() === v;
};
const isPs = (v: unknown): v is PaymentState => typeof v === "string" && (PS as readonly string[]).includes(v);
const isRs = (v: unknown): v is RefundState => typeof v === "string" && (RS as readonly string[]).includes(v);
const next = (v: string) => (BigInt(v) < MAX ? String(BigInt(v) + 1n) : null);

const allowed = (v: unknown, keys: readonly string[]): Row | null => {
  try {
    if (!v || typeof v !== "object" || Array.isArray(v) || Object.getPrototypeOf(v) !== Object.prototype) return null;
    const o: Row = {};
    for (const k of Reflect.ownKeys(v)) {
      if (typeof k !== "string" || !keys.includes(k)) return null;
      const d = Object.getOwnPropertyDescriptor(v, k);
      if (!d?.enumerable || !("value" in d)) return null;
      o[k] = d.value;
    }
    return keys.every((k) => k in o) ? o : null;
  } catch {
    return null;
  }
};

const readP = (r: Row | null): PaymentRecord | null => {
  if (
    !r ||
    !isId(r.payment_id) ||
    !isId(r.account_id) ||
    !isMoney(r.amount_e8) ||
    !isMoney(r.refunded_e8, true) ||
    !isMoney(r.pending_refund_e8, true) ||
    r.currency !== "USD" ||
    !isPs(r.state) ||
    !isVer(r.version) ||
    !isUtc(r.created_at) ||
    !isUtc(r.updated_at)
  )
    return null;
  const p = r as PaymentRecord;
  if (BigInt(p.refunded_e8) + BigInt(p.pending_refund_e8) > BigInt(p.amount_e8)) return null;
  if (p.state === "refunded" && p.refunded_e8 !== p.amount_e8) return null;
  if (["created", "authorized", "failed", "manual_review"].includes(p.state) && p.pending_refund_e8 !== "0")
    return null;
  return p;
};

const readR = (r: Row | null): RefundRecord | null =>
  !r ||
  !isId(r.refund_id) ||
  !isId(r.payment_id) ||
  !isMoney(r.amount_e8) ||
  !isRs(r.state) ||
  !isVer(r.version) ||
  !isUtc(r.created_at) ||
  !isUtc(r.updated_at)
    ? null
    : (r as RefundRecord);

const payEdge = (a: PaymentState, b: PaymentState) =>
  (a === "created" && ["authorized", "succeeded", "failed", "manual_review"].includes(b)) ||
  (a === "authorized" && ["succeeded", "failed", "manual_review"].includes(b)) ||
  (a === "manual_review" && ["authorized", "succeeded", "failed"].includes(b));

const refEdge = (a: RefundState, b: RefundState) =>
  (a === "created" && ["succeeded", "failed", "manual_review"].includes(b)) ||
  (a === "manual_review" && ["succeeded", "failed"].includes(b));

const hash = async (v: unknown) => sha256(canonical(v));

export class PaymentRuntime {
  constructor(
    private readonly db: D1Database,
    private readonly clock: Clock = Date.now
  ) {}

  private at(): string | null {
    try {
      const t = new Date(this.clock()).toISOString();
      return isUtc(t) ? t : null;
    } catch {
      return null;
    }
  }

  private async p(payment_id: string): Promise<Load<PaymentRecord>> {
    try {
      const r = await this.db.prepare("SELECT * FROM payment_records WHERE payment_id=?").bind(payment_id).first<Row>();
      if (!r) return { e: "NOT_FOUND" };
      const v = readP(r);
      return v ? { v } : { e: "CORRUPT_STATE" };
    } catch {
      return { e: "UNAVAILABLE" };
    }
  }

  private async r(refund_id: string): Promise<Load<RefundRecord>> {
    try {
      const r = await this.db
        .prepare("SELECT * FROM payment_refund_records WHERE refund_id=?")
        .bind(refund_id)
        .first<Row>();
      if (!r) return { e: "NOT_FOUND" };
      const v = readR(r);
      return v ? { v } : { e: "CORRUPT_STATE" };
    } catch {
      return { e: "UNAVAILABLE" };
    }
  }

  private err<T>(x: Load<T>): PaymentResult | undefined {
    return x.e ? { ok: false, code: x.e } : undefined;
  }

  private guard() {
    const g = id();
    return [
      this.db.prepare("INSERT INTO payment_batch_guards(guard_id,matched) VALUES(?,changes())").bind(g),
      this.db.prepare("DELETE FROM payment_batch_guards WHERE guard_id=?").bind(g),
    ] as const;
  }

  private artifacts(
    p: PaymentRecord,
    r: RefundRecord | undefined,
    action: string,
    previous: string | null,
    semantic: string,
    at: string,
    topic: "payment.changed" | "refund.changed"
  ) {
    const audit = id();
    const outbox = id();
    return {
      audit,
      outbox,
      s: [
        this.db
          .prepare(
            "INSERT INTO payment_audit_events(event_id,payment_id,refund_id,action,previous_state,next_state,version,semantic_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?)"
          )
          .bind(audit, p.payment_id, r?.refund_id ?? null, action, previous, r?.state ?? p.state, r?.version ?? p.version, semantic, at),
        this.db
          .prepare(
            "INSERT INTO payment_outbox_events(event_id,payment_id,refund_id,topic,semantic_digest,created_at) VALUES(?,?,?,?,?,?)"
          )
          .bind(outbox, p.payment_id, r?.refund_id ?? null, topic, semantic, at),
      ],
    };
  }

  private async witness(
    op: string,
    key: string,
    semantic: string,
    p: PaymentRecord,
    r: RefundRecord | undefined,
    at: string,
    e: { audit: string; outbox: string }
  ) {
    const json = canonical({ payment: p, refund: r ?? null });
    const result = await sha256(json);
    return this.db
      .prepare(
        "INSERT INTO payment_idempotency_witnesses(operation,idempotency_key,semantic_digest,payment_id,refund_id,snapshot_json,result_digest,audit_event_id,outbox_event_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)"
      )
      .bind(op, key, semantic, p.payment_id, r?.refund_id ?? null, json, result, e.audit, e.outbox, at);
  }

  private evidence(op: string, p: PaymentRecord, r: RefundRecord | undefined) {
    const action =
      op === "create"
        ? "payment_created"
        : op === "transition"
          ? "payment_transitioned"
          : op === "refund_create"
            ? "refund_created"
            : op === "refund_transition"
              ? "refund_transitioned"
              : op === "refund"
                ? "refund_succeeded"
                : op === "provider_event"
                  ? "provider_event_accepted"
                  : null;
    if (!action) return null;
    const topic = r ? "refund.changed" : "payment.changed";
    const paymentLedger = (op === "transition" || op === "provider_event") && p.state === "succeeded";
    const refundLedger = (op === "refund" || op === "refund_transition") && r?.state === "succeeded";
    return {
      action,
      topic,
      next_state: r?.state ?? p.state,
      version: r?.version ?? p.version,
      ledger: paymentLedger
        ? { refund_id: null, kind: "payment_settlement", debit: "customer_cash", credit: "merchant_revenue", amount_e8: p.amount_e8 }
        : refundLedger
          ? { refund_id: r.refund_id, kind: "refund_settlement", debit: "refund_liability", credit: "customer_cash", amount_e8: r.amount_e8 }
          : null,
    };
  }

  private async replay(op: string, key: string, semantic: string): Promise<PaymentResult | null> {
    try {
      const w = await this.db
        .prepare("SELECT * FROM payment_idempotency_witnesses WHERE operation=? AND idempotency_key=?")
        .bind(op, key)
        .first<Row>();
      if (!w) return null;
      if (w.semantic_digest !== semantic) return { ok: false, code: "IDEMPOTENCY_COLLISION" };
      if (
        !isId(w.payment_id as any) ||
        (w.refund_id !== null && !isId(w.refund_id as any)) ||
        typeof w.snapshot_json !== "string" ||
        typeof w.result_digest !== "string" ||
        !isId(w.audit_event_id as any) ||
        !isId(w.outbox_event_id as any)
      )
        return { ok: false, code: "CORRUPT_STATE" };
      if ((await sha256(w.snapshot_json)) !== w.result_digest) return { ok: false, code: "CORRUPT_STATE" };
      let x: unknown;
      try {
        x = JSON.parse(w.snapshot_json);
      } catch {
        return { ok: false, code: "CORRUPT_STATE" };
      }
      const o = allowed(x, ["payment", "refund"]);
      const p = o ? readP(o.payment as Row) : null;
      const r = o && o.refund !== null ? readR(o.refund as Row) ?? undefined : undefined;
      if (!o || !p || (o.refund !== null && !r) || p.payment_id !== w.payment_id || (r?.refund_id ?? null) !== w.refund_id)
        return { ok: false, code: "CORRUPT_STATE" };
      const expected = this.evidence(op, p, r);
      if (!expected) return { ok: false, code: "CORRUPT_STATE" };
      const statements = [
        this.db
          .prepare("SELECT payment_id,refund_id,action,next_state,version,semantic_digest FROM payment_audit_events WHERE event_id=?")
          .bind(w.audit_event_id),
        this.db
          .prepare("SELECT payment_id,refund_id,topic,semantic_digest FROM payment_outbox_events WHERE event_id=?")
          .bind(w.outbox_event_id),
      ];
      if (expected.ledger)
        statements.push(
          this.db
            .prepare("SELECT payment_id,refund_id,kind,debit_account,credit_account,amount_e8 FROM payment_ledger_transactions WHERE payment_id=? AND refund_id IS ? AND kind=?")
            .bind(p.payment_id, expected.ledger.refund_id, expected.ledger.kind)
        );
      const [a, b, ledger] = await this.db.batch(statements);
      const ar = a.results[0] as Row | undefined;
      const br = b.results[0] as Row | undefined;
      const lr = ledger?.results[0] as Row | undefined;
      if (
        !ar ||
        !br ||
        ar.payment_id !== p.payment_id ||
        br.payment_id !== p.payment_id ||
        ar.refund_id !== (r?.refund_id ?? null) ||
        br.refund_id !== (r?.refund_id ?? null) ||
        ar.action !== expected.action ||
        ar.next_state !== expected.next_state ||
        ar.version !== expected.version ||
        br.topic !== expected.topic ||
        ar.semantic_digest !== semantic ||
        br.semantic_digest !== semantic ||
        (expected.ledger &&
          (!lr ||
            lr.payment_id !== p.payment_id ||
            lr.refund_id !== expected.ledger.refund_id ||
            lr.kind !== expected.ledger.kind ||
            lr.debit_account !== expected.ledger.debit ||
            lr.credit_account !== expected.ledger.credit ||
            lr.amount_e8 !== expected.ledger.amount_e8))
      )
        return { ok: false, code: "CORRUPT_STATE" };
      return { ok: true, payment: p, ...(r ? { refund: r } : {}) };
    } catch {
      return { ok: false, code: "UNAVAILABLE" };
    }
  }

  private async batch(s: D1PreparedStatement[]): Promise<boolean> {
    try {
      await this.db.batch(s);
      return true;
    } catch {
      return false;
    }
  }

  private async afterFailure(
    op: string,
    key: string,
    semantic: string,
    paymentId: string,
    before: PaymentRecord | undefined
  ): Promise<PaymentResult> {
    const replayed = await this.replay(op, key, semantic);
    if (replayed) return replayed;
    const authority = await this.p(paymentId);
    const error = this.err(authority);
    if (error) {
      // A create begins with no authority, so its missing post-failure row only
      // proves that the failed batch committed nothing; it is not NOT_FOUND.
      return !before && authority.e === "NOT_FOUND" ? { ok: false, code: "UNAVAILABLE" } : error;
    }
    if (!before) return { ok: false, code: "CONFLICT" };
    return canonical(authority.v) === canonical(before)
      ? { ok: false, code: "UNAVAILABLE" }
      : { ok: false, code: "CONFLICT" };
  }

  async create(input: unknown): Promise<PaymentResult> {
    const x = allowed(input, ["payment_id", "account_id", "amount_e8", "idempotency_key"]);
    if (!x || !isId(x.payment_id) || !isId(x.account_id) || !isMoney(x.amount_e8) || !isKey(x.idempotency_key))
      return { ok: false, code: "INVALID_INPUT" };
    const paymentId = x.payment_id as string;
    const semantic = await hash({ payment_id: x.payment_id, account_id: x.account_id, amount_e8: x.amount_e8, currency: "USD" });
    const old = await this.replay("create", x.idempotency_key as string, semantic);
    if (old) return old;
    const at = this.at();
    if (!at) return { ok: false, code: "UNAVAILABLE" };
    const p: PaymentRecord = {
      payment_id: paymentId,
      account_id: x.account_id as string,
      amount_e8: x.amount_e8 as string,
      refunded_e8: "0",
      pending_refund_e8: "0",
      currency: "USD",
      state: "created",
      version: "1",
      created_at: at,
      updated_at: at,
    };
    const e = this.artifacts(p, undefined, "payment_created", null, semantic, at, "payment.changed");
    const w = await this.witness("create", x.idempotency_key as string, semantic, p, undefined, at, e);
    const ok = await this.batch([
      this.db
        .prepare(
          "INSERT INTO payment_records(payment_id,account_id,amount_e8,refunded_e8,pending_refund_e8,currency,state,version,created_at,updated_at) VALUES(?,?,?,'0','0','USD','created','1',?,?)"
        )
        .bind(p.payment_id, p.account_id, p.amount_e8, at, at),
      ...e.s,
      w,
    ]);
    return ok ? { ok: true, payment: p } : this.afterFailure("create", x.idempotency_key as string, semantic, paymentId, undefined);
  }

  async transition(input: unknown): Promise<PaymentResult> {
    const x = allowed(input, ["payment_id", "next_state", "expected_version", "idempotency_key"]);
    if (
      !x ||
      !isId(x.payment_id) ||
      !isPs(x.next_state) ||
      !isVer(x.expected_version) ||
      !isKey(x.idempotency_key)
    )
      return { ok: false, code: "INVALID_INPUT" };
    const semantic = await hash({
      payment_id: x.payment_id,
      next_state: x.next_state,
      expected_version: x.expected_version,
    });
    const old = await this.replay("transition", x.idempotency_key as string, semantic);
    if (old) return old;
    const l = await this.p(x.payment_id as string);
    const er = this.err(l);
    if (er) return er;
    const before = l.v!;
    if (before.version !== x.expected_version) return { ok: false, code: "CONFLICT" };
    if (!payEdge(before.state, x.next_state as PaymentState)) return { ok: false, code: "ILLEGAL_TRANSITION" };
    const v = next(before.version);
    const at = this.at();
    if (!v) return { ok: false, code: "CORRUPT_STATE" };
    if (!at) return { ok: false, code: "UNAVAILABLE" };
    const p = { ...before, state: x.next_state, version: v, updated_at: at } as PaymentRecord;
    const [g, clear] = this.guard();
    const e = this.artifacts(p, undefined, "payment_transitioned", before.state, semantic, at, "payment.changed");
    const ledger =
      x.next_state === "succeeded"
        ? [
            this.db
              .prepare(
                "INSERT INTO payment_ledger_transactions(ledger_id,payment_id,refund_id,kind,debit_account,credit_account,amount_e8,created_at) VALUES(?,?,NULL,'payment_settlement','customer_cash','merchant_revenue',?,?)"
              )
              .bind(id(), p.payment_id, p.amount_e8, at),
          ]
        : [];
    const w = await this.witness("transition", x.idempotency_key as string, semantic, p, undefined, at, e);
    const ok = await this.batch([
      this.db
        .prepare("UPDATE payment_records SET state=?,version=CAST(CAST(version AS INTEGER)+1 AS TEXT),updated_at=? WHERE payment_id=? AND version=? AND state=?")
        .bind(p.state, at, p.payment_id, before.version, before.state),
      g,
      ...ledger,
      ...e.s,
      w,
      clear,
    ]);
    return ok ? { ok: true, payment: p } : this.afterFailure("transition", x.idempotency_key as string, semantic, p.payment_id, before);
  }

  async createRefund(input: unknown): Promise<PaymentResult> {
    const x = allowed(input, ["refund_id", "payment_id", "amount_e8", "expected_payment_version", "idempotency_key"]);
    if (
      !x ||
      !isId(x.refund_id) ||
      !isId(x.payment_id) ||
      !isMoney(x.amount_e8) ||
      !isVer(x.expected_payment_version) ||
      !isKey(x.idempotency_key)
    )
      return { ok: false, code: "INVALID_INPUT" };
    const semantic = await hash({
      refund_id: x.refund_id,
      payment_id: x.payment_id,
      amount_e8: x.amount_e8,
      expected_payment_version: x.expected_payment_version,
      state: "created",
    });
    const old = await this.replay("refund_create", x.idempotency_key as string, semantic);
    if (old) return old;
    const l = await this.p(x.payment_id as string);
    const er = this.err(l);
    if (er) return er;
    const before = l.v!;
    if (before.version !== x.expected_payment_version) return { ok: false, code: "CONFLICT" };
    if (before.state !== "succeeded") return { ok: false, code: "ILLEGAL_TRANSITION" };
    const pending = BigInt(before.pending_refund_e8) + BigInt(x.amount_e8 as string);
    if (BigInt(before.refunded_e8) + pending > BigInt(before.amount_e8)) return { ok: false, code: "OVER_REFUND" };
    const v = next(before.version);
    const at = this.at();
    if (!v) return { ok: false, code: "CORRUPT_STATE" };
    if (!at) return { ok: false, code: "UNAVAILABLE" };
    const p = { ...before, pending_refund_e8: String(pending), version: v, updated_at: at };
    const r: RefundRecord = {
      refund_id: x.refund_id as string,
      payment_id: x.payment_id as string,
      amount_e8: x.amount_e8 as string,
      state: "created",
      version: "1",
      created_at: at,
      updated_at: at,
    };
    const [g, clear] = this.guard();
    const e = this.artifacts(p, r, "refund_created", null, semantic, at, "refund.changed");
    const w = await this.witness("refund_create", x.idempotency_key as string, semantic, p, r, at, e);
    const ok = await this.batch([
      this.db
        .prepare("UPDATE payment_records SET pending_refund_e8=?,version=CAST(CAST(version AS INTEGER)+1 AS TEXT),updated_at=? WHERE payment_id=? AND version=? AND state='succeeded'")
        .bind(p.pending_refund_e8, at, p.payment_id, before.version),
      g,
      this.db
        .prepare(
          "INSERT INTO payment_refund_records(refund_id,payment_id,amount_e8,state,version,created_at,updated_at) VALUES(?,?,?,'created','1',?,?)"
        )
        .bind(r.refund_id, r.payment_id, r.amount_e8, at, at),
      ...e.s,
      w,
      clear,
    ]);
    return ok ? { ok: true, payment: p, refund: r } : this.afterFailure("refund_create", x.idempotency_key as string, semantic, p.payment_id, before);
  }

  async transitionRefund(input: unknown): Promise<PaymentResult> {
    const x = allowed(input, [
      "refund_id",
      "payment_id",
      "next_state",
      "expected_payment_version",
      "expected_refund_version",
      "idempotency_key",
    ]);
    if (
      !x ||
      !isId(x.refund_id) ||
      !isId(x.payment_id) ||
      !isRs(x.next_state) ||
      !isVer(x.expected_payment_version) ||
      !isVer(x.expected_refund_version) ||
      !isKey(x.idempotency_key)
    )
      return { ok: false, code: "INVALID_INPUT" };
    const semantic = await hash({
      refund_id: x.refund_id,
      payment_id: x.payment_id,
      next_state: x.next_state,
      expected_payment_version: x.expected_payment_version,
      expected_refund_version: x.expected_refund_version,
    });
    const old = await this.replay("refund_transition", x.idempotency_key as string, semantic);
    if (old) return old;
    const pl = await this.p(x.payment_id as string);
    const rl = await this.r(x.refund_id as string);
    const pe = this.err(pl);
    const re = this.err(rl);
    if (pe) return pe;
    if (re) return re;
    const before = pl.v!;
    const rb = rl.v!;
    if (rb.payment_id !== before.payment_id) return { ok: false, code: "CORRUPT_STATE" };
    if (before.version !== x.expected_payment_version || rb.version !== x.expected_refund_version)
      return { ok: false, code: "CONFLICT" };
    if (before.state !== "succeeded" || !refEdge(rb.state, x.next_state as RefundState))
      return { ok: false, code: "ILLEGAL_TRANSITION" };
    const amount = BigInt(rb.amount_e8);
    if (BigInt(before.pending_refund_e8) < amount) return { ok: false, code: "CORRUPT_STATE" };
    const pv = next(before.version);
    const rv = next(rb.version);
    const at = this.at();
    if (!pv || !rv) return { ok: false, code: "CORRUPT_STATE" };
    if (!at) return { ok: false, code: "UNAVAILABLE" };

    // FIX: Compute final payment state WITHOUT relying on trigger projection
    let pendingResult: bigint;
    let refundedResult: bigint;
    if (x.next_state === "manual_review") {
      // manual_review: RETAIN the reservation (no change to pending or refunded)
      pendingResult = BigInt(before.pending_refund_e8);
      refundedResult = BigInt(before.refunded_e8);
    } else if (x.next_state === "failed") {
      // failed: RELEASE the reservation
      pendingResult = BigInt(before.pending_refund_e8) - amount;
      refundedResult = BigInt(before.refunded_e8);
    } else {
      // succeeded: SETTLE (move from pending to refunded)
      pendingResult = BigInt(before.pending_refund_e8) - amount;
      refundedResult = BigInt(before.refunded_e8) + amount;
    }
    if (refundedResult > BigInt(before.amount_e8)) return { ok: false, code: "CORRUPT_STATE" };

    const p = {
      ...before,
      pending_refund_e8: String(pendingResult),
      refunded_e8: String(refundedResult),
      state: refundedResult === BigInt(before.amount_e8) ? "refunded" : "succeeded",
      version: pv,
      updated_at: at,
    } as PaymentRecord;
    const r = { ...rb, state: x.next_state, version: rv, updated_at: at } as RefundRecord;
    const [g, clear] = this.guard();
    const e = this.artifacts(p, r, "refund_transitioned", rb.state, semantic, at, "refund.changed");
    const ledger =
      x.next_state === "succeeded"
        ? [
            this.db
              .prepare(
                "INSERT INTO payment_ledger_transactions(ledger_id,payment_id,refund_id,kind,debit_account,credit_account,amount_e8,created_at) VALUES(?,?,?,'refund_settlement','refund_liability','customer_cash',?,?)"
              )
              .bind(id(), p.payment_id, r.refund_id, r.amount_e8, at),
          ]
        : [];
    const w = await this.witness("refund_transition", x.idempotency_key as string, semantic, p, r, at, e);
    const ok = await this.batch([
      this.db
        .prepare(
          "UPDATE payment_records SET refunded_e8=?,pending_refund_e8=?,state=?,version=CAST(CAST(version AS INTEGER)+1 AS TEXT),updated_at=? WHERE payment_id=? AND version=? AND state='succeeded' AND EXISTS(SELECT 1 FROM payment_refund_records WHERE refund_id=? AND payment_id=? AND version=? AND state=?)"
        )
        .bind(p.refunded_e8, p.pending_refund_e8, p.state, at, p.payment_id, before.version, r.refund_id, p.payment_id, rb.version, rb.state),
      g,
      this.db
        .prepare("UPDATE payment_refund_records SET state=?,version=CAST(CAST(version AS INTEGER)+1 AS TEXT),updated_at=? WHERE refund_id=? AND payment_id=? AND version=? AND state=?")
        .bind(r.state, at, r.refund_id, p.payment_id, rb.version, rb.state),
      ...ledger,
      ...e.s,
      w,
      clear,
    ]);
    return ok ? { ok: true, payment: p, refund: r } : this.afterFailure("refund_transition", x.idempotency_key as string, semantic, p.payment_id, before);
  }

  async refundPayment(input: unknown): Promise<PaymentResult> {
    const x = allowed(input, ["refund_id", "payment_id", "amount_e8", "expected_payment_version", "idempotency_key"]);
    if (
      !x ||
      !isId(x.refund_id) ||
      !isId(x.payment_id) ||
      !isMoney(x.amount_e8) ||
      !isVer(x.expected_payment_version) ||
      !isKey(x.idempotency_key)
    )
      return { ok: false, code: "INVALID_INPUT" };
    const semantic = await hash({
      refund_id: x.refund_id,
      payment_id: x.payment_id,
      amount_e8: x.amount_e8,
      expected_payment_version: x.expected_payment_version,
      state: "succeeded",
    });
    const old = await this.replay("refund", x.idempotency_key as string, semantic);
    if (old) return old;
    const pl = await this.p(x.payment_id as string);
    const pe = this.err(pl);
    if (pe) return pe;
    const before = pl.v!;
    if (before.version !== x.expected_payment_version) return { ok: false, code: "CONFLICT" };
    if (before.state !== "succeeded") return { ok: false, code: "ILLEGAL_TRANSITION" };
    const used = BigInt(before.refunded_e8) + BigInt(before.pending_refund_e8) + BigInt(x.amount_e8 as string);
    if (used > BigInt(before.amount_e8)) return { ok: false, code: "OVER_REFUND" };
    const pv = next(before.version);
    const at = this.at();
    if (!pv) return { ok: false, code: "CORRUPT_STATE" };
    if (!at) return { ok: false, code: "UNAVAILABLE" };
    const refunded = BigInt(before.refunded_e8) + BigInt(x.amount_e8 as string);
    const p = {
      ...before,
      refunded_e8: String(refunded),
      state: refunded === BigInt(before.amount_e8) ? "refunded" : "succeeded",
      version: pv,
      updated_at: at,
    } as PaymentRecord;
    const r: RefundRecord = {
      refund_id: x.refund_id as string,
      payment_id: x.payment_id as string,
      amount_e8: x.amount_e8 as string,
      state: "succeeded",
      version: "1",
      created_at: at,
      updated_at: at,
    };
    const [g, clear] = this.guard();
    const e = this.artifacts(p, r, "refund_succeeded", null, semantic, at, "refund.changed");
    const w = await this.witness("refund", x.idempotency_key as string, semantic, p, r, at, e);
    const ok = await this.batch([
      this.db
        .prepare("UPDATE payment_records SET refunded_e8=?,state=?,version=CAST(CAST(version AS INTEGER)+1 AS TEXT),updated_at=? WHERE payment_id=? AND version=? AND state='succeeded'")
        .bind(p.refunded_e8, p.state, at, p.payment_id, before.version),
      g,
      this.db
        .prepare(
          "INSERT INTO payment_refund_records(refund_id,payment_id,amount_e8,state,version,created_at,updated_at) VALUES(?,?,?,'succeeded','1',?,?)"
        )
        .bind(r.refund_id, r.payment_id, r.amount_e8, at, at),
      this.db
        .prepare(
          "INSERT INTO payment_ledger_transactions(ledger_id,payment_id,refund_id,kind,debit_account,credit_account,amount_e8,created_at) VALUES(?,?,?,'refund_settlement','refund_liability','customer_cash',?,?)"
        )
        .bind(id(), p.payment_id, r.refund_id, r.amount_e8, at),
      ...e.s,
      w,
      clear,
    ]);
    return ok ? { ok: true, payment: p, refund: r } : this.afterFailure("refund", x.idempotency_key as string, semantic, p.payment_id, before);
  }

  async acceptProviderEvent(input: unknown): Promise<PaymentResult> {
    const x = allowed(input, ["provider_event_id", "payment_id", "next_state", "expected_version"]);
    if (
      !x ||
      !isKey(x.provider_event_id) ||
      !isId(x.payment_id) ||
      !isPs(x.next_state) ||
      !isVer(x.expected_version)
    )
      return { ok: false, code: "INVALID_INPUT" };
    const semantic = await hash({
      provider_event_id: x.provider_event_id,
      payment_id: x.payment_id,
      next_state: x.next_state,
      expected_version: x.expected_version,
    });
    try {
      const [dedup, witness] = await this.db.batch([
        this.db
          .prepare("SELECT semantic_digest,payment_id FROM payment_provider_event_dedup WHERE provider_event_id=?")
          .bind(x.provider_event_id),
        this.db
          .prepare("SELECT semantic_digest,payment_id FROM payment_idempotency_witnesses WHERE operation='provider_event' AND idempotency_key=?")
          .bind(x.provider_event_id),
      ]);
      const d = dedup.results[0] as Row | undefined;
      const w = witness.results[0] as Row | undefined;
      if (Boolean(d) !== Boolean(w)) return { ok: false, code: "CORRUPT_STATE" };
      if (d && w) {
        if (
          typeof d.semantic_digest !== "string" ||
          typeof w.semantic_digest !== "string" ||
          d.semantic_digest !== w.semantic_digest ||
          d.payment_id !== w.payment_id
        )
          return { ok: false, code: "CORRUPT_STATE" };
        return (
          (await this.replay("provider_event", x.provider_event_id as string, semantic)) ?? {
            ok: false,
            code: "CORRUPT_STATE" as const,
          }
        );
      }
    } catch {
      return { ok: false, code: "UNAVAILABLE" };
    }
    const pl = await this.p(x.payment_id as string);
    const pe = this.err(pl);
    if (pe) return pe;
    const before = pl.v!;
    if (before.version !== x.expected_version) return { ok: false, code: "CONFLICT" };
    if (!payEdge(before.state, x.next_state as PaymentState)) return { ok: false, code: "ILLEGAL_TRANSITION" };
    const pv = next(before.version);
    const at = this.at();
    if (!pv) return { ok: false, code: "CORRUPT_STATE" };
    if (!at) return { ok: false, code: "UNAVAILABLE" };
    const p = { ...before, state: x.next_state, version: pv, updated_at: at } as PaymentRecord;
    const [g, clear] = this.guard();
    const e = this.artifacts(p, undefined, "provider_event_accepted", before.state, semantic, at, "payment.changed");
    const w = await this.witness("provider_event", x.provider_event_id as string, semantic, p, undefined, at, e);
    const settle =
      x.next_state === "succeeded"
        ? [
            this.db
              .prepare(
                "INSERT INTO payment_ledger_transactions(ledger_id,payment_id,refund_id,kind,debit_account,credit_account,amount_e8,created_at) VALUES(?,?,NULL,'payment_settlement','customer_cash','merchant_revenue',?,?)"
              )
              .bind(id(), p.payment_id, p.amount_e8, at),
          ]
        : [];
    const ok = await this.batch([
      this.db
        .prepare("UPDATE payment_records SET state=?,version=CAST(CAST(version AS INTEGER)+1 AS TEXT),updated_at=? WHERE payment_id=? AND version=? AND state=?")
        .bind(p.state, at, p.payment_id, before.version, before.state),
      g,
      this.db
        .prepare(
          "INSERT INTO payment_provider_event_dedup(provider_event_id,semantic_digest,payment_id,created_at) VALUES(?,?,?,?)"
        )
        .bind(x.provider_event_id, semantic, p.payment_id, at),
      ...settle,
      ...e.s,
      w,
      clear,
    ]);
    return ok ? { ok: true, payment: p } : this.afterFailure("provider_event", x.provider_event_id as string, semantic, p.payment_id, before);
  }
}
