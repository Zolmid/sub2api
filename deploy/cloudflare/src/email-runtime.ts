/** D1 authority for one-time email challenges. No provider call lives here. */
const MAX = 9_223_372_036_854_775_807n;
const E = new TextEncoder();
const D = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const ID = /^[a-z0-9][a-z0-9_-]{7,127}$/;
const SMALL = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const B64 = /^[A-Za-z0-9_-]+$/;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

type Row = Record<string, unknown>;
type Key = Readonly<{ id: string; material: Uint8Array }>;
type Envelope = Readonly<{ keyId: string; nonce: string; ciphertext: string }>;
type Event =
  | "issued"
  | "rejected"
  | "expired"
  | "consumed"
  | "claimed"
  | "renewed"
  | "delivered"
  | "retry_scheduled"
  | "dead"
  | "cancelled";

export interface RotatingKey {
  id: string;
  material: Uint8Array;
}

export interface EmailKeyring {
  token: { current: RotatingKey; previous?: readonly RotatingKey[] };
  delivery: { current: RotatingKey; previous?: readonly RotatingKey[] };
}

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

export interface IssueChallengeInput {
  id: string;
  accountId: string;
  purpose: string;
  idempotencyKey: string;
  deliveryReference: string;
  expiresAt: string;
  maxAttempts?: number;
  maxDeliveryAttempts?: number;
}

export interface IssuedChallenge {
  id: string;
  token?: string;
  expiresAt: string;
  replayed: boolean;
}

export interface VerifyChallengeInput {
  id: string;
  accountId: string;
  purpose: string;
  token: string;
}

export interface EmailJobClaim {
  id: string;
  challengeId: string;
  fence: string;
  token: string;
  deliveryReference: string;
}

export class EmailRuntimeError extends Error {
  readonly retryable: boolean;
  readonly terminal: boolean;

  constructor(
    readonly code:
      | "invalid_input"
      | "clock_failure"
      | "challenge_not_found"
      | "challenge_expired"
      | "challenge_consumed"
      | "invalid_token"
      | "idempotency_collision"
      | "idempotency_corrupt"
      | "job_not_found"
      | "stale_fence"
      | "counter_exhausted"
      | "unknown_key_id"
      | "corrupt_state"
      | "storage_failure"
  ) {
    super(code);
    this.retryable = code === "stale_fence" || code === "storage_failure";
    this.terminal = !this.retryable;
  }
}

const fail = (code: EmailRuntimeError["code"]): never => {
  throw new EmailRuntimeError(code);
};

function text(v: unknown, max: number): v is string {
  if (typeof v !== "string" || v.includes("\0") || E.encode(v).byteLength > max) {
    return false;
  }
  for (let i = 0; i < v.length; i++) {
    const n = v.charCodeAt(i);
    if (n >= 0xd800 && n <= 0xdbff) {
      if (++i >= v.length || v.charCodeAt(i) < 0xdc00 || v.charCodeAt(i) > 0xdfff) {
        return false;
      }
    } else if (n >= 0xdc00 && n <= 0xdfff) {
      return false;
    }
  }
  return true;
}

const inputId = (v: unknown) => (typeof v === "string" && ID.test(v) ? v : fail("invalid_input"));
const inputSmall = (v: unknown) => (typeof v === "string" && SMALL.test(v) ? v : fail("invalid_input"));
const storedId = (v: unknown) => (typeof v === "string" && ID.test(v) ? v : fail("corrupt_state"));
const storedSmall = (v: unknown) => (typeof v === "string" && SMALL.test(v) ? v : fail("corrupt_state"));

function decimal(v: unknown, zero = false): string {
  if (
    typeof v !== "string" ||
    !/^(?:0|[1-9][0-9]{0,18})$/.test(v) ||
    (!zero && v === "0")
  ) {
    fail("corrupt_state");
  }
  const value = v as string;
  try {
    if (BigInt(value) > MAX) {
      fail("corrupt_state");
    }
  } catch {
    fail("corrupt_state");
  }
  return value;
}

function next(v: string): string {
  const n = BigInt(decimal(v));
  if (n === MAX) {
    fail("counter_exhausted");
  }
  return String(n + 1n);
}

export function canonicalUtc(v: string): string {
  if (
    typeof v !== "string" ||
    !UTC.test(v) ||
    !Number.isFinite(Date.parse(v)) ||
    new Date(v).toISOString() !== v
  ) {
    fail("invalid_input");
  }
  return v;
}

function b64(v: Uint8Array): string {
  let s = "";
  for (const b of v) {
    s += String.fromCharCode(b);
  }
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function unb64(v: unknown, exact?: number): Uint8Array {
  if (typeof v !== "string" || !B64.test(v) || v.length % 4 === 1) {
    fail("corrupt_state");
  }
  const value = v as string;
  try {
    const s = atob(
      value.replaceAll("-", "+").replaceAll("_", "/") +
        "=".repeat((4 - (value.length % 4)) % 4)
    );
    const o = Uint8Array.from(s, (c) => c.charCodeAt(0));
    if ((exact !== undefined && o.length !== exact) || b64(o) !== value) {
      fail("corrupt_state");
    }
    return o;
  } catch (e) {
    if (e instanceof EmailRuntimeError) {
      throw e;
    }
    return fail("corrupt_state");
  }
}

const same = (a: Uint8Array, b: Uint8Array) => {
  if (a.length !== b.length) {
    return false;
  }
  let d = 0;
  for (let i = 0; i < a.length; i++) {
    d |= a[i]! ^ b[i]!;
  }
  return d === 0;
};

const uuid = () => crypto.randomUUID().replaceAll("-", "");

function object(v: unknown, keys: readonly string[]): Row {
  if (
    !v ||
    typeof v !== "object" ||
    Array.isArray(v) ||
    Object.getPrototypeOf(v as object) !== Object.prototype
  ) {
    fail("invalid_input");
  }
  const source = v as Record<string, unknown>;
  const out: Row = {};
  for (const key of Reflect.ownKeys(source)) {
    if (typeof key !== "string" || !keys.includes(key)) {
      fail("invalid_input");
    }
    const named = key as string;
    const d = Object.getOwnPropertyDescriptor(source, named);
    if (!d?.enumerable || !("value" in d)) {
      fail("invalid_input");
    }
    out[named] = (d as PropertyDescriptor & { value: unknown }).value;
  }
  return out;
}

function rowB64(v: unknown, n?: number): string {
  try {
    return b64(unb64(v, n));
  } catch {
    return fail("corrupt_state");
  }
}

function rowUtc(v: unknown): string {
  try {
    return canonicalUtc(String(v));
  } catch {
    return fail("corrupt_state");
  }
}

type Challenge = {
  id: string;
  account: string;
  purpose: string;
  tokenKey: string;
  verifier: string;
  token: Envelope;
  delivery: Envelope;
  state: "issued" | "consumed" | "expired";
  failed: number;
  max: number;
  expires: string;
  version: string;
};

type Job = {
  id: string;
  challenge: string;
  state: "pending" | "claimed" | "delivered" | "dead" | "cancelled";
  attempt: number;
  max: number;
  notBefore: string;
  owner: string | null;
  until: string | null;
  fence: string;
  version: string;
};

type DeliveryWitness = {
  jobId: string;
  auditId: string;
  outboxId: string;
  jobVersion: string;
  fence: string;
  evidenceHmac: string;
};


export class EmailRuntime {
  private readonly tokens = new Map<string, Key>();
  private readonly deliveries = new Map<string, Key>();
  private readonly token: Key;
  private readonly delivery: Key;

  constructor(
    private readonly db: D1Database,
    ring: EmailKeyring,
    private readonly clock: Clock = systemClock
  ) {
    const tokens = this.ring(ring.token);
    const deliveries = this.ring(ring.delivery);
    for (const key of tokens.all) {
      this.tokens.set(key.id, key);
    }
    for (const key of deliveries.all) {
      this.deliveries.set(key.id, key);
    }
    for (const a of tokens.all) {
      for (const b of deliveries.all) {
        if (a.id === b.id || same(a.material, b.material)) {
          fail("invalid_input");
        }
      }
    }
    this.token = tokens.current;
    this.delivery = deliveries.current;
  }

  async issueChallenge(raw: unknown): Promise<IssuedChallenge> {
    const x = this.issue(raw);
    const old = await this.first(
      "SELECT * FROM email_issue_idempotency WHERE account_id=? AND idempotency_key=?",
      x.account,
      x.key
    );
    if (old) {
      return this.replay(x, old);
    }

    const semantic = await this.mac(this.token, "email.issue.v1", this.fields(x));
    const token = b64(crypto.getRandomValues(new Uint8Array(32)));
    const aad = this.aad(x);
    const tokenEnvelope = await this.seal(this.delivery, token, aad + "\u001ftoken");
    const deliveryEnvelope = await this.seal(
      this.delivery,
      x.reference,
      aad + "\u001fdelivery-reference"
    );
    const job = uuid();
    const audit = uuid();
    const outbox = uuid();
    const witness = await this.mac(this.token, "email.issue-witness.v1", [
      x.account,
      x.key,
      x.id,
      job,
      audit,
      outbox,
      semantic,
    ]);

    try {
      await this.db.batch([
        this.db
          .prepare(
            "INSERT INTO email_challenges(id,account_id,purpose,token_hmac_key_id,token_verifier,token_envelope_key_id,token_nonce,token_ciphertext,delivery_envelope_key_id,delivery_nonce,delivery_ciphertext,state,failed_attempts,max_attempts,expires_at,created_at,consumed_at,version) VALUES(?,?,?,?,?,?,?,?,?,?,?,'issued',0,?,?,?,NULL,'1')"
          )
          .bind(
            x.id,
            x.account,
            x.purpose,
            this.token.id,
            await this.mac(this.token, "email.token.v1", [x.id, x.account, x.purpose, token]),
            tokenEnvelope.keyId,
            tokenEnvelope.nonce,
            tokenEnvelope.ciphertext,
            deliveryEnvelope.keyId,
            deliveryEnvelope.nonce,
            deliveryEnvelope.ciphertext,
            x.max,
            x.expires,
            x.now
          ),
        this.db
          .prepare(
            "INSERT INTO email_delivery_jobs(id,challenge_id,state,attempt,max_attempts,not_before,lease_owner,lease_until,fence,version,last_error_code,created_at,updated_at) VALUES(?,?,'pending',0,?,?,NULL,NULL,'1','1',NULL,?,?)"
          )
          .bind(job, x.id, x.deliveryMax, x.now, x.now, x.now),
        this.db
          .prepare(
            "INSERT INTO email_issue_idempotency(account_id,idempotency_key,request_hmac_key_id,semantic_hmac,challenge_id,job_id,created_at) VALUES(?,?,?,?,?,?,?)"
          )
          .bind(x.account, x.key, this.token.id, semantic, x.id, job, x.now),
        ...(await this.events(audit, outbox, x.id, null, "issued", "1", null, null, x.now, "created")),
        this.db
          .prepare(
            "INSERT INTO email_issue_witnesses(account_id,idempotency_key,challenge_id,job_id,audit_id,outbox_id,challenge_version,job_version,fence,evidence_hmac) VALUES(?,?,?,?,?,?,'1','1','1',?)"
          )
          .bind(x.account, x.key, x.id, job, audit, outbox, witness),
      ]);
    } catch (e) {
      // D1 reports the first statement that loses an atomic issue race. That
      // can be the caller-supplied challenge id, not the idempotency insert.
      // A replay is safe only if the immutable idempotency authority now exists.
      if (e instanceof Error && /UNIQUE constraint failed/.test(e.message)) {
        const r = await this.first(
          "SELECT * FROM email_issue_idempotency WHERE account_id=? AND idempotency_key=?",
          x.account,
          x.key
        );
        if (r) {
          return this.replay(x, r);
        }
      }
      return this.storage(e);
    }

    return { id: x.id, token, expiresAt: x.expires, replayed: false };
  }

  async verifyChallenge(raw: unknown): Promise<void> {
    const x = object(raw, ["id", "accountId", "purpose", "token"]);
    const id = inputId(x.id);
    const account = inputSmall(x.accountId);
    const purpose = inputSmall(x.purpose);
    if (!text(x.token, 64)) {
      fail("invalid_input");
    }
    const token = x.token as string;
    // A claim and a consume/expiry transition both CAS the challenge and job.
    // Retrying a lost race keeps the final state coherent rather than leaving
    // a newly-consumed challenge with a sendable job.
    for (let attempt = 0; attempt < 3; attempt++) {
      const now = this.now();
      const c = await this.challenge(id, account, purpose);
      if (c.state === "consumed") {
        fail("challenge_consumed");
      }
      if (c.state === "expired") {
        fail("challenge_expired");
      }
      const j = (await this.jobByChallenge(c.id)) ?? fail("corrupt_state");
      if (c.expires <= now) {
        try {
          await this.settleChallenge(c, j, "expired", "expired", now);
        } catch (e) {
          if (e instanceof EmailRuntimeError && e.code === "stale_fence") {
            continue;
          }
          throw e;
        }
        fail("challenge_expired");
      }

      const key = this.tokenKey(c.tokenKey);
      const computed = await this.mac(key, "email.token.v1", [id, account, purpose, token]);
      if (!same(unb64(computed, 32), unb64(c.verifier, 32))) {
        const failed = c.failed + 1;
        try {
          if (failed >= c.max) {
            await this.settleChallenge(c, j, "expired", "expired", now, failed);
          } else {
            await this.changeChallenge(c, "issued", failed, null, "rejected", now);
          }
        } catch (e) {
          if (e instanceof EmailRuntimeError && e.code === "stale_fence") {
            continue;
          }
          throw e;
        }
        fail("invalid_token");
      }

      try {
        await this.settleChallenge(c, j, "consumed", "consumed", now);
        return;
      } catch (e) {
        if (e instanceof EmailRuntimeError && e.code === "stale_fence") {
          continue;
        }
        throw e;
      }
    }
    fail("stale_fence");
  }

  async claimDeliveryJobs(worker: string, limit = 10): Promise<EmailJobClaim[]> {
    inputSmall(worker);
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      fail("invalid_input");
    }

    const now = this.now();
    const rows = await this.all(
      "SELECT j.*,c.account_id,c.purpose,c.state AS challenge_state,c.expires_at,c.token_hmac_key_id,c.token_verifier,c.token_envelope_key_id,c.token_nonce,c.token_ciphertext,c.delivery_envelope_key_id,c.delivery_nonce,c.delivery_ciphertext,c.failed_attempts,c.max_attempts,c.version AS challenge_version FROM email_delivery_jobs j JOIN email_challenges c ON c.id=j.challenge_id WHERE (j.state='pending' AND j.not_before<=?) OR (j.state='claimed' AND j.lease_until<=?) ORDER BY j.not_before,c.id,j.id LIMIT ?",
      now,
      now,
      limit
    );

    const out: EmailJobClaim[] = [];
    for (const row of rows) {
      const j = this.jobRow(row);
      const c = this.challengeRow(row, true);
      if (c.state !== "issued") {
        try {
          await this.cancel(j, c, now);
        } catch (e) {
          if (!(e instanceof EmailRuntimeError) || e.code !== "stale_fence") {
            throw e;
          }
        }
        continue;
      }
      if (c.expires <= now) {
        try {
          await this.settleChallenge(c, j, "expired", "expired", now);
        } catch (e) {
          if (!(e instanceof EmailRuntimeError) || e.code !== "stale_fence") {
            throw e;
          }
        }
        continue;
      }

      // A reclaimed lease must fence the prior owner even when the worker ID
      // happens to be reused after a crash.
      const fence = next(j.fence);
      const version = next(j.version);
      const until = new Date(Date.parse(now) + 60000).toISOString();
      const audit = uuid();
      const outb = uuid();

      const statements = [
        this.db
          .prepare(
            "UPDATE email_delivery_jobs SET state='claimed',lease_owner=?,lease_until=?,fence=?,version=?,updated_at=? WHERE id=? AND version=? AND fence=? AND ((state='pending' AND not_before<=?) OR (state='claimed' AND lease_until<=?)) AND EXISTS (SELECT 1 FROM email_challenges c WHERE c.id=email_delivery_jobs.challenge_id AND c.state='issued' AND c.version=? AND c.expires_at>?)"
          )
          .bind(worker, until, fence, version, now, j.id, j.version, j.fence, now, now, c.version, now),
        ...(await this.events(
          audit,
          outb,
          c.id,
          j.id,
          "claimed",
          c.version,
          version,
          fence,
          now,
          worker
        )),
        this.db
          .prepare(
            "INSERT INTO email_delivery_witnesses(job_id,event,audit_id,outbox_id,job_version,fence,evidence_hmac) VALUES(?,'claimed',?,?,?,?,?)"
          )
          .bind(
            j.id,
            audit,
            outb,
            version,
            fence,
            await this.mac(this.token, "email.delivery-witness.v1", [
              j.id,
              audit,
              outb,
              version,
              fence,
            ])
          ),
      ];

      try {
        await this.guarded(statements);
      } catch (e) {
        if (e instanceof EmailRuntimeError && e.code === "stale_fence") {
          continue;
        }
        throw e;
      }

      const aad = this.aad(c);
      out.push({
        id: j.id,
        challengeId: c.id,
        fence,
        token: await this.open(this.deliveryKey(c.token.keyId), c.token, aad + "\u001ftoken"),
        deliveryReference: await this.open(
          this.deliveryKey(c.delivery.keyId),
          c.delivery,
          aad + "\u001fdelivery-reference"
        ),
      });
    }
    return out;
  }

  async renewDelivery(id: string, worker: string, fence: string, leaseSeconds = 60): Promise<void> {
    inputId(id);
    inputSmall(worker);
    decimal(fence);
    if (!Number.isInteger(leaseSeconds) || leaseSeconds < 1 || leaseSeconds > 900) {
      fail("invalid_input");
    }

    const { j, c, now } = await this.leased(id, worker, fence);
    if (c.state !== "issued" || c.expires <= now) {
      try {
        await this.cancel(j, c, now, worker, fence);
      } catch (e) {
        if (e instanceof EmailRuntimeError && e.code === "stale_fence") {
          // job already changed, proceed to throw challenge_expired
        } else {
          throw e;
        }
      }
      fail("challenge_expired");
    }

    const version = next(j.version);
    const until = new Date(Date.parse(now) + leaseSeconds * 1000).toISOString();
    await this.guarded([
      this.db
        .prepare(
          "UPDATE email_delivery_jobs SET lease_until=?,version=?,updated_at=? WHERE id=? AND state='claimed' AND lease_owner=? AND fence=? AND lease_until>?"
        )
        .bind(until, version, now, id, worker, fence, now),
      ...(await this.artifacts(c.id, id, "renewed", c.version, version, fence, now, worker)),
    ]);
  }

  async completeDelivery(id: string, worker: string, fence: string): Promise<void> {
    inputId(id);
    inputSmall(worker);
    decimal(fence);
    const prior = await this.job(id);
    const priorChallenge = await this.challengeById(prior.challenge);
    if (prior.state === "delivered" && prior.fence === fence) {
      await this.deliveryReplay(priorChallenge, prior, "delivered", fence, "external-send-unknown");
      return;
    }
    const { j, c, now } = await this.leased(id, worker, fence);
    if (c.state !== "issued" || c.expires <= now) {
      try {
        await this.cancel(j, c, now, worker, fence);
      } catch (e) {
        if (e instanceof EmailRuntimeError && e.code === "stale_fence") {
          // job already changed, proceed to throw challenge_expired
        } else {
          throw e;
        }
      }
      fail("challenge_expired");
    }

    const version = next(j.version);
    await this.guarded([
      this.db
        .prepare(
          "UPDATE email_delivery_jobs SET state='delivered',lease_owner=NULL,lease_until=NULL,version=?,updated_at=? WHERE id=? AND state='claimed' AND lease_owner=? AND fence=? AND lease_until>?"
        )
        .bind(version, now, id, worker, fence, now),
      ...(await this.artifacts(
        c.id,
        id,
        "delivered",
        c.version,
        version,
        fence,
        now,
        "external-send-unknown"
      )),
    ]);
  }

  async failDelivery(
    id: string,
    worker: string,
    fence: string,
    errorCode: string
  ): Promise<"pending" | "dead"> {
    inputId(id);
    inputSmall(worker);
    decimal(fence);
    inputSmall(errorCode);
    const prior = await this.job(id);
    const priorChallenge = await this.challengeById(prior.challenge);
    if (prior.fence === fence && prior.state === "dead") {
      await this.deliveryReplay(priorChallenge, prior, "dead", fence, errorCode);
      return "dead";
    }
    if (prior.fence === fence && prior.state === "pending") {
      await this.deliveryReplay(priorChallenge, prior, "retry_scheduled", fence, errorCode);
      return "pending";
    }
    const { j, c, now } = await this.leased(id, worker, fence);
    if (c.state !== "issued" || c.expires <= now) {
      try {
        await this.cancel(j, c, now, worker, fence);
      } catch (e) {
        if (e instanceof EmailRuntimeError && e.code === "stale_fence") {
          // job already changed, proceed to throw challenge_expired
        } else {
          throw e;
        }
      }
      fail("challenge_expired");
    }

    const attempt = j.attempt + 1;
    const dead = attempt >= j.max;
    const version = next(j.version);
    const notBefore = dead
      ? now
      : new Date(Date.parse(now) + Math.min(3600, 30 * 2 ** Math.min(attempt - 1, 7)) * 1000)
          .toISOString();
    const event: Event = dead ? "dead" : "retry_scheduled";

    await this.guarded([
      this.db
        .prepare(
          "UPDATE email_delivery_jobs SET state=?,attempt=?,not_before=?,lease_owner=NULL,lease_until=NULL,last_error_code=?,version=?,updated_at=? WHERE id=? AND state='claimed' AND lease_owner=? AND fence=? AND lease_until>?"
        )
        .bind(dead ? "dead" : "pending", attempt, notBefore, errorCode, version, now, id, worker, fence, now),
      ...(await this.artifacts(c.id, id, event, c.version, version, fence, now, errorCode)),
    ]);
    return dead ? "dead" : "pending";
  }


  private issue(raw: unknown) {
    const x = object(raw, [
      "id",
      "accountId",
      "purpose",
      "idempotencyKey",
      "deliveryReference",
      "expiresAt",
      "maxAttempts",
      "maxDeliveryAttempts",
    ]);
    const now = this.now();
    const expires = canonicalUtc(String(x.expiresAt));
    const max = x.maxAttempts ?? 5;
    const deliveryMax = x.maxDeliveryAttempts ?? 5;
    if (
      expires <= now ||
      !text(x.deliveryReference, 4096) ||
      !Number.isInteger(max) ||
      !Number.isInteger(deliveryMax)
    ) {
      fail("invalid_input");
    }
    const attempts = max as number;
    const deliveryAttempts = deliveryMax as number;
    if (attempts < 1 || attempts > 20 || deliveryAttempts < 1 || deliveryAttempts > 20) {
      fail("invalid_input");
    }
    return {
      id: inputId(x.id),
      account: inputSmall(x.accountId),
      purpose: inputSmall(x.purpose),
      key: inputSmall(x.idempotencyKey),
      reference: x.deliveryReference as string,
      expires,
      max: attempts,
      deliveryMax: deliveryAttempts,
      now,
    };
  }

  private fields(x: ReturnType<EmailRuntime["issue"]>) {
    return [
      x.id,
      x.account,
      x.purpose,
      x.key,
      x.reference,
      x.expires,
      String(x.max),
      String(x.deliveryMax),
    ];
  }

  private ring(r: { current: RotatingKey; previous?: readonly RotatingKey[] }) {
    const all: Key[] = [];
    for (const raw of [r?.current, ...(r?.previous ?? [])]) {
      if (
        !raw ||
        !SMALL.test(raw.id) ||
        !(raw.material instanceof Uint8Array) ||
        raw.material.length !== 32 ||
        all.some((k) => k.id === raw.id)
      ) {
        fail("invalid_input");
      }
      all.push({ id: raw.id, material: raw.material.slice() });
    }
    if (!all.length) {
      fail("invalid_input");
    }
    return { current: all[0]!, all };
  }

  private now() {
    try {
      const n = this.clock.now();
      if (!(n instanceof Date) || !Number.isFinite(n.valueOf())) {
        fail("clock_failure");
      }
      return canonicalUtc(n.toISOString());
    } catch (e) {
      if (e instanceof EmailRuntimeError) {
        throw e;
      }
      return fail("clock_failure");
    }
  }

  private aad(x: { id: string; account: string; purpose: string }) {
    return "email-runtime/v1\u001f" + x.id + "\u001f" + x.account + "\u001f" + x.purpose;
  }

  private tokenKey(id: string) {
    return this.tokens.get(storedSmall(id)) ?? fail("unknown_key_id");
  }

  private deliveryKey(id: string) {
    return this.deliveries.get(storedSmall(id)) ?? fail("unknown_key_id");
  }

  private async mac(key: Key, domain: string, fields: readonly string[]) {
    const imported = await crypto.subtle.importKey(
      "raw",
      key.material,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    return b64(
      new Uint8Array(
        await crypto.subtle.sign("HMAC", imported, E.encode(domain + "\n" + JSON.stringify(fields)))
      )
    );
  }

  private async seal(key: Key, plain: string, aad: string): Promise<Envelope> {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const imported = await crypto.subtle.importKey("raw", key.material, "AES-GCM", false, [
      "encrypt",
    ]);
    const cipher = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: E.encode(aad + "\u001f" + key.id) },
      imported,
      E.encode(plain)
    );
    return { keyId: key.id, nonce: b64(nonce), ciphertext: b64(new Uint8Array(cipher)) };
  }

  private async open(key: Key, envelope: Envelope, aad: string): Promise<string> {
    try {
      const imported = await crypto.subtle.importKey("raw", key.material, "AES-GCM", false, [
        "decrypt",
      ]);
      const plain = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: unb64(envelope.nonce, 12),
          additionalData: E.encode(aad + "\u001f" + key.id),
        },
        imported,
        unb64(envelope.ciphertext)
      );
      const value = D.decode(plain);
      if (!text(value, 4096)) {
        fail("corrupt_state");
      }
      return value;
    } catch (e) {
      if (e instanceof EmailRuntimeError) {
        throw e;
      }
      return fail("corrupt_state");
    }
  }

  private async first(sql: string, ...args: unknown[]): Promise<Row | null> {
    try {
      return await this.db.prepare(sql).bind(...args).first<Row>();
    } catch (e) {
      return this.storage(e);
    }
  }

  private async all(sql: string, ...args: unknown[]): Promise<Row[]> {
    try {
      const r = await this.db.prepare(sql).bind(...args).all<Row>();
      if (!Array.isArray(r.results)) {
        fail("corrupt_state");
      }
      return r.results;
    } catch (e) {
      if (e instanceof EmailRuntimeError) {
        throw e;
      }
      return this.storage(e);
    }
  }

  private storage(e: unknown): never {
    if (e instanceof EmailRuntimeError) {
      throw e;
    }
    if (
      e instanceof Error &&
      (/UNIQUE constraint failed/.test(e.message) ||
        /FOREIGN KEY constraint failed/.test(e.message) ||
        /CHECK constraint failed/.test(e.message) ||
        /immutable/.test(e.message) ||
        /illegal.*transition/.test(e.message))
    ) {
      throw new EmailRuntimeError("corrupt_state");
    }
    throw new EmailRuntimeError("storage_failure");
  }

  private challengeRow(r: Row, joined = false): Challenge {
    const state = joined ? r.challenge_state : r.state;
    if (state !== "issued" && state !== "consumed" && state !== "expired") {
      fail("corrupt_state");
    }
    const failed = r.failed_attempts;
    const max = r.max_attempts;
    if (!Number.isInteger(failed) || !Number.isInteger(max)) {
      fail("corrupt_state");
    }
    const badFailed = failed as number;
    const badMax = max as number;
    if (badFailed < 0 || badFailed > badMax || badMax < 1 || badMax > 20) {
      fail("corrupt_state");
    }

    const envelope = (
      key: unknown,
      nonce: unknown,
      cipher: unknown,
      token: boolean
    ): Envelope => {
      const out = {
        keyId: storedSmall(key),
        nonce: rowB64(nonce, 12),
        ciphertext: rowB64(cipher),
      };
      if (
        (token && out.ciphertext.length !== 79) ||
        (!token && (out.ciphertext.length < 17 || out.ciphertext.length > 5496))
      ) {
        fail("corrupt_state");
      }
      return out;
    };

    return {
      id: storedId(joined ? r.challenge_id : r.id),
      account: storedSmall(r.account_id),
      purpose: storedSmall(r.purpose),
      tokenKey: storedSmall(r.token_hmac_key_id),
      verifier: rowB64(r.token_verifier, 32),
      token: envelope(r.token_envelope_key_id, r.token_nonce, r.token_ciphertext, true),
      delivery: envelope(r.delivery_envelope_key_id, r.delivery_nonce, r.delivery_ciphertext, false),
      state: state as Challenge["state"],
      failed: badFailed,
      max: badMax,
      expires: rowUtc(r.expires_at),
      version: decimal(joined ? r.challenge_version : r.version),
    };
  }

  private jobRow(r: Row): Job {
    const state = r.state;
    if (
      state !== "pending" &&
      state !== "claimed" &&
      state !== "delivered" &&
      state !== "dead" &&
      state !== "cancelled"
    ) {
      fail("corrupt_state");
    }
    const attempt = r.attempt;
    const max = r.max_attempts;
    if (!Number.isInteger(attempt) || !Number.isInteger(max)) {
      fail("corrupt_state");
    }
    const jobAttempt = attempt as number;
    const jobMax = max as number;
    if (
      jobAttempt < 0 ||
      jobAttempt > jobMax ||
      jobMax < 1 ||
      jobMax > 20 ||
      (state === "dead" && jobAttempt !== jobMax)
    ) {
      fail("corrupt_state");
    }
    const owner = r.lease_owner === null ? null : storedSmall(r.lease_owner);
    const until = r.lease_until === null ? null : rowUtc(r.lease_until);
    if (
      (state === "claimed") !== (owner !== null && until !== null) ||
      (state !== "claimed" && (owner !== null || until !== null))
    ) {
      fail("corrupt_state");
    }
    return {
      id: storedId(r.id),
      challenge: storedId(r.challenge_id),
      state: state as Job["state"],
      attempt: jobAttempt,
      max: jobMax,
      notBefore: rowUtc(r.not_before),
      owner,
      until,
      fence: decimal(r.fence),
      version: decimal(r.version),
    };
  }

  private async challenge(id: string, account: string, purpose: string) {
    const r = await this.first(
      "SELECT * FROM email_challenges WHERE id=? AND account_id=? AND purpose=?",
      id,
      account,
      purpose
    );
    return r ? this.challengeRow(r) : fail("challenge_not_found");
  }

  private async challengeById(id: string) {
    const r = await this.first("SELECT * FROM email_challenges WHERE id=?", id);
    return r ? this.challengeRow(r) : fail("corrupt_state");
  }

  private async job(id: string) {
    const r = await this.first("SELECT * FROM email_delivery_jobs WHERE id=?", id);
    return r ? this.jobRow(r) : fail("job_not_found");
  }

  private async jobByChallenge(challengeId: string): Promise<Job | null> {
    const r = await this.first(
      "SELECT * FROM email_delivery_jobs WHERE challenge_id=?",
      challengeId
    );
    return r ? this.jobRow(r) : null;
  }

  private async guarded(s: D1PreparedStatement[], guardCount = 1) {
    if (!Number.isInteger(guardCount) || guardCount < 1 || guardCount > s.length) {
      fail("corrupt_state");
    }
    const guards = Array.from({ length: guardCount }, uuid);
    const batch: D1PreparedStatement[] = [];
    for (let i = 0; i < s.length; i++) {
      batch.push(s[i]!);
      if (i < guardCount) {
        batch.push(
          this.db
            .prepare("INSERT INTO email_runtime_batch_guards(guard_id,matched) VALUES(?,changes())")
            .bind(guards[i]!)
        );
      }
    }
    try {
      await this.db.batch([
        ...batch,
        ...guards.map((guard) =>
          this.db.prepare("DELETE FROM email_runtime_batch_guards WHERE guard_id=?").bind(guard)
        ),
      ]);
    } catch (e) {
      if (e instanceof Error) {
        if (/version exhausted/.test(e.message)) {
          fail("counter_exhausted");
        }
        if (
          /CHECK constraint failed(?:: [^\n]*)?(?:email_runtime_batch_guards\.)?matched/.test(
            e.message
          ) || /email_runtime_batch_guards.*CHECK constraint failed/.test(e.message)
        ) {
          fail("stale_fence");
        }
      }
      return this.storage(e);
    }
  }

  private async events(
    audit: string,
    outbox: string,
    challenge: string,
    job: string | null,
    event: Event,
    cv: string,
    jv: string | null,
    fence: string | null,
    at: string,
    detail: string
  ) {
    const evidence = await this.mac(this.token, "email.event.v1", [
      challenge,
      job ?? "",
      event,
      cv,
      jv ?? "",
      fence ?? "",
      detail,
      at,
    ]);
    const payload = await this.mac(this.token, "email.outbox.v1", [
      challenge,
      job ?? "",
      event,
      cv,
      jv ?? "",
      fence ?? "",
      evidence,
      at,
    ]);
    return [
      this.db
        .prepare(
          "INSERT INTO email_runtime_audit(audit_id,challenge_id,job_id,event,challenge_version,job_version,fence,evidence_hmac_key_id,evidence_hmac,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)"
        )
        .bind(audit, challenge, job, event, cv, jv, fence, this.token.id, evidence, at),
      this.db
        .prepare(
          "INSERT INTO email_runtime_outbox(outbox_id,audit_id,challenge_id,job_id,event,payload_hmac_key_id,payload_hmac,created_at) VALUES(?,?,?,?,?,?,?,?)"
        )
        .bind(outbox, audit, challenge, job, event, this.token.id, payload, at),
    ];
  }

  private async artifacts(
    c: string,
    j: string | null,
    event: Event,
    cv: string,
    jv: string | null,
    fence: string | null,
    at: string,
    detail: string
  ) {
    return this.events(uuid(), uuid(), c, j, event, cv, jv, fence, at, detail);
  }

  private async changeChallenge(
    c: Challenge,
    state: Challenge["state"],
    failed: number,
    consumed: string | null,
    event: Event,
    now: string
  ) {
    const version = next(c.version);
    await this.guarded([
      this.db
        .prepare(
          "UPDATE email_challenges SET state=?,failed_attempts=?,consumed_at=?,version=? WHERE id=? AND state='issued' AND version=?"
        )
        .bind(state, failed, consumed, version, c.id, c.version),
      ...(await this.artifacts(c.id, null, event, version, null, null, now, state)),
    ]);
  }

  /** Atomically retire the challenge and revoke its still-sendable job. */
  private async settleChallenge(
    c: Challenge,
    j: Job,
    state: "consumed" | "expired",
    event: "consumed" | "expired",
    now: string,
    failed = c.failed
  ) {
    const challengeVersion = next(c.version);
    if (j.state !== "pending" && j.state !== "claimed") {
      await this.guarded([
        this.db
          .prepare(
            "UPDATE email_challenges SET state=?,failed_attempts=?,consumed_at=?,version=? WHERE id=? AND state='issued' AND version=?"
          )
          .bind(state, failed, state === "consumed" ? now : null, challengeVersion, c.id, c.version),
        ...(await this.artifacts(c.id, null, event, challengeVersion, null, null, now, state)),
      ]);
      return;
    }

    const jobVersion = next(j.version);
    await this.guarded(
      [
        this.db
          .prepare(
            "UPDATE email_challenges SET state=?,failed_attempts=?,consumed_at=?,version=? WHERE id=? AND state='issued' AND version=?"
          )
          .bind(state, failed, state === "consumed" ? now : null, challengeVersion, c.id, c.version),
        this.db
          .prepare(
            "UPDATE email_delivery_jobs SET state='cancelled',lease_owner=NULL,lease_until=NULL,version=?,updated_at=? WHERE id=? AND challenge_id=? AND state IN ('pending','claimed') AND version=? AND fence=?"
          )
          .bind(jobVersion, now, j.id, c.id, j.version, j.fence),
        ...(await this.artifacts(c.id, null, event, challengeVersion, null, null, now, state)),
        ...(await this.artifacts(
          c.id,
          j.id,
          "cancelled",
          challengeVersion,
          jobVersion,
          j.fence,
          now,
          "challenge-not-sendable"
        )),
      ],
      2
    );
  }

  private async cancel(j: Job, c: Challenge, now: string, owner?: string, fence?: string) {
    if (j.state === "cancelled" || j.state === "dead" || j.state === "delivered") {
      return;
    }

    const version = next(j.version);
    const query = owner
      ? "UPDATE email_delivery_jobs SET state='cancelled',lease_owner=NULL,lease_until=NULL,version=?,updated_at=? WHERE id=? AND state='claimed' AND lease_owner=? AND fence=? AND lease_until>?"
      : "UPDATE email_delivery_jobs SET state='cancelled',lease_owner=NULL,lease_until=NULL,version=?,updated_at=? WHERE id=? AND fence=? AND (state='pending' OR (state='claimed' AND lease_until<=?))";
    const args = owner ? [version, now, j.id, owner, fence, now] : [version, now, j.id, j.fence, now];

    await this.guarded([
      this.db.prepare(query).bind(...args),
      ...(await this.artifacts(
        c.id,
        j.id,
        "cancelled",
        c.version,
        version,
        j.fence,
        now,
        "challenge-not-sendable"
      )),
    ]);
  }

  private async leased(id: string, worker: string, fence: string) {
    inputId(id);
    inputSmall(worker);
    decimal(fence);
    const now = this.now();
    const j = await this.job(id);
    const c = await this.challengeById(j.challenge);
    if (c.state !== "issued" || c.expires <= now) {
      try {
        if (j.state === "claimed" || j.state === "pending") {
          await this.cancel(j, c, now);
        }
      } catch (_) {
        // best-effort cancel
      }
      fail("challenge_expired");
    }
    if (j.state !== "claimed" || j.owner !== worker || j.fence !== fence || !j.until || j.until <= now) {
      fail("stale_fence");
    }
    return { j, c, now };
  }

  /**
   * A lost client response may replay a completed fail/complete call.  Only a
   * matching immutable audit MAC makes that replay a no-op; a terminal row by
   * itself is never sufficient evidence.
   */
  private async deliveryReplay(
    c: Challenge,
    j: Job,
    event: "delivered" | "retry_scheduled" | "dead",
    fence: string,
    detail: string
  ) {
    const rows = await this.all(
      "SELECT challenge_version,job_version,fence,evidence_hmac_key_id,evidence_hmac,created_at FROM email_runtime_audit WHERE challenge_id=? AND job_id=? AND event=? AND job_version=? AND fence=?",
      c.id,
      j.id,
      event,
      j.version,
      fence
    );
    if (rows.length !== 1) {
      fail("corrupt_state");
    }
    const row = rows[0]!;
    const challengeVersion = decimal(row.challenge_version);
    const jobVersion = decimal(row.job_version);
    const auditFence = decimal(row.fence);
    const at = rowUtc(row.created_at);
    if (challengeVersion !== c.version || jobVersion !== j.version || auditFence !== fence) {
      fail("corrupt_state");
    }
    const key = this.tokenKey(storedSmall(row.evidence_hmac_key_id));
    const expected = await this.mac(key, "email.event.v1", [
      c.id,
      j.id,
      event,
      challengeVersion,
      jobVersion,
      auditFence,
      detail,
      at,
    ]);
    if (!same(unb64(expected, 32), unb64(rowB64(row.evidence_hmac, 32), 32))) {
      fail("corrupt_state");
    }
  }

  private async replay(x: ReturnType<EmailRuntime["issue"]>, r: Row): Promise<IssuedChallenge> {
    const key = this.tokenKey(storedSmall(r.request_hmac_key_id));
    const semantic = await this.mac(key, "email.issue.v1", this.fields(x));
    const id = storedId(r.challenge_id);
    const job = storedId(r.job_id);
    if (!same(unb64(semantic, 32), unb64(rowB64(r.semantic_hmac, 32), 32))) {
      fail("idempotency_collision");
    }

    const witness = await this.first(
      "SELECT w.*,w.evidence_hmac AS witness_hmac,c.account_id,c.purpose,c.expires_at,j.challenge_id AS linked_job_challenge,a.audit_id AS linked_audit,a.challenge_id AS audit_challenge_id,a.job_id AS audit_job_id,a.event AS audit_event,a.challenge_version AS audit_challenge_version,a.job_version AS audit_job_version,a.fence AS audit_fence,a.evidence_hmac_key_id AS audit_key_id,a.evidence_hmac AS audit_hmac,a.created_at AS audit_created_at,o.outbox_id AS linked_outbox,o.audit_id AS linked_outbox_audit,o.challenge_id AS outbox_challenge_id,o.job_id AS outbox_job_id,o.event AS outbox_event,o.payload_hmac_key_id AS outbox_key_id,o.payload_hmac AS outbox_hmac,o.created_at AS outbox_created_at FROM email_issue_witnesses w LEFT JOIN email_challenges c ON c.id=w.challenge_id LEFT JOIN email_delivery_jobs j ON j.id=w.job_id LEFT JOIN email_runtime_audit a ON a.audit_id=w.audit_id LEFT JOIN email_runtime_outbox o ON o.outbox_id=w.outbox_id WHERE w.account_id=? AND w.idempotency_key=?",
      x.account,
      x.key
    );
    if (!witness) {
      fail("idempotency_corrupt");
    }
    const w = witness as Row;
    if (
      w.challenge_id !== id ||
      w.job_id !== job ||
      w.account_id !== x.account ||
      w.idempotency_key !== x.key ||
      w.purpose !== x.purpose ||
      w.linked_job_challenge !== id ||
      w.linked_audit !== w.audit_id ||
      w.linked_outbox !== w.outbox_id ||
      w.linked_outbox_audit !== w.audit_id ||
      w.audit_event !== "issued" ||
      w.outbox_event !== "issued" ||
      w.audit_challenge_id !== id ||
      w.outbox_challenge_id !== id ||
      w.audit_job_id !== null ||
      w.outbox_job_id !== null ||
      w.audit_challenge_version !== "1" ||
      w.audit_job_version !== null ||
      w.audit_fence !== null ||
      w.audit_created_at !== w.outbox_created_at ||
      w.challenge_version !== "1" ||
      w.job_version !== "1" ||
      w.fence !== "1"
    ) {
      fail("idempotency_corrupt");
    }

    const expected = await this.mac(key, "email.issue-witness.v1", [
      x.account,
      x.key,
      id,
      job,
      String(w.audit_id),
      String(w.outbox_id),
      semantic,
    ]);
    if (!same(unb64(expected, 32), unb64(rowB64(w.witness_hmac, 32), 32))) {
      fail("idempotency_corrupt");
    }

    const at = rowUtc(w.audit_created_at);
    const auditKey = this.tokenKey(storedSmall(w.audit_key_id));
    const audit = await this.mac(auditKey, "email.event.v1", [
      id, "", "issued", "1", "", "", "created", at,
    ]);
    if (!same(unb64(audit, 32), unb64(rowB64(w.audit_hmac, 32), 32))) {
      fail("idempotency_corrupt");
    }
    const outboxKey = this.tokenKey(storedSmall(w.outbox_key_id));
    const outbox = await this.mac(outboxKey, "email.outbox.v1", [
      id, "", "issued", "1", "", "", audit, at,
    ]);
    if (!same(unb64(outbox, 32), unb64(rowB64(w.outbox_hmac, 32), 32))) {
      fail("idempotency_corrupt");
    }

    return { id, expiresAt: rowUtc(w.expires_at), replayed: true };
  }
}
