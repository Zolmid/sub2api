import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { PaymentRuntime } from "../src/payment-runtime";

let n = 0;
let paymentId = "";
const tag = (x: string) => x + "-" + paymentId;
const rt = () => new PaymentRuntime(env.DB, () => Date.parse("2026-09-10T00:00:00.000Z"));
const create = () =>
  rt().create({ payment_id: paymentId, account_id: "acct-1", amount_e8: "100", idempotency_key: tag("create") });
const settle = () =>
  rt().transition({ payment_id: paymentId, next_state: "succeeded", expected_version: "1", idempotency_key: tag("settle") });
beforeEach(() => {
  paymentId = "pay-" + ++n;
});

describe("payment runtime", () => {
  it("returns immutable creation snapshot after later transitions", async () => {
    const created = await create();
    await settle();
    await expect(create()).resolves.toEqual(created);
  });

  it("returns immutable provider event snapshot after later transitions", async () => {
    await create();
    await rt().transition({ payment_id: paymentId, next_state: "authorized", expected_version: "1", idempotency_key: tag("authorize") });
    const event = { provider_event_id: tag("event"), payment_id: paymentId, next_state: "manual_review" as const, expected_version: "2" };
    const provider = await rt().acceptProviderEvent(event);
    expect(provider).toMatchObject({ ok: true, payment: { state: "manual_review", version: "3" } });
    await rt().transition({ payment_id: paymentId, next_state: "authorized", expected_version: "3", idempotency_key: tag("release") });
    await expect(rt().acceptProviderEvent(event)).resolves.toEqual(provider);
  });

  it("reserves staged refund, retains on manual_review WITHOUT trigger, releases on failure, settles on success", async () => {
    await create();
    await settle();
    const first = await rt().createRefund({ refund_id: tag("r1"), payment_id: paymentId, amount_e8: "60", expected_payment_version: "2", idempotency_key: tag("reserve1") });
    expect(first).toMatchObject({ ok: true, payment: { pending_refund_e8: "60", version: "3" }, refund: { state: "created", version: "1" } });

    const manual = await rt().transitionRefund({
      refund_id: tag("r1"),
      payment_id: paymentId,
      next_state: "manual_review",
      expected_payment_version: "3",
      expected_refund_version: "1",
      idempotency_key: tag("review"),
    });
    expect(manual).toMatchObject({
      ok: true,
      payment: { pending_refund_e8: "60", refunded_e8: "0", version: "4" },
      refund: { state: "manual_review", version: "2" },
    });
    const dbPending = (
      await env.DB.prepare("SELECT pending_refund_e8 FROM payment_records WHERE payment_id=?")
        .bind(paymentId)
        .first<{ pending_refund_e8: string }>()
    )?.pending_refund_e8;
    expect(dbPending).toBe("60");

    await expect(
      rt().createRefund({ refund_id: tag("r2"), payment_id: paymentId, amount_e8: "50", expected_payment_version: "4", idempotency_key: tag("reserve2") })
    ).resolves.toEqual({ ok: false, code: "OVER_REFUND" });

    await expect(
      rt().transitionRefund({
        refund_id: tag("r1"),
        payment_id: paymentId,
        next_state: "failed",
        expected_payment_version: "3",
        expected_refund_version: "2",
        idempotency_key: tag("stale"),
      })
    ).resolves.toEqual({ ok: false, code: "CONFLICT" });

    await expect(
      rt().transitionRefund({
        refund_id: tag("r1"),
        payment_id: paymentId,
        next_state: "succeeded",
        expected_payment_version: "4",
        expected_refund_version: "2",
        idempotency_key: tag("approve"),
      })
    ).resolves.toMatchObject({
      ok: true,
      payment: { refunded_e8: "60", pending_refund_e8: "0", version: "5" },
      refund: { state: "succeeded", version: "3" },
    });
  });

  it("replays each refund from its immutable snapshot after later refunds mutate payment", async () => {
    await create();
    await settle();
    const one = { refund_id: tag("r1"), payment_id: paymentId, amount_e8: "25", expected_payment_version: "2", idempotency_key: tag("one") };
    const first = await rt().refundPayment(one);
    await rt().refundPayment({ refund_id: tag("r2"), payment_id: paymentId, amount_e8: "25", expected_payment_version: "3", idempotency_key: tag("two") });
    await expect(rt().refundPayment(one)).resolves.toEqual(first);
  });

  it("rejects unknown fields, prototype tricks, symbol accessors, and malformed money", async () => {
    await expect(
      rt().create({ payment_id: paymentId, account_id: "acct", amount_e8: "1", idempotency_key: "x", ignored: "hostile" })
    ).resolves.toEqual({ ok: false, code: "INVALID_INPUT" });
    await expect(rt().create({ payment_id: paymentId, account_id: "acct", amount_e8: "01", idempotency_key: "x" })).resolves.toEqual({
      ok: false,
      code: "INVALID_INPUT",
    });
    await expect(rt().create({ payment_id: paymentId, account_id: "acct", amount_e8: "0", idempotency_key: "x" })).resolves.toEqual({
      ok: false,
      code: "INVALID_INPUT",
    });
    await expect(rt().create({ payment_id: paymentId, account_id: "acct", amount_e8: "9223372036854775808", idempotency_key: "x" })).resolves.toEqual({
      ok: false,
      code: "INVALID_INPUT",
    });
  });

  it("detects corrupt authority and distinguishes from NOT_FOUND", async () => {
    await create();
    await env.DB.prepare("UPDATE payment_records SET pending_refund_e8='101' WHERE payment_id=?").bind(paymentId).run();
    await expect(
      rt().transition({ payment_id: paymentId, next_state: "authorized", expected_version: "1", idempotency_key: "corrupt" })
    ).resolves.toEqual({ ok: false, code: "CORRUPT_STATE" });

    await expect(
      rt().transition({ payment_id: "pay-missing", next_state: "authorized", expected_version: "1", idempotency_key: "missing" })
    ).resolves.toEqual({ ok: false, code: "NOT_FOUND" });
  });

  it("rolls back concurrent stale CAS without orphan evidence", async () => {
    await create();
    const results = await Promise.all([
      rt().transition({ payment_id: paymentId, next_state: "authorized", expected_version: "1", idempotency_key: "a" }),
      rt().transition({ payment_id: paymentId, next_state: "authorized", expected_version: "1", idempotency_key: "b" }),
    ]);
    expect(results.filter((x) => x.ok).length).toBe(1);
    expect(results.filter((x) => !x.ok)).toEqual([{ ok: false, code: "CONFLICT" }]);
    expect(
      (
        await env.DB.prepare("SELECT count(*) n FROM payment_audit_events WHERE payment_id=? AND action='payment_transitioned'")
          .bind(paymentId)
          .first<{ n: number }>()
      )?.n
    ).toBe(1);
    expect((await env.DB.prepare("SELECT count(*) n FROM payment_batch_guards").first<{ n: number }>())?.n).toBe(0);
  });

  it("rolls back a D1 schema-trigger failure without partial payment evidence", async () => {
    await create();
    await env.DB.exec("CREATE TRIGGER payment_test_outbox_abort BEFORE INSERT ON payment_outbox_events BEGIN SELECT RAISE(ABORT,'test schema failure'); END");
    try {
      await expect(
        rt().transition({ payment_id: paymentId, next_state: "authorized", expected_version: "1", idempotency_key: tag("schema-failure") })
      ).resolves.toEqual({ ok: false, code: "UNAVAILABLE" });
      await expect(
        env.DB.prepare("SELECT state,version FROM payment_records WHERE payment_id=?").bind(paymentId).first<{ state: string; version: string }>()
      ).resolves.toEqual({ state: "created", version: "1" });
      await expect(
        env.DB.prepare("SELECT count(*) n FROM payment_audit_events WHERE payment_id=? AND action='payment_transitioned'").bind(paymentId).first<{ n: number }>()
      ).resolves.toEqual({ n: 0 });
      await expect(
        env.DB.prepare("SELECT count(*) n FROM payment_outbox_events WHERE payment_id=?").bind(paymentId).first<{ n: number }>()
      ).resolves.toEqual({ n: 1 });
      await expect(
        env.DB.prepare("SELECT count(*) n FROM payment_ledger_transactions WHERE payment_id=?").bind(paymentId).first<{ n: number }>()
      ).resolves.toEqual({ n: 0 });
      await expect(
        env.DB.prepare("SELECT count(*) n FROM payment_idempotency_witnesses WHERE operation='transition' AND idempotency_key=?").bind(tag("schema-failure")).first<{ n: number }>()
      ).resolves.toEqual({ n: 0 });
      await expect(env.DB.prepare("SELECT count(*) n FROM payment_batch_guards").first<{ n: number }>()).resolves.toEqual({ n: 0 });
    } finally {
      await env.DB.exec("DROP TRIGGER payment_test_outbox_abort");
    }
  });

  it("keeps durable evidence immutable", async () => {
    await create();
    await expect(env.DB.prepare("UPDATE payment_idempotency_witnesses SET result_digest='0' WHERE operation='create'").run()).rejects.toThrow(
      /immutable/
    );
    await expect(env.DB.prepare("DELETE FROM payment_outbox_events").run()).rejects.toThrow(/immutable/);
    await expect(env.DB.prepare("UPDATE payment_audit_events SET version='999' WHERE payment_id=?").bind(paymentId).run()).rejects.toThrow(
      /immutable/
    );
  });

  it("enforces payment state machine", async () => {
    await create();
    await expect(
      rt().transition({ payment_id: paymentId, next_state: "refunded", expected_version: "1", idempotency_key: "bad" })
    ).resolves.toEqual({ ok: false, code: "ILLEGAL_TRANSITION" });
    await rt().transition({ payment_id: paymentId, next_state: "authorized", expected_version: "1", idempotency_key: "ok1" });
    await expect(
      rt().transition({ payment_id: paymentId, next_state: "created", expected_version: "2", idempotency_key: "regress" })
    ).resolves.toEqual({ ok: false, code: "ILLEGAL_TRANSITION" });
  });

  it("enforces refund state machine", async () => {
    await create();
    await settle();
    await rt().createRefund({ refund_id: tag("r1"), payment_id: paymentId, amount_e8: "50", expected_payment_version: "2", idempotency_key: tag("cr") });
    await expect(
      rt().transitionRefund({
        refund_id: tag("r1"),
        payment_id: paymentId,
        next_state: "created",
        expected_payment_version: "3",
        expected_refund_version: "1",
        idempotency_key: tag("regress"),
      })
    ).resolves.toEqual({ ok: false, code: "ILLEGAL_TRANSITION" });
  });

  it("rejects terminal-to-terminal refund regression", async () => {
    await create();
    await settle();
    await rt().createRefund({ refund_id: tag("r1"), payment_id: paymentId, amount_e8: "50", expected_payment_version: "2", idempotency_key: tag("cr") });
    await rt().transitionRefund({
      refund_id: tag("r1"), payment_id: paymentId, next_state: "failed",
      expected_payment_version: "3", expected_refund_version: "1", idempotency_key: tag("fail"),
    });
    await expect(
      rt().transitionRefund({
        refund_id: tag("r1"), payment_id: paymentId, next_state: "succeeded",
        expected_payment_version: "4", expected_refund_version: "2", idempotency_key: tag("zombie"),
      })
    ).resolves.toEqual({ ok: false, code: "ILLEGAL_TRANSITION" });
  });

  it("prevents full-refund state from accepting new refunds", async () => {
    await create();
    await settle();
    await rt().refundPayment({ refund_id: tag("r1"), payment_id: paymentId, amount_e8: "100", expected_payment_version: "2", idempotency_key: tag("full") });
    await expect(
      rt().refundPayment({ refund_id: tag("r2"), payment_id: paymentId, amount_e8: "1", expected_payment_version: "3", idempotency_key: tag("extra") })
    ).resolves.toEqual({ ok: false, code: "ILLEGAL_TRANSITION" });
  });

  it("detects version overflow at next() boundary", async () => {
    await create();
    await env.DB.prepare("UPDATE payment_records SET version='9223372036854775807' WHERE payment_id=?").bind(paymentId).run();
    await expect(
      rt().transition({ payment_id: paymentId, next_state: "authorized", expected_version: "9223372036854775807", idempotency_key: tag("overflow") })
    ).resolves.toEqual({ ok: false, code: "CORRUPT_STATE" });
  });

  it("detects missing witness audit evidence", async () => {
    await create();
    // Keep the witness FK target intact, but swap the table runtime reads to
    // simulate an imported/corrupt schema whose audit evidence is absent.
    await env.DB.exec("ALTER TABLE payment_audit_events RENAME TO payment_audit_events_authoritative");
    let replacementInstalled = false;
    try {
      await env.DB
        .prepare("CREATE TABLE payment_audit_events (event_id TEXT PRIMARY KEY,payment_id TEXT,refund_id TEXT,action TEXT,previous_state TEXT,next_state TEXT,version TEXT,semantic_digest TEXT,created_at TEXT)")
        .run();
      replacementInstalled = true;
      // Replay with missing audit evidence should detect corruption.
      await expect(create()).resolves.toEqual({ ok: false, code: "CORRUPT_STATE" });
    } finally {
      if (replacementInstalled) await env.DB.exec("DROP TABLE payment_audit_events");
      await env.DB.exec("ALTER TABLE payment_audit_events_authoritative RENAME TO payment_audit_events");
    }
  });

  it("detects mismatched audit semantic digest", async () => {
    await create();
    const w = await env.DB.prepare("SELECT audit_event_id FROM payment_idempotency_witnesses WHERE operation='create'").first<{ audit_event_id: string }>();
    await env.DB.exec("DROP TRIGGER payment_audit_immutable_update");
    await env.DB.prepare("UPDATE payment_audit_events SET semantic_digest='0000000000000000000000000000000000000000000000000000000000000000' WHERE event_id=?").bind(w!.audit_event_id).run();
    await env.DB.exec("CREATE TRIGGER payment_audit_immutable_update BEFORE UPDATE ON payment_audit_events BEGIN SELECT RAISE(ABORT,'payment audit is immutable'); END");
    await expect(create()).resolves.toEqual({ ok: false, code: "CORRUPT_STATE" });
  });

  it("replays identical provider callback after later transitions", async () => {
    await create();
    await rt().transition({ payment_id: paymentId, next_state: "authorized", expected_version: "1", idempotency_key: tag("authorize") });
    const event1 = await rt().acceptProviderEvent({ provider_event_id: tag("prov"), payment_id: paymentId, next_state: "manual_review", expected_version: "2" });
    expect(event1).toMatchObject({ ok: true, payment: { state: "manual_review", version: "3" } });
    await rt().transition({ payment_id: paymentId, next_state: "succeeded", expected_version: "3", idempotency_key: tag("final") });
    await expect(rt().acceptProviderEvent({ provider_event_id: tag("prov"), payment_id: paymentId, next_state: "manual_review", expected_version: "2" })).resolves.toEqual(event1);
  });

  it("rejects changed provider payload under same provider_event_id", async () => {
    await create();
    await rt().transition({ payment_id: paymentId, next_state: "authorized", expected_version: "1", idempotency_key: tag("authorize") });
    await rt().acceptProviderEvent({ provider_event_id: tag("prov"), payment_id: paymentId, next_state: "manual_review", expected_version: "2" });
    // Changed next_state under the same provider_event_id and same expected_version
    // The dedup record semantic_digest check fires before version-gate
    await expect(
      rt().acceptProviderEvent({ provider_event_id: tag("prov"), payment_id: paymentId, next_state: "succeeded", expected_version: "2" })
    ).resolves.toEqual({ ok: false, code: "IDEMPOTENCY_COLLISION" });
  });

  it("enforces version overflow trigger protection", async () => {
    await create();
    await env.DB.prepare("UPDATE payment_records SET version='9223372036854775807' WHERE payment_id=?").bind(paymentId).run();
    await expect(
      rt().transition({ payment_id: paymentId, next_state: "authorized", expected_version: "9223372036854775807", idempotency_key: tag("overflow2") })
    ).resolves.toEqual({ ok: false, code: "CORRUPT_STATE" });
  });

  it("settlement creates unique ledger entry", async () => {
    await create();
    await settle();
    const count = (await env.DB.prepare("SELECT count(*) n FROM payment_ledger_transactions WHERE payment_id=? AND kind='payment_settlement'").bind(paymentId).first<{ n: number }>())?.n;
    expect(count).toBe(1);
    const entry = await env.DB.prepare("SELECT debit_account, credit_account, amount_e8 FROM payment_ledger_transactions WHERE payment_id=?").bind(paymentId).first<{ debit_account: string; credit_account: string; amount_e8: string }>();
    expect(entry).toEqual({ debit_account: "customer_cash", credit_account: "merchant_revenue", amount_e8: "100" });
  });

  it("enforces exactly one NULL-refund payment settlement and kind/refund linkage", async () => {
    await create();
    await settle();
    await expect(
      env.DB
        .prepare("INSERT INTO payment_ledger_transactions(ledger_id,payment_id,refund_id,kind,debit_account,credit_account,amount_e8,created_at) VALUES(?,?,NULL,'payment_settlement','customer_cash','merchant_revenue','100','2026-09-10T00:00:00.000Z')")
        .bind("0".repeat(32), paymentId)
        .run()
    ).rejects.toThrow(/UNIQUE constraint failed/);
    await expect(
      env.DB
        .prepare("INSERT INTO payment_ledger_transactions(ledger_id,payment_id,refund_id,kind,debit_account,credit_account,amount_e8,created_at) VALUES(?,?,NULL,'refund_settlement','refund_liability','customer_cash','1','2026-09-10T00:00:00.000Z')")
        .bind("1".repeat(32), paymentId)
        .run()
    ).rejects.toThrow(/kind\/refund linkage/);
    await expect(
      env.DB
        .prepare("INSERT INTO payment_ledger_transactions(ledger_id,payment_id,refund_id,kind,debit_account,credit_account,amount_e8,created_at) VALUES(?,?,?,'payment_settlement','customer_cash','merchant_revenue','1','2026-09-10T00:00:00.000Z')")
        .bind("2".repeat(32), paymentId, tag("not-a-payment-settlement-refund"))
        .run()
    ).rejects.toThrow(/kind\/refund linkage/);
  });

  it("increments each conditional payment and refund version by exactly one", async () => {
    await create();
    await expect(settle()).resolves.toMatchObject({ ok: true, payment: { version: "2" } });
    await expect(
      rt().createRefund({ refund_id: tag("r1"), payment_id: paymentId, amount_e8: "30", expected_payment_version: "2", idempotency_key: tag("reserve") })
    ).resolves.toMatchObject({ ok: true, payment: { version: "3" }, refund: { version: "1" } });
    await expect(
      rt().transitionRefund({ refund_id: tag("r1"), payment_id: paymentId, next_state: "succeeded", expected_payment_version: "3", expected_refund_version: "1", idempotency_key: tag("settle-refund") })
    ).resolves.toMatchObject({ ok: true, payment: { version: "4" }, refund: { version: "2" } });
  });

  it("refund settlement creates double-entry ledger linked to refund", async () => {
    await create();
    await settle();
    await rt().refundPayment({ refund_id: tag("r1"), payment_id: paymentId, amount_e8: "30", expected_payment_version: "2", idempotency_key: tag("refund1") });
    const entry = await env.DB.prepare("SELECT kind, debit_account, credit_account, amount_e8, refund_id FROM payment_ledger_transactions WHERE payment_id=? AND kind='refund_settlement'").bind(paymentId).first<{ kind: string; debit_account: string; credit_account: string; amount_e8: string; refund_id: string }>();
    expect(entry).toMatchObject({ kind: "refund_settlement", debit_account: "refund_liability", credit_account: "customer_cash", amount_e8: "30", refund_id: tag("r1") });
  });

  it("outbox events have correct topics and semantic links", async () => {
    await create();
    await settle();
    await rt().refundPayment({ refund_id: tag("r1"), payment_id: paymentId, amount_e8: "50", expected_payment_version: "2", idempotency_key: tag("ref1") });
    const outbox = (await env.DB.prepare("SELECT topic, payment_id, refund_id, semantic_digest FROM payment_outbox_events WHERE payment_id=? ORDER BY created_at").bind(paymentId).all<{ topic: string; payment_id: string; refund_id: string | null; semantic_digest: string }>()).results;
    expect(outbox.length).toBe(3);
    expect(outbox[0].topic).toBe("payment.changed");
    expect(outbox[0].refund_id).toBeNull();
    expect(outbox[1].topic).toBe("payment.changed");
    expect(outbox[2].topic).toBe("refund.changed");
    expect(outbox[2].refund_id).toBe(tag("r1"));
    // Each has a valid 64-char hex digest
    for (const o of outbox) {
      expect(o.semantic_digest).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("audit events track correct action, state transitions, and versions", async () => {
    await create();
    await settle();
    const audits = (await env.DB.prepare("SELECT action, previous_state, next_state, version FROM payment_audit_events WHERE payment_id=? ORDER BY created_at").bind(paymentId).all<{ action: string; previous_state: string | null; next_state: string; version: string }>()).results;
    expect(audits.length).toBe(2);
    expect(audits[0]).toEqual({ action: "payment_created", previous_state: null, next_state: "created", version: "1" });
    expect(audits[1]).toEqual({ action: "payment_transitioned", previous_state: "created", next_state: "succeeded", version: "2" });
  });

  it("does not invert missing authority and D1 read failures", async () => {
    await expect(
      rt().transition({ payment_id: "pay-no-exist", next_state: "authorized", expected_version: "1", idempotency_key: "x" })
    ).resolves.toEqual({ ok: false, code: "NOT_FOUND" });
    await env.DB.exec("ALTER TABLE payment_records RENAME TO payment_records_authoritative");
    try {
      await expect(
        rt().transition({ payment_id: "pay-read-failure", next_state: "authorized", expected_version: "1", idempotency_key: "read-failure" })
      ).resolves.toEqual({ ok: false, code: "UNAVAILABLE" });
    } finally {
      await env.DB.exec("ALTER TABLE payment_records_authoritative RENAME TO payment_records");
    }
  });
});
