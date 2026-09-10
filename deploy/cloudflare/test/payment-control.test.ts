import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { controlPlane } from "../src/control-plane";
import { BRIDGE_VERSION } from "../src/contracts";
import { routeIngress } from "../src/index";

let sequence = 0;
let prefix = "";

const id = (name: string) => `${name}-${prefix}`;
const request = (
  path: string,
  body: unknown,
  options: {
    containerID?: string | null;
    host?: string;
    method?: string;
    rawBody?: string;
  } = {},
) => {
  const headers = new Headers({
    "content-type": "application/json",
    "X-Sub2API-Bridge-Version": BRIDGE_VERSION,
  });
  if (options.containerID !== null) {
    headers.set("X-Sub2API-Container-Id", options.containerID ?? "payment-control-test");
  }
  const method = options.method ?? "POST";
  return new Request(`http://${options.host ?? "sub2api.internal"}${path}`, {
    method,
    headers,
    body: method === "GET" || method === "HEAD" ? undefined : options.rawBody ?? JSON.stringify(body),
  });
};

const call = (path: string, body: unknown, options = {}, targetEnv: Env = env) =>
  controlPlane(request(path, body, options), targetEnv);
const code = async (response: Response) =>
  (await response.json<{ error: { code: string } }>()).error.code;

beforeEach(() => {
  prefix = String(++sequence);
});

describe("private payment control plane", () => {
  it("wires every exact private route and preserves runtime success snapshots", async () => {
    const createInput = {
      payment_id: id("pay-main"), account_id: id("account"), amount_e8: "100", idempotency_key: id("create"),
    };
    const created = await call("/v1/private/payments/create", createInput);
    expect(created.status).toBe(200);
    const createdSnapshot = await created.json();
    expect(createdSnapshot).toMatchObject({ ok: true, payment: { payment_id: createInput.payment_id, state: "created", version: "1" } });

    const replay = await call("/v1/private/payments/create", createInput);
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(createdSnapshot);

    const settled = await call("/v1/private/payments/transition", {
      payment_id: createInput.payment_id, next_state: "succeeded", expected_version: "1", idempotency_key: id("settle"),
    });
    expect(settled.status).toBe(200);
    expect(await settled.json()).toMatchObject({ ok: true, payment: { state: "succeeded", version: "2" } });

    const reserved = await call("/v1/private/payments/create-refund", {
      refund_id: id("refund-reserved"), payment_id: createInput.payment_id, amount_e8: "30", expected_payment_version: "2", idempotency_key: id("reserve"),
    });
    expect(reserved.status).toBe(200);
    expect(await reserved.json()).toMatchObject({ ok: true, payment: { version: "3" }, refund: { state: "created", version: "1" } });

    const refundTransition = await call("/v1/private/payments/transition-refund", {
      refund_id: id("refund-reserved"), payment_id: createInput.payment_id, next_state: "succeeded", expected_payment_version: "3", expected_refund_version: "1", idempotency_key: id("settle-refund"),
    });
    expect(refundTransition.status).toBe(200);
    expect(await refundTransition.json()).toMatchObject({ ok: true, payment: { version: "4" }, refund: { state: "succeeded", version: "2" } });

    const immediatePayment = id("pay-immediate");
    await call("/v1/private/payments/create", {
      payment_id: immediatePayment, account_id: id("account-immediate"), amount_e8: "100", idempotency_key: id("create-immediate"),
    });
    await call("/v1/private/payments/transition", {
      payment_id: immediatePayment, next_state: "succeeded", expected_version: "1", idempotency_key: id("settle-immediate"),
    });
    const immediateRefund = await call("/v1/private/payments/refund-payment", {
      refund_id: id("refund-immediate"), payment_id: immediatePayment, amount_e8: "25", expected_payment_version: "2", idempotency_key: id("refund-immediate"),
    });
    expect(immediateRefund.status).toBe(200);
    expect(await immediateRefund.json()).toMatchObject({ ok: true, payment: { version: "3" }, refund: { state: "succeeded", version: "1" } });

    const eventPayment = id("pay-event");
    await call("/v1/private/payments/create", {
      payment_id: eventPayment, account_id: id("account-event"), amount_e8: "100", idempotency_key: id("create-event"),
    });
    const event = await call("/v1/private/payments/accept-provider-event", {
      provider_event_id: id("provider-event"), payment_id: eventPayment, next_state: "authorized", expected_version: "1",
    });
    expect(event.status).toBe(200);
    expect(await event.json()).toMatchObject({ ok: true, payment: { state: "authorized", version: "2" } });
  });

  it("maps every runtime failure class and sanitizes unavailable authority", async () => {
    const paymentID = id("pay-errors");
    const createInput = { payment_id: paymentID, account_id: id("account-errors"), amount_e8: "100", idempotency_key: id("create-errors") };
    expect((await call("/v1/private/payments/create", { ...createInput, extra: true })).status).toBe(400);
    const missing = await call("/v1/private/payments/transition", {
      payment_id: id("missing"), next_state: "authorized", expected_version: "1", idempotency_key: id("missing"),
    });
    expect(missing.status).toBe(404);
    expect(await code(missing)).toBe("NOT_FOUND");

    expect((await call("/v1/private/payments/create", createInput)).status).toBe(200);
    const conflict = await call("/v1/private/payments/transition", {
      payment_id: paymentID, next_state: "authorized", expected_version: "2", idempotency_key: id("stale"),
    });
    expect(conflict.status).toBe(409);
    expect(await code(conflict)).toBe("CONFLICT");
    const collision = await call("/v1/private/payments/create", {
      ...createInput, amount_e8: "99",
    });
    expect(collision.status).toBe(409);
    expect(await code(collision)).toBe("IDEMPOTENCY_COLLISION");
    const illegalTransition = await call("/v1/private/payments/refund-payment", {
      refund_id: id("illegal"), payment_id: paymentID, amount_e8: "1", expected_payment_version: "1", idempotency_key: id("illegal"),
    });
    expect(illegalTransition.status).toBe(409);
    expect(await code(illegalTransition)).toBe("ILLEGAL_TRANSITION");

    await call("/v1/private/payments/transition", {
      payment_id: paymentID, next_state: "succeeded", expected_version: "1", idempotency_key: id("settle-errors"),
    });
    const overRefund = await call("/v1/private/payments/refund-payment", {
      refund_id: id("over"), payment_id: paymentID, amount_e8: "101", expected_payment_version: "2", idempotency_key: id("over"),
    });
    expect(overRefund.status).toBe(409);
    expect(await code(overRefund)).toBe("OVER_REFUND");

    await env.DB.prepare("UPDATE payment_records SET pending_refund_e8='101' WHERE payment_id=?").bind(paymentID).run();
    const corrupt = await call("/v1/private/payments/transition", {
      payment_id: paymentID, next_state: "manual_review", expected_version: "2", idempotency_key: id("corrupt"),
    });
    expect(corrupt.status).toBe(503);
    expect(await code(corrupt)).toBe("PAYMENT_UNAVAILABLE");

    const unavailable = await call("/v1/private/payments/create", {
      payment_id: id("pay-unavailable"), account_id: id("account-unavailable"), amount_e8: "1", idempotency_key: id("unavailable"),
    }, {}, {
      ...env,
      DB: { prepare: () => { throw new Error("injected storage detail"); } },
    } as unknown as Env);
    expect(unavailable.status).toBe(503);
    expect(await code(unavailable)).toBe("PAYMENT_UNAVAILABLE");
  });

  it("rejects malformed, non-object, over-limit, bad-boundary, and unknown requests before payment execution", async () => {
    for (const rawBody of ["{", "[]", "null", "true"]) {
      const response = await controlPlane(request("/v1/private/payments/create", undefined, { rawBody }), env);
      expect(response.status).toBe(400);
      expect(await code(response)).toBe("INVALID_INPUT");
    }
    const oversized = await call("/v1/private/payments/create", { payload: "x".repeat(70_000) });
    expect(oversized.status).toBe(400);
    expect(await code(oversized)).toBe("INVALID_INPUT");
    expect((await call("/v1/private/payments/create", {}, { containerID: "" })).status).toBe(404);
    expect((await call("/v1/private/payments/create", {}, { containerID: null })).status).toBe(404);
    expect((await call("/v1/private/payments/create", {}, { method: "GET" })).status).toBe(404);
    expect((await call("/v1/private/payments/create", {}, { host: "public.example" })).status).toBe(404);
    expect((await call("/v1/private/payments/nope", {})).status).toBe(404);
    expect((await call("/v1/private/payments/create/nope", {})).status).toBe(404);

    const publicIngress = await routeIngress(
      new Request("http://sub2api.internal/v1/private/payments/create", { method: "POST" }),
      env,
    );
    expect(publicIngress.status).toBe(404);
  });
});
