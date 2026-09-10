import {
  error,
  isBoundedString,
  json,
  readJson,
} from "./contracts";
import {
  PaymentRuntime,
  type PaymentResult,
} from "./payment-runtime";

const MAX_CONTAINER_ID_LENGTH = 256;

type PaymentOperation = (runtime: PaymentRuntime, input: unknown) => Promise<PaymentResult>;

/**
 * The private Container-to-Worker payment state-machine surface. These exact
 * routes deliberately do not create a public Worker ingress API.
 */
export const paymentControlRoutes: Readonly<Record<string, PaymentOperation>> = {
  "/v1/private/payments/create": (runtime, input) => runtime.create(input),
  "/v1/private/payments/transition": (runtime, input) => runtime.transition(input),
  "/v1/private/payments/create-refund": (runtime, input) => runtime.createRefund(input),
  "/v1/private/payments/transition-refund": (runtime, input) => runtime.transitionRefund(input),
  "/v1/private/payments/refund-payment": (runtime, input) => runtime.refundPayment(input),
  "/v1/private/payments/accept-provider-event": (runtime, input) => runtime.acceptProviderEvent(input),
};

export function isPaymentControlPath(pathname: string): boolean {
  return Object.hasOwn(paymentControlRoutes, pathname);
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function paymentResultResponse(result: PaymentResult): Response {
  if (result.ok) return json(result);

  switch (result.code) {
    case "INVALID_INPUT":
      return error(result.code, 400);
    case "NOT_FOUND":
      return error(result.code, 404);
    case "CONFLICT":
    case "IDEMPOTENCY_COLLISION":
    case "ILLEGAL_TRANSITION":
    case "OVER_REFUND":
      return error(result.code, 409);
    case "CORRUPT_STATE":
    case "UNAVAILABLE":
      // Do not expose storage, authority, or runtime-failure details across
      // the Container boundary.
      return error("PAYMENT_UNAVAILABLE", 503);
  }
}

export async function paymentControlPlane(
  request: Request,
  env: Env,
  pathname: string,
): Promise<Response> {
  if (!isBoundedString(request.headers.get("X-Sub2API-Container-Id"), MAX_CONTAINER_ID_LENGTH)) {
    return error("NOT_FOUND", 404);
  }
  const operation = paymentControlRoutes[pathname];
  if (!operation) return error("NOT_FOUND", 404);

  // The adapter only distinguishes a JSON object from malformed/non-object
  // JSON. PaymentRuntime remains the sole owner of exact input validation.
  const body = await readJson<unknown>(request);
  if (!isJsonObject(body)) return error("INVALID_INPUT", 400);

  try {
    return paymentResultResponse(await operation(new PaymentRuntime(env.DB), body));
  } catch {
    return error("PAYMENT_UNAVAILABLE", 503);
  }
}
