import {
  error,
  isBoundedString,
  json,
  readJson,
} from "./contracts";
import {
  SubscriptionRuntime,
  SubscriptionRuntimeError,
} from "./subscription-runtime";

type RuntimeOperation = (runtime: SubscriptionRuntime, input: unknown) => Promise<unknown>;

const invalidInputCodes = new Set([
  "INVALID_INPUT",
  "UNKNOWN_FIELD",
  "MISSING_FIELD",
  "INVALID_OPERATION_ID",
  "INVALID_ID",
  "INVALID_MONEY",
  "MONEY_OVERFLOW",
  "INVALID_TIMESTAMP",
  "INVALID_TEXT",
  "INVALID_INTEGER",
  "INVALID_BOOLEAN",
  "INVALID_STATUS",
  "INVALID_CURRENCY",
  "INVALID_VALIDITY_UNIT",
  "BOUNDARY_IN_FUTURE",
  "NO_WINDOWS_SELECTED",
]);

const notFoundCodes = new Set([
  "USER_NOT_FOUND",
  "ADMIN_NOT_FOUND",
  "GROUP_NOT_FOUND",
  "PLAN_NOT_FOUND",
  "SUBSCRIPTION_NOT_FOUND",
]);

const conflictCodes = new Set([
  "IDEMPOTENCY_CONFLICT",
  "CREATE_PLAN_CONFLICT",
  "ASSIGN_CONFLICT",
  "STALE_VERSION",
  "SUBSCRIPTION_NOT_REVOKED",
  "RESTORE_CONFLICT",
  "WINDOWS_ALREADY_ACTIVATED",
  "WINDOWS_NOT_ACTIVATED",
  "SUBSCRIPTION_SUSPENDED",
  "SUBSCRIPTION_EXPIRED",
  "DAILY_LIMIT_EXCEEDED",
  "WEEKLY_LIMIT_EXCEEDED",
  "MONTHLY_LIMIT_EXCEEDED",
  "SWEEP_CONFLICT",
  "GROUP_NOT_SUBSCRIPTION_TYPE",
  "VERSION_OVERFLOW",
  "CANNOT_SHORTEN_EXPIRED",
  "ADJUST_WOULD_EXPIRE",
]);

/**
 * The private Go-to-Worker protocol surface. Keep this table as the single
 * source of truth for the exact, versioned subscription route contract.
 */
export const subscriptionControlRoutes: Readonly<Record<string, RuntimeOperation>> = {
  "/v1/subscriptions/plans/create": (runtime, input) => runtime.createPlan(input),
  "/v1/subscriptions/plans/get": (runtime, input) => runtime.getPlan(input),
  "/v1/subscriptions/plans/list": (runtime, input) => runtime.listPlans(input),
  "/v1/subscriptions/assign-or-extend": (runtime, input) => runtime.assignOrExtend(input),
  "/v1/subscriptions/get": (runtime, input) => runtime.getSubscription(input),
  "/v1/subscriptions/list": (runtime, input) => runtime.listSubscriptions(input),
  "/v1/subscriptions/revoke": (runtime, input) => runtime.revoke(input),
  "/v1/subscriptions/restore": (runtime, input) => runtime.restore(input),
  "/v1/subscriptions/extend": (runtime, input) => runtime.extend(input),
  "/v1/subscriptions/windows/activate": (runtime, input) => runtime.activateWindows(input),
  "/v1/subscriptions/windows/maintain": (runtime, input) => runtime.maintainWindows(input),
  "/v1/subscriptions/windows/reset": (runtime, input) => runtime.resetWindows(input),
  "/v1/subscriptions/usage/reserve": (runtime, input) => runtime.reserveUsage(input),
  "/v1/subscriptions/expiry/sweep": (runtime, input) => runtime.sweepExpired(input),
};

export function isSubscriptionControlPath(pathname: string): boolean {
  return Object.hasOwn(subscriptionControlRoutes, pathname);
}

function subscriptionErrorResponse(cause: unknown): Response {
  if (!(cause instanceof SubscriptionRuntimeError)) {
    return error("SUBSCRIPTION_UNAVAILABLE", 503);
  }
  if (invalidInputCodes.has(cause.code)) return error(cause.code, 400);
  if (notFoundCodes.has(cause.code)) return error(cause.code, 404);
  if (conflictCodes.has(cause.code)) return error(cause.code, 409);

  // Corrupt persisted state and future runtime-only codes are unavailable to
  // the bridge. Do not turn internal state or exception text into a protocol.
  return error("SUBSCRIPTION_UNAVAILABLE", 503);
}

export async function subscriptionControlPlane(
  request: Request,
  env: Env,
  pathname: string,
): Promise<Response> {
  if (!isBoundedString(request.headers.get("X-Sub2API-Container-Id"), 256)) {
    return error("NOT_FOUND", 404);
  }
  const operation = subscriptionControlRoutes[pathname];
  if (!operation) return error("NOT_FOUND", 404);

  const body = await readJson<unknown>(request);
  if (body === null) return error("INVALID_REQUEST", 400);

  try {
    return json(await operation(new SubscriptionRuntime(env.DB), body));
  } catch (cause) {
    return subscriptionErrorResponse(cause);
  }
}
