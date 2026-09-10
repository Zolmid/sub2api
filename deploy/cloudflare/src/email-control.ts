import {
  EmailRuntime,
  EmailRuntimeError,
  type EmailKeyring,
  type RotatingKey,
} from "./email-runtime";
import {
  BRIDGE_VERSION,
  INTERNAL_HOST,
  error,
  isBoundedString,
  json,
  readJson,
} from "./contracts";

const TOKEN_KEYRING_SECRET = "SUB2API_CF_EMAIL_TOKEN_KEYRING";
const DELIVERY_KEYRING_SECRET = "SUB2API_CF_EMAIL_DELIVERY_KEYRING";
const MAX_KEYRING_SECRET_BYTES = 4_096;
const MAX_PREVIOUS_KEYS = 4;
const MAX_CONTAINER_ID_LENGTH = 256;
const MAX_DELIVERY_REFERENCE_BYTES = 4_096;
const MAX_COUNTER = 9_223_372_036_854_775_807n;
const ID = /^[a-z0-9][a-z0-9_-]{7,127}$/;
const SMALL = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

type EmailControlEnv = Env & {
  SUB2API_CF_EMAIL_TOKEN_KEYRING?: string;
  SUB2API_CF_EMAIL_DELIVERY_KEYRING?: string;
};

type JsonObject = Record<string, unknown>;

const own = (value: object, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(value, key);

function object(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(
  value: JsonObject,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return Object.keys(value).every((key) => allowed.has(key)) &&
    required.every((key) => own(value, key));
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function decodeBase64url32(value: unknown): Uint8Array | null {
  if (typeof value !== "string" || !BASE64URL_32.test(value)) return null;
  try {
    const decoded = Uint8Array.from(
      atob(`${value.replaceAll("-", "+").replaceAll("_", "/")}=`),
      (character) => character.charCodeAt(0),
    );
    if (decoded.byteLength !== 32) return null;
    const canonical = btoa(String.fromCharCode(...decoded))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replace(/=+$/, "");
    return canonical === value ? decoded : null;
  } catch {
    return null;
  }
}

function parseKey(value: unknown): RotatingKey | null {
  if (!object(value) || !exactKeys(value, ["id", "key"])) return null;
  if (typeof value.id !== "string" || !SMALL.test(value.id)) return null;
  const material = decodeBase64url32(value.key);
  return material ? { id: value.id, material } : null;
}

/**
 * Parses one independently-managed 32-byte base64url keyring. A single
 * current key is mandatory; previous keys are deliberately bounded so a
 * compromised/forgotten rotation cannot make every request unbounded work.
 */
export function parseEmailKeyring(raw: unknown):
  | { current: RotatingKey; previous?: readonly RotatingKey[] }
  | null {
  if (
    typeof raw !== "string" ||
    new TextEncoder().encode(raw).byteLength > MAX_KEYRING_SECRET_BYTES
  ) {
    return null;
  }
  let document: unknown;
  try {
    document = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!object(document) || !exactKeys(document, ["current"], ["previous"])) {
    return null;
  }
  if (
    document.previous !== undefined &&
    (!Array.isArray(document.previous) || document.previous.length > MAX_PREVIOUS_KEYS)
  ) {
    return null;
  }
  const current = parseKey(document.current);
  const previous = document.previous === undefined
    ? []
    : document.previous.map(parseKey);
  if (!current || previous.some((key) => key === null)) return null;
  const keys = [current, ...(previous as RotatingKey[])];
  for (let index = 0; index < keys.length; index++) {
    for (let other = index + 1; other < keys.length; other++) {
      if (
        keys[index]!.id === keys[other]!.id ||
        sameBytes(keys[index]!.material, keys[other]!.material)
      ) {
        return null;
      }
    }
  }
  return {
    current,
    ...(keys.length > 1 ? { previous: keys.slice(1) } : {}),
  };
}

function runtime(env: Env): EmailRuntime | null {
  try {
    const secretEnv = env as EmailControlEnv;
    const token = parseEmailKeyring(secretEnv[TOKEN_KEYRING_SECRET]);
    const delivery = parseEmailKeyring(secretEnv[DELIVERY_KEYRING_SECRET]);
    if (!token || !delivery) return null;
    const ring: EmailKeyring = { token, delivery };
    return new EmailRuntime(env.DB, ring);
  } catch {
    // Key material and storage configuration are never surfaced to callers.
    return null;
  }
}

function validText(value: unknown, maximumBytes: number): value is string {
  if (
    typeof value !== "string" || value.includes("\0") ||
    new TextEncoder().encode(value).byteLength > maximumBytes
  ) return false;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (++index >= value.length) return false;
      const low = value.charCodeAt(index);
      if (low < 0xdc00 || low > 0xdfff) return false;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function validId(value: unknown): value is string {
  return typeof value === "string" && ID.test(value);
}

function validSmall(value: unknown): value is string {
  return typeof value === "string" && SMALL.test(value);
}

function validCounter(value: unknown): value is string {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,18}$/.test(value)) return false;
  try {
    return BigInt(value) <= MAX_COUNTER;
  } catch {
    return false;
  }
}

function validUtc(value: unknown): value is string {
  return typeof value === "string" && UTC.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

function validInteger(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" && Number.isInteger(value) &&
    value >= minimum && value <= maximum;
}

function invalid(): Response {
  return error("INVALID_EMAIL_REQUEST", 400);
}

function unavailable(): Response {
  return error("EMAIL_UNAVAILABLE", 503);
}

async function body(request: Request): Promise<JsonObject | null> {
  const parsed = await readJson<unknown>(request);
  return object(parsed) ? parsed : null;
}

async function issueChallenge(request: Request, service: EmailRuntime): Promise<Response> {
  const value = await body(request);
  if (
    !value ||
    !exactKeys(value, [
      "id", "accountId", "purpose", "idempotencyKey", "deliveryReference", "expiresAt",
    ], ["maxAttempts", "maxDeliveryAttempts"]) ||
    !validId(value.id) || !validSmall(value.accountId) || !validSmall(value.purpose) ||
    !validSmall(value.idempotencyKey) || !validText(value.deliveryReference, MAX_DELIVERY_REFERENCE_BYTES) ||
    !validUtc(value.expiresAt) ||
    (value.maxAttempts !== undefined && !validInteger(value.maxAttempts, 1, 20)) ||
    (value.maxDeliveryAttempts !== undefined && !validInteger(value.maxDeliveryAttempts, 1, 20))
  ) {
    return invalid();
  }
  return json(await service.issueChallenge(value));
}

async function verifyChallenge(request: Request, service: EmailRuntime): Promise<Response> {
  const value = await body(request);
  if (
    !value || !exactKeys(value, ["id", "accountId", "purpose", "token"]) ||
    !validId(value.id) || !validSmall(value.accountId) || !validSmall(value.purpose) ||
    !validText(value.token, 64) || !BASE64URL_32.test(value.token)
  ) return invalid();
  await service.verifyChallenge(value);
  return json({ ok: true });
}

async function claimDeliveryJobs(request: Request, service: EmailRuntime): Promise<Response> {
  const value = await body(request);
  if (
    !value || !exactKeys(value, ["worker"], ["limit"]) || !validSmall(value.worker) ||
    (value.limit !== undefined && !validInteger(value.limit, 1, 100))
  ) return invalid();
  return json({ jobs: await service.claimDeliveryJobs(value.worker, value.limit as number | undefined) });
}

async function renewDelivery(request: Request, service: EmailRuntime): Promise<Response> {
  const value = await body(request);
  if (
    !value || !exactKeys(value, ["id", "worker", "fence"], ["leaseSeconds"]) ||
    !validId(value.id) || !validSmall(value.worker) || !validCounter(value.fence) ||
    (value.leaseSeconds !== undefined && !validInteger(value.leaseSeconds, 1, 900))
  ) return invalid();
  await service.renewDelivery(value.id, value.worker, value.fence, value.leaseSeconds as number | undefined);
  return json({ ok: true });
}

async function completeDelivery(request: Request, service: EmailRuntime): Promise<Response> {
  const value = await body(request);
  if (
    !value || !exactKeys(value, ["id", "worker", "fence"]) || !validId(value.id) ||
    !validSmall(value.worker) || !validCounter(value.fence)
  ) return invalid();
  await service.completeDelivery(value.id, value.worker, value.fence);
  return json({ ok: true });
}

async function failDelivery(request: Request, service: EmailRuntime): Promise<Response> {
  const value = await body(request);
  if (
    !value || !exactKeys(value, ["id", "worker", "fence", "errorCode"]) ||
    !validId(value.id) || !validSmall(value.worker) || !validCounter(value.fence) ||
    !validSmall(value.errorCode)
  ) return invalid();
  return json({ state: await service.failDelivery(value.id, value.worker, value.fence, value.errorCode) });
}

type Operation = (request: Request, service: EmailRuntime) => Promise<Response>;

/** The complete private, D1-only EmailRuntime route contract. */
export const emailControlRoutes: Readonly<Record<string, Operation>> = {
  "/v1/private/email/issue-challenge": issueChallenge,
  "/v1/private/email/verify-challenge": verifyChallenge,
  "/v1/private/email/claim-delivery-jobs": claimDeliveryJobs,
  "/v1/private/email/renew-delivery": renewDelivery,
  "/v1/private/email/complete-delivery": completeDelivery,
  "/v1/private/email/fail-delivery": failDelivery,
};

export function isEmailControlPath(pathname: string): boolean {
  return own(emailControlRoutes, pathname);
}

function responseFor(cause: unknown): Response {
  if (!(cause instanceof EmailRuntimeError)) return unavailable();
  switch (cause.code) {
    case "invalid_input":
      return invalid();
    case "challenge_not_found":
    case "job_not_found":
      return error("EMAIL_NOT_FOUND", 404);
    case "stale_fence":
      return error("EMAIL_LEASE_CONFLICT", 409);
    case "challenge_expired":
    case "challenge_consumed":
    case "invalid_token":
    case "idempotency_collision":
    case "counter_exhausted":
      return error("EMAIL_CONFLICT", 409);
    case "clock_failure":
    case "idempotency_corrupt":
    case "unknown_key_id":
    case "corrupt_state":
    case "storage_failure":
      return unavailable();
  }
}

/**
 * Handles only the email-private namespace. `null` means another private
 * control-plane adapter owns the path. The handler repeats the bridge checks
 * so direct invocation cannot turn it into public Worker ingress.
 */
export async function emailControlPlane(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (!isEmailControlPath(url.pathname)) return null;
  if (
    url.hostname !== INTERNAL_HOST || request.method !== "POST" ||
    request.headers.get("X-Sub2API-Bridge-Version") !== BRIDGE_VERSION ||
    !isBoundedString(request.headers.get("X-Sub2API-Container-Id"), MAX_CONTAINER_ID_LENGTH)
  ) {
    return error("NOT_FOUND", 404);
  }
  const service = runtime(env);
  if (!service) return unavailable();
  try {
    return await emailControlRoutes[url.pathname]!(request, service);
  } catch (cause) {
    return responseFor(cause);
  }
}
