import {
  error,
  isBoundedString,
  json,
  readJson,
} from "./contracts";
import {
  SettingsRuntime,
  SettingsRuntimeError,
  type SettingMutation,
  type SettingsKey,
  type SettingsKeyring,
} from "./settings-runtime";

const SETTINGS_KEYRING_SECRET = "SUB2API_CF_SETTINGS_KEYRING";
const MAX_KEYRING_SECRET_BYTES = 8_192;
const MAX_PREVIOUS_KEYS = 8;
const MAX_CONTAINER_ID_LENGTH = 256;
const SETTINGS_ACCOUNT_ID = "sub2api-settings-control-v1";
const SETTINGS_DOMAIN = "worker-private-control-plane-v1";
const KEY_ID_RE = /^[A-Za-z0-9._:-]{1,64}$/;
const BASE64URL_32_RE = /^[A-Za-z0-9_-]{43}$/;

/**
 * These names are Worker secrets, intentionally absent from generated Env.
 * The control plane narrows Env locally so a config type refresh cannot make
 * an undeclared secret silently look like a non-secret variable.
 */
type SettingsControlEnv = Env & {
  SUB2API_CF_SETTINGS_KEYRING?: string;
};

type KeyDescriptor = Readonly<{ id: string; key: string }>;
type KeyringDocument = Readonly<{
  current: KeyDescriptor;
  previous?: readonly KeyDescriptor[];
  fingerprint: string;
}>;
type JsonObject = Record<string, unknown>;
type RouteHandler = (
  request: Request,
  runtime: SettingsRuntime,
) => Promise<Response>;

const own = (value: object, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(value, key);

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function only(value: JsonObject, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function exactKeys(value: JsonObject, required: readonly string[], optional: readonly string[] = []): boolean {
  return only(value, [...required, ...optional]) && required.every((key) => own(value, key));
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index++) difference |= left[index] ^ right[index];
  return difference === 0;
}

function decodeBase64url32(value: unknown): Uint8Array | null {
  if (typeof value !== "string" || !BASE64URL_32_RE.test(value)) return null;
  try {
    const decoded = Uint8Array.from(atob(`${value.replaceAll("-", "+").replaceAll("_", "/")}=`), (character) => character.charCodeAt(0));
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

function parseKeyDescriptor(value: unknown): SettingsKey | null {
  if (!isObject(value) || !exactKeys(value, ["id", "key"]) || typeof value.id !== "string" || !KEY_ID_RE.test(value.id)) return null;
  const material = decodeBase64url32(value.key);
  return material ? { id: value.id, material } : null;
}

function parseKeyring(value: unknown): SettingsKeyring | null {
  if (typeof value !== "string" || new TextEncoder().encode(value).byteLength > MAX_KEYRING_SECRET_BYTES) return null;
  let document: unknown;
  try {
    document = JSON.parse(value);
  } catch {
    return null;
  }
  if (!isObject(document) || !exactKeys(document, ["current", "fingerprint"], ["previous"])) return null;
  if (document.previous !== undefined && (!Array.isArray(document.previous) || document.previous.length > MAX_PREVIOUS_KEYS)) return null;
  const current = parseKeyDescriptor(document.current);
  const previous = document.previous === undefined
    ? []
    : document.previous.map(parseKeyDescriptor);
  const fingerprintMaterial = decodeBase64url32(document.fingerprint);
  if (!current || previous.some((key) => key === null) || !fingerprintMaterial) return null;
  const dataKeys = [current, ...(previous as SettingsKey[])];
  for (let index = 0; index < dataKeys.length; index++) {
    if (sameBytes(dataKeys[index].material, fingerprintMaterial)) return null;
    for (let other = index + 1; other < dataKeys.length; other++) {
      if (dataKeys[index].id === dataKeys[other].id || sameBytes(dataKeys[index].material, dataKeys[other].material)) return null;
    }
  }
  return { current, ...(dataKeys.length > 1 ? { previous: dataKeys.slice(1) } : {}), fingerprintMaterial };
}

function createRuntime(env: Env): SettingsRuntime | null {
  try {
    const keyring = parseKeyring((env as SettingsControlEnv)[SETTINGS_KEYRING_SECRET]);
    if (!keyring) return null;
    return new SettingsRuntime({
      db: env.DB,
      keyring,
      accountId: SETTINGS_ACCOUNT_ID,
      domain: SETTINGS_DOMAIN,
    });
  } catch {
    return null;
  }
}

async function body(request: Request): Promise<JsonObject | null> {
  const parsed = await readJson<unknown>(request);
  return isObject(parsed) ? parsed : null;
}

function writeOptions(value: JsonObject): { requestId: string; expectedVersion?: string } | null {
  if (typeof value.request_id !== "string") return null;
  if (value.expected_version !== undefined && typeof value.expected_version !== "string") return null;
  return {
    requestId: value.request_id,
    ...(value.expected_version === undefined ? {} : { expectedVersion: value.expected_version }),
  };
}

function mutation(value: unknown): SettingMutation | null {
  if (!isObject(value) || typeof value.kind !== "string" || typeof value.key !== "string") return null;
  if (value.kind === "set") {
    if (!exactKeys(value, ["kind", "key", "value"], ["expected_version"]) || typeof value.value !== "string" ||
      (value.expected_version !== undefined && typeof value.expected_version !== "string")) return null;
    return { kind: "set", key: value.key, value: value.value, ...(value.expected_version === undefined ? {} : { expectedVersion: value.expected_version }) };
  }
  if (value.kind === "delete") {
    if (!exactKeys(value, ["kind", "key"], ["expected_version"]) ||
      (value.expected_version !== undefined && typeof value.expected_version !== "string")) return null;
    return { kind: "delete", key: value.key, ...(value.expected_version === undefined ? {} : { expectedVersion: value.expected_version }) };
  }
  return null;
}

const invalid = (): Response => error("INVALID_INPUT", 400);

async function get(request: Request, runtime: SettingsRuntime): Promise<Response> {
  const value = await body(request);
  if (!value || !exactKeys(value, ["key"]) || typeof value.key !== "string") return invalid();
  return json(await runtime.get(value.key));
}

async function getValue(request: Request, runtime: SettingsRuntime): Promise<Response> {
  const value = await body(request);
  if (!value || !exactKeys(value, ["key"]) || typeof value.key !== "string") return invalid();
  return json(await runtime.getValue(value.key));
}

async function getMultiple(request: Request, runtime: SettingsRuntime): Promise<Response> {
  const value = await body(request);
  if (!value || !exactKeys(value, ["keys"]) || !Array.isArray(value.keys) || value.keys.length > 512 || !value.keys.every((key) => typeof key === "string")) return invalid();
  return json(await runtime.getMultiple(value.keys));
}

async function getAll(request: Request, runtime: SettingsRuntime): Promise<Response> {
  const value = await body(request);
  if (!value || !exactKeys(value, [])) return invalid();
  return json(await runtime.getAll());
}

async function set(request: Request, runtime: SettingsRuntime): Promise<Response> {
  const value = await body(request);
  if (!value || !exactKeys(value, ["key", "value", "request_id"], ["expected_version"]) || typeof value.key !== "string" || typeof value.value !== "string") return invalid();
  const options = writeOptions(value);
  return options ? json(await runtime.set(value.key, value.value, options)) : invalid();
}

async function setMultiple(request: Request, runtime: SettingsRuntime): Promise<Response> {
  const value = await body(request);
  if (!value || !exactKeys(value, ["values", "request_id"], ["expected_version"]) || !isObject(value.values) || Object.keys(value.values).length > 16 || !Object.values(value.values).every((item) => typeof item === "string")) return invalid();
  const options = writeOptions(value);
  return options ? json(await runtime.setMultiple(value.values as Record<string, string>, options)) : invalid();
}

async function remove(request: Request, runtime: SettingsRuntime): Promise<Response> {
  const value = await body(request);
  if (!value || !exactKeys(value, ["key", "request_id"], ["expected_version"]) || typeof value.key !== "string") return invalid();
  const options = writeOptions(value);
  return options ? json(await runtime.delete(value.key, options)) : invalid();
}

async function mutate(request: Request, runtime: SettingsRuntime): Promise<Response> {
  const value = await body(request);
  if (!value || !exactKeys(value, ["mutations", "request_id"], ["expected_version"]) || !Array.isArray(value.mutations) || value.mutations.length < 1 || value.mutations.length > 16) return invalid();
  const mutations = value.mutations.map(mutation);
  const options = writeOptions(value);
  return mutations.every((item) => item !== null) && options
    ? json(await runtime.mutate(mutations as SettingMutation[], options))
    : invalid();
}

const routes: Readonly<Record<string, RouteHandler>> = {
  "/v1/private/settings/get": get,
  "/v1/private/settings/get-value": getValue,
  "/v1/private/settings/get-multiple": getMultiple,
  "/v1/private/settings/get-all": getAll,
  "/v1/private/settings/set": set,
  "/v1/private/settings/set-multiple": setMultiple,
  "/v1/private/settings/delete": remove,
  "/v1/private/settings/mutate": mutate,
};

export function isSettingsControlPath(path: string): boolean {
  return own(routes, path);
}

function statusFor(errorValue: SettingsRuntimeError): number {
  switch (errorValue.code) {
    case "INVALID_INPUT": return 400;
    case "NOT_FOUND": return 404;
    case "CAS_MISMATCH":
    case "IDEMPOTENCY_COLLISION":
    case "VERSION_EXHAUSTED": return 409;
    default: return 503;
  }
}

export async function settingsControlPlane(request: Request, env: Env, path: string): Promise<Response> {
  if (!isBoundedString(request.headers.get("X-Sub2API-Container-Id"), MAX_CONTAINER_ID_LENGTH)) return error("NOT_FOUND", 404);
  const handler = routes[path];
  if (!handler) return error("NOT_FOUND", 404);
  const runtime = createRuntime(env);
  if (!runtime) return error("SETTINGS_UNAVAILABLE", 503);
  try {
    return await handler(request, runtime);
  } catch (caught) {
    if (caught instanceof SettingsRuntimeError) {
      const status = statusFor(caught);
      if (caught.code === "NOT_FOUND") return error("SETTING_NOT_FOUND", status);
      return status === 503 ? error("SETTINGS_UNAVAILABLE", status) : error(caught.code, status);
    }
    return error("SETTINGS_UNAVAILABLE", 503);
  }
}
