import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { controlPlane } from "../src/control-plane";
import { BRIDGE_VERSION } from "../src/contracts";

const material = (offset: number): Uint8Array =>
  Uint8Array.from({ length: 32 }, (_, index) => (offset + index) % 256);
const base64url = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
const dataKey = (id: string, offset: number) => ({ id, key: base64url(material(offset)) });
const keyring = (
  current = dataKey("current", 1),
  previous: readonly { id: string; key: string }[] = [],
  fingerprint = base64url(material(201)),
): string => JSON.stringify({ current, ...(previous.length > 0 ? { previous } : {}), fingerprint });

let sequence = 0;
const requestID = (): string => `settings-control-request-${++sequence}`;

const overrideEnv = (overrides: Record<string, unknown>): Env =>
  new Proxy(env, {
    get(target, property, receiver) {
      return Object.prototype.hasOwnProperty.call(overrides, property)
        ? overrides[property as string]
        : Reflect.get(target, property, receiver);
    },
  }) as Env;

const configuredEnv = (secret = keyring()): Env => overrideEnv({
  SUB2API_CF_SETTINGS_KEYRING: secret,
});

const request = (
  path: string,
  body: unknown,
  options: Readonly<{
    host?: string;
    method?: string;
    version?: string;
    containerID?: string | null;
  }> = {},
): Request => {
  const method = options.method ?? "POST";
  const headers = new Headers({ "content-type": "application/json" });
  if (options.version !== null) headers.set("X-Sub2API-Bridge-Version", options.version ?? BRIDGE_VERSION);
  if (options.containerID !== null) headers.set("X-Sub2API-Container-Id", options.containerID ?? "container-settings-test");
  return new Request(`http://${options.host ?? "sub2api.internal"}${path}`, {
    method,
    headers,
    ...(method === "GET" || method === "HEAD" ? {} : { body: JSON.stringify(body) }),
  });
};

const call = (path: string, body: unknown, targetEnv = configuredEnv(), options = {}) =>
  controlPlane(request(path, body, options), targetEnv);

const errorCode = async (response: Response): Promise<string> =>
  ((await response.json()) as { error: { code: string } }).error.code;

describe("private settings control plane", () => {
  it("dispatches every explicit SettingsRuntime route and preserves encrypted round trips", async () => {
    const target = configuredEnv();
    const setResponse = await call("/v1/private/settings/set", {
      key: "alpha", value: "encrypted value", request_id: requestID(),
    }, target);
    expect(setResponse.status).toBe(200);
    expect(await setResponse.json()).toMatchObject({ key: "alpha", version: "1", deleted: false, replayed: false });

    const getResponse = await call("/v1/private/settings/get", { key: "alpha" }, target);
    expect(getResponse.status).toBe(200);
    expect(await getResponse.json()).toMatchObject({ key: "alpha", value: "encrypted value", version: "1" });
    expect((await target.DB.prepare("SELECT ciphertext_b64 FROM settings_runtime WHERE setting_key='alpha'").first("ciphertext_b64")) as string).not.toContain("encrypted value");

    const getValueResponse = await call("/v1/private/settings/get-value", { key: "alpha" }, target);
    expect(getValueResponse.status).toBe(200);
    expect(await getValueResponse.json()).toBe("encrypted value");

    const missingValueResponse = await call("/v1/private/settings/get-value", { key: "missing" }, target);
    expect(missingValueResponse.status).toBe(404);
    expect(await errorCode(missingValueResponse)).toBe("SETTING_NOT_FOUND");

    const getMultipleResponse = await call("/v1/private/settings/get-multiple", { keys: ["alpha", "missing"] }, target);
    expect(getMultipleResponse.status).toBe(200);
    expect(await getMultipleResponse.json()).toEqual({ alpha: "encrypted value" });

    const setMultipleResponse = await call("/v1/private/settings/set-multiple", {
      values: { beta: "two", gamma: "three" }, request_id: requestID(),
    }, target);
    expect(setMultipleResponse.status).toBe(200);
    expect(await setMultipleResponse.json()).toEqual([
      expect.objectContaining({ key: "beta", deleted: false }),
      expect.objectContaining({ key: "gamma", deleted: false }),
    ]);

    const getAllResponse = await call("/v1/private/settings/get-all", {}, target);
    expect(getAllResponse.status).toBe(200);
    expect(await getAllResponse.json()).toEqual({ alpha: "encrypted value", beta: "two", gamma: "three" });

    const deleteResponse = await call("/v1/private/settings/delete", {
      key: "gamma", request_id: requestID(), expected_version: "1",
    }, target);
    expect(deleteResponse.status).toBe(200);
    expect(await deleteResponse.json()).toMatchObject({ key: "gamma", version: "2", deleted: true });

    const mutateResponse = await call("/v1/private/settings/mutate", {
      request_id: requestID(),
      mutations: [
        { kind: "set", key: "delta", value: "four" },
        { kind: "delete", key: "beta", expected_version: "1" },
      ],
    }, target);
    expect(mutateResponse.status).toBe(200);
    expect(await mutateResponse.json()).toEqual([
      expect.objectContaining({ key: "delta", deleted: false }),
      expect.objectContaining({ key: "beta", deleted: true }),
    ]);
  });

  it("retains exact replay, idempotency collision, and CAS semantics", async () => {
    const target = configuredEnv();
    const replayID = requestID();
    const first = await call("/v1/private/settings/set", { key: "idem", value: "same", request_id: replayID }, target);
    const replay = await call("/v1/private/settings/set", { key: "idem", value: "same", request_id: replayID }, target);
    expect(await first.json()).toMatchObject({ replayed: false, version: "1" });
    expect(await replay.json()).toMatchObject({ replayed: true, version: "1" });

    const collision = await call("/v1/private/settings/set", { key: "idem", value: "different", request_id: replayID }, target);
    expect(collision.status).toBe(409);
    expect(await errorCode(collision)).toBe("IDEMPOTENCY_COLLISION");

    const create = await call("/v1/private/settings/set", {
      key: "cas", value: "first", request_id: requestID(), expected_version: "0",
    }, target);
    expect(create.status).toBe(200);
    const update = await call("/v1/private/settings/set", {
      key: "cas", value: "second", request_id: requestID(), expected_version: "1",
    }, target);
    expect(update.status).toBe(200);
    const stale = await call("/v1/private/settings/set", {
      key: "cas", value: "third", request_id: requestID(), expected_version: "1",
    }, target);
    expect(stale.status).toBe(409);
    expect(await errorCode(stale)).toBe("CAS_MISMATCH");
  });

  it("rejects private-boundary failures, malformed input, oversized bodies, unknown fields, and unknown paths", async () => {
    const target = configuredEnv();
    expect((await controlPlane(request("/v1/private/settings/get", { key: "x" }, { host: "public.example" }), target)).status).toBe(404);
    expect((await controlPlane(request("/v1/private/settings/get", { key: "x" }, { version: "wrong" }), target)).status).toBe(404);
    expect((await controlPlane(request("/v1/private/settings/get", { key: "x" }, { method: "GET" }), target)).status).toBe(404);
    expect((await controlPlane(request("/v1/private/settings/get", { key: "x" }, { containerID: "" }), target)).status).toBe(404);
    expect((await controlPlane(request("/v1/private/settings/get", { key: "x" }, { containerID: null }), target)).status).toBe(404);

    const malformed = new Request("http://sub2api.internal/v1/private/settings/get", {
      method: "POST",
      headers: { "content-type": "application/json", "X-Sub2API-Bridge-Version": BRIDGE_VERSION, "X-Sub2API-Container-Id": "container-settings-test" },
      body: "{",
    });
    const malformedResponse = await controlPlane(malformed, target);
    expect(malformedResponse.status).toBe(400);
    expect(await errorCode(malformedResponse)).toBe("INVALID_INPUT");

    const oversized = await call("/v1/private/settings/set", {
      key: "too-large-body", value: "x".repeat(70_000), request_id: requestID(),
    }, target);
    expect(oversized.status).toBe(400);
    expect(await errorCode(oversized)).toBe("INVALID_INPUT");

    const unknown = await call("/v1/private/settings/get", { key: "x", extra: true }, target);
    expect(unknown.status).toBe(400);
    expect(await errorCode(unknown)).toBe("INVALID_INPUT");
    expect((await call("/v1/private/settings/get/nope", { key: "x" }, target)).status).toBe(404);
  });

  it("fails closed for missing, malformed, duplicate, equal, or fingerprint-reused secret material", async () => {
    const duplicate = base64url(material(10));
    const invalidSecrets = [
      undefined,
      "not-json",
      JSON.stringify({ current: { id: "current", key: "not-canonical-base64url" }, fingerprint: base64url(material(201)) }),
      JSON.stringify({ current: dataKey("current", 1), previous: [{ id: "current", key: base64url(material(2)) }], fingerprint: base64url(material(201)) }),
      JSON.stringify({ current: dataKey("current", 1), previous: [{ id: "old", key: base64url(material(1)) }], fingerprint: base64url(material(201)) }),
      JSON.stringify({ current: { id: "current", key: duplicate }, fingerprint: duplicate }),
    ];
    for (const secret of invalidSecrets) {
      const response = await call("/v1/private/settings/get", { key: "x" }, overrideEnv({ SUB2API_CF_SETTINGS_KEYRING: secret }));
      expect(response.status).toBe(503);
      expect(await errorCode(response)).toBe("SETTINGS_UNAVAILABLE");
    }
  });

  it("reads rows encrypted by an old key after a documented rotation", async () => {
    const old = dataKey("old", 31);
    const original = configuredEnv(keyring(old));
    const write = await call("/v1/private/settings/set", { key: "rotated", value: "old-key-value", request_id: requestID() }, original);
    expect(write.status).toBe(200);

    const rotated = configuredEnv(keyring(dataKey("new", 32), [old]));
    const read = await call("/v1/private/settings/get-value", { key: "rotated" }, rotated);
    expect(read.status).toBe(200);
    expect(await read.json()).toBe("old-key-value");
  });

  it("redacts corrupt D1 and unexpected failures as SETTINGS_UNAVAILABLE", async () => {
    const original = configuredEnv(keyring(dataKey("same-id", 41)));
    expect((await call("/v1/private/settings/set", { key: "corrupt", value: "not-public", request_id: requestID() }, original)).status).toBe(200);
    const wrongKey = configuredEnv(keyring(dataKey("same-id", 42)));
    const corrupt = await call("/v1/private/settings/get-value", { key: "corrupt" }, wrongKey);
    expect(corrupt.status).toBe(503);
    expect(await errorCode(corrupt)).toBe("SETTINGS_UNAVAILABLE");

    const broken = overrideEnv({
      SUB2API_CF_SETTINGS_KEYRING: keyring(),
      DB: { prepare: () => { throw new Error("injected database password"); } },
    });
    const unavailable = await call("/v1/private/settings/get", { key: "x" }, broken);
    expect(unavailable.status).toBe(503);
    const body = await unavailable.text();
    expect(body).toContain("SETTINGS_UNAVAILABLE");
    expect(body).not.toContain("password");
  });
});
