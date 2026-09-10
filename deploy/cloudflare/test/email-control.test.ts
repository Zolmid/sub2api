import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { BRIDGE_VERSION } from "../src/contracts";
import { parseEmailKeyring } from "../src/email-control";
import { routeIngress, routePrivateControlPlane } from "../src/index";

const material = (offset: number): Uint8Array =>
  Uint8Array.from({ length: 32 }, (_, index) => (offset + index) % 256);
const base64url = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
const key = (id: string, offset: number) => ({ id, key: base64url(material(offset)) });
const ring = (current: { id: string; key: string }, previous: readonly { id: string; key: string }[] = []) =>
  JSON.stringify({ current, ...(previous.length ? { previous } : {}) });

const configuredEnv = (
  token = ring(key("email-token-current", 1)),
  delivery = ring(key("email-delivery-current", 101)),
): Env => new Proxy(env, {
  get(target, property, receiver) {
    if (property === "SUB2API_CF_EMAIL_TOKEN_KEYRING") return token;
    if (property === "SUB2API_CF_EMAIL_DELIVERY_KEYRING") return delivery;
    return Reflect.get(target, property, receiver);
  },
}) as Env;

const request = (
  path: string,
  body: unknown,
  options: Readonly<{
    host?: string;
    method?: string;
    bridge?: string | null;
    container?: string | null;
    raw?: string;
  }> = {},
): Request => {
  const method = options.method ?? "POST";
  const headers = new Headers({ "content-type": "application/json" });
  if (options.bridge !== null) headers.set("X-Sub2API-Bridge-Version", options.bridge ?? BRIDGE_VERSION);
  if (options.container !== null) headers.set("X-Sub2API-Container-Id", options.container ?? "email-control-test");
  return new Request(`http://${options.host ?? "sub2api.internal"}${path}`, {
    method,
    headers,
    ...(method === "GET" || method === "HEAD" ? {} : { body: options.raw ?? JSON.stringify(body) }),
  });
};

const call = (path: string, body: unknown, target = configuredEnv(), options = {}) =>
  routePrivateControlPlane(request(path, body, options), target);

const code = async (response: Response): Promise<string> =>
  ((await response.json()) as { error: { code: string } }).error.code;

const issue = (id: string, suffix = id) => ({
  id,
  accountId: "account-email",
  purpose: "verify-email",
  idempotencyKey: `request-${suffix}`,
  deliveryReference: `delivery-${suffix}`,
  expiresAt: "2030-01-01T00:00:00.000Z",
  maxAttempts: 2,
  maxDeliveryAttempts: 2,
});

describe("private EmailRuntime control plane", () => {
  it("routes every EmailRuntime operation through the private router", async () => {
    const target = configuredEnv();
    const verified = await call("/v1/private/email/issue-challenge", issue("email-verify-001"), target);
    expect(verified.status).toBe(200);
    const issued = await verified.json<{ token: string; replayed: boolean }>();
    expect(issued.token).toHaveLength(43);
    expect(issued.replayed).toBe(false);

    const verify = await call("/v1/private/email/verify-challenge", {
      id: "email-verify-001", accountId: "account-email", purpose: "verify-email", token: issued.token,
    }, target);
    expect(verify.status).toBe(200);
    expect(await verify.json()).toEqual({ ok: true });

    const deliveryIssue = await call("/v1/private/email/issue-challenge", issue("email-delivery-001"), target);
    expect(deliveryIssue.status).toBe(200);
    const claim = await call("/v1/private/email/claim-delivery-jobs", { worker: "worker-email", limit: 1 }, target);
    expect(claim.status).toBe(200);
    const jobs = (await claim.json<{ jobs: Array<{ id: string; fence: string; token: string; deliveryReference: string }> }>()).jobs;
    expect(jobs).toHaveLength(1);
    expect(jobs[0]).toMatchObject({ token: expect.any(String), deliveryReference: "delivery-email-delivery-001" });

    const renew = await call("/v1/private/email/renew-delivery", {
      id: jobs[0]!.id, worker: "worker-email", fence: jobs[0]!.fence, leaseSeconds: 90,
    }, target);
    expect(renew.status).toBe(200);
    const complete = await call("/v1/private/email/complete-delivery", {
      id: jobs[0]!.id, worker: "worker-email", fence: jobs[0]!.fence,
    }, target);
    expect(complete.status).toBe(200);

    await expect(call("/v1/private/email/issue-challenge", issue("email-fail-001"), target)).resolves.toHaveProperty("status", 200);
    const failedClaim = await call("/v1/private/email/claim-delivery-jobs", { worker: "worker-email", limit: 1 }, target);
    const failedJob = (await failedClaim.json<{ jobs: Array<{ id: string; fence: string }> }>()).jobs[0]!;
    const failed = await call("/v1/private/email/fail-delivery", {
      id: failedJob.id, worker: "worker-email", fence: failedJob.fence, errorCode: "provider-timeout",
    }, target);
    expect(failed.status).toBe(200);
    expect(await failed.json()).toEqual({ state: "pending" });
  });

  it("accepts rotated previous keys but rejects malformed, duplicate, and cross-ring secret material", async () => {
    const tokenOld = key("email-token-old", 1);
    const deliveryOld = key("email-delivery-old", 101);
    const initial = configuredEnv(ring(tokenOld), ring(deliveryOld));
    const response = await call("/v1/private/email/issue-challenge", issue("email-rotate-001"), initial);
    const token = (await response.json<{ token: string }>()).token;

    const rotated = configuredEnv(
      ring(key("email-token-current", 2), [tokenOld]),
      ring(key("email-delivery-current", 102), [deliveryOld]),
    );
    const verified = await call("/v1/private/email/verify-challenge", {
      id: "email-rotate-001", accountId: "account-email", purpose: "verify-email", token,
    }, rotated);
    expect(verified.status).toBe(200);

    expect(parseEmailKeyring(JSON.stringify({ current: tokenOld, previous: [tokenOld] }))).toBeNull();
    expect(parseEmailKeyring(JSON.stringify({ current: { id: "bad", key: "not-a-key" } }))).toBeNull();
    expect((await call("/v1/private/email/issue-challenge", issue("email-malformed-001"), configuredEnv("{", ring(deliveryOld)))).status).toBe(503);
    expect((await call("/v1/private/email/issue-challenge", issue("email-cross-ring-001"), configuredEnv(ring(tokenOld), ring(tokenOld)))).status).toBe(503);
  });

  it("bounds every request and maps not-found, lease conflict, and unavailable state without leaking errors", async () => {
    const target = configuredEnv();
    for (const raw of ["{", "[]", "null", "true"]) {
      const response = await call("/v1/private/email/issue-challenge", undefined, target, { raw });
      expect(response.status).toBe(400);
      expect(await code(response)).toBe("INVALID_EMAIL_REQUEST");
    }
    const oversized = await call("/v1/private/email/issue-challenge", {
      ...issue("email-large-001"), deliveryReference: "x".repeat(4_097),
    }, target);
    expect(oversized.status).toBe(400);
    const oversizedBody = await call("/v1/private/email/issue-challenge", undefined, target, {
      raw: `{\"payload\":\"${"x".repeat(70_000)}\"}`,
    });
    expect(oversizedBody.status).toBe(400);
    const missing = await call("/v1/private/email/verify-challenge", {
      id: "email-missing-001", accountId: "account-email", purpose: "verify-email", token: "a".repeat(43),
    }, target);
    expect(missing.status).toBe(404);
    expect(await code(missing)).toBe("EMAIL_NOT_FOUND");

    await call("/v1/private/email/issue-challenge", issue("email-fence-001"), target);
    const claim = await call("/v1/private/email/claim-delivery-jobs", { worker: "worker-email" }, target);
    const job = (await claim.json<{ jobs: Array<{ id: string; fence: string }> }>()).jobs[0]!;
    const stale = await call("/v1/private/email/complete-delivery", {
      id: job.id, worker: "worker-email", fence: String(Number(job.fence) + 1),
    }, target);
    expect(stale.status).toBe(409);
    expect(await code(stale)).toBe("EMAIL_LEASE_CONFLICT");

    const unavailable = await call("/v1/private/email/issue-challenge", issue("email-storage-001"), {
      ...target,
      DB: { prepare: () => { throw new Error("private D1 details"); } },
    } as unknown as Env);
    expect(unavailable.status).toBe(503);
    expect(await code(unavailable)).toBe("EMAIL_UNAVAILABLE");
  });

  it("rejects non-bridge callers and preserves the public /v1/private ingress reservation", async () => {
    expect((await call("/v1/private/email/issue-challenge", issue("email-public-001"), configuredEnv(), { host: "public.example" })).status).toBe(404);
    expect((await call("/v1/private/email/issue-challenge", issue("email-method-001"), configuredEnv(), { method: "GET" })).status).toBe(404);
    expect((await call("/v1/private/email/issue-challenge", issue("email-header-001"), configuredEnv(), { bridge: null })).status).toBe(404);
    const ingress = await routeIngress(
      new Request("http://public.example/v1/private/email/issue-challenge", { method: "POST" }),
      env,
    );
    expect(ingress.status).toBe(404);
  });
});
