import {
  Container,
  ContainerProxy,
  getContainer,
  type OutboundHandlerContext,
} from "@cloudflare/containers";
import { consumeUsageBatch, controlPlane, drainOutbox } from "./control-plane";
import {
  INTERNAL_HOST,
  error,
  readJson,
  type UsageEnvelope,
} from "./contracts";
import { AuthLoginAdmissionDO } from "./auth-login-admission";
import { AccountLeaseDO } from "./lease";
import { TOTPSecurityDO } from "./totp-security";

export { AccountLeaseDO, AuthLoginAdmissionDO, TOTPSecurityDO, ContainerProxy };

type ContainerRuntimeEnv = Omit<
  Env,
  | "ENVIRONMENT"
  | "ALLOW_TEST_FIXTURE"
  | "SUB2API_CF_UPSTREAM_ALLOWED_HOSTS"
  | "SUB2API_CF_LEASE_TTL_SECONDS"
  | "SUB2API_CF_JWT_SECRET"
> & {
  ENVIRONMENT: string;
  ALLOW_TEST_FIXTURE: string;
  SUB2API_CF_UPSTREAM_ALLOWED_HOSTS: string;
  SUB2API_CF_LEASE_TTL_SECONDS: string;
  SUB2API_CF_JWT_SECRET: string;
};

type LoginAdmissionRuntimeEnv = Env & {
  // This Worker secret is deliberately not declared in wrangler vars.
  SUB2API_CF_LOGIN_ADMISSION_KEY?: string;
};

const FIXTURE_CONTAINER_HEADER = "X-Sub2API-Fixture-Container";
const FIXTURE_CONTAINER_NAMES = new Set(["gateway-a", "gateway-b"]);
const MAX_FIXTURE_DELAY_MS = 60_000;
const RESERVED_INGRESS_HEADERS = [
  FIXTURE_CONTAINER_HEADER,
  "X-Sub2API-Bridge-Version",
  "X-Sub2API-Container-Id",
];
const AUTH_LOGIN_PATH = "/api/v1/auth/login";
const AUTH_LOGIN_ADMISSION_KEY_BYTES = 32;

export type ContainerForwarder = (
  request: Request,
  containerName: string,
) => Promise<Response>;

function validIPv4(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every((part) => {
      if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return false;
      const numeric = Number(part);
      return Number.isInteger(numeric) && numeric >= 0 && numeric <= 255;
    })
  );
}

function validIPv6(value: string): boolean {
  let address = value;
  if (address.includes(".")) {
    const separator = address.lastIndexOf(":");
    if (separator < 0 || !validIPv4(address.slice(separator + 1))) return false;
    address = `${address.slice(0, separator + 1)}0:0`;
  }
  if (!/^[0-9A-Fa-f:]+$/.test(address) || !address.includes(":")) {
    return false;
  }

  const compressed = address.includes("::");
  if (compressed && address.indexOf("::") !== address.lastIndexOf("::")) {
    return false;
  }
  const [left, right] = compressed ? address.split("::") : [address, ""];
  const parts = [
    ...(left === "" ? [] : left.split(":")),
    ...(right === "" ? [] : right.split(":")),
  ];
  if (parts.some((part) => !/^[0-9A-Fa-f]{1,4}$/.test(part))) return false;
  return compressed ? parts.length < 8 : parts.length === 8;
}

export function authoritativeClientIdentity(value: string | null): string | null {
  if (value === null || value.length < 7 || value.length > 45) return null;
  return validIPv4(value) || validIPv6(value) ? value : null;
}

function base64Key(value: unknown): Uint8Array | null {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9+/]{43}=$/.test(value)
  ) {
    return null;
  }
  try {
    const decoded = Uint8Array.from(atob(value), (character) =>
      character.charCodeAt(0),
    );
    return decoded.byteLength === AUTH_LOGIN_ADMISSION_KEY_BYTES
      ? decoded
      : null;
  } catch {
    return null;
  }
}

async function admissionShardName(
  clientIdentity: string,
  secret: unknown,
): Promise<string | null> {
  const key = base64Key(secret);
  if (!key) return null;
  try {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = await crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      new TextEncoder().encode(`sub2api-auth-login-v1\u0000${clientIdentity}`),
    );
    const shard = [...new Uint8Array(signature)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    return `auth-login-v1:${shard}`;
  } catch {
    return null;
  }
}

function admissionError(
  code: "LOGIN_ADMISSION_UNAVAILABLE" | "LOGIN_ADMISSION_LIMITED",
  status: 429 | 503,
  retryAfter?: number,
): Response {
  const headers = new Headers({ "cache-control": "no-store" });
  if (retryAfter !== undefined) headers.set("retry-after", String(retryAfter));
  return Response.json({ error: { code, message: code } }, { status, headers });
}

async function admitLogin(
  request: Request,
  env: Env,
  timeMs: number,
): Promise<Response | null> {
  const identity = authoritativeClientIdentity(
    request.headers.get("CF-Connecting-IP"),
  );
  const runtime = env as LoginAdmissionRuntimeEnv;
  const shard = identity
    ? await admissionShardName(identity, runtime.SUB2API_CF_LOGIN_ADMISSION_KEY)
    : null;
  if (!shard) return admissionError("LOGIN_ADMISSION_UNAVAILABLE", 503);

  try {
    const result = await env.AUTH_LOGIN_ADMISSION.getByName(shard).admit(timeMs);
    if (result.allowed) return null;
    if (
      !Number.isSafeInteger(result.retry_after_seconds) ||
      result.retry_after_seconds < 1 ||
      result.retry_after_seconds > 60
    ) {
      return admissionError("LOGIN_ADMISSION_UNAVAILABLE", 503);
    }
    return admissionError(
      "LOGIN_ADMISSION_LIMITED",
      429,
      result.retry_after_seconds,
    );
  } catch {
    return admissionError("LOGIN_ADMISSION_UNAVAILABLE", 503);
  }
}

export function parseContainerHosts(raw: string): string[] {
  return raw
    .split(",")
    .map((host) => host.trim().toLowerCase().replace(/\.$/, ""))
    .filter(
      (host, index, hosts) =>
        host.length > 0 &&
        host.length <= 253 &&
        !/[/?#@]/.test(host) &&
        hosts.indexOf(host) === index,
    );
}

export function selectContainerName(
  request: Request,
  environment: string,
  allowTestFixture: string,
): string | null {
  if (environment !== "local" || allowTestFixture !== "true") {
    return "gateway";
  }
  const requested = request.headers.get(FIXTURE_CONTAINER_HEADER);
  if (requested === null) return "gateway";
  return FIXTURE_CONTAINER_NAMES.has(requested) ? requested : null;
}

export function sanitizeIngressRequest(request: Request): Request {
  if (!RESERVED_INGRESS_HEADERS.some((header) => request.headers.has(header))) {
    return request;
  }
  const headers = new Headers(request.headers);
  for (const header of RESERVED_INGRESS_HEADERS) headers.delete(header);
  return new Request(request, { headers });
}

/** Container lifecycle DO; AccountLeaseDO owns business concurrency state. */
export class Sub2APIContainer extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = "5m";
  interceptHttps = true;
  enableInternet = false;

  constructor(ctx: DurableObjectState<{}>, env: Env) {
    super(ctx, env);
    const runtime = env as unknown as ContainerRuntimeEnv;
    const upstreamHosts = parseContainerHosts(
      runtime.SUB2API_CF_UPSTREAM_ALLOWED_HOSTS,
    );
    // The SDK's allowed-host gate runs before every outbound handler. Keeping
    // enableInternet=false means only these explicit hosts can leave the image.
    this.allowedHosts = [INTERNAL_HOST, ...upstreamHosts];
    this.envVars = {
      SUB2API_DEPLOYMENT_MODE: "cloudflare",
      SERVER_HOST: "0.0.0.0",
      SERVER_PORT: "8080",
      SUB2API_CF_CONTROL_PLANE_URL: `http://${INTERNAL_HOST}`,
      SUB2API_CF_UPSTREAM_ALLOWED_HOSTS: upstreamHosts.join(","),
      SUB2API_CF_ALLOW_TEST_FIXTURE: runtime.ALLOW_TEST_FIXTURE,
      SUB2API_CF_LEASE_TTL_SECONDS: runtime.SUB2API_CF_LEASE_TTL_SECONDS,
      // This is a Worker secret binding. It is intentionally absent from
      // wrangler vars and is exposed only to the private Container process.
      SUB2API_CF_JWT_SECRET: runtime.SUB2API_CF_JWT_SECRET,
      // With HTTPS interception the SDK mounts an ephemeral CA at runtime. It
      // is deliberately not copied into the immutable image.
      SSL_CERT_FILE: "/etc/cloudflare/certs/cloudflare-containers-ca.crt",
    };
  }

}

// Register through Container's inherited static setters. Native class-field
// semantics define an own property and bypass those setters, leaving the SDK's
// ContainerProxy registry empty even though interception itself is enabled.
Sub2APIContainer.outboundByHost = {
  [INTERNAL_HOST]: async (
    request: Request,
    env: Env,
    ctx: OutboundHandlerContext,
  ): Promise<Response> => {
    const headers = new Headers(request.headers);
    headers.set("X-Sub2API-Container-Id", ctx.containerId);
    return controlPlane(new Request(request, { headers }), env);
  },
  "mock.upstream": async (request: Request, env: Env): Promise<Response> => {
    const runtime = env as unknown as ContainerRuntimeEnv;
    if (
      runtime.ENVIRONMENT !== "local" ||
      runtime.ALLOW_TEST_FIXTURE !== "true"
    ) {
      return error("NOT_FOUND", 404);
    }
    const url = new URL(request.url);
    if (
      request.method !== "POST" ||
      url.pathname !== "/v1/chat/completions" ||
      request.headers.get("authorization") !==
        "Bearer fixture-upstream-token"
    ) {
      return error("FIXTURE_UPSTREAM_REJECTED", 401);
    }

    const body = await readJson<{
      stream?: unknown;
      x_sub2api_fixture_delay_ms?: unknown;
    }>(request);
    if (!body) return error("FIXTURE_UPSTREAM_INVALID", 400);
    const delay = body.x_sub2api_fixture_delay_ms;
    if (
      delay !== undefined &&
      (!Number.isInteger(delay) ||
        (delay as number) < 0 ||
        (delay as number) > MAX_FIXTURE_DELAY_MS)
    ) {
      return error("FIXTURE_UPSTREAM_INVALID", 400);
    }
    if (typeof delay === "number" && delay > 0) {
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
    const id = "fixture-completion";
    if (body.stream === true) {
      return new Response(
        [
          `data: {"id":"${id}","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"fixture"}}]}`,
          `data: {"id":"${id}","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`,
          "data: [DONE]",
          "",
        ].join("\n\n"),
        {
          headers: {
            "content-type": "text/event-stream",
            "cache-control": "no-cache",
          },
        },
      );
    }
    return Response.json({
      id,
      object: "chat.completion",
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: "fixture" },
          finish_reason: "stop",
        },
      ],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    });
  },
};

// Requests have already passed the SDK allow-host gate. Returning fetch
// preserves request and response streams for authorized real upstreams.
Sub2APIContainer.outbound = (request: Request): Promise<Response> =>
  fetch(request);

const worker = {
  async fetch(request: Request, env: Env): Promise<Response> {
    return routeIngress(request, env);
  },

  async queue(batch: MessageBatch<UsageEnvelope>, env: Env): Promise<void> {
    await consumeUsageBatch(batch, env);
  },

  async scheduled(
    _controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    // The bounded outbox drain never calls the Container and therefore cannot
    // defeat idle scale-to-zero.
    ctx.waitUntil(drainOutbox(env));
  },
};

export async function routeIngress(
  request: Request,
  env: Env,
  forward: ContainerForwarder = (routedRequest, containerName) =>
    getContainer(env.SUB2API_CONTAINER, containerName).fetch(routedRequest),
  clock: () => number = Date.now,
): Promise<Response> {
  if (new URL(request.url).hostname === INTERNAL_HOST) {
    // An external caller must never reach the private control plane by
    // forging the URL/Host. Only Container outbound dispatch invokes it.
    return error("NOT_FOUND", 404);
  }
  const runtime = env as unknown as ContainerRuntimeEnv;
  const containerName = selectContainerName(
    request,
    runtime.ENVIRONMENT,
    runtime.ALLOW_TEST_FIXTURE,
  );
  if (containerName === null) {
    return error("FIXTURE_CONTAINER_INVALID", 400);
  }

  const url = new URL(request.url);
  if (request.method === "POST" && url.pathname === AUTH_LOGIN_PATH) {
    // This preflight intentionally examines only the authoritative edge
    // address header; the login body is still unread at Container handoff.
    const rejection = await admitLogin(request, env, clock());
    if (rejection) return rejection;
  }

  const routedRequest = sanitizeIngressRequest(request);
  return forward(routedRequest, containerName);
}

export default worker;
