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
import { AccountLeaseDO } from "./lease";

export { AccountLeaseDO, ContainerProxy };

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

const FIXTURE_CONTAINER_HEADER = "X-Sub2API-Fixture-Container";
const FIXTURE_CONTAINER_NAMES = new Set(["gateway-a", "gateway-b"]);
const MAX_FIXTURE_DELAY_MS = 60_000;
const RESERVED_INGRESS_HEADERS = [
  FIXTURE_CONTAINER_HEADER,
  "X-Sub2API-Bridge-Version",
  "X-Sub2API-Container-Id",
];

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

    const routedRequest = sanitizeIngressRequest(request);
    return getContainer(env.SUB2API_CONTAINER, containerName).fetch(
      routedRequest,
    );
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

export default worker;
