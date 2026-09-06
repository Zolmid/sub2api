import { Container, ContainerProxy, getContainer } from "@cloudflare/containers";
import { AccountLeaseDO } from "./lease";
import { controlPlane, publish } from "./control-plane";
import { INTERNAL_HOST, error, now, sha256 } from "./contracts";

export { AccountLeaseDO, ContainerProxy };

/** Container lifecycle DO. AccountLeaseDO is the separate business-concurrency object. */
export class Sub2APIContainer extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = "5m";
  interceptHttps = true;
  envVars = {
    SUB2API_DEPLOYMENT_MODE: "cloudflare", SERVER_HOST: "0.0.0.0", SERVER_PORT: "8080",
    SUB2API_CF_CONTROL_PLANE_URL: "http://sub2api.internal",
    SUB2API_CF_UPSTREAM_ALLOWED_HOSTS: String((this.env as Env & { SUB2API_CF_UPSTREAM_ALLOWED_HOSTS: string }).SUB2API_CF_UPSTREAM_ALLOWED_HOSTS),
    SUB2API_CF_ALLOW_TEST_FIXTURE: String((this.env as Env & { ALLOW_TEST_FIXTURE: string }).ALLOW_TEST_FIXTURE),
    SUB2API_CF_LEASE_TTL_SECONDS: String((this.env as Env & { SUB2API_CF_LEASE_TTL_SECONDS: string }).SUB2API_CF_LEASE_TTL_SECONDS),
    SSL_CERT_FILE: "/etc/cloudflare/certs/cloudflare-containers-ca.crt",
  };
  static outboundByHost = {
    [INTERNAL_HOST]: async (request: Request, env: Env, ctx: { containerId: string }) => {
      const headers = new Headers(request.headers); headers.set("X-Sub2API-Container-Id", ctx.containerId);
      return controlPlane(new Request(request, { headers }), env);
    },
    "mock.upstream": async (request: Request, env: Env) => {
      if (String((env as Env & { ALLOW_TEST_FIXTURE: string }).ALLOW_TEST_FIXTURE) !== "true") return error("NOT_FOUND", 404);
      const streaming = (await request.clone().json().catch(() => ({})) as { stream?: boolean }).stream === true;
      const id = "fixture-completion";
      if (streaming) return new Response(`data: {"id":"${id}","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"fixture"}}]}\n\ndata: {"id":"${id}","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}\n\ndata: [DONE]\n\n`, { headers: { "content-type": "text/event-stream", "cache-control": "no-cache" } });
      return Response.json({ id, object: "chat.completion", choices: [{ index: 0, message: { role: "assistant", content: "fixture" }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } });
    },
  };
  static outbound = (request: Request) => fetch(request); // Stream-preserving: no clone/text/json of external traffic.
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.hostname === INTERNAL_HOST) return error("NOT_FOUND", 404); // Worker public ingress never exposes control plane.
    const container = getContainer(env.SUB2API_CONTAINER, "gateway");
    return container.fetch(request);
  },
  async queue(batch: MessageBatch<{ event_id: string; payload: string; payload_hash: string }>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      try {
        const actual = await sha256(message.body.payload); const payload = JSON.parse(message.body.payload) as Record<string, unknown>;
        if (actual !== message.body.payload_hash || payload.event_id !== message.body.event_id || typeof payload.event_id !== "string" || typeof payload.request_id !== "string" || payload.schema_version !== "2026-09-06.v1" || payload.event_type !== "gateway.usage.v1" || !["api_key_id","account_id","lease_epoch","input_tokens","output_tokens","cache_read_tokens","duration_ms"].every((key) => typeof payload[key] === "string" && /^[1-9][0-9]*$/.test(String(payload[key]))) || !["lease_id","model","upstream_model","outcome","usage_state"].every((key) => typeof payload[key] === "string" && String(payload[key]).length > 0)) { message.retry(); continue; }
        const known = await env.DB.prepare("SELECT payload_hash FROM usage_events WHERE event_id=?").bind(payload.event_id).first<{ payload_hash: string }>();
        if (known && known.payload_hash !== actual) { await env.DB.prepare("INSERT INTO outbox_conflicts(event_id,existing_hash,incoming_hash,observed_at) VALUES(?,?,?,?)").bind(String(payload.event_id), known.payload_hash, actual, now()).run(); message.ack(); continue; }
        if (!known) await env.DB.batch([
          env.DB.prepare("INSERT INTO usage_events(event_id,request_id,payload_hash,api_key_id,account_id,lease_id,lease_epoch,model,upstream_model,outcome,usage_state,input_tokens,output_tokens,cache_read_tokens,duration_ms,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(payload.event_id, payload.request_id, actual, payload.api_key_id, payload.account_id, payload.lease_id, payload.lease_epoch, payload.model, payload.upstream_model, payload.outcome, payload.usage_state, payload.input_tokens, payload.output_tokens, payload.cache_read_tokens, payload.duration_ms, now()),
          // A late/out-of-order queue message cannot move an already terminal request backwards.
          env.DB.prepare("UPDATE gateway_requests SET state=state WHERE request_id=? AND state IN ('succeeded','failed')").bind(payload.request_id),
        ]);
        message.ack();
      } catch { message.retry(); }
    }
  },
  async scheduled(_: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    // Bounded drain intentionally has no Container call.
    const events = await env.DB.prepare("SELECT event_id,payload_json,payload_hash FROM outbox_events WHERE state='pending' ORDER BY created_at LIMIT 50").all<{ event_id: string; payload_json: string; payload_hash: string }>();
    for (const event of events.results) ctx.waitUntil(publish(env, event.event_id, event.payload_json, event.payload_hash).catch(() => undefined));
  },
};
