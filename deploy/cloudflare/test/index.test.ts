import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { INTERNAL_HOST } from "../src/contracts";
import {
  Sub2APIContainer,
  parseContainerHosts,
  sanitizeIngressRequest,
  selectContainerName,
  routeIngress,
} from "../src/index";
import { JOB_EXECUTION_PRIVATE_PATH } from "../src/job-executors";

describe("container egress registration", () => {
  it("registers handlers through the Containers SDK static setters", () => {
    // A native static class field would become an own property, bypass the
    // SDK setter, and leave ContainerProxy without a registered handler.
    expect(
      Object.prototype.hasOwnProperty.call(
        Sub2APIContainer,
        "outboundByHost",
      ),
    ).toBe(false);
    expect(
      Object.prototype.hasOwnProperty.call(Sub2APIContainer, "outbound"),
    ).toBe(false);
    expect(Sub2APIContainer.outboundByHost?.[INTERNAL_HOST]).toBeTypeOf(
      "function",
    );
    expect(Sub2APIContainer.outboundByHost?.["mock.upstream"]).toBeTypeOf(
      "function",
    );
    expect(Sub2APIContainer.outbound).toBeTypeOf("function");
  });

  it("normalizes and deduplicates configured upstream hosts", () => {
    expect(
      parseContainerHosts(
        "API.Example.com., api.example.com, mock.upstream, bad/path, ",
      ),
    ).toEqual(["api.example.com", "mock.upstream"]);
  });

  it("permits only fixed two-instance routing in local fixture mode", () => {
    const request = (value?: string) =>
      new Request("https://example.test/v1/chat/completions", {
        headers: value
          ? { "X-Sub2API-Fixture-Container": value }
          : undefined,
      });

    expect(selectContainerName(request(), "local", "true")).toBe("gateway");
    expect(selectContainerName(request("gateway-a"), "local", "true")).toBe(
      "gateway-a",
    );
    expect(selectContainerName(request("gateway-b"), "local", "true")).toBe(
      "gateway-b",
    );
    expect(selectContainerName(request("other"), "local", "true")).toBeNull();
    expect(
      selectContainerName(request("gateway-a"), "production", "false"),
    ).toBe("gateway");
  });

  it("removes every internal or fixture routing header at public ingress", () => {
    const original = new Request("https://example.test/v1/chat/completions", {
      headers: {
        Authorization: "Bearer public-client-key",
        "X-Sub2API-Fixture-Container": "gateway-a",
        "X-Sub2API-Bridge-Version": "forged",
        "X-Sub2API-Container-Id": "forged",
      },
    });
    const sanitized = sanitizeIngressRequest(original);
    expect(sanitized.headers.get("authorization")).toBe(
      "Bearer public-client-key",
    );
    expect(sanitized.headers.has("X-Sub2API-Fixture-Container")).toBe(false);
    expect(sanitized.headers.has("X-Sub2API-Bridge-Version")).toBe(false);
    expect(sanitized.headers.has("X-Sub2API-Container-Id")).toBe(false);
  });
});

describe("edge readiness", () => {
  it("checks the authoritative pricing snapshot without waking a Container", async () => {
    let forwarded = 0;
    const forward = async () => {
      forwarded += 1;
      return new Response("unexpected");
    };
    const ready = await routeIngress(new Request("https://example.test/ready"), env, forward);
    expect(ready.status).toBe(200);
    expect(ready.headers.get("cache-control")).toBe("no-store");
    expect(forwarded).toBe(0);

    await env.DB.prepare("DELETE FROM pricing_active_version").run();
    const unavailable = await routeIngress(new Request("https://example.test/ready"), env, forward);
    expect(unavailable.status).toBe(503);
    expect(forwarded).toBe(0);
  });

  it("fails closed for normalized forms of every private RPC namespace", async () => {
    let forwarded = 0;
    const forward = async () => {
      forwarded += 1;
      return new Response("unexpected");
    };

    const hostilePaths = [
      JOB_EXECUTION_PRIVATE_PATH,
      `${JOB_EXECUTION_PRIVATE_PATH}/extra`,
      "/internal/cloudflare/",
      "/internal%2fcloudflare/jobs/execute",
      "/internal%252Fcloudflare%252Fjobs%252Fexecute",
      "/internal%5ccloudflare%5cjobs%5cexecute",
      "//internal///cloudflare//jobs/execute",
      "/INTERNAL/CLOUDFLARE/jobs/execute",
      "/internal/%2e/cloudflare/jobs/execute",
      "/internal/cloudflare/%2e%2e/cloudflare/jobs/execute",
      "/v1/private/settings/get",
      "/v1/private/payments/create",
      "/v1%2fprivate%2fsubscriptions/get",
      "/v1%252Fprivate%252Fauth-sessions%252Fget",
      "/V1/PRIVATE/settings/get",
      "/v1/private/../private/payments/create",
    ];

    for (const path of hostilePaths) {
      const response = await routeIngress(
        new Request(`https://example.test${path}`, {
          method: "POST",
          headers: {
            "X-Sub2API-Fixture-Container": "gateway-a",
            "X-Sub2API-Container-Id": "forged",
            "X-Sub2API-Bridge-Version": "forged",
          },
        }),
        env,
        forward,
      );
      expect(response.status, path).toBe(404);
    }
    expect(forwarded).toBe(0);
  });

  it("keeps unrelated internal-looking and public API paths routable", async () => {
    const forwardedPaths: string[] = [];
    const forward = async (request: Request) => {
      forwardedPaths.push(new URL(request.url).pathname);
      return new Response(null, { status: 204 });
    };

    for (const path of [
      "/internality/cloudflare",
      "/internal/cloudflared/jobs/execute",
      "/v1/privately/settings/get",
      "/api/v1/models",
      "/v1/chat/completions",
    ]) {
      const response = await routeIngress(
        new Request(`https://example.test${path}`),
        env,
        forward,
      );
      expect(response.status, path).toBe(204);
    }
    expect(forwardedPaths).toEqual([
      "/internality/cloudflare",
      "/internal/cloudflared/jobs/execute",
      "/v1/privately/settings/get",
      "/api/v1/models",
      "/v1/chat/completions",
    ]);
  });
});
