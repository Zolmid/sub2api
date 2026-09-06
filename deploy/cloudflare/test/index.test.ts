import { describe, expect, it } from "vitest";
import { INTERNAL_HOST } from "../src/contracts";
import {
  Sub2APIContainer,
  parseContainerHosts,
  sanitizeIngressRequest,
  selectContainerName,
} from "../src/index";

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
