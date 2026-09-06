import { describe, expect, it } from "vitest";
import {
  canonical,
  isCanonicalPositiveDecimal,
  isCanonicalUnsignedDecimal,
  readJson,
  sha256,
} from "../src/contracts";

describe("control-plane primitives", () => {
  it("hashes fixture keys without retaining the raw value", async () => {
    expect(await sha256("fixture-test-key")).toBe(
      "40829bc3c826ce7293feb726994f7f21b24d66e85f4f79e3696e994b9047853c",
    );
  });

  it("produces stable canonical payload hashes", async () => {
    expect(canonical({ b: 1, a: ["x"] })).toBe(
      canonical({ a: ["x"], b: 1 }),
    );
    expect(await sha256(canonical({ a: 1 }))).toHaveLength(64);
    expect(() => canonical({ bad: undefined })).toThrow(TypeError);
  });

  it("distinguishes positive IDs from zero-capable counters", () => {
    expect(isCanonicalPositiveDecimal("9007199254740993")).toBe(true);
    expect(isCanonicalPositiveDecimal("0")).toBe(false);
    expect(isCanonicalPositiveDecimal("01")).toBe(false);
    expect(isCanonicalUnsignedDecimal("0")).toBe(true);
    expect(isCanonicalUnsignedDecimal("01")).toBe(false);
  });

  it("rejects an oversized streamed control-plane body", async () => {
    const request = new Request("https://sub2api.internal/test", {
      method: "POST",
      body: JSON.stringify({ value: "x".repeat(128) }),
    });
    expect(await readJson(request, 32)).toBeNull();
  });
});
