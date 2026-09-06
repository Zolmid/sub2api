import { describe, expect, it } from "vitest";
import { canonical, sha256 } from "../src/contracts";

describe("control-plane primitives", () => {
  it("hashes fixture keys without retaining the raw value", async () => {
    expect(await sha256("fixture-test-key")).toBe("40829bc3c826ce7293feb726994f7f21b24d66e85f4f79e3696e994b9047853c");
  });
  it("produces stable payload hashes for completion idempotency", async () => {
    expect(canonical({ b: 1, a: ["x"] })).toBe(canonical({ a: ["x"], b: 1 }));
    expect(await sha256(canonical({ a: 1 }))).toHaveLength(64);
  });
});
