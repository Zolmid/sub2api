import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  lookupAdmissionPriceCard,
  pricingDigest,
  PricingUnavailableError,
  type PricingRule,
  validatePricingSnapshot,
} from "../src/pricing";

const testEnv = env as Env;
let sequence = 0;

function rule(versionID: string, pattern: string, kind: "exact" | "family", input = "300"): PricingRule {
  return {
    version_id: versionID, model_pattern: pattern, match_kind: kind,
    input_e8_per_million: input, output_e8_per_million: "1500",
    cache_read_e8_per_million: "30", cache_write_e8_per_million: "375",
    cache_write_5m_e8_per_million: "375", cache_write_1h_e8_per_million: "750",
    image_input_e8_per_million: "0", image_output_e8_per_million: "0",
    priority_input_e8_per_million: "600", priority_output_e8_per_million: "3000",
    priority_cache_read_e8_per_million: "60", priority_cache_write_e8_per_million: "750",
    fast_multiplier_bps: "12500", flex_multiplier_bps: "8000",
    max_reasoning_effort_multiplier_bps: "30000",
  };
}

async function seed(rules: PricingRule[], digest?: string): Promise<{ versionID: string; digest: string }> {
  const versionID = `test-price-${++sequence}`;
  const versionRules = rules.map((item) => ({ ...item, version_id: versionID }));
  const resolvedDigest = digest ?? await pricingDigest(versionID, "99999999", versionRules);
  await testEnv.DB.prepare(
    "INSERT INTO pricing_versions(version_id,digest,max_reservation_e8_usd,created_at) VALUES(?,?,?,?)",
  ).bind(versionID, resolvedDigest, "99999999", new Date().toISOString()).run();
  for (const item of versionRules) {
    await testEnv.DB.prepare(
      `INSERT INTO pricing_rules(version_id,model_pattern,match_kind,
       input_e8_per_million,output_e8_per_million,cache_read_e8_per_million,
       cache_write_e8_per_million,cache_write_5m_e8_per_million,cache_write_1h_e8_per_million,
       image_input_e8_per_million,image_output_e8_per_million,
       priority_input_e8_per_million,priority_output_e8_per_million,
       priority_cache_read_e8_per_million,priority_cache_write_e8_per_million,
       fast_multiplier_bps,flex_multiplier_bps,max_reasoning_effort_multiplier_bps)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).bind(...[
      item.version_id, item.model_pattern, item.match_kind,
      item.input_e8_per_million, item.output_e8_per_million, item.cache_read_e8_per_million,
      item.cache_write_e8_per_million, item.cache_write_5m_e8_per_million, item.cache_write_1h_e8_per_million,
      item.image_input_e8_per_million, item.image_output_e8_per_million,
      item.priority_input_e8_per_million, item.priority_output_e8_per_million,
      item.priority_cache_read_e8_per_million, item.priority_cache_write_e8_per_million,
      item.fast_multiplier_bps, item.flex_multiplier_bps, item.max_reasoning_effort_multiplier_bps,
    ]).run();
  }
  await testEnv.DB.prepare(
    "INSERT INTO pricing_active_version(singleton,version_id,activated_at) VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET version_id=excluded.version_id,activated_at=excluded.activated_at",
  ).bind(versionID, new Date().toISOString()).run();
  return { versionID, digest: resolvedDigest };
}

describe("admission pricing", () => {
  it("uses an exact rule before its trailing wildcard family", async () => {
    await seed([rule("", "gpt-*", "family", "100"), rule("", "gpt-5.6", "exact", "777")]);
    const card = await lookupAdmissionPriceCard(testEnv, "gpt-5.6");
    expect(card.rule.model_pattern).toBe("gpt-5.6");
    expect(card.rule.input_e8_per_million).toBe("777");
  });

  it("fails closed for missing active pricing or a missing model even with stale KV", async () => {
    await testEnv.DB.prepare("DELETE FROM pricing_active_version").run();
    await testEnv.CONFIG_CACHE.put("pricing:missing", JSON.stringify({ version_id: "stale" }));
    await expect(lookupAdmissionPriceCard(testEnv, "missing")).rejects.toBeInstanceOf(PricingUnavailableError);
    await seed([rule("", "gpt-*", "family")]);
    await testEnv.CONFIG_CACHE.put("pricing:not-priced", JSON.stringify({ version_id: "stale" }));
    await expect(lookupAdmissionPriceCard(testEnv, "not-priced")).rejects.toBeInstanceOf(PricingUnavailableError);
  });

  it("rejects digest mismatches and malformed or ambiguous snapshots", async () => {
    const versionID = "invalid-snapshot";
    const valid = rule(versionID, "gpt-*", "family");
    await expect(validatePricingSnapshot(versionID, "100", "0".repeat(64), [valid])).rejects.toThrow("digest mismatch");
    await expect(validatePricingSnapshot(versionID, "100", "0".repeat(64), [{ ...valid, input_e8_per_million: "01" }])).rejects.toThrow("malformed");
    const digest = await pricingDigest(versionID, "100", [valid, rule(versionID, "gpt-5-*", "family")]);
    await expect(validatePricingSnapshot(versionID, "100", digest, [valid, rule(versionID, "gpt-5-*", "family")])).rejects.toThrow("ambiguous");
  });

  it("uses D1 when KV is stale or unavailable", async () => {
    const seeded = await seed([rule("", "gpt-5.6", "exact", "321")]);
    await testEnv.CONFIG_CACHE.put(`pricing:${seeded.versionID}:gpt-5.6`, JSON.stringify({ version_id: "stale", digest: "0".repeat(64) }));
    const stale = await lookupAdmissionPriceCard(testEnv, "gpt-5.6");
    expect(stale.rule.input_e8_per_million).toBe("321");
    const unavailableKV = {
      get: async () => { throw new Error("KV unavailable"); },
      put: async () => { throw new Error("KV unavailable"); },
    } as unknown as KVNamespace;
    const fromD1 = await lookupAdmissionPriceCard({ DB: testEnv.DB, CONFIG_CACHE: unavailableKV }, "gpt-5.6");
    expect(fromD1.rule.input_e8_per_million).toBe("321");
  });

  it("normalizes case, whitespace, and Claude dot aliases before family matching", async () => {
    await seed([rule("", "claude-fable-5-1*", "family", "456")]);
    const card = await lookupAdmissionPriceCard(testEnv, "  Claude-Fable-5.1-20260909  ");
    expect(card.rule.model_pattern).toBe("claude-fable-5-1*");
    expect(card.rule.input_e8_per_million).toBe("456");
  });

  it("hashes the same snapshot independently of D1 row order", async () => {
    const versionID = "deterministic-order";
    const first = rule(versionID, "z-model", "exact");
    const second = rule(versionID, "a-model", "exact");
    expect(await pricingDigest(versionID, "100", [first, second]))
      .toBe(await pricingDigest(versionID, "100", [second, first]));
  });
});
