import { canonical, isBoundedString, isCanonicalUnsignedDecimal, sha256 } from "./contracts";

const PRICE_FIELDS = ["input_e8_per_million", "output_e8_per_million", "cache_read_e8_per_million", "cache_write_e8_per_million", "cache_write_5m_e8_per_million", "cache_write_1h_e8_per_million", "image_input_e8_per_million", "image_output_e8_per_million", "priority_input_e8_per_million", "priority_output_e8_per_million", "priority_cache_read_e8_per_million", "priority_cache_write_e8_per_million"] as const;
const BPS_FIELDS = ["fast_multiplier_bps", "flex_multiplier_bps", "max_reasoning_effort_multiplier_bps"] as const;

export type PricingRule = Record<(typeof PRICE_FIELDS)[number] | (typeof BPS_FIELDS)[number], string> & { version_id: string; model_pattern: string; match_kind: "exact" | "family" };
export type AdmittedPriceCard = { version_id: string; digest: string; max_reservation_e8_usd: string; rule: PricingRule };
export type PricingSnapshot = { version_id: string; digest: string; max_reservation_e8_usd: string; rules: PricingRule[] };
type VersionRow = Omit<PricingSnapshot, "rules">;

export class PricingUnavailableError extends Error { constructor(message: string) { super(message); this.name = "PricingUnavailableError"; } }

export function normalizePricingModel(value: unknown): string | null {
  if (!isBoundedString(value, 256)) return null;
  let normalized = value.trim().toLowerCase();
  if (!/^[a-z0-9._:/-]+$/.test(normalized)) return null;
  if (normalized.startsWith("claude-")) normalized = normalized.replaceAll(".", "-");
  return normalized;
}

export function normalizePricingPattern(value: unknown, kind: unknown): string | null {
  if ((kind !== "exact" && kind !== "family") || typeof value !== "string") return null;
  if (kind === "family" && (!value.endsWith("*") || value.slice(0, -1).includes("*"))) return null;
  const model = normalizePricingModel(kind === "family" ? value.slice(0, -1) : value);
  return model === null ? null : model + (kind === "family" ? "*" : "");
}

function unsigned(value: unknown, maxLength = 40): value is string { return isCanonicalUnsignedDecimal(value) && value.length <= maxLength; }
function positive(value: unknown, maxLength = 40): value is string { return unsigned(value, maxLength) && value !== "0"; }
function digest(value: unknown): value is string { return typeof value === "string" && /^[0-9a-f]{64}$/.test(value); }
function versionID(value: unknown): value is string { return typeof value === "string" && /^[a-z0-9._:-]{1,128}$/.test(value); }
function byteCompare(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }

function validRule(value: unknown): value is PricingRule {
  if (!value || typeof value !== "object") return false;
  const rule = value as Partial<PricingRule>;
  return versionID(rule.version_id) && (rule.match_kind === "exact" || rule.match_kind === "family") && normalizePricingPattern(rule.model_pattern, rule.match_kind) === rule.model_pattern && PRICE_FIELDS.every((field) => unsigned(rule[field])) && unsigned(rule.fast_multiplier_bps, 8) && unsigned(rule.flex_multiplier_bps, 8) && positive(rule.max_reasoning_effort_multiplier_bps, 8);
}

function familiesOverlap(left: PricingRule, right: PricingRule): boolean {
  if (left.match_kind !== "family" || right.match_kind !== "family") return false;
  const a = left.model_pattern.slice(0, -1); const b = right.model_pattern.slice(0, -1);
  return a.startsWith(b) || b.startsWith(a);
}

export async function pricingDigest(version: string, cap: string, rules: PricingRule[]): Promise<string> {
  const ordered = [...rules].sort((left, right) => byteCompare(left.model_pattern, right.model_pattern) || byteCompare(left.match_kind, right.match_kind));
  return sha256(canonical({ version_id: version, max_reservation_e8_usd: cap, rules: ordered }));
}

export async function validatePricingSnapshot(version: unknown, cap: unknown, expectedDigest: unknown, rules: unknown): Promise<PricingSnapshot> {
  if (!versionID(version) || !positive(cap) || !digest(expectedDigest) || !Array.isArray(rules) || rules.length === 0 || !rules.every(validRule) || !rules.every((rule) => rule.version_id === version)) throw new PricingUnavailableError("malformed pricing snapshot");
  const exact = new Set<string>();
  for (const rule of rules) if (rule.match_kind === "exact") { if (exact.has(rule.model_pattern)) throw new PricingUnavailableError("ambiguous exact pricing rule"); exact.add(rule.model_pattern); }
  for (let index = 0; index < rules.length; index += 1) if (rules.slice(index + 1).some((other) => familiesOverlap(rules[index], other))) throw new PricingUnavailableError("ambiguous pricing wildcard rule");
  if (await pricingDigest(version, cap, rules) !== expectedDigest) throw new PricingUnavailableError("pricing digest mismatch");
  return { version_id: version, digest: expectedDigest, max_reservation_e8_usd: cap, rules };
}

function selectRule(model: string, rules: PricingRule[]): PricingRule {
  const exact = rules.filter((rule) => rule.match_kind === "exact" && rule.model_pattern === model);
  if (exact.length > 1) throw new PricingUnavailableError("ambiguous exact pricing rule");
  if (exact.length === 1) return exact[0];
  const family = rules.filter((rule) => rule.match_kind === "family" && model.startsWith(rule.model_pattern.slice(0, -1)));
  if (family.length !== 1) throw new PricingUnavailableError(family.length === 0 ? "missing model price" : "ambiguous pricing wildcard rule");
  return family[0];
}

async function activeSnapshot(env: Pick<Env, "DB">): Promise<PricingSnapshot> {
  const active = await env.DB.prepare(`SELECT v.version_id,v.digest,v.max_reservation_e8_usd FROM pricing_active_version AS a JOIN pricing_versions AS v ON v.version_id=a.version_id`).all<VersionRow>();
  if (active.results.length !== 1) throw new PricingUnavailableError("missing or ambiguous active pricing version");
  const version = active.results[0];
  const rules = await env.DB.prepare(`SELECT version_id,model_pattern,match_kind,input_e8_per_million,output_e8_per_million,cache_read_e8_per_million,cache_write_e8_per_million,cache_write_5m_e8_per_million,cache_write_1h_e8_per_million,image_input_e8_per_million,image_output_e8_per_million,priority_input_e8_per_million,priority_output_e8_per_million,priority_cache_read_e8_per_million,priority_cache_write_e8_per_million,fast_multiplier_bps,flex_multiplier_bps,max_reasoning_effort_multiplier_bps FROM pricing_rules WHERE version_id=?`).bind(version.version_id).all<PricingRule>();
  return validatePricingSnapshot(version.version_id, version.max_reservation_e8_usd, version.digest, rules.results);
}

export async function validateActivePricing(env: Pick<Env, "DB">): Promise<PricingSnapshot> { return activeSnapshot(env); }

export async function lookupAdmissionPriceCard(env: Pick<Env, "DB" | "CONFIG_CACHE">, model: string): Promise<AdmittedPriceCard> {
  const normalized = normalizePricingModel(model); if (normalized === null) throw new PricingUnavailableError("invalid model");
  const snapshot = await activeSnapshot(env); const card: AdmittedPriceCard = { version_id: snapshot.version_id, digest: snapshot.digest, max_reservation_e8_usd: snapshot.max_reservation_e8_usd, rule: selectRule(normalized, snapshot.rules) };
  try { await env.CONFIG_CACHE.put(`pricing:${card.version_id}:${normalized}`, JSON.stringify(card), { expirationTtl: 300 }); } catch { /* D1 already authorized this result. */ }
  return card;
}
