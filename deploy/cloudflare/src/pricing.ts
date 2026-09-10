import { canonical, isBoundedString, isCanonicalUnsignedDecimal, sha256 } from "./contracts";

const PRICE_FIELDS = ["input_e8_per_million", "output_e8_per_million", "cache_read_e8_per_million", "cache_write_e8_per_million", "cache_write_5m_e8_per_million", "cache_write_1h_e8_per_million", "image_input_e8_per_million", "image_output_e8_per_million", "priority_input_e8_per_million", "priority_output_e8_per_million", "priority_cache_read_e8_per_million", "priority_cache_write_e8_per_million"] as const;
const BPS_FIELDS = ["fast_multiplier_bps", "flex_multiplier_bps", "max_reasoning_effort_multiplier_bps"] as const;
const MAX_USAGE_DIGITS = 20;
export type PricingRule = Record<(typeof PRICE_FIELDS)[number] | (typeof BPS_FIELDS)[number], string> & { version_id: string; model_pattern: string; match_kind: "exact" | "family" };
export type AdmittedPriceCard = { version_id: string; digest: string; max_reservation_e8_usd: string; rule: PricingRule };
export type PricingSnapshot = { version_id: string; digest: string; max_reservation_e8_usd: string; rules: PricingRule[] };
export type UsageForPricing = { input_tokens: string; image_input_tokens: string; output_tokens: string; image_output_tokens: string; cache_creation_tokens: string; cache_creation_5m_tokens: string; cache_creation_1h_tokens: string; cache_read_tokens: string; service_tier: string; reasoning_effort: string; rate_multiplier_bps: string };
export type E8ChargeBreakdown = { input_e8_usd: string; image_input_e8_usd: string; output_e8_usd: string; image_output_e8_usd: string; cache_write_e8_usd: string; cache_read_e8_usd: string; total_e8_usd: string; exceeds_reservation_cap: boolean };
type VersionRow = Omit<PricingSnapshot, "rules">;
type Part = { numerator: bigint; denominator: bigint; index: number };
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
  const normalized = normalizePricingModel(kind === "family" ? value.slice(0, -1) : value);
  return normalized === null ? null : normalized + (kind === "family" ? "*" : "");
}
function unsigned(value: unknown, max = 40): value is string { return isCanonicalUnsignedDecimal(value) && value.length <= max; }
function positive(value: unknown, max = 40): value is string { return unsigned(value, max) && value !== "0"; }
function digest(value: unknown): value is string { return typeof value === "string" && /^[0-9a-f]{64}$/.test(value); }
function versionID(value: unknown): value is string { return typeof value === "string" && /^[a-z0-9._:-]{1,128}$/.test(value); }
function validRule(value: unknown): value is PricingRule {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const rule = value as Partial<PricingRule>;
  return versionID(rule.version_id) && (rule.match_kind === "exact" || rule.match_kind === "family") &&
    normalizePricingPattern(rule.model_pattern, rule.match_kind) === rule.model_pattern &&
    PRICE_FIELDS.every((key) => unsigned(rule[key])) && BPS_FIELDS.every((key) => unsigned(rule[key], 8)) &&
    positive(rule.max_reasoning_effort_multiplier_bps, 8);
}
function overlap(a: PricingRule, b: PricingRule): boolean {
  if (a.match_kind !== "family" || b.match_kind !== "family") return false;
  const left = a.model_pattern.slice(0, -1), right = b.model_pattern.slice(0, -1);
  return left.startsWith(right) || right.startsWith(left);
}
function order(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }
export async function pricingDigest(version: string, cap: string, rules: PricingRule[]): Promise<string> {
  return sha256(canonical({ version_id: version, max_reservation_e8_usd: cap, rules: [...rules].sort((a,b) => order(a.model_pattern,b.model_pattern) || order(a.match_kind,b.match_kind)) }));
}
export async function validatePricingSnapshot(version: unknown, cap: unknown, expectedDigest: unknown, rules: unknown[]): Promise<PricingSnapshot> {
  if (!versionID(version) || !positive(cap, 18) || !digest(expectedDigest) || !Array.isArray(rules) || rules.length === 0 || !rules.every(validRule) || !rules.every((rule) => rule.version_id === version)) throw new PricingUnavailableError("malformed pricing snapshot");
  const exact = new Set<string>();
  for (const rule of rules) { if (rule.match_kind === "exact") { if (exact.has(rule.model_pattern)) throw new PricingUnavailableError("ambiguous exact pricing rule"); exact.add(rule.model_pattern); } }
  for (let i=0;i<rules.length;i+=1) if (rules.slice(i+1).some((other) => overlap(rules[i],other))) throw new PricingUnavailableError("ambiguous pricing wildcard rule");
  if (await pricingDigest(version,cap,rules) !== expectedDigest) throw new PricingUnavailableError("pricing digest mismatch");
  return { version_id: version, digest: expectedDigest, max_reservation_e8_usd: cap, rules };
}
function selectRule(model: string, rules: PricingRule[]): PricingRule {
  const exact = rules.filter((rule) => rule.match_kind === "exact" && rule.model_pattern === model);
  if (exact.length === 1) return exact[0]; if (exact.length > 1) throw new PricingUnavailableError("ambiguous exact pricing rule");
  const family = rules.filter((rule) => rule.match_kind === "family" && model.startsWith(rule.model_pattern.slice(0,-1)));
  if (family.length !== 1) throw new PricingUnavailableError(family.length ? "ambiguous pricing wildcard rule" : "missing model price");
  return family[0];
}
const ruleColumns = "version_id,model_pattern,match_kind,input_e8_per_million,output_e8_per_million,cache_read_e8_per_million,cache_write_e8_per_million,cache_write_5m_e8_per_million,cache_write_1h_e8_per_million,image_input_e8_per_million,image_output_e8_per_million,priority_input_e8_per_million,priority_output_e8_per_million,priority_cache_read_e8_per_million,priority_cache_write_e8_per_million,fast_multiplier_bps,flex_multiplier_bps,max_reasoning_effort_multiplier_bps";
async function activeSnapshot(env: Pick<Env,"DB">): Promise<PricingSnapshot> {
  const rows = await env.DB.prepare("SELECT v.version_id,v.digest,v.max_reservation_e8_usd FROM pricing_active_version a JOIN pricing_versions v ON v.version_id=a.version_id").all<VersionRow>();
  if (rows.results.length !== 1) throw new PricingUnavailableError("missing or ambiguous active pricing version");
  const version = rows.results[0]; const rules = await env.DB.prepare(`SELECT ${ruleColumns} FROM pricing_rules WHERE version_id=?`).bind(version.version_id).all<PricingRule>();
  return validatePricingSnapshot(version.version_id,version.max_reservation_e8_usd,version.digest,rules.results);
}
export async function validateActivePricing(env: Pick<Env,"DB">): Promise<PricingSnapshot> { return activeSnapshot(env); }
export async function lookupAdmissionPriceCard(env: Pick<Env,"DB"|"CONFIG_CACHE">, model: string): Promise<AdmittedPriceCard> {
  const normalized = normalizePricingModel(model); if (!normalized) throw new PricingUnavailableError("invalid model");
  const snapshot = await activeSnapshot(env); const card = { version_id:snapshot.version_id,digest:snapshot.digest,max_reservation_e8_usd:snapshot.max_reservation_e8_usd,rule:selectRule(normalized,snapshot.rules) };
  try { await env.CONFIG_CACHE.put(`pricing:${card.version_id}:${normalized}`,JSON.stringify(card),{expirationTtl:300}); } catch { /* D1 authorized admission. */ }
  return card;
}
export async function loadAdmittedPriceCard(env: Pick<Env,"DB">, versionIDValue: string, versionDigest: string, pricingModel: string, modelPattern?: string, matchKind?: "exact" | "family"): Promise<AdmittedPriceCard> {
  const version = await env.DB.prepare("SELECT version_id,digest,max_reservation_e8_usd FROM pricing_versions WHERE version_id=? AND digest=?").bind(versionIDValue,versionDigest).first<VersionRow>();
  if (!version) throw new PricingUnavailableError("admitted price card missing");
  const rules = await env.DB.prepare(`SELECT ${ruleColumns} FROM pricing_rules WHERE version_id=?`).bind(versionIDValue).all<PricingRule>();
  const snapshot = await validatePricingSnapshot(version.version_id,version.max_reservation_e8_usd,version.digest,rules.results);
  const pattern = modelPattern ?? pricingModel;
  const normalized = normalizePricingModel(pricingModel); if (!normalized) throw new PricingUnavailableError("invalid admitted pricing model");
  const selected = selectRule(normalized,snapshot.rules);
  if (selected.model_pattern !== pattern || (matchKind !== undefined && selected.match_kind !== matchKind)) throw new PricingUnavailableError("admitted pricing rule mismatch");
  return {version_id:snapshot.version_id,digest:snapshot.digest,max_reservation_e8_usd:snapshot.max_reservation_e8_usd,rule:selected};
}
function price(value: string): bigint { return BigInt(value); }
function usage(value: unknown): bigint {
  if (!unsigned(value,MAX_USAGE_DIGITS)) throw new PricingUnavailableError("invalid usage"); return BigInt(value);
}
function halfUp(n: bigint, d: bigint): bigint { return n / d + ((n % d) * 2n >= d ? 1n : 0n); }
function nonzero(current: bigint, fallback: bigint): bigint { return current > 0n ? current : fallback; }
function tokenPart(tokens: bigint, unit: bigint, index: number, multiplier: bigint): Part { return { numerator: tokens * unit * multiplier, denominator: 1_000_000n * 10_000n * 10_000n * 10_000n, index }; }
function allocate(parts: Part[]): [bigint[],bigint] {
  const denominator = parts[0]?.denominator; if (!denominator || parts.some((part) => part.denominator !== denominator || part.numerator < 0n)) throw new PricingUnavailableError("invalid charge parts");
  const total = halfUp(parts.reduce((sum,part) => sum + part.numerator,0n),denominator); const values=parts.map((part) => part.numerator/denominator); const remainders=parts.map((part) => part.numerator%denominator);
  let delta=total-values.reduce((sum,value)=>sum+value,0n); if(delta<0n||delta>BigInt(parts.length))throw new PricingUnavailableError("invalid component allocation");
  const indices=parts.map((_,index)=>index).sort((a,b)=>remainders[a]===remainders[b]?parts[a].index-parts[b].index:remainders[a]>remainders[b]?-1:1);
  for(let i=0n;i<delta;i+=1n) values[indices[Number(i)]] += 1n; return [values,total];
}
function cacheCreation(total: bigint, five: bigint, hour: bigint): [bigint,bigint] {
  if (total === 0n) { if (five !== 0n || hour !== 0n) throw new PricingUnavailableError("cache detail without total"); return [0n,0n]; }
  if (five + hour <= total) return [five,hour];
  const detail=five+hour; if(detail===0n) throw new PricingUnavailableError("invalid cache detail"); const allocated=halfUp(total*five,detail); return allocated >= total ? [total,0n] : [allocated,total-allocated];
}
export function calculateAdmittedE8Charge(card: AdmittedPriceCard, value: UsageForPricing): E8ChargeBreakdown {
  if (!validRule(card.rule) || !positive(card.max_reservation_e8_usd,18) || !digest(card.digest) || !versionID(card.version_id) || card.rule.version_id !== card.version_id) throw new PricingUnavailableError("invalid admitted price card");
  const input=usage(value.input_tokens), imageInput=usage(value.image_input_tokens), output=usage(value.output_tokens), imageOutput=usage(value.image_output_tokens), creation=usage(value.cache_creation_tokens), creation5=usage(value.cache_creation_5m_tokens), creation1=usage(value.cache_creation_1h_tokens), read=usage(value.cache_read_tokens);
  if(imageInput>input||imageOutput>output) throw new PricingUnavailableError("impossible image usage subset");
  const rate=usage(value.rate_multiplier_bps); if(rate===0n || rate>99_999_999n) throw new PricingUnavailableError("invalid rate multiplier");
  let inputPrice=price(card.rule.input_e8_per_million),outputPrice=price(card.rule.output_e8_per_million),readPrice=price(card.rule.cache_read_e8_per_million),writePrice=price(card.rule.cache_write_e8_per_million),tierMultiplier=10_000n;
  const tier=value.service_tier.trim().toLowerCase();
  if(tier==="priority"||tier==="fast") { const fast=price(card.rule.fast_multiplier_bps); if(fast>0n)tierMultiplier=fast; else if(price(card.rule.priority_input_e8_per_million)>0n||price(card.rule.priority_output_e8_per_million)>0n||price(card.rule.priority_cache_read_e8_per_million)>0n||price(card.rule.priority_cache_write_e8_per_million)>0n){ inputPrice=nonzero(price(card.rule.priority_input_e8_per_million),inputPrice);outputPrice=nonzero(price(card.rule.priority_output_e8_per_million),outputPrice);readPrice=nonzero(price(card.rule.priority_cache_read_e8_per_million),readPrice);writePrice=nonzero(price(card.rule.priority_cache_write_e8_per_million),writePrice); }else tierMultiplier=20_000n; }
  if(tier==="flex") tierMultiplier=price(card.rule.flex_multiplier_bps)>0n?price(card.rule.flex_multiplier_bps):5_000n;
  const multiplier=tierMultiplier*rate*(value.reasoning_effort.trim().toLowerCase()==="max"?price(card.rule.max_reasoning_effort_multiplier_bps):10_000n);
  const [five,hour]=cacheCreation(creation,creation5,creation1); const write5=price(card.rule.cache_write_5m_e8_per_million),write1=price(card.rule.cache_write_1h_e8_per_million);
  const parts: Part[]=[]; const add=(tokens:bigint,unit:bigint) => parts.push(tokenPart(tokens,unit,parts.length,multiplier));
  add(input-imageInput,inputPrice); add(imageInput,nonzero(price(card.rule.image_input_e8_per_million),inputPrice)); add(output-imageOutput,outputPrice); add(imageOutput,nonzero(price(card.rule.image_output_e8_per_million),outputPrice));
  if(write5>0n||write1>0n) { add(five===0n&&hour===0n&&creation>0n?creation:five,write5); add(five===0n&&hour===0n&&creation>0n?0n:hour,write1); } else { add(creation,writePrice); add(0n,writePrice); }
  add(read,readPrice); const [values,total]=allocate(parts);
  return {input_e8_usd:values[0].toString(),image_input_e8_usd:values[1].toString(),output_e8_usd:values[2].toString(),image_output_e8_usd:values[3].toString(),cache_write_e8_usd:(values[4]+values[5]).toString(),cache_read_e8_usd:values[6].toString(),total_e8_usd:total.toString(),exceeds_reservation_cap:total>BigInt(card.max_reservation_e8_usd)};
}
// Backward-compatible narrow helper retained for callers that only have the
// legacy three counters. New settlement uses calculateAdmittedE8Charge.
export function calculateUsageChargeE8USD(card: AdmittedPriceCard,input:string,output:string,cacheRead:string): string {
  for (const value of [input,output,cacheRead]) if (!unsigned(value,MAX_USAGE_DIGITS)) throw new PricingUnavailableError("invalid usage");
  const numerator=BigInt(input)*price(card.rule.input_e8_per_million)+BigInt(output)*price(card.rule.output_e8_per_million)+BigInt(cacheRead)*price(card.rule.cache_read_e8_per_million);
  return halfUp(numerator,1_000_000n).toString();
}
