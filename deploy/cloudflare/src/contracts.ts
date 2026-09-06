export const BRIDGE_VERSION = "2026-09-06.v1";
export const INTERNAL_HOST = "sub2api.internal";
export const json = (value: unknown, status = 200) => Response.json(value, { status, headers: { "cache-control": "no-store" } });
export const error = (code: string, status = 400) => json({ error: { code, message: code } }, status);
export const now = () => new Date().toISOString();
export const decimal = (value: unknown): string | null => typeof value === "string" && /^[0-9]+$/.test(value) ? value : null;
export async function sha256(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
export async function readJson<T>(request: Request): Promise<T | null> {
  try { return await request.json() as T; } catch { return null; }
}
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const input = value as Record<string, unknown>;
  return `{${Object.keys(input).sort().map((key) => `${JSON.stringify(key)}:${canonical(input[key])}`).join(",")}}`;
}

export type BridgeEnv = Env;
export type LeaseIdentity = { request_id: string; account_id: string; lease_id: string; owner: string; epoch: string };
export type Completion = LeaseIdentity & { event_id: string; api_key_id: string; outcome: "succeeded" | "failed"; usage_state: "confirmed" | "unknown"; input_tokens: string; output_tokens: string; cache_read_tokens: string; model: string; upstream_model: string; upstream_request_id?: string; duration_ms: string };
