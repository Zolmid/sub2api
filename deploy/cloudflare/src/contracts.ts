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
export async function readJson<T>(request: Request, limit = 64 * 1024): Promise<T | null> {
  if (!request.body) return null;
  const reader = request.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > limit) { await reader.cancel(); return null; } chunks.push(part.value); }
    const output = new Uint8Array(size); let at = 0; for (const chunk of chunks) { output.set(chunk, at); at += chunk.length; }
    return JSON.parse(new TextDecoder().decode(output)) as T;
  } catch { return null; } finally { reader.releaseLock(); }
}
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const input = value as Record<string, unknown>;
  return `{${Object.keys(input).sort().map((key) => `${JSON.stringify(key)}:${canonical(input[key])}`).join(",")}}`;
}

export type BridgeEnv = Env;
export type LeaseIdentity = { request_id: string; account_id: string; lease_id: string; owner: string; epoch: string };
export type Completion = Omit<LeaseIdentity, "epoch"> & { lease_epoch: string; schema_version: typeof BRIDGE_VERSION; event_type: "gateway.usage.v1"; event_id: string; api_key_id: string; outcome: "succeeded" | "failed"; usage_state: "confirmed" | "unknown"; input_tokens: string; output_tokens: string; cache_read_tokens: string; model: string; upstream_model: string; upstream_request_id?: string; duration_ms: string };
