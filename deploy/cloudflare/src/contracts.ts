export const BRIDGE_VERSION = "2026-09-09.v3";
export const D1_BASE_SCHEMA_VERSION = "2026-09-06.v1";
export const USAGE_SCHEMA_VERSION = "2026-09-09.v2";
export const USAGE_EVENT_TYPE = "gateway.usage.v2";
export const INTERNAL_HOST = "sub2api.internal";
export const MAX_CONTROL_BODY_BYTES = 64 * 1024;

export const json = (value: unknown, status = 200): Response =>
  Response.json(value, {
    status,
    headers: { "cache-control": "no-store" },
  });

export const error = (code: string, status = 400): Response =>
  json({ error: { code, message: code } }, status);

export const now = (): string => new Date().toISOString();

export function isCanonicalPositiveDecimal(value: unknown): value is string {
  return typeof value === "string" && /^[1-9][0-9]*$/.test(value);
}

export function isCanonicalUnsignedDecimal(value: unknown): value is string {
  return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value);
}

export function isBoundedString(
  value: unknown,
  maximumLength: number,
  minimumLength = 1,
): value is string {
  return (
    typeof value === "string" &&
    value.length >= minimumLength &&
    value.length <= maximumLength
  );
}

export async function sha256(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function readJson<T>(
  request: Request,
  limit = MAX_CONTROL_BODY_BYTES,
): Promise<T | null> {
  const declaredLength = request.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^[0-9]+$/.test(declaredLength) || Number(declaredLength) > limit)
  ) {
    return null;
  }
  if (!request.body) return null;

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > limit) {
        await reader.cancel();
        return null;
      }
      chunks.push(part.value);
    }

    const output = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      output.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return JSON.parse(new TextDecoder().decode(output)) as T;
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}

/** Stable JSON for hashing protocol-owned values. Unsupported JS values fail. */
export function canonical(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  if (typeof value !== "object") {
    throw new TypeError("unsupported canonical JSON value");
  }

  const input = value as Record<string, unknown>;
  return `{${Object.keys(input)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(input[key])}`)
    .join(",")}}`;
}

export type LeaseIdentity = {
  request_id: string;
  account_id: string;
  lease_id: string;
  owner: string;
  epoch: string;
};

export type Completion = Omit<LeaseIdentity, "owner" | "epoch"> & {
  lease_epoch: string;
  schema_version: typeof USAGE_SCHEMA_VERSION;
  event_type: typeof USAGE_EVENT_TYPE;
  event_id: string;
  api_key_id: string;
  outcome: "succeeded" | "failed";
  usage_state: "confirmed" | "unknown";
  input_tokens: string;
  image_input_tokens?: string;
  output_tokens: string;
  image_output_tokens?: string;
  cache_creation_tokens?: string;
  cache_creation_5m_tokens?: string;
  cache_creation_1h_tokens?: string;
  cache_read_tokens: string;
  service_tier?: string;
  reasoning_effort?: string;
  model: string;
  upstream_model: string;
  upstream_request_id?: string;
  duration_ms: string;
};

export type UsageEnvelope = {
  event_id: string;
  payload: string;
  payload_hash: string;
};
