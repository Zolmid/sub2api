import { isBoundedString } from "./contracts";

export type CredentialRuntime = {
  ENVIRONMENT: string;
  ALLOW_TEST_FIXTURE: string;
  SUB2API_CF_UPSTREAM_ALLOWED_HOSTS: string;
  CREDENTIAL_ENCRYPTION_KEY?: string;
};

export function decodeBase64(value: string): Uint8Array {
  const decoded = atob(value);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function allowedUpstreamHosts(env: CredentialRuntime): string[] {
  return env.SUB2API_CF_UPSTREAM_ALLOWED_HOSTS.split(",")
    .map((host) => host.trim().toLowerCase().replace(/\.$/, ""))
    .filter((host, index, values) =>
      host.length > 0 && host.length <= 253 && !/[/?#@]/.test(host) &&
      values.indexOf(host) === index,
    );
}

const TOTP_ENVELOPE_PREFIX = "aes-gcm:v1:totp:";

function encodeBase64(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value));
}

export async function encryptTOTPSecret(
  secret: string,
  env: Pick<CredentialRuntime, "CREDENTIAL_ENCRYPTION_KEY">,
): Promise<string | null> {
  if (!/^[A-Z2-7]{32}$/.test(secret)) return null;
  const key = await encryptionKey(env as CredentialRuntime);
  if (!key) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  try {
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: new TextEncoder().encode("sub2api:totp:v1"),
      },
      key,
      new TextEncoder().encode(secret),
    );
    return TOTP_ENVELOPE_PREFIX + encodeBase64(iv) + ":" +
      encodeBase64(new Uint8Array(ciphertext));
  } catch {
    return null;
  }
}

export async function decryptTOTPSecret(
  envelope: string,
  env: Pick<CredentialRuntime, "CREDENTIAL_ENCRYPTION_KEY">,
): Promise<string | null> {
  if (!envelope.startsWith(TOTP_ENVELOPE_PREFIX)) return null;
  const parts = envelope.split(":");
  if (parts.length !== 5 || parts.slice(0, 3).join(":") !== "aes-gcm:v1:totp") {
    return null;
  }
  const key = await encryptionKey(env as CredentialRuntime);
  if (!key) return null;
  try {
    const iv = decodeBase64(parts[3]);
    const ciphertext = decodeBase64(parts[4]);
    if (iv.byteLength !== 12 || ciphertext.byteLength < 32) return null;
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: new TextEncoder().encode("sub2api:totp:v1"),
      },
      key,
      ciphertext,
    );
    const secret = new TextDecoder().decode(plaintext);
    return /^[A-Z2-7]{32}$/.test(secret) ? secret : null;
  } catch {
    return null;
  }
}

function hostMatches(pattern: string, hostname: string): boolean {
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2);
    return hostname.length > suffix.length && hostname.endsWith("." + suffix);
  }
  return pattern === hostname;
}

export function validateAPIKeyCredentials(candidate: unknown, env: CredentialRuntime): Record<string, string> | null {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return null;
  const value = candidate as Record<string, unknown>;
  if (!isBoundedString(value.api_key, 16_384) || !isBoundedString(value.base_url, 2_048)) return null;
  try {
    const url = new URL(value.base_url);
    const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
    if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "" || !allowedUpstreamHosts(env).some((host) => hostMatches(host, hostname))) return null;
    return { api_key: value.api_key, base_url: url.toString().replace(/\/$/, "") };
  } catch {
    return null;
  }
}

async function encryptionKey(env: CredentialRuntime): Promise<CryptoKey | null> {
  if (!env.CREDENTIAL_ENCRYPTION_KEY) return null;
  try {
    const keyBytes = decodeBase64(env.CREDENTIAL_ENCRYPTION_KEY);
    if (keyBytes.byteLength !== 32) return null;
    return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
  } catch {
    return null;
  }
}

export async function encryptAPIKeyCredentials(candidate: unknown, env: CredentialRuntime): Promise<string | null> {
  const credentials = validateAPIKeyCredentials(candidate, env);
  const key = await encryptionKey(env);
  if (!credentials || !key) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(credentials)));
    const encode = (value: Uint8Array) => btoa(String.fromCharCode(...value));
    return "aes-gcm:v1:" + encode(iv) + ":" + encode(new Uint8Array(ciphertext));
  } catch {
    return null;
  }
}

export async function decryptAPIKeyCredentials(envelope: string, env: CredentialRuntime): Promise<Record<string, string> | null> {
  if (env.ENVIRONMENT === "local" && env.ALLOW_TEST_FIXTURE === "true" && envelope === "fixture:v1:mock-upstream") return validateAPIKeyCredentials({ api_key: "fixture-upstream-token", base_url: "https://mock.upstream" }, env);
  const parts = envelope.split(":");
  const key = await encryptionKey(env);
  if (!key || parts.length !== 4 || parts[0] !== "aes-gcm" || parts[1] !== "v1") return null;
  try {
    const iv = decodeBase64(parts[2]);
    const ciphertext = decodeBase64(parts[3]);
    if (iv.byteLength !== 12 || ciphertext.byteLength < 17) return null;
    const cleartext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return validateAPIKeyCredentials(JSON.parse(new TextDecoder().decode(cleartext)), env);
  } catch {
    return null;
  }
}
