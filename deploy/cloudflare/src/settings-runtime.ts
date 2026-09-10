import { canonical } from "./contracts";

const MAX_I64 = 9_223_372_036_854_775_807n;
const MAX_MUTATIONS = 16;
const MAX_READ_KEYS = 512;
const READ_PAGE_SIZE = 64;
const MAX_VALUE_BYTES = 16_384;
const KEY_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const KEY_ID_RE = /^[A-Za-z0-9._:-]{1,64}$/;
const REQUEST_ID_RE = /^[A-Za-z0-9._:-]{16,128}$/;
const ID_RE = /^[0-9a-f]{32}$/;
const HEX_RE = /^[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

export type SettingsKey = Readonly<{ id: string; material: Uint8Array }>;
export type SettingsKeyring = Readonly<{
  current: SettingsKey;
  previous?: readonly SettingsKey[];
  /** Stable, independently managed 32-byte HMAC material; do not rotate with data keys. */
  fingerprintMaterial: Uint8Array;
}>;
export type Setting = Readonly<{ key: string; value: string; version: string; updatedAt: string }>;
export type WriteOptions = Readonly<{ requestId: string; expectedVersion?: string }>;
export type SettingMutation = Readonly<
  | { kind: "set"; key: string; value: string; expectedVersion?: string }
  | { kind: "delete"; key: string; expectedVersion?: string }
>;
export type WriteResult = Readonly<{ key: string; version: string; deleted: boolean; replayed: boolean }>;

export class SettingsRuntimeError extends Error {
  constructor(
    readonly code:
      | "INVALID_INPUT" | "NOT_FOUND" | "CAS_MISMATCH" | "VERSION_EXHAUSTED"
      | "CORRUPT" | "IDEMPOTENCY_COLLISION" | "IDEMPOTENCY_CORRUPT",
  ) {
    super(code);
  }
}

type StoredRow = Record<string, unknown>;
type ExistingIdempotency = {
  scope_id: string; request_id: string; semantic_digest: string; result_digest: string; witness_count: number;
};
type Witness = { auditId: string; outboxId: string; settingId: string; operation: "set" | "delete"; version: string };
type PreparedMutation = {
  input: SettingMutation; currentVersion: string; nextVersion: string; settingId: string;
  envelope: Envelope | null; contextTag: string | null; auditId: string; outboxId: string;
};
type Envelope = { keyId: string; nonce: string; ciphertext: string };

function fail(code: SettingsRuntimeError["code"]): never { throw new SettingsRuntimeError(code); }
function uuid32(): string { return crypto.randomUUID().replaceAll("-", ""); }
function validVersion(value: unknown, allowZero = false): value is string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(value)) return false;
  if (!allowZero && value === "0") return false;
  try { return BigInt(value) <= MAX_I64; } catch { return false; }
}
function nextVersion(value: string): string {
  if (!validVersion(value)) fail("CORRUPT");
  const next = BigInt(value) + 1n;
  if (next > MAX_I64) fail("VERSION_EXHAUSTED");
  return next.toString();
}
function validText(value: unknown): value is string {
  if (typeof value !== "string" || encoder.encode(value).byteLength > MAX_VALUE_BYTES || value.includes("\0")) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) { if (++i >= value.length || value.charCodeAt(i) < 0xdc00 || value.charCodeAt(i) > 0xdfff) return false; }
    else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}
function validIdentity(value: unknown): value is string {
  return validText(value) && value.length > 0 && encoder.encode(value).byteLength <= 128;
}
function validTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !ISO_RE.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}
function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index++) difference |= left[index] ^ right[index];
  return difference === 0;
}
function b64url(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
function arrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}
function fromB64url(value: unknown, maximum: number): Uint8Array | null {
  if (typeof value !== "string" || !B64URL_RE.test(value) || value.length > Math.ceil(maximum / 3) * 4) return null;
  try {
    const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
    const decoded = atob(padded);
    if (decoded.length > maximum) return null;
    const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    return b64url(bytes) === value ? bytes : null;
  } catch { return null; }
}

export class SettingsRuntime {
  private readonly keys = new Map<string, SettingsKey>();
  private readonly currentKey: SettingsKey;
  private readonly fingerprintMaterial: Uint8Array;

  constructor(private readonly options: Readonly<{
    db: D1Database; keyring: SettingsKeyring; accountId: string; domain: string; now?: () => Date;
  }>) {
    if (!validIdentity(options.accountId) || !validIdentity(options.domain)) fail("INVALID_INPUT");
    if (options.keyring.fingerprintMaterial.byteLength !== 32) fail("INVALID_INPUT");
    for (const key of [options.keyring.current, ...(options.keyring.previous ?? [])]) {
      if (!KEY_ID_RE.test(key.id) || key.material.byteLength !== 32 || this.keys.has(key.id)) fail("INVALID_INPUT");
      if (sameBytes(key.material, options.keyring.fingerprintMaterial)) fail("INVALID_INPUT");
      this.keys.set(key.id, { id: key.id, material: key.material.slice() });
    }
    this.currentKey = this.keys.get(options.keyring.current.id)!;
    this.fingerprintMaterial = options.keyring.fingerprintMaterial.slice();
  }

  async get(key: string): Promise<Setting | null> {
    this.assertKey(key);
    const row = await this.options.db.prepare("SELECT setting_key,version,tombstone,envelope_version,algorithm,key_id,nonce_b64,ciphertext_b64,context_tag,created_at,updated_at FROM settings_runtime WHERE scope_id=? AND setting_key=?")
      .bind(await this.scopeId(), key).first<StoredRow>();
    if (!row) return null;
    return this.decodeRow(row, key);
  }

  async getValue(key: string): Promise<string> {
    const setting = await this.get(key);
    if (!setting) fail("NOT_FOUND");
    return setting.value;
  }

  async getMultiple(keys: readonly string[]): Promise<Record<string, string>> {
    if (keys.length > MAX_READ_KEYS || new Set(keys).size !== keys.length) fail("INVALID_INPUT");
    const entries: [string, string][] = [];
    for (const key of keys) { const setting = await this.get(key); if (setting) entries.push([key, setting.value]); }
    return Object.fromEntries(entries);
  }

  async getAll(): Promise<Record<string, string>> {
    const scopeId = await this.scopeId();
    const entries: [string, string][] = [];
    let afterKey = "";
    while (true) {
      const rows = await this.options.db.prepare("SELECT setting_key,version,tombstone,envelope_version,algorithm,key_id,nonce_b64,ciphertext_b64,context_tag,created_at,updated_at FROM settings_runtime WHERE scope_id=? AND setting_key>? ORDER BY setting_key LIMIT ?")
        .bind(scopeId, afterKey, READ_PAGE_SIZE).all<StoredRow>();
      if (!Array.isArray(rows.results) || rows.results.length > READ_PAGE_SIZE) fail("CORRUPT");
      for (const row of rows.results) {
        const key = row.setting_key;
        if (typeof key !== "string" || !KEY_RE.test(key) || key <= afterKey) fail("CORRUPT");
        const setting = await this.decodeRow(row, key);
        if (setting) entries.push([key, setting.value]);
        afterKey = key;
      }
      if (rows.results.length < READ_PAGE_SIZE) return Object.fromEntries(entries);
    }
  }

  async set(key: string, value: string, options: WriteOptions): Promise<WriteResult> {
    return (await this.mutate([{ kind: "set", key, value, expectedVersion: options.expectedVersion }], options))[0];
  }

  async setMultiple(values: Readonly<Record<string, string>>, options: WriteOptions): Promise<readonly WriteResult[]> {
    const mutations = Object.keys(values).sort().map((key) => ({ kind: "set" as const, key, value: values[key] }));
    return this.mutate(mutations, options);
  }

  async delete(key: string, options: WriteOptions): Promise<WriteResult> {
    return (await this.mutate([{ kind: "delete", key, expectedVersion: options.expectedVersion }], options))[0];
  }

  async mutate(mutations: readonly SettingMutation[], options: WriteOptions): Promise<readonly WriteResult[]> {
    if (mutations.length < 1 || mutations.length > MAX_MUTATIONS || !REQUEST_ID_RE.test(options.requestId) ||
      (options.expectedVersion !== undefined && !validVersion(options.expectedVersion, true))) fail("INVALID_INPUT");
    const keys = new Set<string>();
    for (const mutation of mutations) {
      this.assertKey(mutation.key);
      if (keys.has(mutation.key) || (mutation.kind === "set" && !validText(mutation.value))) fail("INVALID_INPUT");
      if (mutation.expectedVersion !== undefined && !validVersion(mutation.expectedVersion, true)) fail("INVALID_INPUT");
      if (mutation.expectedVersion !== undefined && options.expectedVersion !== undefined && mutation.expectedVersion !== options.expectedVersion) fail("INVALID_INPUT");
      keys.add(mutation.key);
    }
    const scopeId = await this.scopeId();
    const semanticDigest = await this.digest("request", canonical({ requestId: options.requestId, operations: await Promise.all(mutations.map(async (mutation) => ({
      kind: mutation.kind, settingId: await this.settingId(scopeId, mutation.key), expectedVersion: mutation.expectedVersion ?? options.expectedVersion ?? null,
      valueDigest: mutation.kind === "set" ? await this.digest("value", mutation.value) : null,
    }))) }));
    const prior = await this.options.db.prepare("SELECT scope_id,request_id,semantic_digest,result_digest,witness_count FROM settings_runtime_idempotency WHERE scope_id=? AND request_id=?")
      .bind(scopeId, options.requestId).first<ExistingIdempotency>();
    if (prior) return this.replay(prior, semanticDigest, mutations);

    const now = this.timestamp();
    const prepared: PreparedMutation[] = [];
    for (const input of mutations) {
      const current = await this.readState(scopeId, input.key);
      const expected = input.expectedVersion ?? options.expectedVersion ?? current?.version ?? "0";
      if (!current && expected !== "0") fail("CAS_MISMATCH");
      const version = current ? nextVersion(current.version) : "1";
      const settingId = await this.settingId(scopeId, input.key);
      const envelope = input.kind === "set" ? await this.encrypt(input.key, input.value, scopeId) : null;
      const contextTag = envelope ? await this.digest("row", canonical({ scopeId, key: input.key, version, ...envelope })) : null;
      prepared.push({ input, currentVersion: expected, nextVersion: version, settingId, envelope, contextTag, auditId: uuid32(), outboxId: uuid32() });
    }
    const witnesses: Witness[] = prepared.map((entry) => ({ auditId: entry.auditId, outboxId: entry.outboxId, settingId: entry.settingId, operation: entry.input.kind, version: entry.nextVersion })).sort((left, right) => left.settingId.localeCompare(right.settingId));
    const resultDigest = await this.digest("result", canonical({ requestId: options.requestId, semanticDigest, witnesses }));
    const guardId = uuid32();
    const predicates = prepared.map(() => "(scope_id=? AND setting_key=? AND version=? AND tombstone=?)").join(" OR ");
    const guardArgs = prepared.flatMap((entry) => [scopeId, entry.input.key, entry.nextVersion, entry.input.kind === "delete" ? 1 : 0]);
    const statements: D1PreparedStatement[] = prepared.map((entry) => this.options.db.prepare("INSERT INTO settings_runtime_cas_claims(scope_id,setting_key,expected_version,request_id,created_at) VALUES(?,?,?,?,?)").bind(scopeId, entry.input.key, entry.currentVersion, options.requestId, now));
    statements.push(...prepared.map((entry) => {
      const encrypted = entry.envelope;
      return this.options.db.prepare(`INSERT INTO settings_runtime(scope_id,setting_key,version,tombstone,envelope_version,algorithm,key_id,nonce_b64,ciphertext_b64,context_tag,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(scope_id,setting_key) DO UPDATE SET version=excluded.version,tombstone=excluded.tombstone,envelope_version=excluded.envelope_version,algorithm=excluded.algorithm,key_id=excluded.key_id,nonce_b64=excluded.nonce_b64,ciphertext_b64=excluded.ciphertext_b64,context_tag=excluded.context_tag,updated_at=excluded.updated_at WHERE version=?`)
        .bind(scopeId, entry.input.key, entry.nextVersion, entry.input.kind === "delete" ? 1 : 0, encrypted ? 1 : null, encrypted ? "A256GCM-HKDF-SHA256" : null, encrypted?.keyId ?? null, encrypted?.nonce ?? null, encrypted?.ciphertext ?? null, entry.contextTag, now, now, entry.currentVersion);
    }));
    statements.push(this.options.db.prepare(`INSERT INTO settings_runtime_batch_guards(guard_id,expected_count,actual_count) SELECT ?,?,COUNT(*) FROM settings_runtime WHERE ${predicates}`).bind(guardId, prepared.length, ...guardArgs));
    for (const entry of prepared) {
      statements.push(this.options.db.prepare("INSERT INTO settings_runtime_audit(audit_id,scope_id,setting_id,operation,version,request_id,semantic_digest,result_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?)").bind(entry.auditId, scopeId, entry.settingId, entry.input.kind, entry.nextVersion, options.requestId, semanticDigest, resultDigest, now));
      statements.push(this.options.db.prepare("INSERT INTO settings_runtime_outbox(outbox_id,audit_id,scope_id,setting_id,operation,version,request_id,payload_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?)").bind(entry.outboxId, entry.auditId, scopeId, entry.settingId, entry.input.kind, entry.nextVersion, options.requestId, resultDigest, now));
    }
    statements.push(this.options.db.prepare("INSERT INTO settings_runtime_idempotency(scope_id,request_id,semantic_digest,result_digest,witness_count,created_at) VALUES(?,?,?,?,?,?)").bind(scopeId, options.requestId, semanticDigest, resultDigest, prepared.length, now));
    for (const witness of witnesses) statements.push(this.options.db.prepare("INSERT INTO settings_runtime_request_witness(scope_id,request_id,audit_id,outbox_id,setting_id,operation,version) VALUES(?,?,?,?,?,?,?)").bind(scopeId, options.requestId, witness.auditId, witness.outboxId, witness.settingId, witness.operation, witness.version));
    statements.push(this.options.db.prepare("DELETE FROM settings_runtime_batch_guards WHERE guard_id=?").bind(guardId));
    try { await this.options.db.batch(statements); } catch (error) {
      const raced = await this.options.db.prepare("SELECT scope_id,request_id,semantic_digest,result_digest,witness_count FROM settings_runtime_idempotency WHERE scope_id=? AND request_id=?").bind(scopeId, options.requestId).first<ExistingIdempotency>();
      if (raced) return this.replay(raced, semanticDigest, mutations);
      if (error instanceof Error && /settings version exhausted/.test(error.message)) fail("VERSION_EXHAUSTED");
      if (error instanceof Error && /illegal settings transition|settings_runtime_batch_guards|settings_runtime_cas_claims|CHECK constraint failed/.test(error.message)) fail("CAS_MISMATCH");
      throw error;
    }
    return prepared.map((entry) => ({ key: entry.input.key, version: entry.nextVersion, deleted: entry.input.kind === "delete", replayed: false }));
  }

  private async replay(row: ExistingIdempotency, semanticDigest: string, requested: readonly SettingMutation[]): Promise<readonly WriteResult[]> {
    if (!HEX_RE.test(row.scope_id) || !REQUEST_ID_RE.test(row.request_id) || !HEX_RE.test(row.semantic_digest) || !HEX_RE.test(row.result_digest) || !Number.isInteger(row.witness_count) || row.witness_count < 1 || row.witness_count > MAX_MUTATIONS || row.witness_count !== requested.length) fail("IDEMPOTENCY_CORRUPT");
    if (row.semantic_digest !== semanticDigest) fail("IDEMPOTENCY_COLLISION");
    const witnesses = await this.options.db.prepare(`SELECT w.audit_id,w.outbox_id,w.setting_id,w.operation,w.version,
        a.scope_id AS audit_scope_id,a.setting_id AS audit_setting_id,a.operation AS audit_operation,
        a.version AS audit_version,a.request_id AS audit_request_id,a.semantic_digest AS audit_semantic_digest,
        a.result_digest AS audit_digest,a.created_at AS audit_created_at,
        o.audit_id AS outbox_audit_id,o.scope_id AS outbox_scope_id,o.setting_id AS outbox_setting_id,
        o.operation AS outbox_operation,o.version AS outbox_version,o.request_id AS outbox_request_id,
        o.payload_digest AS outbox_digest,o.created_at AS outbox_created_at
      FROM settings_runtime_request_witness w
      LEFT JOIN settings_runtime_audit a ON a.audit_id=w.audit_id
      LEFT JOIN settings_runtime_outbox o ON o.outbox_id=w.outbox_id
      WHERE w.scope_id=? AND w.request_id=? ORDER BY w.setting_id`)
      .bind(row.scope_id, row.request_id).all<Record<string, unknown>>();
    if (!witnesses.results || witnesses.results.length !== row.witness_count) fail("IDEMPOTENCY_CORRUPT");
    const decoded: Witness[] = witnesses.results.map((value) => {
      const auditId = value.audit_id; const outboxId = value.outbox_id; const settingId = value.setting_id;
      if (typeof auditId !== "string" || !ID_RE.test(auditId) || typeof outboxId !== "string" || !ID_RE.test(outboxId) || typeof settingId !== "string" || !HEX_RE.test(settingId) ||
        (value.operation !== "set" && value.operation !== "delete") || !validVersion(value.version) ||
        value.audit_scope_id !== row.scope_id || value.audit_setting_id !== value.setting_id || value.audit_operation !== value.operation ||
        value.audit_version !== value.version || value.audit_request_id !== row.request_id || value.audit_semantic_digest !== row.semantic_digest ||
        value.audit_digest !== row.result_digest || !validTimestamp(value.audit_created_at) ||
        value.outbox_audit_id !== value.audit_id || value.outbox_scope_id !== row.scope_id || value.outbox_setting_id !== value.setting_id ||
        value.outbox_operation !== value.operation || value.outbox_version !== value.version || value.outbox_request_id !== row.request_id ||
        value.outbox_digest !== row.result_digest || !validTimestamp(value.outbox_created_at)) fail("IDEMPOTENCY_CORRUPT");
      return { auditId, outboxId, settingId, operation: value.operation, version: value.version };
    });
    const expected = await this.digest("result", canonical({ requestId: row.request_id, semanticDigest, witnesses: decoded }));
    if (expected !== row.result_digest) fail("IDEMPOTENCY_CORRUPT");
    const bySettingId = new Map(decoded.map((entry) => [entry.settingId, entry]));
    return Promise.all(requested.map(async (input) => {
      const entry = bySettingId.get(await this.settingId(row.scope_id, input.key));
      if (!entry || entry.operation !== input.kind) fail("IDEMPOTENCY_CORRUPT");
      return { key: input.key, version: entry.version, deleted: entry.operation === "delete", replayed: true };
    }));
  }

  private async readState(scopeId: string, key: string): Promise<{ version: string } | null> {
    const row = await this.options.db.prepare("SELECT setting_key,version,tombstone,envelope_version,algorithm,key_id,nonce_b64,ciphertext_b64,context_tag,created_at,updated_at FROM settings_runtime WHERE scope_id=? AND setting_key=?").bind(scopeId, key).first<StoredRow>();
    if (!row) return null;
    const version = row.version;
    if (!validVersion(version) || row.setting_key !== key || (row.tombstone !== 0 && row.tombstone !== 1) ||
      !validTimestamp(row.created_at) || !validTimestamp(row.updated_at) || row.updated_at < row.created_at) fail("CORRUPT");
    if (row.tombstone === 0) await this.decodeRow(row, key); else if (row.envelope_version !== null || row.algorithm !== null || row.key_id !== null || row.nonce_b64 !== null || row.ciphertext_b64 !== null || row.context_tag !== null) fail("CORRUPT");
    return { version };
  }

  private async decodeRow(row: StoredRow, key: string): Promise<Setting | null> {
    if (row.setting_key !== key || !validVersion(row.version) || (row.tombstone !== 0 && row.tombstone !== 1) ||
      !validTimestamp(row.created_at) || !validTimestamp(row.updated_at) || row.updated_at < row.created_at) fail("CORRUPT");
    if (row.tombstone === 1) {
      if (row.envelope_version !== null || row.algorithm !== null || row.key_id !== null || row.nonce_b64 !== null || row.ciphertext_b64 !== null || row.context_tag !== null) fail("CORRUPT");
      return null;
    }
    if (row.envelope_version !== 1 || row.algorithm !== "A256GCM-HKDF-SHA256" || typeof row.key_id !== "string" || !KEY_ID_RE.test(row.key_id) || typeof row.nonce_b64 !== "string" || typeof row.ciphertext_b64 !== "string" || typeof row.context_tag !== "string" || !HEX_RE.test(row.context_tag)) fail("CORRUPT");
    const scopeId = await this.scopeId();
    const envelope = { keyId: row.key_id, nonce: row.nonce_b64, ciphertext: row.ciphertext_b64 };
    const expectedTag = await this.digest("row", canonical({ scopeId, key, version: row.version, ...envelope }));
    if (expectedTag !== row.context_tag) fail("CORRUPT");
    const value = await this.decrypt(key, envelope, scopeId);
    return { key, value, version: row.version, updatedAt: row.updated_at };
  }

  private async encrypt(key: string, value: string, scopeId: string): Promise<Envelope> {
    const source = this.currentKey;
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const cryptoKey = await this.encryptionKey(source, key, scopeId);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: arrayBuffer(nonce), additionalData: this.aad(key, source.id) }, cryptoKey, arrayBuffer(encoder.encode(value)));
    return { keyId: source.id, nonce: b64url(nonce), ciphertext: b64url(new Uint8Array(ciphertext)) };
  }

  private async decrypt(key: string, envelope: Envelope, scopeId: string): Promise<string> {
    const source = this.keys.get(envelope.keyId);
    const nonce = fromB64url(envelope.nonce, 12); const ciphertext = fromB64url(envelope.ciphertext, MAX_VALUE_BYTES + 16);
    if (!source || !nonce || nonce.byteLength !== 12 || !ciphertext || ciphertext.byteLength < 16) fail("CORRUPT");
    try {
      const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: arrayBuffer(nonce), additionalData: this.aad(key, source.id) }, await this.encryptionKey(source, key, scopeId), arrayBuffer(ciphertext));
      const value = decoder.decode(plaintext);
      if (!validText(value)) fail("CORRUPT");
      return value;
    } catch { fail("CORRUPT"); }
  }

  private aad(key: string, keyId: string): ArrayBuffer { return arrayBuffer(encoder.encode(canonical({ algorithm: "A256GCM-HKDF-SHA256", accountId: this.options.accountId, domain: this.options.domain, key, keyId, version: 1 }))); }
  private async encryptionKey(source: SettingsKey, key: string, scopeId: string): Promise<CryptoKey> {
    const master = await crypto.subtle.importKey("raw", arrayBuffer(source.material), "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: arrayBuffer(encoder.encode(scopeId)), info: arrayBuffer(encoder.encode(`sub2api.settings.v1/encryption/${this.options.accountId}/${this.options.domain}/${key}/${source.id}`)) }, master, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  private async digest(domain: string, value: string): Promise<string> {
    const key = await crypto.subtle.importKey("raw", arrayBuffer(this.fingerprintMaterial), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return [...new Uint8Array(await crypto.subtle.sign("HMAC", key, arrayBuffer(encoder.encode(`sub2api.settings.v1/${domain}\0${value}`))))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  private scopeId(): Promise<string> { return this.digest("scope", canonical({ accountId: this.options.accountId, domain: this.options.domain })); }
  private settingId(scopeId: string, key: string): Promise<string> { return this.digest("setting-id", canonical({ scopeId, key })); }
  private assertKey(key: string): void { if (!KEY_RE.test(key)) fail("INVALID_INPUT"); }
  private timestamp(): string {
    try {
      const value = (this.options.now?.() ?? new Date()).toISOString();
      if (!validTimestamp(value)) fail("INVALID_INPUT");
      return value;
    } catch { fail("INVALID_INPUT"); }
  }
}
