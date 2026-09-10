import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { SettingsRuntime, SettingsRuntimeError } from "../src/settings-runtime";

const material = (offset: number) => Uint8Array.from({ length: 32 }, (_, index) => (index + offset) % 256);
const fingerprint = material(91);
let sequence = 0;
const requestId = () => `settings-runtime-request-${++sequence}`;
const runtime = (account = `account-${++sequence}`, key = material(1), previous: readonly { id: string; material: Uint8Array }[] = [], currentId = "current") => new SettingsRuntime({
  db: env.DB,
  accountId: account,
  domain: "control-plane",
  keyring: {
    current: { id: currentId, material: key },
    previous,
    fingerprintMaterial: fingerprint,
  },
  now: () => new Date("2026-09-10T00:00:00.000Z"),
});

const expectCode = async (promise: Promise<unknown>, code: SettingsRuntimeError["code"]) => {
  await expect(promise).rejects.toMatchObject({ code });
};

describe("settings runtime", () => {
  it("migrates, encrypts every value, uses fresh nonces, and round-trips empty values", async () => {
    const store = runtime();
    await store.setMultiple({ alpha: "private value", empty: "" }, { requestId: requestId() });
    expect(await store.getValue("alpha")).toBe("private value");
    expect(await store.getValue("empty")).toBe("");
    expect(await store.getMultiple(["alpha", "missing"])).toEqual({ alpha: "private value" });
    expect(await store.getAll()).toEqual({ alpha: "private value", empty: "" });
    const raw = await env.DB.prepare("SELECT nonce_b64,ciphertext_b64,context_tag FROM settings_runtime WHERE setting_key IN ('alpha','empty') ORDER BY setting_key").all<Record<string, string>>();
    expect(JSON.stringify(raw.results)).not.toContain("private value");
    expect(raw.results[0].nonce_b64).not.toBe(raw.results[1].nonce_b64);
    const tables = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='settings_runtime'").all<{ name: string }>();
    expect(tables.results).toEqual([{ name: "settings_runtime" }]);
  });

  it("paginates complete reads beyond the write-batch bound and preserves hostile property names", async () => {
    const store = runtime();
    const expected: Record<string, string> = {};
    for (let offset = 0; offset < 65; offset += 16) {
      const values: Record<string, string> = {};
      for (let index = offset; index < Math.min(offset + 16, 65); index++) {
        values[`bulk-${index.toString().padStart(3, "0")}`] = `value-${index}`;
        expected[`bulk-${index.toString().padStart(3, "0")}`] = `value-${index}`;
      }
      await store.setMultiple(values, { requestId: requestId() });
    }
    await store.set("__proto__", "ordinary-setting", { requestId: requestId() });
    const all = await store.getAll();
    expect(Object.keys(all)).toHaveLength(66);
    expect(all).toMatchObject(expected);
    expect(Object.hasOwn(all, "__proto__")).toBe(true);
    expect(all.__proto__).toBe("ordinary-setting");
    expect(Object.getPrototypeOf(all)).toBe(Object.prototype);
    const selected = await store.getMultiple(["__proto__", "bulk-064"]);
    expect(Object.hasOwn(selected, "__proto__")).toBe(true);
    expect(selected.__proto__).toBe("ordinary-setting");
  });

  it("binds ciphertext to account, domain, key, and authenticates wrong keys", async () => {
    const old = material(3); const fresh = material(4); const account = `binding-${++sequence}`;
    const original = runtime(account, old, [], "old");
    await original.set("bound", "cannot move", { requestId: requestId() });
    const rotated = runtime(account, fresh, [{ id: "old", material: old }], "new");
    expect(await rotated.getValue("bound")).toBe("cannot move");
    await rotated.set("new", "uses current", { requestId: requestId() });
    await expectCode(runtime(account, fresh, [], "new").getValue("bound"), "CORRUPT");
    await expectCode(runtime(`${account}-other`, fresh, [{ id: "old", material: old }], "new").getValue("bound"), "NOT_FOUND");
    await expect(env.DB.prepare("UPDATE settings_runtime SET nonce_b64=(SELECT nonce_b64 FROM settings_runtime WHERE setting_key='bound'), ciphertext_b64=(SELECT ciphertext_b64 FROM settings_runtime WHERE setting_key='bound') WHERE setting_key='new'").run()).rejects.toThrow();
  });

  it("snapshots caller-owned key bytes and rejects fingerprint/data-key reuse", async () => {
    const key = material(31); const hmac = material(121); const account = `snapshot-${++sequence}`;
    const store = new SettingsRuntime({
      db: env.DB, accountId: account, domain: "control-plane",
      keyring: { current: { id: "snapshot", material: key }, fingerprintMaterial: hmac },
      now: () => new Date("2026-09-10T00:00:00.000Z"),
    });
    await store.set("before", "still-readable", { requestId: requestId() });
    key.fill(0); hmac.fill(0);
    await store.set("after", "still-encrypted", { requestId: requestId() });
    expect(await store.getAll()).toMatchObject({ before: "still-readable", after: "still-encrypted" });
    const reused = material(77);
    expect(() => new SettingsRuntime({
      db: env.DB, accountId: "account", domain: "control-plane",
      keyring: { current: { id: "same", material: reused }, fingerprintMaterial: reused },
    })).toThrowError(expect.objectContaining({ code: "INVALID_INPUT" }));
  });

  it("fails closed for malformed envelopes, poisoned rows, and bad authentication", async () => {
    const key = material(7); const account = `corrupt-${++sequence}`; const store = runtime(account, key);
    await store.set("safe", "value", { requestId: requestId() });
    await expectCode(runtime(account, material(8)).getValue("safe"), "CORRUPT");
    await env.DB.prepare("INSERT INTO settings_runtime(scope_id,setting_key,version,tombstone,envelope_version,algorithm,key_id,nonce_b64,ciphertext_b64,context_tag,created_at,updated_at) SELECT scope_id,'poison',1,0,1,'A256GCM-HKDF-SHA256','current','AAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAAAAAAAA','0000000000000000000000000000000000000000000000000000000000000000',created_at,updated_at FROM settings_runtime WHERE setting_key='safe'").run();
    await expectCode(store.getValue("poison"), "CORRUPT");
    await expect(env.DB.prepare("INSERT INTO settings_runtime(scope_id,setting_key,version,tombstone,created_at,updated_at) SELECT scope_id,'null-envelope','1',0,created_at,updated_at FROM settings_runtime WHERE setting_key='safe'").run()).rejects.toThrow();
    await expect(env.DB.prepare("INSERT INTO settings_runtime(scope_id,setting_key,version,tombstone,created_at,updated_at) SELECT scope_id,'bad-time','1',1,?,? FROM settings_runtime WHERE setting_key='safe'").bind("xxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxx").run()).rejects.toThrow();
  });

  it("uses explicit CAS and all-or-nothing multi-set batches", async () => {
    const store = runtime();
    await expectCode(store.set("missing", "must-not-create", { requestId: requestId(), expectedVersion: "7" }), "CAS_MISMATCH");
    expect(await store.get("missing")).toBeNull();
    await store.set("created", "yes", { requestId: requestId(), expectedVersion: "0" });
    await expectCode(store.mutate([{ kind: "set", key: "bad-global", value: "x" }], { requestId: requestId(), expectedVersion: "01" }), "INVALID_INPUT");
    await store.set("a", "one", { requestId: requestId() });
    const race = await Promise.allSettled([
      store.set("a", "two", { requestId: requestId(), expectedVersion: "1" }),
      store.set("a", "three", { requestId: requestId(), expectedVersion: "1" }),
    ]);
    expect(race.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(race.filter((result) => result.status === "rejected")[0]).toMatchObject({ reason: { code: "CAS_MISMATCH" } });
    const before = await store.getValue("a");
    await store.set("b", "old", { requestId: requestId() });
    await expectCode(store.mutate([
      { kind: "set", key: "a", value: "should-roll-back", expectedVersion: "2" },
      { kind: "set", key: "b", value: "also-rollback", expectedVersion: "0" },
    ], { requestId: requestId() }), "CAS_MISMATCH");
    expect(await store.getValue("a")).toBe(before);
    expect(await store.getValue("b")).toBe("old");
  });

  it("requires exact idempotency semantics and detects immutable-witness tampering", async () => {
    const store = runtime(); const id = requestId();
    const first = await store.set("idem", "same", { requestId: id });
    const replay = await store.set("idem", "same", { requestId: id });
    expect(first.replayed).toBe(false); expect(replay.replayed).toBe(true); expect(replay.version).toBe(first.version);
    await expectCode(store.set("idem", "different", { requestId: id }), "IDEMPOTENCY_COLLISION");
    await expect(env.DB.prepare("UPDATE settings_runtime_audit SET result_digest='0000000000000000000000000000000000000000000000000000000000000000'").run()).rejects.toThrow();
    await expect(env.DB.prepare("DELETE FROM settings_runtime_outbox").run()).rejects.toThrow();
    await expect(env.DB.prepare("UPDATE settings_runtime_request_witness SET version='2'").run()).rejects.toThrow();
    await env.DB.exec("DROP TRIGGER settings_runtime_witness_no_update");
    await env.DB.prepare("UPDATE settings_runtime_request_witness SET version='999' WHERE request_id=?").bind(id).run();
    await expectCode(store.set("idem", "same", { requestId: id }), "IDEMPOTENCY_CORRUPT");
    await env.DB.exec("CREATE TRIGGER IF NOT EXISTS settings_runtime_witness_no_update BEFORE UPDATE ON settings_runtime_request_witness BEGIN SELECT RAISE(ABORT,'settings witness is immutable'); END");
    const idempotencyId = requestId();
    await store.set("idem-corrupt", "same", { requestId: idempotencyId });
    await env.DB.exec("DROP TRIGGER settings_runtime_idempotency_no_update");
    await env.DB.prepare("UPDATE settings_runtime_idempotency SET result_digest='0000000000000000000000000000000000000000000000000000000000000000' WHERE request_id=?").bind(idempotencyId).run();
    await expectCode(store.set("idem-corrupt", "same", { requestId: idempotencyId }), "IDEMPOTENCY_CORRUPT");
    await env.DB.exec("CREATE TRIGGER IF NOT EXISTS settings_runtime_idempotency_no_update BEFORE UPDATE ON settings_runtime_idempotency BEGIN SELECT RAISE(ABORT,'settings idempotency is immutable'); END");
    const metadataId = requestId();
    await store.set("metadata-corrupt", "same", { requestId: metadataId });
    await env.DB.exec("DROP TRIGGER settings_runtime_audit_no_update");
    await env.DB.prepare("UPDATE settings_runtime_audit SET operation='delete' WHERE request_id=?").bind(metadataId).run();
    await expectCode(store.set("metadata-corrupt", "same", { requestId: metadataId }), "IDEMPOTENCY_CORRUPT");
    await env.DB.exec("CREATE TRIGGER IF NOT EXISTS settings_runtime_audit_no_update BEFORE UPDATE ON settings_runtime_audit BEGIN SELECT RAISE(ABORT,'settings audit is immutable'); END");
  });

  it("creates versioned tombstones and rejects overflow, duplicate operations, hostile keys, and oversized values", async () => {
    const store = runtime();
    await store.set("gone", "value", { requestId: requestId() });
    const deleted = await store.delete("gone", { requestId: requestId(), expectedVersion: "1" });
    expect(deleted).toMatchObject({ version: "2", deleted: true });
    await expectCode(store.getValue("gone"), "NOT_FOUND");
    const tombstone = await env.DB.prepare("SELECT tombstone,envelope_version,ciphertext_b64 FROM settings_runtime WHERE setting_key='gone'").first<Record<string, unknown>>();
    expect(tombstone).toEqual({ tombstone: 1, envelope_version: null, ciphertext_b64: null });
    await expectCode(store.mutate([{ kind: "set", key: "dup", value: "a" }, { kind: "delete", key: "dup" }], { requestId: requestId() }), "INVALID_INPUT");
    await expectCode(store.set("bad'); DROP TABLE settings_runtime;--", "x", { requestId: requestId() }), "INVALID_INPUT");
    await expectCode(store.set("long", "x".repeat(16_385), { requestId: requestId() }), "INVALID_INPUT");
    await expectCode(store.getMultiple(Array.from({ length: 513 }, (_, index) => `key-${index}`)), "INVALID_INPUT");
    const badClock = new SettingsRuntime({
      db: env.DB, accountId: `bad-clock-${++sequence}`, domain: "control-plane",
      keyring: { current: { id: "current", material: material(1) }, fingerprintMaterial: fingerprint },
      now: () => new Date(Number.NaN),
    });
    await expectCode(badClock.set("time", "x", { requestId: requestId() }), "INVALID_INPUT");
    await env.DB.prepare("INSERT INTO settings_runtime(scope_id,setting_key,version,tombstone,created_at,updated_at) SELECT scope_id,'exhausted','9223372036854775807',1,created_at,updated_at FROM settings_runtime WHERE setting_key='gone'").run();
    await expectCode(store.delete("exhausted", { requestId: requestId(), expectedVersion: "9223372036854775807" }), "VERSION_EXHAUSTED");
    const table = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='settings_runtime'").first<{ name: string }>();
    expect(table?.name).toBe("settings_runtime");
  });
});
