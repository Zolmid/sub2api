import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { controlPlane } from "../src/control-plane";
import { BRIDGE_VERSION } from "../src/contracts";

type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };
const testEnv = env as TestEnv;
const id = () => "9" + String(crypto.getRandomValues(new Uint32Array(1))[0]).padStart(10, "0");
const encryptionKey = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const secureEnv = new Proxy(env, {
  get(target, property, receiver) {
    if (property === "CREDENTIAL_ENCRYPTION_KEY") return encryptionKey;
    return Reflect.get(target, property, receiver);
  },
}) as Env;
const missingCredentialKeyEnv = new Proxy(env, {
  get(target, property, receiver) {
    if (property === "CREDENTIAL_ENCRYPTION_KEY") return undefined;
    return Reflect.get(target, property, receiver);
  },
}) as Env;
const request = (path: string, body: object, options: { host?: string; version?: string; container?: string } = {}) =>
  new Request("http://" + (options.host ?? "sub2api.internal") + path, {
    method: "POST",
    headers: { "content-type": "application/json", "X-Sub2API-Bridge-Version": options.version ?? BRIDGE_VERSION, ...(options.container === "" ? {} : { "X-Sub2API-Container-Id": options.container ?? "management-test" }) },
    body: JSON.stringify(body),
  });
const call = (path: string, body: object, options?: Parameters<typeof request>[2], target: Env = secureEnv) => {
  return controlPlane(request(path, body, options), target);
};

async function createScope(tag: string) {
  const userID = id(); const groupID = id(); const keyID = id(); const accountID = id();
  const operation = tag + "-user-" + userID;
  const userResponse = await call("/v1/manage/users/create", { operation_id: operation, semantic_digest: "a".repeat(64), id: userID, email: tag + "-" + userID + "@example.test", password_hash: "password-hash-for-" + tag, username: tag, notes: "", status: "active", role: "user", concurrency: 1, rpm_limit: 0, balance_microusd: "1", allowed_group_ids: [], restrict_public_groups: false });
  if (userResponse.status !== 200) throw new Error(await userResponse.text());
  const groupResponse = await call("/v1/manage/groups/create", { operation_id: tag + "-group-" + groupID, id: groupID, name: tag, platform: "openai", status: "active", is_exclusive: false, subscription_type: "standard" });
  if (groupResponse.status !== 200) throw new Error(await groupResponse.text());
  expect((await call("/v1/manage/users/update", { operation_id: tag + "-groups-" + userID, id: userID, allowed_group_ids: [groupID] })).status).toBe(200);
  return { userID, groupID, keyID, accountID };
}

const userCreateBody = (
  operationID: string,
  userID: string,
  email: string,
  overrides: Record<string, unknown> = {},
) => ({
  operation_id: operationID,
  semantic_digest: "c".repeat(64),
  id: userID,
  email,
  password_hash: "bcrypt-compatible-test-hash-0001",
  username: "managed-user",
  notes: "",
  status: "active",
  role: "user",
  concurrency: 1,
  rpm_limit: 0,
  balance_microusd: "0",
  allowed_group_ids: [],
  restrict_public_groups: false,
  ...overrides,
});

describe("Stage C private management control plane", () => {
  it("loads the deterministic fixture users through the managed decoder shape", async () => {
    const list = await call("/v1/manage/users/list", { cursor: "0", limit: 10 });
    expect(list.status).toBe(200);
    expect(await list.json()).toMatchObject({
      users: [
        { id: "1001", email: "fixture-active-1001@example.test", username: "fixture-active-1001" },
        { id: "1002", email: "fixture-disabled-1002@example.test", username: "fixture-disabled-1002" },
      ],
    });
  });
  it("reads immutable balance history with stable paging and does not expose operation IDs", async () => {
    const scope = await createScope("ledger-history-" + id());
    const adminID = id();
    expect((await call("/v1/manage/users/create", userCreateBody("ledger-history-admin-" + adminID, adminID, "ledger-history-admin-" + adminID + "@example.test"))).status).toBe(200);
    await env.DB.prepare("UPDATE users SET role='admin' WHERE id=?").bind(adminID).run();
    const stamp = "2026-09-07T01:02:03Z";
    await env.DB.batch([
      env.DB.prepare("INSERT INTO balance_ledger(id,operation_id,actor_user_id,target_user_id,adjustment_type,reason,delta_e8_usd,balance_before_e8_usd,balance_after_e8_usd,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind("history-a-" + scope.userID, "secret-operation-a", adminID, scope.userID, "add", "first add", "125000000", "0", "125000000", stamp),
      env.DB.prepare("INSERT INTO balance_ledger(id,operation_id,actor_user_id,target_user_id,adjustment_type,reason,delta_e8_usd,balance_before_e8_usd,balance_after_e8_usd,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind("history-b-" + scope.userID, "secret-operation-b", adminID, scope.userID, "subtract", "second subtract", "-25000000", "125000000", "100000000", stamp),
    ]);
    const first = await call("/v1/manage/users/balance-history", { id: scope.userID, page: 1, page_size: 1 });
    expect(first.status).toBe(200);
    const firstBody = await first.json<{ items: Array<{ adjustment_type: string; delta_microusd: string; reason: string }>; total: string; total_recharged: number }>();
    expect(firstBody).toMatchObject({ total: "2", total_recharged: 1.25, items: [{ adjustment_type: "subtract", delta_microusd: "-250000", reason: "second subtract" }] });
    expect(JSON.stringify(firstBody)).not.toContain("secret-operation");
    const second = await call("/v1/manage/users/balance-history", { id: scope.userID, page: 2, page_size: 1, type: "admin_balance" });
    expect(second.status).toBe(200);
    expect(await second.json()).toMatchObject({ items: [{ adjustment_type: "add", delta_microusd: "1250000" }], total: "2", total_recharged: 1.25 });
    expect((await call("/v1/manage/users/balance-history", { id: scope.userID, page: 1, page_size: 1, type: "concurrency" })).status).toBe(200);
    expect((await call("/v1/manage/users/balance-history", { id: scope.userID, page: 1, page_size: 1, type: "not-a-history-type" })).status).toBe(400);
    expect(await env.DB.prepare("UPDATE users SET deleted_at=? WHERE id=?").bind(stamp, scope.userID).run());
    expect((await call("/v1/manage/users/balance-history", { id: scope.userID, page: 1, page_size: 1 })).status).toBe(404);
    expect((await call("/v1/manage/users/balance-history", { id: "999999999999", page: 1, page_size: 1 })).status).toBe(404);
    expect((await call("/v1/manage/users/balance-history", { id: scope.userID, page: 0, page_size: 1 })).status).toBe(400);
  });
  it("commits exact immutable balance ledger entries with idempotency and stale guards", async () => {
    const scope = await createScope("ledger-" + id());
    const adminID = id();
    expect((await call("/v1/manage/users/create", userCreateBody("ledger-admin-" + adminID, adminID, "ledger-admin-" + adminID + "@example.test", { role: "user" }))).status).toBe(200);
    await env.DB.prepare("UPDATE users SET role='admin' WHERE id=?").bind(adminID).run();
    const request = { operation_id: "ledger-op-" + scope.userID, actor_user_id: adminID, target_user_id: scope.userID, operation: "add", amount_microusd: "999999", reason: "manual" };
    const first = await call("/v1/manage/users/balance-adjust", request); expect(first.status).toBe(200);
    const result = await first.json<{ balance: { balance_before_microusd: string; balance_after_microusd: string; delta_microusd: string }; replayed: boolean }>();
    expect(result.balance).toMatchObject({ balance_before_microusd: "1", balance_after_microusd: "1000000", delta_microusd: "999999" }); expect(result.replayed).toBe(false);
    const replay = await call("/v1/manage/users/balance-adjust", request);
    expect(replay.status).toBe(200);
    expect(await replay.json()).toMatchObject({ replayed: true });
    expect((await call("/v1/manage/users/balance-adjust", { ...request, amount_microusd: "2" })).status).toBe(409);
    expect((await call("/v1/manage/users/balance-adjust", { ...request, operation_id: "ledger-negative-" + scope.userID, operation: "subtract", amount_microusd: "1000001" })).status).toBe(409);
    const maximum = "9007199254740991";
    expect((await call("/v1/manage/users/balance-adjust", { ...request, operation_id: "ledger-maximum-" + scope.userID, operation: "set", amount_microusd: maximum })).status).toBe(200);
    const unreadableOperation = "ledger-unreadable-" + scope.userID;
    expect((await call("/v1/manage/users/balance-adjust", { ...request, operation_id: unreadableOperation, operation: "set", amount_microusd: "9007199254740992" })).status).toBe(409);
    expect(await env.DB.prepare("SELECT balance_e8_usd FROM users WHERE id=?").bind(scope.userID).first("balance_e8_usd")).toBe((BigInt(maximum) * 100n).toString());
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id=?").bind(unreadableOperation).first("count")).toBe(0);
    expect(await env.DB.prepare("SELECT count(*) count FROM balance_ledger WHERE operation_id=?").bind(unreadableOperation).first("count")).toBe(0);
    expect((await call("/v1/manage/users/balance-adjust", { ...request, operation_id: "ledger-overflow-" + scope.userID, operation: "add", amount_microusd: "1" })).status).toBe(409);
    const ledger = await env.DB.prepare("SELECT count(*) count FROM balance_ledger WHERE target_user_id=?").bind(scope.userID).first("count"); expect(ledger).toBe(2);
    await expect(env.DB.prepare("UPDATE balance_ledger SET reason='rewritten' WHERE target_user_id=?").bind(scope.userID).run()).rejects.toThrow();
    await expect(env.DB.prepare("DELETE FROM balance_ledger WHERE target_user_id=?").bind(scope.userID).run()).rejects.toThrow();
    await env.DB.prepare("UPDATE users SET deleted_at=?,status='disabled' WHERE id=?").bind(new Date().toISOString(), scope.userID).run();
    expect((await call("/v1/manage/users/balance-adjust", { ...request, operation_id: "ledger-deleted-" + scope.userID })).status).toBe(404);
    expect((await call("/v1/manage/users/balance-adjust", { ...request, operation_id: "ledger-actor-" + scope.userID, actor_user_id: scope.userID })).status).toBe(403);
  });
  it("preserves single-e8 adjustments and canonicalizes legacy retries", async () => {
    const scope = await createScope("ledger-e8-" + id());
    const adminID = id();
    expect((await call("/v1/manage/users/create", userCreateBody(
      "ledger-e8-admin-" + adminID,
      adminID,
      "ledger-e8-admin-" + adminID + "@example.test",
    ))).status).toBe(200);
    await env.DB.prepare("UPDATE users SET role='admin' WHERE id=?").bind(adminID).run();

    const compatibleOperation = "ledger-e8-compatible-" + scope.userID;
    const exact = await call("/v1/manage/users/balance-adjust", {
      operation_id: compatibleOperation,
      actor_user_id: adminID,
      target_user_id: scope.userID,
      operation: "add",
      amount_e8_usd: "100",
      reason: "canonical retry",
    });
    expect(exact.status).toBe(200);
    expect(await exact.json()).toMatchObject({
      replayed: false,
      balance: {
        delta_e8_usd: "100",
        balance_before_e8_usd: "100",
        balance_after_e8_usd: "200",
      },
    });
    const legacyReplay = await call("/v1/manage/users/balance-adjust", {
      operation_id: compatibleOperation,
      actor_user_id: adminID,
      target_user_id: scope.userID,
      operation: "add",
      amount_microusd: "1",
      reason: "canonical retry",
    });
    expect(legacyReplay.status).toBe(200);
    expect(await legacyReplay.json()).toMatchObject({ replayed: true });

    const oneE8Operation = "ledger-e8-one-" + scope.userID;
    const oneE8 = await call("/v1/manage/users/balance-adjust", {
      operation_id: oneE8Operation,
      actor_user_id: adminID,
      target_user_id: scope.userID,
      operation: "add",
      amount_e8_usd: "1",
      reason: "one e8",
    });
    expect(oneE8.status).toBe(200);
    const oneE8Body = await oneE8.json<{ balance: Record<string, unknown> }>();
    expect(oneE8Body.balance).toMatchObject({
      delta_e8_usd: "1",
      balance_before_e8_usd: "200",
      balance_after_e8_usd: "201",
    });
    expect(oneE8Body.balance).not.toHaveProperty("delta_microusd");
    expect(await env.DB.prepare(
      "SELECT delta_e8_usd,balance_after_e8_usd FROM balance_ledger WHERE operation_id=?",
    ).bind(oneE8Operation).first()).toMatchObject({
      delta_e8_usd: "1",
      balance_after_e8_usd: "201",
    });
    const zeroOperation = "ledger-e8-zero-" + scope.userID;
    expect((await call("/v1/manage/users/balance-adjust", {
      operation_id: zeroOperation,
      actor_user_id: adminID,
      target_user_id: scope.userID,
      operation: "add",
      amount_e8_usd: "0",
      reason: "zero",
    })).status).toBe(400);
    expect(await env.DB.prepare(
      "SELECT count(*) AS count FROM management_operations WHERE operation_id=?",
    ).bind(zeroOperation).first<number>("count")).toBe(0);
  });
  it("leaves no operation or ledger when the guarded projection update is stale", async () => {
    const scope = await createScope("ledger-stale-" + id());
    const adminID = id();
    expect((await call("/v1/manage/users/create", userCreateBody("ledger-stale-admin-" + adminID, adminID, "ledger-stale-admin-" + adminID + "@example.test"))).status).toBe(200);
    await env.DB.prepare("UPDATE users SET role='admin' WHERE id=?").bind(adminID).run();
    const operation = "ledger-stale-" + scope.userID;
    const stamp = new Date().toISOString();
    const results = await env.DB.batch([
      env.DB.prepare("UPDATE users SET balance_e8_usd=?,updated_at=? WHERE id=? AND deleted_at IS NULL AND balance_e8_usd=? AND EXISTS(SELECT 1 FROM users AS actor WHERE actor.id=? AND actor.deleted_at IS NULL AND actor.status='active' AND actor.role='admin')").bind("200", stamp, scope.userID, "99900", adminID),
      env.DB.prepare("INSERT INTO management_operations(operation_id,route,request_hash,response_json,created_at) SELECT ?,?,?,?,? WHERE changes()=1").bind(operation, "/v1/manage/users/balance-adjust", "a".repeat(64), "{\"balance\":{}}", stamp),
      env.DB.prepare("INSERT INTO balance_ledger(id,operation_id,actor_user_id,target_user_id,adjustment_type,reason,delta_e8_usd,balance_before_e8_usd,balance_after_e8_usd,created_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM management_operations WHERE operation_id=?)").bind(operation, operation, adminID, scope.userID, "add", "stale", "100", "100", "200", stamp, operation),
    ]);
    expect(results[0].meta.changes).toBe(0);
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id=?").bind(operation).first("count")).toBe(0);
    expect(await env.DB.prepare("SELECT count(*) count FROM balance_ledger WHERE operation_id=?").bind(operation).first("count")).toBe(0);
    expect(await env.DB.prepare("SELECT balance_e8_usd FROM users WHERE id=?").bind(scope.userID).first("balance_e8_usd")).toBe("100");
  });
  it("rejects noncanonical ledger decimals at the migration boundary", async () => {
    const insertLedger = (
      tag: string,
      delta: string,
      before: string,
      after: string,
      actor = "1",
      target = "2",
    ) => env.DB.prepare(
      "INSERT INTO balance_ledger(id,operation_id,actor_user_id,target_user_id,adjustment_type,reason,delta_e8_usd,balance_before_e8_usd,balance_after_e8_usd,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
    ).bind(tag, tag, actor, target, "set", "migration constraint", delta, before, after, new Date().toISOString()).run();

    const prefix = "ledger-canonical-" + id();
    await expect(insertLedger(prefix + "-positive", "1", "0", "1")).resolves.toBeDefined();
    await expect(insertLedger(prefix + "-negative", "-1", "1", "0")).resolves.toBeDefined();
    await expect(insertLedger(prefix + "-zero", "0", "1", "1")).resolves.toBeDefined();
    await expect(insertLedger(prefix + "-leading-delta", "01", "0", "1")).rejects.toThrow();
    await expect(insertLedger(prefix + "-suffix-delta", "12abc", "0", "1")).rejects.toThrow();
    await expect(insertLedger(prefix + "-negative-suffix", "-12abc", "12", "0")).rejects.toThrow();
    await expect(insertLedger(prefix + "-leading-before", "1", "01", "1")).rejects.toThrow();
    await expect(insertLedger(prefix + "-suffix-after", "1", "0", "1abc")).rejects.toThrow();
    await expect(insertLedger(prefix + "-leading-actor", "1", "0", "1", "01", "2")).rejects.toThrow();
    await expect(insertLedger(prefix + "-suffix-target", "1", "0", "1", "1", "2abc")).rejects.toThrow();
    expect(await env.DB.prepare("SELECT count(*) count FROM balance_ledger WHERE id LIKE ?").bind(prefix + "%").first("count")).toBe(3);
  });
  it("revalidates the actor in the guarded statement and resolves a demotion race as forbidden", async () => {
    const scope = await createScope("ledger-actor-race-" + id());
    const adminID = id();
    expect((await call("/v1/manage/users/create", userCreateBody("ledger-actor-race-admin-" + adminID, adminID, "ledger-actor-race-admin-" + adminID + "@example.test"))).status).toBe(200);
    await env.DB.prepare("UPDATE users SET role='admin' WHERE id=?").bind(adminID).run();

    await env.DB.prepare("UPDATE users SET role='user' WHERE id=?").bind(adminID).run();
    const directOperation = "ledger-actor-guard-" + scope.userID;
    const stamp = new Date().toISOString();
    const guarded = await env.DB.batch([
      env.DB.prepare("UPDATE users SET balance_e8_usd=?,updated_at=? WHERE id=? AND deleted_at IS NULL AND balance_e8_usd=? AND EXISTS(SELECT 1 FROM users AS actor WHERE actor.id=? AND actor.deleted_at IS NULL AND actor.status='active' AND actor.role='admin')").bind("200", stamp, scope.userID, "100", adminID),
      env.DB.prepare("INSERT INTO management_operations(operation_id,route,request_hash,response_json,created_at) SELECT ?,?,?,?,? WHERE changes()=1").bind(directOperation, "/v1/manage/users/balance-adjust", "b".repeat(64), "{\"balance\":{}}", stamp),
      env.DB.prepare("INSERT INTO balance_ledger(id,operation_id,actor_user_id,target_user_id,adjustment_type,reason,delta_e8_usd,balance_before_e8_usd,balance_after_e8_usd,created_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM management_operations WHERE operation_id=?)").bind(directOperation, directOperation, adminID, scope.userID, "add", "actor guard", "100", "100", "200", stamp, directOperation),
    ]);
    expect(guarded[0].meta.changes).toBe(0);
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id=?").bind(directOperation).first("count")).toBe(0);
    expect(await env.DB.prepare("SELECT count(*) count FROM balance_ledger WHERE operation_id=?").bind(directOperation).first("count")).toBe(0);
    expect(await env.DB.prepare("SELECT balance_e8_usd FROM users WHERE id=?").bind(scope.userID).first("balance_e8_usd")).toBe("100");

    await env.DB.prepare("UPDATE users SET role='admin' WHERE id=?").bind(adminID).run();
    const trigger = "balance_actor_race_" + scope.userID;
    const racedOperation = "ledger-actor-raced-" + scope.userID;
    await env.DB.prepare(`CREATE TRIGGER ${trigger} BEFORE UPDATE OF balance_e8_usd ON users WHEN OLD.id='${scope.userID}' BEGIN UPDATE users SET role='user' WHERE id='${adminID}'; SELECT RAISE(IGNORE); END`).run();
    try {
      const raced = await call("/v1/manage/users/balance-adjust", { operation_id: racedOperation, actor_user_id: adminID, target_user_id: scope.userID, operation: "add", amount_microusd: "1", reason: "race" });
      expect(raced.status).toBe(403);
      expect(await raced.json()).toMatchObject({ error: { code: "ACTOR_FORBIDDEN" } });
      expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id=?").bind(racedOperation).first("count")).toBe(0);
      expect(await env.DB.prepare("SELECT count(*) count FROM balance_ledger WHERE operation_id=?").bind(racedOperation).first("count")).toBe(0);
      expect(await env.DB.prepare("SELECT balance_e8_usd FROM users WHERE id=?").bind(scope.userID).first("balance_e8_usd")).toBe("100");
    } finally {
      await env.DB.prepare(`DROP TRIGGER IF EXISTS ${trigger}`).run();
    }
  });
  it("backfills Stage B timestamps on the fresh migration chain", async () => {
    await applyD1Migrations(env.DB, testEnv.TEST_MIGRATIONS);
    expect(await env.DB.prepare("SELECT count(*) count FROM pragma_table_info('users') WHERE name='updated_at'").first("count")).toBe(1);
    expect((await env.DB.prepare("PRAGMA foreign_key_check").all()).results).toEqual([]);
  });

  it("encrypts Worker-managed credentials and excludes secrets from operation responses", async () => {
    const scope = await createScope("credentials"); const rawKey = "WorkerManagedKey_123456"; const upstreamKey = "upstream-secret-" + id(); const baseURL = "https://mock.upstream";
    expect((await call("/v1/manage/api-keys/create", { operation_id: "credentials-key", id: scope.keyID, user_id: scope.userID, group_id: scope.groupID, name: "key", status: "active", raw_key: rawKey, ip_whitelist: [], ip_blacklist: [], expires_at: null })).status).toBe(200);
    const accountCreateRequest = { operation_id: "credentials-account", id: scope.accountID, name: "account", platform: "openai", status: "active", schedulable: true, priority: 2, max_concurrency: 1, credentials: { api_key: upstreamKey, base_url: baseURL }, extra: { privacy_mode: "training_off" }, group_ids: [scope.groupID] };
    const accountCreate = await call("/v1/manage/accounts/create", accountCreateRequest);
    expect(accountCreate.status).toBe(200);
    const accountCreateRead = await accountCreate.json<{ account: { extra: Record<string, unknown> } }>();
    expect(accountCreateRead.account.extra).toEqual({ privacy_mode: "training_off" });
    expect((await call("/v1/manage/accounts/create", { ...accountCreateRequest, operation_id: "credentials-extra-rejected", id: id(), extra: { api_key: upstreamKey } })).status).toBe(400);
    const legacySecret = "legacy-operation-secret-" + id();
    await env.DB.prepare("UPDATE management_operations SET response_json=? WHERE operation_id='credentials-account'").bind(JSON.stringify({ secret: legacySecret, account: { ...accountCreateRead.account, credentials: { api_key: legacySecret }, credential_envelope: legacySecret, extra: { privacy_mode: "training_off", api_key: legacySecret } } })).run();
    const accountCreateReplay = await call("/v1/manage/accounts/create", accountCreateRequest);
    expect(accountCreateReplay.status).toBe(200);
    const accountCreateReplayRead = await accountCreateReplay.json<{ account: { extra: Record<string, unknown> } }>();
    expect(accountCreateReplayRead.account.extra).toEqual({ privacy_mode: "training_off" });
    expect(JSON.stringify(accountCreateReplayRead)).not.toContain(legacySecret);
    await env.DB.prepare("UPDATE management_operations SET response_json=? WHERE operation_id='credentials-account'").bind(JSON.stringify(accountCreateRead)).run();
    const accountGet = await call("/v1/manage/accounts/get", { id: scope.accountID });
    expect(accountGet.status).toBe(200);
    const accountRead = await accountGet.json<Record<string, unknown>>();
    expect(accountRead).toMatchObject({ account: { id: scope.accountID, type: "apikey", extra: { privacy_mode: "training_off" }, group_ids: [scope.groupID] } });
    expect(JSON.stringify(accountRead)).not.toContain(upstreamKey);
    expect(JSON.stringify(accountRead)).not.toContain(baseURL);
    expect(JSON.stringify(accountRead)).not.toContain("credential_envelope");
    const accountList = await call("/v1/manage/accounts/list", { cursor: "0", limit: 1 });
    expect(accountList.status).toBe(200);
    const accountListRead = await accountList.json<Record<string, unknown>>();
    expect(JSON.stringify(accountListRead)).not.toContain(upstreamKey);
    expect(JSON.stringify(accountListRead)).not.toContain(baseURL);
    expect(JSON.stringify(accountListRead)).not.toContain("credential_envelope");
    const encrypted = await env.DB.prepare("SELECT credential_envelope FROM accounts WHERE id=?").bind(scope.accountID).first("credential_envelope") as string;
    expect(encrypted).toMatch(/^aes-gcm:v1:/); expect(encrypted).not.toContain(upstreamKey); expect(encrypted).not.toContain(baseURL);
    const admission = await call("/v1/requests/admit", { request_id: "managed-admission-" + id(), api_key_id: scope.keyID, group_id: scope.groupID, model: "fixture-model", lease_ttl_seconds: 30 });
    expect(admission.status).toBe(200); expect(await admission.json()).toMatchObject({ account: { id: scope.accountID, credentials: { api_key: upstreamKey, base_url: baseURL } } });
    const rows = await env.DB.prepare("SELECT response_json FROM management_operations").all<{ response_json: string }>();
    for (const row of rows.results) { expect(row.response_json).not.toContain("password-hash-for-credentials"); expect(row.response_json).not.toContain("test-only-cloudflare-jwt-secret-32-bytes"); expect(row.response_json).not.toContain(rawKey); expect(row.response_json).not.toContain(upstreamKey); expect(row.response_json).not.toContain(baseURL); }
    expect((await call("/v1/manage/accounts/create", { operation_id: "no-secret", id: id(), name: "bad", platform: "openai", status: "active", schedulable: true, priority: 1, max_concurrency: 1, credentials: { api_key: "x", base_url: baseURL }, extra: {}, group_ids: [scope.groupID] }, undefined, missingCredentialKeyEnv)).status).toBe(400);
    expect((await call("/v1/manage/accounts/delete", { operation_id: "delete-account-read", id: scope.accountID })).status).toBe(200);
    const tombstoneGet = await call("/v1/manage/accounts/get", { id: scope.accountID });
    expect(tombstoneGet.status).toBe(200);
    const tombstoneRead = await tombstoneGet.json<{ account: { deleted_at: string | null; status: string } }>();
    expect(tombstoneRead.account.status).toBe("disabled");
    expect(tombstoneRead.account.deleted_at).not.toBeNull();
    expect(JSON.stringify(tombstoneRead)).not.toContain(upstreamKey);
    const tombstoneList = await call("/v1/manage/accounts/list", { cursor: "0", limit: 1 });
    expect(tombstoneList.status).toBe(200);
    const tombstoneListRead = JSON.stringify(await tombstoneList.json());
    expect(tombstoneListRead).not.toContain(upstreamKey);
    expect(tombstoneListRead).not.toContain(baseURL);
    expect(tombstoneListRead).not.toContain("credential_envelope");
    const tombstoneAdmission = await call("/v1/requests/admit", { request_id: "tombstone-admission-" + id(), api_key_id: scope.keyID, group_id: scope.groupID, model: "fixture-model", lease_ttl_seconds: 30 });
    expect(tombstoneAdmission.status).toBe(429);
  });

  it("replays semantic account creates across disposable IDs and conflicts on changed intent", async () => {
    const scope = await createScope("account-replay-" + id());
    const secondGroupID = id();
    expect((await call("/v1/manage/groups/create", {
      operation_id: "account-replay-second-group-" + secondGroupID,
      id: secondGroupID,
      name: "account replay second group " + secondGroupID,
      platform: "openai",
      status: "active",
      is_exclusive: false,
      subscription_type: "standard",
    })).status).toBe(200);
    const ascendingGroupIDs = [scope.groupID, secondGroupID].sort();
    const retryID = id();
    const operationID = "browser-account-" + id();
    const upstreamKey = "semantic-upstream-" + id();
    const baseURL = "https://mock.upstream";
    const createRequest = {
      operation_id: operationID,
      id: scope.accountID,
      name: "semantic account",
      platform: "openai",
      status: "active",
      schedulable: true,
      priority: 4,
      max_concurrency: 2,
      credentials: { api_key: upstreamKey, base_url: baseURL },
      extra: { privacy_mode: "training_off" },
      group_ids: [...ascendingGroupIDs].reverse(),
    };

    const createdResponse = await call("/v1/manage/accounts/create", createRequest);
    expect(createdResponse.status).toBe(200);
    const createdText = await createdResponse.text();
    expect(createdText).not.toContain(upstreamKey);
    expect(createdText).not.toContain(baseURL);
    expect(JSON.parse(createdText)).toMatchObject({ account: { id: scope.accountID }, replayed: false });

    const replayResponse = await call("/v1/manage/accounts/create", {
      ...createRequest,
      id: retryID,
      group_ids: ascendingGroupIDs,
    });
    expect(replayResponse.status).toBe(200);
    const replayText = await replayResponse.text();
    expect(replayText).not.toContain(upstreamKey);
    expect(replayText).not.toContain(baseURL);
    expect(JSON.parse(replayText)).toMatchObject({ account: { id: scope.accountID }, replayed: true });
    expect(await env.DB.prepare("SELECT count(*) count FROM accounts WHERE id=?").bind(retryID).first("count")).toBe(0);
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id=?").bind(operationID).first("count")).toBe(1);

    const operation = await env.DB.prepare(
      "SELECT request_hash,response_json FROM management_operations WHERE operation_id=?",
    ).bind(operationID).first<{ request_hash: string; response_json: string }>();
    expect(operation?.request_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(operation?.response_json).not.toContain(upstreamKey);
    expect(operation?.response_json).not.toContain(baseURL);
    expect(operation?.response_json).not.toContain("credential_digest");

    const changedPayload = await call("/v1/manage/accounts/create", {
      ...createRequest,
      id: retryID,
      priority: 5,
    });
    expect(changedPayload.status).toBe(409);
    expect(await changedPayload.json()).toMatchObject({ error: { code: "IDEMPOTENCY_CONFLICT" } });
    const changedCredential = await call("/v1/manage/accounts/create", {
      ...createRequest,
      id: retryID,
      credentials: { api_key: upstreamKey + "-changed", base_url: baseURL },
    });
    expect(changedCredential.status).toBe(409);
    expect(await changedCredential.json()).toMatchObject({ error: { code: "IDEMPOTENCY_CONFLICT" } });
  });

  it("uses JavaScript UTF-16 length and exact trimming for account names", async () => {
    const scope = await createScope("account-name-" + id());
    const requestBody = {
      operation_id: "account-name-valid-" + scope.accountID,
      id: scope.accountID,
      name: "😀".repeat(50),
      platform: "openai",
      status: "active",
      schedulable: true,
      priority: 0,
      max_concurrency: 1,
      credentials: { api_key: "account-name-secret-" + id(), base_url: "https://mock.upstream" },
      extra: {},
      group_ids: [scope.groupID],
    };
    expect((await call("/v1/manage/accounts/create", requestBody)).status).toBe(200);
    expect((await call("/v1/manage/accounts/create", {
      ...requestBody,
      operation_id: "account-name-long-" + scope.accountID,
      id: id(),
      name: "😀".repeat(51),
    })).status).toBe(400);
    expect((await call("/v1/manage/accounts/create", {
      ...requestBody,
      operation_id: "account-name-padded-" + scope.accountID,
      id: id(),
      name: " padded ",
    })).status).toBe(400);
  });

  it("preserves omitted account credentials, encrypts replacements, and rolls back invalid groups", async () => {
    const scope = await createScope("account-update-" + id());
    const rawKey = "AccountUpdateKey_" + id();
    const firstSecret = "first-account-secret-" + id();
    const replacementSecret = "replacement-account-secret-" + id();
    expect((await call("/v1/manage/api-keys/create", {
      operation_id: "account-update-key-" + scope.keyID,
      id: scope.keyID,
      user_id: scope.userID,
      group_id: scope.groupID,
      name: "account update key",
      status: "active",
      raw_key: rawKey,
      ip_whitelist: [],
      ip_blacklist: [],
      expires_at: null,
    })).status).toBe(200);
    expect((await call("/v1/manage/accounts/create", {
      operation_id: "account-update-create-" + scope.accountID,
      id: scope.accountID,
      name: "before update",
      platform: "openai",
      status: "active",
      schedulable: true,
      priority: 2,
      max_concurrency: 1,
      credentials: { api_key: firstSecret, base_url: "https://mock.upstream" },
      extra: {},
      group_ids: [scope.groupID],
    })).status).toBe(200);
    const originalEnvelope = await env.DB.prepare(
      "SELECT credential_envelope FROM accounts WHERE id=?",
    ).bind(scope.accountID).first("credential_envelope") as string;

    const omitted = await call("/v1/manage/accounts/update", {
      operation_id: "account-update-omitted-" + scope.accountID,
      id: scope.accountID,
      name: "credentials preserved",
    });
    expect(omitted.status).toBe(200);
    expect(await env.DB.prepare("SELECT credential_envelope FROM accounts WHERE id=?").bind(scope.accountID).first("credential_envelope")).toBe(originalEnvelope);

    const replaced = await call("/v1/manage/accounts/update", {
      operation_id: "account-update-replaced-" + scope.accountID,
      id: scope.accountID,
      credentials: { api_key: replacementSecret, base_url: "https://mock.upstream" },
    });
    expect(replaced.status).toBe(200);
    const replacedText = await replaced.text();
    expect(replacedText).not.toContain(firstSecret);
    expect(replacedText).not.toContain(replacementSecret);
    const replacementEnvelope = await env.DB.prepare(
      "SELECT credential_envelope FROM accounts WHERE id=?",
    ).bind(scope.accountID).first("credential_envelope") as string;
    expect(replacementEnvelope).toMatch(/^aes-gcm:v1:/);
    expect(replacementEnvelope).not.toBe(originalEnvelope);
    expect(replacementEnvelope).not.toContain(replacementSecret);

    const admission = await call("/v1/requests/admit", {
      request_id: "replacement-admission-" + id(),
      api_key_id: scope.keyID,
      group_id: scope.groupID,
      model: "fixture-model",
      lease_ttl_seconds: 30,
    });
    expect(admission.status).toBe(200);
    expect(await admission.json()).toMatchObject({
      account: { id: scope.accountID, credentials: { api_key: replacementSecret, base_url: "https://mock.upstream" } },
    });

    const missingGroupID = id();
    const invalidOperation = "account-update-invalid-group-" + scope.accountID;
    const invalidGroup = await call("/v1/manage/accounts/update", {
      operation_id: invalidOperation,
      id: scope.accountID,
      group_ids: [missingGroupID],
    });
    expect(invalidGroup.status).toBe(409);
    expect(await invalidGroup.json()).toMatchObject({ error: { code: "REFERENCE_REJECTED" } });
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id=?").bind(invalidOperation).first("count")).toBe(0);
    expect(await env.DB.prepare("SELECT count(*) count FROM account_groups WHERE account_id=? AND group_id=?").bind(scope.accountID, scope.groupID).first("count")).toBe(1);
    expect(await env.DB.prepare("SELECT count(*) count FROM account_groups WHERE account_id=? AND group_id=?").bind(scope.accountID, missingGroupID).first("count")).toBe(0);

    const operationRows = await env.DB.prepare(
      "SELECT response_json FROM management_operations WHERE operation_id IN (?,?)",
    ).bind("account-update-omitted-" + scope.accountID, "account-update-replaced-" + scope.accountID).all<{ response_json: string }>();
    for (const row of operationRows.results) {
      expect(row.response_json).not.toContain(firstSecret);
      expect(row.response_json).not.toContain(replacementSecret);
      expect(row.response_json).not.toContain("mock.upstream");
    }
  });

  it("makes tombstones terminal and owner-scoped revoke atomically releases the credential hash", async () => {
    const scope = await createScope("tombstone"); const rawKey = "ReusableKey_123456";
    expect((await call("/v1/manage/api-keys/create", { operation_id: "tombstone-key", id: scope.keyID, user_id: scope.userID, group_id: scope.groupID, name: "key", status: "active", raw_key: rawKey, ip_whitelist: [], ip_blacklist: [], expires_at: null })).status).toBe(200);
    const oldHash = await env.DB.prepare("SELECT key_hash FROM api_keys WHERE id=?").bind(scope.keyID).first("key_hash");
    expect((await call("/v1/manage/api-keys/revoke", { operation_id: "wrong-owner", id: scope.keyID, expected_user_id: "999" })).status).toBe(404);
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id='wrong-owner'").first("count")).toBe(0);
    expect((await call("/v1/manage/api-keys/revoke", { operation_id: "revoke", id: scope.keyID, expected_user_id: scope.userID })).status).toBe(200);
    const tombstone = await env.DB.prepare("SELECT key_hash,deleted_at FROM api_keys WHERE id=?").bind(scope.keyID).first<{ key_hash: string; deleted_at: string }>();
    expect(tombstone?.key_hash).not.toBe(oldHash); expect((await call("/v1/auth/resolve", { key: rawKey })).status).toBe(404);
    expect((await call("/v1/manage/api-keys/revoke", { operation_id: "revoke", id: scope.keyID, expected_user_id: scope.userID })).status).toBe(200);
    expect((await call("/v1/manage/api-keys/revoke", { operation_id: "revoke", id: scope.keyID, expected_user_id: "999" })).status).toBe(409);
    expect((await call("/v1/manage/api-keys/revoke", { operation_id: "fresh-revoke", id: scope.keyID, expected_user_id: scope.userID })).status).toBe(200);
    expect(await env.DB.prepare("SELECT deleted_at FROM api_keys WHERE id=?").bind(scope.keyID).first("deleted_at")).toBe(tombstone?.deleted_at);
    expect((await call("/v1/manage/api-keys/rotate", { operation_id: "rotate-tombstone", id: scope.keyID, raw_key: "NoRestoreKey_123456" })).status).toBe(409);
    expect((await call("/v1/manage/api-keys/create", { operation_id: "reuse-key", id: id(), user_id: scope.userID, group_id: scope.groupID, name: "reused", status: "active", raw_key: rawKey, ip_whitelist: [], ip_blacklist: [], expires_at: null })).status).toBe(200);
    expect((await call("/v1/manage/users/delete", { operation_id: "delete-user", id: scope.userID })).status).toBe(200);
    expect((await call("/v1/manage/users/update", { operation_id: "restore-user", id: scope.userID, status: "active" })).status).toBe(409);
    expect((await call("/v1/manage/groups/delete", { operation_id: "delete-group", id: scope.groupID })).status).toBe(200);
    expect((await call("/v1/manage/groups/update", { operation_id: "restore-group", id: scope.groupID, status: "active" })).status).toBe(409);
  });

  it("replays stable operation IDs and rejects conflicting reuse after tombstones", async () => {
    const scope = await createScope("replay"); const rawKey = "ReplayKey_123456789";
    const keyRequest = { operation_id: "replay-key", id: scope.keyID, user_id: scope.userID, group_id: scope.groupID, name: "key", status: "active", raw_key: rawKey, ip_whitelist: [], ip_blacklist: [], expires_at: null };
    const created = await (await call("/v1/manage/api-keys/create", keyRequest)).json<Record<string, unknown>>();
    expect(created).toMatchObject({ api_key: { id: scope.keyID } }); expect(created).not.toHaveProperty("raw_key");
    const replay = await (await call("/v1/manage/api-keys/create", keyRequest)).json<Record<string, unknown>>();
    expect(replay).toMatchObject({ api_key: { id: scope.keyID } }); expect(replay).not.toHaveProperty("raw_key");
    expect((await call("/v1/manage/api-keys/create", { ...keyRequest, name: "different" })).status).toBe(409);
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id='replay-key'").first("count")).toBe(1);

    expect((await call("/v1/manage/users/delete", { operation_id: "delete-user-first", id: scope.userID })).status).toBe(200);
    const deletedAt = await env.DB.prepare("SELECT deleted_at FROM users WHERE id=?").bind(scope.userID).first("deleted_at");
    const terminalRequest = { operation_id: "terminal-noop", id: scope.userID };
    expect((await call("/v1/manage/users/delete", terminalRequest)).status).toBe(200);
    expect((await call("/v1/manage/users/delete", terminalRequest)).status).toBe(200);
    expect(await env.DB.prepare("SELECT deleted_at FROM users WHERE id=?").bind(scope.userID).first("deleted_at")).toBe(deletedAt);
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id='terminal-noop'").first("count")).toBe(1);

    expect((await call("/v1/manage/groups/delete", { operation_id: "delete-group-first", id: scope.groupID })).status).toBe(200);
    expect((await call("/v1/manage/groups/delete", { operation_id: "terminal-noop", id: scope.groupID })).status).toBe(409);
  });

  it("replays browser group creates across candidate IDs and enforces live-name uniqueness", async () => {
    const operationID = "browser-group-" + id();
    const firstID = id();
    const retryID = id();
    const name = "browser-" + id();
    const createRequest = {
      operation_id: operationID,
      id: firstID,
      name,
      platform: "openai",
      status: "active",
      is_exclusive: false,
      subscription_type: "standard",
    };

    const createdResponse = await call("/v1/manage/groups/create", createRequest);
    expect(createdResponse.status).toBe(200);
    const created = await createdResponse.json<{ group: { id: string }; replayed: boolean }>();
    expect(created).toMatchObject({ group: { id: firstID }, replayed: false });

    const replayResponse = await call("/v1/manage/groups/create", { ...createRequest, id: retryID });
    expect(replayResponse.status).toBe(200);
    const replay = await replayResponse.json<{ group: { id: string }; replayed: boolean }>();
    expect(replay).toMatchObject({ group: { id: firstID }, replayed: true });
    expect(await env.DB.prepare("SELECT count(*) count FROM groups WHERE id=?").bind(retryID).first("count")).toBe(0);

    expect((await call("/v1/manage/groups/create", { ...createRequest, id: retryID, name: name + "-changed" })).status).toBe(409);
    expect((await call("/v1/manage/groups/create", { ...createRequest, operation_id: operationID + "-duplicate", id: retryID })).status).toBe(409);

    expect((await call("/v1/manage/groups/delete", { operation_id: operationID + "-delete", id: firstID })).status).toBe(200);
    expect((await call("/v1/manage/groups/create", { ...createRequest, operation_id: operationID + "-recreate", id: retryID })).status).toBe(200);
  });

  it("replays user creates across disposable IDs and never persists credential material in operation rows", async () => {
    const operationID = "browser-user-" + id();
    const firstID = id();
    const retryID = id();
    const email = "browser-user-" + id() + "@example.test";
    const firstHash = "bcrypt-compatible-test-hash-first";
    const retryHash = "bcrypt-compatible-test-hash-retry";
    const createRequest = userCreateBody(operationID, firstID, email, {
      password_hash: firstHash,
      semantic_digest: "d".repeat(64),
      balance_microusd: "1000001",
    });

    const createdResponse = await call("/v1/manage/users/create", createRequest);
    expect(createdResponse.status).toBe(200);
    const createdText = await createdResponse.text();
    expect(createdText).not.toContain(firstHash);
    expect(createdText).not.toContain("semantic_digest");
    expect(JSON.parse(createdText)).toMatchObject({ user: { id: firstID }, replayed: false });

    const replayResponse = await call("/v1/manage/users/create", {
      ...createRequest,
      id: retryID,
      password_hash: retryHash,
    });
    expect(replayResponse.status).toBe(200);
    const replayText = await replayResponse.text();
    expect(replayText).not.toContain(firstHash);
    expect(replayText).not.toContain(retryHash);
    expect(JSON.parse(replayText)).toMatchObject({ user: { id: firstID }, replayed: true });
    expect(await env.DB.prepare("SELECT count(*) count FROM users WHERE id=?").bind(retryID).first("count")).toBe(0);

    const operation = await env.DB.prepare(
      "SELECT request_hash,response_json FROM management_operations WHERE operation_id=?",
    ).bind(operationID).first<{ request_hash: string; response_json: string }>();
    expect(operation?.request_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(operation?.response_json).not.toContain(firstHash);
    expect(operation?.response_json).not.toContain(retryHash);
    expect(operation?.response_json).not.toContain("semantic_digest");

    const authRead = await call("/v1/private/auth-users/get", { id: firstID });
    expect(authRead.status).toBe(200);
    expect(await authRead.json()).toMatchObject({ user: { id: firstID, password_hash: firstHash } });

    expect((await call("/v1/manage/users/create", {
      ...createRequest,
      id: retryID,
      email: "changed-" + email,
      password_hash: retryHash,
    })).status).toBe(409);
    const changedSecret = await call("/v1/manage/users/create", {
      ...createRequest,
      id: retryID,
      password_hash: retryHash,
      semantic_digest: "e".repeat(64),
    });
    expect(changedSecret.status).toBe(409);
    expect(await changedSecret.json()).toMatchObject({ error: { code: "IDEMPOTENCY_CONFLICT" } });
  });

  it("uses normalized live email identity and permits reuse only after the prior user is deleted", async () => {
    const suffix = id();
    const firstID = id();
    const secondID = id();
    const mixedCaseEmail = "Case-" + suffix + "@Example.Test";
    expect((await call("/v1/manage/users/create", userCreateBody("email-first-" + suffix, firstID, mixedCaseEmail))).status).toBe(200);

    const duplicate = await call(
      "/v1/manage/users/create",
      userCreateBody("email-duplicate-" + suffix, secondID, mixedCaseEmail.toLowerCase()),
    );
    expect(duplicate.status).toBe(409);
    expect(await duplicate.json()).toMatchObject({ error: { code: "EMAIL_EXISTS" } });
    expect(await env.DB.prepare("SELECT count(*) count FROM users WHERE id=?").bind(secondID).first("count")).toBe(0);

    expect((await call("/v1/manage/users/delete", { operation_id: "email-delete-" + suffix, id: firstID })).status).toBe(200);
    expect((await call(
      "/v1/manage/users/create",
      userCreateBody("email-reuse-" + suffix, secondID, mixedCaseEmail.toLowerCase()),
    )).status).toBe(200);
  });

  it("patches only submitted user fields and validates group references only when supplied", async () => {
    const scope = await createScope("user-patch-" + id());
    const historicalGroup = id();
    expect((await call("/v1/manage/groups/create", {
      operation_id: "historical-group-" + historicalGroup,
      id: historicalGroup,
      name: "historical-" + historicalGroup,
      platform: "openai",
      status: "disabled",
      is_exclusive: true,
      subscription_type: "standard",
    })).status).toBe(200);
    expect((await call("/v1/manage/users/update", {
      operation_id: "historical-assign-" + scope.userID,
      id: scope.userID,
      allowed_group_ids: [historicalGroup],
    })).status).toBe(200);
    await env.DB.prepare("UPDATE groups SET deleted_at=? WHERE id=?").bind(new Date().toISOString(), historicalGroup).run();
    await env.DB.prepare("UPDATE users SET balance_e8_usd='765432100' WHERE id=?").bind(scope.userID).run();

    const notesUpdate = await call("/v1/manage/users/update", {
      operation_id: "notes-only-" + scope.userID,
      id: scope.userID,
      notes: "preserve unrelated state",
    });
    expect(notesUpdate.status).toBe(200);
    const stored = await env.DB.prepare(
      "SELECT notes,role,balance_e8_usd,allowed_group_ids_json FROM users WHERE id=?",
    ).bind(scope.userID).first<{ notes: string; role: string; balance_e8_usd: string; allowed_group_ids_json: string }>();
    expect(stored).toEqual({
      notes: "preserve unrelated state",
      role: "user",
      balance_e8_usd: "765432100",
      allowed_group_ids_json: JSON.stringify([historicalGroup]),
    });

    const referenced = await call("/v1/manage/users/update", {
      operation_id: "historical-resubmit-" + scope.userID,
      id: scope.userID,
      allowed_group_ids: [historicalGroup],
    });
    expect(referenced.status).toBe(409);
    expect(await referenced.json()).toMatchObject({ error: { code: "REFERENCE_REJECTED" } });
    expect((await call("/v1/manage/users/update", {
      operation_id: "role-write-" + scope.userID,
      id: scope.userID,
      role: "admin",
    })).status).toBe(400);
    expect((await call("/v1/manage/users/update", {
      operation_id: "balance-write-" + scope.userID,
      id: scope.userID,
      balance_microusd: "1",
    })).status).toBe(400);
  });

  it("atomically protects admins and tombstones every live key only after the user delete succeeds", async () => {
    const scope = await createScope("user-delete-" + id());
    const rawKey = "DeleteUserKey_" + id();
    expect((await call("/v1/manage/api-keys/create", {
      operation_id: "delete-user-key-" + scope.keyID,
      id: scope.keyID,
      user_id: scope.userID,
      group_id: scope.groupID,
      name: "delete with owner",
      status: "active",
      raw_key: rawKey,
      ip_whitelist: [],
      ip_blacklist: [],
      expires_at: null,
    })).status).toBe(200);
    const beforeKey = await env.DB.prepare(
      "SELECT key_hash,status,deleted_at FROM api_keys WHERE id=?",
    ).bind(scope.keyID).first<{ key_hash: string; status: string; deleted_at: string | null }>();

    await env.DB.prepare(
      `CREATE TRIGGER user_delete_ignored_${scope.userID} BEFORE UPDATE ON users WHEN OLD.id='${scope.userID}' AND NEW.deleted_at IS NOT NULL BEGIN SELECT RAISE(IGNORE); END`,
    ).run();
    const ignoredOperation = "ignored-user-delete-" + scope.userID;
    expect((await call("/v1/manage/users/delete", { operation_id: ignoredOperation, id: scope.userID })).status).toBe(409);
    expect(await env.DB.prepare("SELECT deleted_at FROM users WHERE id=?").bind(scope.userID).first("deleted_at")).toBeNull();
    expect(await env.DB.prepare("SELECT key_hash,status,deleted_at FROM api_keys WHERE id=?").bind(scope.keyID).first()).toEqual(beforeKey);
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id=?").bind(ignoredOperation).first("count")).toBe(0);
    await env.DB.prepare(`DROP TRIGGER user_delete_ignored_${scope.userID}`).run();

    await env.DB.prepare("UPDATE users SET role='admin' WHERE id=?").bind(scope.userID).run();
    const protectedResponse = await call("/v1/manage/users/delete", {
      operation_id: "protected-user-delete-" + scope.userID,
      id: scope.userID,
    });
    expect(protectedResponse.status).toBe(409);
    expect(await protectedResponse.json()).toMatchObject({ error: { code: "ROLE_PROTECTED" } });
    expect(await env.DB.prepare("SELECT key_hash FROM api_keys WHERE id=?").bind(scope.keyID).first("key_hash")).toBe(beforeKey?.key_hash);

    const disabledAdmin = await call("/v1/manage/users/update", {
      operation_id: "disable-admin-" + scope.userID,
      id: scope.userID,
      status: "disabled",
    });
    expect(disabledAdmin.status).toBe(409);
    expect(await disabledAdmin.json()).toMatchObject({ error: { code: "ROLE_PROTECTED" } });
    await env.DB.prepare("UPDATE users SET role='user' WHERE id=?").bind(scope.userID).run();

    expect((await call("/v1/manage/users/delete", {
      operation_id: "delete-user-success-" + scope.userID,
      id: scope.userID,
    })).status).toBe(200);
    const afterKey = await env.DB.prepare(
      "SELECT key_hash,status,deleted_at FROM api_keys WHERE id=?",
    ).bind(scope.keyID).first<{ key_hash: string; status: string; deleted_at: string | null }>();
    expect(afterKey?.key_hash).not.toBe(beforeKey?.key_hash);
    expect(afterKey?.status).toBe("disabled");
    expect(afterKey?.deleted_at).not.toBeNull();
    expect((await call("/v1/private/auth-users/get", { id: scope.userID })).status).toBe(404);
    expect((await call("/v1/auth/resolve", { key: rawKey })).status).toBe(404);
  });

  it("uses JavaScript UTF-16 length limits for managed user text", async () => {
    const suffix = id();
    expect((await call("/v1/manage/users/create", userCreateBody(
      "unicode-user-valid-" + suffix,
      id(),
      "unicode-valid-" + suffix + "@example.test",
      { username: "😀".repeat(50) },
    ))).status).toBe(200);
    expect((await call("/v1/manage/users/create", userCreateBody(
      "unicode-user-invalid-" + suffix,
      id(),
      "unicode-invalid-" + suffix + "@example.test",
      { username: "😀".repeat(51) },
    ))).status).toBe(400);
  });

  it("does not change account_groups or record success when the primary account update affects zero rows", async () => {
    const scope = await createScope("zero-primary");
    expect((await call("/v1/manage/accounts/create", { operation_id: "zero-primary-account", id: scope.accountID, name: "account", platform: "openai", status: "active", schedulable: true, priority: 2, max_concurrency: 1, credentials: { api_key: "zero-primary-upstream", base_url: "https://mock.upstream" }, extra: {}, group_ids: [scope.groupID] })).status).toBe(200);
    await env.DB.prepare("CREATE TRIGGER account_update_ignored BEFORE UPDATE ON accounts WHEN NEW.name='ignored-account-update' BEGIN SELECT RAISE(IGNORE); END").run();
    const response = await call("/v1/manage/accounts/update", { operation_id: "zero-primary-update", id: scope.accountID, name: "ignored-account-update", priority: 3, group_ids: ["2001"] });
    expect(response.status).toBe(409);
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id='zero-primary-update'").first("count")).toBe(0);
    expect(await env.DB.prepare("SELECT count(*) count FROM account_groups WHERE account_id=? AND group_id=?").bind(scope.accountID, scope.groupID).first("count")).toBe(1);
    expect(await env.DB.prepare("SELECT count(*) count FROM account_groups WHERE account_id=? AND group_id='2001'").bind(scope.accountID).first("count")).toBe(0);
    await env.DB.prepare("DROP TRIGGER account_update_ignored").run();
  });

  it("rebinds only live standard OpenAI groups and atomically grants an exclusive group", async () => {
    const scope = await createScope("rebind-" + id());
    const exclusiveID = id();
    const subscriptionID = id();
    const rawKey = "RebindKey_" + id();
    expect((await call("/v1/manage/groups/create", {
      operation_id: "exclusive-group-" + exclusiveID, id: exclusiveID, name: "exclusive", platform: "openai",
      status: "active", is_exclusive: true, subscription_type: "standard",
    })).status).toBe(200);
    expect((await call("/v1/manage/groups/create", {
      operation_id: "unsupported-group-" + subscriptionID, id: subscriptionID, name: "unsupported", platform: "openai",
      status: "active", is_exclusive: false, subscription_type: "standard",
    })).status).toBe(200);
    expect((await call("/v1/manage/api-keys/create", {
      operation_id: "rebind-key-" + scope.keyID, id: scope.keyID, user_id: scope.userID, group_id: scope.groupID,
      name: "key", status: "active", raw_key: rawKey, ip_whitelist: [], ip_blacklist: [], expires_at: null,
    })).status).toBe(200);

    // The public group route deliberately does not create unsupported groups,
    // so seed these adversarial rows directly to exercise rebind validation.
    await env.DB.prepare("UPDATE groups SET subscription_type='subscription' WHERE id=?").bind(subscriptionID).run();
    const rejected = await call("/v1/manage/api-keys/rebind-group", { operation_id: "reject-subscription-" + scope.keyID, id: scope.keyID, group_id: subscriptionID });
    expect(rejected.status).toBe(409);
    expect(await rejected.json()).toMatchObject({ error: { code: "REFERENCE_REJECTED" } });
    await env.DB.prepare("UPDATE groups SET platform='anthropic',subscription_type='standard' WHERE id=?").bind(subscriptionID).run();
    expect((await call("/v1/manage/api-keys/rebind-group", { operation_id: "reject-platform-" + scope.keyID, id: scope.keyID, group_id: subscriptionID })).status).toBe(409);
    await env.DB.prepare("UPDATE groups SET platform='openai',status='disabled' WHERE id=?").bind(subscriptionID).run();
    expect((await call("/v1/manage/api-keys/rebind-group", { operation_id: "reject-inactive-group-" + scope.keyID, id: scope.keyID, group_id: subscriptionID })).status).toBe(409);
    await env.DB.prepare("UPDATE groups SET status='active',deleted_at=? WHERE id=?").bind(new Date().toISOString(), subscriptionID).run();
    expect((await call("/v1/manage/api-keys/rebind-group", { operation_id: "reject-deleted-group-" + scope.keyID, id: scope.keyID, group_id: subscriptionID })).status).toBe(409);

    const request = { operation_id: "grant-exclusive-" + scope.keyID, id: scope.keyID, group_id: exclusiveID };
    await env.DB.prepare("UPDATE users SET status='disabled' WHERE id=?").bind(scope.userID).run();
    expect((await call("/v1/manage/api-keys/rebind-group", request)).status).toBe(409);
    await env.DB.prepare("UPDATE users SET status='active' WHERE id=?").bind(scope.userID).run();
    const first = await call("/v1/manage/api-keys/rebind-group", request);
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({
      api_key: { id: scope.keyID, group_id: exclusiveID }, group: { id: exclusiveID, name: "exclusive" },
      auto_granted_group_access: true, granted_group_id: exclusiveID, granted_group_name: "exclusive",
    });
    expect(await env.DB.prepare("SELECT allowed_group_ids_json FROM users WHERE id=?").bind(scope.userID).first("allowed_group_ids_json")).toBe(JSON.stringify([scope.groupID, exclusiveID]));
    expect(await env.DB.prepare("SELECT group_id FROM api_keys WHERE id=?").bind(scope.keyID).first("group_id")).toBe(exclusiveID);
    expect((await call("/v1/manage/api-keys/rebind-group", request)).status).toBe(200);
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id=?").bind(request.operation_id).first("count")).toBe(1);
    expect((await call("/v1/manage/api-keys/rebind-group", { ...request, group_id: scope.groupID })).status).toBe(409);

    const same = await call("/v1/manage/api-keys/rebind-group", { operation_id: "same-group-" + scope.keyID, id: scope.keyID, group_id: exclusiveID });
    expect(same.status).toBe(200);
    expect(await same.json()).toMatchObject({ api_key: { group_id: exclusiveID }, auto_granted_group_access: false });
    await env.DB.prepare("UPDATE api_keys SET status='disabled' WHERE id=?").bind(scope.keyID).run();
    expect((await call("/v1/manage/api-keys/rebind-group", { operation_id: "reject-inactive-key-" + scope.keyID, id: scope.keyID, group_id: scope.groupID })).status).toBe(404);
    await env.DB.prepare("UPDATE api_keys SET status='active' WHERE id=?").bind(scope.keyID).run();

    const secondExclusiveID = id();
    expect((await call("/v1/manage/groups/create", {
      operation_id: "exclusive-group-two-" + secondExclusiveID, id: secondExclusiveID, name: "exclusive-two", platform: "openai",
      status: "active", is_exclusive: true, subscription_type: "standard",
    })).status).toBe(200);
    await env.DB.prepare("CREATE TRIGGER reject_exclusive_grant BEFORE UPDATE ON users WHEN OLD.id='" + scope.userID + "' BEGIN SELECT RAISE(IGNORE); END").run();
    const failed = await call("/v1/manage/api-keys/rebind-group", { operation_id: "atomic-failure-" + scope.keyID, id: scope.keyID, group_id: secondExclusiveID });
    expect(failed.status).toBe(409);
    expect(await env.DB.prepare("SELECT group_id FROM api_keys WHERE id=?").bind(scope.keyID).first("group_id")).toBe(exclusiveID);
    expect(await env.DB.prepare("SELECT allowed_group_ids_json FROM users WHERE id=?").bind(scope.userID).first("allowed_group_ids_json")).toBe(JSON.stringify([scope.groupID, exclusiveID]));
    expect(await env.DB.prepare("SELECT count(*) count FROM management_operations WHERE operation_id=?").bind("atomic-failure-" + scope.keyID).first("count")).toBe(0);
    await env.DB.prepare("DROP TRIGGER reject_exclusive_grant").run();
  });

  it("rejects malformed and unsupported role, platform, and subscription values", async () => {
    expect((await call("/v1/manage/users/list", { limit: 101 })).status).toBe(400);
    expect((await call("/v1/manage/users/create", { operation_id: "bad-role-" + id(), semantic_digest: "b".repeat(64), id: id(), email: "bad-role-" + id() + "@example.test", password_hash: "password-hash-123456789", username: "x", notes: "", status: "active", role: "operator", concurrency: 1, rpm_limit: 0, balance_microusd: "1", allowed_group_ids: [], restrict_public_groups: false })).status).toBe(400);
    for (const [operation, platform, subscription] of [["bad-platform", "anthropic", "standard"], ["bad-subscription", "openai", "subscription"], ["bad-mode", "openai", "payg"]]) expect((await call("/v1/manage/groups/create", { operation_id: operation, id: id(), name: "x", platform, status: "active", is_exclusive: false, subscription_type: subscription })).status).toBe(400);
    expect((await call("/v1/manage/users/get", { id: "1001" }, { host: "public.example" })).status).toBe(404);
  });
});
