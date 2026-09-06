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
  const userResponse = await call("/v1/manage/users/create", { operation_id: operation, id: userID, email: tag + "-" + userID + "@example.test", password_hash: "password-hash-for-" + tag, username: tag, notes: "", status: "active", role: "user", concurrency: 1, rpm_limit: 0, balance_microusd: "1", allowed_group_ids: [], restrict_public_groups: false });
  if (userResponse.status !== 200) throw new Error(await userResponse.text());
  const groupResponse = await call("/v1/manage/groups/create", { operation_id: tag + "-group-" + groupID, id: groupID, name: tag, platform: "openai", status: "active", is_exclusive: false, subscription_type: "standard" });
  if (groupResponse.status !== 200) throw new Error(await groupResponse.text());
  expect((await call("/v1/manage/users/update", { operation_id: tag + "-groups-" + userID, id: userID, allowed_group_ids: [groupID] })).status).toBe(200);
  return { userID, groupID, keyID, accountID };
}

describe("Stage C private management control plane", () => {
  it("backfills Stage B timestamps on the fresh migration chain", async () => {
    await applyD1Migrations(env.DB, testEnv.TEST_MIGRATIONS);
    expect(await env.DB.prepare("SELECT count(*) count FROM pragma_table_info('users') WHERE name='updated_at'").first("count")).toBe(1);
  });

  it("encrypts Worker-managed credentials and excludes secrets from operation responses", async () => {
    const scope = await createScope("credentials"); const rawKey = "WorkerManagedKey_123456"; const upstreamKey = "upstream-secret-" + id(); const baseURL = "https://mock.upstream";
    expect((await call("/v1/manage/api-keys/create", { operation_id: "credentials-key", id: scope.keyID, user_id: scope.userID, group_id: scope.groupID, name: "key", status: "active", raw_key: rawKey, ip_whitelist: [], ip_blacklist: [], expires_at: null })).status).toBe(200);
    const accountCreateRequest = { operation_id: "credentials-account", id: scope.accountID, name: "account", platform: "openai", status: "active", schedulable: true, priority: 2, max_concurrency: 1, credentials: { api_key: upstreamKey, base_url: baseURL }, extra: { privacy_mode: "training_off", api_key: upstreamKey, base_url: baseURL }, group_ids: [scope.groupID] };
    const accountCreate = await call("/v1/manage/accounts/create", accountCreateRequest);
    expect(accountCreate.status).toBe(200);
    const accountCreateRead = await accountCreate.json<{ account: { extra: Record<string, unknown> } }>();
    expect(accountCreateRead.account.extra).toEqual({ privacy_mode: "training_off" });
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
    expect((await call("/v1/manage/accounts/create", { operation_id: "no-secret", id: id(), name: "bad", platform: "openai", status: "active", schedulable: true, priority: 1, max_concurrency: 1, credentials: { api_key: "x", base_url: baseURL }, extra: {}, group_ids: [scope.groupID] }, undefined, env)).status).toBe(400);
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

  it("rejects malformed and unsupported role, platform, and subscription values", async () => {
    expect((await call("/v1/manage/users/list", { limit: 101 })).status).toBe(400);
    expect((await call("/v1/manage/users/create", { operation_id: "bad-role-" + id(), id: id(), email: "bad-role-" + id() + "@example.test", password_hash: "password-hash-123456789", username: "x", notes: "", status: "active", role: "operator", concurrency: 1, rpm_limit: 0, balance_microusd: "1", allowed_group_ids: [], restrict_public_groups: false })).status).toBe(400);
    for (const [operation, platform, subscription] of [["bad-platform", "anthropic", "standard"], ["bad-subscription", "openai", "subscription"], ["bad-mode", "openai", "payg"]]) expect((await call("/v1/manage/groups/create", { operation_id: operation, id: id(), name: "x", platform, status: "active", is_exclusive: false, subscription_type: subscription })).status).toBe(400);
    expect((await call("/v1/manage/users/get", { id: "1001" }, { host: "public.example" })).status).toBe(404);
  });
});
