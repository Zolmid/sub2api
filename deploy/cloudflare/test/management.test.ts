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
    await env.DB.prepare("UPDATE users SET balance_microusd='7654321' WHERE id=?").bind(scope.userID).run();

    const notesUpdate = await call("/v1/manage/users/update", {
      operation_id: "notes-only-" + scope.userID,
      id: scope.userID,
      notes: "preserve unrelated state",
    });
    expect(notesUpdate.status).toBe(200);
    const stored = await env.DB.prepare(
      "SELECT notes,role,balance_microusd,allowed_group_ids_json FROM users WHERE id=?",
    ).bind(scope.userID).first<{ notes: string; role: string; balance_microusd: string; allowed_group_ids_json: string }>();
    expect(stored).toEqual({
      notes: "preserve unrelated state",
      role: "user",
      balance_microusd: "7654321",
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
