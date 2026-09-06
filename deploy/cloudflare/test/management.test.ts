import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { controlPlane } from "../src/control-plane";
import { BRIDGE_VERSION } from "../src/contracts";

type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };
const testEnv = env as TestEnv;
const request = (path: string, body: object, options: { host?: string; version?: string; container?: string } = {}) =>
  new Request("http://" + (options.host ?? "sub2api.internal") + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Sub2API-Bridge-Version": options.version ?? BRIDGE_VERSION,
      ...(options.container === "" ? {} : { "X-Sub2API-Container-Id": options.container ?? "management-test" }),
    },
    body: JSON.stringify(body),
  });
const call = (path: string, body: object, options?: Parameters<typeof request>[2]) => controlPlane(request(path, body, options), env);

describe("Stage C private management control plane", () => {
  it("applies the forward migration repeatedly without losing Stage B fixtures", async () => {
    await applyD1Migrations(env.DB, testEnv.TEST_MIGRATIONS);
    expect(await env.DB.prepare("SELECT count(*) count FROM pragma_table_info('users') WHERE name IN ('email','password_hash','deleted_at')").first("count")).toBe(3);
    expect(await env.DB.prepare("SELECT count(*) count FROM users WHERE id='1001'").first("count")).toBe(1);
  });

  it("manages four bounded resources while preserving canonical decimal identifiers", async () => {
    const userID = "9007199254740993"; const groupID = "9007199254740994"; const keyID = "9007199254740995"; const accountID = "9007199254740996";
    const createdUser = await call("/v1/manage/users/create", { operation_id: "stage-c-user-create", id: userID, email: "stage-c@example.test", password_hash: "bcrypt-hash-that-is-never-returned", username: "stage-c", notes: "local test", status: "active", role: "user", concurrency: 3, rpm_limit: 9, balance_microusd: "9007199254740993000000", allowed_group_ids: [], restrict_public_groups: false });
    expect(createdUser.status).toBe(200);
    const userBody = await createdUser.json<{ user: Record<string, unknown> }>();
    expect(userBody.user).toMatchObject({ id: userID, balance_microusd: "9007199254740993000000" });
    expect(userBody.user).not.toHaveProperty("password_hash");
    expect(await env.DB.prepare("SELECT password_hash FROM users WHERE id=?").bind(userID).first("password_hash")).toBe("bcrypt-hash-that-is-never-returned");
    expect((await call("/v1/manage/groups/create", { operation_id: "stage-c-group-create", id: groupID, name: "stage-c-group", platform: "openai", status: "active", is_exclusive: false, subscription_type: "payg" })).status).toBe(200);
    expect((await call("/v1/manage/users/update", { operation_id: "stage-c-user-group", id: userID, allowed_group_ids: [groupID] })).status).toBe(200);
    const rawKey = "StageC_Test_Key_123456";
    const createdKey = await call("/v1/manage/api-keys/create", { operation_id: "stage-c-key-create", id: keyID, user_id: userID, group_id: groupID, name: "stage-c key", status: "active", raw_key: rawKey, ip_whitelist: ["127.0.0.1"], ip_blacklist: [], expires_at: null });
    expect(await createdKey.json()).toMatchObject({ raw_key: rawKey, api_key: { id: keyID } });
    expect(await env.DB.prepare("SELECT key_hash FROM api_keys WHERE id=?").bind(keyID).first("key_hash")).not.toBe(rawKey);
    const replay = await call("/v1/manage/api-keys/create", { operation_id: "stage-c-key-create", id: keyID, user_id: userID, group_id: groupID, name: "stage-c key", status: "active", raw_key: rawKey, ip_whitelist: ["127.0.0.1"], ip_blacklist: [], expires_at: null });
    expect(await replay.json()).not.toHaveProperty("raw_key");
    expect((await call("/v1/manage/accounts/create", { operation_id: "stage-c-account-create", id: accountID, name: "stage-c upstream", platform: "openai", status: "active", schedulable: true, priority: 3, max_concurrency: 2, credential_envelope: "fixture:v1:mock-upstream", extra: { openai_responses_supported: false }, group_ids: [groupID] })).status).toBe(200);
    const account = await (await call("/v1/manage/accounts/get", { id: accountID })).json<{ account: Record<string, unknown> }>();
    expect(account.account).toMatchObject({ id: accountID, type: "apikey", group_ids: [groupID] });
    expect(account.account).not.toHaveProperty("credential_envelope");
    expect(await env.DB.prepare("SELECT count(*) count FROM account_groups WHERE account_id=? AND group_id=?").bind(accountID, groupID).first("count")).toBe(1);
    expect(await (await call("/v1/manage/users/list", { cursor: "9007199254740992", limit: 1 })).json()).toMatchObject({ users: [{ id: userID }], next_cursor: null });
  });

  it("rejects malformed, disabled, missing, and cross-tenant references", async () => {
    expect((await call("/v1/manage/users/list", { limit: 101 })).status).toBe(400);
    expect((await call("/v1/manage/groups/create", { operation_id: "unknown-field", id: "901", name: "x", platform: "openai", status: "active", is_exclusive: false, subscription_type: "payg", surprise: true })).status).toBe(400);
    expect((await call("/v1/manage/users/get", { id: "1001" }, { host: "public.example" })).status).toBe(404);
    expect((await call("/v1/manage/users/get", { id: "1001" }, { version: "wrong" })).status).toBe(404);
    expect((await call("/v1/manage/users/get", { id: "1001" }, { container: "" })).status).toBe(404);
    expect((await call("/v1/manage/api-keys/create", { operation_id: "cross-tenant-key", id: "9007199254740997", user_id: "1002", group_id: "2001", name: "bad", status: "active", raw_key: "CrossTenantKey_1234", ip_whitelist: [], ip_blacklist: [], expires_at: null })).status).toBe(409);
    expect((await call("/v1/manage/accounts/create", { operation_id: "missing-account-group", id: "9007199254740998", name: "bad", platform: "openai", status: "active", schedulable: true, priority: 1, max_concurrency: 1, credential_envelope: "fixture:v1:mock-upstream", extra: {}, group_ids: ["999999"] })).status).toBe(400);
  });

  it("revokes keys and soft-deletes apikey upstream accounts", async () => {
    expect((await call("/v1/manage/api-keys/revoke", { operation_id: "fixture-key-revoke", id: "3001" })).status).toBe(200);
    expect(await env.DB.prepare("SELECT status,deleted_at FROM api_keys WHERE id='3001'").first<{ status: string; deleted_at: string }>()).toMatchObject({ status: "disabled" });
    expect((await call("/v1/manage/accounts/delete", { operation_id: "fixture-account-delete", id: "4001" })).status).toBe(200);
    expect(await env.DB.prepare("SELECT status,schedulable,deleted_at FROM accounts WHERE id='4001'").first<{ status: string; schedulable: number; deleted_at: string }>()).toMatchObject({ status: "disabled", schedulable: 0 });
    expect(await env.DB.prepare("SELECT count(*) count FROM account_groups WHERE account_id='4001' AND group_id='2001'").first("count")).toBe(1);
  });
});
