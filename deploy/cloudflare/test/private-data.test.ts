import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { controlPlane } from "../src/control-plane";
import { BRIDGE_VERSION, sha256 } from "../src/contracts";

const request = (path: string, body: object) =>
  new Request("http://sub2api.internal" + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Sub2API-Bridge-Version": BRIDGE_VERSION,
      "X-Sub2API-Container-Id": "private-data-test",
    },
    body: JSON.stringify(body),
  });

const call = (path: string, body: object) => controlPlane(request(path, body), env);
const stamp = "2026-09-06T00:00:00.000Z";

async function insertUser(id: string, email: string, status = "active", deletedAt: string | null = null) {
  await env.DB.prepare(
    "INSERT INTO users(id,status,role,concurrency,balance_e8_usd,allowed_group_ids_json,restrict_public_groups,created_at,email,password_hash,username,notes,rpm_limit,updated_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
  ).bind(id, status, "user", 1, "100", "[]", 0, stamp, email, "bcrypt-test-password-hash", "tester", "", 0, stamp, deletedAt).run();
}

async function insertGroup(id: string) {
  await env.DB.prepare(
    "INSERT INTO groups(id,name,platform,status,is_exclusive,subscription_type,created_at,updated_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?)",
  ).bind(id, "standard", "openai", "active", 0, "standard", stamp, stamp, null).run();
}

async function insertKey(id: string, userID: string, groupID: string, raw: string, deletedAt: string | null = null) {
  await env.DB.prepare(
    "INSERT INTO api_keys(id,user_id,group_id,name,status,key_hash,ip_whitelist_json,ip_blacklist_json,expires_at,last_used_at,created_at,updated_at,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
  ).bind(id, userID, groupID, "key-" + id, deletedAt ? "disabled" : "active", await sha256(raw), "[]", "[]", null, null, stamp, stamp, deletedAt).run();
}

describe("private Container data protocol", () => {
  it("returns auth-only fields with normalized email and string-safe IDs", async () => {
    const userID = "9007199254740993";
    await insertUser(userID, "User@Example.test");
    const response = await call("/v1/private/auth-users/get", { email: "  user@example.TEST " });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      user: { id: userID, email: "User@Example.test", password_hash: "bcrypt-test-password-hash" },
    });

    const byID = await call("/v1/private/auth-users/get", { id: userID });
    expect(byID.status).toBe(200);
    expect((await byID.json<{ user: { id: unknown } }>()).user.id).toBe(userID);

    const managed = await call("/v1/manage/users/get", { id: userID });
    const managedBody = JSON.stringify(await managed.json());
    expect(managedBody).not.toContain("password_hash");
    expect(managedBody).not.toContain("bcrypt-test-password-hash");
    const managedList = await call("/v1/manage/users/list", { cursor: "0", limit: 100 });
    const managedListBody = JSON.stringify(await managedList.json());
    expect(managedListBody).not.toContain("password_hash");
    expect(managedListBody).not.toContain("bcrypt-test-password-hash");
    expect(managedListBody).not.toContain("test-only-cloudflare-jwt-secret-32-bytes");
  });

  it("treats tombstones as absent and enforces normalized live email identity", async () => {
    await insertUser("9007199254741001", "Gone@example.test", "disabled", stamp);
    expect((await call("/v1/private/auth-users/get", { email: "gone@example.test" })).status).toBe(404);
    expect((await call("/v1/private/auth-users/get", { id: "9007199254741001" })).status).toBe(404);

    await insertUser("9007199254741002", "Alias@Example.test");
    await expect(insertUser("9007199254741003", " alias@example.TEST ")).rejects.toThrow(
      /UNIQUE constraint failed/,
    );
    const normalized = await call("/v1/private/auth-users/get", { email: " ALIAS@example.test " });
    expect(normalized.status).toBe(200);
    expect(await normalized.json()).toMatchObject({ user: { id: "9007199254741002" } });
  });

  it("keeps owner lists isolated, excludes tombstones, and never stores raw keys", async () => {
    const owner = "9007199254741101";
    const other = "9007199254741102";
    const group = "9007199254741201";
    await insertUser(owner, "owner@example.test");
    await insertUser(other, "other@example.test");
    await insertGroup(group);
    await insertKey("9007199254741301", owner, group, "OwnerRawKey_123456");
    await insertKey("9007199254741302", owner, group, "DeletedRawKey_123456", stamp);
    await insertKey("9007199254741303", other, group, "OtherRawKey_123456");

    const response = await call("/v1/private/api-keys/list-by-owner", {
      user_id: owner, page: 1, page_size: 20, sort_by: "created_at", sort_order: "desc",
    });
    expect(response.status).toBe(200);
    const body = await response.json<{ api_keys: { id: string }[]; total: string }>();
    expect(body.total).toBe("1");
    expect(body.api_keys.map((key) => key.id)).toEqual(["9007199254741301"]);
    expect(JSON.stringify(body)).not.toContain("RawKey");

    expect(await (await call("/v1/private/api-keys/exists", { raw_key: "OwnerRawKey_123456" })).json()).toEqual({ exists: true });
    expect(await (await call("/v1/private/api-keys/exists", { raw_key: "DeletedRawKey_123456" })).json()).toEqual({ exists: false });
    const persisted = await env.DB.prepare("SELECT key_hash FROM api_keys WHERE id=?").bind("9007199254741301").first<{ key_hash: string }>();
    expect(persisted?.key_hash).toHaveLength(64);
    expect(persisted?.key_hash).not.toContain("OwnerRawKey_123456");
  });
});
