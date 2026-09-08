import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { controlPlane } from "../src/control-plane";
import { BRIDGE_VERSION } from "../src/contracts";
import { generateTOTPCode } from "../src/totp-security";

const id = () =>
  "7" + String(crypto.getRandomValues(new Uint32Array(1))[0]).padStart(10, "0");

const call = (body: Record<string, unknown>) => controlPlane(new Request(
  "http://sub2api.internal/v1/manage/users/role-change",
  {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Sub2API-Bridge-Version": BRIDGE_VERSION,
      "X-Sub2API-Container-Id": "role-management-test",
    },
    body: JSON.stringify(body),
  },
), env);

async function createUser(role: "user" | "admin", status: "active" | "disabled" = "active") {
  const userID = id();
  const stamp = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO users(
       id,status,role,concurrency,balance_microusd,allowed_group_ids_json,
       restrict_public_groups,created_at,updated_at,email,password_hash,
       username,notes,rpm_limit,deleted_at
     ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
  ).bind(
    userID, status, role, 1, "0", "[]", 0, stamp, stamp,
    `role-${userID}@example.test`, "test-password-hash", `role-${userID}`, "", 0,
  ).run();
  return userID;
}

function roleRequest(
  operationID: string,
  actorID: string,
  targetID: string,
  sessionID: string,
  role: "user" | "admin",
  overrides: Record<string, unknown> = {},
) {
  return {
    operation_id: operationID,
    actor_user_id: actorID,
    actor_auth_method: "jwt",
    actor_session_id: sessionID,
    id: targetID,
    role,
    ...overrides,
  };
}

async function enableAndGrant(userID: string, sessionID: string) {
  const stub = env.TOTP_SECURITY.get(
    env.TOTP_SECURITY.idFromName(`user:${userID}`),
  );
  const setup = await stub.beginSetup(userID);
  if (!setup.ok) throw new Error(`begin setup failed: ${setup.code}`);
  const setupCode = await generateTOTPCode(setup.secret, Date.now());
  if (!setupCode) throw new Error("failed to generate setup code");
  const enabled = await stub.completeSetup(userID, setup.setup_token, setupCode);
  if (!enabled.ok) throw new Error(`enable failed: ${enabled.code}`);
  const stepUpCode = await generateTOTPCode(setup.secret, Date.now());
  if (!stepUpCode) throw new Error("failed to generate step-up code");
  const granted = await stub.verifyStepUp(userID, sessionID, stepUpCode);
  if (!granted.ok) throw new Error(`step-up failed: ${granted.code}`);
}

describe("Cloudflare-native administrator role management", () => {
  it("promotes with ordinary fields, replays durably, conflicts on identity changes, and keeps audit immutable", async () => {
    const actorID = await createUser("admin");
    const secondActorID = await createUser("admin");
    const targetID = await createUser("user");
    const otherTargetID = await createUser("user");
    const sessionID = `role-session-${id()}`;
    const secondSessionID = `role-session-${id()}`;
    await enableAndGrant(actorID, sessionID);
    await enableAndGrant(secondActorID, secondSessionID);
    const operationID = `role-promote-${id()}`;
    const passwordHash = `secret-derived-password-hash-${id()}`;
    const passwordSemanticDigest = "a".repeat(64);
    const request = roleRequest(operationID, actorID, targetID, sessionID, "admin", {
      username: "promoted-admin",
      notes: "safe audit note stays on the user only",
      concurrency: 3,
      password_hash: passwordHash,
      password_semantic_digest: passwordSemanticDigest,
    });

    const promoted = await call(request);
    expect(promoted.status).toBe(200);
    const promotedBody = await promoted.json<{
      user: { id: string; role: string; username: string; concurrency: number };
      replayed: boolean;
    }>();
    expect(promotedBody).toMatchObject({
      user: { id: targetID, role: "admin", username: "promoted-admin", concurrency: 3 },
      replayed: false,
    });
    expect(JSON.stringify(promotedBody)).not.toContain(passwordHash);

    const storedOperation = await env.DB.prepare(
      "SELECT route,request_hash,response_json FROM management_operations WHERE operation_id=?",
    ).bind(operationID).first<{
      route: string;
      request_hash: string;
      response_json: string;
    }>();
    expect(storedOperation?.route).toBe("/v1/manage/users/role-change");
    expect(storedOperation?.request_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(storedOperation?.response_json).not.toContain(passwordHash);
    expect(JSON.stringify(storedOperation)).not.toContain(sessionID);
    expect(JSON.stringify(storedOperation)).not.toContain(passwordSemanticDigest);

    const audit = await env.DB.prepare(
      `SELECT operation_id,actor_user_id,target_user_id,old_role,new_role,created_at
       FROM admin_role_change_audit WHERE operation_id=?`,
    ).bind(operationID).first<Record<string, unknown>>();
    expect(audit).toMatchObject({
      operation_id: operationID,
      actor_user_id: actorID,
      target_user_id: targetID,
      old_role: "user",
      new_role: "admin",
    });
    expect(JSON.stringify(audit)).not.toContain(sessionID);
    expect(JSON.stringify(audit)).not.toContain(passwordHash);

    const replay = await call({
      ...request,
      password_hash: `fresh-bcrypt-salt-${id()}`,
    });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toMatchObject({ replayed: true, user: { role: "admin" } });
    expect(await env.DB.prepare(
      "SELECT password_hash FROM users WHERE id=?",
    ).bind(targetID).first("password_hash")).toBe(passwordHash);
    expect(await env.DB.prepare(
      "SELECT count(*) AS count FROM admin_role_change_audit WHERE operation_id=?",
    ).bind(operationID).first("count")).toBe(1);

    const noOpOperation = `role-noop-${id()}`;
    const noOp = await call(roleRequest(
      noOpOperation, actorID, targetID, sessionID, "admin",
    ));
    expect(noOp.status).toBe(200);
    expect(await noOp.json()).toMatchObject({ replayed: false, user: { role: "admin" } });
    expect(await env.DB.prepare(
      "SELECT count(*) AS count FROM admin_role_change_audit WHERE operation_id=?",
    ).bind(noOpOperation).first("count")).toBe(0);
    expect(await env.TOTP_SECURITY.get(
      env.TOTP_SECURITY.idFromName(`user:${actorID}`),
    ).hasStepUp(actorID, sessionID)).toMatchObject({ ok: true, granted: true });

    for (const conflict of [
      roleRequest(operationID, actorID, otherTargetID, sessionID, "admin"),
      roleRequest(operationID, secondActorID, targetID, secondSessionID, "admin"),
      roleRequest(operationID, actorID, targetID, sessionID, "user"),
      { ...request, password_semantic_digest: "b".repeat(64) },
    ]) {
      const response = await call(conflict);
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ error: { code: "IDEMPOTENCY_CONFLICT" } });
    }

    await expect(env.DB.prepare(
      "UPDATE admin_role_change_audit SET new_role='user' WHERE operation_id=?",
    ).bind(operationID).run()).rejects.toThrow();
    await expect(env.DB.prepare(
      "DELETE FROM admin_role_change_audit WHERE operation_id=?",
    ).bind(operationID).run()).rejects.toThrow();
  });

  it("fails closed for API keys, missing sessions or TOTP, absent grants, stale grants, and unsafe input", async () => {
    const actorID = await createUser("admin");
    const targetID = await createUser("user");
    const sessionID = `role-session-${id()}`;
    const operationID = `role-auth-${id()}`;
    const base = roleRequest(operationID, actorID, targetID, sessionID, "admin");

    const apiKey = await call({ ...base, actor_auth_method: "admin_api_key" });
    expect(apiKey.status).toBe(403);
    expect(await apiKey.json()).toMatchObject({ error: { code: "STEP_UP_ADMIN_API_KEY_FORBIDDEN" } });
    const noSession = await call({ ...base, actor_session_id: undefined });
    expect(noSession.status).toBe(401);
    expect(await noSession.json()).toMatchObject({ error: { code: "STEP_UP_SESSION_REQUIRED" } });
    const noTOTP = await call(base);
    expect(noTOTP.status).toBe(403);
    expect(await noTOTP.json()).toMatchObject({ error: { code: "STEP_UP_TOTP_NOT_ENABLED" } });

    const stub = env.TOTP_SECURITY.get(env.TOTP_SECURITY.idFromName(`user:${actorID}`));
    const setup = await stub.beginSetup(actorID);
    if (!setup.ok) throw new Error(`begin setup failed: ${setup.code}`);
    const setupCode = await generateTOTPCode(setup.secret, Date.now());
    if (!setupCode) throw new Error("failed to generate setup code");
    expect(await stub.completeSetup(actorID, setup.setup_token, setupCode)).toMatchObject({ ok: true });
    const noGrant = await call(base);
    expect(noGrant.status).toBe(403);
    expect(await noGrant.json()).toMatchObject({ error: { code: "STEP_UP_REQUIRED" } });

    const stepUpCode = await generateTOTPCode(setup.secret, Date.now());
    if (!stepUpCode) throw new Error("failed to generate step-up code");
    expect(await stub.verifyStepUp(actorID, sessionID, stepUpCode)).toMatchObject({ ok: true });
    await env.DB.prepare(
      "UPDATE users SET totp_revision=totp_revision+1 WHERE id=?",
    ).bind(actorID).run();
    const stale = await call(base);
    expect(stale.status).toBe(403);
    expect(await stale.json()).toMatchObject({ error: { code: "STEP_UP_REQUIRED" } });

    const ordinaryActor = await createUser("user");
    const ordinarySession = `role-session-${id()}`;
    await enableAndGrant(ordinaryActor, ordinarySession);
    const selfPromotionOperation = `role-self-promote-${id()}`;
    const selfPromotion = await call(roleRequest(
      selfPromotionOperation, ordinaryActor, ordinaryActor, ordinarySession, "admin",
    ));
    expect(selfPromotion.status).toBe(403);
    expect(await selfPromotion.json()).toMatchObject({ error: { code: "ACTOR_FORBIDDEN" } });

    expect((await call({ ...base, id: "070000000001" })).status).toBe(400);
    expect((await call({ ...base, id: 70000000001 })).status).toBe(400);
    expect((await call({ ...base, role: "owner" })).status).toBe(400);
    expect((await call({ ...base, unexpected: true })).status).toBe(400);
    expect((await call({ ...base, password_hash: "valid-password-hash-without-digest" })).status).toBe(400);
    expect((await call({ ...base, password_semantic_digest: "c".repeat(64) })).status).toBe(400);
    expect(await env.DB.prepare(
      "SELECT count(*) AS count FROM management_operations WHERE operation_id=?",
    ).bind(operationID).first("count")).toBe(0);
    expect(await env.DB.prepare(
      "SELECT count(*) AS count FROM management_operations WHERE operation_id=?",
    ).bind(selfPromotionOperation).first("count")).toBe(0);
  });

  it("demotes safely, rejects removal of the last live administrator, and preserves hard admin deletion", async () => {
    const actorID = await createUser("admin");
    const targetID = await createUser("admin");
    const sessionID = `role-session-${id()}`;
    await enableAndGrant(actorID, sessionID);

    const demotion = await call(roleRequest(
      `role-demote-${id()}`, actorID, targetID, sessionID, "user",
    ));
    expect(demotion.status).toBe(200);
    expect(await demotion.json()).toMatchObject({ user: { id: targetID, role: "user" } });

    const lastOperation = `role-last-${id()}`;
    const last = await call(roleRequest(
      lastOperation, actorID, actorID, sessionID, "user",
    ));
    expect(last.status).toBe(409);
    expect(await last.json()).toMatchObject({ error: { code: "LAST_ADMIN_REQUIRED" } });
    const disable = await call(roleRequest(
      `role-disable-last-${id()}`, actorID, actorID, sessionID, "admin", { status: "disabled" },
    ));
    expect(disable.status).toBe(409);
    expect(await disable.json()).toMatchObject({ error: { code: "LAST_ADMIN_REQUIRED" } });
    expect(await env.DB.prepare(
      "SELECT count(*) AS count FROM users WHERE role='admin' AND status='active' AND deleted_at IS NULL",
    ).first("count")).toBe(1);
    expect(await env.DB.prepare(
      "SELECT count(*) AS count FROM management_operations WHERE operation_id=?",
    ).bind(lastOperation).first("count")).toBe(0);

    const deletion = await controlPlane(new Request(
      "http://sub2api.internal/v1/manage/users/delete",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "X-Sub2API-Bridge-Version": BRIDGE_VERSION,
          "X-Sub2API-Container-Id": "role-management-test",
        },
        body: JSON.stringify({ operation_id: `delete-admin-${id()}`, id: actorID }),
      },
    ), env);
    expect(deletion.status).toBe(409);
    expect(await deletion.json()).toMatchObject({ error: { code: "ROLE_PROTECTED" } });
  });

  it("serializes concurrent demotion and disable so one live administrator always remains", async () => {
    const firstAdmin = await createUser("admin");
    const secondAdmin = await createUser("admin");
    const firstSession = `role-session-${id()}`;
    const secondSession = `role-session-${id()}`;
    await enableAndGrant(firstAdmin, firstSession);
    await enableAndGrant(secondAdmin, secondSession);
    const demoteOperation = `role-race-demote-${id()}`;
    const disableOperation = `role-race-disable-${id()}`;

    const results = await Promise.all([
      call(roleRequest(demoteOperation, firstAdmin, firstAdmin, firstSession, "user")),
      call(roleRequest(
        disableOperation, secondAdmin, secondAdmin, secondSession, "admin", { status: "disabled" },
      )),
    ]);
    expect(results.map((response) => response.status).sort()).toEqual([200, 409]);
    const rejected = results.find((response) => response.status === 409)!;
    expect(await rejected.json()).toMatchObject({ error: { code: "LAST_ADMIN_REQUIRED" } });
    expect(await env.DB.prepare(
      "SELECT count(*) AS count FROM users WHERE role='admin' AND status='active' AND deleted_at IS NULL",
    ).first("count")).toBe(1);
    expect(await env.DB.prepare(
      "SELECT count(*) AS count FROM management_operations WHERE operation_id IN (?,?)",
    ).bind(demoteOperation, disableOperation).first("count")).toBe(1);
  });

  it("leaves the ordinary user update path unchanged", async () => {
    const targetID = await createUser("user");
    const response = await controlPlane(new Request(
      "http://sub2api.internal/v1/manage/users/update",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "X-Sub2API-Bridge-Version": BRIDGE_VERSION,
          "X-Sub2API-Container-Id": "role-management-test",
        },
        body: JSON.stringify({
          operation_id: `ordinary-update-${id()}`,
          id: targetID,
          username: "ordinary-update",
          notes: "still accepted",
        }),
      },
    ), env);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      user: { id: targetID, role: "user", username: "ordinary-update", notes: "still accepted" },
    });
  });
});
