import {
  env,
  evictDurableObject,
  runInDurableObject,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { controlPlane } from "../src/control-plane";
import { BRIDGE_VERSION } from "../src/contracts";
import {
  generateTOTPCode,
  TOTP_MAX_ATTEMPTS,
  type TOTPSecurityDO,
} from "../src/totp-security";

type SuccessBody = Record<string, unknown>;

const nextUserID = () =>
  "8" + String(crypto.getRandomValues(new Uint32Array(1))[0]).padStart(10, "0");

async function createUser(): Promise<string> {
  const userID = nextUserID();
  const stamp = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO users(
       id,status,role,concurrency,balance_e8_usd,allowed_group_ids_json,
       restrict_public_groups,created_at,updated_at,email,password_hash,
       username,notes,rpm_limit,deleted_at
     ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
  ).bind(
    userID,
    "active",
    "user",
    1,
    "0",
    "[]",
    0,
    stamp,
    stamp,
    `totp-${userID}@example.test`,
    "test-password-hash",
    `totp-${userID}`,
    "",
    0,
  ).run();
  expect(
    await env.DB.prepare("SELECT id FROM users WHERE id=?")
      .bind(userID)
      .first<string>("id"),
  ).toBe(userID);
  return userID;
}

const stubFor = (userID: string) =>
  env.TOTP_SECURITY.get(env.TOTP_SECURITY.idFromName(`user:${userID}`));

const invoke = (
  path: string,
  body: Record<string, unknown>,
  container = "totp-security-test",
) => controlPlane(new Request(`http://sub2api.internal${path}`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "X-Sub2API-Bridge-Version": BRIDGE_VERSION,
    ...(container === "" ? {} : { "X-Sub2API-Container-Id": container }),
  },
  body: JSON.stringify(body),
}), env);

async function responseBody(response: Response): Promise<SuccessBody> {
  return response.json<SuccessBody>();
}

async function enableTOTP(userID: string) {
  const stub = stubFor(userID);
  const setup = await stub.beginSetup(userID);
  if (!setup.ok) throw new Error(`begin setup failed: ${setup.code}`);
  const code = await generateTOTPCode(setup.secret, Date.now());
  if (!code) throw new Error("failed to generate test TOTP code");
  const completed = await stub.completeSetup(userID, setup.setup_token, code);
  if (!completed.ok) throw new Error(`complete setup failed: ${completed.code}`);
  return { stub, setup, code };
}

async function wrongCode(secret: string): Promise<string> {
  const now = Date.now();
  const live = new Set(await Promise.all([
    generateTOTPCode(secret, now - 30_000),
    generateTOTPCode(secret, now),
    generateTOTPCode(secret, now + 30_000),
  ]));
  for (const candidate of ["000000", "111111", "222222", "999999"]) {
    if (!live.has(candidate)) return candidate;
  }
  throw new Error("failed to select an invalid code");
}

describe("TOTPSecurityDO", () => {
  it("keeps setup material encrypted and completes login plus session-bound step-up", async () => {
    const userID = await createUser();
    expect((await invoke("/v1/private/totp/status", { user_id: userID }, "")).status)
      .toBe(404);
    expect((await invoke("/v1/private/totp/status", {
      user_id: userID,
      unexpected: true,
    })).status).toBe(400);

    const setupResponse = await invoke("/v1/private/totp/setup/begin", {
      user_id: userID,
  });
    expect(setupResponse.status).toBe(200);
    const setup = await responseBody(setupResponse) as {
      secret: string;
      qr_code_url: string;
      setup_token: string;
      countdown: number;
    };
    expect(setup.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(setup.setup_token).toMatch(/^[0-9a-f]{64}$/);
    expect(setup.qr_code_url).toContain(`secret=${setup.secret}`);
    expect(setup.countdown).toBe(300);

    const stub = stubFor(userID);
    const durableSetup = await runInDurableObject(
      stub as DurableObjectStub<TOTPSecurityDO>,
      (_instance, state) => state.storage.sql.exec<{
        token_hash: string;
        secret_envelope: string;
      }>("SELECT token_hash,secret_envelope FROM totp_setup WHERE id=1").one(),
    );
    expect(durableSetup.token_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(durableSetup.token_hash).not.toBe(setup.setup_token);
    expect(durableSetup.secret_envelope).toMatch(/^aes-gcm:v1:totp:/);
    expect(durableSetup.secret_envelope).not.toContain(setup.secret);
    const before = await env.DB.prepare(
      "SELECT totp_secret_envelope,totp_enabled,totp_revision FROM users WHERE id=?",
    ).bind(userID).first<{
      totp_secret_envelope: string | null;
      totp_enabled: number;
      totp_revision: number;
    }>();
    expect(before).toEqual({
      totp_secret_envelope: null,
      totp_enabled: 0,
      totp_revision: 0,
    });

    const setupCode = await generateTOTPCode(setup.secret, Date.now());
    expect(setupCode).toMatch(/^[0-9]{6}$/);
    const enabled = await invoke("/v1/private/totp/setup/complete", {
      user_id: userID,
      setup_token: setup.setup_token,
      totp_code: setupCode,
    });
    expect(enabled.status).toBe(200);
    expect(await enabled.json()).toEqual({});
    const replay = await invoke("/v1/private/totp/setup/complete", {
      user_id: userID,
      setup_token: setup.setup_token,
      totp_code: setupCode,
    });
    expect(replay.status).toBe(200);

    const stored = await env.DB.prepare(
      `SELECT totp_secret_envelope,totp_enabled,totp_enabled_at,totp_revision
       FROM users WHERE id=?`,
    ).bind(userID).first<{
      totp_secret_envelope: string;
      totp_enabled: number;
      totp_enabled_at: string;
      totp_revision: number;
    }>();
    expect(stored?.totp_enabled).toBe(1);
    expect(stored?.totp_revision).toBe(1);
    expect(stored?.totp_enabled_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(stored?.totp_secret_envelope).toMatch(/^aes-gcm:v1:totp:/);
    expect(stored?.totp_secret_envelope).not.toContain(setup.secret);

    const login = await invoke("/v1/private/totp/login/begin", {
      user_id: userID,
    });
    expect(login.status).toBe(200);
    const challenge = await responseBody(login) as {
      temp_token: string;
      countdown: number;
    };
    expect(challenge.temp_token).toMatch(new RegExp(`^${userID}\\.[0-9a-f]{64}$`));
    expect(challenge.countdown).toBe(300);
    const loginCode = await generateTOTPCode(setup.secret, Date.now());
    const verified = await invoke("/v1/private/totp/login/verify", {
      temp_token: challenge.temp_token,
      totp_code: loginCode,
    });
    expect(verified.status).toBe(200);
    expect(await verified.json()).toEqual({ user_id: userID });
    const consumed = await invoke("/v1/private/totp/login/verify", {
      temp_token: challenge.temp_token,
      totp_code: loginCode,
    });
    expect(consumed.status).toBe(400);
    expect(await consumed.json()).toEqual({
      error: {
        code: "TOTP_LOGIN_EXPIRED",
        message: "TOTP_LOGIN_EXPIRED",
      },
    });

    const sessionID = "session-primary-1234";
    const stepUpCode = await generateTOTPCode(setup.secret, Date.now());
    const stepUp = await invoke("/v1/private/totp/step-up/verify", {
      user_id: userID,
      session_id: sessionID,
      totp_code: stepUpCode,
    });
    expect(stepUp.status).toBe(200);
    expect(await stepUp.json()).toEqual({ expires_in: 900 });
    await evictDurableObject(stub);
    const granted = await invoke("/v1/private/totp/step-up/check", {
      user_id: userID,
      session_id: sessionID,
    });
    expect(await granted.json()).toEqual({ granted: true });
    const otherSession = await invoke("/v1/private/totp/step-up/check", {
      user_id: userID,
      session_id: "session-secondary-5678",
    });
    expect(await otherSession.json()).toEqual({ granted: false });

    await env.DB.prepare(
      "UPDATE users SET totp_revision=totp_revision+1 WHERE id=?",
    ).bind(userID).run();
    const staleGrant = await invoke("/v1/private/totp/step-up/check", {
      user_id: userID,
      session_id: sessionID,
    });
    expect(await staleGrant.json()).toEqual({ granted: false });

    const disabled = await invoke("/v1/private/totp/disable", {
      user_id: userID,
    });
    expect(disabled.status).toBe(200);
    const after = await env.DB.prepare(
      `SELECT totp_secret_envelope,totp_enabled,totp_enabled_at,totp_revision
       FROM users WHERE id=?`,
    ).bind(userID).first<{
      totp_secret_envelope: string | null;
      totp_enabled: number;
      totp_enabled_at: string | null;
      totp_revision: number;
    }>();
    expect(after).toEqual({
      totp_secret_envelope: null,
      totp_enabled: 0,
      totp_enabled_at: null,
      totp_revision: 3,
    });
  });

  it("persists lockout and rejects expired or superseded login challenges", async () => {
    const userID = await createUser();
    const { stub, setup } = await enableTOTP(userID);

    const first = await stub.beginLogin(userID);
    const second = await stub.beginLogin(userID);
    if (!first.ok || !second.ok) throw new Error("begin login failed");
    const currentCode = await generateTOTPCode(setup.secret, Date.now());
    const superseded = await stub.verifyLogin(userID, first.temp_token, currentCode!);
    expect(superseded).toEqual({ ok: false, code: "TOTP_LOGIN_EXPIRED" });

    const badCode = await wrongCode(setup.secret);
    for (let attempt = 0; attempt < TOTP_MAX_ATTEMPTS; attempt += 1) {
      expect(await stub.verifyLogin(userID, second.temp_token, badCode))
        .toEqual({ ok: false, code: "TOTP_INVALID_CODE" });
    }
    await evictDurableObject(stub);
    expect(await stub.verifyLogin(userID, second.temp_token, currentCode!))
      .toEqual({ ok: false, code: "TOTP_TOO_MANY_ATTEMPTS" });

    await runInDurableObject(
      stub as DurableObjectStub<TOTPSecurityDO>,
      (_instance, state) => {
        state.storage.sql.exec("DELETE FROM totp_attempts");
        state.storage.sql.exec(
          "UPDATE totp_login_challenges SET expires_at=?",
          Date.now() - 1,
        );
      },
    );
    expect(await stub.verifyLogin(userID, second.temp_token, currentCode!))
      .toEqual({ ok: false, code: "TOTP_LOGIN_EXPIRED" });
  });

  it("recovers when D1 commits setup before the DO completion marker", async () => {
    const userID = await createUser();
    const stub = stubFor(userID);
    const setup = await stub.beginSetup(userID);
    if (!setup.ok) throw new Error(`begin setup failed: ${setup.code}`);
    const storedSetup = await runInDurableObject(
      stub as DurableObjectStub<TOTPSecurityDO>,
      (_instance, state) => state.storage.sql.exec<{
        secret_envelope: string;
        base_revision: number;
        completed: number;
      }>(
        `SELECT secret_envelope,base_revision,completed
         FROM totp_setup WHERE id=1`,
      ).one(),
    );
    expect(storedSetup.completed).toBe(0);
    const stamp = new Date().toISOString();
    await env.DB.prepare(
      `UPDATE users
       SET totp_secret_envelope=?,totp_enabled=1,totp_enabled_at=?,
           totp_revision=totp_revision+1,updated_at=?
       WHERE id=? AND totp_enabled=0 AND totp_revision=?`,
    ).bind(
      storedSetup.secret_envelope,
      stamp,
      stamp,
      userID,
      storedSetup.base_revision,
    ).run();
    expect(
      await env.DB.prepare(
        "SELECT totp_secret_envelope FROM users WHERE id=? AND totp_enabled=1 AND totp_revision=?",
      )
        .bind(userID, storedSetup.base_revision + 1)
        .first<string>("totp_secret_envelope"),
    ).toBe(storedSetup.secret_envelope);

    const code = await generateTOTPCode(setup.secret, Date.now());
    expect(await stub.completeSetup(userID, setup.setup_token, code!))
      .toEqual({ ok: true });
    expect(await runInDurableObject(
      stub as DurableObjectStub<TOTPSecurityDO>,
      (_instance, state) => state.storage.sql.exec<{ completed: number }>(
        "SELECT completed FROM totp_setup WHERE id=1",
      ).one().completed,
    )).toBe(1);
  });

  it("fails closed when encryption material is unavailable or malformed", async () => {
    const { encryptTOTPSecret, decryptTOTPSecret } = await import("../src/credentials");
    const secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    expect(await encryptTOTPSecret(secret, {})).toBeNull();
    expect(await encryptTOTPSecret("invalid", {
      CREDENTIAL_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    })).toBeNull();
    expect(await decryptTOTPSecret("aes-gcm:v1:totp:not-valid", {
      CREDENTIAL_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    })).toBeNull();
  });

  it("enforces D1 state consistency and reports revision exhaustion as conflict", async () => {
    const userID = await createUser();
    await expect(env.DB.prepare(
      "UPDATE users SET totp_enabled=1 WHERE id=?",
    ).bind(userID).run()).rejects.toThrow();
    await env.DB.prepare(
      "UPDATE users SET totp_revision=9007199254740991 WHERE id=?",
    ).bind(userID).run();

    const stub = stubFor(userID);
    const setup = await stub.beginSetup(userID);
    if (!setup.ok) throw new Error(`begin setup failed: ${setup.code}`);
    const code = await generateTOTPCode(setup.secret, Date.now());
    expect(await stub.completeSetup(userID, setup.setup_token, code!))
      .toEqual({ ok: false, code: "TOTP_STATE_CONFLICT" });
    expect(await env.DB.prepare(
      "SELECT totp_enabled,totp_secret_envelope FROM users WHERE id=?",
    ).bind(userID).first()).toEqual({
      totp_enabled: 0,
      totp_secret_envelope: null,
    });
  });
});
