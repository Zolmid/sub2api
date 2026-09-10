import { DurableObject } from "cloudflare:workers";
import {
  decryptTOTPSecret,
  encryptTOTPSecret,
  type CredentialRuntime,
} from "./credentials";
import {
  isBoundedString,
  isCanonicalPositiveDecimal,
  sha256,
} from "./contracts";

export const TOTP_SETUP_TTL_MS = 5 * 60 * 1000;
export const TOTP_LOGIN_TTL_MS = 5 * 60 * 1000;
export const TOTP_ATTEMPT_TTL_MS = 15 * 60 * 1000;
export const TOTP_STEP_UP_TTL_MS = 15 * 60 * 1000;
export const TOTP_MAX_ATTEMPTS = 5;

type TOTPRuntimeEnv = Env & Pick<CredentialRuntime, "CREDENTIAL_ENCRYPTION_KEY">;

type UserTOTPRow = {
  id: string;
  email: string;
  status: string;
  deleted_at: string | null;
  totp_secret_envelope: string | null;
  totp_enabled: number;
  totp_enabled_at: string | null;
  totp_revision: number;
};

type SetupRow = {
  token_hash: string;
  secret_envelope: string;
  base_revision: number;
  expires_at: number;
  completed: number;
};

type LoginRow = {
  token_hash: string;
  revision: number;
  expires_at: number;
};

type GrantRow = {
  session_hash: string;
  revision: number;
  expires_at: number;
};

export type TOTPSecurityCode =
  | "NOT_FOUND"
  | "TOTP_ALREADY_ENABLED"
  | "TOTP_NOT_SETUP"
  | "TOTP_SETUP_EXPIRED"
  | "TOTP_INVALID_CODE"
  | "TOTP_TOO_MANY_ATTEMPTS"
  | "TOTP_LOGIN_EXPIRED"
  | "TOTP_STATE_CONFLICT"
  | "TOTP_UNAVAILABLE";

export type TOTPSecurityFailure = { ok: false; code: TOTPSecurityCode };
export type TOTPStatusResult =
  | TOTPSecurityFailure
  | {
      ok: true;
      enabled: boolean;
      enabled_at: string | null;
      revision: number;
    };
export type TOTPSetupResult =
  | TOTPSecurityFailure
  | {
      ok: true;
      secret: string;
      qr_code_url: string;
      setup_token: string;
      countdown: number;
    };
export type TOTPLoginResult =
  | TOTPSecurityFailure
  | { ok: true; temp_token: string; countdown: number };
export type TOTPOperationResult = TOTPSecurityFailure | { ok: true };
export type TOTPLoginVerificationResult =
  | TOTPSecurityFailure
  | { ok: true; user_id: string };
export type TOTPStepUpResult =
  | TOTPSecurityFailure
  | { ok: true; expires_in: number };
export type TOTPStepUpCheckResult =
  | TOTPSecurityFailure
  | { ok: true; granted: boolean };

const failure = (code: TOTPSecurityCode): TOTPSecurityFailure => ({
  ok: false,
  code,
});

function validUserID(value: unknown): value is string {
  return (
    isCanonicalPositiveDecimal(value) &&
    value.length <= 20
  );
}

function validRevision(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) &&
    Number(value) >= 0
  );
}

function randomHex(bytes: number): string {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return [...value]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function base32Encode(value: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let accumulator = 0;
  let output = "";
  for (const byte of value) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += alphabet[(accumulator >>> bits) & 31];
    }
  }
  if (bits > 0) output += alphabet[(accumulator << (5 - bits)) & 31];
  return output;
}

function base32Decode(value: string): Uint8Array | null {
  if (!/^[A-Z2-7]{32}$/.test(value)) return null;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let accumulator = 0;
  const output: number[] = [];
  for (const character of value) {
    const part = alphabet.indexOf(character);
    if (part < 0) return null;
    accumulator = (accumulator << 5) | part;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 0xff);
    }
  }
  return new Uint8Array(output);
}

async function codeForCounter(secret: string, counter: number): Promise<string | null> {
  const keyBytes = base32Decode(secret);
  if (!keyBytes || !Number.isSafeInteger(counter) || counter < 0) return null;
  const message = new ArrayBuffer(8);
  const view = new DataView(message);
  const high = Math.floor(counter / 0x1_0000_0000);
  const low = counter >>> 0;
  view.setUint32(0, high, false);
  view.setUint32(4, low, false);
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-1" },
      false,
      ["sign"],
    );
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
    const offset = digest[digest.length - 1] & 0x0f;
    const binary =
      ((digest[offset] & 0x7f) << 24) |
      ((digest[offset + 1] & 0xff) << 16) |
      ((digest[offset + 2] & 0xff) << 8) |
      (digest[offset + 3] & 0xff);
    return String(binary % 1_000_000).padStart(6, "0");
  } catch {
    return null;
  }
}

/** Exported for deterministic interoperability tests, never for production state. */
export async function generateTOTPCode(
  secret: string,
  timeMs: number,
): Promise<string | null> {
  if (!Number.isSafeInteger(timeMs) || timeMs < 0) return null;
  return codeForCounter(secret, Math.floor(timeMs / 30_000));
}

async function validTOTPCode(
  secret: string,
  code: string,
  timeMs: number,
): Promise<boolean> {
  if (!/^[0-9]{6}$/.test(code)) return false;
  const counter = Math.floor(timeMs / 30_000);
  let matched = 0;
  for (const skew of [-1, 0, 1]) {
    if (counter + skew < 0) continue;
    const candidate = await codeForCounter(secret, counter + skew);
    if (!candidate) return false;
    let difference = 0;
    for (let index = 0; index < code.length; index += 1) {
      difference |= code.charCodeAt(index) ^ candidate.charCodeAt(index);
    }
    matched |= Number(difference === 0);
  }
  return matched === 1;
}

/** One SQLite-backed authentication-security object per decimal user ID. */
export class TOTPSecurityDO extends DurableObject<TOTPRuntimeEnv> {
  private serial: Promise<void> = Promise.resolve();

  constructor(ctx: DurableObjectState, env: TOTPRuntimeEnv) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS totp_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS totp_setup (
        id INTEGER PRIMARY KEY CHECK(id=1),
        token_hash TEXT NOT NULL,
        secret_envelope TEXT NOT NULL,
        base_revision INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0,1))
      );
      CREATE TABLE IF NOT EXISTS totp_login_challenges (
        token_hash TEXT PRIMARY KEY,
        revision INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS totp_step_up_grants (
        session_hash TEXT PRIMARY KEY,
        revision INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS totp_attempts (
        id INTEGER PRIMARY KEY CHECK(id=1),
        attempts INTEGER NOT NULL CHECK(attempts>=0),
        expires_at INTEGER NOT NULL
      );
    `);
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const prior = this.serial;
    let release = () => {};
    this.serial = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private bindUser(userID: string): boolean {
    if (!validUserID(userID)) return false;
    const existing = this.ctx.storage.sql
      .exec<{ value: string }>(
        "SELECT value FROM totp_meta WHERE key='user_id'",
      )
      .toArray()[0];
    if (existing) return existing.value === userID;
    this.ctx.storage.sql.exec(
      "INSERT INTO totp_meta(key,value) VALUES('user_id',?)",
      userID,
    );
    return true;
  }

  private async user(userID: string): Promise<UserTOTPRow | null> {
    const row = await this.env.DB.prepare(
      `SELECT id,email,status,deleted_at,totp_secret_envelope,totp_enabled,
              totp_enabled_at,totp_revision
       FROM users WHERE id=?`,
    ).bind(userID).first<UserTOTPRow>();
    const enabled = row?.totp_enabled === 1;
    const hasEnvelope = row?.totp_secret_envelope !== null &&
      isBoundedString(row?.totp_secret_envelope, 512, 32) &&
      row.totp_secret_envelope.startsWith("aes-gcm:v1:totp:");
    const hasEnabledAt = row?.totp_enabled_at !== null &&
      isBoundedString(row?.totp_enabled_at, 64);
    if (
      !row ||
      row.id !== userID ||
      !isBoundedString(row.email, 255) ||
      !validRevision(row.totp_revision) ||
      (row.totp_enabled !== 0 && row.totp_enabled !== 1) ||
      enabled !== hasEnvelope ||
      enabled !== hasEnabledAt
    ) {
      return null;
    }
    return row;
  }

  private active(user: UserTOTPRow | null): user is UserTOTPRow {
    return user !== null && user.status === "active" && user.deleted_at === null;
  }

  private cleanup(timeMs: number): void {
    this.ctx.storage.sql.exec("DELETE FROM totp_setup WHERE expires_at<=?", timeMs);
    this.ctx.storage.sql.exec(
      "DELETE FROM totp_login_challenges WHERE expires_at<=?",
      timeMs,
    );
    this.ctx.storage.sql.exec(
      "DELETE FROM totp_step_up_grants WHERE expires_at<=?",
      timeMs,
    );
    this.ctx.storage.sql.exec("DELETE FROM totp_attempts WHERE expires_at<=?", timeMs);
  }

  private async reschedule(): Promise<void> {
    const next = this.ctx.storage.sql.exec<{ expires_at: number }>(
      `SELECT MIN(expires_at) expires_at FROM (
         SELECT expires_at FROM totp_setup
         UNION ALL SELECT expires_at FROM totp_login_challenges
         UNION ALL SELECT expires_at FROM totp_step_up_grants
         UNION ALL SELECT expires_at FROM totp_attempts
       )`,
    ).toArray()[0]?.expires_at;
    if (!Number.isSafeInteger(next)) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    await this.ctx.storage.setAlarm(Math.max(Date.now() + 1, next));
  }

  private blocked(timeMs: number): boolean {
    const row = this.ctx.storage.sql.exec<{ attempts: number; expires_at: number }>(
      "SELECT attempts,expires_at FROM totp_attempts WHERE id=1",
    ).toArray()[0];
    return Boolean(
      row &&
      Number.isSafeInteger(row.attempts) &&
      row.attempts >= TOTP_MAX_ATTEMPTS &&
      row.expires_at > timeMs,
    );
  }

  private failedAttempt(timeMs: number): void {
    const row = this.ctx.storage.sql.exec<{ attempts: number; expires_at: number }>(
      "SELECT attempts,expires_at FROM totp_attempts WHERE id=1",
    ).toArray()[0];
    if (!row || row.expires_at <= timeMs) {
      this.ctx.storage.sql.exec(
        `INSERT INTO totp_attempts(id,attempts,expires_at) VALUES(1,1,?)
         ON CONFLICT(id) DO UPDATE SET attempts=1,expires_at=excluded.expires_at`,
        timeMs + TOTP_ATTEMPT_TTL_MS,
      );
      return;
    }
    this.ctx.storage.sql.exec(
      "UPDATE totp_attempts SET attempts=attempts+1 WHERE id=1",
    );
  }

  private clearAttempts(): void {
    this.ctx.storage.sql.exec("DELETE FROM totp_attempts");
  }

  private revokeTransient(): void {
    this.ctx.storage.sql.exec("DELETE FROM totp_login_challenges");
    this.ctx.storage.sql.exec("DELETE FROM totp_step_up_grants");
    this.clearAttempts();
  }

  async status(userID: string): Promise<TOTPStatusResult> {
    return this.exclusive(async () => {
      if (!this.bindUser(userID)) return failure("NOT_FOUND");
      const user = await this.user(userID);
      if (!this.active(user)) return failure("NOT_FOUND");
      return {
        ok: true,
        enabled: user.totp_enabled === 1,
        enabled_at: user.totp_enabled_at,
        revision: user.totp_revision,
      };
    });
  }

  async beginSetup(userID: string): Promise<TOTPSetupResult> {
    return this.exclusive(async () => {
      if (!this.bindUser(userID)) return failure("NOT_FOUND");
      const timeMs = Date.now();
      this.cleanup(timeMs);
      const user = await this.user(userID);
      if (!this.active(user)) return failure("NOT_FOUND");
      if (user.totp_enabled === 1) return failure("TOTP_ALREADY_ENABLED");

      const secret = base32Encode(crypto.getRandomValues(new Uint8Array(20)));
      const envelope = await encryptTOTPSecret(secret, this.env);
      if (!envelope) return failure("TOTP_UNAVAILABLE");
      const setupToken = randomHex(32);
      const tokenHash = await sha256(setupToken);
      const expiresAt = timeMs + TOTP_SETUP_TTL_MS;
      this.ctx.storage.sql.exec(
        `INSERT INTO totp_setup(
           id,token_hash,secret_envelope,base_revision,expires_at,completed
         ) VALUES(1,?,?,?,?,0)
         ON CONFLICT(id) DO UPDATE SET
           token_hash=excluded.token_hash,
           secret_envelope=excluded.secret_envelope,
           base_revision=excluded.base_revision,
           expires_at=excluded.expires_at,
           completed=0`,
        tokenHash,
        envelope,
        user.totp_revision,
        expiresAt,
      );
      this.revokeTransient();
      await this.reschedule();
      const label = encodeURIComponent(`Sub2API:${user.email}`);
      return {
        ok: true,
        secret,
        qr_code_url:
          `otpauth://totp/${label}?secret=${secret}&issuer=Sub2API&algorithm=SHA1&digits=6&period=30`,
        setup_token: setupToken,
        countdown: Math.floor(TOTP_SETUP_TTL_MS / 1000),
      };
    });
  }

  async completeSetup(
    userID: string,
    setupToken: string,
    code: string,
  ): Promise<TOTPOperationResult> {
    return this.exclusive(async () => {
      if (
        !this.bindUser(userID) ||
        !isBoundedString(setupToken, 128) ||
        !/^[0-9]{6}$/.test(code)
      ) return failure("TOTP_SETUP_EXPIRED");
      const timeMs = Date.now();
      this.cleanup(timeMs);
      if (this.blocked(timeMs)) return failure("TOTP_TOO_MANY_ATTEMPTS");
      const setup = this.ctx.storage.sql.exec<SetupRow>(
        `SELECT token_hash,secret_envelope,base_revision,expires_at,completed
         FROM totp_setup WHERE id=1`,
      ).toArray()[0];
      if (!setup || setup.expires_at <= timeMs) return failure("TOTP_SETUP_EXPIRED");
      if (setup.token_hash !== await sha256(setupToken)) {
        this.failedAttempt(timeMs);
        await this.reschedule();
        return failure("TOTP_SETUP_EXPIRED");
      }
      const user = await this.user(userID);
      if (!this.active(user)) return failure("NOT_FOUND");
      const setupCommitted =
        user.totp_enabled === 1 &&
        user.totp_revision === setup.base_revision + 1 &&
        user.totp_secret_envelope === setup.secret_envelope;
      if (setupCommitted) {
        if (setup.completed !== 1) {
          this.ctx.storage.sql.exec(
            "UPDATE totp_setup SET completed=1 WHERE id=1 AND token_hash=?",
            setup.token_hash,
          );
        }
        this.revokeTransient();
        await this.reschedule();
        return { ok: true };
      }
      if (setup.completed === 1) return failure("TOTP_STATE_CONFLICT");
      if (user.totp_enabled === 1) return failure("TOTP_ALREADY_ENABLED");
      if (user.totp_revision !== setup.base_revision) {
        return failure("TOTP_STATE_CONFLICT");
      }
      const secret = await decryptTOTPSecret(setup.secret_envelope, this.env);
      if (!secret) return failure("TOTP_UNAVAILABLE");
      if (!await validTOTPCode(secret, code, timeMs)) {
        this.failedAttempt(timeMs);
        await this.reschedule();
        return failure("TOTP_INVALID_CODE");
      }
      const stamp = new Date(timeMs).toISOString();
      await this.env.DB.prepare(
        `UPDATE users
         SET totp_secret_envelope=?,totp_enabled=1,totp_enabled_at=?,
             totp_revision=totp_revision+1,updated_at=?
         WHERE id=? AND status='active' AND deleted_at IS NULL
           AND totp_enabled=0 AND totp_revision=?
           AND totp_revision<9007199254740991`,
      ).bind(
        setup.secret_envelope,
        stamp,
        stamp,
        userID,
        setup.base_revision,
      ).run();
      // D1's reported change count includes writes made by auth-cache
      // triggers. Confirm the exact guarded postcondition instead of treating
      // that implementation detail as the CAS result.
      const committed = await this.user(userID);
      if (
        !committed ||
        committed.totp_enabled !== 1 ||
        committed.totp_revision !== setup.base_revision + 1 ||
        committed.totp_secret_envelope !== setup.secret_envelope
      ) {
        return failure("TOTP_STATE_CONFLICT");
      }
      this.ctx.storage.sql.exec(
        "UPDATE totp_setup SET completed=1 WHERE id=1 AND token_hash=?",
        setup.token_hash,
      );
      this.revokeTransient();
      await this.reschedule();
      return { ok: true };
    });
  }

  async disable(userID: string): Promise<TOTPOperationResult> {
    return this.exclusive(async () => {
      if (!this.bindUser(userID)) return failure("NOT_FOUND");
      const user = await this.user(userID);
      if (!this.active(user)) return failure("NOT_FOUND");
      if (user.totp_enabled !== 1 || !user.totp_secret_envelope) {
        return failure("TOTP_NOT_SETUP");
      }
      const stamp = new Date().toISOString();
      await this.env.DB.prepare(
        `UPDATE users
         SET totp_secret_envelope=NULL,totp_enabled=0,totp_enabled_at=NULL,
             totp_revision=totp_revision+1,updated_at=?
         WHERE id=? AND status='active' AND deleted_at IS NULL
           AND totp_enabled=1 AND totp_revision=?
           AND totp_revision<9007199254740991`,
      ).bind(stamp, userID, user.totp_revision).run();
      // See completeSetup: a trigger-expanded D1 change count is not a
      // reliable indication that this guarded update lost its CAS race.
      const cleared = await this.user(userID);
      if (
        !cleared ||
        cleared.totp_enabled !== 0 ||
        cleared.totp_secret_envelope !== null ||
        cleared.totp_enabled_at !== null ||
        cleared.totp_revision !== user.totp_revision + 1
      ) {
        return failure("TOTP_STATE_CONFLICT");
      }
      this.ctx.storage.sql.exec("DELETE FROM totp_setup");
      this.revokeTransient();
      await this.reschedule();
      return { ok: true };
    });
  }

  async beginLogin(userID: string): Promise<TOTPLoginResult> {
    return this.exclusive(async () => {
      if (!this.bindUser(userID)) return failure("NOT_FOUND");
      const timeMs = Date.now();
      this.cleanup(timeMs);
      const user = await this.user(userID);
      if (
        !this.active(user) ||
        user.totp_enabled !== 1 ||
        !user.totp_secret_envelope
      ) return failure("TOTP_NOT_SETUP");
      const tempToken = `${userID}.${randomHex(32)}`;
      const tokenHash = await sha256(tempToken);
      const expiresAt = timeMs + TOTP_LOGIN_TTL_MS;
      this.ctx.storage.sql.exec("DELETE FROM totp_login_challenges");
      this.ctx.storage.sql.exec(
        `INSERT INTO totp_login_challenges(token_hash,revision,expires_at)
         VALUES(?,?,?)`,
        tokenHash,
        user.totp_revision,
        expiresAt,
      );
      await this.reschedule();
      return {
        ok: true,
        temp_token: tempToken,
        countdown: Math.floor(TOTP_LOGIN_TTL_MS / 1000),
      };
    });
  }

  async verifyLogin(
    userID: string,
    tempToken: string,
    code: string,
  ): Promise<TOTPLoginVerificationResult> {
    return this.exclusive(async () => {
      if (
        !this.bindUser(userID) ||
        !isBoundedString(tempToken, 128) ||
        !/^[0-9]{6}$/.test(code)
      ) return failure("TOTP_LOGIN_EXPIRED");
      const timeMs = Date.now();
      this.cleanup(timeMs);
      if (this.blocked(timeMs)) return failure("TOTP_TOO_MANY_ATTEMPTS");
      const tokenHash = await sha256(tempToken);
      const challenge = this.ctx.storage.sql.exec<LoginRow>(
        `SELECT token_hash,revision,expires_at FROM totp_login_challenges
         WHERE token_hash=?`,
        tokenHash,
      ).toArray()[0];
      if (!challenge || challenge.expires_at <= timeMs) {
        return failure("TOTP_LOGIN_EXPIRED");
      }
      const user = await this.user(userID);
      if (
        !this.active(user) ||
        user.totp_enabled !== 1 ||
        !user.totp_secret_envelope ||
        user.totp_revision !== challenge.revision
      ) {
        this.ctx.storage.sql.exec(
          "DELETE FROM totp_login_challenges WHERE token_hash=?",
          tokenHash,
        );
        await this.reschedule();
        return failure("TOTP_LOGIN_EXPIRED");
      }
      const secret = await decryptTOTPSecret(user.totp_secret_envelope, this.env);
      if (!secret) return failure("TOTP_UNAVAILABLE");
      if (!await validTOTPCode(secret, code, timeMs)) {
        this.failedAttempt(timeMs);
        await this.reschedule();
        return failure("TOTP_INVALID_CODE");
      }
      this.ctx.storage.sql.exec(
        "DELETE FROM totp_login_challenges WHERE token_hash=?",
        tokenHash,
      );
      this.clearAttempts();
      await this.reschedule();
      return { ok: true, user_id: userID };
    });
  }

  async verifyStepUp(
    userID: string,
    sessionID: string,
    code: string,
  ): Promise<TOTPStepUpResult> {
    return this.exclusive(async () => {
      if (
        !this.bindUser(userID) ||
        !isBoundedString(sessionID, 128, 8) ||
        !/^[0-9]{6}$/.test(code)
      ) return failure("TOTP_INVALID_CODE");
      const timeMs = Date.now();
      this.cleanup(timeMs);
      if (this.blocked(timeMs)) return failure("TOTP_TOO_MANY_ATTEMPTS");
      const user = await this.user(userID);
      if (
        !this.active(user) ||
        user.totp_enabled !== 1 ||
        !user.totp_secret_envelope
      ) return failure("TOTP_NOT_SETUP");
      const secret = await decryptTOTPSecret(user.totp_secret_envelope, this.env);
      if (!secret) return failure("TOTP_UNAVAILABLE");
      if (!await validTOTPCode(secret, code, timeMs)) {
        this.failedAttempt(timeMs);
        await this.reschedule();
        return failure("TOTP_INVALID_CODE");
      }
      const sessionHash = await sha256(sessionID);
      const expiresAt = timeMs + TOTP_STEP_UP_TTL_MS;
      this.ctx.storage.sql.exec(
        `INSERT INTO totp_step_up_grants(session_hash,revision,expires_at)
         VALUES(?,?,?)
         ON CONFLICT(session_hash) DO UPDATE SET
           revision=excluded.revision,expires_at=excluded.expires_at`,
        sessionHash,
        user.totp_revision,
        expiresAt,
      );
      this.clearAttempts();
      await this.reschedule();
      return {
        ok: true,
        expires_in: Math.floor(TOTP_STEP_UP_TTL_MS / 1000),
      };
    });
  }

  async hasStepUp(
    userID: string,
    sessionID: string,
  ): Promise<TOTPStepUpCheckResult> {
    return this.exclusive(async () => {
      if (!this.bindUser(userID) || !isBoundedString(sessionID, 128, 8)) {
        return failure("TOTP_NOT_SETUP");
      }
      const timeMs = Date.now();
      this.cleanup(timeMs);
      const user = await this.user(userID);
      if (
        !this.active(user) ||
        user.totp_enabled !== 1 ||
        !user.totp_secret_envelope
      ) return failure("TOTP_NOT_SETUP");
      const sessionHash = await sha256(sessionID);
      const grant = this.ctx.storage.sql.exec<GrantRow>(
        `SELECT session_hash,revision,expires_at FROM totp_step_up_grants
         WHERE session_hash=?`,
        sessionHash,
      ).toArray()[0];
      const granted = Boolean(
        grant &&
        grant.expires_at > timeMs &&
        grant.revision === user.totp_revision,
      );
      if (grant && !granted) {
        this.ctx.storage.sql.exec(
          "DELETE FROM totp_step_up_grants WHERE session_hash=?",
          sessionHash,
        );
      }
      await this.reschedule();
      return { ok: true, granted };
    });
  }

  async revokeAll(userID: string): Promise<TOTPOperationResult> {
    return this.exclusive(async () => {
      if (!this.bindUser(userID)) return failure("NOT_FOUND");
      this.ctx.storage.sql.exec("DELETE FROM totp_setup");
      this.revokeTransient();
      await this.reschedule();
      return { ok: true };
    });
  }

  async alarm(): Promise<void> {
    await this.exclusive(async () => {
      this.cleanup(Date.now());
      await this.reschedule();
    });
  }
}
