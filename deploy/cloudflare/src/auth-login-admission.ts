import { DurableObject } from "cloudflare:workers";

export const AUTH_LOGIN_ADMISSION_LIMIT = 20;
export const AUTH_LOGIN_ADMISSION_WINDOW_MS = 60_000;

export type AuthLoginAdmission =
  | { allowed: true }
  | { allowed: false; retry_after_seconds: number };

type AdmissionState = {
  window_start_ms: number;
  admissions: number;
};

/**
 * A single privacy-derived client shard's fixed-window login admission state.
 * The Worker is responsible for deriving an opaque shard name from the
 * authoritative edge identity; this object never receives an address.
 */
export class AuthLoginAdmissionDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS auth_login_admission_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        window_start_ms INTEGER NOT NULL,
        admissions INTEGER NOT NULL CHECK (admissions >= 0)
      );
    `);
  }

  async admit(timeMs: number): Promise<AuthLoginAdmission> {
    if (
      !Number.isSafeInteger(timeMs) ||
      timeMs < 0 ||
      timeMs > Number.MAX_SAFE_INTEGER - AUTH_LOGIN_ADMISSION_WINDOW_MS
    ) {
      throw new TypeError("invalid admission timestamp");
    }

    return this.ctx.storage.transactionSync<AuthLoginAdmission>(() => {
      const windowStart = timeMs - (timeMs % AUTH_LOGIN_ADMISSION_WINDOW_MS);
      const existing = this.ctx.storage.sql
        .exec<AdmissionState>(
          `SELECT window_start_ms, admissions
           FROM auth_login_admission_state WHERE id = 1`,
        )
        .toArray()[0];

      if (!existing) {
        this.ctx.storage.sql.exec(
          `INSERT INTO auth_login_admission_state(id, window_start_ms, admissions)
           VALUES(1, ?, 1)
           ON CONFLICT(id) DO UPDATE SET window_start_ms=excluded.window_start_ms,
                                         admissions=excluded.admissions`,
          windowStart,
        );
        return { allowed: true };
      }

      if (
        !Number.isSafeInteger(existing.window_start_ms) ||
        !Number.isSafeInteger(existing.admissions) ||
        existing.admissions < 0
      ) {
        throw new TypeError("invalid persisted admission state");
      }

      if (existing.window_start_ms !== windowStart) {
        this.ctx.storage.sql.exec(
          `UPDATE auth_login_admission_state
           SET window_start_ms=?, admissions=1 WHERE id=1`,
          windowStart,
        );
        return { allowed: true };
      }

      if (existing.admissions < AUTH_LOGIN_ADMISSION_LIMIT) {
        this.ctx.storage.sql.exec(
          "UPDATE auth_login_admission_state SET admissions=admissions+1 WHERE id=1",
        );
        return { allowed: true };
      }

      const remainingMs = windowStart + AUTH_LOGIN_ADMISSION_WINDOW_MS - timeMs;
      return {
        allowed: false,
        retry_after_seconds: Math.max(1, Math.ceil(remainingMs / 1000)),
      };
    });
  }
}
