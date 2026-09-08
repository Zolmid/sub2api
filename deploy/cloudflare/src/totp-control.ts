import {
  error,
  isBoundedString,
  isCanonicalPositiveDecimal,
  json,
  readJson,
} from "./contracts";
import type {
  TOTPSecurityFailure,
  TOTPSecurityCode,
} from "./totp-security";

const paths = new Set([
  "/v1/private/totp/status",
  "/v1/private/totp/setup/begin",
  "/v1/private/totp/setup/complete",
  "/v1/private/totp/disable",
  "/v1/private/totp/login/begin",
  "/v1/private/totp/login/verify",
  "/v1/private/totp/step-up/verify",
  "/v1/private/totp/step-up/check",
  "/v1/private/totp/revoke",
]);

function only(body: Record<string, unknown>, allowed: readonly string[]): boolean {
  const names = new Set(allowed);
  return Object.keys(body).every((key) => names.has(key));
}

function userID(value: unknown): value is string {
  return isCanonicalPositiveDecimal(value) && value.length <= 20;
}

function code(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}

function statusFor(code: TOTPSecurityCode): number {
  switch (code) {
    case "NOT_FOUND":
      return 404;
    case "TOTP_ALREADY_ENABLED":
    case "TOTP_STATE_CONFLICT":
      return 409;
    case "TOTP_TOO_MANY_ATTEMPTS":
      return 429;
    case "TOTP_UNAVAILABLE":
      return 503;
    default:
      return 400;
  }
}

function result(value: { ok: true } | TOTPSecurityFailure): Response {
  if (!value.ok) return error(value.code, statusFor(value.code));
  const { ok: _ok, ...body } = value;
  return json(body);
}

function stub(env: Env, id: string) {
  return env.TOTP_SECURITY.get(
    env.TOTP_SECURITY.idFromName(`user:${id}`),
  );
}

function loginUserID(token: string): string | null {
  const matched = /^([1-9][0-9]{0,19})\.[0-9a-f]{64}$/.exec(token);
  return matched && userID(matched[1]) ? matched[1] : null;
}

export function isTOTPControlPath(path: string): boolean {
  return paths.has(path);
}

export async function totpControlPlane(
  request: Request,
  env: Env,
  path: string,
): Promise<Response> {
  if (
    !isBoundedString(
      request.headers.get("X-Sub2API-Container-Id"),
      256,
    )
  ) return error("NOT_FOUND", 404);
  const body = await readJson<Record<string, unknown>>(request);
  if (!body) return error("INVALID_REQUEST");

  switch (path) {
    case "/v1/private/totp/status": {
      if (!only(body, ["user_id"]) || !userID(body.user_id)) {
        return error("INVALID_REQUEST");
      }
      return result(await stub(env, body.user_id).status(body.user_id));
    }
    case "/v1/private/totp/setup/begin": {
      if (!only(body, ["user_id"]) || !userID(body.user_id)) {
        return error("INVALID_REQUEST");
      }
      return result(await stub(env, body.user_id).beginSetup(body.user_id));
    }
    case "/v1/private/totp/setup/complete": {
      if (
        !only(body, ["user_id", "setup_token", "totp_code"]) ||
        !userID(body.user_id) ||
        !isBoundedString(body.setup_token, 128) ||
        !code(body.totp_code)
      ) return error("INVALID_REQUEST");
      return result(await stub(env, body.user_id).completeSetup(
        body.user_id,
        body.setup_token,
        body.totp_code,
      ));
    }
    case "/v1/private/totp/disable":
    case "/v1/private/totp/revoke": {
      if (!only(body, ["user_id"]) || !userID(body.user_id)) {
        return error("INVALID_REQUEST");
      }
      return result(path.endsWith("/disable")
        ? await stub(env, body.user_id).disable(body.user_id)
        : await stub(env, body.user_id).revokeAll(body.user_id));
    }
    case "/v1/private/totp/login/begin": {
      if (!only(body, ["user_id"]) || !userID(body.user_id)) {
        return error("INVALID_REQUEST");
      }
      return result(await stub(env, body.user_id).beginLogin(body.user_id));
    }
    case "/v1/private/totp/login/verify": {
      if (
        !only(body, ["temp_token", "totp_code"]) ||
        !isBoundedString(body.temp_token, 128) ||
        !code(body.totp_code)
      ) return error("INVALID_REQUEST");
      const id = loginUserID(body.temp_token);
      if (!id) return error("TOTP_LOGIN_EXPIRED", 400);
      return result(await stub(env, id).verifyLogin(
        id,
        body.temp_token,
        body.totp_code,
      ));
    }
    case "/v1/private/totp/step-up/verify": {
      if (
        !only(body, ["user_id", "session_id", "totp_code"]) ||
        !userID(body.user_id) ||
        !isBoundedString(body.session_id, 128, 8) ||
        !code(body.totp_code)
      ) return error("INVALID_REQUEST");
      return result(await stub(env, body.user_id).verifyStepUp(
        body.user_id,
        body.session_id,
        body.totp_code,
      ));
    }
    case "/v1/private/totp/step-up/check": {
      if (
        !only(body, ["user_id", "session_id"]) ||
        !userID(body.user_id) ||
        !isBoundedString(body.session_id, 128, 8)
      ) return error("INVALID_REQUEST");
      return result(await stub(env, body.user_id).hasStepUp(
        body.user_id,
        body.session_id,
      ));
    }
    default:
      return error("NOT_FOUND", 404);
  }
}
