import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { controlPlane } from "../src/control-plane";
import { BRIDGE_VERSION, MAX_CONTROL_BODY_BYTES } from "../src/contracts";
import { subscriptionControlRoutes } from "../src/subscription-control";

const at = "2026-09-10T00:00:00.000Z";

function id(): string {
  return "8" + String(crypto.getRandomValues(new Uint32Array(1))[0]).padStart(10, "0");
}

function request(
  path: string,
  body: BodyInit | null,
  options: {
    method?: string;
    host?: string;
    version?: string;
    container?: string;
    contentLength?: string;
  } = {},
): Request {
  const method = options.method ?? "POST";
  return new Request(`http://${options.host ?? "sub2api.internal"}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      "X-Sub2API-Bridge-Version": options.version ?? BRIDGE_VERSION,
      ...(options.container === "" ? {} : {
        "X-Sub2API-Container-Id": options.container ?? "subscription-control-test",
      }),
      ...(options.contentLength === undefined ? {} : { "content-length": options.contentLength }),
    },
    body: method === "GET" || method === "HEAD" ? null : body,
  });
}

async function call(
  path: string,
  body: unknown,
  options?: Parameters<typeof request>[2],
  targetEnv: Env = env,
): Promise<Response> {
  return controlPlane(request(path, JSON.stringify(body), options), targetEnv);
}

async function expectError(response: Response, status: number, code: string) {
  expect(response.status).toBe(status);
  expect(await response.json()).toEqual({ error: { code, message: code } });
}

async function seedReferences(userID: string, groupID: string, adminID: string) {
  const user = (id: string, role: "user" | "admin") => env.DB.prepare(`INSERT INTO users(
    id,status,role,concurrency,balance_e8_usd,allowed_group_ids_json,restrict_public_groups,
    created_at,updated_at,email,password_hash,username,notes,rpm_limit,deleted_at
  ) VALUES(?,?,?,?,?,'[]',0,?,?,?,?,?,?,0,NULL)`).bind(
    id, "active", role, 1, "0", at, at, `${id}@subscription-control.test`, "", `user-${id}`, "",
  );
  await env.DB.batch([
    user(userID, "user"),
    user(adminID, "admin"),
    env.DB.prepare(`INSERT INTO groups(
      id,name,platform,status,is_exclusive,subscription_type,created_at,updated_at,deleted_at
    ) VALUES(?,?,?,?,0,'subscription',?,?,NULL)`).bind(
      groupID, `group-${groupID}`, "openai", "active", at, at,
    ),
  ]);
}

function planInput(operationID: string, planID: string, groupID: string, adminID: string) {
  return {
    operation_id: operationID,
    id: planID,
    group_id: groupID,
    name: "Bridge plan",
    description: "",
    price_e8_usd: "0",
    original_price_e8_usd: null,
    daily_limit_e8_usd: null,
    weekly_limit_e8_usd: null,
    monthly_limit_e8_usd: null,
    currency: "USD",
    validity_days: 30,
    validity_unit: "day",
    features: "",
    product_name: "",
    for_sale: true,
    sort_order: 0,
    actor_user_id: adminID,
    at,
  };
}

describe("subscription control plane", () => {
  it("dispatches a successful operation and preserves the runtime response", async () => {
    const userID = id();
    const groupID = id();
    const adminID = id();
    const planID = id();
    await seedReferences(userID, groupID, adminID);

    const response = await call(
      "/v1/subscriptions/plans/create",
      planInput(`subscription-plan-${planID}`, planID, groupID, adminID),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      plan: expect.objectContaining({
        id: planID,
        group_id: groupID,
        price_e8_usd: "0",
        version: 1,
      }),
    });
  });

  it("makes every registered runtime operation reachable", async () => {
    for (const path of Object.keys(subscriptionControlRoutes)) {
      await expectError(await call(path, {}), 400, "MISSING_FIELD");
    }
  });

  it("fails closed before dispatch for malformed, oversized, unknown, and private-boundary requests", async () => {
    await expectError(
      await controlPlane(request("/v1/subscriptions/list", "{", {}), env),
      400,
      "INVALID_REQUEST",
    );
    await expectError(
      await controlPlane(request("/v1/subscriptions/list", "{}", {
        contentLength: String(MAX_CONTROL_BODY_BYTES + 1),
      }), env),
      400,
      "INVALID_REQUEST",
    );
    await expectError(await call("/v1/subscriptions/list", { unexpected: true }), 400, "UNKNOWN_FIELD");

    for (const options of [
      { method: "GET" },
      { host: "public.example" },
      { version: "wrong-version" },
      { container: "" },
    ]) {
      await expectError(await call("/v1/subscriptions/list", {}, options), 404, "NOT_FOUND");
    }
    await expectError(await call("/v1/subscriptions/unknown", {}), 404, "NOT_FOUND");
  });

  it("maps runtime input, absence, and conflict codes to stable protocol responses", async () => {
    await expectError(
      await call("/v1/subscriptions/plans/get", { id: "999999999", include_deleted: false }),
      404,
      "PLAN_NOT_FOUND",
    );

    const userID = id();
    const groupID = id();
    const adminID = id();
    const subscriptionID = id();
    await seedReferences(userID, groupID, adminID);
    const assigned = await call("/v1/subscriptions/assign-or-extend", {
      operation_id: `subscription-assign-${subscriptionID}`,
      new_subscription_id: subscriptionID,
      user_id: userID,
      group_id: groupID,
      plan_id: null,
      validity_days: 30,
      assigned_by: null,
      notes: "",
      now: "2026-09-10T12:00:00Z",
      daily_boundary: "2026-09-10T00:00:00Z",
    });
    expect(assigned.status).toBe(200);
    await expectError(await call("/v1/subscriptions/revoke", {
      operation_id: `subscription-stale-${subscriptionID}`,
      subscription_id: subscriptionID,
      expected_version: 2,
      actor_user_id: adminID,
      at: "2026-09-10T12:01:00Z",
    }), 409, "STALE_VERSION");
  });

  it("redacts D1 and unexpected failures as one availability error", async () => {
    const failingEnv = new Proxy(env, {
      get(target, property, receiver) {
        if (property === "DB") {
          return { prepare: () => { throw new Error("private D1 failure detail"); } };
        }
        return Reflect.get(target, property, receiver);
      },
    }) as Env;

    const response = await call("/v1/subscriptions/list", {
      user_id: null,
      group_id: null,
      status: null,
      include_deleted: false,
      after_id: null,
      limit: 1,
    }, undefined, failingEnv);
    expect(response.status).toBe(503);
    const body = await response.json();
    expect(body).toEqual({
      error: { code: "SUBSCRIPTION_UNAVAILABLE", message: "SUBSCRIPTION_UNAVAILABLE" },
    });
    expect(JSON.stringify(body)).not.toContain("private D1 failure detail");
  });
});
