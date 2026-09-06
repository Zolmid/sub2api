import { env, evictDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  AUTH_LOGIN_ADMISSION_WINDOW_MS,
  type AuthLoginAdmissionDO,
} from "../src/auth-login-admission";
import {
  authoritativeClientIdentity,
  routeIngress,
  type ContainerForwarder,
} from "../src/index";

type TestEnv = Env & { SUB2API_CF_LOGIN_ADMISSION_KEY?: string };

const testEnv = env as TestEnv;
const WINDOW_START = 1_700_000_040_000;
const WINDOW_TIME = WINDOW_START + 1_234;

const stubFor = (name: string) =>
  testEnv.AUTH_LOGIN_ADMISSION.get(
    testEnv.AUTH_LOGIN_ADMISSION.idFromName(name),
  );

function loginRequest(ip: string | null, body?: BodyInit): Request {
  const headers = new Headers();
  if (ip !== null) headers.set("CF-Connecting-IP", ip);
  return new Request("https://api.example.test/api/v1/auth/login", {
    method: "POST",
    headers,
    body,
  });
}

function forwardCounter(): {
  forward: ContainerForwarder;
  calls: () => number;
  request: () => Request | null;
} {
  let count = 0;
  let forwarded: Request | null = null;
  return {
    forward: async (request) => {
      count += 1;
      forwarded = request;
      return new Response("container", { status: 200 });
    },
    calls: () => count,
    request: () => forwarded,
  };
}

async function route(
  request: Request,
  envOverride: Env = testEnv,
  clock: () => number = () => WINDOW_TIME,
) {
  const counter = forwardCounter();
  const response = await routeIngress(
    request,
    envOverride,
    counter.forward,
    clock,
  );
  return { response, ...counter };
}

describe("AuthLoginAdmissionDO", () => {
  it("allows exactly 20 concurrent admissions and reports exact Retry-After", async () => {
    const stub = stubFor("auth-login-concurrent");
    const results = await Promise.all(
      Array.from({ length: 21 }, () => stub.admit(WINDOW_TIME)),
    );
    expect(results.filter((result) => result.allowed)).toHaveLength(20);
    expect(results.filter((result) => !result.allowed)).toEqual([
      { allowed: false, retry_after_seconds: 59 },
    ]);
  });

  it("resets the fixed window at rollover", async () => {
    const stub = stubFor("auth-login-rollover");
    const finalMoment = WINDOW_START + AUTH_LOGIN_ADMISSION_WINDOW_MS - 1;
    const firstWindow = await Promise.all(
      Array.from({ length: 20 }, () => stub.admit(finalMoment)),
    );
    expect(firstWindow.every((result) => result.allowed)).toBe(true);
    expect(await stub.admit(finalMoment)).toEqual({
      allowed: false,
      retry_after_seconds: 1,
    });
    expect(await stub.admit(WINDOW_START + AUTH_LOGIN_ADMISSION_WINDOW_MS)).toEqual({
      allowed: true,
    });
  });

  it("retains the admission count across a Durable Object eviction", async () => {
    const stub = stubFor("auth-login-eviction");
    await Promise.all(Array.from({ length: 20 }, () => stub.admit(WINDOW_TIME)));
    await evictDurableObject(stub);
    expect(await stub.admit(WINDOW_TIME)).toEqual({
      allowed: false,
      retry_after_seconds: 59,
    });
  });
});

describe("Worker login admission preflight", () => {
  it("isolates clients and does not call the Container for a limited login", async () => {
    const clientA = "203.0.113.10";
    const allowed = await Promise.all(
      Array.from({ length: 20 }, () => route(loginRequest(clientA))),
    );
    expect(allowed.every(({ response, calls }) => response.status === 200 && calls() === 1)).toBe(true);

    const limited = await route(loginRequest(clientA));
    expect(limited.response.status).toBe(429);
    expect(limited.response.headers.get("retry-after")).toBe("59");
    expect(await limited.response.json()).toEqual({
      error: {
        code: "LOGIN_ADMISSION_LIMITED",
        message: "LOGIN_ADMISSION_LIMITED",
      },
    });
    expect(limited.calls()).toBe(0);

    const isolated = await route(loginRequest("198.51.100.20"));
    expect(isolated.response.status).toBe(200);
    expect(isolated.calls()).toBe(1);
  });

  it("fails closed for absent or invalid authoritative client identity", async () => {
    const absent = await route(loginRequest(null));
    expect(absent.response.status).toBe(503);
    expect(absent.calls()).toBe(0);

    const request = loginRequest("not-an-address");
    request.headers.set("X-Forwarded-For", "203.0.113.1");
    const invalid = await route(request);
    expect(invalid.response.status).toBe(503);
    expect(invalid.calls()).toBe(0);

    expect(authoritativeClientIdentity("2001:db8::1")).toBe("2001:db8::1");
    expect(authoritativeClientIdentity("203.0.113.1, 198.51.100.1")).toBeNull();
    expect(authoritativeClientIdentity("203.0.113.256")).toBeNull();
  });

  it("fails closed when the key, binding, or Durable Object RPC is unavailable", async () => {
    const noSecret = new Proxy(testEnv, {
      get(target, property, receiver) {
        if (property === "SUB2API_CF_LOGIN_ADMISSION_KEY") return undefined;
        return Reflect.get(target, property, receiver);
      },
    }) as Env;
    const missingSecret = await route(loginRequest("203.0.113.30"), noSecret);
    expect(missingSecret.response.status).toBe(503);
    expect(missingSecret.calls()).toBe(0);

    const noBinding = new Proxy(testEnv, {
      get(target, property, receiver) {
        if (property === "AUTH_LOGIN_ADMISSION") return undefined;
        return Reflect.get(target, property, receiver);
      },
    }) as Env;
    const missingBinding = await route(loginRequest("203.0.113.31"), noBinding);
    expect(missingBinding.response.status).toBe(503);
    expect(missingBinding.calls()).toBe(0);

    const failedRpc = new Proxy(testEnv, {
      get(target, property, receiver) {
        if (property === "AUTH_LOGIN_ADMISSION") {
          return {
            getByName: () => ({
              admit: async () => {
                throw new Error("test RPC failure");
              },
            }),
          };
        }
        return Reflect.get(target, property, receiver);
      },
    }) as Env;
    const unavailable = await route(loginRequest("203.0.113.32"), failedRpc);
    expect(unavailable.response.status).toBe(503);
    expect(unavailable.calls()).toBe(0);
    expect(await unavailable.response.json()).toEqual({
      error: {
        code: "LOGIN_ADMISSION_UNAVAILABLE",
        message: "LOGIN_ADMISSION_UNAVAILABLE",
      },
    });
  });

  it("does not preflight non-login requests", async () => {
    const getLogin = new Request("https://api.example.test/api/v1/auth/login");
    const getResult = await route(getLogin);
    expect(getResult.response.status).toBe(200);
    expect(getResult.calls()).toBe(1);

    const other = await route(
      new Request("https://api.example.test/v1/chat/completions", {
        method: "POST",
      }),
    );
    expect(other.response.status).toBe(200);
    expect(other.calls()).toBe(1);
  });

  it("does not read a successful login request body before Container forwarding", async () => {
    const request = loginRequest("203.0.113.40", "sensitive-login-body");
    const result = await route(request);
    expect(result.response.status).toBe(200);
    expect(result.calls()).toBe(1);
    expect(request.bodyUsed).toBe(false);
    expect(result.request()).toBe(request);
    expect(result.request()!.bodyUsed).toBe(false);
  });
});
