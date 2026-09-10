import { getContainer } from "@cloudflare/containers";
import { INTERNAL_HOST } from "./contracts";
import type {
  JobExecutor,
  JobExecutorMap,
  JobExecutorResult,
} from "./job-worker";
import type { JobRecord } from "./job-runtime";
import { createSubscriptionExpiryMaintenanceExecutor } from "./subscription-expiry-job";

export const JOB_EXECUTION_PRIVATE_PATH = "/internal/cloudflare/jobs/execute";
export const JOB_EXECUTION_RPC_VERSION = 1 as const;
export const MAX_JOB_EXECUTION_PAYLOAD_BYTES = 262_144;
export const MAX_JOB_EXECUTION_RESPONSE_BYTES = 8_192;

export const BACKGROUND_JOB_ROUTES = {
  OAUTH_REFRESH_V1: "oauth-refresh.v1",
  EMAIL_DELIVERY_V1: "email-delivery.v1",
  PAYMENT_RECONCILIATION_V1: "payment-reconciliation.v1",
  SUBSCRIPTION_EXPIRY_MAINTENANCE_V1: "subscription-expiry-maintenance.v1",
} as const;

export const REGISTERED_BACKGROUND_JOB_ROUTES = Object.freeze(
  Object.values(BACKGROUND_JOB_ROUTES),
);

type BackgroundJobRoute = (typeof REGISTERED_BACKGROUND_JOB_ROUTES)[number];
type ContainerBackgroundJobRoute = Exclude<
  BackgroundJobRoute,
  typeof BACKGROUND_JOB_ROUTES.SUBSCRIPTION_EXPIRY_MAINTENANCE_V1
>;

type ContainerJobEnv = Pick<Env, "SUB2API_CONTAINER">;

type ContainerDispatch = (request: Request) => Promise<Response>;

const OPAQUE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;
const encoder = new TextEncoder();

function boundedOpaque(value: unknown, maximum: number): value is string {
  return typeof value === "string" &&
    value.length >= 1 &&
    value.length <= maximum &&
    value.trim() === value &&
    OPAQUE.test(value);
}

function plainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length &&
    keys.every((key) => typeof key === "string" && expected.includes(key)) &&
    expected.every((key) => Object.prototype.propertyIsEnumerable.call(value, key));
}

function manual(reasonCode: string, evidenceRef: string): JobExecutorResult {
  return { kind: "manual_review", reasonCode, evidenceRef };
}

function jobEvidence(job: JobRecord): string {
  return `job:${job.jobId}`;
}

function rpcEnvelope(job: JobRecord, payloadBody: string): string {
  return JSON.stringify({
    v: JOB_EXECUTION_RPC_VERSION,
    method: "sub2api.cloudflare.jobs.execute",
    params: {
      job: {
        id: job.jobId,
        version: job.version,
        route: job.route,
        type: job.jobType,
        idempotencyKey: job.idempotencyKey,
      },
      payload: {
        codec: job.payloadCodec,
        body: payloadBody,
        digest: job.payloadDigest,
      },
    },
  });
}

async function readBoundedText(
  response: Response,
): Promise<"too_large" | "decode_error" | string> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const parsed = Number(contentLength);
    if (
      !Number.isSafeInteger(parsed) ||
      parsed < 0 ||
      parsed > MAX_JOB_EXECUTION_RESPONSE_BYTES
    ) {
      return "too_large";
    }
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) {
        received += value.byteLength;
        if (received > MAX_JOB_EXECUTION_RESPONSE_BYTES) {
          await reader.cancel();
          return "too_large";
        }
        chunks.push(value);
      }
    }
    const body = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body);
  } catch {
    return "decode_error";
  }
}

function parseContainerResult(value: unknown): JobExecutorResult | null {
  if (!plainObject(value) || value.v !== JOB_EXECUTION_RPC_VERSION) return null;
  if (value.kind === "succeeded") {
    return hasExactKeys(value, ["v", "kind", "resultDigest"]) &&
      boundedOpaque(value.resultDigest, 160)
      ? { kind: "succeeded", resultDigest: value.resultDigest }
      : null;
  }
  if (value.kind === "retryable_failure") {
    return hasExactKeys(value, ["v", "kind", "errorCode"]) &&
      boundedOpaque(value.errorCode, 96)
      ? { kind: "retryable_failure", errorCode: value.errorCode }
      : null;
  }
  if (value.kind === "permanent_failure") {
    return hasExactKeys(value, ["v", "kind", "errorCode"]) &&
      boundedOpaque(value.errorCode, 96)
      ? { kind: "permanent_failure", errorCode: value.errorCode }
      : null;
  }
  if (value.kind === "manual_review") {
    return hasExactKeys(value, ["v", "kind", "reasonCode", "evidenceRef"]) &&
      boundedOpaque(value.reasonCode, 96) &&
      boundedOpaque(value.evidenceRef, 256)
      ? {
        kind: "manual_review",
        reasonCode: value.reasonCode,
        evidenceRef: value.evidenceRef,
      }
      : null;
  }
  return null;
}

export async function executeJobInGatewayContainer(
  input: Parameters<JobExecutor>[0],
  dispatch: ContainerDispatch,
): Promise<JobExecutorResult> {
  if (encoder.encode(input.payloadBody).byteLength > MAX_JOB_EXECUTION_PAYLOAD_BYTES) {
    return manual("payload_too_large", jobEvidence(input.job));
  }

  let response: Response;
  try {
    response = await dispatch(new Request(
      `http://${INTERNAL_HOST}${JOB_EXECUTION_PRIVATE_PATH}`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "cache-control": "no-store",
        },
        body: rpcEnvelope(input.job, input.payloadBody),
      },
    ));
  } catch {
    return manual("container_dispatch_failed", jobEvidence(input.job));
  }

  if (response.status !== 200) {
    return manual("container_http_status", `container:http:${response.status}`);
  }

  const text = await readBoundedText(response);
  if (text === "too_large") {
    return manual("container_response_too_large", jobEvidence(input.job));
  }
  if (text === "decode_error") {
    return manual("container_response_non_json", jobEvidence(input.job));
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return manual("container_response_non_json", jobEvidence(input.job));
  }

  const result = parseContainerResult(parsed);
  return result ?? manual("container_response_invalid", jobEvidence(input.job));
}

export function createGatewayJobExecutors(
  env: ContainerJobEnv,
  dispatch: ContainerDispatch = (request: Request) =>
    getContainer(env.SUB2API_CONTAINER, "gateway").fetch(request),
): JobExecutorMap {
  const entries = REGISTERED_BACKGROUND_JOB_ROUTES.filter(
    (route): route is ContainerBackgroundJobRoute =>
      route !== BACKGROUND_JOB_ROUTES.SUBSCRIPTION_EXPIRY_MAINTENANCE_V1,
  ).map(
    (route): readonly [ContainerBackgroundJobRoute, JobExecutor] => [
      route,
      (input) => executeJobInGatewayContainer(input, dispatch),
    ],
  );
  return Object.freeze(Object.fromEntries(entries)) as JobExecutorMap;
}

/** The subscription expiry route is the sole Worker-local background executor. */
export function createWorkerJobExecutors(
  env: Pick<Env, "DB" | "SUB2API_CONTAINER">,
  dispatch?: ContainerDispatch,
): JobExecutorMap {
  return Object.freeze({
    ...createGatewayJobExecutors(env, dispatch),
    [BACKGROUND_JOB_ROUTES.SUBSCRIPTION_EXPIRY_MAINTENANCE_V1]:
      createSubscriptionExpiryMaintenanceExecutor(env.DB),
  });
}
