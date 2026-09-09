import { describe, expect, it } from "vitest";
import {
  JOB_STATE_LIMITS,
  acquire,
  cancel,
  complete,
  fail,
  recoverExpired,
  renew,
  retryDelayMs,
  start,
  submit,
  type Authority,
  type Job,
  type Submission,
  type TransitionOutcome,
} from "../src/job-state";

const submission = (nowMs = 100): Submission => ({
  key: {
    namespace: "accounts",
    type: "refresh",
    idempotencyKey: "request-1",
  },
  payload: {
    digest: "sha256:payload",
    reference: "d1:job-payload-1",
  },
  retryPolicy: {
    maxAttempts: 3,
    baseDelayMs: 10,
    maxDelayMs: 100,
    jitterBasisPoints: 1_000,
    jitterSeed: "seed-a",
  },
  nowMs,
});

const jobOf = (outcome: { job?: Job }): Job => {
  if (!outcome.job) throw new Error("expected a valid job outcome");
  return outcome.job;
};

const fresh = (): Job => jobOf(submit(undefined, submission()));

const acquireAt = (
  job: Job,
  nowMs = 100,
  owner = "worker-a",
  deliveryId = "queue-1",
): TransitionOutcome =>
  acquire(job, { owner, deliveryId, nowMs, leaseMs: 50 });

const authority = (job: Job): Authority => {
  if (!job.lease) throw new Error("expected an active lease");
  return {
    owner: job.lease.owner,
    deliveryId: job.lease.deliveryId,
    fence: job.lease.fence,
  };
};

const running = (): Job => {
  let job = jobOf(acquireAt(fresh()));
  job = jobOf(start(job, { ...authority(job), nowMs: 101 }));
  return job;
};

const succeeded = (): Job => {
  const job = running();
  return jobOf(complete(job, {
    ...authority(job),
    nowMs: 102,
    result: { digest: "sha256:result", reference: "d1:result-1" },
  }));
};

describe("background job state machine", () => {
  it("requires complete payload and retry-policy equality for replay", () => {
    const first = submit(undefined, submission());
    expect(first.code).toBe("SUBMITTED");
    expect(submit(first.job, submission()).code).toBe("IDEMPOTENT_SUBMISSION");
    expect(submit(first.job, {
      ...submission(),
      payload: { digest: "sha256:other" },
    }).code).toBe("IDEMPOTENCY_CONFLICT");
    expect(submit(first.job, {
      ...submission(),
      payload: { ...submission().payload, reference: "d1:moved" },
    }).code).toBe("IDEMPOTENCY_CONFLICT");
    expect(submit(first.job, {
      ...submission(),
      payload: { digest: submission().payload.digest, reference: null },
    }).code).toBe("IDEMPOTENCY_CONFLICT");
    expect(submit(first.job, {
      ...submission(),
      retryPolicy: { ...submission().retryPolicy, maxAttempts: 4 },
    }).code).toBe("IDEMPOTENCY_CONFLICT");

    const withNull = submit(undefined, {
      ...submission(),
      payload: { digest: "sha256:payload", reference: null },
    });
    expect(submit(withNull.job, {
      ...submission(),
      payload: { digest: "sha256:payload", reference: null },
    }).code).toBe("IDEMPOTENT_SUBMISSION");
    expect(submit(withNull.job, {
      ...submission(),
      payload: { digest: "sha256:payload" },
    }).code).toBe("IDEMPOTENCY_CONFLICT");
  });

  it("fails closed for null, arrays, malformed objects, and hostile accessors", () => {
    const hostile = new Proxy({}, {
      get() {
        throw new Error("must be contained");
      },
      ownKeys() {
        throw new Error("must be contained");
      },
    });
    const malformed: unknown[] = [
      undefined,
      null,
      [],
      {},
      "bad",
      true,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      1n,
      Symbol("bad"),
      () => undefined,
      hostile,
    ];
    const validJob = fresh();
    const transitions = [acquire, renew, start, complete, fail, cancel, recoverExpired];

    for (const value of malformed) {
      expect(() => submit(undefined, value)).not.toThrow();
      expect(submit(undefined, value).code).toBe("INVALID_INPUT");
      expect(() => retryDelayMs(value, 1)).not.toThrow();
      expect(retryDelayMs(value, 1)).toBeUndefined();
      for (const transition of transitions) {
        expect(() => transition(validJob, value)).not.toThrow();
        expect(transition(validJob, value).code).toBe("INVALID_INPUT");
      }
    }
  });

  it("contains values that become hostile after runtime validation", () => {
    const unstableJob = (): unknown => {
      let statusReads = 0;
      return new Proxy(fresh(), {
        get(target, property, receiver) {
          if (property === "status" && ++statusReads === 4) {
            throw new Error("became hostile after validation");
          }
          return Reflect.get(target, property, receiver);
        },
      });
    };
    const calls: Array<(job: unknown) => TransitionOutcome> = [
      (job) => acquire(job, {
        owner: "worker-a",
        deliveryId: "queue-1",
        nowMs: 100,
        leaseMs: 10,
      }),
      (job) => renew(job, {
        owner: "worker-a",
        deliveryId: "queue-1",
        fence: 1,
        nowMs: 100,
        leaseMs: 10,
      }),
      (job) => start(job, {
        owner: "worker-a",
        deliveryId: "queue-1",
        fence: 1,
        nowMs: 100,
      }),
      (job) => complete(job, {
        owner: "worker-a",
        deliveryId: "queue-1",
        fence: 1,
        nowMs: 100,
        result: { digest: "sha256:result" },
      }),
      (job) => fail(job, {
        owner: "worker-a",
        deliveryId: "queue-1",
        fence: 1,
        nowMs: 100,
        kind: "started_known_failure",
        retryable: false,
      }),
      (job) => cancel(job, { nowMs: 100 }),
      (job) => recoverExpired(job, { nowMs: 100 }),
    ];
    for (const call of calls) {
      expect(() => call(unstableJob())).not.toThrow();
      expect(call(unstableJob())).toEqual({
        code: "INVALID_JOB",
        changed: false,
      });
    }

    const unstableSubmissionJob = (): unknown => {
      let keyReads = 0;
      return new Proxy(fresh(), {
        get(target, property, receiver) {
          if (property === "key" && ++keyReads === 2) {
            throw new Error("became hostile after validation");
          }
          return Reflect.get(target, property, receiver);
        },
      });
    };
    expect(() => submit(unstableSubmissionJob(), submission())).not.toThrow();
    expect(submit(unstableSubmissionJob(), submission())).toEqual({
      code: "INVALID_JOB",
      changed: false,
    });

    const unstablePolicy = (): unknown => {
      let maxAttemptReads = 0;
      return new Proxy({
        maxAttempts: 3,
        baseDelayMs: 1,
        maxDelayMs: 10,
      }, {
        get(target, property, receiver) {
          if (property === "maxAttempts" && ++maxAttemptReads === 4) {
            throw new Error("became hostile after validation");
          }
          return Reflect.get(target, property, receiver);
        },
      });
    };
    expect(() => retryDelayMs(unstablePolicy(), 1)).not.toThrow();
    expect(retryDelayMs(unstablePolicy(), 1)).toBeUndefined();
  });

  it("rejects corrupted persisted jobs and every malformed nested shape", () => {
    const pending = fresh();
    const leased = jobOf(acquireAt(pending));
    const done = succeeded();
    const cancelledAfterLease = jobOf(cancel(leased, { nowMs: 101 }));
    const corrupted: unknown[] = [
      null,
      [],
      {},
      { ...pending, unexpected: true },
      { ...pending, key: null },
      { ...pending, key: { ...pending.key, credential: "forbidden" } },
      { ...pending, payload: [] },
      { ...pending, payload: { ...pending.payload, bytes: "forbidden" } },
      { ...pending, retryPolicy: { ...pending.retryPolicy, maxAttempts: 0 } },
      { ...pending, status: "unknown" },
      { ...pending, createdAtMs: Number.NaN },
      { ...pending, updatedAtMs: Number.POSITIVE_INFINITY },
      { ...pending, nextAttemptAtMs: Number.MAX_SAFE_INTEGER + 1 },
      { ...pending, attempts: null },
      { ...pending, attempts: new Array(4).fill(null) },
      { ...leased, attempts: [{ ...leased.attempts[0], fence: 0 }] },
      { ...leased, attempts: [{ ...leased.attempts[0], startedAtMs: undefined }] },
      { ...leased, lease: { ...leased.lease, expiresAtMs: 99 } },
      { ...leased, lease: { ...leased.lease, owner: "worker a" } },
      {
        ...leased,
        audit: [leased.audit[0], { atMs: 100, code: "leased" }],
      },
      { ...pending, lease: undefined },
      { ...pending, audit: [{ atMs: 100, code: "secret", token: "x" }] },
      { ...pending, audit: [{ atMs: Number.NaN, code: "submitted" }] },
      {
        ...pending,
        audit: new Array(JOB_STATE_LIMITS.maxAuditFacts + 1)
          .fill(pending.audit[0]),
      },
      { ...pending, nextFence: 0 },
      { ...pending, nextFence: Number.MAX_SAFE_INTEGER + 1 },
      { ...pending, nextFence: Number.MAX_SAFE_INTEGER },
      { ...done, result: { ...done.result, objectBytes: "forbidden" } },
      { ...done, result: { ...done.result, reference: undefined } },
      { ...pending, result: undefined },
      { ...done, status: "running" },
      {
        ...cancelledAfterLease,
        attempts: [{
          ...cancelledAfterLease.attempts[0],
          startedAtMs: 100,
        }],
      },
    ];
    const calls: Array<(job: unknown) => TransitionOutcome> = [
      (job) => acquire(job, {
        owner: "worker-a",
        deliveryId: "queue-1",
        nowMs: 200,
        leaseMs: 10,
      }),
      (job) => renew(job, {
        owner: "worker-a",
        deliveryId: "queue-1",
        fence: 1,
        nowMs: 200,
        leaseMs: 10,
      }),
      (job) => start(job, {
        owner: "worker-a",
        deliveryId: "queue-1",
        fence: 1,
        nowMs: 200,
      }),
      (job) => complete(job, {
        owner: "worker-a",
        deliveryId: "queue-1",
        fence: 1,
        nowMs: 200,
        result: { digest: "sha256:result" },
      }),
      (job) => fail(job, {
        owner: "worker-a",
        deliveryId: "queue-1",
        fence: 1,
        nowMs: 200,
        kind: "started_known_failure",
        retryable: false,
      }),
      (job) => cancel(job, { nowMs: 200 }),
      (job) => recoverExpired(job, { nowMs: 200 }),
    ];

    for (const job of corrupted) {
      expect(submit(job, submission()).code).toBe("INVALID_JOB");
      for (const call of calls) {
        expect(() => call(job)).not.toThrow();
        expect(call(job)).toEqual({ code: "INVALID_JOB", changed: false });
      }
    }
  });

  it("rejects unknown fields and invalid nested values without mutation", () => {
    const job = fresh();
    const symbol = Symbol("forbidden");
    const acquireResult = acquire(job, {
      owner: "worker-a",
      deliveryId: "queue-1",
      nowMs: 100,
      leaseMs: 10,
      credential: "forbidden",
    });
    expect(acquireResult).toEqual({
      code: "INVALID_INPUT",
      changed: false,
      job,
    });
    expect(submit(undefined, {
      ...submission(),
      payload: { ...submission().payload, secret: "forbidden" },
    }).code).toBe("INVALID_INPUT");
    expect(submit(undefined, {
      ...submission(),
      [symbol]: "forbidden",
    }).code).toBe("INVALID_INPUT");

    const active = running();
    expect(complete(active, {
      ...authority(active),
      nowMs: 102,
      result: { digest: "sha256:result", bytes: [1, 2, 3] },
    }).code).toBe("INVALID_INPUT");
  });

  it("separates bounded identifiers from references containing spaces", () => {
    expect(submit(undefined, {
      ...submission(),
      payload: {
        digest: "sha256:payload",
        reference: "d1:folder with spaces/item",
      },
    }).code).toBe("SUBMITTED");
    expect(submit(undefined, {
      ...submission(),
      key: { ...submission().key, namespace: " leading" },
    }).code).toBe("INVALID_INPUT");
    expect(submit(undefined, {
      ...submission(),
      payload: { digest: "sha256:payload\n" },
    }).code).toBe("INVALID_INPUT");
    expect(submit(undefined, {
      ...submission(),
      payload: { digest: "sha256:\u0085payload" },
    }).code).toBe("INVALID_INPUT");
    expect(submit(undefined, {
      ...submission(),
      payload: { digest: "sha256:payload", reference: " trailing " },
    }).code).toBe("INVALID_INPUT");
    expect(submit(undefined, {
      ...submission(),
      key: { ...submission().key, type: "bad\ud800" },
    }).code).toBe("INVALID_INPUT");
    expect(submit(undefined, {
      ...submission(),
      retryPolicy: {
        ...submission().retryPolicy,
        jitterSeed: undefined,
      },
    }).code).toBe("INVALID_INPUT");
    expect(submit(undefined, {
      ...submission(),
      key: {
        ...submission().key,
        namespace: "😀".repeat(49),
      },
    }).code).toBe("INVALID_INPUT");
    expect(submit(undefined, {
      ...submission(),
      key: {
        ...submission().key,
        namespace: "😀".repeat(48),
      },
    }).code).toBe("SUBMITTED");

    const oversizedInputs: unknown[] = [
      {
        ...submission(),
        key: {
          ...submission().key,
          namespace: "n".repeat(JOB_STATE_LIMITS.maxNamespaceLength + 1),
        },
      },
      {
        ...submission(),
        payload: {
          digest: "d".repeat(JOB_STATE_LIMITS.maxDigestLength + 1),
        },
      },
      {
        ...submission(),
        payload: {
          digest: "sha256:payload",
          reference: "r".repeat(JOB_STATE_LIMITS.maxReferenceLength + 1),
        },
      },
      { ...submission(), nowMs: Number.NaN },
      { ...submission(), nowMs: Number.POSITIVE_INFINITY },
      { ...submission(), nowMs: Number.MAX_SAFE_INTEGER + 1 },
    ];
    for (const input of oversizedInputs) {
      expect(() => submit(undefined, input)).not.toThrow();
      expect(submit(undefined, input).code).toBe("INVALID_INPUT");
    }
  });

  it("makes active duplicate delivery a no-op but requires expiry recovery", () => {
    const leased = jobOf(acquireAt(fresh()));
    expect(acquireAt(leased, 110)).toEqual({
      code: "DUPLICATE_DELIVERY",
      changed: false,
      job: leased,
    });
    expect(acquireAt(leased, 150).code).toBe("LEASE_EXPIRED");
  });

  it("makes only an authority-and-result exact completion a duplicate", () => {
    const done = succeeded();
    const exact = complete(done, {
      owner: "worker-a",
      deliveryId: "queue-1",
      fence: 1,
      nowMs: 500,
      result: { digest: "sha256:result", reference: "d1:result-1" },
    });
    expect(exact).toEqual({ code: "DUPLICATE_COMPLETION", changed: false, job: done });
    expect(complete(done, {
      owner: "worker-b",
      deliveryId: "queue-1",
      fence: 1,
      nowMs: 500,
      result: { digest: "sha256:result", reference: "d1:result-1" },
    }).code).toBe("STALE_AUTHORITY");
    expect(complete(done, {
      owner: "worker-a",
      deliveryId: "queue-1",
      fence: 1,
      nowMs: 500,
      result: { digest: "sha256:different" },
    }).code).toBe("TERMINAL_IMMUTABLE");
    expect(complete(done, {
      owner: "worker-a",
      deliveryId: "queue-1",
      fence: 1,
      nowMs: 500,
      result: { digest: "sha256:result" },
    }).code).toBe("TERMINAL_IMMUTABLE");
    expect(complete(done, {
      owner: "worker-a",
      deliveryId: "queue-1",
      fence: 0,
      nowMs: 500,
      result: { digest: "sha256:result", reference: "d1:result-1" },
    }).code).toBe("INVALID_INPUT");
  });

  it("rejects stale fences and out-of-order events without changing authority", () => {
    let job = jobOf(acquireAt(fresh()));
    const oldAuthority = authority(job);
    job = jobOf(recoverExpired(job, { nowMs: 150 }));
    job = jobOf(acquireAt(job, job.nextAttemptAtMs, "worker-b", "queue-2"));
    const snapshot = job;
    expect(renew(job, { ...oldAuthority, nowMs: job.updatedAtMs, leaseMs: 10 })).toEqual({
      code: "STALE_AUTHORITY",
      changed: false,
      job: snapshot,
    });
    expect(start(job, { ...authority(job), nowMs: job.updatedAtMs - 1 })).toEqual({
      code: "OUT_OF_ORDER_EVENT",
      changed: false,
      job: snapshot,
    });
  });

  it("enforces monotonic time for every transition and permits equal times", () => {
    const pending = fresh();
    expect(acquireAt(pending, 99)).toEqual({
      code: "OUT_OF_ORDER_EVENT",
      changed: false,
      job: pending,
    });

    const leased = jobOf(acquireAt(pending, 100));
    expect(renew(leased, {
      ...authority(leased),
      nowMs: 99,
      leaseMs: 10,
    }).code).toBe("OUT_OF_ORDER_EVENT");
    expect(start(leased, {
      ...authority(leased),
      nowMs: 99,
    }).code).toBe("OUT_OF_ORDER_EVENT");
    expect(recoverExpired(leased, { nowMs: 99 }).code)
      .toBe("OUT_OF_ORDER_EVENT");

    const active = jobOf(start(leased, {
      ...authority(leased),
      nowMs: 101,
    }));
    expect(complete(active, {
      ...authority(active),
      nowMs: 100,
      result: { digest: "sha256:result" },
    }).code).toBe("OUT_OF_ORDER_EVENT");
    expect(fail(active, {
      ...authority(active),
      nowMs: 100,
      kind: "started_known_failure",
      retryable: false,
    }).code).toBe("OUT_OF_ORDER_EVENT");
    expect(cancel(active, { nowMs: 100 }).code).toBe("OUT_OF_ORDER_EVENT");
    expect(recoverExpired(active, { nowMs: 100 }).code)
      .toBe("OUT_OF_ORDER_EVENT");

    let sameTime = jobOf(acquireAt(fresh(), 100));
    sameTime = jobOf(renew(sameTime, {
      ...authority(sameTime),
      nowMs: 100,
      leaseMs: 1,
    }));
    sameTime = jobOf(start(sameTime, {
      ...authority(sameTime),
      nowMs: 100,
    }));
    sameTime = jobOf(complete(sameTime, {
      ...authority(sameTime),
      nowMs: 100,
      result: { digest: "sha256:same-time" },
    }));
    expect(sameTime.updatedAtMs).toBe(100);
    expect(sameTime.attempts[0]).toMatchObject({
      leasedAtMs: 100,
      startedAtMs: 100,
      finishedAtMs: 100,
    });

    const exactExpiry = recoverExpired(leased, { nowMs: 150 });
    expect(exactExpiry.code).toBe("RETRY_SCHEDULED");
    expect(jobOf(exactExpiry).attempts[0].finishedAtMs).toBe(150);
  });

  it("does not shorten a live lease during renewal", () => {
    const job = jobOf(acquireAt(fresh()));
    const expiresAtMs = job.lease?.expiresAtMs;
    const renewed = jobOf(renew(job, {
      ...authority(job),
      nowMs: 101,
      leaseMs: 1,
    }));
    expect(renewed.lease?.expiresAtMs).toBe(expiresAtMs);

    const extended = jobOf(renew(job, {
      ...authority(job),
      nowMs: 110,
      leaseMs: 100,
    }));
    expect(extended.lease?.expiresAtMs).toBe(210);
  });

  it("distinguishes never-started and known started failures", () => {
    const leased = jobOf(acquireAt(fresh()));
    const retry = fail(leased, {
      ...authority(leased),
      nowMs: 101,
      kind: "never_started_retryable",
      retryable: true,
    });
    expect(retry.code).toBe("RETRY_SCHEDULED");
    expect(jobOf(retry).attempts[0].failureKind).toBe("never_started_retryable");

    const active = running();
    const known = fail(active, {
      ...authority(active),
      nowMs: 102,
      kind: "started_known_failure",
      retryable: false,
    });
    expect(known.code).toBe("FAILED");
    expect(jobOf(known).status).toBe("failed");
  });

  it("never retries an explicitly or implicitly unknown started result", () => {
    const active = running();
    const explicit = fail(active, {
      ...authority(active),
      nowMs: 102,
      kind: "started_unknown_result",
    });
    expect(explicit.code).toBe("MANUAL_REVIEW_REQUIRED");
    expect(jobOf(explicit).attempts[0]).toMatchObject({
      finishedAtMs: 102,
      failureKind: "started_unknown_result",
    });

    const recovered = recoverExpired(active, { nowMs: 150 });
    expect(recovered.code).toBe("MANUAL_REVIEW_REQUIRED");
    expect(jobOf(recovered).attempts[0]).toMatchObject({
      finishedAtMs: 150,
      failureKind: "started_unknown_result",
    });
  });

  it("dead-letters at the exact retry-attempt boundary", () => {
    let job = jobOf(submit(undefined, {
      ...submission(),
      retryPolicy: { maxAttempts: 2, baseDelayMs: 10, maxDelayMs: 10 },
    }));
    job = jobOf(acquireAt(job));
    job = jobOf(fail(job, {
      ...authority(job),
      nowMs: 101,
      kind: "never_started_retryable",
      retryable: true,
    }));
    job = jobOf(acquireAt(job, job.nextAttemptAtMs, "worker-b", "queue-2"));
    const exhausted = fail(job, {
      ...authority(job),
      nowMs: job.updatedAtMs + 1,
      kind: "never_started_retryable",
      retryable: true,
    });
    expect(exhausted.code).toBe("DEAD_LETTERED");
    expect(jobOf(exhausted).attempts).toHaveLength(2);
  });

  it.each([
    [1, 10],
    [2, 20],
    [3, 40],
    [4, 75],
    [100, 75],
  ])("computes capped no-jitter delay for attempt %i", (attempt, expected) => {
    expect(retryDelayMs({
      maxAttempts: 100,
      baseDelayMs: 10,
      maxDelayMs: 75,
    }, attempt)).toBe(expected);
  });

  it("bounds overflow, work, and deterministic jitter", () => {
    const overflowPolicy = {
      maxAttempts: 100,
      baseDelayMs: Number.MAX_SAFE_INTEGER - 1,
      maxDelayMs: Number.MAX_SAFE_INTEGER,
      jitterBasisPoints: 10_000,
      jitterSeed: "overflow-seed",
    };
    expect(retryDelayMs(overflowPolicy, 100)).toBe(Number.MAX_SAFE_INTEGER);
    expect(retryDelayMs(overflowPolicy, 101)).toBeUndefined();
    expect(retryDelayMs({ ...overflowPolicy, baseDelayMs: 0 }, 1)).toBe(0);
    expect(retryDelayMs({ ...overflowPolicy, baseDelayMs: 0 }, 100)).toBe(0);
    expect(retryDelayMs({
      maxAttempts: 100,
      baseDelayMs: 0,
      maxDelayMs: 0,
    }, 100)).toBe(0);
    expect(retryDelayMs(overflowPolicy, 0)).toBeUndefined();
    expect(retryDelayMs(overflowPolicy, -1)).toBeUndefined();
    expect(retryDelayMs(overflowPolicy, Number.POSITIVE_INFINITY))
      .toBeUndefined();
    expect(retryDelayMs(null, 1)).toBeUndefined();

    const policy = submission().retryPolicy;
    expect(retryDelayMs(policy, 2)).toBe(retryDelayMs(policy, 2));
    const delay = retryDelayMs(policy, 2);
    expect(delay).toBeGreaterThanOrEqual(20);
    expect(delay).toBeLessThanOrEqual(22);
  });

  it("fails closed when a timestamp cannot represent a positive lease", () => {
    const nearLimit = jobOf(submit(
      undefined,
      submission(Number.MAX_SAFE_INTEGER),
    ));
    expect(acquire(nearLimit, {
      owner: "worker-a",
      deliveryId: "queue-1",
      nowMs: Number.MAX_SAFE_INTEGER,
      leaseMs: 1,
    })).toEqual({
      code: "TIME_EXHAUSTED",
      changed: false,
      job: nearLimit,
    });

    const startAtMs = Number.MAX_SAFE_INTEGER - 100;
    const nearExpiry = jobOf(acquire(
      jobOf(submit(undefined, submission(startAtMs))),
      {
        owner: "worker-a",
        deliveryId: "queue-1",
        nowMs: startAtMs,
        leaseMs: 100,
      },
    ));
    expect(renew(nearExpiry, {
      ...authority(nearExpiry),
      nowMs: Number.MAX_SAFE_INTEGER - 50,
      leaseMs: 100,
    })).toEqual({
      code: "TIME_EXHAUSTED",
      changed: false,
      job: nearExpiry,
    });
  });

  it("fails closed before a monotonic fence token can overflow", () => {
    let job = jobOf(acquireAt(fresh()));
    job = jobOf(fail(job, {
      ...authority(job),
      nowMs: 101,
      kind: "never_started_retryable",
      retryable: true,
    }));
    const fence = Number.MAX_SAFE_INTEGER - 1;
    const exhausted = {
      ...job,
      nextFence: Number.MAX_SAFE_INTEGER,
      attempts: job.attempts.map((attempt) => ({ ...attempt, fence })),
      audit: job.audit.map((fact) =>
        fact.fence === undefined ? fact : { ...fact, fence }),
    };
    expect(acquire(exhausted, {
      owner: "worker-b",
      deliveryId: "queue-2",
      nowMs: exhausted.nextAttemptAtMs,
      leaseMs: 10,
    }).code).toBe("FENCE_EXHAUSTED");
  });

  it("keeps running cancellation open for exact late completion evidence", () => {
    const active = running();
    const requested = cancel(active, { nowMs: 102 });
    expect(requested.code).toBe("CANCEL_REQUESTED");
    expect(jobOf(requested).status).toBe("cancel_requested");
    expect(jobOf(requested).attempts[0].finishedAtMs).toBeUndefined();
    const completed = complete(requested.job, {
      ...authority(jobOf(requested)),
      nowMs: 103,
      result: { digest: "sha256:late-evidence" },
    });
    expect(completed.code).toBe("SUCCEEDED");
    expect(jobOf(completed).status).toBe("succeeded");
    expect(complete(requested.job, {
      ...authority(jobOf(requested)),
      nowMs: 101,
      result: { digest: "sha256:reordered" },
    }).code).toBe("OUT_OF_ORDER_EVENT");
  });

  it("suppresses retry after cancellation and preserves unknown late failure", () => {
    const active = running();
    const requested = jobOf(cancel(active, { nowMs: 102 }));
    const known = fail(requested, {
      ...authority(requested),
      nowMs: 103,
      kind: "started_known_failure",
      retryable: true,
    });
    expect(known.code).toBe("CANCELLED");
    expect(jobOf(known).status).toBe("cancelled");

    const requestedAgain = jobOf(cancel(running(), { nowMs: 102 }));
    const unknown = fail(requestedAgain, {
      ...authority(requestedAgain),
      nowMs: 103,
      kind: "started_unknown_result",
    });
    expect(unknown.code).toBe("MANUAL_REVIEW_REQUIRED");
    expect(jobOf(unknown).status).toBe("manual_review");
    expect(fail(requestedAgain, {
      ...authority(requestedAgain),
      nowMs: 101,
      kind: "started_known_failure",
      retryable: false,
    }).code).toBe("OUT_OF_ORDER_EVENT");

    const expiringRequest = jobOf(cancel(running(), { nowMs: 102 }));
    expect(recoverExpired(expiringRequest, { nowMs: 150 }).code)
      .toBe("MANUAL_REVIEW_REQUIRED");
  });

  it("sends cancellation at the exact running expiry to manual review", () => {
    const active = running();
    const activeAuthority = authority(active);
    const review = cancel(active, { nowMs: 150 });
    expect(review.code).toBe("MANUAL_REVIEW_REQUIRED");
    expect(jobOf(review).status).toBe("manual_review");
    expect(jobOf(review).lease).toBeUndefined();
    expect(jobOf(review).attempts[0]).toMatchObject({
      startedAtMs: 101,
      finishedAtMs: 150,
      failureKind: "started_unknown_result",
    });
    expect(complete(review.job, {
      ...activeAuthority,
      nowMs: 151,
      result: { digest: "sha256:too-late" },
    }).code).toBe("TERMINAL_IMMUTABLE");

    const requested = jobOf(cancel(running(), { nowMs: 102 }));
    expect(cancel(requested, { nowMs: 150 }).code)
      .toBe("MANUAL_REVIEW_REQUIRED");
  });

  it("cancels pending and leased-never-started work terminally", () => {
    expect(jobOf(cancel(fresh(), { nowMs: 101 })).status).toBe("cancelled");
    const leased = jobOf(acquireAt(fresh()));
    const cancelled = jobOf(cancel(leased, { nowMs: 101 }));
    expect(cancelled.status).toBe("cancelled");
    expect(cancelled.attempts[0].finishedAtMs).toBe(101);

    let waiting = jobOf(acquireAt(fresh()));
    waiting = jobOf(fail(waiting, {
      ...authority(waiting),
      nowMs: 101,
      kind: "never_started_retryable",
      retryable: true,
    }));
    const stopped = jobOf(cancel(waiting, { nowMs: 103 }));
    expect(stopped.status).toBe("cancelled");
    expect(cancel(stopped, { nowMs: 104 }).code).toBe("TERMINAL_IMMUTABLE");
  });

  it("terminal and duplicate events still enforce monotonic time", () => {
    const done = succeeded();
    expect(complete(done, {
      owner: "worker-a",
      deliveryId: "queue-1",
      fence: 1,
      nowMs: 101,
      result: { digest: "sha256:result", reference: "d1:result-1" },
    }).code).toBe("OUT_OF_ORDER_EVENT");
    expect(cancel(done, { nowMs: 101 }).code).toBe("OUT_OF_ORDER_EVENT");
    expect(submit(done, { ...submission(), nowMs: 101 }).code).toBe(
      "OUT_OF_ORDER_EVENT",
    );

    expect(cancel(done, { nowMs: 103 }).code).toBe("TERMINAL_IMMUTABLE");
  });

  it("never mutates or normalizes a supplied job in place", () => {
    const active = running();
    const before = JSON.stringify(active);
    const outcome = complete(active, {
      ...authority(active),
      nowMs: 102,
      result: { digest: "sha256:immutable" },
    });
    expect(outcome.code).toBe("SUCCEEDED");
    expect(JSON.stringify(active)).toBe(before);
    expect(outcome.job).not.toBe(active);
    expect(outcome.job?.attempts).not.toBe(active.attempts);

    const corrupted = { ...active, status: "not-a-state" };
    const corruptedBefore = JSON.stringify(corrupted);
    expect(cancel(corrupted, { nowMs: 103 })).toEqual({
      code: "INVALID_JOB",
      changed: false,
    });
    expect(JSON.stringify(corrupted)).toBe(corruptedBefore);
  });

  it("caps redacted audit history and excludes authority and payload facts", () => {
    let job = jobOf(acquireAt(fresh()));
    for (let nowMs = 101; nowMs <= 140; nowMs += 1) {
      job = jobOf(renew(job, {
        ...authority(job),
        nowMs,
        leaseMs: 50,
      }));
    }
    expect(job.audit).toHaveLength(JOB_STATE_LIMITS.maxAuditFacts);
    expect(JSON.stringify(job.audit)).not.toContain("worker-a");
    expect(JSON.stringify(job.audit)).not.toContain("sha256:payload");
    for (const fact of job.audit) {
      expect(Object.keys(fact).sort()).toEqual(
        ["atMs", "attempt", "code", "fence"].sort(),
      );
    }
  });

  it("is deterministic under replay and reordered no-op events", () => {
    const run = (events: readonly string[]): Job => {
      let job = fresh();
      for (const event of events) {
        if (event === "acquire") job = jobOf(acquireAt(job));
        if (event === "duplicate-acquire") {
          job = jobOf(acquireAt(job, 100));
        }
        if (event === "early-complete") {
          job = jobOf(complete(job, {
            owner: "worker-a",
            deliveryId: "queue-1",
            fence: 1,
            nowMs: 100,
            result: { digest: "sha256:result" },
          }));
        }
        if (event === "start") {
          job = jobOf(start(job, { ...authority(job), nowMs: 101 }));
        }
        if (event === "duplicate-start") {
          job = jobOf(start(job, { ...authority(job), nowMs: 101 }));
        }
        if (event === "complete") {
          job = jobOf(complete(job, {
            ...authority(job),
            nowMs: 102,
            result: { digest: "sha256:result" },
          }));
        }
        if (event === "duplicate-complete") {
          job = jobOf(complete(job, {
            owner: "worker-a",
            deliveryId: "queue-1",
            fence: 1,
            nowMs: 500,
            result: { digest: "sha256:result" },
          }));
        }
      }
      return job;
    };
    const canonical = run(["acquire", "start", "complete"]);
    const replayed = run([
      "early-complete",
      "acquire",
      "duplicate-acquire",
      "start",
      "duplicate-start",
      "complete",
      "duplicate-complete",
    ]);
    expect(replayed).toEqual(canonical);
  });
});
