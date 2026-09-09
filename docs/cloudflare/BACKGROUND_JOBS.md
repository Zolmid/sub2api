# Background-job state machine foundation

`deploy/cloudflare/src/job-state.ts` is a pure, deterministic TypeScript model for future background work. It accepts caller-supplied time, fencing, and jitter inputs; it does not bind Queue, Durable Objects (DO), D1, R2, secrets, Worker environment values, or a live service. TypeScript types are not an authority boundary: every exported function validates runtime-unknown input and fails closed instead of throwing (`INVALID_INPUT`/`INVALID_JOB`, or `undefined` for malformed delay calculations).

Payloads and results contain only bounded opaque digest/reference fields. Exact object-key allowlists reject extra fields. Identifiers reject whitespace and control characters. References have a separate validator so they may contain interior spaces, while leading/trailing whitespace and control characters remain invalid. Limits are enforced on both UTF-16 units and Unicode code points; the UTF-16 bound is decisive for astral characters. The state machine must never receive object bytes, credentials, authorization headers, tokens, or customer secrets.

## Contract

A submission is idempotent on the tuple `(namespace, type, idempotencyKey)`. Repeating it returns `IDEMPOTENT_SUBMISSION` only when the entire payload and retry policy are semantically identical. Payload equality includes the digest and distinguishes an absent reference, an explicit `null`, and a concrete reference. Retry equality includes all limits, jitter settings, and optional-field presence. Any difference returns `IDEMPOTENCY_CONFLICT` and leaves the original job untouched.

The states are `pending`, `leased`, `running`, `cancel_requested`, `retry_wait`, `succeeded`, `failed`, `cancelled`, `dead_letter`, and `manual_review`. `manual_review` is the explicit unknown-result state. Terminal states are immutable. A lease has a monotonic positive safe-integer fence token, owner, delivery ID, and expiry. Allocation returns `FENCE_EXHAUSTED` before the next token could exceed the safe-integer range. Unrepresentable future lease or retry timestamps return `TIME_EXHAUSTED` without mutation. Any late owner or old fence cannot change current authority. Events earlier than the persisted `updatedAtMs` return `OUT_OF_ORDER_EVENT`, including terminal and duplicate events; same-time transitions are allowed. The exact expiry instant is expired.

Loaded jobs are accepted only when their root and nested shapes, state-specific lease/result/attempt invariants, chronological attempt/audit facts, fence sequence, attempt limit, and audit limit all validate. A corrupted row is not normalized or repaired by this module; an adapter must quarantine or reconcile it explicitly.

Repeated Queue delivery is exact: the current unexpired `(owner, deliveryId)` lease returns `DUPLICATE_DELIVERY` with no mutation. Once the lease reaches its expiry it requires recovery. A repeated successful completion returns `DUPLICATE_COMPLETION` only when result digest/reference and the original owner, delivery ID, and fence all match. A malformed, stale-authority, or differently shaped late completion cannot replace a terminal result.

`fail` explicitly distinguishes three cases:

- `never_started_retryable`: work did not start, so retry is safe when attempts remain.
- `started_known_failure`: execution started but a known failure was observed; it may retry only when the caller says it is retryable.
- `started_unknown_result`: execution started and the result is uncertain; it always enters `manual_review` instead of blindly retrying possible side effects.

An expired `leased` state is recoverable to `retry_wait`; an expired `running` or `cancel_requested` state finishes the attempt as `started_unknown_result` and enters `manual_review`. Cancelling pending or leased-but-never-started work closes any attempt, revokes authority, and enters terminal `cancelled`. Cancelling running work before expiry enters `cancel_requested` and retains the lease and unfinished attempt so exact, in-order late completion/failure evidence can still be recorded. A cancellation arriving at or after expiry enters `manual_review` directly. A known late failure suppresses retry and completes cancellation; a known late success becomes `succeeded`; unknown failure or lease expiry becomes `manual_review`. A completion already made terminal remains immutable.

Backoff is capped exponential (`baseDelayMs * 2^(attempt-1)`, capped before multiplication), accepts only attempt numbers from one through `maxAttempts`, and computes the cap in constant time. A zero base delay is valid and returns zero deterministically in constant time. Optional jitter derives from an explicit deterministic seed and uses overflow-safe integer arithmetic. The module never calls `Math.random()` or `Date.now()`.

Audit facts include only time, stable reason code, attempt number, and fence token. They deliberately omit owners, payload/result references, and all secret-bearing data.

## Future responsibility split

| Layer | Future responsibility | State-machine responsibility now |
| --- | --- | --- |
| Queue producer/consumer | Enqueue a delivery, acknowledge/retry transport, provide delivery ID | Interpret repeated delivery deterministically |
| Durable Object | Serialize authority for a job key and issue/coordinate fences | Validate owner, delivery ID, expiry, and fence transitions |
| D1 | Persist jobs, attempts, audit facts, idempotency index, and terminal result digest | Define bounded data and replay-safe transitions |
| Worker executor | Resolve payload reference, execute job, report known result/failure | Require explicit start/complete/fail authority and uncertainty handling |
| Reconciler | Inspect `manual_review` and dead-letter jobs and take an operator-approved action | Preserve evidence that side effects are not confirmed |

Candidate future job types include account or credential **refresh**, expired-data **cleanup**, usage or billing **aggregation**, and ledger/provider **reconciliation**. Each needs its own side-effect and idempotency contract before it is wired to the executor. A full service-by-service inventory of existing background work, ownership, timing, and failure behavior remains separate work, as do all Queue/DO/D1 adapters.

## Observability

Future adapters should count transitions by `OutcomeCode`, state, attempt number, and job namespace/type; track lease expiry, stale authority, duplicate delivery/completion, retry delay, dead-letter, cancellation, and manual-review rates. Logs and metrics should retain the redacted audit facts only. Correlating IDs must be opaque hashed identifiers rather than payloads, references, user data, or credentials.

## Status

This is an isolated foundation with focused unit tests only. There is no Queue, DO, D1, migration, Worker, R2, deployment, live integration, or production acceptance yet.
