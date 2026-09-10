# Background jobs on D1 and Queues

`deploy/cloudflare/migrations/0011_background_job_runtime.sql` and
`deploy/cloudflare/src/job-runtime.ts` are the generic persistence/runtime
foundation for future email, payment, account-maintenance, reconciliation, and
similar adapters. They are intentionally not imported by the Worker entry point
and no Queue binding is declared yet.

Cloudflare Queues delivery is treated as an at-least-once, unordered wake-up.
D1 is the authority for whether work may start, which attempt owns the lease,
and whether a result is terminal. A Queue delivery can never advance a job by
itself.

## Durable model

- `background_jobs` stores payloads, retry policy, status, attempt count,
  authority lease, optimistic `version`, result/error summaries, and replay
  provenance. `(route, idempotency_key)` makes submission idempotent.
  Identity, route/type, payload codec/body/digest, retry policy, submission
  timestamp, and replay provenance are immutable after creation; jobs cannot
  be deleted.
- `background_job_transitions` is an append-only ledger. Triggers reject update
  and delete, and `(job_id, to_version)` allows exactly one fact per committed
  job version.
- `background_job_outbox` stores versioned Queue envelopes and publisher lease
  state. `(job_id, job_version)` allows at most one enqueue request for each
  state version. Its identity, job/version, canonical envelope, and creation
  time are immutable, and outbox rows cannot be deleted.
- Due-job, lease-expiry, replay, transition, and drain indexes support bounded
  maintenance scans without using Queue order as an authority.

Every state change uses a caller-supplied expected version. All mutable job,
transition, and outbox versions/counters are capped at `2,147,483,647`; the
runtime rejects an attempted increment at that boundary before issuing a
mutation. Timestamps must be safe, non-negative integers no later than
`4102444800000`, and update/completion times cannot regress.

Lease owner, token, delivery ID, and lease expiry are all present exactly for
`claimed`/`running` jobs and absent for every other status. Terminal statuses
have a completion time exactly when terminal; success requires a result digest,
and queued/claimed/running rows cannot carry a result or error summary. A live
claimed/running lease always expires strictly after the row's update time.

Every exported runtime state change uses a caller-supplied expected version.
Its D1 batch runs a guarded `UPDATE`, an
`INSERT ... SELECT ... WHERE changes()=1` transition, and, when a delivery is
needed, another conditional insert for the outbox. The runtime explicitly
checks every statement's `meta.changes`: either every row is one or every row
is zero. A stale CAS therefore produces no transition and no outbox row.
Constraint or uniqueness failure aborts that runtime batch.

The schema's checks and triggers reject malformed individual rows and illegal
transition shapes, but they are not a SQL authorization layer and do not claim
to couple every arbitrary hand-written `UPDATE` to a history insert. The
supported mutation surface is `job-runtime.ts`; operators and adapters must not
write these tables directly. Atomic state/history/outbox coupling refers to
the guarded batches issued by that runtime API.

Creation and replay use conditional plain `INSERT`s, never `INSERT OR IGNORE`.
Only a duplicate matching every immutable submission semantic is a no-op;
check failures, foreign-key failures, transition-ID collisions, outbox-version
collisions, and any other uniqueness target abort rather than masquerading as
idempotency. Idempotent creation and replay also require the canonical,
immutable version-one outbox witness; its later `publishing` or `published`
state is allowed, but a missing or divergent original envelope is reported as
corruption instead of a successful replay. The transition ledger accepts only
the defined event/status pair, version step, timestamp, and reason/evidence
fields that match the committed job row when the entry is inserted.

The database also rejects any update to `succeeded`, `failed`, `dead_letter`, or
`manual_review`. A controlled replay never reopens that terminal row; it creates
a new queued job that points to the source and records the source's expected
version/status, replay key, operator, reason, evidence kind/reference, and
request timestamp. Exact replay idempotency compares every persisted request
and derived result semantic, including the new job's route/type, payload
codec/body/digest, retry policy, transition ID, and timestamp; any mismatch is
a conflict. Original attempts and transitions remain immutable.

## Runtime API

The stable generic functions are:

- `createAndEnqueueJob` for idempotent creation plus the first outbox record;
- `claimJob` and `startJob` for delivery-version CAS and leased authority;
- `renewJobLease` for a fenced, strictly extending claimed/running lease
  renewal that advances the job version and appends `lease_renewed`;
- `succeedJob`, `recordRetryableFailure`, `recordPermanentFailure`, and
  `deadLetterJob` for known outcomes;
- `moveToManualReview` for a side effect that started but has an unknown result;
- `recoverExpiredJob`, which retries an expired never-started claim but moves an
  expired running attempt to manual review;
- `replayTerminalJob` for evidence-backed DLQ/manual-review replay as a new job;
- `listDrainableOutbox`, `claimOutbox`, `markOutboxPublished`, `releaseOutbox`,
  and `drainOutbox` for recoverable publication; and
- `processQueueBatch` for independent per-message `ack()`/`retry()` outcomes.

Retries use capped exponential delay from persisted `attempt_count`,
`base_delay_ms`, and `max_delay_ms`. There is no random jitter. Job authority
operations receive explicit time, IDs, leases, and evidence. `drainOutbox`
receives an initial scan/claim time and an injectable clock; after each awaited
Queue send it reads that clock exactly once before the mark or release CAS. If
no clock is injected it uses the Workers `Date.now()` clock. The attempt limit
is one through 100, the configured delay cap is seven days, and an exhausted
retry transitions to `dead_letter` without another outbox record.

`not_started` is retryable because no external effect began.
`started_known_failure` may be retried only when an adapter has observed that
failure. An effect that started and whose result is unknown must call
`moveToManualReview`; it must not call a retry API. Replaying manual-review work
requires explicit provider-idempotency, provider-query, or operator evidence.
Future adapters may automate this only when their provider's idempotency/query
contract supplies durable evidence.

## Opaque Queue envelope

The only accepted envelope shape is:

```json
{"v":1,"jobId":"opaque-id","route":"adapter.v1","jobVersion":1}
```

The parser requires exactly those four keys. Credentials, provider tokens,
email addresses or bodies, reset tokens, payment details, payloads, and results
are forbidden from the Queue envelope. The runtime returns redacted job records
and does not return `payload_body`.

Payload content stays in D1 behind `job_id`. D1/platform encryption at rest is
required. Any future adapter that persists credentials, tokens, message bodies,
payment data, or comparable sensitive content must additionally use the
project's approved application-encryption/key-rotation mechanism and store
`payload_codec='app_encrypted_v1'`. This foundation does not create keys,
secrets, or adapter-specific encryption.

## Crash-window contract

| Window | Durable recovery |
| --- | --- |
| D1 commit before Queue publish | The pending outbox row remains drainable. |
| Queue publish before outbox mark | The publisher lease expires and the same opaque envelope may publish again; job-version CAS makes it harmless. |
| Consumer D1 commit before Queue ack | Redelivery observes a newer or terminal job version and is acknowledged without another transition. |
| Partial Queue batch | Each message is handled independently; successful/invalid items are acknowledged and only transient failures are retried. |
| Claimed lease expires before start | Recovery creates a bounded retry (or dead-letters at the attempt limit). |
| Running lease expires with unknown result | Recovery enters terminal `manual_review`; it never blindly repeats the side effect. |
| Long claimed/running work approaches expiry | The current fenced owner renews to a strictly later expiry and receives the next authoritative job version. |

Publisher and consumer code must await `drainOutbox`/`processQueueBatch`; do not
start floating promises. SQL parameters are always bound. IDs may be generated
with Workers Web Crypto (`crypto.randomUUID()`); Node-only crypto or mutable
module-level request state is not required.

`drainOutbox` claims an outbox row before publication and sends the canonical
envelope read after that claim, never the stale candidate from the initial
drain scan. Publisher mark/release operations fence on row version, owner, and
an unexpired publisher lease, using a fresh time read after the external send.
If the lease expired during a failed send, the runtime reports
`publish_failed_unreleased` rather than falsely claiming it returned the row to
pending; the expired publishing row is immediately reclaimable. `published` is terminal: it cannot return to
`pending` or `publishing`; recovery can only re-claim an expired `publishing`
row, deliberately allowing an opaque duplicate publication in the
publish-before-mark crash window.

## Relationship to the pure state model

`deploy/cloudflare/src/job-state.ts` remains a persistence-neutral state-machine
model with its own broader cancellation/fencing contract. The D1 runtime in
this document is the production-shaped generic persistence lane. Adapters must
choose the durable runtime contract and must not assume an in-memory state
object is authoritative across Worker requests.

## Current integration boundary

The migration, runtime, real-D1 tests, and this contract are local and isolated.
`src/index.ts`, Wrangler configuration/bindings, scheduler runtime, billing,
control-plane contracts, setup, package scripts, Go code, deployment, and live
Queue resources are intentionally unchanged. A later integration lane must add
the Queue producer/consumer entry points and bindings, then run deployment and
end-to-end acceptance separately.
