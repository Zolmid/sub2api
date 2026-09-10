# Cloudflare background jobs

`JOB_QUEUE` is a dedicated producer/consumer binding for opaque version-one
envelopes. It is intentionally separate from the existing `USAGE_QUEUE`; the
background queue is named `sub2api-background-jobs` in both production and
local Wrangler configuration so the Worker can dispatch it without a
production/local name mismatch.

## Guarantees and limits

- Payloads stay in D1. Queue messages contain only `{v, jobId, route,
  jobVersion}` and are strictly validated before use.
- The D1 state machine is the authority: an envelope must claim the current
  version, then renew its lease, start, and make one fenced terminal mutation
  before it is acknowledged. Duplicate, delayed, and out-of-order envelopes
  become harmless acknowledgements.
- The outbox is published in a bounded scheduled drain. A publish-before-mark
  crash can publish the same opaque envelope again, which remains safe because
  of the claim/version fence.
- Scheduled recovery is bounded. An expired `claimed` job returns to the
  retry policy; an expired `running` job moves to `manual_review` because an
  external effect may be unknown.
- Unknown executor routes are moved to audited `manual_review`, not silently
  acknowledged. Retry exhaustion is `dead_letter`. Generic infrastructure
  exceptions retry the Queue delivery; no effect is executed again while a
  running lease is fenced.

## Executors and replay

The queue runtime accepts an injected route-to-executor map. An executor must
return exactly one of: success (with an opaque result digest), retryable
failure, permanent failure, or manual review. Executors receive the payload
only after a valid running lease is established and must not log it.

Do not retry `manual_review` or `dead_letter` records by modifying them. Use
the existing audited replay API with a new job ID, idempotency key, replay key,
actor, reason, and evidence that the prior effect did not occur.

## Configuration and authorization boundary

The Wrangler files declare bindings only. They do not create queues, deploy a
Worker, read provider credentials, or contact R2. Remote queue creation,
consumer attachment, and deployment remain explicit operator actions requiring
separate authorization. Local tests call the runtime with injected executors;
they do not require remote Queue resources.
