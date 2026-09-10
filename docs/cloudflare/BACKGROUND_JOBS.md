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

Production Worker execution now uses a non-empty exact registry for the
current migration responsibilities:

- `oauth-refresh.v1`
- `email-delivery.v1`
- `payment-reconciliation.v1`
- `subscription-expiry-maintenance.v1`

These names are versioned constants, not prefixes. Any other route remains
`manual_review` with `unknown_route` evidence. Registered routes dispatch to
the gateway Container on the private path
`/internal/cloudflare/jobs/execute`. The entire `/internal/cloudflare`
namespace is reserved: public Worker ingress returns 404 for that path or any
descendant before fixture or routing headers are honored. The boundary applies
after normalizing repeated separators, dot segments, backslashes, case, and
single or nested percent encodings of `%`, `.`, `/`, and `\\`; an external
caller therefore cannot reach the job RPC by path or header forgery. This does
not reserve unrelated public paths such as `/internality`, `/api/v1`, or `/v1`.

The Worker sends a bounded JSON RPC envelope:

```json
{
  "v": 1,
  "method": "sub2api.cloudflare.jobs.execute",
  "params": {
    "job": {
      "id": "opaque job id",
      "version": 4,
      "route": "oauth-refresh.v1",
      "type": "oauth-refresh",
      "idempotencyKey": "opaque idempotency key"
    },
    "payload": {
      "codec": "json",
      "body": "{}",
      "digest": "sha256:..."
    }
  }
}
```

The Worker rejects payload bodies above 256 KiB before Container dispatch and
never stores the payload body in transition evidence. Container responses are
accepted only when they are 200 responses whose JSON body is no larger than 8
KiB and exactly matches one of these shapes:

- `{ "v": 1, "kind": "succeeded", "resultDigest": "..." }`
- `{ "v": 1, "kind": "retryable_failure", "errorCode": "..." }`
- `{ "v": 1, "kind": "permanent_failure", "errorCode": "..." }`
- `{ "v": 1, "kind": "manual_review", "reasonCode": "...", "evidenceRef": "..." }`

Malformed, oversized, non-JSON, network-failed, non-200, or otherwise
ambiguous Container outcomes fail closed to `manual_review`. Only an explicit,
validated `retryable_failure` response from the private Go endpoint may enter
the retry path.

This is still infrastructure only. The recognized routes are not end-to-end
complete until the Go gateway implements the private endpoint above and maps
each route's provider/payment/email/subscription behavior into the response
contract without logging or returning secret payload material.

Do not retry `manual_review` or `dead_letter` records by modifying them. Use
the existing audited replay API with a new job ID, idempotency key, replay key,
actor, reason, and evidence that the prior effect did not occur.

## Configuration and authorization boundary

The Wrangler files declare bindings only. They do not create queues, deploy a
Worker, read provider credentials, or contact R2. Remote queue creation,
consumer attachment, and deployment remain explicit operator actions requiring
separate authorization. Local tests call the runtime with injected executors;
they do not require remote Queue resources.
