# Authentication Cache Runtime

`deploy/cloudflare/src/auth-cache-runtime.ts` is a D1-authoritative foundation for a
future Worker auth integration. It is not wired into the shared Worker entry
points yet and this document does not describe a production deployment.

The runtime accepts a presented credential only long enough to compute a
SHA-256 digest. Raw credentials are never stored in L1 cache, migration rows,
outbox events, replica payloads, diagnostics, or returned authorization data.

## Consistency Model

Every `resolve()` starts with a minimal D1 probe. The probe contains only the
credential digest, key/user/group identities, active and deleted markers, and
monotonic revisions, including the user/group subscription revision. It does
not read allowed groups, exclusivity, subscription type, subscription windows,
or computed authorization results.

On a cache miss, the full authorization projection is loaded by one D1 SQL
statement. That statement returns a single snapshot containing the same probe
fields plus `allowed_group_ids_json`, key expiry, user restriction state, group
exclusivity, group subscription type, and the current live user subscription.
The live subscription filter is `deleted_at IS NULL`, `status = 'active'`, and
`starts_at <= now < expires_at`.

The runtime hashes the probe-shaped part of the full row and compares it with
the initial probe fingerprint. A mismatch causes a bounded re-probe and retry,
so a mutation between probe and full load cannot authorize stale state. Cache
hits are also rechecked against a fresh probe before authorization.

## Authorization Semantics

The cache stores only projections that passed local structural, type, ID,
timestamp, revision, and policy validation. Authorization remains fail closed
for malformed D1 rows, hostile input objects, poisoned local cache entries, and
transported replica payloads.

Standard public groups authorize only when the group is not exclusive and the
user does not restrict public groups. Restricted or exclusive standard groups
require the key group to be present in `allowed_group_ids_json`. Subscription
groups do not inherit either standard rule: they require a current live
subscription window from D1.

`drain()` exports local entries for a future transport, but `rebuild()` treats
that payload as quarantined. It validates the payload shape, discards supplied
authorization facts, re-probes D1, and reconstructs any usable entry through
the authoritative full-load path.

## Revisions And Invalidation

Migration `0014_auth_cache_runtime.sql` creates digest and entity revision
tables plus a digest/ID-only invalidation outbox. Relevant `api_keys`, `users`,
`groups`, and `user_subscriptions` inserts, updates, and deletes bump exactly
the affected source revisions and write outbox rows in the same D1 statement
transaction as the source mutation.

API key rotation bumps the API-key identity, the old credential digest, and the
new credential digest. Rotation outbox rows contain only IDs and credential
digests, including both old and new digests on the API-key event. They never
contain raw credentials or authorization projections.

Subscription revision identity is `user_id:group_id`. An update that keeps the
same identity bumps that revision once. An update that moves identity bumps and
emits invalidations for both the old and new identities.

All revision and outbox numeric text is canonical decimal with explicit SQLite
int64 upper bounds. Authority timestamp fields use canonical millisecond RFC3339
UTC strings with SQLite-validated calendar dates, times, leap years, and a
four-digit `0000`–`9999` year bound. Event IDs and credential digests are lowercase hexadecimal with fixed
lengths. Revision and outbox histories reject deletion. Outbox rows must match
the relevant revision history exactly; entity IDs are canonical source IDs (or
`user_id:group_id` for subscriptions), and the row's type, digest fields,
revision, state, lease fields, and publication fields are constrained together.

## Outbox Delivery

`drainOutbox()` implements at-least-once delivery. It claims pending or expired
claimed rows with a lease token and fencing version, rereads the currently
claimed D1 row before delivery, and marks only the matching, unexpired live
claim as published. Publication time and the lease/fence comparison come from
one fresh authority-clock read after delivery returns; a pre-delivery claim
time is never persisted as `published_at`. A mark reports success only when its
own compare-and-set changed the row; a stale or duplicate mark is false even if
another actor has already published it.

If the process crashes before delivery, the claim is released or later expires.
If delivery succeeds but the process crashes before mark, the expired lease can
be reclaimed and the same event ID/revision is delivered again. An expired claim
at the final allowed attempt is instead deterministically fenced and moved to
`dead` during runtime draining, so it cannot remain stranded. Consumers must
therefore be idempotent by event ID and revision.

Renewal increments the fence. The pre-renew fence, an expired lease, or a
pre-takeover token cannot mark publication or release a claim; terminal `dead`
and `published` rows cannot be regressed. Each synchronous claim, renewal,
release, or publication authority decision reads the runtime clock once.

## Deployment Boundary

This slice adds schema, runtime code, tests, and documentation only. It does
not modify shared Worker entry points, generated types, Wrangler config,
Cloudflare resources, Worker secrets, or upstream network calls.
