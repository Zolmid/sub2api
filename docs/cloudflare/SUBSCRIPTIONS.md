# Cloudflare-native subscriptions

This lane adds the D1-authoritative persistence foundation for subscription
plans, user subscriptions, quota windows, and subscription mutation history,
plus a private Worker control-plane adapter. It does not expose a public API,
wire Go handlers, billing, request admission, schedulers, or `src/index.ts`.

## Authority and representation

- Migration `0012_subscription_runtime.sql` follows canonical migration 0011.
- Persistent int64 identifiers are canonical positive decimal `TEXT`, never
  JavaScript numbers.
- Prices, plan limits, subscription limit snapshots, and usage are canonical
  non-negative E8 USD decimal `TEXT` in the signed-int64 range
  `0..9223372036854775807`. Runtime arithmetic uses `BigInt`; no `REAL`, float,
  or JavaScript `Number` participates in money arithmetic.
- A nullable limit means unlimited. It is distinct from exact zero. Required
  monetary properties must still be present; missing, `undefined`, malformed,
  negative, fractional, non-canonical, and overflowing values are rejected.
- User-subscription notes are non-null text and a valid empty string is
  preserved. Control characters, bidi controls, BOMs, unpaired surrogates, and
  overlong UTF-8 input are rejected.
- All instants are strict RFC3339 UTC values and are persisted in canonical
  millisecond `Z` form. This module does not ship or emulate a timezone
  database.

## Schema invariants

`subscription_plans` belongs to a live group whose `subscription_type` is
`subscription`. It stores the baseline catalog fields plus exact plan price and
daily, weekly, and monthly E8 limits.

`user_subscriptions` preserves `active`, `expired`, and `suspended`, supports
soft deletion, and uses a partial unique index to allow at most one non-deleted
row for `(user_id, group_id)`. A replacement can therefore be created after a
revoke, while restoring the old row conflicts if a replacement is live.
Triggers validate live users, live subscription groups, live matching plans,
and live administrators in `assigned_by`. Plan limits are snapshotted onto a
subscription when a plan is assigned so a later catalog change cannot rewrite
already granted quota semantics.

`subscription_operations` is an append-only operation record containing the
operation kind, complete semantic-input fingerprint, committed response, target
identity, version, and timestamp. `subscription_operation_effects` is also
append-only. Conditional mutations insert a guard only when SQLite `changes()`
is exactly one; the effect references that guard. Consequently, a stale
`UPDATE 0` makes the D1 batch fail and rolls back the operation row and every
other effect in that batch.

An identical operation key and semantic payload returns the stored committed
response. Reusing the key with any changed semantic field returns
`IDEMPOTENCY_CONFLICT`. Audit rows are never replaced or deleted.

## Runtime API

Every method accepts `unknown`, rejects unknown properties, and either returns
a typed result or throws `SubscriptionRuntimeError` with a stable `code`.

- `createPlan`, `getPlan`, `listPlans`
- `assignOrExtend`, `getSubscription`, `listSubscriptions`
- `revoke`, `restore`, `extend`
- `activateWindows`, `maintainWindows`, `resetWindows`
- `reserveUsage`
- `sweepExpired`

## Private control-plane contract

The Worker exposes every runtime operation only through
`http://sub2api.internal`, as `POST`, with
`X-Sub2API-Bridge-Version: 2026-09-09.v3` and a non-empty
`X-Sub2API-Container-Id`. Bodies are JSON and capped by the shared 64 KiB
control-plane limit. Each successful response is the runtime result unchanged.
The exact route registry is:

- `/v1/subscriptions/plans/create` -> `createPlan`
- `/v1/subscriptions/plans/get` -> `getPlan`
- `/v1/subscriptions/plans/list` -> `listPlans`
- `/v1/subscriptions/assign-or-extend` -> `assignOrExtend`
- `/v1/subscriptions/get` -> `getSubscription`
- `/v1/subscriptions/list` -> `listSubscriptions`
- `/v1/subscriptions/revoke` -> `revoke`
- `/v1/subscriptions/restore` -> `restore`
- `/v1/subscriptions/extend` -> `extend`
- `/v1/subscriptions/windows/activate` -> `activateWindows`
- `/v1/subscriptions/windows/maintain` -> `maintainWindows`
- `/v1/subscriptions/windows/reset` -> `resetWindows`
- `/v1/subscriptions/usage/reserve` -> `reserveUsage`
- `/v1/subscriptions/expiry/sweep` -> `sweepExpired`

Unknown routes, wrong host/version, non-POST requests, and missing container
identity fail with `404 NOT_FOUND`. Malformed or oversized JSON gets
`400 INVALID_REQUEST`. Runtime validation errors map to 400, missing
references to 404, and idempotency/version/state/quota conflicts to 409, all
using `{ "error": { "code": "...", "message": "..." } }`. D1 failures,
unexpected exceptions, and corrupt internal runtime state return only
`503 SUBSCRIPTION_UNAVAILABLE`; their details are never bridged.

Go bridge wiring and remote Cloudflare deployment remain separate integration
work. This adapter neither changes the Go backend nor creates or deploys any
Cloudflare resource.

Mutation calls carry an operation key. Mutations of an existing subscription
also carry `expected_version`, except `assignOrExtend`, which retries a bounded
CAS loop so two independent deliveries can each apply once without losing an
extension. Other stale writers fail with `STALE_VERSION`; they never append a
success audit row. List limits are `1..100` and cursors are canonical ID
strings.

`assignOrExtend` refuses a standard balance group. A first assignment starts an
active term. An unexpired live row extends from its current expiry; an expired
row restarts at the supplied `now`, becomes active, resets all usage, and sets
the supplied daily boundary plus rolling activation anchors. Non-empty notes
append; an empty notes string is accepted and is a no-op for an existing note.
Validity is `1..36500` days and expiry is capped at the baseline maximum
`2099-12-31T23:59:59Z`.

`restore` preserves the stored status, except an `active` row whose expiry is
not after `now` restores as `expired`. `extend` rejects shortening an expired
term or any adjustment whose result is not after `now`; extending an `expired`
status reactivates it, while a suspended status remains suspended.

## Window semantics

The caller supplies both `now`/`activated_at` and the configured-timezone
calendar midnight as an explicit UTC `daily_boundary`.

- First activation stores the daily boundary and anchors weekly/monthly at the
  activation instant.
- Daily maintenance advances to the caller's current boundary. A term of at
  most 24 hours has one-time daily quota and never auto-refills.
- Weekly and monthly windows are anchored rolling `7x24h` and `30x24h`
  durations, not calendar weeks or months.
- Imported initial midnight anchors must be explicitly marked
  `legacy_initial`; only a value matching the stored initial daily boundary is
  normalized to `starts_at`. Manual midnight anchors are marked `manual` and
  remain authoritative.
- Automatic maintenance does not advance any window at or after expiry and
  never creates a final partial rolling period.
- Manual daily reset stores the supplied calendar boundary; manual weekly and
  monthly reset store the supplied reset instant.

`reserveUsage` atomically adds the exact E8 amount to all three usage counters,
checks nullable/zero limits, int64 overflow, status, expiry, activation, and the
expected version, and commits the usage plus audit in one guarded batch.
Reset-versus-usage therefore has one winner for a shared version and cannot
silently erase or over-grant usage.

`sweepExpired` selects at most 100 live active rows in canonical ID order and
atomically changes only rows still active, still due by the supplied cutoff,
and still at the selected version. Guarded per-row effects make the whole batch
fail on a concurrent restore/extension. Replaying an older successful sweep
returns its stored result without overwriting a later extension.

## Intentional integration boundary

Billing and request admission do not reserve subscription quota, management
routes do not expose these methods, and no scheduler invokes `sweepExpired`.
A later Go integration lane must map authenticated actors and request
identities into this private protocol, perform window maintenance before
reservation, and wire cache invalidation after committed D1 mutations. It must
preserve the operation key and expected-version contracts rather than adding an
unguarded read/modify/write layer.
