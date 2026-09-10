# Scheduler runtime components

The Cloudflare private `/v1/requests/admit` path is now connected to this runtime. The only Cloudflare mode uses these bindings; the traditional PostgreSQL/Redis mode is unchanged. This is local implementation and workerd acceptance, not a production deployment claim.

## Authoritative state and freshness

`0010_scheduler_runtime.sql` stores only non-secret scheduler facts:

- `scheduler_account_runtime` stores capability and quota observations with an evidence state, bounded source, observed time, freshness deadline, and monotonic version metadata.
- `scheduler_principal_limits` stores account, user, and API-key RPM limits with the same provenance and freshness shape.
- all identifiers, versions, counters, basis points, and millisecond timestamps use `TEXT` or `INTEGER`; no authoritative value uses `REAL`.

`buildSchedulerSnapshot` joins D1 accounts, account-group membership, groups, API keys, users, and the scheduler tables. Expired, malformed, estimated hard-capacity, or unknown facts remain explicitly unconfirmed and fail the pure scheduler policy's hard gates. Credentials, authorization headers, request/response bodies, and user content are never selected into the snapshot.

Live concurrency, health, cooldown, temporary-unschedulable state, and RPM counts use SQLite-backed Durable Object state. Health/cooldown/temporary observations are source-labelled and independently versioned. An update with an older version/time cannot replace a newer row; an equal version/time with a different payload is an idempotency conflict. Stale observations are returned as `unknown`, not `confirmed`. No process-local EWMA is authoritative.

## Object identity and RPM windows

Object identity is canonical and independent of group membership:

- `ACCOUNT_LEASE` uses `account:<canonical-id>` and owns that account's lease, account RPM, health, cooldown, and temporary-unschedulable state;
- `USER_RATE_LIMIT` uses `user:<canonical-id>`;
- `API_KEY_RATE_LIMIT` uses `api-key:<canonical-id>`.

Therefore, an account in multiple groups still has one concurrency/RPM/cooldown authority. Group membership never appears in an object name and cannot multiply capacity.

RPM is a server-time, aligned 60-second fixed window. Reserve, commit, release, and inspect operations validate canonical IDs, bounded opaque admission/request IDs, principal/limits, and a principal/second pending-reservation TTL. Reusing an admission ID with different identity is a conflict. Exact duplicates are idempotent. Pending reservations can be compensated; committed admissions continue to count until the window closes. Closed IDs retain bounded tombstones so a late exact rollback or release after `released`, `expired`, or `window_closed` is duplicate-success; any identity mismatch remains a conflict. SQLite state and alarms survive object eviction. Limits above 100,000 and invalid/corrupt counts fail closed.

Durable Object alarms are cleanup/recovery, not keepalive heartbeats. Pending reservations expire after their short TTL, leases expire after their lease TTL, committed counts expire at the window boundary, and tombstones are bounded by age and count. Natural lease expiry writes the same exact lease fence retained for an explicit release before deleting the active row, so a late terminal close cannot affect a later lease.

## Non-atomic multi-object admission protocol

`reserveSchedulerResources` is the state machine used by the private admission route. It does not claim atomicity across Durable Objects. Its fixed acquisition order is:

1. account lease;
2. account RPM reservation;
3. user RPM reservation;
4. API-key RPM reservation;
5. billing reservation.

The three RPM reservations are committed in account/user/API-key order before billing is attempted. Thus billing is always the final acquired authority. The caller supplies stable `requestId` and `admissionId` values. If any later step fails, newly acquired reversible resources are released in exact reverse order: billing (when its response authority is unknown), API-key RPM, user RPM, account RPM, then the account lease. A retry does not release a resource that predated that retry.

Committed RPM records have an internal exact-identity rollback used only before Admit returns. A lost or malformed RPM reserve response speculatively rolls back that exact fenced identity before earlier scopes. A lost lease-acquire response invokes `/abort`, which requires the exact account, request, owner, and admission fingerprint; stale owner/fingerprint calls cannot mutate a lease. Any unknown authority or compensation failure fails closed and is returned as reconciliation-required rather than a clean rejection.

There are still unavoidable process-death windows because the objects and D1 billing reservation cannot commit atomically. A death before billing leaves only short-lived pending RPM reservations and a fenced lease. A death after billing may leave a reservation until bounded scheduled recovery calls the billing expiry transition; DO alarms independently expire pending counters and leases. If billing expiry commits before that cleanup completes, the recovery sweep retains the expiry transition as a bounded cleanup candidate and retries the same exact terminal actions. Delivery and alarms are at-least-once and not exact-time timers. A request that reached the upstream start marker is moved to billing `unknown/prompt reconciliation` rather than refunded as if no upstream execution occurred.

## Selection behavior and terminal release

The runtime feeds only qualified snapshots to `decideSchedulerPolicy`. Sticky selection remains inside the eligible set; a stale capability, active cooldown, temporary block, exhausted concurrency, or exhausted account/user/API-key RPM gate causes deterministic failover. Repeating the same validated input and snapshot produces the same decision.

Admission uses the stable `request_id` for stickiness and DO idempotency plus a bounded semantic fingerprint. Changed semantic payloads conflict. Successful completion and any path that may have reached upstream settle RPM records exactly once, preserving their count through the current fixed window. A pre-start release rolls the exact RPM identity back. Both paths then release only the matching fenced lease; replays cannot release a newer lease token.

The scheduled handler performs bounded outbox and stale-admission recovery only. Recovery scans at most 25 rows whose durable `scheduler_release_state` is still `pending`: stale `reserved`/`started` rows are eligible after a 15-minute age threshold, while terminal `completed`/`released`/`unknown` rows are eligible immediately for idempotent scheduler cleanup. Each expiry uses the reservation's expected version and a deterministic operation ID/evidence digest. Reserved rows are refunded and RPM-rolled-back; started rows become `unknown` without refund and their RPM is settled. A completion returns success once billing commits even if the later DO cleanup fails, preventing a false client retry; cron then retries that exact pending cleanup. Repeated delivery cannot double refund or charge. The handler does not call or keep the Container alive, and no public internal route or credential-bearing scheduler record is introduced.

## Acceptance boundary

Local foundation acceptance consists of workerd/Vitest state-machine tests, strict TypeScript, generated-binding drift checks, fresh/repeated local D1 migrations, and canonical Go bridge tests. Those checks prove deterministic local wiring and preservation of the traditional service regression surface. They do not prove that a Worker, Durable Object migration, D1 database, Queue, or cron exists in a Cloudflare account. Deployed acceptance separately requires an authorized deployment plus remote Worker/DO/D1/Queue/cron readback and real bridge/upstream requests; none of those actions are performed by this work.
