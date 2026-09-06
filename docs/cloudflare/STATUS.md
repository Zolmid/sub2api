# Cloudflare migration status

Updated: 2026-09-06. Baseline: `ab99d56e9626e6cd731592dae8553c9758a0efa2`.

## Completed and locally evidenced

- Locked the upstream source, dependency/tool versions, license, and initial
  test results in `BASELINE.md`.
- Audited the major PostgreSQL, Redis, process-local, filesystem, gateway,
  management, billing, scheduling, OAuth, and background-work surfaces in
  `COMPATIBILITY.md`.
- Verified current official Cloudflare Container, outbound Worker mapping, D1,
  Durable Object SQLite, KV consistency, Queue delivery, Workers testing, and
  platform-limit contracts before selecting APIs.
- Added an explicit Cloudflare composition root before traditional setup and
  PostgreSQL/Redis initialization.
- Added a typed v1 private control-plane client and an API-key repository adapter
  that fails closed for every method outside the first slice.
- Routed `/v1/chat/completions` through the original Sub2API authentication,
  parsing, OpenAI forwarding, streaming/error, and usage extraction code.
- Added recoverable lease renew/release handling and Cloudflare-only upstream
  cancellation while retaining traditional detached-request behavior.
- Added unit coverage for auth, unknown keys, raw-key transport boundaries,
  protocol validation, response limits, account/lease validation, completion,
  release, renew, runtime fail-closed settings, and cancellation semantics.

## Stage B vertical slice: local gate complete

- Added the Worker external entry, private Container outbound handlers, Go image,
  D1 migration/fixture, account-keyed lease DO, KV alias cache, outbox, Queue
  consumer, AES-GCM production credential envelope, and HTTPS mock upstream.
- Fresh migration, repeated migration, explicit fixture import, type generation,
  TypeScript checking, and 27 workerd-backed tests pass.
- A production-config `wrangler deploy --dry-run` builds both the 101.17 KiB
  Worker bundle (23.87 KiB gzip) and the distroless Go image without mutating
  Cloudflare.
- Real local `wrangler dev` requests pass through Worker -> Go Container ->
  private Worker handler -> D1/DO -> HTTPS fixture upstream -> outbox/Queue ->
  D1 usage. Both non-streaming and SSE responses retain their original format.
- Two distinct Go Container instances contend against one account DO: one
  delayed request succeeds, the overlapping request receives 429, and the
  second instance succeeds after release. A 10/15-second silent upstream wait
  also succeeds with a five-second initial lease, proving renewal is active.
- Forced SIGKILL during a 60-second upstream wait returns a detectable 500,
  preserves the D1 request as `admitted`, and recovers the account lease to zero.
  The killed Container then starts cleanly and serves another request using the
  same D1 data. The pending record is intentionally retained for the stage D
  reconciler rather than relabeled as known zero usage.

## Explicitly not complete

This branch is not yet a full Sub2API Cloudflare migration. Management UI/API
write paths, complete user/group/account repositories, subscriptions, pricing,
reservation and authoritative monetary ledger, multi-account scheduling policy,
OAuth refresh/rotation, rate limits/cooldowns beyond the first lease path,
batch/images/files, imports/exports, backup/restore, reconciliation operations,
performance/resource measurements, and production runbooks remain open matrix
items. No undeclared fallback supplies them.

The approved service set also lacks durable image/file object storage. Preserving
those audited features requires an explicit decision to add an object-storage
product such as R2; they have not been silently removed or stored in D1/KV.

## Baseline and environment limitations

- The existing macOS installer test still fails because it uses GNU-only
  `head -n -1`; this predates migration changes.
- OrbStack was started only for local verification. No long-running dependency
  is required by the produced Cloudflare mode; `wrangler dev` and its test
  Containers are stopped after the gate.
- No Cloudflare account resource, production DNS, paid instance, real upstream,
  production credential, or production ledger has been touched.

## Next executable acceptance sequence

1. Begin stage C with one coherent D1-backed management surface: users, groups,
   API keys, and API-key accounts, while retaining the existing HTTP contracts
   and keeping traditional Ent/PostgreSQL providers unchanged.
2. Add contract tests shared by the traditional and Cloudflare providers, then
   reconnect the existing management UI to those routes in Cloudflare mode.
3. Expand account selection and policy state only after those durable CRUD
   contracts are stable. Reservation/ledger, OAuth, payment, and background-job
   work remain stage D gates, not implied by CRUD success.
4. Keep remote Cloudflare and real-upstream verification behind their separate
   authorization and disposable-resource requirements.
