# Cloudflare migration status

Updated: 2026-09-07. Baseline: `ab99d56e9626e6cd731592dae8553c9758a0efa2`.

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
- Added Cloudflare-mode login/current-user, user-owned API-key CRUD, available
  groups, offline first-admin bootstrap, admin read projections, admin group
  mutations, and the bounded admin-user mutation slice described below.

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

## Stage C admin-user increment: local composed API gate passed

- The existing `POST`, `PUT`, and `DELETE /api/v1/admin/users` console contracts
  now route through the Cloudflare composition root to private Worker handlers
  and D1. Traditional Ent/PostgreSQL wiring is unchanged.
- Create requires a browser-supplied, administrator-scoped idempotency key.
  Retries use an operation-salted Argon2id semantic token so a new candidate ID
  and randomized bcrypt hash can safely replay the committed user without
  persisting plaintext or a reusable password verifier in D1.
- Management responses and operation records exclude password hashes and the
  semantic token. The Go bridge separately reads the private authentication
  projection before accepting a create or password update.
- D1 enforces one live `lower(trim(email))` identity. Group references are
  checked again inside the mutation statement, user updates write only fields
  actually supplied, and deleting a non-admin user tombstones all live API keys
  in the same D1 batch.
- Cloudflare mode intentionally rejects admin creation, role changes, balance
  updates, disabling/deleting admins, disabled-user creation, and concurrency
  zero. Those operations need the missing step-up/ledger policy rather than an
  undeclared downgrade.
- Automated evidence passed in isolated layers: Go bridge tests and vet,
  workerd-backed Worker tests (8 files / 51 tests), frontend production build,
  typecheck, lint, full suite (254 files / 1865 tests), fresh/repeated D1
  migration and fixture import, embedded Go build, and production-config
  Wrangler dry-run (157.50 KiB Worker / 34.70 KiB gzip plus Container image).
- The offline first-admin tool passed its real local preflight, guarded insert,
  and exact readback against a fresh `0001` through `0004` D1 chain. Its schema
  guard now follows the normalized `users_email_live_identity_idx` introduced
  by `0004` instead of requiring the superseded index.
- The post-migration local fixture now supplies non-empty `updated_at` values.
  A real composed request had exposed that the previous legacy-column insert
  produced an invalid group readback even though fixture import itself exited
  successfully.
- A fresh local `wrangler dev` composition passed an HTTP lifecycle through the
  embedded Go Container and private Worker/D1 control plane: console HTML and
  its CSP nonce matched, admin login succeeded, create replay returned the same
  user, a changed payload and normalized duplicate email returned 409, a
  password update supported a new login, a created API key reached the fixture
  upstream, and deleting the user made login and that key return 401. D1
  readback confirmed both user and key tombstones and no foreign-key failures.

This is a local composed **API** runtime result, not visual browser acceptance:
the embedded console document and nonce were checked over HTTP, but its
JavaScript UI was not driven in a real browser. Remote Cloudflare verification,
real-upstream verification, and production acceptance remain separate gates.

## Explicitly not complete

This branch is not yet a full Sub2API Cloudflare migration. Remaining admin API
key and account writes, user role/step-up operations, dedicated balance changes,
default subscriptions/default balance, complete repositories, subscriptions,
pricing, reservation and authoritative monetary ledger, multi-account
scheduling policy, OAuth refresh/rotation, rate limits/cooldowns beyond the
first lease path, batch/images/files, imports/exports, backup/restore,
reconciliation operations, performance/resource measurements, and production
runbooks remain open matrix items. No undeclared fallback supplies them.

Before applying migration `0004_user_live_email_identity.sql` to any existing
D1 database, operators must identify and resolve duplicate live emails after
ASCII case-folding and trimming. The unique index deliberately makes migration
fail instead of choosing an account silently. Internationalized email addresses
are not admitted by the current Cloudflare-mode write contract.

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

1. Drive the embedded console in a real browser for visual/interaction
   acceptance, and retain a dedicated concurrency probe for a group-reference
   change racing a user mutation. The composed API lifecycle itself now passes.
2. Complete the remaining bounded stage C management surfaces: admin API-key
   routes and API-key-account writes, with shared contract tests and no
   PostgreSQL/Redis fallback.
3. Design role promotion/demotion and balance changes only with their required
   step-up, audit, reservation, and ledger semantics. Default subscription and
   default-balance behavior must also be made explicit.
4. Expand account selection and policy state only after those durable CRUD
   contracts are stable. OAuth, payment, and background-job work remain stage D
   gates, not implied by CRUD success.
5. Keep remote Cloudflare and real-upstream verification behind their separate
   authorization and disposable-resource requirements.
