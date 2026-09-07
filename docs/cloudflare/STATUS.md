# Cloudflare migration status

Updated: 2026-09-07. Baseline: `ab99d56e9626e6cd731592dae8553c9758a0efa2`.

## Completed and locally evidenced

- Added bounded Cloudflare-mode administrator account CRUD for OpenAI API-key
  accounts through the private Worker management routes. The local contract is
  limited to name, active/inactive status, schedulable, priority, concurrency,
  AES-GCM `api_key`/`base_url`, safe `privacy_mode`, and compatible live groups.
  Account create idempotency fingerprints semantic fields and a credential
  digest rather than the disposable candidate ID; replay returns the original
  committed account without retaining plaintext credentials. Updates preserve
  omitted envelopes, replacements are encrypted, and delete leaves a disabled,
  unschedulable tombstone that admission excludes.
  The embedded console has a dedicated Cloudflare branch for this contract:
  create/edit/filter/list expose only supported fields and actions, omit
  credential replacement when the key is blank, preserve exact decimal-string
  IDs, and suppress legacy probes, bulk tools, and unsupported row actions.
  Traditional-mode components and request payloads retain their existing paths.
  The automated local gate passed the Go 1.27 bridge package, Worker TypeScript
  and generated types, workerd (8 files / 55 tests), the five focused frontend
  files (106 tests), and the full frontend suite (257 files / 1884 tests),
  typecheck, read-only lint, and production build. At revision `507a64cf6`, a
  fresh real-Chromium composition then passed account list/detail (including
  the shared `timezone` parameter), create, edit with omitted-credential
  preservation, credential replacement, status/scheduling toggles, and delete.
  The corrected create modal made no Antigravity mapping, TLS, quota, or Web
  Search request; every account request returned 200 and no response disclosed
  credentials. Persisted D1 readback found both exercised accounts disabled,
  unschedulable, tombstoned, AES-GCM-enveloped, and linked to their selected
  group, with the expected operation rows and no foreign-key violations. A
  production-config Wrangler dry-run at the same revision rebuilt the frontend,
  Go binary, and distroless Container image and produced a 169.43 KiB Worker
  bundle (36.32 KiB gzip) without mutating Cloudflare resources.
  OAuth/import/test/refresh/batch/export and other platform/type paths remain
  unavailable; this is not remote deployment or real-upstream evidence.

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
  mutations, the bounded admin-user mutation slice, and the bounded admin
  API-key group-rebind slice described below.

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

For the admin-user lifecycle above, this is a local composed **API** runtime
result, not visual browser acceptance: the embedded console document and nonce
were checked over HTTP, but that create/update/delete sequence was not driven in
a real browser. Remote Cloudflare verification, real-upstream verification, and
production acceptance remain separate gates.

## Stage C admin API-key group rebind: local composed browser gate passed

- Cloudflare mode now implements the existing
  `PUT /api/v1/admin/api-keys/:id` contract only for binding a live key owned by
  an active user to a live, active, standard OpenAI group. The traditional
  handler and the generic private API-key patch allowlist are unchanged.
- The public request accepts exactly one positive `group_id`; unbind, reset,
  quota/rate, unknown, duplicate, malformed, and unsafe numeric fields fail
  closed. Decimal-string IDs preserve values above JavaScript's safe range.
- The modal read path now has a strict owner-scoped
  `GET /api/v1/admin/users/:id/api-keys` bridge. It caps pages at the private D1
  contract's 100-row limit, enriches each key with its current group, clears raw
  key material again at the public boundary, and accepts only pagination/sort
  parameters plus the shared frontend client's ignored `timezone` parameter.
- Exclusive-group access is appended from the current D1 JSON array in the same
  sequential batch as the key update. Conditional zero-row writes deliberately
  fail the batch, so concurrent grants, liveness changes, the 100-group limit,
  or an `is_exclusive` transition cannot leave only one side committed.
- The embedded console detects Cloudflare mode from injected public settings,
  hides unbind, and offers only active standard OpenAI groups. Traditional mode
  retains its existing selector behavior.
- Isolated automated evidence passed: Go 1.27 cloudflarebridge package tests;
  workerd-backed Worker tests (8 files / 55 tests); the focused frontend
  component suite (3 tests), typecheck, and lint; and a Wrangler 4.129.0
  production-config dry-run that rebuilt the frontend, Go binary, distroless
  image, and 160.55 KiB Worker bundle (35.22 KiB gzip).
- A before/after local composition first reproduced the previous candidate's
  missing owner-key route as HTTP 404. Real Chromium then exposed and closed a
  second integration gap: every GET receives the browser timezone, which the
  strict new route initially rejected. The final route returned 200 in the
  embedded console without weakening its actual filter allowlist.
- In real Chromium, the key modal showed `fixture-group` as the initial group,
  offered only the two active standard OpenAI groups, omitted both the disabled
  group and unbind, and sent a successful rebind to
  `exclusive-browser-target`. The UI displayed the automatic exclusive-access
  grant notification; after a full reload it still showed the new group.
  Wrangler logged the owner-key GET, group-list GET, and rebind PUT as 200.
  Direct D1 readback found key `3001` on group `2002` and user `1001` with
  exactly `["2001","2002"]` in its allowed-group array.

This is a bounded local browser/composition result. It is not remote
Cloudflare, production, real-upstream, or broad console acceptance; unrelated
console surfaces that are still outside the migration contract continue to
fail closed.

## Explicitly not complete

This branch is not yet a full Sub2API Cloudflare migration. Account writes
outside the bounded OpenAI API-key CRUD contract, user role/step-up operations,
dedicated balance changes,
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

1. Retain a dedicated concurrency probe for a group-reference change racing a
   user mutation, and drive the remaining embedded-console flows—especially
   ambiguous admin-user create retry—in a real browser. The bounded account
   CRUD and API-key rebind browser flows plus the composed API lifecycle now
   pass separately.
2. Treat the existing user-owned API-key lifecycle plus the administrator
   owner-list/group-rebind contract as the complete current API-key management
   surface; do not invent administrator CRUD routes absent from the upstream
   public contract. Keep OAuth/import/test/refresh/batch/export account
   operations fail-closed until separately designed and tested.
3. Design role promotion/demotion and balance changes only with their required
   step-up, audit, reservation, and ledger semantics. Default subscription and
   default-balance behavior must also be made explicit.
4. Expand account selection and policy state only after those durable CRUD
   contracts are stable. OAuth, payment, and background-job work remain stage D
   gates, not implied by CRUD success.
5. Keep remote Cloudflare and real-upstream verification behind their separate
   authorization and disposable-resource requirements.
