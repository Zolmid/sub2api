# Cloudflare-native architecture

Status: staged migration, with the first gateway and bounded management/TOTP
vertical slices locally verified. This document does not claim full
compatibility; see
`COMPATIBILITY.md` and `STATUS.md` for the remaining baseline surface.

Platform behavior and package APIs were checked against Cloudflare's official
documentation and published package types on 2026-09-06. The implementation is
locked to the versions in `deploy/cloudflare/package.json` and to the generated
Wrangler binding types rather than hand-written environment declarations.

## Decision 1: additive composition root

Traditional mode remains the default and retains its existing PostgreSQL and
Redis graph. `SUB2API_DEPLOYMENT_MODE=cloudflare` selects a separate composition
root in `backend/cmd/server/main.go` before setup, config-file loading, Ent, SQL,
or Redis initialization can run. There is no fallback to an in-memory, local
file, PostgreSQL, or Redis implementation when a Cloudflare operation is not yet
migrated; the adapter returns `ErrNotMigrated` instead.

The first slice deliberately reuses the original Gin API-key middleware,
request parser, service-tier validation, OpenAI Chat Completions forwarding,
SSE handling, error conversion, usage extraction, SSRF checks, and HTTP
transport. Selection and persistence are moved outside that service graph. This
is a seam for incremental migration, not a second gateway implementation.

## Decision 2: private, versioned Container-to-Worker protocol

The Go Container calls only `http://sub2api.internal`. The Container SDK's
outbound host mapping intercepts that virtual hostname and dispatches it to a
Worker handler with D1, KV, Queue, and business-DO bindings. The hostname is not
a public route, the Go process refuses any other control-plane URL, the default
HTTP client ignores proxy environment variables and refuses redirects, and the
Worker rejects internal protocol paths reached from a public request.

The installed Containers SDK registers static handlers through inherited
setters. The implementation therefore assigns `outboundByHost` and `outbound`
after defining `Sub2APIContainer`; a native static class field would shadow the
setter and leave `ContainerProxy` without a handler. A regression test locks
this runtime-sensitive invariant.

Every call includes `X-Sub2API-Bridge-Version: 2026-09-08.v2`. Incompatible
control-plane changes require a new negotiated version. Usage envelopes retain
their independent `2026-09-06.v1` schema version. Persistent identifiers,
epochs, token counts, durations, and authoritative E8 USD amounts cross JSON as
decimal strings so JavaScript cannot round them. Raw API keys appear only in
the private auth request body; the Worker hashes them before lookup and neither
side logs them.

The v1 operations are:

| Operation | Authoritative effect | Idempotency or fencing |
| --- | --- | --- |
| Resolve API key | D1 reads key, user, and group state; KV may provide only a rebuildable hash alias | D1 status and relationship checks remain authoritative |
| Touch API key | D1 updates last-used metadata | Monotonic/latest timestamp update |
| Admit request | D1 validates the active immutable pricing snapshot and creates or reads the request admission; an account business DO grants capacity | Server-generated `request_id`; admitted pricing version/digest/rule and DO lease identity are fixed on the request |
| Renew lease | Account business DO extends one matching active lease | Full request/account/lease/owner/epoch match required |
| Complete request | D1 records immutable outcome/usage and an outbox event | Stable server-generated `event_id`; different payload for one ID is a conflict |
| Release lease | Account business DO removes a matching lease | Repeated release is safe; stale owner or epoch cannot release a newer lease |
| TOTP setup/login/disable | D1 owns the encrypted TOTP envelope and revision; the user-keyed `TOTPSecurityDO` owns short-lived challenges and attempt state | Setup/login tokens are stored only as hashes; setup completion is replay-safe and every D1 mutation is revision-guarded |
| TOTP step-up | The user-keyed `TOTPSecurityDO` verifies a code and records a short-lived grant for the current JWT session hash | The grant must match user, session hash, non-expired revision, and current enabled TOTP state |
| Administrator role change | Go verifies JWT/TOTP policy; the Worker rechecks the exact user/session grant and atomically writes the D1 user, management operation, and immutable audit row | Actor-scoped idempotency fingerprint covers target, role, and every supplied patch field; a guarded predicate preserves at least one live administrator |

The Go lease keeper renews at one third of the lease TTL. Cloudflare-marked
upstream contexts preserve cancellation through the original forwarding code;
if the lease expires after renewal failures, the active upstream HTTP request is
canceled. Traditional requests retain their previous detached-context behavior.

## Decision 3: state ownership

| State | Authority | Why |
| --- | --- | --- |
| Users, API-key hashes, groups, accounts, request admissions | D1 | Durable relational facts and queryable recovery state |
| Completion events, outbox, usage records and future ledger entries | D1 | Durable idempotency and reconciliation; monetary values use fixed-point integers or exact decimal text, never `REAL` |
| Per-account active leases, concurrency, cooldown, refresh version | `AccountLeaseDO`, keyed only by account ID | One serialization authority even when the account belongs to multiple groups |
| TOTP challenges, attempt lockout, and step-up grants | `TOTPSecurityDO`, keyed only by user ID | One serialization authority per user; only token/session hashes and bounded expiries persist in DO SQLite |
| Administrator role-change audit | D1 `admin_role_change_audit` | Minimal durable actor/target/old/new-role facts; update/delete triggers make records append-only |
| Container process routing/lifecycle | Container SDK lifecycle Durable Object | Infrastructure lifecycle only; it never owns account/business coordination |
| Rebuildable, non-sensitive aliases or display/config snapshots | KV | Staleness is acceptable and every security decision can fall back to D1 |
| Usage settlement/projection delivery | Queue, sourced from the D1 outbox | Delivery is at least once; the D1 consumer transaction owns dedupe plus effect |
| Account and TOTP secrets | Purpose-separated AES-GCM envelopes in D1; key material from a Worker secret binding | Random IVs and authenticated purpose data prevent cross-protocol envelope reuse; no plaintext secret, Base64-as-encryption, or key in source/config |
| Go Container filesystem | No durable authority | Container restarts and sleep may discard all local files |

The approved product set has no durable object store for image/file bytes. If
the audited upload, image retention, plugin binary, or backup surfaces must be
preserved in Cloudflare mode, adding R2 (or another explicitly approved product)
is a declared architecture decision, not an implicit substitution.

## Request and event flow

1. The external Worker streams the request to the Go Container without reading
   or cloning the body.
2. The original Go middleware extracts the bearer key and calls private auth
   resolution. D1 remains authoritative even if a KV alias is present.
3. Go parses the original request and asks the Worker to admit it. The Worker
   records the server-generated request ID and attempts candidate accounts via
   their account-keyed business DOs.
4. The selected DO atomically grants a recoverable lease. The Worker decrypts
   only that account's credential and returns the account plus fenced lease.
5. The original Sub2API OpenAI forwarding path streams to the authorized
   upstream. The Go lease keeper renews in parallel and can cancel the upstream.
6. Go posts one deterministic completion event. D1 persists the completion and
   outbox record before any Queue publication is treated as successful.
7. An outbox dispatcher sends the stable event to the Queue. Duplicate sends are
   expected. The consumer atomically inserts its dedupe record and usage effect
   in D1; a payload mismatch for the same event ID is an auditable conflict.
8. Go releases the exact lease in a bounded cleanup context. Expiry plus the DO
   alarm recover capacity after Container death or a lost release.

## TOTP and session step-up flow

1. After current-password verification in Go, the Container asks the private
   Worker to begin setup. The user-keyed DO creates a random secret, encrypts it
   before D1/DO persistence, and returns the plaintext only for the one-time QR
   setup response.
2. Setup completion verifies the submitted code, conditionally writes the D1
   envelope/enabled timestamp/revision, and marks the setup complete. Replaying
   the same completed setup is idempotent; a changed revision fails closed.
3. Password login for a TOTP-enabled user returns a five-minute unpredictable,
   user-bound challenge instead of a JWT. Successful one-time verification
   reloads the active D1 user and only then issues the normal JWT.
4. Sensitive operations can require a 15-minute step-up grant. Verification
   stores only a hash of the JWT session ID; checking a different session or a
   stale TOTP revision fails.
5. Disable clears the D1 envelope and increments the revision, then deletes
   setup, login, step-up, and attempt state in the DO. Expiry alarms perform the
   same cleanup for abandoned transient rows.

## Administrator role-change flow

1. The existing admin user-edit UI detects an actual role difference, obtains a
   session-bound TOTP step-up grant, and sends a stable idempotency key plus an
   explicit role-operation marker. Ordinary profile edits and neutral same-role
   fields retain their existing non-step-up path.
2. Go admits only a live administrator authenticated by JWT, rejects
   administrator API keys, confirms enabled TOTP and the current session grant,
   and derives an operation ID scoped to the actor. A password patch is reduced
   to an operation-salted Argon2id semantic token before the private call; the
   plaintext never crosses into the Worker.
3. The private Worker validates the exact field allowlist and rechecks the
   actor/session grant against `TOTPSecurityDO`. It fingerprints actor, target,
   requested role, every supplied patch field, and the password semantic token,
   but never the randomized bcrypt hash, JWT, plaintext password, or raw
   session ID.
4. One D1 batch conditionally updates the user and inserts the idempotency
   result plus immutable role audit. If the transition would demote or disable
   the final live administrator, the guarded update affects zero rows and
   returns `LAST_ADMIN_REQUIRED` without an operation or audit record.
5. An identical retry returns the committed response with the replay marker.
   Reusing the key with any changed actor, target, role, field, or password
   returns an idempotency conflict.

## Atomicity and crash boundaries

D1, a Durable Object, and a Queue do not share a distributed transaction.
Correctness is therefore expressed as recoverable state transitions:

- Lease acquisition/release is atomic only inside one account DO's SQLite
  transaction. Candidate selection across accounts is ordered and compensating,
  not cross-object atomic.
- Completion and outbox creation share one D1 atomic batch/transaction boundary.
  A committed outbox row is the durable source for publication recovery.
- Queue publication and marking an outbox row as sent are separate. A crash in
  either direction may cause a resend, so consumer dedupe is mandatory.
- Consumer dedupe and the usage projection effect share one D1 atomic boundary.
  A duplicate identical event is a no-op; a duplicate ID with a changed payload
  is rejected rather than silently swallowed.
- A request may reach the external upstream and then die before accurate usage
  is persisted. The admission remains pending/unknown for reconciliation; the
  system does not invent zero or exact token usage.
- Fencing prevents stale owners from mutating DO state. It cannot revoke bytes
  already accepted by an external upstream during a network partition, so the
  configured account limit needs operational safety margin.

## Lifecycle and security boundaries

- The Container serves no binding-management API and receives no Cloudflare
  account token. Bindings are invoked only through the private outbound handler.
- Authorized upstream hosts are an explicit fail-closed setting. Production
  private hosts and redirects to the internal bridge are rejected. Test-fixture
  mode permits internal resolution only when the sole host is the virtual
  `mock.upstream`; it cannot be combined with an arbitrary host allowlist.
- Two fixed Container names and an artificial upstream delay are available only
  when both `ENVIRONMENT=local` and `ALLOW_TEST_FIXTURE=true`. The routing header
  is removed before entering Go; production ignores it and retains the single
  `gateway` Container. This is a concurrency/lifecycle harness, not a public
  tenant-controlled routing feature.
- The Worker limits internal JSON sizes and validates exact object shapes,
  string IDs, protocol version, state, and lease identity.
- TOTP private routes additionally require a bounded Container identity. D1
  persists only purpose-bound ciphertext and revision state; the DO persists
  only hashes for disposable tokens and sessions. TOTP codes, plaintext
  secrets, temporary tokens, and token prefixes are excluded from logs.
- Role mutation is the only management path that consumes a TOTP step-up grant.
  It requires both the public JWT check and a private Worker recheck. Audit and
  operation responses exclude session identifiers, passwords, bcrypt hashes,
  and semantic tokens.
- Container SIGTERM is handled with a bounded HTTP shutdown. Durable correctness
  does not depend on that grace period: pending admissions, leases, and outbox
  rows remain recoverable.
- Streaming responses are passed through. Once response bytes are committed, a
  late persistence or upstream failure is logged/reconciled rather than replaced
  with an invalid synthetic HTTP response or a transparent second upstream call.

## Migration expansion rule

Each remaining repository or background process is migrated only after its
contract and state owner are named in `COMPATIBILITY.md`. The same contract must
run against the traditional provider and the Cloudflare provider where behavior
is intended to match. Full management, subscription, multi-account scheduling,
reservation/ledger, OAuth refresh, images/files, imports/exports, and operational
recovery remain separate acceptance gates; the initial chat-completions slice
cannot be used as evidence that those gates are complete.
