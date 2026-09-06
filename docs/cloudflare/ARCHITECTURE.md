# Cloudflare-native architecture

Status: staged migration, with the first gateway vertical slice locally
verified. This document does not claim full compatibility; see
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

Every call includes `X-Sub2API-Bridge-Version: 2026-09-06.v1`. Incompatible
changes require a new version/route. Persistent identifiers, epochs, token
counts, and durations cross JSON as decimal strings so an existing Go `int64`
cannot be rounded by JavaScript. Raw API keys appear only in the private auth
request body; the Worker hashes them before lookup and neither side logs them.

The v1 operations are:

| Operation | Authoritative effect | Idempotency or fencing |
| --- | --- | --- |
| Resolve API key | D1 reads key, user, and group state; KV may provide only a rebuildable hash alias | D1 status and relationship checks remain authoritative |
| Touch API key | D1 updates last-used metadata | Monotonic/latest timestamp update |
| Admit request | D1 creates or reads the request admission; an account business DO grants capacity | Server-generated `request_id`; DO returns `lease_id`, owner, epoch, and expiry |
| Renew lease | Account business DO extends one matching active lease | Full request/account/lease/owner/epoch match required |
| Complete request | D1 records immutable outcome/usage and an outbox event | Stable server-generated `event_id`; different payload for one ID is a conflict |
| Release lease | Account business DO removes a matching lease | Repeated release is safe; stale owner or epoch cannot release a newer lease |

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
| Container process routing/lifecycle | Container SDK lifecycle Durable Object | Infrastructure lifecycle only; it never owns account/business coordination |
| Rebuildable, non-sensitive aliases or display/config snapshots | KV | Staleness is acceptable and every security decision can fall back to D1 |
| Usage settlement/projection delivery | Queue, sourced from the D1 outbox | Delivery is at least once; the D1 consumer transaction owns dedupe plus effect |
| Credentials | AES-GCM envelope in D1; key material from a Worker secret binding | No plaintext credential, Base64-as-encryption, or key in source/config |
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
