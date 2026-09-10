# Cloudflare-native operations runbook

Use this runbook only for the Cloudflare-native slice named in deployment configuration. It does not convert local evidence into remote acceptance and does not authorize changes to Workers, D1, DNS, secrets, providers, or Cloudflare resources.

## Component and authority map

| Component | Binding/configuration | Authority and first evidence |
| --- | --- | --- |
| Worker / Container | `Sub2APIContainer`, `SUB2API_CONTAINER` | Request routing and Go gateway lifecycle; inspect Worker errors and agreed request correlation data. |
| D1 | `DB` | Migrated relational facts, idempotency, completion/outbox, and supported recovery state. Inspect the named database and guarded records. |
| Account lease DO | `ACCOUNT_LEASE` | Per-account lease/fencing; inspect lease conflicts, expiry/release, and D1 admission state together. |
| Rate-limit DOs | `USER_RATE_LIMIT`, `API_KEY_RATE_LIMIT` | Per-user and per-key RPM reservations/fencing; correlate exact admission identity with the account lease and billing reservation. |
| Billing DO | `BILLING_PRINCIPAL` | Per-user reservation transition serialization; D1 remains the monetary ledger and balance authority. |
| Login/TOTP DOs | `AUTH_LOGIN_ADMISSION`, `TOTP_SECURITY` | Login admission and hashed disposable TOTP/session state; never extract plaintext codes or secrets. |
| KV | `CONFIG_CACHE` | Rebuildable, non-sensitive cache only. A KV value cannot overrule D1. |
| Usage Queue / DLQ | `USAGE_QUEUE`, `sub2api-usage`, `sub2api-usage-dlq` | At-least-once delivery; inspect D1 usage outbox/projection/dedupe with Queue retry/DLQ state. |
| Background-job Queue / DLQ | `JOB_QUEUE`, `sub2api-background-jobs`, `sub2api-background-jobs-dlq` | Opaque versioned envelopes only; inspect D1 job/outbox/transition state, lease fencing, retry, and manual-review evidence. |
| Cron | `*/2 * * * *` | Scheduled maintenance trigger; inspect execution/error evidence and durable follow-up state. |
| Traditional mode | Docker Compose, PostgreSQL, Redis | Independent fallback/continuity path; do not conflate its health with Cloudflare readiness. |

## Monitoring baseline

For every incident capture UTC window, Worker/version/config identity, resource identities, correlation IDs, error class, and traffic decision. Redact API keys, JWTs, passwords, TOTP values, credential envelopes, payment data, email tokens, and secret material.

- **Worker/Container:** error rate, HTTP status mix, startup/restart, request duration/stream interruption, configuration/readback mismatch.
- **D1:** query/write errors, schema/migration version, guarded-update conflicts, outbox backlog, validation failures, available export/Time Travel point.
- **Durable Objects:** lease/RPM contention, stale owner/fence results, billing reservation conflicts, admission denials, TOTP/session replay failures, delayed/failing alarms, unexpected restarts.
- **KV:** cache misses/staleness and rebuild failures; never treat a cache value as an authorization or balance fact.
- **Queue/DLQ:** producer/send failures, retries, age/backlog, redelivery, DLQ entries, and matching D1 outbox/dedupe rows.

## Incident procedures

### Authentication, admission, or TOTP failure

1. Confirm Cloudflare mode and capture a redacted correlation ID/status; do not request a password, code, JWT, or secret.
2. Check Worker errors, `AUTH_LOGIN_ADMISSION` rate-limit behavior, and `TOTP_SECURITY` revision/session-replay outcomes.
3. Verify expected secret *names* and fixture-off runtime configuration; never read or rotate values during triage.
4. If configuration/secret drift is suspected, stop rollout or use the approved traditional path. Rotate only through the key-rotation process below.

### Scheduler, rate limit, or lease contention

1. Capture account/request IDs, admission result, lease owner/fence/expiry, rate decision, and whether an upstream request started.
2. Inspect `ACCOUNT_LEASE`, `USER_RATE_LIMIT`, `API_KEY_RATE_LIMIT`, `BILLING_PRINCIPAL`, and D1 admission/outbox facts together; never repair a stale owner by deleting rows or bypassing fencing.
3. If an upstream attempt may have started, classify its result as unknown until durable reconciliation has evidence. Do not blind-retry.
4. Reduce or stop Cloudflare traffic and use traditional mode only under the approved continuity decision if contention is widespread.

### Billing or payment inconsistency

1. Stop the affected Cloudflare write path and preserve idempotency key, immutable audit/ledger evidence, request digest, and provider correlation ID where available.
2. Do not refund, recharge, replay, or mutate D1 rows by hand. A payment result must be immutable and a refund must have a recoverable transition before acceptance.
3. The tracked Cloudflare documents do not establish full payment production integration. Escalate to payment owner; keep the feature disabled or on approved traditional implementation until a tested repair/reconciliation plan is authorized.

### Email or background-job failure

1. Identify the usage Queue, background-job Queue, or email path. The job Queue dispatcher is configured, but a concrete executor or email provider is not presumed live merely because its runtime module exists.
2. For configured Queue work, compare Queue message identity/version with its D1 outbox and dedupe/effect or job-transition records. Redelivery may be valid; duplicate effects are not.
3. For DLQ or an unknown side effect, preserve opaque identity and provider evidence. Do not expose payloads, tokens, recipients, or bodies.
4. Replay only through a supported idempotent/recovery contract after an explicit owner decision; otherwise hold for manual review.

### Queue redelivery or DLQ backlog

1. Pause promotion if send/consumer errors rise or DLQ grows.
2. Verify whether D1 committed outbox before publication and whether consumer committed a deduped effect before ack. These are separate crash windows, so duplicates are expected but must be harmless.
3. Classify each message as safely deduplicated, retryable without external side effect, or unknown/manual review. Do not bulk-replay a DLQ.
4. Escalate persistent backlog, message divergence, or unknown external effects with redacted correlation IDs and D1/Queue evidence.

### Protocol or upstream failure

1. Record upstream host class, status, timeout/stream phase, request ID, and whether response bytes or a provider-side effect may have occurred.
2. Confirm `SUB2API_CF_UPSTREAM_ALLOWED_HOSTS` is restrictive and fixture mode is off. Do not relax the allowlist while diagnosing an outage.
3. Do not retry a request that may have reached upstream solely because Worker/client disconnected. Reconcile admission/usage state first.
4. Escalate TLS, redirect, SSRF boundary, secret exposure, or cross-tenant data indications as security incidents and stop affected traffic.

### D1 migration or recovery failure

1. Stop writers and traffic cutover. Preserve exact bundle digest, import/validation files, D1 export checksum, Time Travel bookmark, and command result.
2. If outcome is unknown, inspect provenance, counts, checksums, foreign-key/integrity validation before retrying. Replay only exact reviewed file when all existing rows are byte-equivalent.
3. On divergence, do not replay. Escalate with `MIGRATION.md`; restoring a bookmark overwrites D1 and needs explicit destructive approval plus post-cutover-write reconciliation.

### Key rotation

The declared secrets have no documented operator-safe in-place multi-key rotation procedure in this bounded slice. Treat suspected compromise as security incident: restrict traffic, preserve evidence, identify affected encrypted records/sessions, and obtain an approved migration/rollback plan. Do not overwrite a key or re-encrypt records ad hoc.

### Rollback and escalation

For a configuration-only regression with no authoritative D1 writes, an authorized operator may return to prior reviewed Worker configuration and verify it. For D1 writes, stop first: Worker rollback does not roll back D1. Follow `MIGRATION.md` for export, Time Travel, reconciliation, and destructive-restore boundaries.

Escalate immediately for data exposure, secret/key suspicion, payment mismatch, unknown upstream effect, D1 divergence, persistent DLQ growth, or failed rollback. Include redacted evidence and name the required decision owner: Cloudflare operator, database/migration owner, security owner, payment owner, or traditional-service owner.
