# OAuth refresh runtime foundation

0013_oauth_refresh_runtime.sql provides the D1 authority for account credential versions and encrypted-envelope fingerprints, live/terminal refresh attempts, immutable audit, opaque invalidation outbox, and immutable commit witnesses. The bounded Worker coordinator now binds `OAUTH_REFRESH_AUTHORITY` to `OAuthRefreshAuthorityDO`; it does not add a provider adapter, scheduler, Queue publisher, or public ingress.

The Durable Object has one narrow job: metadata-only single-flight fencing for one account. It receives only canonical account id, credential version, operation id, owner, fence, and trusted-Worker timestamps. It must never receive an envelope, token, provider response, email address, proxy detail, or another secret. It persists its first account id and rejects all future cross-account RPCs. On an expired takeover, its atomic result includes only the predecessor's account/version/operation/owner/fence/expiry metadata; the Worker loads the matching D1 attempt to obtain its fingerprint before terminalizing it.

## Private Container API

Only `POST` requests to `sub2api.internal` with the current
`X-Sub2API-Bridge-Version` and a bounded opaque injected
`X-Sub2API-Container-Id` reach this coordinator. The routes accept exact JSON
objects and never return envelopes, token material, raw storage errors, or
provider data:

- `/v1/private/oauth-refresh/acquire-begin` — `{accountId,operationId,nowMs,leaseMs}`. The Worker loads the active OAuth account's current D1 envelope/version/fingerprint, initializes a missing legacy fingerprint under the existing audited guard, acquires the account-named DO, terminalizes an exact expired predecessor, then begins D1 work. `ready` is 200; busy and terminal domain conflicts are 409; absent/non-refreshable accounts are 404.
- `/v1/private/oauth-refresh/mark-provider-started` — `{accountId,operationId,nowMs}`. This records the pre-network boundary only; it calls no provider.
- `/v1/private/oauth-refresh/commit-success` — `{accountId,operationId,nowMs,nextCredentialEnvelope}`. The Worker checks the encrypted envelope's UTF-8 byte bound, computes its fingerprint locally, performs the D1 CAS/witness batch, and finishes the DO with exactly version plus one. A completed operation replays as 200 without echoing the envelope.
- `/v1/private/oauth-refresh/recover-invalid-grant` — `{accountId,operationId,nowMs}`. It performs the existing fail-closed invalid-grant recovery and releases the DO for a resulting terminal state.

`manual_review` is a 409 fail-closed account state. In particular, an expired
`provider_started` predecessor is terminalized to `manual_review`, its new
takeover lease is released, and no replacement operation is begun until a
future explicit review/remediation capability is authorized.

Malformed values return a sanitized 400. DO/D1/configuration/corruption failures return a sanitized 503. Every public request under `/v1/private/...` remains 404 before any Container routing.

## Required operation order

1. A trusted Worker validates a canonical positive-decimal signed-int64 account id and refreshability, then asks the account's DO to acquire a bounded lease.
2. On a DO takeover, it first calls expireRefreshAttempt for the expired predecessor using the predecessor's exact account/version/fingerprint/owner/fence. A pre_provider attempt becomes the terminal `failed_retryable` state and returns `retry_required`: only a new operation id may retry. provider_started becomes manual_review.
3. It calls beginRefreshAttempt with the exact returned DO fence and expiry. D1's partial unique index permits only one pre_provider or provider_started operation for an account, regardless of version; an expired predecessor must be terminalized first.
4. Immediately before the provider request it calls markProviderStarted. After this phase, unknown provider outcomes are never blindly retried.
5. The adapter keeps old and new encrypted envelopes only in Worker memory and calls commitRefreshSuccess. It first proves both supplied fingerprints are SHA-256 hashes of those envelopes. Its final D1 batch statement inserts a commit witness; a SQLite trigger aborts the entire batch unless account CAS, succeeded attempt, audit, and opaque outbox agree exactly.
6. The adapter calls DO finish: successful completion is exactly leased credential version plus one; a non-successful release uses null.

Timestamps are caller-supplied only by the trusted Worker boundary. Every D1/DO timestamp is bounded to 4,102,444,800,000 ms and validated for monotonicity; an active DO lease rejects a clock value before acquired_at. Callers at or after lease expiry cannot start or commit provider work. Operation ids are opaque ASCII identifiers of 1–120 characters so every derived opaque audit/outbox id stays within its 160-character database bound. Credential versions and fences are exact integers from 1 through 2,147,483,647; a refresh that would exceed that limit is rejected before incrementing.

## Remaining provider-adapter gap

- Existing management writes that replace credential_envelope must atomically increment credential_version and replace credential_fingerprint; they do not do so yet. Legacy fingerprints require guarded, audited initialization.
- A future provider adapter must call these private routes in the documented order, obtain and encrypt a genuinely refreshed envelope outside the DO, reject PAT/non-refreshable accounts, and retain no credential material in logs or durable metadata. This slice does not implement or call any OAuth provider and must not be represented as production refresh support.
- A later outbox dispatcher may invalidate auth and scheduler caches using only account id, credential version, and event type. It must not build a Queue payload containing an envelope.

## Safety semantics

The same operation id is idempotent only when account, expected version/fingerprint, owner, fence, and lease expiry all match. A divergent reuse is a conflict. A completed replay also requires the exact immutable witness, attempt owner/fence, new version, fingerprint, and matching audit digest; it remains valid after later account rotations and otherwise is a conflict. Legacy fingerprint initialization never succeeds without exactly one immutable audit for account/version/fingerprint. immutable attempts, audit, fingerprint-audit, commit witnesses, and outbox rows reject delete; live attempts are append-only too. Outbox identity is immutable and it permits only pending-to-published/dead transitions (or a no-op terminal update), with published_at required exactly for published. invalid_grant becomes already_refreshed only when the conditional D1 transition observes advanced credentials. Results, errors, audit, outbox, and witnesses contain identifiers, versions, states, and hashes only.

The focused suite uses the shared setup's actual 0013 migration, bound workerd DO RPC, deterministic lease-core checks, takeover ordering, D1 CAS, and public-ingress rejection.
