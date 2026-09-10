# Email challenge runtime

`EmailRuntime` is D1 authority for a one-time challenge and its durable,
at-least-once delivery work item. It is deliberately unwired from the Worker
entrypoint and has no mail-provider integration. A caller must construct it
with independently managed token-HMAC and delivery-AES key rings.

## Design

Issuance creates a 256-bit base64url token. D1 stores only a domain-separated
HMAC verifier plus two AES-256-GCM envelopes: one for token recovery by a
fresh worker and one for the opaque delivery reference. The AAD binds the
challenge, account, purpose, envelope kind, and delivery key ID. Plaintext
recipient, message content, delivery reference, and token are never written
to D1, audit, or outbox tables.

An issue replay uses the persisted request-HMAC key ID, so retained previous
token keys can verify old idempotency records after rotation. Exact replays
return metadata only; they never re-disclose a token. The immutable issue
witness links the original challenge, job, audit, and outbox rows. Replay also
recomputes the original audit and outbox MACs using each persisted key ID and
checks their complete challenge/job/audit linkage; missing, inconsistent, or
cryptographically invalid evidence is fail-closed as idempotency-corrupt.

Token-HMAC and delivery-AEAD key rings use independent key IDs and material.
Reusing a key ID or material across purposes is rejected at construction.
Every audit and outbox row persists the HMAC key ID used to compute its MAC,
so historical evidence remains verifiable after key rotation.

## Job lifecycle

Jobs move `pending → claimed → delivered|pending|dead|cancelled`. Claims
receive a fence and lease; renew, complete, and fail require that exact owner,
fence, and an unexpired lease. A crashed worker after an external provider
send can therefore result in another send after lease expiry: delivery is
explicitly at-least-once. This runtime makes no provider call, so provider
idempotency must be implemented at that boundary.

Every successful claim creates an immutable delivery witness linking the job,
audit, outbox, job version, and fence. An expired-lease reclaim always advances
the fence, including if the replacement has the same worker ID: an old process
therefore cannot complete, renew, or fail the reclaimed lease. A complete or
fail after an ambiguous commit (lost response) can safely replay only when the
same fence has exactly one matching immutable audit MAC. That replay is a
no-op and cannot trigger a second send or consume another delivery attempt.

## Guarded state transitions

Every challenge or job transition is a guarded D1 batch with immutable audit
and outbox records. Consuming or expiring a challenge revokes a pending or
claimed job in that same guarded batch. A claim CAS rechecks the selected job's
`not_before`, version, fence, and a still-issued, unexpired challenge, so a
stale selection cannot reclaim a newly deferred or retired job. Each guarded
CAS must modify a row before the rest of its batch commits. A true zero-row
CAS deterministically returns `stale_fence`. D1/constraint/storage failures
such as UNIQUE violations, CHECK failures, immutability trigger rejections,
or unknown errors are classified as `corrupt_state` or `storage_failure`
rather than masquerading as stale CAS.

Expired or exhausted challenges cannot be sent and pending or claimed jobs are
cancelled with evidence in the same transition. Counters are canonical signed-int64 decimal text
and fail closed at exhaustion. SQL CHECK constraints and triggers enforce
NULL-safe bounds, immutable identity fields, legal state transitions, audit/
outbox key IDs, and witness consistency.

## Error classification

- `invalid_input`: malformed request, unknown input fields, prototype tricks,
  invalid Unicode, oversized references, or out-of-range numeric values.
- `clock_failure`: clock returned a non-finite or non-Date value.
- `challenge_not_found`: no matching challenge for the given ID, account,
  and purpose.
- `challenge_expired`: challenge exceeded its expiry time or failed-attempt
  limit.
- `challenge_consumed`: challenge was already successfully verified.
- `invalid_token`: token HMAC verification failed.
- `idempotency_collision`: same idempotency key with changed semantic fields.
- `idempotency_corrupt`: issue witness missing, malformed, or HMAC mismatch.
- `job_not_found`: no job exists with the given ID.
- `stale_fence`: retryable true zero-row CAS detected; job state, owner,
  fence, or lease changed concurrently.
- `counter_exhausted`: version or fence reached int64 maximum.
- `unknown_key_id`: referenced key ID not present in the provided keyring.
- `corrupt_state`: stored row violated invariants, constraints, schema, or
  referential integrity; or a D1 constraint/trigger/uniqueness failure.
- `storage_failure`: retryable unclassified D1 error. Errors are returned as
  stable codes only; D1 exception text, bound values, tokens, and delivery
  references are never logged by this runtime.

## Key rotation

Token-HMAC keys are used for token verifiers, request semantic HMACs, issue
witness HMACs, audit evidence HMACs, and outbox payload HMACs. The current
token key is used for new operations. Previous token keys remain available
for replay verification and historical audit/outbox validation.

Delivery-AEAD keys seal token and delivery-reference envelopes. The current
delivery key is used for new envelopes. Previous delivery keys remain
available to decrypt envelopes created before rotation.

Token and delivery keyrings must use distinct key IDs and material. Reusing
a key ID or material across the two purposes is rejected at construction.

## Acceptance boundary

This runtime does not wire into the Worker entrypoint, queue consumer,
provider, setup, fixture, config, or aggregate suite. It does not deploy or
use real credentials. Existing uncommitted changes elsewhere belong to other
agents. Acceptance tests use the repository's real `cloudflare:test` env.DB
path and the actual migration, not an in-memory fake.
