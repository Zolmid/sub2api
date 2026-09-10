# Cloudflare payment foundation

Migration 0016_payment_runtime.sql and payment-runtime.ts provide a
D1-authoritative E8 USD payment and refund foundation. The Worker now wires it
only through the private Container outbound control plane at these exact
POST-only routes: `create`, `transition`, `create-refund`, `transition-refund`,
`refund-payment`, and `accept-provider-event` under
`/v1/private/payments/`. The adapter requires the bounded Container boundary
header, accepts JSON objects only, delegates all exact field/value validation
to PaymentRuntime, preserves successful runtime snapshots, and sanitizes
corruption/storage failures as `PAYMENT_UNAVAILABLE`. It creates no public
Worker payment route. All amounts, versions,
identifiers, timestamps, states, audit/outbox evidence, provider-event
deduplication, and idempotency witnesses are constrained and immutable where
appropriate.

## Core guarantees

Every accepted operation stores a canonical immutable payment/refund snapshot,
its digest, and the exact immutable audit and outbox event IDs. Replaying the
same semantic request validates those records and returns that original
snapshot, rather than reading mutable current payment state. The returned
result, witness snapshot, replay, and D1 authority are byte and semantically
consistent. A reused idempotency or provider-event key with different semantics
is rejected as IDEMPOTENCY_COLLISION.

Refunds can be reserved with createRefund, then moved through created to
manual_review, succeeded, or failed, and from manual_review to succeeded or
failed using transitionRefund. Reservations are bounded by refunded_e8 plus
pending_refund_e8 no greater than amount_e8. Success settles to the immutable
balanced refund ledger, failure releases the reservation, and manual review
retains it. Manual review retains the reservation in both D1 authority and the
immutable returned snapshot without depending on trigger projection.
refundPayment remains an immediate-success helper.

All mutations use a conditional D1 update whose SQL version expression is
exactly `CAST(CAST(version AS INTEGER)+1 AS TEXT)`, followed by a changes() batch guard,
so stale CAS work and D1 schema/trigger failures roll back before they can
create refund, ledger, audit, outbox, or witness rows. Batch failures attempt
exact immutable replay;
otherwise compare the post-failure validated payment authority with the
pre-mutation snapshot: a changed CAS/version is CONFLICT, unchanged authority
with a D1 schema/storage failure is UNAVAILABLE, and a missing record or a
failed read remains NOT_FOUND or UNAVAILABLE respectively (never inverted).
Malformed authority or witness corruption is CORRUPT_STATE.

## Schema constraints

- Immutable identities: payment_id, account_id, amount_e8, currency, created_at
  for payments; refund_id, payment_id, amount_e8, created_at for refunds
- Versions increment exactly once and fail at signed-int64 max
- Canonical UTC timestamps (year >= 2020) with updated_at >= created_at
- Ledger uniqueness on (payment_id, refund_id, kind), plus a partial unique key
  for one NULL-refund payment settlement per payment
- Ledger kind/refund linkage: payment settlements require NULL refund_id;
  refund settlements require a refund belonging to the same payment
- Audit, outbox, ledger, witness, and provider dedup records are immutable
- Payment state machine: created -> authorized|succeeded|failed|manual_review;
  authorized -> succeeded|failed|manual_review; manual_review ->
  authorized|succeeded|failed; succeeded -> refunded (only when fully refunded)
- Refund state machine: created -> succeeded|failed|manual_review;
  manual_review -> succeeded|failed
- Settlement ledger inserted exactly once per succeeded payment or refund

## Replay validation

Replay must validate the full immutable witness snapshot, canonical JSON/result
digest, exact payment/refund IDs, semantic digest, audit and outbox IDs,
action/topic/state/version and reference linkage. A missing, mutated, or
mismatched witness, audit, outbox, provider dedup, ledger relationship, or
malformed snapshot returns CORRUPT_STATE, not NOT_FOUND or CONFLICT.

Provider event dedup and its provider_event witness are read together before a
callback is projected. If either half is missing or their payment ID or semantic
digest differs, the authority is corrupt; an identical callback replays its
original snapshot after later transitions; a changed payload under a valid
provider ID is an idempotency collision. Concurrent callbacks create at most
one transition and ledger effect.

## Limitations

Provider authentication and provider network actions remain absent: there are
no provider credentials, webhook verification, provider HTTP client, queue
consumer, live charge, or live refund action. Go callers and public payment
endpoints also remain absent. A production integration must authenticate
provider events, perform reconciliation, and obtain explicit authorization for
financial or deployment actions.
