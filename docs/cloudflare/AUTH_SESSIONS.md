# Cloudflare Auth Sessions

This slice stores refresh-token session state in D1 for the private
Container-to-Worker protocol only. It does not expose a public management API
and it does not validate a remote deployment.

## Authority and Wire Contract

D1 is the durable authority for refresh-token sessions. The Container calls
`sub2api.internal` with the existing bridge/version/container headers and these
private endpoints:

- `POST /v1/auth-sessions/store`
- `POST /v1/auth-sessions/get`
- `POST /v1/auth-sessions/delete`
- `POST /v1/auth-sessions/revoke-user`
- `POST /v1/auth-sessions/revoke-family`
- `POST /v1/auth-sessions/list-user`
- `POST /v1/auth-sessions/list-family`
- `POST /v1/auth-sessions/contains`
- `POST /v1/auth-sessions/rotate`

Session records contain only:

`token_hash`, `user_id`, `token_version`, `family_id`, `binding_hash`,
`created_at`, and `expires_at`.

`token_hash` is the full SHA-256 hex digest of the refresh token. The optional
`binding_hash` preserves the existing Go session-binding contract: either an
empty string or the 32-character lowercase hex encoding of its truncated
SHA-256 fingerprint. Refresh and access tokens must never be sent to, returned
by, or stored in the Worker. Numeric identifiers and counters that cross
JSON/JavaScript boundaries use canonical decimal strings; `token_version` is
stored as text so non-negative int64 values do not lose precision.

## Rotation Atomicity

`/rotate` accepts `old_token_hash` plus one complete replacement session
record. D1 consumes the old active token, inserts the replacement, records a
bounded audit digest, and inserts a rotation witness in one D1 batch. The
witness trigger asserts that the consumed row and replacement row match the
same user, family, binding hash, and user revocation `token_version`. A normal
refresh rotation deliberately keeps that version unchanged; password or
credential changes invalidate the family before rotation rather than using
the refresh-token sequence as the user version.

This is a D1 atomic protocol, not a distributed transaction. If the batch fails
before the witness is created, callers receive a stable conflict, expiry,
revocation, not-found, or reuse outcome and may retry according to that code.

An exact retry of the same old/new pair may return success after reading the
existing witness. A different replacement after the old token has already been
consumed is treated as refresh-token reuse: the whole family is revoked, active
descendants become unusable, and list/contains/get stop treating the family as
active.

## Failure Boundaries

Stable machine codes include:

- `INVALID_REQUEST`
- `AUTH_SESSION_NOT_FOUND`
- `AUTH_SESSION_EXPIRED`
- `AUTH_SESSION_REVOKED`
- `AUTH_SESSION_REUSE`
- `AUTH_SESSION_CONFLICT`
- `AUTH_SESSION_UNAVAILABLE`

`AUTH_SESSION_UNAVAILABLE` means the Worker could not safely consult or update
D1. It is not a fail-open result. Callers should retry or require operator
review depending on where they are in the login flow.

Audit rows contain event type, subject identifiers, UTC time, and a SHA-256
detail digest only. They do not contain token plaintext, request bodies, access
tokens, refresh tokens, or key material.

## Key-Loss Boundary

This runtime only receives hashes. If the Container loses the plaintext refresh
token or the material needed to compute the same hash, D1 cannot reconstruct it.
The safe recovery path is to revoke the affected token, user, or family and
force a new login flow.
