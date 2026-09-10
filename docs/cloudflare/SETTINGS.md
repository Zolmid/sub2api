# Encrypted settings runtime foundation

`0015_settings_runtime.sql` and `src/settings-runtime.ts` provide a deliberately
unwired Cloudflare-native settings repository. Traditional PostgreSQL settings
remain unchanged. No Worker entry point, configuration, generated binding, or
deployment route imports this foundation yet.

## Use and key material

Construct `SettingsRuntime` with the D1 binding, an account identifier, a
domain, and caller-injected key material. It never reads secrets from Wrangler
variables, writes key material to D1, or logs values. All current and previous
data-encryption keys and the separate fingerprint key are exactly 32 bytes.
Key IDs are explicit, bounded, and stored in the envelope. A rotation writes
with `keyring.current`; reads may use `keyring.previous`. Keep
`fingerprintMaterial` stable throughout the history it identifies; rotate it
only through a separately designed migration because it names opaque scopes,
setting IDs, and witnesses.
The constructor snapshots every supplied byte array and rejects reusing a data
key as fingerprint material, so later caller mutation cannot silently change
the repository's cryptographic identity.

Each live row contains only this logical envelope: version `1`, algorithm
`A256GCM-HKDF-SHA256`, key ID, a new 96-bit AES-GCM nonce, ciphertext, and an
opaque context tag. For every setting value (including non-secret settings),
the runtime HKDF-derives an AES-256-GCM key using the account, domain, setting
key, and key ID. Its authenticated data repeats those identities. A
domain-separated HMAC under the distinct fingerprint material creates opaque
scope, setting, value, row, request, audit, and result fingerprints. Thus no
plaintext, ciphertext, nonce, data key, or low-entropy value hash is placed in
audit/outbox/idempotency metadata. Copying an envelope to another setting,
account, or domain fails authentication/context validation.

The public repository API has `get`, `getValue`, `getMultiple`, `getAll`,
`set`, `setMultiple`, `delete`, and the lower-level `mutate`. Missing reads are
omitted by plural reads; `getValue` raises `NOT_FOUND`, matching the useful
traditional behavior. `getAll` keyset-paginates through every row instead of
silently applying the 16-item mutation bound; `getMultiple` accepts at most
512 unique keys in one caller-controlled request. Returned maps preserve keys
such as `__proto__` as ordinary own data properties. Deletes create encrypted-field-free, versioned
tombstones and are never physical deletes. Reads of unknown key IDs, wrong
keys, invalid base64/envelope fields, tag mismatch, decoding failure, and any
structurally poisoned row fail closed with `CORRUPT` and never return plaintext.

## Writes, CAS, and idempotency

Every write needs a bounded opaque `requestId`. An optional expected version is
explicit CAS (`"0"` is create-only); a missing row with any nonzero expected
version is rejected before encryption or mutation. Even when omitted, the repository reads
the D1 version and conditions the mutation on it, so a conflicting concurrent
write fails with `CAS_MISMATCH`. Versions are canonical decimal text, bounded
at signed 64-bit maximum; timestamps are canonical millisecond UTC text.
Base64url envelopes must use their unique unpadded encoding. Values are at most
16 KiB; keys, IDs, the 16-mutation batch size, duplicate keys, and conflicting
operations are validated before any write. SQL is always parameter-bound.

`mutate` rejects duplicate keys and batches at most 16 changes. Its one D1
`batch()` first records an immutable unique `(scope, setting, expected-version)`
CAS claim, then includes conditional state mutations and a guard whose CHECK constraint
requires every intended row to reach its exact next version, immutable audit
rows, digest/ID-only outbox rows, the idempotency record, witnesses, and guard
cleanup. D1 documents `batch()` as a SQL transaction: a failed statement,
including the CAS guard or unique request ID, rolls back the entire sequence.
That is the atomicity guarantee here. It is not a claim that arbitrary direct
SQL principals are authorization-isolated, nor that D1 transactions extend to
external queues or Workers.

An idempotent replay is a no-op only after the request semantic HMAC matches
and the stored result digest, every witness, immutable audit entry, and outbox
entry agree. A changed semantic payload under the same request ID is
`IDEMPOTENCY_COLLISION`; missing, malformed, or mismatched witnesses are
`IDEMPOTENCY_CORRUPT`. Returned write metadata contains key/version/deleted/
replayed only—not values, ciphertext, nonces, or key material.

## D1 constraints and threat boundary

The migration constrains canonical IDs, versions, timestamps, algorithms,
base64url shapes/sizes, tombstone/envelope consistency, audit/outbox shapes,
and bounded guard counts. Triggers reject settings physical deletion, illegal
version transitions/overflow, literal duplicate nonce+ciphertext transplants,
and update/delete of audit, outbox, idempotency, or witness history. These are
defense-in-depth checks; SQLite cannot independently verify an HMAC or prevent
a principal that is authorized to alter schema/triggers from subverting its own
database. Runtime Web Crypto therefore remains the cryptographic authority and
all bad D1 state fails closed.

Focused real-D1 Vitest coverage exercises encrypted round trips, no plaintext
at rest, nonce uniqueness, key rotation/wrong-key authentication failure,
malformed rows, CAS races, idempotency collision and immutable witnesses,
batch rollback, tombstones, overflow, hostile keys, and bounds. It uses only
test-only fixed key material; this foundation neither creates nor stores a real
secret.
