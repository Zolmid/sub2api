# Encrypted settings runtime foundation

`0015_settings_runtime.sql`, `src/settings-runtime.ts`, and
`src/settings-control.ts` provide the Cloudflare-native encrypted settings
repository and its private Worker adapter. Traditional PostgreSQL settings
remain unchanged. This Worker lane neither wires Go callers nor creates remote
secrets or deploys resources.

## Private Worker control-plane contract

The adapter is reachable only through the existing Container outbound bridge:
`http://sub2api.internal`, `POST`, and the exact current
`X-Sub2API-Bridge-Version`. It additionally requires a non-empty
`X-Sub2API-Container-Id` of at most 256 characters. The ID is a private-bridge
identity check only; it never selects the settings account or domain. The
server owns the fixed `SettingsRuntime` scope identity
`accountId=sub2api-settings-control-v1` and
`domain=worker-private-control-plane-v1`.
Public Worker ingress reserves the complete `/v1/private` namespace before
Container forwarding, including normalized and encoded path variants.

The body is a JSON object within the shared 64 KiB control-plane limit. Every
route rejects unknown fields. These are the only accepted paths; prefixes and
descendants not listed here are `404 NOT_FOUND`.

| Path | Exact body | Runtime call and success response |
| --- | --- | --- |
| `/v1/private/settings/get` | `{ "key" }` | `get(key)` result, including JSON `null` |
| `/v1/private/settings/get-value` | `{ "key" }` | `getValue(key)` JSON string |
| `/v1/private/settings/get-multiple` | `{ "keys" }` | `getMultiple(keys)` result |
| `/v1/private/settings/get-all` | `{}` | `getAll()` result |
| `/v1/private/settings/set` | `{ "key", "value", "request_id", "expected_version"? }` | `set(...)` result |
| `/v1/private/settings/set-multiple` | `{ "values", "request_id", "expected_version"? }` | `setMultiple(...)` result |
| `/v1/private/settings/delete` | `{ "key", "request_id", "expected_version"? }` | `delete(...)` result |
| `/v1/private/settings/mutate` | `{ "mutations", "request_id", "expected_version"? }` | `mutate(...)` result |

`mutations` contains only the runtime's exact `{ "kind": "set", "key",
"value", "expected_version"? }` or `{ "kind": "delete", "key",
"expected_version"? }` shapes. `expected_version` and `request_id` retain the
runtime's canonical string validation and CAS/idempotency behavior. Successful
responses preserve the runtime result rather than exposing envelope fields or
secret material.

Malformed or oversized JSON and runtime `INVALID_INPUT` are `400`. A missing
setting is returned as JSON `null` by `get`, while `get-value` reports
`404 SETTING_NOT_FOUND`. The endpoint-specific code prevents an absent or
version-skewed private route's generic `404 NOT_FOUND` from being mistaken for
an absent setting by the Go repository.
`CAS_MISMATCH`, `IDEMPOTENCY_COLLISION`, and
`VERSION_EXHAUSTED` are `409`. Corruption, idempotency-witness corruption, D1
errors, secret configuration errors, and unexpected failures return only
`503 SETTINGS_UNAVAILABLE`; exception text, data keys, fingerprint material,
nonces, ciphertext, and setting values are not logged or returned by those
errors.

## Worker keyring secret contract

The adapter reads exactly one Worker **secret string binding**, intentionally
not a Wrangler variable or generated Env field:
`SUB2API_CF_SETTINGS_KEYRING`. Its UTF-8 JSON value is at most 8192 bytes and
has exactly this shape (with `previous` optional):

```json
{
  "current": { "id": "2026-09", "key": "<32-byte-canonical-base64url>" },
  "previous": [
    { "id": "2026-08", "key": "<32-byte-canonical-base64url>" }
  ],
  "fingerprint": "<distinct-stable-32-byte-canonical-base64url>"
}
```

Every key encoding is unpadded canonical base64url for exactly 32 bytes (43
characters). IDs match `[A-Za-z0-9._:-]{1,64}`. There is one `current` key and
at most eight `previous` keys. IDs and data-key bytes are unique across the
whole keyring, and no data key may equal the distinct fingerprint key.
Malformed, duplicate, oversized, or missing material fails closed.

Rotate by adding the old current key to `previous` and making a new unique key
current; new writes then use the new key and old rows remain readable. Keep a
previous key until every row encrypted under it is no longer needed. Losing a
data key before that boundary makes its rows permanently unreadable and fails
closed. The fingerprint key is a stable identity key for opaque scopes,
setting IDs, and witnesses; changing it is not ordinary data-key rotation and
requires a separate migration/continuity design.

The Cloudflare Go composition root constructs this adapter only when it is
given the real `*HTTPControlPlane`; it then supplies one `SettingService` to
auth token issuance, JWT/admin validation, backend-mode guards, and the public
settings overlay. It never falls back to PostgreSQL, Redis, or an in-memory
production repository. Package-local bridge tests use an explicit injected
repository seam for fake control planes.

Only `backend_mode_enabled` is overlaid onto the otherwise fixed Cloudflare
public-settings payload (including frontend injection). Its existing
`SettingService` semantics are fail-safe: a missing, malformed, or unavailable
Worker value reads as `false`. Therefore a control-plane outage neither claims
backend mode is enabled nor exposes Worker errors, setting values, or secrets.
Session-binding settings use the same service and the root installs
`SessionBindingContext` before all auth handlers, so newly issued access and
refresh tokens, refresh rotation, and JWT validation share one IP/User-Agent
fingerprint.

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
