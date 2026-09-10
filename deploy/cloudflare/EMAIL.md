# Private EmailRuntime control plane

`src/email-control.ts` exposes the existing D1-authoritative `EmailRuntime`
only to the Container-to-Worker bridge. It does not send email, call an email
provider, enqueue work, or make any external network request. Provider delivery
is deliberately unwired: a caller may claim a job and report its outcome, but
the caller owns any future delivery integration.

## Private route contract

All routes are `POST` JSON and require the internal host, the current
`X-Sub2API-Bridge-Version`, and a bounded `X-Sub2API-Container-Id`. Public
ingress continues to reject `/v1/private/...` before Container routing.

| Route | Exact body | Success body |
| --- | --- | --- |
| `/v1/private/email/issue-challenge` | `id`, `accountId`, `purpose`, `idempotencyKey`, `deliveryReference`, `expiresAt`; optional `maxAttempts`, `maxDeliveryAttempts` | runtime `IssuedChallenge` |
| `/v1/private/email/verify-challenge` | `id`, `accountId`, `purpose`, `token` | `{ "ok": true }` |
| `/v1/private/email/claim-delivery-jobs` | `worker`; optional `limit` | `{ "jobs": [...] }` |
| `/v1/private/email/renew-delivery` | `id`, `worker`, `fence`; optional `leaseSeconds` | `{ "ok": true }` |
| `/v1/private/email/complete-delivery` | `id`, `worker`, `fence` | `{ "ok": true }` |
| `/v1/private/email/fail-delivery` | `id`, `worker`, `fence`, `errorCode` | `{ "state": "pending" | "dead" }` |

Bodies are capped at 64 KiB. `deliveryReference` is capped at 4,096 UTF-8
bytes; IDs, worker/error strings, counters, UTC timestamps, and attempt/lease
limits are validated before `EmailRuntime` is invoked. The adapter returns only
`INVALID_EMAIL_REQUEST` (400), `EMAIL_NOT_FOUND` (404),
`EMAIL_CONFLICT`/`EMAIL_LEASE_CONFLICT` (409), or `EMAIL_UNAVAILABLE` (503).
The 503 response intentionally hides D1, crypto, key, and corruption details.

## Secrets and rotation

Set two separate Worker secrets; do not use settings, payment, JWT, or any
other Worker key for either ring:

- `SUB2API_CF_EMAIL_TOKEN_KEYRING` for token/challenge HMAC keys.
- `SUB2API_CF_EMAIL_DELIVERY_KEYRING` for AES-GCM delivery-payload keys.

Each secret is a JSON document under 4,096 UTF-8 bytes:

```json
{
  "current": { "id": "email-token-202609", "key": "<32-byte-base64url-without-padding>" },
  "previous": [
    { "id": "email-token-202608", "key": "<32-byte-base64url-without-padding>" }
  ]
}
```

`current` is mandatory. Key IDs must match `[a-z0-9][a-z0-9._-]{0,63}`;
each key is exactly 32 bytes encoded as canonical unpadded base64url (43
characters). At most four `previous` keys are accepted. Each ring rejects
unknown fields, duplicate IDs, duplicate material, malformed JSON, and missing
or non-canonical key material. The runtime also rejects any ID or key material
shared between the two rings.

For rotation, first publish the new key as `current` and move the former
current key into `previous`. Keep it until every still-valid challenge and
delivery lease encrypted or signed with it can no longer be read (including the
maximum challenge lifetime and operational retry window). Then remove it from
`previous`. Rotate token and delivery rings independently, never by copying a
key across rings. Do not put example or production key material in source,
Wrangler vars, logs, or test fixtures.
