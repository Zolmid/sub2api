# Platform test coverage

The workerd-backed suite covers SHA-256 auth lookup and disabled keys/users;
`AccountLeaseDO` idempotency, concurrency, fencing, duplicate release, expiry and
alarm recovery; repeated/conflicting completion and Queue deliveries; outbox
recovery; internal-host ingress rejection; D1 schema constraints; KV fallback;
and the Containers SDK egress-handler registration invariant. Stage C adds
workerd-backed management CRUD tests for users, groups, API keys, and existing
group-bound `apikey` accounts; safe-integer-exceeding decimal IDs; D1 migration
replay; request fencing; malformed and cross-tenant references; one-time raw
key responses; hash-only persistence; and revoke/soft-delete behavior.

The TOTP slice adds purpose-bound AES-GCM secret envelopes, D1 consistency and
revision guards, replay-safe setup, one-time login challenges, supersession,
five-attempt lockout, alarm expiry across Durable Object eviction,
JWT-session-bound step-up, disable cleanup, malformed/missing encryption-key
failure, strict private route allowlists, and Container identity enforcement.

The suite currently passes 9 files / 66 tests. Containers are not emulated by
the Vitest pool, so Docker build, private HTTP/HTTPS interception, SSE, idle wake,
two-process concurrency and process-death recovery are separately exercised with
real local `wrangler dev`. The TOTP lane additionally passed a fresh composed
HTTP flow through Wrangler, the Go Container, D1, and the user-keyed security
DO. Neither layer is treated as remote Cloudflare proof.
