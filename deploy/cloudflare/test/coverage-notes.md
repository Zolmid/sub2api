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

The suite currently passes 6 files / 32 tests. Containers are not emulated by
the Vitest pool, so Docker build, private HTTP/HTTPS interception, SSE, idle wake,
two-process concurrency and process-death recovery are separately exercised with
real local `wrangler dev`. Neither layer is treated as remote Cloudflare proof.
