# Platform test coverage

The intended Workers-pool tests cover the following boundary contracts when a local `workerd` build is available: SHA-256 auth lookup and disabled keys/users; `AccountLeaseDO` request/owner idempotency, max=1 concurrency, duplicate release, stale owner/epoch rejection, and alarm expiry; repeated completion (at least ten), conflicting same event IDs, Queue duplicate and ordering behavior, publish failure leaving outbox pending, internal-host ingress rejection, and KV miss/error D1 fallback.

The checked-in unit tests cover deterministic wire primitives. The current local runtime cannot execute `workerd` because the enclosing pnpm workspace policy rejects its build script; Containers themselves are also not emulated by the Vitest pool. Neither limitation is treated as Container platform proof.
