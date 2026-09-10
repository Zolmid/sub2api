# Cloudflare-native deployment guide

This is an operator guide for the bounded Cloudflare-native slice. It is not a deployment authorization. Local checks, a Wrangler dry-run, a staging deployment, and production acceptance are separate gates.

Traditional Sub2API remains supported. `deploy/docker-compose.yml` retains PostgreSQL and Redis. Do not set `SUB2API_DEPLOYMENT_MODE=cloudflare` in that deployment unless an approved Cloudflare cutover has completed. The Cloudflare composition is additive and must fail closed outside its implemented surface; it is not a PostgreSQL/Redis fallback.

## Configuration inventory

`deploy/cloudflare/wrangler.jsonc` is the production template. Before a remote operation, replace its D1 and KV placeholders in a reviewed operator-owned configuration. Do not put secrets in `vars`, source files, shell history, or tickets.

| Kind | Names in the tracked template | Operator rule |
| --- | --- | --- |
| Worker and Container | `sub2api-cloudflare`, `Sub2APIContainer` | The Container is a Worker binding, not an independently managed data store. |
| D1 | `DB` / `sub2api-cloudflare` | D1 is authoritative for migrated relational state. Confirm target identity before each remote write. |
| KV | `CONFIG_CACHE` | Cache only rebuildable, non-sensitive aliases; never use it for auth, balances, leases, or credentials. |
| Durable Objects | `SUB2API_CONTAINER`, `ACCOUNT_LEASE`, `USER_RATE_LIMIT`, `API_KEY_RATE_LIMIT`, `BILLING_PRINCIPAL`, `AUTH_LOGIN_ADMISSION`, `TOTP_SECURITY` | Preserve all five declared migration tags when promoting configuration. |
| Usage Queue | `USAGE_QUEUE` / `sub2api-usage`, `sub2api-usage-dlq` | Delivery is at least once. D1 deduplication/effects, not an acknowledgment, establish business completion. |
| Background-job Queue | `JOB_QUEUE` / `sub2api-background-jobs`, `sub2api-background-jobs-dlq` | Messages carry only opaque job identity/version. D1 job/outbox transitions and lease fencing are authoritative; unknown routes enter manual review. |
| Cron | `*/2 * * * *` | A trigger is not evidence that scheduled recovery/maintenance succeeded. |
| Environment | `ENVIRONMENT`, `ALLOW_TEST_FIXTURE`, `SUB2API_CF_UPSTREAM_ALLOWED_HOSTS`, `SUB2API_CF_LEASE_TTL_SECONDS` | Production template is `production`, `false`, empty allowlist, and `90`; set the allowlist explicitly before real traffic. |
| Worker secrets | `CREDENTIAL_ENCRYPTION_KEY`, `SUB2API_CF_LOGIN_ADMISSION_KEY`, `SUB2API_CF_JWT_SECRET` | Use the secret store only. They protect credential/TOTP envelopes, login-admission sharding, and Cloudflare-mode JWT handling. |

The tracked local config deliberately uses local D1/KV, fixture mode, `mock.upstream`, a five-second lease, two Container instances, a local usage Queue/DLQ, and the dedicated background-job Queue/DLQ. It is neither staging nor production configuration.

## Ordered gates

### Gate 0 — authorization and freeze decision

Obtain explicit authorization for the account, Worker, D1, KV, queues, route/DNS change (if any), staging or production scope, and each D1 write. This guide grants none of those permissions. For data cutover, follow `MIGRATION.md`: freeze approved legacy writers, retain a verified D1 export/Time Travel point, and identify the rollback owner.

### Gate 1 — local, credential-free acceptance

Use repository-pinned tooling:

```sh
cd deploy/cloudflare
pnpm install --frozen-lockfile
pnpm exec wrangler types --check
pnpm run check
pnpm test
pnpm run ci:local
pnpm run dry-run
```

`ci:local` is the decisive aggregate: generated-type checking, TypeScript/Vitest, fresh and repeated local D1 migrations in temporary state, focused Go bridge tests, and the listed traditional-service regression. `dry-run` is `wrangler deploy --dry-run`; it builds artifacts but does not deploy.

For local composition, use only synthetic data and ignored local secrets:

```sh
cd deploy/cloudflare
pnpm run migrate:local
pnpm run fixture:local
pnpm run dev
```

Provide local-only values for the three Worker secrets in ignored `.dev.vars`; never reuse staging or production material. The fixture and `mock.upstream` are not real-upstream evidence.

### Gate 2 — staging preparation

An authorized operator must use a separate staging D1 database, KV namespace, usage Queue/DLQ, and background-job Queue/DLQ, then make an explicit staging config from the tracked template. Set distinct IDs, Worker/queue names, `ENVIRONMENT=staging`, `ALLOW_TEST_FIXTURE=false`, a restrictive upstream allowlist, and the intended lease TTL. Preserve the declared DO migrations and observability.

After configuration/secret-name review, remote commands have this pinned form (substitute only the reviewed config path):

```sh
cd deploy/cloudflare
pnpm exec wrangler d1 migrations apply sub2api-staging --config /secure/path/wrangler.staging.jsonc
pnpm exec wrangler secret put CREDENTIAL_ENCRYPTION_KEY --config /secure/path/wrangler.staging.jsonc
pnpm exec wrangler secret put SUB2API_CF_LOGIN_ADMISSION_KEY --config /secure/path/wrangler.staging.jsonc
pnpm exec wrangler secret put SUB2API_CF_JWT_SECRET --config /secure/path/wrangler.staging.jsonc
pnpm exec wrangler deploy --config /secure/path/wrangler.staging.jsonc
```

These are remote-mutating commands and are not Gate 1. Secret entry must remain interactive/private.

### Gate 3 — staging acceptance

Require evidence, not just Wrangler output: read back Worker bindings/resource IDs; confirm the named staging schema; exercise an authorized synthetic account through Worker, Container, D1/DO lease, both Queue/outbox paths and DLQ recovery; prove fixture routing is unavailable; prove allowlist rejection; and record errors, retries, DLQ state, and observed limits/costs. The background-job dispatcher is wired, but the default executor map intentionally contains no real provider routes; unknown routes move to manual review. Test billing, payment, email, or a concrete job executor only when each is explicitly approved and integrated; their source/tests alone do not prove production readiness.

### Gate 4 — production promotion and smoke

Production needs fresh explicit authorization after staging. Re-verify configuration/resource identities, freeze or drain agreed writers, and complete any approved D1 migration plan before `deploy`. Do not reuse staging IDs, queues, or secrets. After promotion, smoke only agreed low-impact paths: routing, authorized authentication, one controlled gateway request, expected D1/outbox behavior, and queue consumption. Production acceptance additionally requires the agreed functional, security, observability, and rollback criteria.

## Rollback boundaries

Before configuration promotion, retain the prior reviewed Worker configuration/deployment identifier. If authoritative D1 state was not changed, an authorized operator may restore that prior Worker configuration and verify it. Worker rollback never rolls back D1. For data changes, stop writers, preserve incident evidence, and follow `MIGRATION.md`; D1 restore or replay is destructive remote work requiring explicit approval and reconciliation of post-cutover writes.

## Traditional Docker/PostgreSQL/Redis mode

Traditional mode remains independently operable:

```sh
cd deploy
docker compose up -d
docker compose logs -f sub2api
```

The tracked Compose file starts PostgreSQL and Redis, waits for their health checks, and exposes `/health`. Its PostgreSQL migrations are forward-only; use a verified database backup or approved compensating migration for rollback. Do not point this mode at D1 or remove PostgreSQL/Redis because a Cloudflare local gate passed.
