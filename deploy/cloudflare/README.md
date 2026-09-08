# Sub2API Cloudflare vertical slice

This directory is the Worker half of protocol `2026-09-06.v1`. It keeps persistent IDs and all microusd ledger values as decimal strings at the JavaScript/D1 boundary. D1 is authoritative; `CONFIG_CACHE` only caches non-sensitive model aliases.

`Sub2APIContainer` serves the existing Go Cloudflare-mode gateway on port 8080.
`sub2api.internal` is the versioned private control plane;
fixture-gated `mock.upstream` is available only locally. Production upstream
hosts must be listed explicitly in `SUB2API_CF_UPSTREAM_ALLOWED_HOSTS`; every
other host is denied before the stream-preserving outbound path can run.

Stage C adds a private management protocol for the Go Cloudflare adapter. It is
not a public API: every call is `POST` to `sub2api.internal`, with
`X-Sub2API-Bridge-Version: 2026-09-06.v1` and a Container identity header.
The explicit routes are `/v1/manage/{users,groups,api-keys,accounts}/{create,get,list,update,delete}`;
API keys also provide `revoke` and `rotate`, and administrator role changes use
`/v1/manage/users/role-change`. This slice accepts only `user` and `admin`
roles, `openai` groups with `standard` subscription type, and upstream
accounts whose type is `apikey` and platform is `openai`. Accounts remain bound to groups by
the existing `account_groups` table, and admission continues selecting from
the key's group-bound account candidates. There is no per-API-key account
association.

All IDs and `balance_microusd` values are canonical decimal strings. Mutation
requests require an `operation_id`, reject unknown fields, and are replay-safe.
User `password_hash`, API-key raw values, account credentials/envelopes, and
stored hashes are write-only: get/list responses never include them. A raw API
key is returned only by the first successful create or rotate response. Account
create/update accepts write-only `{ api_key, base_url }`; the Worker validates
the allowed host and encrypts it with `CREDENTIAL_ENCRYPTION_KEY` before D1 write.

HTTPS egress interception is enabled for the fixture host. At runtime the Container passes `SSL_CERT_FILE=/etc/cloudflare/certs/cloudflare-containers-ca.crt` so Go trusts Cloudflare's ephemeral interception CA; that file is not copied into the image.

Production account credentials require `aes-gcm:v1:<base64(iv)>:<base64(ciphertext)>` plus the `CREDENTIAL_ENCRYPTION_KEY` secret. TOTP secrets use the same 32-byte secret binding with a distinct `aes-gcm:v1:totp:` envelope and purpose-bound authenticated data. The deploy configuration is fixture-off and fail-closed. Local tests use `wrangler.test.jsonc`, which sets `ENVIRONMENT=local`, `ALLOW_TEST_FIXTURE=true`, `mock.upstream`, and a compatibility date constrained by the bundled workerd runtime.

`POST /api/v1/auth/login` is additionally admitted at the Worker edge by the
SQLite-backed `AUTH_LOGIN_ADMISSION` Durable Object: 20 requests per 60-second
fixed window for each privacy-derived Cloudflare client identity. Production
and local Worker runs require a dedicated base64-encoded 32-byte
`SUB2API_CF_LOGIN_ADMISSION_KEY` Worker secret. Keep it out of `vars`, source,
and logs; provision it through the normal secret mechanism before accepting
login traffic. The test pool supplies a fixed test-only key. A missing or
invalid edge identity, secret, binding, or DO call intentionally fails closed.
For `pnpm dev`, put a local-only value with that name in the ignored
`deploy/cloudflare/.dev.vars`; do not reuse a production value.

Cloudflare-mode TOTP is owned by the per-user SQLite-backed `TOTP_SECURITY`
Durable Object and D1 migration `0006_totp_security.sql`. The private
`/v1/private/totp/*` routes require the version header and Container identity.
D1 stores only the encrypted TOTP envelope, enabled timestamp, and monotonic
revision; the DO stores setup/login token hashes, session hashes, expiries, and
attempt counters. Plaintext secret material exists only in the one-time setup
response needed by the existing console and is not persisted or logged.

Setup and login challenges expire after five minutes. Five failed codes lock
verification for 15 minutes, and a successful step-up grant is bound to the
current JWT session for 15 minutes. Enabling or disabling TOTP in Cloudflare
mode requires the current password; the email-verification variant fails with
`EMAIL_VERIFY_NOT_ENABLED` until durable email delivery is migrated. A TOTP
revision change invalidates old login challenges and step-up grants. Production
and local runtime startup therefore also require a valid base64-encoded
32-byte `CREDENTIAL_ENCRYPTION_KEY`; keep it in Worker secrets or the ignored
local `.dev.vars`, never in Wrangler `vars`.

Administrator promotion/demotion remains on the existing public
`PUT /api/v1/admin/users/:id` route. A real administrator JWT, enabled TOTP,
and a current step-up grant for that JWT session are required; administrator
API keys are rejected. The frontend marks only actual role changes and keeps a
stable actor/target/payload-scoped idempotency key across step-up or ambiguous
retry failures. Password-bearing retries use an operation-salted semantic
digest so fresh bcrypt hashes do not break replay, while plaintext passwords,
JWTs, session IDs, bcrypt hashes, and semantic digests are excluded from audit
and operation responses.

D1 migration `0007_admin_role_management.sql` adds the append-only
`admin_role_change_audit` table. The private Worker rechecks the exact
user/session grant and atomically commits the user patch, operation response,
and minimal actor/target/old/new-role audit row. The guarded update refuses to
demote or disable the final live administrator. Direct admin creation and
deletion remain unavailable in Cloudflare mode.

Run source checks from this directory:

```sh
pnpm install --frozen-lockfile
pnpm exec wrangler types --check
pnpm run check
pnpm test
pnpm run dry-run
```

The local Vitest pool can validate Worker, D1, Queue, KV, and Durable Object behavior. It cannot prove Cloudflare Containers' real Docker build/lifecycle or outbound interception; that is deliberately documented as a platform acceptance gap rather than simulated as proof.

For the real local runtime, apply migrations and the fixture to an isolated
state directory, then start Wrangler with the same path:

```sh
pnpm exec wrangler d1 migrations apply sub2api-cloudflare-local --local \
  --config wrangler.local.jsonc --persist-to /tmp/sub2api-cf-state
pnpm exec wrangler d1 execute sub2api-cloudflare-local --local \
  --config wrangler.local.jsonc --persist-to /tmp/sub2api-cf-state \
  --file fixtures/local.sql
pnpm exec wrangler dev --config wrangler.local.jsonc \
  --persist-to /tmp/sub2api-cf-state
```

`fixture-test-key` and `fixture-model` are synthetic local values. The optional
`X-Sub2API-Fixture-Container: gateway-a|gateway-b` header and
`x_sub2api_fixture_delay_ms` request member exist only when both local fixture
gates are enabled; they are used for two-process and lease-renewal tests.

The SDK egress handlers are assigned after the class declaration on purpose.
Changing them to native static class fields bypasses the package's inherited
registration setters and makes local outbound requests fall through to a
`Network connection lost` error; `test/index.test.ts` guards this constraint.
