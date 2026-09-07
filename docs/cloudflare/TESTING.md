# Cloudflare migration testing

This file separates source-level tests, local Cloudflare runtime evidence,
remote Cloudflare evidence, and real-upstream evidence. A passing lower layer
must not be reported as a passing higher layer.

Verified date: 2026-09-07. Commands below are run from the locked checkout.

## Current stage C admin-user increment

| Scope | Command | Result |
| --- | --- | --- |
| Go user-management bridge | `cd backend && go test ./internal/cloudflarebridge` and `go vet ./internal/cloudflarebridge` under `golang:1.27.0-alpine` | Passed. Tests include HTTP contract validation, create replay across fresh IDs and bcrypt hashes, credential non-disclosure/readback, exact balance conversion, Unicode password limits, admin protection, field-level updates, and unrelated concurrent balance preservation. |
| Frontend API helper | `cd frontend && pnpm run test:run`, `pnpm run typecheck`, `pnpm run lint:check`, and `pnpm run build` | Passed: 254 test files / 1865 tests, typecheck, read-only lint, and production build. After the explicit null-narrowing cleanup, the 7 user API tests, typecheck, and lint were rerun and passed. The Cloudflare Docker build independently rebuilt the frontend with its pinned pnpm 9 toolchain. |
| Worker control plane | `cd deploy/cloudflare && pnpm exec wrangler types --check`, `pnpm run check`, and `pnpm test` with Wrangler 4.129.0 | Passed: generated types current, `tsc --noEmit`, and 8 test files / 51 tests. Missing source files referenced by published Container package sourcemaps remain warning-only. |
| D1 migration | Apply all migrations to a new local persistence directory, apply again, then import `fixtures/local.sql` | Passed: migrations `0001` through `0004` applied, the second run reported no pending migrations, and all 8 corrected fixture statements succeeded with non-empty management timestamps. Worker test setup no longer repairs empty fixture timestamps after import, so the 51-test suite enforces this invariant. Existing databases still require the duplicate normalized-live-email preflight documented in `STATUS.md`. |
| Offline first admin | Run `cloudflare-first-admin -inspect-local`, then the TTY-only guarded local apply against the fresh migration state | Passed: the normalized live-email index was accepted, exactly one admin was inserted, and credential-aware readback matched. The local test state used synthetic credentials only. |
| Local composed API runtime | Start Wrangler 4.129.0 with the fresh D1 state and local-only secrets, then drive the embedded console and admin/user/key HTTP lifecycle | Passed: console/CSP nonce 200, admin login 200, create/replay 200 with one ID, semantic conflict 409, update and updated-password login 200, normalized-email conflict 409, API-key create and fixture gateway request 200, delete 200, then deleted-user login/key 401 and admin read 404. D1 readback confirmed both tombstones and no foreign-key violations. |
| Embedded service | Frontend production build followed by `go build -tags embed -trimpath -o /tmp/sub2api-server ./cmd/server` under Go 1.27 | Passed; the actual generated console was embedded into the complete server binary. |
| Production-config build | `cd deploy/cloudflare && pnpm run dry-run` | Passed with Wrangler 4.129.0: 157.50 KiB Worker upload / 34.70 KiB gzip, frontend rebuild, Go build, and distroless Container image export. Wrangler exited at `--dry-run`; no Cloudflare resource was mutated. |

The last row before the build checks is a real local HTTP composition, but it
does not claim browser visual/JavaScript interaction or production acceptance.
Remote Cloudflare and real-upstream gates remain unrun.

## Baseline regression

| Scope | Command | Result |
| --- | --- | --- |
| Go unit suite | `cd backend && go test -tags=unit ./...` | Passed on the locked baseline and migration branch. The final branch run used `golang:1.27.0-alpine`; an initial read-only source mount failed only because an existing Ent schema test creates `.entc`, and the corrected writable-mount run passed every package. |
| Frontend install | `cd frontend && pnpm@9 install --frozen-lockfile` | Passed; lockfile unchanged. |
| Frontend lint | `cd frontend && pnpm@9 run lint:check` | Passed. |
| Frontend types | `cd frontend && pnpm@9 run typecheck` | Passed. |
| Frontend critical suite | Root `Makefile` 13-file `FRONTEND_CRITICAL_VITEST` selection | Passed: 13 files, 168 tests. |
| Compose static checks | `sh deploy/tests/docker-compose-gateway-env-test.sh`, `sh deploy/tests/docker-compose-security-test.sh`, `sh deploy/tests/docker-runtime-resources-test.sh` | Passed. |
| Existing installer test | `bash deploy/tests/install-github-token-test.sh` | Baseline failure on macOS: GNU-only `head -n -1`, then missing `github_api_curl`. |

The baseline environment is recorded in `BASELINE.md`; ordinary CI should use
the repository's standard Go 1.27 and Node 20/pnpm 9 setup.

## Go Cloudflare seam

| Scope | Command | Result |
| --- | --- | --- |
| Bridge unit tests | `cd backend && go test -tags=unit ./internal/cloudflarebridge` | Passed. |
| Traditional and lease-bound cancellation regression | `cd backend && go test ./internal/service -run 'TestDetachUpstreamContextSemantics\|TestDetachUpstreamContextIgnoresClientCancel\|TestForwardAsChatCompletions_UpstreamRequestIgnoresClientCancel\|TestForwardAsRawChatCompletions_UpstreamRequestIgnoresClientCancel' -count=1` | Passed. |
| Server composition | `cd backend && go test -tags=unit ./cmd/server` | Passed. |
| Bridge race detector | `cd backend && go test -race -tags=unit ./internal/cloudflarebridge -count=1` | Not counted in the current Alpine gate: its CGO-disabled toolchain rejected the command with `-race requires cgo`. Focused bridge tests and vet passed separately. |
| Linux Container binary | `cd backend && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/sub2api-cloudflare-server ./cmd/server` | Passed; produced a statically linked x86-64 ELF. |
| Cloudflare-mode startup | Start a Darwin build with Cloudflare mode, no PostgreSQL/Redis services, then `curl http://127.0.0.1:18765/health` | Passed; returned `{"deployment_mode":"cloudflare","status":"ok"}` and shut down cleanly on SIGINT. |

Bridge tests use only synthetic keys and credentials. They verify that the raw
key is sent in the private request body rather than a URL, upstream credentials
do not reach completion events, errors do not reflect Worker response details,
oversized responses are rejected, IDs/leases are validated, and the original Go
gateway path produces the persisted usage event and release.

One controlled SSE test stays silent longer than the initial three-second lease,
observes at least three successful renewals, then verifies the original raw SSE
path, confirmed `11/4` token usage, completion input, and release. A separate
injected-renewal-failure test proves lease expiry cancels the active upstream
context and records unknown usage rather than inventing token counts.

## Worker and platform adapter

Run from `deploy/cloudflare/` after the implementation and lockfile are present:

```sh
pnpm install --frozen-lockfile
pnpm exec wrangler types --check
pnpm run check
pnpm test
pnpm run dry-run
```

Fresh/repeated local schema and fixture checks used an isolated persistence
directory:

```sh
pnpm exec wrangler d1 migrations apply sub2api-cloudflare-local --local \
  --config wrangler.local.jsonc --persist-to /private/tmp/sub2api-cf-state
pnpm exec wrangler d1 execute sub2api-cloudflare-local --local \
  --config wrangler.local.jsonc --persist-to /private/tmp/sub2api-cf-state \
  --file fixtures/local.sql
```

Current result: frozen install passed the lockfile supply-chain policy;
generated types were current; `tsc --noEmit` passed; Vitest passed 8 files / 51
tests; and the production dry-run built a 157.50 KiB Worker bundle (34.70 KiB
gzip) plus the distroless Container image. The package's published sourcemaps
reference missing source files and produce warnings, but no test failure.

Required unit/integration assertions include:

- fresh and repeated D1 migration; fixture initialization is explicit and
  refuses production use;
- API-key hash lookup, revoked/disabled user/key/account, stale/missing KV, and
  public attempts to reach the internal bridge;
- exact decimal-string IDs and fixed-point values outside JavaScript's safe
  integer range;
- simultaneous acquire, cross-group account authority, repeated release, late
  renew, expiry/renew race, alarm rebuild, and lease-bound cancellation;
- completion/outbox crash windows; ten identical deliveries; one conflicting
  payload; partial batch retry; finalized state cannot regress;
- AES-GCM envelope authentication failure and wrong/missing key version;
- external Worker-to-Container streaming without response buffering, plus
  controlled mock SSE with a pause longer than the initial lease period.
- user-create semantic replay across regenerated IDs and bcrypt hashes without
  persisting credential material in management operations;
- normalized live-email uniqueness, post-delete email reuse, field-level user
  patches, conditional group validation, admin role guards, and atomic owned-key
  tombstoning on user deletion.

Pure Vitest/miniflare evidence and a real local `wrangler dev` process are
reported separately because mocked bindings cannot prove Container routing or
actual runtime behavior.

## Stage C local composed API gate

The admin-user increment was exercised against a second, fresh persistence
directory rather than reusing unit-test state. The sequence was migrations
`0001` through `0004`, offline first-admin guarded creation, corrected explicit
fixture import, then `wrangler dev` with ignored local `.dev.vars` values.

One in-memory HTTP harness retained JWTs and the newly issued API-key secret
without printing them. It verified the following observable sequence:

- embedded console HTML returned 200 and rendered the same nonce advertised in
  its `script-src` CSP;
- admin login, user creation, same-key replay, field/password update, updated
  user login, user API-key creation, and fixture gateway request returned 200;
- changed data under the create operation and a case-variant duplicate email
  returned 409;
- deleting the user returned 200, after which password login and gateway use of
  the owned key returned 401 and an ordinary admin read returned 404;
- direct D1 readback showed the user and owned key disabled with non-null
  tombstones, all fixture management timestamps non-empty, and an empty
  `PRAGMA foreign_key_check` result.

This proves the HTTP/Container/private-control-plane/D1 composition for the
bounded flow. It does not prove real browser rendering/interaction, a remote
Cloudflare deployment, production traffic, or a real upstream account.

## Local vertical-slice gate

The stage B local gate passed with a compiled Go image and no PostgreSQL, Redis,
or durable Container-local files:

```text
client -> Worker -> Go Container -> private Worker binding
       -> D1 fixture auth/account -> AccountLeaseDO
       -> mock upstream SSE -> D1 completion/outbox
       -> Queue consumer -> D1 usage record -> lease release
```

Evidence from the persisted local runtime state:

- Non-streaming and SSE requests returned the exact fixture response through an
  HTTPS outbound interception; Wrangler logged the matching Queue consumption.
- Completed requests were `succeeded`; outbox rows were `published`; usage rows
  were `confirmed` with exact text counters; no payload conflict was recorded;
  and active account leases returned to zero.
- Two separately named Go Containers made overlapping requests against an
  account with concurrency 1. Exactly one returned 200 and one returned 429;
  the rejected instance returned 200 after the first lease released.
- Successful 10-second and 15-second silent waits exceeded the five-second
  initial lease, exercising renewal in the real local runtime.
- A SIGKILL during a 60-second wait returned `Container suddenly disconnected`
  with HTTP 500. D1 retained the request as `admitted`, the DO expired its lease
  back to zero, and the removed Container restarted and completed a new request
  without re-importing fixture state.
- An idle Container expired and a later `/health` request recreated it
  successfully. Container removal did not remove D1, DO, KV, outbox, or usage
  state.

The forced-kill request deliberately remains pending/unknown for a future
reconciler. It is evidence of the documented uncertainty window, not a complete
stage D reconciliation implementation. Slow-client, rolling-update, load, and
resource-accounting tests remain stage E work.

## Remote and real-upstream gates

Remote Cloudflare verification requires explicit authorization, an account with
Workers Paid/Containers access, scoped deployment credentials, and a disposable
test resource namespace. Real-upstream verification additionally requires an
authorized synthetic-budget account and redacted logging. Neither gate has been
run. No local or dry-run result may be relabeled as remote Cloudflare or
real-upstream acceptance.
