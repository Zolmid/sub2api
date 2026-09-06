# Cloudflare migration testing

This file separates source-level tests, local Cloudflare runtime evidence,
remote Cloudflare evidence, and real-upstream evidence. A passing lower layer
must not be reported as a passing higher layer.

Verified date: 2026-09-06. Commands below are run from the locked checkout.

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
| Bridge race detector | `cd backend && go test -race -tags=unit ./internal/cloudflarebridge -count=1` | Passed. |
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

Actual result: frozen install passed the lockfile supply-chain policy; generated
types were current; `tsc --noEmit` passed; Vitest passed 5 files / 27 tests; and
the production dry-run built a 101.17 KiB Worker bundle (23.87 KiB gzip) plus the
distroless Container image. The package's published sourcemaps reference missing
source files and produce warnings, but no test failure.

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

Pure Vitest/miniflare evidence and a real local `wrangler dev` process are
reported separately because mocked bindings cannot prove Container routing or
actual runtime behavior.

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
