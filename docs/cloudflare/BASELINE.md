# Cloudflare migration baseline

Verified on 2026-09-06 (Asia/Shanghai). This file records the immutable
comparison point for the Cloudflare-native migration. Later migration work must
not silently follow upstream `main`; upstream updates require a separate rebase
and a new baseline record.

## Locked source

- Upstream: `https://github.com/Wei-Shaw/sub2api.git`
- Branch at clone time: `main`
- Commit: `ab99d56e9626e6cd731592dae8553c9758a0efa2`
- Commit time: `2026-09-05T09:45:17Z`
- Commit subject: `chore: sync VERSION to 0.2.1 [skip ci]`
- Nearest release tag: `v0.2.1` (the locked commit is one commit after it)
- Embedded server version: `0.2.1`
- License: GNU Lesser General Public License v3.0 (`LICENSE`)

The clone was clean before the local branch `codex/cloudflare-native` was
created. No pre-existing checkout or user changes were present in the supplied
workspace.

## Locked tool and dependency inputs

- Backend module: `github.com/Wei-Shaw/sub2api` (`backend/go.mod`)
- Go directive and CI assertion: Go `1.27.0`
- Primary backend packages include Ent `0.14.5`, Gin `1.9.1`, go-redis
  `9.17.2`, lib/pq `1.10.9`, shopspring/decimal `1.4.0`, and modernc SQLite
  `1.44.3`. `backend/go.sum` is the complete dependency lock.
- Frontend package: `sub2api-frontend@1.0.0`
- Frontend CI runtime: Node `20`, pnpm `9`
- Container build inputs: Node `24-alpine`, Go `1.27.0-alpine`, Alpine
  `3.21`, and PostgreSQL `18-alpine` (`Dockerfile`)
- Frontend lock format: pnpm lockfile `9.0`; `frontend/pnpm-lock.yaml` is the
  complete dependency lock.

Local baseline execution used the official Go `1.27.0` darwin/arm64 archive
(SHA-256 `90493b3bbd5e10f91d12153198bf1994fd756399b4fec93b49b0c6e2acdeeb3e`),
the Codex-bundled Node `24.19.0`, and pnpm `9.15.9`. Node differs from CI, so
frontend results below are useful but do not replace the Node 20 CI gate.

## Initial verification

| Layer | Command | Result |
| --- | --- | --- |
| Backend unit suite | `go test -tags=unit ./...` from `backend/` with Go 1.27.0 | Passed; all reported packages passed, including `internal/service` (166.775s). |
| Frontend install | `pnpm@9 install --frozen-lockfile` from `frontend/` | Passed; 973 packages installed and the package/lock files remained unchanged. |
| Frontend lint | `pnpm@9 run lint:check` | Passed. |
| Frontend type check | `pnpm@9 run typecheck` | Passed. |
| Frontend critical tests | The 13-file `FRONTEND_CRITICAL_VITEST` set from the root `Makefile` | Passed: 13 files, 168 tests. Existing Vue `router-link` warnings, one jsdom `AggregateError` stderr message, and stale Browserslist data were non-failing. |
| Compose gateway env | `sh deploy/tests/docker-compose-gateway-env-test.sh` | Passed. |
| Compose security | `sh deploy/tests/docker-compose-security-test.sh` | Passed. |
| Runtime resources | `sh deploy/tests/docker-runtime-resources-test.sh` | Passed. |
| Installer token test | `bash deploy/tests/install-github-token-test.sh` | Baseline failure on macOS: BSD `head` rejects `head -n -1`, followed by `github_api_curl: command not found`. No migration code was involved. |

Docker CLI `29.4.0` and OrbStack `2.2.3` are installed, but the OrbStack Docker
daemon was not running during the first baseline pass. Integration/E2E tests,
the production image build, and any Container test therefore remain pending;
they must not be reported as passed.

No Cloudflare account, remote resource, paid Container instance, production
DNS, real upstream account, or real payment callback was touched during this
baseline.
