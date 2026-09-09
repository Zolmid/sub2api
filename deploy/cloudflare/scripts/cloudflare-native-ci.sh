#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CF_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$CF_DIR/../.." && pwd)
BACKEND_DIR="$REPO_ROOT/backend"

cd "$REPO_ROOT"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage: bash deploy/cloudflare/scripts/cloudflare-native-ci.sh

Runs the credential-free Cloudflare-native local acceptance aggregate:
Worker type/check/Vitest, fresh and repeated local D1 migrations, focused
Cloudflare Go tests, and a minimal traditional-service regression.
EOF
  exit 0
fi

command -v pnpm >/dev/null 2>&1 || { echo "pnpm is required" >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo "node is required for the Worker gates" >&2; exit 1; }

cd "$CF_DIR"
pnpm exec wrangler types --check
pnpm run check
pnpm test

# Keep this state outside the checkout and remove only the directory created by
# this invocation. No repository or user data is touched by the trap.
STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sub2api-cf-ci.XXXXXX")
cleanup_state() {
  if [[ -n "${STATE_DIR:-}" && -d "$STATE_DIR" ]]; then
    rm -rf -- "$STATE_DIR"
  fi
}
trap cleanup_state EXIT
echo "D1 local state: $STATE_DIR"
[[ -f wrangler.local.jsonc ]] || {
  echo "missing canonical local Wrangler config: $CF_DIR/wrangler.local.jsonc" >&2
  exit 1
}
pnpm exec wrangler d1 migrations apply sub2api-cloudflare-local --local \
  --config wrangler.local.jsonc --persist-to "$STATE_DIR"
pnpm exec wrangler d1 migrations apply sub2api-cloudflare-local --local \
  --config wrangler.local.jsonc --persist-to "$STATE_DIR"

cd "$BACKEND_DIR"
command -v go >/dev/null 2>&1 || { echo "go is required for the Go gates" >&2; exit 1; }
go test -race -tags=unit ./internal/cloudflarebridge
go vet -tags=unit ./internal/cloudflarebridge
go test ./internal/service -run 'TestDetachUpstreamContextSemantics|TestDetachUpstreamContextIgnoresClientCancel|TestForwardAsChatCompletions_UpstreamRequestIgnoresClientCancel|TestForwardAsRawChatCompletions_UpstreamRequestIgnoresClientCancel' -count=1

echo "Cloudflare-native local CI aggregate passed (no deployment performed)."
