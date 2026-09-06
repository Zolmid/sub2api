# Sub2API Cloudflare vertical slice

This directory is the Worker half of protocol `2026-09-06.v1`. It keeps persistent IDs and all microusd ledger values as decimal strings at the JavaScript/D1 boundary. D1 is authoritative; `CONFIG_CACHE` only caches non-sensitive model aliases.

`Sub2APIContainer` serves the existing Go Cloudflare-mode gateway on port 8080. Its only special outbound hosts are `sub2api.internal` (the versioned private control plane) and fixture-gated `mock.upstream`. All other outbound requests use the stream-preserving Container outbound path.

Production account credentials require `aes-gcm:v1:<base64(iv)>:<base64(ciphertext)>` plus the `CREDENTIAL_ENCRYPTION_KEY` secret. Local fixture use is limited to `ENVIRONMENT=local` and `ALLOW_TEST_FIXTURE=true`.

Run from this directory:

```sh
pnpm install --frozen-lockfile
pnpm exec wrangler types
pnpm exec tsc --noEmit
pnpm exec vitest run
pnpm exec wrangler deploy --dry-run
```

The local Vitest pool can validate Worker, D1, Queue, KV, and Durable Object behavior. It cannot prove Cloudflare Containers' real Docker build/lifecycle or outbound interception; that is deliberately documented as a platform acceptance gap rather than simulated as proof.
