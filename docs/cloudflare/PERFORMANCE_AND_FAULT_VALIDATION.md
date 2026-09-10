# Cloudflare-native performance and fault validation

`cloudflare-loadcheck` is a dependency-free, bounded HTTP validator for the Cloudflare-native gateway. It is for local validation, or staging only when that target is explicitly authorized. It does not deploy, mutate Cloudflare resources, discover credentials, or use production credentials.

Run it from `backend`. Its safe default base URL is `http://127.0.0.1:8787`:

```sh
go run ./cmd/cloudflare-loadcheck --path /api/v1/status --requests 100 --concurrency 10 --timeout 2s
```

For explicitly authorized staging, use a non-sensitive fixture route and name the target directly:

```sh
go run ./cmd/cloudflare-loadcheck --base-url https://staging.example.invalid --path /health --requests 50 --concurrency 5 --timeout 3s --authorized-remote-target
```

The command accepts `--path`, `--requests`, `--concurrency`, `--method`, `--body`, repeatable `--header`, `--timeout`, `--max-response-bytes`, `--cancel-after`, and `--authorized-remote-target`. The default target must be localhost or another loopback address. Any non-loopback target is rejected before any request is created or sent unless `--authorized-remote-target` is present. That flag records only the operator's explicit authorization for the test target; it is not a substitute for the environment owner's permission.

It rejects URL user-info and credential-bearing headers: authorization, cookies, and header names containing `token`, `secret`, or `api-key`. It has no credential flags and does not print request bodies, response bodies, headers, URL queries, or credentials.

Every run has both per-request and aggregate bounds. Requests are limited to 10,000 and concurrency to 64. The per-request timeout is at most 2 minutes. The entire run always has a wall-clock deadline: omitting `--cancel-after` or setting it to zero uses the safe 2-minute default, while an explicit positive value is limited to 10 minutes. A parent context may end it sooner.

The request body is limited to 1 MiB per request and 64 MiB across the configured run. A response is limited to 64 MiB per request, with a 512 MiB aggregate response-read budget; that aggregate calculation includes the one extra detection byte needed to classify an over-limit body. Therefore high request counts must use a correspondingly smaller `--max-response-bytes`, even when the expected response is tiny. The base URL, path, query, and method are limited to 2,048, 2,048, 2,048, and 32 bytes respectively. At most 32 configured headers are accepted; each name is limited to 256 bytes, each value to 4,096 bytes, and their combined encoded allowance to 16 KiB. These configured worst-case limits keep network work and aggregation memory bounded independently of the target's behavior.

Use a small local baseline first, then compare repeated results as load is increased. Fault fixtures should return 4xx and 5xx responses, delay past `--timeout`, block until the run deadline fires, or flush an initial streaming event before delaying the rest of the body. The report always records time to first response headers, the first response-body byte when present (including SSE data), and the complete end-to-end duration after draining and closing the body. No streaming mode flag is needed; first-body-byte timing never weakens the full-body completion requirement.

Each run emits one JSON object with fixed struct field ordering. `attempted` is a request handed to the HTTP client. `completed` is counted only after the response body is fully read within `--max-response-bytes` and closed without error. Requests not started before cancellation, deadline, or normal completion equal `requested - attempted`; `cancelled` counts attempted requests that ended with context cancellation, while deadline expiry is classified as timeout. HTTP categories are `http_3xx`, `http_4xx`, `http_5xx`, and `http_unexpected`; redirects are never followed automatically, so 3xx responses stay on the original target and are classified in the report. Transport categories are timeout, cancellation, and other error. Body categories are timeout, cancellation, over-limit, truncated, and other read or close error.

Latency fields are deliberately named by what they measure:

- `response_header_latency_ms`: time until response headers are available. This is not called first byte.
- `first_body_byte_latency_ms`: time until the first response-body byte, including the first SSE data bytes when a streaming route flushes data.
- `first_body_byte_absent`: count of fully read responses with no response body.
- `end_to_end_latency_ms`: full request duration through response-body read and close, or through terminal transport/body failure.

Percentiles are deterministic: samples are copied, sorted ascending, and p50/p95/p99 use nearest rank `ceil(p*n)-1` with zero-based indexing. Empty sets encode count and percentile values as zero. Field layout and percentile selection are stable; measured duration and throughput vary with the target and host.

This is a local/staging verification aid. It does not establish production capacity, availability, Cloudflare edge behavior, security posture, or production acceptance.
