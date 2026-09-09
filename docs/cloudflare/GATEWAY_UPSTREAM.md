# Cloudflare gateway upstream boundary

The Cloudflare-native gateway marks each lease-backed upstream attempt with
`WithCloudflareUpstreamStartMarker`. The Go HTTP container recognizes that
marker at the final egress boundary. Traditional deployments do not carry the
marker and retain their existing configured upstream behavior.

For marked OpenAI gateway requests, the container requires an absolute HTTPS
URL with no userinfo, fragment, traversal segment, or Host override. The
destination (and every DNS answer) must be public, redirects are not followed,
and forwarding, hop-by-hop, proxy-authentication, Cookie, Cloudflare access or
metadata (`cf-access-client-id`, `cf-access-client-secret`,
`cf-connecting-ip`, `cf-ray`, `cf-worker`), and any
`x-sub2api-*` header are rejected before network dispatch. OpenAI
authentication must be exactly one non-empty `Bearer` or `AgentAssertion`
value. The boundary allows at most 64 outbound header values, 64 KiB in total,
and 16 KiB per value; control characters are always rejected.

Buffered responses use `gateway.upstream_response_read_max_bytes`. SSE now uses
the same total byte budget in addition to its existing per-line scanner limit,
bounded event channel, client-cancellation handling, and stream interval
timeout. Exceeding the budget produces the canonical upstream-too-large error;
it is not a reason to replay an execution whose outcome may be unknown.

This is a Go-container egress boundary only. It does not add, alter, or prove a
Cloudflare Worker route, Worker deployment, or Worker-to-container wiring; that
integration remains outside this lane.
