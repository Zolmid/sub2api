# Cloudflare protocol codec compatibility

`backend/internal/cloudflareprotocol` is a pure Go foundation. It has no HTTP
routes, Container handler wiring, Worker bindings, account selection, billing,
object fetching, persistence, or deployment behavior. Passing its tests is not
gateway-route integration or production acceptance.

## Implemented codec support

| Protocol | Request decode | Non-stream response | SSE event encoding |
| --- | --- | --- | --- |
| OpenAI Chat Completions | system/developer/user/assistant/tool roles; text; absolute external image URIs; functions; tool choice; service tier | text, function calls, stop and confirmed usage | role, text/tool deltas, terminal usage and `[DONE]` |
| OpenAI Responses | string input or item-array; instructions; system/developer/user/assistant items; text/image URLs; function calls/results; functions; tool choice; service tier | text, function calls, stop, content-filter/max-token incomplete details, and confirmed usage | created, ordered output/content/text/function events, completed, and normalized errors |
| Anthropic Messages | string or text-block system prompt; user/assistant text, tool-use, and tool-result blocks; tools; tool choice | text/tool-use, stop and confirmed usage | message start, text/input-json deltas, terminal stop |
| Gemini generateContent and streamGenerateContent request bodies | model supplied from URL/options; system instruction; user/model text; external `fileData` URI; function declarations; function-calling config | text/function calls, finish and confirmed usage | JSON chunks suitable for streamGenerateContent |

All number-bearing usage fields decode/encode as `json.Number`; raw JSON tool
schemas and arguments are preserved without a float conversion. A missing
`Usage` is explicitly unknown and is omitted from output rather than emitted
as zero. The package contains no money or billing representation.

## Fail-closed cases

The codec returns typed `malformed_request`, `validation_error`,
`unsupported_field`, `lossy_conversion`, `limit_exceeded`, `cancelled`, or redacted `upstream_error`
errors. It rejects unknown top-level fields, unsupported content blocks,
unrepresentable role/choice combinations, empty content that would otherwise
be invented, raw object bytes, files, WebSockets, batch semantics, and Gemini
function responses whose call identity cannot be represented losslessly.
Inline base64/data URLs, file bytes, upload/object tasks, and Gemini inlineData
are rejected before they can enter the canonical model. It does not claim lossless conversion for provider-specific
reasoning, citations, cache controls, structured-output schemas, audio/video,
multi-candidate Gemini output, or non-text tool-result media.

## Remaining integration matrix

| Work item | Status | Acceptance needed |
| --- | --- | --- |
| Container HTTP route selection and request limits | not integrated | route tests for all four paths |
| Upstream dispatch and streaming reader wiring | not integrated | real container integration tests with cancellation/backpressure |
| Worker control-plane / usage ledger | not integrated | confirmed usage propagation and failure-state tests |
| Auth, rate limits, model routing, observability | not integrated | gateway policy and redaction tests |
| Production deployment | not attempted | explicit deployment approval and live protocol acceptance |

## Cloudflare bridge embeddings scope

Cloudflare mode exposes the baseline non-streaming OpenAI embeddings contract
at both `POST /v1/embeddings` and `POST /embeddings`. Both aliases use the
same API-key middleware, Worker admission, lease, upstream start marker, and
completion/release lifecycle as the existing bridge gateway routes.

The Worker scheduler does not yet prefilter accounts by endpoint capability.
The bridge therefore rechecks an admitted account for the active OpenAI API-key
embeddings capability before any upstream request; a mismatch releases the
exact reservation and does not issue completion or upstream traffic. It does
not select or retry a later capable account. Adding that behavior requires a
Worker scheduler/admission-contract change and is outside this bounded route
slice.

The bounded SSE parser accepts fragmented readers, CRLF, comments, persistent
IDs, valid numeric retry directives, multiple data lines, and a final line
without a newline. It enforces physical-line, event-body, and event-count
limits and checks context cancellation before reads and callbacks. Callers
select limits appropriate to their route and must close a blocked transport
reader when its context is cancelled.
