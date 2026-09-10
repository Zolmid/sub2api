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

## Cloudflare bridge Gemini scope

Cloudflare mode exposes only these exact native Gemini routes:

| Route | Query contract | Client response |
| --- | --- | --- |
| `POST /v1beta/models/{model}:generateContent` | no query parameters | buffered Gemini JSON |
| `POST /v1beta/models/{model}:streamGenerateContent` | exactly `alt=sse` | `text/event-stream` Gemini `data:` frames |

The route validates the safe model path segment and strict Gemini body through
the codec before Worker admission. It uses the existing API-key middleware,
Worker admission/start/renew/complete/release lifecycle, Worker-supplied model
mapping, cancellation propagation, upstream allowlist/redaction boundary, and
confirmed-usage settlement. It uses the admitted OpenAI API-key Responses
capability as the execution capability; because the Worker does not prefilter
that capability yet, a mismatch releases the exact lease before an upstream
attempt and never locally selects another account.

The bridge adapts only the codec's representable text/function-declaration
request subset to the existing OpenAI Responses vertical slice. It rejects
Gemini media references, model function-call parts, stop sequences, and
upstream function-call output rather than silently dropping unsupported
semantics. The Responses upstream is requested as SSE even for Gemini
`generateContent`, then buffered into one Gemini JSON response; missing usage
remains unknown and is omitted, never converted to zero.

Local unit/contract evidence covers route/query validation, API-key and
admission rejection, mapped model dispatch, capability lease release,
non-stream and SSE framing, unknown usage, cancellation, and redacted upstream
failures. This is not composed Container/Worker evidence, a real upstream
request, remote Cloudflare-resource verification, or production acceptance.

## Remaining integration matrix

| Work item | Status | Acceptance needed |
| --- | --- | --- |
| Gemini route selection, body limit middleware, and strict query/body validation | local unit coverage | composed Container routing acceptance |
| Gemini Responses dispatch and stream-to-Gemini framing | local unit coverage | real upstream cancellation/backpressure acceptance |
| Worker control-plane / usage ledger | bridge lifecycle unit coverage | composed Worker/Container confirmation and reconciliation evidence |
| Auth, rate limits, model routing, observability | bridge API-key/admission/redaction unit coverage | gateway policy and remote observability acceptance |
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
