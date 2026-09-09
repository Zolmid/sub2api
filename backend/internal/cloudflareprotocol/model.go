// Package cloudflareprotocol is a pure protocol-codec foundation for the
// Cloudflare Container gateway. It deliberately has no transport, billing, or
// provider dependencies.
package cloudflareprotocol

import "encoding/json"

type Protocol string

const (
	OpenAIChat      Protocol = "openai.chat_completions"
	OpenAIResponses Protocol = "openai.responses"
	Anthropic       Protocol = "anthropic.messages"
	Gemini          Protocol = "gemini.generate_content"
)

type Role string

const (
	RoleSystem    Role = "system"
	RoleDeveloper Role = "developer"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

type PartKind string

const (
	PartText       PartKind = "text"
	PartMediaRef   PartKind = "media_ref"
	PartToolCall   PartKind = "tool_call"
	PartToolResult PartKind = "tool_result"
)

// Request is the loss-aware, transport-neutral request representation. Raw
// fields retain JSON schemas, arguments, and opaque media references exactly.
type Request struct {
	Protocol        Protocol
	Model           string
	RequestID       string
	ServiceTier     string
	Stream          bool
	MaxOutputTokens json.Number
	StopSequences   []string
	Messages        []Message
	Tools           []Tool
	ToolChoice      ToolChoice
}

type Message struct {
	// ID is a provider output-item ID. Request messages normally leave it empty.
	ID       string
	Role     Role
	Parts    []Part
	Metadata map[string]json.RawMessage
}

type Part struct {
	Kind   PartKind
	Text   string
	Media  *MediaReference
	Call   *ToolCall
	Result *ToolResult
}

// MediaReference never contains fetched object bytes. URL, MIME type and any
// provider-native descriptor are retained as supplied.
type MediaReference struct {
	URL    string
	FileID string
	MIME   string
	Raw    json.RawMessage
}

type Tool struct {
	Name        string
	Description string
	Schema      json.RawMessage
}

type ToolChoice struct {
	Mode string // auto, none, required, or named
	Name string
}

type ToolCall struct {
	// ItemID is the OpenAI Responses output item ID. ID is the protocol's
	// callable correlation ID (call_id / tool_use id / Chat tool-call id).
	ItemID    string
	ID        string
	Name      string
	Arguments json.RawMessage
}

type ToolResult struct {
	CallID  string
	Name    string
	Content []Part
	Raw     json.RawMessage
	IsError bool
}

type StopReason string

const (
	StopEndTurn       StopReason = "end_turn"
	StopMaxTokens     StopReason = "max_tokens"
	StopToolUse       StopReason = "tool_use"
	StopContentFilter StopReason = "content_filter"
	StopCancelled     StopReason = "cancelled"
)

// Usage is present only when the upstream confirms it. Nil means unknown;
// zero is a confirmed zero and is never fabricated by this package.
type Usage struct {
	InputTokens  json.Number
	OutputTokens json.Number
	TotalTokens  json.Number
}

type Response struct {
	ID          string
	CreatedAt   json.Number
	RequestID   string
	Model       string
	ServiceTier string
	Message     Message
	StopReason  StopReason
	Usage       *Usage
}

type EventKind string

const (
	EventStarted         EventKind = "started"
	EventOutputItemStart EventKind = "output_item_start"
	EventOutputItemDone  EventKind = "output_item_done"
	EventTextStart       EventKind = "text_start"
	EventTextDelta       EventKind = "text_delta"
	EventTextDone        EventKind = "text_done"
	EventToolCallStart   EventKind = "tool_call_start"
	EventToolCallDelta   EventKind = "tool_call_delta"
	EventToolCallDone    EventKind = "tool_call_done"
	EventContentPartDone EventKind = "content_part_done"
	EventCompleted       EventKind = "completed"
	EventDone            EventKind = "done"
	EventError           EventKind = "error"
)

// Event ordering is the caller's responsibility; EncodeSSE maps each event
// deterministically without clocks, random IDs, or synthetic usage.
type Event struct {
	Kind           EventKind
	ResponseID     string
	CreatedAt      json.Number
	Model          string
	ChoiceIndex    int
	Index          int
	ContentIndex   int
	ItemID         string
	SequenceNumber *int64
	Text           string
	Delta          string
	ToolCall       *ToolCall
	Response       *Response
	StopReason     StopReason
	Usage          *Usage
	Error          *Error
}
