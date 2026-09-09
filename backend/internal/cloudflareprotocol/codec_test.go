package cloudflareprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func assertBytes(t *testing.T, got []byte, want string) {
	t.Helper()
	if string(got) != want {
		t.Fatalf("wire bytes differ\n got: %q\nwant: %q", got, want)
	}
}

func assertCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var protocolErr *Error
	if !errors.As(err, &protocolErr) || protocolErr.Code != want {
		t.Fatalf("error = %#v, want code %s", err, want)
	}
}

func seq(value int64) *int64 { return &value }

func TestDecodeRepresentativeRequests(t *testing.T) {
	chat, err := DecodeRequest(OpenAIChat, []byte(`{"model":"gpt-x","messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"image_url","image_url":{"url":"https://cdn.example/a.png"}}]}],"tools":[{"type":"function","function":{"name":"weather","description":"lookup","parameters":{"type":"object"}}}],"tool_choice":{"type":"function","function":{"name":"weather"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if chat.ToolChoice != (ToolChoice{Mode: "named", Name: "weather"}) || chat.Messages[0].Parts[1].Media.URL != "https://cdn.example/a.png" {
		t.Fatalf("chat = %#v", chat)
	}

	responses, err := DecodeRequest(OpenAIResponses, []byte(`{"model":"gpt-x","instructions":"be brief","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]},{"type":"function_call","id":"fc_1","call_id":"call_1","name":"weather","arguments":"{\"city\":\"Paris\"}"},{"type":"function_call_output","call_id":"call_1","output":"sunny"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(responses.Messages) != 4 || responses.Messages[2].Parts[0].Call.ItemID != "fc_1" {
		t.Fatalf("responses = %#v", responses)
	}
	stringInput, err := DecodeRequest(OpenAIResponses, []byte(`{"model":"gpt-x","input":"hello"}`))
	if err != nil || stringInput.Messages[0].Parts[0].Text != "hello" {
		t.Fatalf("string input = %#v, %v", stringInput, err)
	}

	anthropic, err := DecodeRequest(Anthropic, []byte(`{"model":"claude-x","max_tokens":32,"system":[{"type":"text","text":"rule one"},{"type":"text","text":"rule two"}],"messages":[{"role":"user","content":"hello"},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"weather","input":{"city":"Paris"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"sunny"},{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"dry"}]}]}],"tools":[{"name":"weather","input_schema":{"type":"object"}}],"tool_choice":{"type":"tool","name":"weather"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(anthropic.Messages) != 4 || len(anthropic.Messages[0].Parts) != 2 || anthropic.Messages[3].Parts[1].Result.Content[0].Text != "dry" {
		t.Fatalf("anthropic = %#v", anthropic)
	}

	gemini, err := DecodeRequestWithOptions(Gemini, []byte(`{"contents":[{"role":"user","parts":[{"text":"hello"},{"fileData":{"mimeType":"image/png","fileUri":"https://files.example/a.png"}}]}],"tools":[{"functionDeclarations":[{"name":"weather","parameters":{"type":"object"}}]}],"toolConfig":{"functionCallingConfig":{"mode":"ANY","allowedFunctionNames":["weather"]}}}`), DecodeOptions{Model: "models/gemini-x"})
	if err != nil {
		t.Fatal(err)
	}
	if gemini.Model != "models/gemini-x" || gemini.ToolChoice.Name != "weather" || len(gemini.Tools) != 1 {
		t.Fatalf("gemini = %#v", gemini)
	}
}

func TestDecodeRejectsMalformedUnknownDuplicateAndUnsafeMedia(t *testing.T) {
	cases := []struct {
		name     string
		protocol Protocol
		body     string
		options  DecodeOptions
		code     ErrorCode
	}{
		{"malformed", OpenAIChat, `{"model":`, DecodeOptions{}, ErrMalformed},
		{"unknown", OpenAIChat, `{"model":"m","messages":[{"role":"user","content":"x"}],"mystery":1}`, DecodeOptions{}, ErrMalformed},
		{"duplicate top", OpenAIChat, `{"model":"a","model":"b","messages":[{"role":"user","content":"x"}]}`, DecodeOptions{}, ErrMalformed},
		{"duplicate nested schema", OpenAIChat, `{"model":"m","messages":[{"role":"user","content":"x"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","type":"array"}}}]}`, DecodeOptions{}, ErrMalformed},
		{"duplicate arguments", OpenAIResponses, `{"model":"m","input":[{"type":"function_call","call_id":"c","name":"f","arguments":"{\"x\":1,\"x\":2}"}]}`, DecodeOptions{}, ErrMalformed},
		{"missing gemini model", Gemini, `{"contents":[{"parts":[{"text":"x"}]}]}`, DecodeOptions{}, ErrValidation},
		{"data URI", OpenAIChat, `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AA"}}]}]}`, DecodeOptions{}, ErrUnsupported},
		{"javascript URI", OpenAIChat, `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"javascript:alert(1)"}}]}]}`, DecodeOptions{}, ErrUnsupported},
		{"credentials URI", OpenAIChat, `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://u:p@example.com/a"}}]}]}`, DecodeOptions{}, ErrValidation},
		{"fragment URI", OpenAIChat, `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a#frag"}}]}]}`, DecodeOptions{}, ErrValidation},
		{"inline bytes", Gemini, `{"contents":[{"parts":[{"inlineData":{"mimeType":"image/png","data":"AA"}}]}]}`, DecodeOptions{Model: "models/g"}, ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRequestWithOptions(tc.protocol, []byte(tc.body), tc.options)
			if err == nil {
				t.Fatal("request accepted")
			}
			assertCode(t, err, tc.code)
		})
	}
}

func TestCompleteResponseWireGoldens(t *testing.T) {
	chat := Response{ID: "chatcmpl_1", CreatedAt: "7", Model: "gpt-x", Message: Message{Role: RoleAssistant, Parts: []Part{{Kind: PartText, Text: "ok"}}}, StopReason: StopEndTurn}
	got, err := EncodeResponse(OpenAIChat, chat)
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, got, `{"choices":[{"finish_reason":"stop","index":0,"message":{"content":"ok","role":"assistant"}}],"created":7,"id":"chatcmpl_1","model":"gpt-x","object":"chat.completion"}`)
	if strings.Contains(string(got), `"usage"`) {
		t.Fatal("unknown usage was serialized")
	}
	chat.Usage = &Usage{InputTokens: "0", OutputTokens: "0", TotalTokens: "0"}
	got, err = EncodeResponse(OpenAIChat, chat)
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, got, `{"choices":[{"finish_reason":"stop","index":0,"message":{"content":"ok","role":"assistant"}}],"created":7,"id":"chatcmpl_1","model":"gpt-x","object":"chat.completion","usage":{"completion_tokens":0,"prompt_tokens":0,"total_tokens":0}}`)

	responses := Response{ID: "resp_1", CreatedAt: "8", Model: "gpt-x", Message: Message{ID: "msg_1", Role: RoleAssistant, Parts: []Part{{Kind: PartText, Text: "a"}, {Kind: PartText, Text: "b"}, {Kind: PartToolCall, Call: &ToolCall{ItemID: "fc_1", ID: "call_1", Name: "weather", Arguments: json.RawMessage(`{"city":"Paris"}`)}}}}, StopReason: StopToolUse}
	got, err = EncodeResponse(OpenAIResponses, responses)
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, got, `{"created_at":8,"id":"resp_1","model":"gpt-x","object":"response","output":[{"content":[{"annotations":[],"text":"a","type":"output_text"},{"annotations":[],"text":"b","type":"output_text"}],"id":"msg_1","role":"assistant","status":"completed","type":"message"},{"arguments":"{\"city\":\"Paris\"}","call_id":"call_1","id":"fc_1","name":"weather","status":"completed","type":"function_call"}],"status":"completed"}`)

	anthropic := Response{ID: "msg_1", Model: "claude-x", Message: Message{Role: RoleAssistant, Parts: []Part{{Kind: PartText, Text: "a"}, {Kind: PartText, Text: "b"}, {Kind: PartToolCall, Call: &ToolCall{ID: "toolu_1", Name: "weather", Arguments: json.RawMessage(`{"city":"Paris"}`)}}}}, StopReason: StopToolUse, Usage: &Usage{InputTokens: "2", OutputTokens: "3", TotalTokens: "5"}}
	got, err = EncodeResponse(Anthropic, anthropic)
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, got, `{"content":[{"text":"a","type":"text"},{"text":"b","type":"text"},{"id":"toolu_1","input":{"city":"Paris"},"name":"weather","type":"tool_use"}],"id":"msg_1","model":"claude-x","role":"assistant","stop_reason":"tool_use","stop_sequence":null,"type":"message","usage":{"input_tokens":2,"output_tokens":3}}`)

	gemini := Response{ID: "resp-g", Model: "gemini-x", Message: Message{Role: RoleAssistant, Parts: []Part{{Kind: PartText, Text: "a"}, {Kind: PartText, Text: "b"}, {Kind: PartToolCall, Call: &ToolCall{Name: "weather", Arguments: json.RawMessage(`{"city":"Paris"}`)}}}}, StopReason: StopToolUse}
	got, err = EncodeResponse(Gemini, gemini)
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, got, `{"candidates":[{"content":{"parts":[{"text":"a"},{"text":"b"},{"functionCall":{"args":{"city":"Paris"},"name":"weather"}}],"role":"model"},"finishReason":"STOP","index":0}],"modelVersion":"gemini-x","responseId":"resp-g"}`)
}

func TestResponseValidationAndLossBoundaries(t *testing.T) {
	base := Response{ID: "r", CreatedAt: "1", Model: "m", Message: Message{Role: RoleAssistant, Parts: []Part{{Kind: PartText, Text: "x"}}}, StopReason: StopEndTurn}
	cases := []struct {
		name     string
		protocol Protocol
		mutate   func(*Response)
		code     ErrorCode
	}{
		{"role", OpenAIChat, func(r *Response) { r.Message.Role = RoleUser }, ErrValidation},
		{"created", OpenAIChat, func(r *Response) { r.CreatedAt = "" }, ErrValidation},
		{"multiple chat text", OpenAIChat, func(r *Response) { r.Message.Parts = append(r.Message.Parts, Part{Kind: PartText, Text: "y"}) }, ErrLossy},
		{"nil tool", OpenAIChat, func(r *Response) { r.Message.Parts = []Part{{Kind: PartToolCall}} }, ErrValidation},
		{"empty tool id", OpenAIChat, func(r *Response) {
			r.Message.Parts = []Part{{Kind: PartToolCall, Call: &ToolCall{Name: "f", Arguments: json.RawMessage(`{}`)}}}
			r.StopReason = StopToolUse
		}, ErrValidation},
		{"bad usage", OpenAIChat, func(r *Response) { r.Usage = &Usage{InputTokens: "1", OutputTokens: "2", TotalTokens: "4"} }, ErrValidation},
		{"responses item id", OpenAIResponses, func(r *Response) { r.Message.ID = "" }, ErrValidation},
		{"gemini call id", Gemini, func(r *Response) {
			r.CreatedAt = ""
			r.Message.Parts = []Part{{Kind: PartToolCall, Call: &ToolCall{ID: "lost", Name: "f", Arguments: json.RawMessage(`{}`)}}}
			r.StopReason = StopToolUse
		}, ErrLossy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.mutate(&r)
			_, err := EncodeResponse(tc.protocol, r)
			if err == nil {
				t.Fatal("response accepted")
			}
			assertCode(t, err, tc.code)
		})
	}
	oversize := base
	_, err := EncodeResponseWithOptions(OpenAIChat, oversize, EncodeOptions{Limits: EncodeLimits{MaxOutputBytes: 8}})
	assertCode(t, err, ErrLimit)
}

type fragmentReader struct {
	data []byte
	step int
}

func (r *fragmentReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := r.step
	if n > len(r.data) {
		n = len(r.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func TestParseSSEWireRules(t *testing.T) {
	input := []byte(": comment\r\nevent: ignored\r\nid: first\r\n\r\nid: second\r\ndata: a\r\ndata:b")
	var frames []SSEFrame
	err := ParseSSE(context.Background(), &fragmentReader{data: input, step: 1}, SSELimits{}, func(frame SSEFrame) error { frames = append(frames, frame); return nil })
	if err != nil {
		t.Fatal(err)
	}
	want := []SSEFrame{{ID: "second", Data: []byte("a\nb")}}
	if !reflect.DeepEqual(frames, want) {
		t.Fatalf("frames = %#v, want %#v", frames, want)
	}

	callbackErr := errors.New("callback stopped")
	err = ParseSSE(context.Background(), strings.NewReader("data: x\n\n"), SSELimits{}, func(SSEFrame) error { return callbackErr })
	if !errors.Is(err, callbackErr) {
		t.Fatalf("callback error = %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	err = ParseSSE(cancelled, strings.NewReader("data: x\n\n"), SSELimits{}, func(SSEFrame) error { return nil })
	assertCode(t, err, ErrCancelled)
}

func TestParseSSELimits(t *testing.T) {
	cases := []struct {
		name, input string
		limits      SSELimits
	}{
		{"line", "data: 12345\n\n", SSELimits{MaxLineBytes: 8}},
		{"joined body", "data: aa\ndata: bb\n\n", SSELimits{MaxEventBytes: 4}},
		{"event count", "data: a\n\ndata: b\n\n", SSELimits{MaxEvents: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ParseSSE(context.Background(), strings.NewReader(tc.input), tc.limits, func(SSEFrame) error { return nil })
			if err == nil {
				t.Fatal("limit was not enforced")
			}
			assertCode(t, err, ErrLimit)
		})
	}
}

func TestOpenAIChatStreamWireGolden(t *testing.T) {
	events := []Event{
		{Kind: EventStarted, ResponseID: "chatcmpl_1", CreatedAt: "7", Model: "gpt-x"},
		{Kind: EventTextDelta, ResponseID: "chatcmpl_1", CreatedAt: "7", Model: "gpt-x", Text: "Hi"},
		{Kind: EventToolCallStart, ResponseID: "chatcmpl_1", CreatedAt: "7", Model: "gpt-x", Index: 0, ToolCall: &ToolCall{ID: "call_1", Name: "weather"}},
		{Kind: EventToolCallDelta, ResponseID: "chatcmpl_1", CreatedAt: "7", Model: "gpt-x", Index: 0, Delta: `{"city":`},
		{Kind: EventCompleted, ResponseID: "chatcmpl_1", CreatedAt: "7", Model: "gpt-x", StopReason: StopToolUse},
		{Kind: EventDone},
	}
	var got []byte
	for _, event := range events {
		wire, err := EncodeSSEEvent(OpenAIChat, event)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, wire...)
	}
	want := "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null,\"index\":0}],\"created\":7,\"id\":\"chatcmpl_1\",\"model\":\"gpt-x\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null,\"index\":0}],\"created\":7,\"id\":\"chatcmpl_1\",\"model\":\"gpt-x\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"\",\"name\":\"weather\"},\"id\":\"call_1\",\"index\":0,\"type\":\"function\"}]},\"finish_reason\":null,\"index\":0}],\"created\":7,\"id\":\"chatcmpl_1\",\"model\":\"gpt-x\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"{\\\"city\\\":\"},\"index\":0}]},\"finish_reason\":null,\"index\":0}],\"created\":7,\"id\":\"chatcmpl_1\",\"model\":\"gpt-x\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\",\"index\":0}],\"created\":7,\"id\":\"chatcmpl_1\",\"model\":\"gpt-x\",\"object\":\"chat.completion.chunk\"}\n\n" +
		"data: [DONE]\n\n"
	assertBytes(t, got, want)
	first, err := EncodeSSEEvent(OpenAIChat, events[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first, []byte{'\\', 'n'}) {
		t.Fatalf("literal backslash-n framing: %q", first)
	}
	if bytes.Contains(first, []byte("event:")) {
		t.Fatalf("invented Chat event name: %q", first)
	}
}

func TestAnthropicStreamWireGolden(t *testing.T) {
	events := []Event{
		{Kind: EventStarted, ResponseID: "msg_1", Model: "claude-x", Usage: &Usage{InputTokens: "2", OutputTokens: "0", TotalTokens: "2"}},
		{Kind: EventTextStart, Index: 0},
		{Kind: EventTextDelta, Index: 0, Text: "Hi"},
		{Kind: EventTextDone, Index: 0},
		{Kind: EventToolCallStart, Index: 1, ToolCall: &ToolCall{ID: "toolu_1", Name: "weather"}},
		{Kind: EventToolCallDelta, Index: 1, Delta: `{"city":`},
		{Kind: EventToolCallDone, Index: 1},
		{Kind: EventCompleted, StopReason: StopToolUse, Usage: &Usage{InputTokens: "2", OutputTokens: "3", TotalTokens: "5"}},
		{Kind: EventDone},
	}
	var got []byte
	for _, event := range events {
		wire, err := EncodeSSEEvent(Anthropic, event)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, wire...)
	}
	want := "event: message_start\ndata: {\"message\":{\"content\":[],\"id\":\"msg_1\",\"model\":\"claude-x\",\"role\":\"assistant\",\"stop_reason\":null,\"stop_sequence\":null,\"type\":\"message\",\"usage\":{\"input_tokens\":2,\"output_tokens\":0}},\"type\":\"message_start\"}\n\n" +
		"event: content_block_start\ndata: {\"content_block\":{\"text\":\"\",\"type\":\"text\"},\"index\":0,\"type\":\"content_block_start\"}\n\n" +
		"event: content_block_delta\ndata: {\"delta\":{\"text\":\"Hi\",\"type\":\"text_delta\"},\"index\":0,\"type\":\"content_block_delta\"}\n\n" +
		"event: content_block_stop\ndata: {\"index\":0,\"type\":\"content_block_stop\"}\n\n" +
		"event: content_block_start\ndata: {\"content_block\":{\"id\":\"toolu_1\",\"input\":{},\"name\":\"weather\",\"type\":\"tool_use\"},\"index\":1,\"type\":\"content_block_start\"}\n\n" +
		"event: content_block_delta\ndata: {\"delta\":{\"partial_json\":\"{\\\"city\\\":\",\"type\":\"input_json_delta\"},\"index\":1,\"type\":\"content_block_delta\"}\n\n" +
		"event: content_block_stop\ndata: {\"index\":1,\"type\":\"content_block_stop\"}\n\n" +
		"event: message_delta\ndata: {\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	assertBytes(t, got, want)
}

func TestResponsesStreamLifecycleGoldens(t *testing.T) {
	start := &Response{ID: "resp_1", CreatedAt: "7", Model: "gpt-x", Message: Message{Role: RoleAssistant}}
	call := &ToolCall{ItemID: "fc_1", ID: "call_1", Name: "weather", Arguments: json.RawMessage(`{"city":"Paris"}`)}
	final := &Response{ID: "resp_1", CreatedAt: "7", Model: "gpt-x", Message: Message{ID: "msg_1", Role: RoleAssistant, Parts: []Part{{Kind: PartText, Text: "Hi"}, {Kind: PartToolCall, Call: call}}}, StopReason: StopToolUse}
	cases := []struct {
		name  string
		event Event
		want  string
	}{
		{"created", Event{Kind: EventStarted, SequenceNumber: seq(0), Response: start}, `event: response.created
data: {"response":{"created_at":7,"id":"resp_1","model":"gpt-x","object":"response","output":[],"status":"in_progress"},"sequence_number":0,"type":"response.created"}

`},
		{"message item added", Event{Kind: EventOutputItemStart, SequenceNumber: seq(1), Index: 0, ItemID: "msg_1"}, `event: response.output_item.added
data: {"item":{"content":[],"id":"msg_1","role":"assistant","status":"in_progress","type":"message"},"output_index":0,"sequence_number":1,"type":"response.output_item.added"}

`},
		{"content added", Event{Kind: EventTextStart, SequenceNumber: seq(2), Index: 0, ContentIndex: 0, ItemID: "msg_1"}, `event: response.content_part.added
data: {"content_index":0,"item_id":"msg_1","output_index":0,"part":{"annotations":[],"text":"","type":"output_text"},"sequence_number":2,"type":"response.content_part.added"}

`},
		{"text delta", Event{Kind: EventTextDelta, SequenceNumber: seq(3), Index: 0, ContentIndex: 0, ItemID: "msg_1", Text: "Hi"}, `event: response.output_text.delta
data: {"content_index":0,"delta":"Hi","item_id":"msg_1","output_index":0,"sequence_number":3,"type":"response.output_text.delta"}

`},
		{"text done", Event{Kind: EventTextDone, SequenceNumber: seq(4), Index: 0, ContentIndex: 0, ItemID: "msg_1", Text: "Hi"}, `event: response.output_text.done
data: {"content_index":0,"item_id":"msg_1","output_index":0,"sequence_number":4,"text":"Hi","type":"response.output_text.done"}

`},
		{"content done", Event{Kind: EventContentPartDone, SequenceNumber: seq(5), Index: 0, ContentIndex: 0, ItemID: "msg_1", Text: "Hi"}, `event: response.content_part.done
data: {"content_index":0,"item_id":"msg_1","output_index":0,"part":{"annotations":[],"text":"Hi","type":"output_text"},"sequence_number":5,"type":"response.content_part.done"}

`},
		{"message item done", Event{Kind: EventOutputItemDone, SequenceNumber: seq(6), Index: 0, ItemID: "msg_1", Text: "Hi"}, `event: response.output_item.done
data: {"item":{"content":[{"annotations":[],"text":"Hi","type":"output_text"}],"id":"msg_1","role":"assistant","status":"completed","type":"message"},"output_index":0,"sequence_number":6,"type":"response.output_item.done"}

`},
		{"function item added", Event{Kind: EventToolCallStart, SequenceNumber: seq(7), Index: 1, ToolCall: &ToolCall{ItemID: "fc_1", ID: "call_1", Name: "weather"}}, `event: response.output_item.added
data: {"item":{"arguments":"","call_id":"call_1","id":"fc_1","name":"weather","status":"in_progress","type":"function_call"},"output_index":1,"sequence_number":7,"type":"response.output_item.added"}

`},
		{"arguments delta", Event{Kind: EventToolCallDelta, SequenceNumber: seq(8), Index: 1, ItemID: "fc_1", Delta: `{"city":`}, `event: response.function_call_arguments.delta
data: {"delta":"{\"city\":","item_id":"fc_1","output_index":1,"sequence_number":8,"type":"response.function_call_arguments.delta"}

`},
		{"arguments done", Event{Kind: EventToolCallDone, SequenceNumber: seq(9), Index: 1, ToolCall: call}, `event: response.function_call_arguments.done
data: {"arguments":"{\"city\":\"Paris\"}","item_id":"fc_1","output_index":1,"sequence_number":9,"type":"response.function_call_arguments.done"}

`},
		{"function item done", Event{Kind: EventOutputItemDone, SequenceNumber: seq(10), Index: 1, ToolCall: call}, `event: response.output_item.done
data: {"item":{"arguments":"{\"city\":\"Paris\"}","call_id":"call_1","id":"fc_1","name":"weather","status":"completed","type":"function_call"},"output_index":1,"sequence_number":10,"type":"response.output_item.done"}

`},
		{"completed", Event{Kind: EventCompleted, SequenceNumber: seq(11), Response: final}, `event: response.completed
data: {"response":{"created_at":7,"id":"resp_1","model":"gpt-x","object":"response","output":[{"content":[{"annotations":[],"text":"Hi","type":"output_text"}],"id":"msg_1","role":"assistant","status":"completed","type":"message"},{"arguments":"{\"city\":\"Paris\"}","call_id":"call_1","id":"fc_1","name":"weather","status":"completed","type":"function_call"}],"status":"completed"},"sequence_number":11,"type":"response.completed"}

`},
		{"error", Event{Kind: EventError, SequenceNumber: seq(12), Error: fail(ErrLimit, "input", "too large", nil)}, `event: error
data: {"code":"limit_exceeded","message":"input: too large","param":null,"sequence_number":12,"type":"error"}

`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EncodeSSEEvent(OpenAIResponses, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			assertBytes(t, got, tc.want)
		})
	}
}
