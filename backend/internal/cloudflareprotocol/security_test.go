package cloudflareprotocol

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseSSECarriesOnlyValidRetryDirective(t *testing.T) {
	input := strings.NewReader(
		"retry: 1500\n\n" +
			"retry: not-a-number\n" +
			"id: event-1\n" +
			"event: response.output_text.delta\n" +
			"data: first\n\n" +
			"data: second",
	)
	var frames []SSEFrame
	err := ParseSSE(context.Background(), input, SSELimits{}, func(frame SSEFrame) error {
		frames = append(frames, frame)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(frames))
	}
	if frames[0].Retry != "1500" || frames[0].ID != "event-1" ||
		frames[0].Event != "response.output_text.delta" ||
		string(frames[0].Data) != "first" {
		t.Fatalf("first frame = %#v", frames[0])
	}
	if frames[1].Retry != "1500" || frames[1].ID != "event-1" ||
		frames[1].Event != "" || string(frames[1].Data) != "second" {
		t.Fatalf("second frame = %#v", frames[1])
	}
}

func TestResponsesContentFilterIsIncomplete(t *testing.T) {
	response := Response{
		ID:        "resp-filtered",
		CreatedAt: "1",
		Model:     "gpt-x",
		Message: Message{
			ID:   "msg-filtered",
			Role: RoleAssistant,
			Parts: []Part{{
				Kind: PartText,
				Text: "",
			}},
		},
		StopReason: StopContentFilter,
	}
	wire, err := EncodeResponse(OpenAIResponses, response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Status            string `json:"status"`
		IncompleteDetails struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
	}
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status != "incomplete" || decoded.IncompleteDetails.Reason != "content_filter" {
		t.Fatalf("response = %s", wire)
	}
}

func TestPublicErrorsNormalizeAndRedact(t *testing.T) {
	secret := "Bearer top-secret-token"
	unknown := &Error{
		Code:       ErrorCode("provider_private_code"),
		Field:      "https://internal.example/private",
		Message:    secret,
		HTTPStatus: 200,
	}
	wire, err := EncodeError(OpenAIChat, unknown)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), secret) ||
		strings.Contains(string(wire), "internal.example") ||
		!strings.Contains(string(wire), `"code":"upstream_error"`) ||
		!strings.Contains(string(wire), "upstream request failed") {
		t.Fatalf("unsafe error response: %s", wire)
	}

	stream, err := EncodeSSEEvent(OpenAIResponses, Event{
		Kind:           EventError,
		SequenceNumber: seq(7),
		Error:          unknown,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stream), "provider_private_code") ||
		!strings.Contains(string(stream), `"code":"upstream_error"`) {
		t.Fatalf("unsafe stream error: %s", stream)
	}

	for _, status := range []int{429, 500, 503} {
		upstream := UpstreamError(status, true, false, secret)
		if upstream.HTTPStatus != status || !upstream.Retryable || upstream.BeforeOutput {
			t.Fatalf("upstream error metadata = %#v", upstream)
		}
		wire, err := EncodeError(Anthropic, upstream)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(wire), secret) ||
			!strings.Contains(string(wire), "upstream request failed") {
			t.Fatalf("unsafe upstream response: %s", wire)
		}
	}
}

func FuzzDecodeRequestDoesNotPanic(f *testing.F) {
	f.Add(byte(0), []byte(`{"model":"m","messages":[{"role":"user","content":"x"}]}`))
	f.Add(byte(1), []byte(`{"model":"m","input":"x"}`))
	f.Add(byte(2), []byte(`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"x"}]}`))
	f.Fuzz(func(t *testing.T, selector byte, body []byte) {
		protocols := [...]Protocol{OpenAIChat, OpenAIResponses, Anthropic, Gemini}
		protocol := protocols[int(selector)%len(protocols)]
		options := DecodeOptions{}
		if protocol == Gemini {
			options.Model = "models/fuzz"
		}
		_, _ = DecodeRequestWithOptions(protocol, body, options)
	})
}

func FuzzParseSSEDoesNotPanic(f *testing.F) {
	f.Add([]byte("data: ok\n\n"))
	f.Add([]byte("retry: 1000\ndata: final"))
	f.Fuzz(func(t *testing.T, body []byte) {
		_ = ParseSSE(
			context.Background(),
			strings.NewReader(string(body)),
			SSELimits{MaxLineBytes: 1024, MaxEventBytes: 4096, MaxEvents: 32},
			func(SSEFrame) error { return nil },
		)
	})
}
