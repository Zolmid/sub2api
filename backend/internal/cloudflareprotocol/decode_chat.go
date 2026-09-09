package cloudflareprotocol

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type chatRequestWire struct {
	Model               string            `json:"model"`
	Messages            []json.RawMessage `json:"messages"`
	Tools               []json.RawMessage `json:"tools,omitempty"`
	ToolChoice          json.RawMessage   `json:"tool_choice,omitempty"`
	Stream              bool              `json:"stream,omitempty"`
	ServiceTier         string            `json:"service_tier,omitempty"`
	MaxCompletionTokens json.Number       `json:"max_completion_tokens,omitempty"`
	MaxTokens           json.Number       `json:"max_tokens,omitempty"`
	Stop                json.RawMessage   `json:"stop,omitempty"`
}

type chatMessageWire struct {
	Role       string            `json:"role"`
	Content    json.RawMessage   `json:"content"`
	ToolCalls  []json.RawMessage `json:"tool_calls,omitempty"`
	ToolCallID string            `json:"tool_call_id,omitempty"`
}

func decodeChatRequest(body []byte, limits DecodeLimits) (Request, error) {
	var wire chatRequestWire
	if err := decodeStrict(body, &wire, "body"); err != nil {
		return Request{}, err
	}
	if err := checkString("model", wire.Model, true, limits); err != nil {
		return Request{}, err
	}
	if wire.MaxCompletionTokens != "" && wire.MaxTokens != "" {
		return Request{}, fail(ErrValidation, "max_completion_tokens", "cannot be combined with max_tokens", nil)
	}
	limit := wire.MaxCompletionTokens
	field := "max_completion_tokens"
	if limit == "" {
		limit = wire.MaxTokens
		field = "max_tokens"
	}
	limit, err := decodeTokenLimit(field, limit)
	if err != nil {
		return Request{}, err
	}
	stop, err := decodeStopSequences(wire.Stop, "stop", limits)
	if err != nil {
		return Request{}, err
	}
	if len(wire.Messages) == 0 {
		return Request{}, fail(ErrValidation, "messages", "must not be empty", nil)
	}
	if err := checkCount("messages", len(wire.Messages), limits); err != nil {
		return Request{}, err
	}
	request := Request{
		Protocol:        OpenAIChat,
		Model:           wire.Model,
		ServiceTier:     wire.ServiceTier,
		Stream:          wire.Stream,
		MaxOutputTokens: limit,
		StopSequences:   stop,
	}
	for i, raw := range wire.Messages {
		message, err := decodeChatMessage(raw, i, limits)
		if err != nil {
			return Request{}, err
		}
		request.Messages = append(request.Messages, message)
	}
	if err := checkCount("tools", len(wire.Tools), limits); err != nil {
		return Request{}, err
	}
	for i, raw := range wire.Tools {
		tool, err := decodeChatTool(raw, i, limits)
		if err != nil {
			return Request{}, err
		}
		request.Tools = append(request.Tools, tool)
	}
	choice, err := decodeChatToolChoice(wire.ToolChoice, limits)
	if err != nil {
		return Request{}, err
	}
	request.ToolChoice = choice
	return request, nil
}

func decodeChatMessage(raw json.RawMessage, index int, limits DecodeLimits) (Message, error) {
	field := fmt.Sprintf("messages[%d]", index)
	var wire chatMessageWire
	if err := decodeStrict(raw, &wire, field); err != nil {
		return Message{}, err
	}
	role := Role(wire.Role)
	switch role {
	case RoleSystem, RoleDeveloper, RoleUser, RoleAssistant, RoleTool:
	default:
		return Message{}, fail(ErrUnsupported, field+".role", "role is not representable", nil)
	}
	parts, isNull, err := decodeChatContent(wire.Content, field+".content", limits)
	if err != nil {
		return Message{}, err
	}
	message := Message{Role: role, Parts: parts}
	if role == RoleTool {
		if err := validateID(field+".tool_call_id", wire.ToolCallID, true, limits); err != nil {
			return Message{}, err
		}
		if len(wire.ToolCalls) != 0 {
			return Message{}, fail(ErrUnsupported, field+".tool_calls", "tool result cannot also declare calls", nil)
		}
		if isNull || len(parts) == 0 {
			return Message{}, fail(ErrLossy, field+".content", "empty tool result is not synthesized", nil)
		}
		message.Parts = []Part{{Kind: PartToolResult, Result: &ToolResult{CallID: wire.ToolCallID, Content: parts}}}
		return message, nil
	}
	if wire.ToolCallID != "" {
		return Message{}, fail(ErrUnsupported, field+".tool_call_id", "only tool messages may carry a call ID", nil)
	}
	if err := checkCount(field+".tool_calls", len(wire.ToolCalls), limits); err != nil {
		return Message{}, err
	}
	for callIndex, callRaw := range wire.ToolCalls {
		call, err := decodeChatToolCall(callRaw, fmt.Sprintf("%s.tool_calls[%d]", field, callIndex), limits)
		if err != nil {
			return Message{}, err
		}
		message.Parts = append(message.Parts, Part{Kind: PartToolCall, Call: call})
	}
	if len(message.Parts) == 0 {
		if isNull && role == RoleAssistant && len(wire.ToolCalls) > 0 {
			return message, nil
		}
		return Message{}, fail(ErrLossy, field+".content", "empty content is not synthesized", nil)
	}
	return message, nil
}

func decodeChatContent(raw json.RawMessage, field string, limits DecodeLimits) ([]Part, bool, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, true, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if err := checkString(field, text, true, limits); err != nil {
			return nil, false, err
		}
		return []Part{{Kind: PartText, Text: text}}, false, nil
	}
	var rawParts []json.RawMessage
	if err := decodeStrict(raw, &rawParts, field); err != nil {
		return nil, false, err
	}
	if len(rawParts) == 0 {
		return nil, false, fail(ErrLossy, field, "empty content is not synthesized", nil)
	}
	if err := checkCount(field, len(rawParts), limits); err != nil {
		return nil, false, err
	}
	parts := make([]Part, 0, len(rawParts))
	for i, rawPart := range rawParts {
		partField := fmt.Sprintf("%s[%d]", field, i)
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(rawPart, &envelope); err != nil {
			return nil, false, fail(ErrMalformed, partField, "invalid content part", err)
		}
		switch envelope.Type {
		case "text":
			var wire struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}
			if err := decodeStrict(rawPart, &wire, partField); err != nil {
				return nil, false, err
			}
			if err := checkString(partField+".text", wire.Text, true, limits); err != nil {
				return nil, false, err
			}
			parts = append(parts, Part{Kind: PartText, Text: wire.Text})
		case "image_url":
			var wire struct {
				Type     string `json:"type"`
				ImageURL struct {
					URL    string `json:"url"`
					Detail string `json:"detail,omitempty"`
				} `json:"image_url"`
			}
			if err := decodeStrict(rawPart, &wire, partField); err != nil {
				return nil, false, err
			}
			if err := validateMediaURI(partField+".image_url.url", wire.ImageURL.URL, limits); err != nil {
				return nil, false, err
			}
			parts = append(parts, Part{Kind: PartMediaRef, Media: &MediaReference{URL: wire.ImageURL.URL, Raw: cloneRaw(rawPart)}})
		default:
			return nil, false, fail(ErrUnsupported, partField+".type", "content part is not representable", nil)
		}
	}
	return parts, false, nil
}

func decodeChatToolCall(raw json.RawMessage, field string, limits DecodeLimits) (*ToolCall, error) {
	var wire struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	if err := decodeStrict(raw, &wire, field); err != nil {
		return nil, err
	}
	if wire.Type != "function" {
		return nil, fail(ErrUnsupported, field+".type", "only function calls are supported", nil)
	}
	if err := validateID(field+".id", wire.ID, true, limits); err != nil {
		return nil, err
	}
	if err := validateToolName(field+".function.name", wire.Function.Name); err != nil {
		return nil, err
	}
	arguments := json.RawMessage(wire.Function.Arguments)
	if err := validateJSONObject(field+".function.arguments", arguments, limits); err != nil {
		return nil, err
	}
	return &ToolCall{ID: wire.ID, Name: wire.Function.Name, Arguments: cloneRaw(arguments)}, nil
}

func decodeChatTool(raw json.RawMessage, index int, limits DecodeLimits) (Tool, error) {
	field := fmt.Sprintf("tools[%d]", index)
	var wire struct {
		Type     string `json:"type"`
		Function struct {
			Name        string          `json:"name"`
			Description string          `json:"description,omitempty"`
			Parameters  json.RawMessage `json:"parameters"`
		} `json:"function"`
	}
	if err := decodeStrict(raw, &wire, field); err != nil {
		return Tool{}, err
	}
	if wire.Type != "function" {
		return Tool{}, fail(ErrUnsupported, field+".type", "only functions are supported", nil)
	}
	if err := validateToolName(field+".function.name", wire.Function.Name); err != nil {
		return Tool{}, err
	}
	if err := checkString(field+".function.description", wire.Function.Description, false, limits); err != nil {
		return Tool{}, err
	}
	if err := validateJSONObject(field+".function.parameters", wire.Function.Parameters, limits); err != nil {
		return Tool{}, err
	}
	return Tool{Name: wire.Function.Name, Description: wire.Function.Description, Schema: cloneRaw(wire.Function.Parameters)}, nil
}

func decodeChatToolChoice(raw json.RawMessage, limits DecodeLimits) (ToolChoice, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ToolChoice{}, nil
	}
	var mode string
	if err := json.Unmarshal(raw, &mode); err == nil {
		switch mode {
		case "auto", "none", "required":
			return ToolChoice{Mode: mode}, nil
		default:
			return ToolChoice{}, fail(ErrUnsupported, "tool_choice", "mode is not supported", nil)
		}
	}
	var wire struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if err := decodeStrict(raw, &wire, "tool_choice"); err != nil {
		return ToolChoice{}, err
	}
	if wire.Type != "function" {
		return ToolChoice{}, fail(ErrUnsupported, "tool_choice.type", "only named functions are supported", nil)
	}
	if err := validateToolName("tool_choice.function.name", wire.Function.Name); err != nil {
		return ToolChoice{}, err
	}
	return ToolChoice{Mode: "named", Name: wire.Function.Name}, nil
}
