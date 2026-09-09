package cloudflareprotocol

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type responsesRequestWire struct {
	Model           string            `json:"model"`
	Instructions    json.RawMessage   `json:"instructions,omitempty"`
	Input           json.RawMessage   `json:"input"`
	Tools           []json.RawMessage `json:"tools,omitempty"`
	ToolChoice      json.RawMessage   `json:"tool_choice,omitempty"`
	Stream          bool              `json:"stream,omitempty"`
	ServiceTier     string            `json:"service_tier,omitempty"`
	MaxOutputTokens json.Number       `json:"max_output_tokens,omitempty"`
}

func decodeResponsesRequest(body []byte, limits DecodeLimits) (Request, error) {
	var wire responsesRequestWire
	if err := decodeStrict(body, &wire, "body"); err != nil {
		return Request{}, err
	}
	if err := checkString("model", wire.Model, true, limits); err != nil {
		return Request{}, err
	}
	maxTokens, err := decodeTokenLimit("max_output_tokens", wire.MaxOutputTokens)
	if err != nil {
		return Request{}, err
	}
	request := Request{
		Protocol:        OpenAIResponses,
		Model:           wire.Model,
		ServiceTier:     wire.ServiceTier,
		Stream:          wire.Stream,
		MaxOutputTokens: maxTokens,
	}
	if len(wire.Instructions) != 0 && !bytes.Equal(wire.Instructions, []byte("null")) {
		var instructions string
		if err := json.Unmarshal(wire.Instructions, &instructions); err != nil {
			return Request{}, fail(ErrUnsupported, "instructions", "only text instructions are supported", err)
		}
		if err := checkString("instructions", instructions, true, limits); err != nil {
			return Request{}, err
		}
		request.Messages = append(request.Messages, Message{Role: RoleDeveloper, Parts: []Part{{Kind: PartText, Text: instructions}}})
	}
	inputMessages, err := decodeResponsesInput(wire.Input, limits)
	if err != nil {
		return Request{}, err
	}
	request.Messages = append(request.Messages, inputMessages...)
	if len(request.Messages) == 0 {
		return Request{}, fail(ErrValidation, "input", "must not be empty", nil)
	}
	if err := checkCount("tools", len(wire.Tools), limits); err != nil {
		return Request{}, err
	}
	for i, raw := range wire.Tools {
		tool, err := decodeResponsesTool(raw, i, limits)
		if err != nil {
			return Request{}, err
		}
		request.Tools = append(request.Tools, tool)
	}
	choice, err := decodeResponsesToolChoice(wire.ToolChoice, limits)
	if err != nil {
		return Request{}, err
	}
	request.ToolChoice = choice
	return request, nil
}

func decodeResponsesInput(raw json.RawMessage, limits DecodeLimits) ([]Message, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, fail(ErrValidation, "input", "is required", nil)
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if err := checkString("input", text, true, limits); err != nil {
			return nil, err
		}
		return []Message{{Role: RoleUser, Parts: []Part{{Kind: PartText, Text: text}}}}, nil
	}
	var items []json.RawMessage
	if err := decodeStrict(raw, &items, "input"); err != nil {
		return nil, err
	}
	if err := checkCount("input", len(items), limits); err != nil {
		return nil, err
	}
	messages := make([]Message, 0, len(items))
	for i, itemRaw := range items {
		field := fmt.Sprintf("input[%d]", i)
		var envelope struct {
			Type string `json:"type,omitempty"`
			Role string `json:"role,omitempty"`
		}
		if err := json.Unmarshal(itemRaw, &envelope); err != nil {
			return nil, fail(ErrMalformed, field, "invalid input item", err)
		}
		var message Message
		var err error
		switch envelope.Type {
		case "function_call":
			message, err = decodeResponsesFunctionCall(itemRaw, field, limits)
		case "function_call_output":
			message, err = decodeResponsesFunctionOutput(itemRaw, field, limits)
		case "", "message":
			message, err = decodeResponsesMessage(itemRaw, field, limits)
		default:
			return nil, fail(ErrUnsupported, field+".type", "input item is not representable", nil)
		}
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, nil
}

func decodeResponsesMessage(raw json.RawMessage, field string, limits DecodeLimits) (Message, error) {
	var wire struct {
		Type    string          `json:"type,omitempty"`
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := decodeStrict(raw, &wire, field); err != nil {
		return Message{}, err
	}
	role := Role(wire.Role)
	switch role {
	case RoleSystem, RoleDeveloper, RoleUser, RoleAssistant:
	default:
		return Message{}, fail(ErrUnsupported, field+".role", "role is not representable", nil)
	}
	parts, err := decodeResponsesContent(wire.Content, field+".content", limits)
	if err != nil {
		return Message{}, err
	}
	return Message{Role: role, Parts: parts}, nil
}

func decodeResponsesContent(raw json.RawMessage, field string, limits DecodeLimits) ([]Part, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if err := checkString(field, text, true, limits); err != nil {
			return nil, err
		}
		return []Part{{Kind: PartText, Text: text}}, nil
	}
	var rawParts []json.RawMessage
	if err := decodeStrict(raw, &rawParts, field); err != nil {
		return nil, err
	}
	if len(rawParts) == 0 {
		return nil, fail(ErrLossy, field, "empty content is not synthesized", nil)
	}
	if err := checkCount(field, len(rawParts), limits); err != nil {
		return nil, err
	}
	parts := make([]Part, 0, len(rawParts))
	for i, rawPart := range rawParts {
		partField := fmt.Sprintf("%s[%d]", field, i)
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(rawPart, &envelope); err != nil {
			return nil, fail(ErrMalformed, partField, "invalid content part", err)
		}
		switch envelope.Type {
		case "input_text", "output_text":
			var wire struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}
			if err := decodeStrict(rawPart, &wire, partField); err != nil {
				return nil, err
			}
			if err := checkString(partField+".text", wire.Text, true, limits); err != nil {
				return nil, err
			}
			parts = append(parts, Part{Kind: PartText, Text: wire.Text})
		case "input_image":
			var wire struct {
				Type     string `json:"type"`
				ImageURL string `json:"image_url,omitempty"`
				FileID   string `json:"file_id,omitempty"`
				Detail   string `json:"detail,omitempty"`
			}
			if err := decodeStrict(rawPart, &wire, partField); err != nil {
				return nil, err
			}
			if (wire.ImageURL == "") == (wire.FileID == "") {
				return nil, fail(ErrValidation, partField, "exactly one image_url or file_id is required", nil)
			}
			if wire.ImageURL != "" {
				if err := validateMediaURI(partField+".image_url", wire.ImageURL, limits); err != nil {
					return nil, err
				}
			}
			if err := validateID(partField+".file_id", wire.FileID, false, limits); err != nil {
				return nil, err
			}
			parts = append(parts, Part{Kind: PartMediaRef, Media: &MediaReference{URL: wire.ImageURL, FileID: wire.FileID, Raw: cloneRaw(rawPart)}})
		default:
			return nil, fail(ErrUnsupported, partField+".type", "content part is not representable", nil)
		}
	}
	return parts, nil
}

func decodeResponsesFunctionCall(raw json.RawMessage, field string, limits DecodeLimits) (Message, error) {
	var wire struct {
		Type      string `json:"type"`
		ID        string `json:"id,omitempty"`
		CallID    string `json:"call_id"`
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	if err := decodeStrict(raw, &wire, field); err != nil {
		return Message{}, err
	}
	if err := validateID(field+".call_id", wire.CallID, true, limits); err != nil {
		return Message{}, err
	}
	if err := validateID(field+".id", wire.ID, false, limits); err != nil {
		return Message{}, err
	}
	if err := validateToolName(field+".name", wire.Name); err != nil {
		return Message{}, err
	}
	arguments := json.RawMessage(wire.Arguments)
	if err := validateJSONObject(field+".arguments", arguments, limits); err != nil {
		return Message{}, err
	}
	return Message{Role: RoleAssistant, Parts: []Part{{Kind: PartToolCall, Call: &ToolCall{ItemID: wire.ID, ID: wire.CallID, Name: wire.Name, Arguments: cloneRaw(arguments)}}}}, nil
}

func decodeResponsesFunctionOutput(raw json.RawMessage, field string, limits DecodeLimits) (Message, error) {
	var wire struct {
		Type   string          `json:"type"`
		CallID string          `json:"call_id"`
		Output json.RawMessage `json:"output"`
	}
	if err := decodeStrict(raw, &wire, field); err != nil {
		return Message{}, err
	}
	if err := validateID(field+".call_id", wire.CallID, true, limits); err != nil {
		return Message{}, err
	}
	var text string
	if err := json.Unmarshal(wire.Output, &text); err != nil {
		return Message{}, fail(ErrUnsupported, field+".output", "only text tool results are supported", err)
	}
	if err := checkString(field+".output", text, true, limits); err != nil {
		return Message{}, err
	}
	return Message{Role: RoleTool, Parts: []Part{{Kind: PartToolResult, Result: &ToolResult{CallID: wire.CallID, Content: []Part{{Kind: PartText, Text: text}}}}}}, nil
}

func decodeResponsesTool(raw json.RawMessage, index int, limits DecodeLimits) (Tool, error) {
	field := fmt.Sprintf("tools[%d]", index)
	var wire struct {
		Type        string          `json:"type"`
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters"`
	}
	if err := decodeStrict(raw, &wire, field); err != nil {
		return Tool{}, err
	}
	if wire.Type != "function" {
		return Tool{}, fail(ErrUnsupported, field+".type", "only functions are supported", nil)
	}
	if err := validateToolName(field+".name", wire.Name); err != nil {
		return Tool{}, err
	}
	if err := checkString(field+".description", wire.Description, false, limits); err != nil {
		return Tool{}, err
	}
	if err := validateJSONObject(field+".parameters", wire.Parameters, limits); err != nil {
		return Tool{}, err
	}
	return Tool{Name: wire.Name, Description: wire.Description, Schema: cloneRaw(wire.Parameters)}, nil
}

func decodeResponsesToolChoice(raw json.RawMessage, limits DecodeLimits) (ToolChoice, error) {
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
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if err := decodeStrict(raw, &wire, "tool_choice"); err != nil {
		return ToolChoice{}, err
	}
	if wire.Type != "function" {
		return ToolChoice{}, fail(ErrUnsupported, "tool_choice.type", "only named functions are supported", nil)
	}
	if err := validateToolName("tool_choice.name", wire.Name); err != nil {
		return ToolChoice{}, err
	}
	return ToolChoice{Mode: "named", Name: wire.Name}, nil
}
