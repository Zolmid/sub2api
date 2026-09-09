package cloudflareprotocol

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func decodeAnthropicRequest(body []byte, limits DecodeLimits) (Request, error) {
	var wire struct {
		Model         string            `json:"model"`
		System        json.RawMessage   `json:"system,omitempty"`
		Messages      []json.RawMessage `json:"messages"`
		Tools         []json.RawMessage `json:"tools,omitempty"`
		ToolChoice    json.RawMessage   `json:"tool_choice,omitempty"`
		Stream        bool              `json:"stream,omitempty"`
		MaxTokens     json.Number       `json:"max_tokens"`
		StopSequences []string          `json:"stop_sequences,omitempty"`
	}
	if err := decodeStrict(body, &wire, "body"); err != nil {
		return Request{}, err
	}
	if err := checkString("model", wire.Model, true, limits); err != nil {
		return Request{}, err
	}
	if wire.MaxTokens == "" {
		return Request{}, fail(ErrValidation, "max_tokens", "is required", nil)
	}
	maxTokens, err := decodeTokenLimit("max_tokens", wire.MaxTokens)
	if err != nil {
		return Request{}, err
	}
	if len(wire.Messages) == 0 {
		return Request{}, fail(ErrValidation, "messages", "must not be empty", nil)
	}
	if err := checkCount("messages", len(wire.Messages), limits); err != nil {
		return Request{}, err
	}
	if err := validateStrings("stop_sequences", wire.StopSequences, limits); err != nil {
		return Request{}, err
	}

	request := Request{
		Protocol:        Anthropic,
		Model:           wire.Model,
		Stream:          wire.Stream,
		MaxOutputTokens: maxTokens,
		StopSequences:   append([]string(nil), wire.StopSequences...),
	}
	if len(wire.System) > 0 && !bytes.Equal(wire.System, []byte("null")) {
		parts, err := decodeAnthropicTextContent(wire.System, "system", limits)
		if err != nil {
			return Request{}, err
		}
		request.Messages = append(request.Messages, Message{Role: RoleSystem, Parts: parts})
	}
	for i, raw := range wire.Messages {
		message, err := decodeAnthropicMessage(raw, fmt.Sprintf("messages[%d]", i), limits)
		if err != nil {
			return Request{}, err
		}
		request.Messages = append(request.Messages, message)
	}
	if err := checkCount("tools", len(wire.Tools), limits); err != nil {
		return Request{}, err
	}
	for i, raw := range wire.Tools {
		field := fmt.Sprintf("tools[%d]", i)
		var tool struct {
			Name        string          `json:"name"`
			Description string          `json:"description,omitempty"`
			InputSchema json.RawMessage `json:"input_schema"`
		}
		if err := decodeStrict(raw, &tool, field); err != nil {
			return Request{}, err
		}
		if err := validateToolName(field+".name", tool.Name); err != nil {
			return Request{}, err
		}
		if err := checkString(field+".description", tool.Description, false, limits); err != nil {
			return Request{}, err
		}
		if err := validateJSONObject(field+".input_schema", tool.InputSchema, limits); err != nil {
			return Request{}, err
		}
		request.Tools = append(request.Tools, Tool{Name: tool.Name, Description: tool.Description, Schema: cloneRaw(tool.InputSchema)})
	}
	choice, err := decodeAnthropicToolChoice(wire.ToolChoice)
	if err != nil {
		return Request{}, err
	}
	request.ToolChoice = choice
	return request, nil
}

func decodeAnthropicMessage(raw json.RawMessage, field string, limits DecodeLimits) (Message, error) {
	var wire struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := decodeStrict(raw, &wire, field); err != nil {
		return Message{}, err
	}
	role := Role(wire.Role)
	if role != RoleUser && role != RoleAssistant {
		return Message{}, fail(ErrUnsupported, field+".role", "only user and assistant roles are supported", nil)
	}
	parts, err := decodeAnthropicBlocks(wire.Content, field+".content", limits)
	if err != nil {
		return Message{}, err
	}
	return Message{Role: role, Parts: parts}, nil
}

func decodeAnthropicTextContent(raw json.RawMessage, field string, limits DecodeLimits) ([]Part, error) {
	if text, ok, err := decodeTextScalar(raw, field, limits); ok || err != nil {
		if err != nil {
			return nil, err
		}
		return []Part{{Kind: PartText, Text: text}}, nil
	}
	var blocks []json.RawMessage
	if err := decodeStrict(raw, &blocks, field); err != nil {
		return nil, err
	}
	if len(blocks) == 0 {
		return nil, fail(ErrLossy, field, "empty content is not synthesized", nil)
	}
	if err := checkCount(field, len(blocks), limits); err != nil {
		return nil, err
	}
	parts := make([]Part, 0, len(blocks))
	for i, rawBlock := range blocks {
		blockField := fmt.Sprintf("%s[%d]", field, i)
		var block struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := decodeStrict(rawBlock, &block, blockField); err != nil {
			return nil, err
		}
		if block.Type != "text" {
			return nil, fail(ErrUnsupported, blockField+".type", "only text blocks are supported", nil)
		}
		if err := checkString(blockField+".text", block.Text, true, limits); err != nil {
			return nil, err
		}
		parts = append(parts, Part{Kind: PartText, Text: block.Text})
	}
	return parts, nil
}

func decodeAnthropicBlocks(raw json.RawMessage, field string, limits DecodeLimits) ([]Part, error) {
	if text, ok, err := decodeTextScalar(raw, field, limits); ok || err != nil {
		if err != nil {
			return nil, err
		}
		return []Part{{Kind: PartText, Text: text}}, nil
	}
	var blocks []json.RawMessage
	if err := decodeStrict(raw, &blocks, field); err != nil {
		return nil, err
	}
	if len(blocks) == 0 {
		return nil, fail(ErrLossy, field, "empty content is not synthesized", nil)
	}
	if err := checkCount(field, len(blocks), limits); err != nil {
		return nil, err
	}
	parts := make([]Part, 0, len(blocks))
	for i, rawBlock := range blocks {
		blockField := fmt.Sprintf("%s[%d]", field, i)
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(rawBlock, &envelope); err != nil {
			return nil, fail(ErrMalformed, blockField, "invalid content block", err)
		}
		switch envelope.Type {
		case "text":
			var block struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}
			if err := decodeStrict(rawBlock, &block, blockField); err != nil {
				return nil, err
			}
			if err := checkString(blockField+".text", block.Text, true, limits); err != nil {
				return nil, err
			}
			parts = append(parts, Part{Kind: PartText, Text: block.Text})
		case "tool_use":
			var block struct {
				Type  string          `json:"type"`
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			}
			if err := decodeStrict(rawBlock, &block, blockField); err != nil {
				return nil, err
			}
			if err := validateID(blockField+".id", block.ID, true, limits); err != nil {
				return nil, err
			}
			if err := validateToolName(blockField+".name", block.Name); err != nil {
				return nil, err
			}
			if err := validateJSONObject(blockField+".input", block.Input, limits); err != nil {
				return nil, err
			}
			parts = append(parts, Part{Kind: PartToolCall, Call: &ToolCall{ID: block.ID, Name: block.Name, Arguments: cloneRaw(block.Input)}})
		case "tool_result":
			var block struct {
				Type      string          `json:"type"`
				ToolUseID string          `json:"tool_use_id"`
				Content   json.RawMessage `json:"content"`
				IsError   bool            `json:"is_error,omitempty"`
			}
			if err := decodeStrict(rawBlock, &block, blockField); err != nil {
				return nil, err
			}
			if err := validateID(blockField+".tool_use_id", block.ToolUseID, true, limits); err != nil {
				return nil, err
			}
			content, err := decodeAnthropicTextContent(block.Content, blockField+".content", limits)
			if err != nil {
				return nil, err
			}
			parts = append(parts, Part{Kind: PartToolResult, Result: &ToolResult{CallID: block.ToolUseID, Content: content, IsError: block.IsError}})
		default:
			return nil, fail(ErrUnsupported, blockField+".type", "content block is not representable", nil)
		}
	}
	return parts, nil
}

func decodeTextScalar(raw json.RawMessage, field string, limits DecodeLimits) (string, bool, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return "", false, nil
	}
	if err := checkString(field, text, true, limits); err != nil {
		return "", true, err
	}
	return text, true, nil
}

func decodeAnthropicToolChoice(raw json.RawMessage) (ToolChoice, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ToolChoice{}, nil
	}
	var wire struct {
		Type string `json:"type"`
		Name string `json:"name,omitempty"`
	}
	if err := decodeStrict(raw, &wire, "tool_choice"); err != nil {
		return ToolChoice{}, err
	}
	switch wire.Type {
	case "auto":
		return ToolChoice{Mode: "auto"}, nil
	case "none":
		return ToolChoice{Mode: "none"}, nil
	case "any":
		return ToolChoice{Mode: "required"}, nil
	case "tool":
		if err := validateToolName("tool_choice.name", wire.Name); err != nil {
			return ToolChoice{}, err
		}
		return ToolChoice{Mode: "named", Name: wire.Name}, nil
	default:
		return ToolChoice{}, fail(ErrUnsupported, "tool_choice.type", "choice is not representable", nil)
	}
}

func decodeGeminiRequest(body []byte, model string, limits DecodeLimits) (Request, error) {
	var wire struct {
		Contents   []json.RawMessage `json:"contents"`
		System     json.RawMessage   `json:"systemInstruction,omitempty"`
		Tools      []json.RawMessage `json:"tools,omitempty"`
		ToolConfig json.RawMessage   `json:"toolConfig,omitempty"`
		Generation json.RawMessage   `json:"generationConfig,omitempty"`
	}
	if err := decodeStrict(body, &wire, "body"); err != nil {
		return Request{}, err
	}
	if err := checkString("options.model", model, true, limits); err != nil {
		return Request{}, err
	}
	if len(wire.Contents) == 0 {
		return Request{}, fail(ErrValidation, "contents", "must not be empty", nil)
	}
	if err := checkCount("contents", len(wire.Contents), limits); err != nil {
		return Request{}, err
	}
	request := Request{Protocol: Gemini, Model: model}
	if len(wire.System) > 0 && !bytes.Equal(wire.System, []byte("null")) {
		message, err := decodeGeminiContent(wire.System, "systemInstruction", limits)
		if err != nil {
			return Request{}, err
		}
		message.Role = RoleSystem
		request.Messages = append(request.Messages, message)
	}
	for i, raw := range wire.Contents {
		message, err := decodeGeminiContent(raw, fmt.Sprintf("contents[%d]", i), limits)
		if err != nil {
			return Request{}, err
		}
		request.Messages = append(request.Messages, message)
	}
	if err := checkCount("tools", len(wire.Tools), limits); err != nil {
		return Request{}, err
	}
	toolCount := 0
	for i, raw := range wire.Tools {
		field := fmt.Sprintf("tools[%d]", i)
		var block struct {
			Functions []struct {
				Name        string          `json:"name"`
				Description string          `json:"description,omitempty"`
				Parameters  json.RawMessage `json:"parameters"`
			} `json:"functionDeclarations"`
		}
		if err := decodeStrict(raw, &block, field); err != nil {
			return Request{}, err
		}
		if len(block.Functions) == 0 {
			return Request{}, fail(ErrValidation, field+".functionDeclarations", "must not be empty", nil)
		}
		toolCount += len(block.Functions)
		if err := checkCount("tools.functionDeclarations", toolCount, limits); err != nil {
			return Request{}, err
		}
		for j, function := range block.Functions {
			functionField := fmt.Sprintf("%s.functionDeclarations[%d]", field, j)
			if err := validateToolName(functionField+".name", function.Name); err != nil {
				return Request{}, err
			}
			if err := checkString(functionField+".description", function.Description, false, limits); err != nil {
				return Request{}, err
			}
			if err := validateJSONObject(functionField+".parameters", function.Parameters, limits); err != nil {
				return Request{}, err
			}
			request.Tools = append(request.Tools, Tool{Name: function.Name, Description: function.Description, Schema: cloneRaw(function.Parameters)})
		}
	}
	choice, err := decodeGeminiToolChoice(wire.ToolConfig, limits)
	if err != nil {
		return Request{}, err
	}
	request.ToolChoice = choice
	if len(wire.Generation) > 0 && !bytes.Equal(wire.Generation, []byte("null")) {
		var config struct {
			MaxOutputTokens json.Number `json:"maxOutputTokens,omitempty"`
			StopSequences   []string    `json:"stopSequences,omitempty"`
		}
		if err := decodeStrict(wire.Generation, &config, "generationConfig"); err != nil {
			return Request{}, err
		}
		maxTokens, err := decodeTokenLimit("generationConfig.maxOutputTokens", config.MaxOutputTokens)
		if err != nil {
			return Request{}, err
		}
		if err := validateStrings("generationConfig.stopSequences", config.StopSequences, limits); err != nil {
			return Request{}, err
		}
		request.MaxOutputTokens = maxTokens
		request.StopSequences = append([]string(nil), config.StopSequences...)
	}
	return request, nil
}

func decodeGeminiContent(raw json.RawMessage, field string, limits DecodeLimits) (Message, error) {
	var wire struct {
		Role  string            `json:"role,omitempty"`
		Parts []json.RawMessage `json:"parts"`
	}
	if err := decodeStrict(raw, &wire, field); err != nil {
		return Message{}, err
	}
	role := RoleUser
	if wire.Role == "model" {
		role = RoleAssistant
	} else if wire.Role != "" && wire.Role != "user" {
		return Message{}, fail(ErrUnsupported, field+".role", "role is not representable", nil)
	}
	if len(wire.Parts) == 0 {
		return Message{}, fail(ErrLossy, field+".parts", "empty content is not synthesized", nil)
	}
	if err := checkCount(field+".parts", len(wire.Parts), limits); err != nil {
		return Message{}, err
	}
	parts := make([]Part, 0, len(wire.Parts))
	for i, rawPart := range wire.Parts {
		partField := fmt.Sprintf("%s.parts[%d]", field, i)
		var part struct {
			Text     *string `json:"text,omitempty"`
			FileData *struct {
				MIME string `json:"mimeType"`
				URI  string `json:"fileUri"`
			} `json:"fileData,omitempty"`
			InlineData json.RawMessage `json:"inlineData,omitempty"`
			Call       *struct {
				Name string          `json:"name"`
				Args json.RawMessage `json:"args"`
			} `json:"functionCall,omitempty"`
			Response json.RawMessage `json:"functionResponse,omitempty"`
		}
		if err := decodeStrict(rawPart, &part, partField); err != nil {
			return Message{}, err
		}
		present := 0
		if part.Text != nil {
			present++
		}
		if part.FileData != nil {
			present++
		}
		if len(part.InlineData) > 0 {
			present++
		}
		if part.Call != nil {
			present++
		}
		if len(part.Response) > 0 {
			present++
		}
		if present != 1 {
			return Message{}, fail(ErrValidation, partField, "exactly one part field is required", nil)
		}
		switch {
		case part.Text != nil:
			if err := checkString(partField+".text", *part.Text, true, limits); err != nil {
				return Message{}, err
			}
			parts = append(parts, Part{Kind: PartText, Text: *part.Text})
		case part.FileData != nil:
			if err := validateMediaURI(partField+".fileData.fileUri", part.FileData.URI, limits); err != nil {
				return Message{}, err
			}
			if err := checkString(partField+".fileData.mimeType", part.FileData.MIME, true, limits); err != nil {
				return Message{}, err
			}
			parts = append(parts, Part{Kind: PartMediaRef, Media: &MediaReference{URL: part.FileData.URI, MIME: part.FileData.MIME, Raw: cloneRaw(rawPart)}})
		case len(part.InlineData) > 0:
			return Message{}, fail(ErrUnsupported, partField+".inlineData", "inline object bytes are out of scope", nil)
		case part.Call != nil:
			if err := validateToolName(partField+".functionCall.name", part.Call.Name); err != nil {
				return Message{}, err
			}
			if err := validateJSONObject(partField+".functionCall.args", part.Call.Args, limits); err != nil {
				return Message{}, err
			}
			parts = append(parts, Part{Kind: PartToolCall, Call: &ToolCall{Name: part.Call.Name, Arguments: cloneRaw(part.Call.Args)}})
		default:
			return Message{}, fail(ErrUnsupported, partField+".functionResponse", "function response identity is not representable", nil)
		}
	}
	return Message{Role: role, Parts: parts}, nil
}

func decodeGeminiToolChoice(raw json.RawMessage, limits DecodeLimits) (ToolChoice, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ToolChoice{}, nil
	}
	var wire struct {
		Config struct {
			Mode    string   `json:"mode"`
			Allowed []string `json:"allowedFunctionNames,omitempty"`
		} `json:"functionCallingConfig"`
	}
	if err := decodeStrict(raw, &wire, "toolConfig"); err != nil {
		return ToolChoice{}, err
	}
	if err := validateStrings("toolConfig.functionCallingConfig.allowedFunctionNames", wire.Config.Allowed, limits); err != nil {
		return ToolChoice{}, err
	}
	switch wire.Config.Mode {
	case "AUTO":
		if len(wire.Config.Allowed) != 0 {
			return ToolChoice{}, fail(ErrLossy, "toolConfig.functionCallingConfig.allowedFunctionNames", "AUTO allow-list is not representable", nil)
		}
		return ToolChoice{Mode: "auto"}, nil
	case "NONE":
		if len(wire.Config.Allowed) != 0 {
			return ToolChoice{}, fail(ErrValidation, "toolConfig.functionCallingConfig.allowedFunctionNames", "must be empty for NONE", nil)
		}
		return ToolChoice{Mode: "none"}, nil
	case "ANY":
		if len(wire.Config.Allowed) == 0 {
			return ToolChoice{Mode: "required"}, nil
		}
		if len(wire.Config.Allowed) != 1 {
			return ToolChoice{}, fail(ErrLossy, "toolConfig.functionCallingConfig.allowedFunctionNames", "multiple named choices are not representable", nil)
		}
		if err := validateToolName("toolConfig.functionCallingConfig.allowedFunctionNames[0]", wire.Config.Allowed[0]); err != nil {
			return ToolChoice{}, err
		}
		return ToolChoice{Mode: "named", Name: wire.Config.Allowed[0]}, nil
	default:
		return ToolChoice{}, fail(ErrUnsupported, "toolConfig.functionCallingConfig.mode", "mode is not representable", nil)
	}
}

func validateStrings(field string, values []string, limits DecodeLimits) error {
	if err := checkCount(field, len(values), limits); err != nil {
		return err
	}
	for i, value := range values {
		if err := checkString(fmt.Sprintf("%s[%d]", field, i), value, true, limits); err != nil {
			return err
		}
	}
	return nil
}

func validateRequest(request Request, limits DecodeLimits) error {
	if err := checkString("model", request.Model, true, limits); err != nil {
		return err
	}
	if err := validateID("request_id", request.RequestID, false, limits); err != nil {
		return err
	}
	if err := checkString("service_tier", request.ServiceTier, false, limits); err != nil {
		return err
	}
	if err := validateStrings("stop_sequences", request.StopSequences, limits); err != nil {
		return err
	}
	if err := checkCount("messages", len(request.Messages), limits); err != nil {
		return err
	}
	if err := checkCount("tools", len(request.Tools), limits); err != nil {
		return err
	}
	toolNames := make(map[string]struct{}, len(request.Tools))
	for i, tool := range request.Tools {
		field := fmt.Sprintf("tools[%d]", i)
		if err := validateToolName(field+".name", tool.Name); err != nil {
			return err
		}
		if _, exists := toolNames[tool.Name]; exists {
			return fail(ErrValidation, field+".name", "duplicate tool name", nil)
		}
		toolNames[tool.Name] = struct{}{}
		if err := checkString(field+".description", tool.Description, false, limits); err != nil {
			return err
		}
		if err := validateJSONObject(field+".schema", tool.Schema, limits); err != nil {
			return err
		}
	}
	for i, message := range request.Messages {
		field := fmt.Sprintf("messages[%d]", i)
		if len(message.Parts) == 0 {
			return fail(ErrLossy, field+".parts", "empty message is not synthesized", nil)
		}
		if err := checkCount(field+".parts", len(message.Parts), limits); err != nil {
			return err
		}
		for j, part := range message.Parts {
			partField := fmt.Sprintf("%s.parts[%d]", field, j)
			switch part.Kind {
			case PartText:
				if err := checkString(partField+".text", part.Text, true, limits); err != nil {
					return err
				}
			case PartMediaRef:
				if part.Media == nil {
					return fail(ErrValidation, partField+".media", "nil media reference", nil)
				}
				if part.Media.URL != "" {
					if err := validateMediaURI(partField+".media.url", part.Media.URL, limits); err != nil {
						return err
					}
				}
				if part.Media.FileID != "" {
					if err := validateID(partField+".media.file_id", part.Media.FileID, true, limits); err != nil {
						return err
					}
				}
				if part.Media.URL == "" && part.Media.FileID == "" {
					return fail(ErrValidation, partField+".media", "external URL or provider file ID is required", nil)
				}
			case PartToolCall:
				if part.Call == nil {
					return fail(ErrValidation, partField+".call", "nil tool call", nil)
				}
				if request.Protocol != Gemini {
					if err := validateID(partField+".call.id", part.Call.ID, true, limits); err != nil {
						return err
					}
				}
				if err := validateToolName(partField+".call.name", part.Call.Name); err != nil {
					return err
				}
				if err := validateJSONObject(partField+".call.arguments", part.Call.Arguments, limits); err != nil {
					return err
				}
			case PartToolResult:
				if part.Result == nil {
					return fail(ErrValidation, partField+".result", "nil tool result", nil)
				}
				if err := validateID(partField+".result.call_id", part.Result.CallID, true, limits); err != nil {
					return err
				}
				if err := checkCount(partField+".result.content", len(part.Result.Content), limits); err != nil {
					return err
				}
				if len(part.Result.Content) == 0 {
					return fail(ErrLossy, partField+".result.content", "empty tool result is not synthesized", nil)
				}
				for k, resultPart := range part.Result.Content {
					resultField := fmt.Sprintf("%s.result.content[%d]", partField, k)
					if resultPart.Kind != PartText {
						return fail(ErrUnsupported, resultField+".kind", "only text tool results are supported", nil)
					}
					if err := checkString(resultField+".text", resultPart.Text, true, limits); err != nil {
						return err
					}
				}
			default:
				return fail(ErrUnsupported, partField+".kind", "part kind is not representable", nil)
			}
		}
	}
	switch request.ToolChoice.Mode {
	case "":
	case "auto", "none":
	case "required":
		if len(request.Tools) == 0 {
			return fail(ErrValidation, "tool_choice", "requires at least one tool", nil)
		}
	case "named":
		if _, ok := toolNames[request.ToolChoice.Name]; !ok {
			return fail(ErrValidation, "tool_choice.name", "must name a declared tool", nil)
		}
	default:
		return fail(ErrUnsupported, "tool_choice.mode", "mode is not representable", nil)
	}
	return nil
}

type EncodeLimits struct {
	MaxOutputBytes     int
	MaxStringBytes     int
	MaxCollectionItems int
	MaxJSONDepth       int
}

type EncodeOptions struct{ Limits EncodeLimits }

func normalizeEncodeLimits(l EncodeLimits) (EncodeLimits, error) {
	if l.MaxOutputBytes < 0 || l.MaxStringBytes < 0 || l.MaxCollectionItems < 0 || l.MaxJSONDepth < 0 {
		return EncodeLimits{}, fail(ErrValidation, "encode.limits", "limits cannot be negative", nil)
	}
	if l.MaxOutputBytes == 0 {
		l.MaxOutputBytes = defaultMaxBodyBytes
	}
	if l.MaxStringBytes == 0 {
		l.MaxStringBytes = defaultMaxStringBytes
	}
	if l.MaxCollectionItems == 0 {
		l.MaxCollectionItems = defaultMaxCollectionItems
	}
	if l.MaxJSONDepth == 0 {
		l.MaxJSONDepth = defaultMaxJSONDepth
	}
	if l.MaxOutputBytes > maxConfiguredBodyBytes || l.MaxStringBytes > maxConfiguredStringBytes || l.MaxCollectionItems > maxConfiguredItems || l.MaxJSONDepth > maxConfiguredJSONDepth {
		return EncodeLimits{}, fail(ErrValidation, "encode.limits", "configured limit exceeds hard maximum", nil)
	}
	return l, nil
}

func (l EncodeLimits) decodeLimits() DecodeLimits {
	return DecodeLimits{MaxBodyBytes: l.MaxOutputBytes, MaxJSONDepth: l.MaxJSONDepth, MaxCollectionItems: l.MaxCollectionItems, MaxStringBytes: l.MaxStringBytes}
}

func EncodeResponse(protocol Protocol, response Response) ([]byte, error) {
	return EncodeResponseWithOptions(protocol, response, EncodeOptions{})
}

func EncodeResponseWithOptions(protocol Protocol, response Response, options EncodeOptions) ([]byte, error) {
	limits, err := normalizeEncodeLimits(options.Limits)
	if err != nil {
		return nil, err
	}
	if err := validateResponseForProtocol(protocol, response, limits); err != nil {
		return nil, err
	}
	var value any
	switch protocol {
	case OpenAIChat:
		value, err = encodeChatResponse(response)
	case OpenAIResponses:
		value, err = encodeResponsesResponse(response)
	case Anthropic:
		value, err = encodeAnthropicResponse(response)
	case Gemini:
		value, err = encodeGeminiResponse(response)
	default:
		return nil, fail(ErrUnsupported, "protocol", "unknown protocol", nil)
	}
	if err != nil {
		return nil, err
	}
	return marshalBounded(value, limits)
}

func validateResponseForProtocol(protocol Protocol, response Response, limits EncodeLimits) error {
	dl := limits.decodeLimits()
	if err := validateID("response.id", response.ID, true, dl); err != nil {
		return err
	}
	if err := checkString("response.model", response.Model, true, dl); err != nil {
		return err
	}
	if err := validateID("response.request_id", response.RequestID, false, dl); err != nil {
		return err
	}
	if response.RequestID != "" {
		return fail(ErrLossy, "response.request_id", "destination has no response request-id field", nil)
	}
	if err := checkString("response.service_tier", response.ServiceTier, false, dl); err != nil {
		return err
	}
	if err := validateRole("response.message.role", response.Message.Role, RoleAssistant); err != nil {
		return err
	}
	if len(response.Message.Metadata) != 0 {
		return fail(ErrLossy, "response.message.metadata", "metadata is not representable", nil)
	}
	if err := checkCount("response.message.parts", len(response.Message.Parts), dl); err != nil {
		return err
	}
	if len(response.Message.Parts) == 0 {
		return fail(ErrLossy, "response.message.parts", "empty output is not synthesized", nil)
	}
	if err := validateUsage(response.Usage); err != nil {
		return err
	}
	if protocol == OpenAIChat || protocol == OpenAIResponses {
		if _, err := parseNonnegativeInteger("response.created_at", response.CreatedAt); err != nil {
			return err
		}
	} else if response.CreatedAt != "" {
		return fail(ErrLossy, "response.created_at", "destination cannot preserve created_at", nil)
	}
	if (protocol == Anthropic || protocol == Gemini) && response.ServiceTier != "" {
		return fail(ErrLossy, "response.service_tier", "destination cannot preserve service tier", nil)
	}
	textCount, callCount, seenCall := 0, 0, false
	for i, part := range response.Message.Parts {
		field := fmt.Sprintf("response.message.parts[%d]", i)
		switch part.Kind {
		case PartText:
			if err := checkString(field+".text", part.Text, false, dl); err != nil {
				return err
			}
			if seenCall && protocol == OpenAIResponses {
				return fail(ErrLossy, field, "text after a function item cannot preserve output ordering", nil)
			}
			textCount++
		case PartToolCall:
			seenCall = true
			callCount++
			if part.Call == nil {
				return fail(ErrValidation, field+".call", "nil tool call", nil)
			}
			if err := validateToolCallForProtocol(protocol, *part.Call, field+".call", dl); err != nil {
				return err
			}
		default:
			return fail(ErrLossy, field+".kind", "response part is not representable", nil)
		}
	}
	if textCount > 1 && protocol == OpenAIChat {
		return fail(ErrLossy, "response.message.parts", "Chat Completions cannot preserve multiple text-part boundaries", nil)
	}
	if protocol == OpenAIResponses {
		if textCount > 0 {
			if err := validateID("response.message.id", response.Message.ID, true, dl); err != nil {
				return err
			}
		}
	} else if response.Message.ID != "" {
		return fail(ErrLossy, "response.message.id", "destination cannot preserve output item ID", nil)
	}
	if err := validateStopReason(protocol, response.StopReason, callCount > 0); err != nil {
		return err
	}
	return nil
}

func validateToolCallForProtocol(protocol Protocol, call ToolCall, field string, limits DecodeLimits) error {
	if err := validateToolName(field+".name", call.Name); err != nil {
		return err
	}
	if err := validateJSONObject(field+".arguments", call.Arguments, limits); err != nil {
		return err
	}
	switch protocol {
	case OpenAIResponses:
		if err := validateID(field+".id", call.ID, true, limits); err != nil {
			return err
		}
		if err := validateID(field+".item_id", call.ItemID, true, limits); err != nil {
			return err
		}
	case OpenAIChat, Anthropic:
		if err := validateID(field+".id", call.ID, true, limits); err != nil {
			return err
		}
		if call.ItemID != "" {
			return fail(ErrLossy, field+".item_id", "destination cannot preserve function item ID", nil)
		}
	case Gemini:
		if call.ID != "" || call.ItemID != "" {
			return fail(ErrLossy, field+".id", "Gemini function calls cannot preserve call IDs", nil)
		}
	}
	return nil
}

func encodeChatResponse(response Response) (any, error) {
	message := map[string]any{"role": "assistant", "content": nil}
	toolCalls := []any{}
	for _, part := range response.Message.Parts {
		if part.Kind == PartText {
			message["content"] = part.Text
			continue
		}
		call := part.Call
		toolCalls = append(toolCalls, map[string]any{"id": call.ID, "type": "function", "function": map[string]any{"name": call.Name, "arguments": string(call.Arguments)}})
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	result := map[string]any{"id": response.ID, "object": "chat.completion", "created": response.CreatedAt, "model": response.Model, "choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": chatStop(response.StopReason)}}}
	if response.ServiceTier != "" {
		result["service_tier"] = response.ServiceTier
	}
	if response.Usage != nil {
		result["usage"] = chatUsage(response.Usage)
	}
	return result, nil
}

func encodeResponsesResponse(response Response) (map[string]any, error) {
	output := []any{}
	content := []any{}
	for _, part := range response.Message.Parts {
		if part.Kind == PartText {
			content = append(content, map[string]any{"type": "output_text", "text": part.Text, "annotations": []any{}})
			continue
		}
		if len(content) > 0 {
			output = append(output, map[string]any{"type": "message", "id": response.Message.ID, "role": "assistant", "status": "completed", "content": content})
			content = nil
		}
		call := part.Call
		output = append(output, map[string]any{"type": "function_call", "id": call.ItemID, "call_id": call.ID, "name": call.Name, "arguments": string(call.Arguments), "status": "completed"})
	}
	if len(content) > 0 {
		output = append(output, map[string]any{"type": "message", "id": response.Message.ID, "role": "assistant", "status": "completed", "content": content})
	}
	status := "completed"
	result := map[string]any{"id": response.ID, "object": "response", "created_at": response.CreatedAt, "model": response.Model, "status": status, "output": output}
	if response.StopReason == StopMaxTokens || response.StopReason == StopContentFilter {
		result["status"] = "incomplete"
		reason := "max_output_tokens"
		if response.StopReason == StopContentFilter {
			reason = "content_filter"
		}
		result["incomplete_details"] = map[string]any{"reason": reason}
	}
	if response.ServiceTier != "" {
		result["service_tier"] = response.ServiceTier
	}
	if response.Usage != nil {
		result["usage"] = responseUsage(response.Usage)
	}
	return result, nil
}

func encodeAnthropicResponse(response Response) (any, error) {
	content := make([]any, 0, len(response.Message.Parts))
	for _, part := range response.Message.Parts {
		if part.Kind == PartText {
			content = append(content, map[string]any{"type": "text", "text": part.Text})
			continue
		}
		var input any
		if err := json.Unmarshal(part.Call.Arguments, &input); err != nil {
			return nil, err
		}
		content = append(content, map[string]any{"type": "tool_use", "id": part.Call.ID, "name": part.Call.Name, "input": input})
	}
	result := map[string]any{"id": response.ID, "type": "message", "role": "assistant", "model": response.Model, "content": content, "stop_reason": anthropicStop(response.StopReason), "stop_sequence": nil}
	if response.Usage != nil {
		result["usage"] = map[string]any{"input_tokens": response.Usage.InputTokens, "output_tokens": response.Usage.OutputTokens}
	}
	return result, nil
}

func encodeGeminiResponse(response Response) (any, error) {
	parts := make([]any, 0, len(response.Message.Parts))
	for _, part := range response.Message.Parts {
		if part.Kind == PartText {
			parts = append(parts, map[string]any{"text": part.Text})
			continue
		}
		var arguments any
		if err := json.Unmarshal(part.Call.Arguments, &arguments); err != nil {
			return nil, err
		}
		parts = append(parts, map[string]any{"functionCall": map[string]any{"name": part.Call.Name, "args": arguments}})
	}
	candidate := map[string]any{"index": 0, "content": map[string]any{"role": "model", "parts": parts}, "finishReason": geminiStop(response.StopReason)}
	result := map[string]any{"responseId": response.ID, "modelVersion": response.Model, "candidates": []any{candidate}}
	if response.Usage != nil {
		result["usageMetadata"] = map[string]any{"promptTokenCount": response.Usage.InputTokens, "candidatesTokenCount": response.Usage.OutputTokens, "totalTokenCount": response.Usage.TotalTokens}
	}
	return result, nil
}

func marshalBounded(value any, limits EncodeLimits) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fail(ErrValidation, "encode", "cannot encode protocol value", err)
	}
	if len(encoded) > limits.MaxOutputBytes {
		return nil, fail(ErrLimit, "encode.output", "encoded output exceeds byte limit", nil)
	}
	return encoded, nil
}

func chatUsage(usage *Usage) map[string]any {
	return map[string]any{"prompt_tokens": usage.InputTokens, "completion_tokens": usage.OutputTokens, "total_tokens": usage.TotalTokens}
}

func responseUsage(usage *Usage) map[string]any {
	return map[string]any{"input_tokens": usage.InputTokens, "output_tokens": usage.OutputTokens, "total_tokens": usage.TotalTokens}
}

func chatStop(reason StopReason) string {
	switch reason {
	case StopEndTurn:
		return "stop"
	case StopMaxTokens:
		return "length"
	case StopToolUse:
		return "tool_calls"
	default:
		return "content_filter"
	}
}

func anthropicStop(reason StopReason) string {
	switch reason {
	case StopEndTurn:
		return "end_turn"
	case StopMaxTokens:
		return "max_tokens"
	default:
		return "tool_use"
	}
}

func geminiStop(reason StopReason) string {
	switch reason {
	case StopMaxTokens:
		return "MAX_TOKENS"
	case StopContentFilter:
		return "SAFETY"
	default:
		return "STOP"
	}
}

func sseData(value any, limits EncodeLimits) ([]byte, error) {
	data, err := marshalBounded(value, limits)
	if err != nil {
		return nil, err
	}
	framed := make([]byte, 0, len(data)+8)
	framed = append(framed, "data: "...)
	framed = append(framed, data...)
	framed = append(framed, '\n', '\n')
	if len(framed) > limits.MaxOutputBytes {
		return nil, fail(ErrLimit, "encode.output", "encoded event exceeds byte limit", nil)
	}
	return framed, nil
}

func EncodeSSEEvent(protocol Protocol, event Event) ([]byte, error) {
	return EncodeSSEEventWithOptions(protocol, event, EncodeOptions{})
}

func EncodeSSEEventWithOptions(protocol Protocol, event Event, options EncodeOptions) ([]byte, error) {
	limits, err := normalizeEncodeLimits(options.Limits)
	if err != nil {
		return nil, err
	}
	if err := validateEventCommon(event, limits); err != nil {
		return nil, err
	}
	switch protocol {
	case OpenAIChat:
		return encodeChatEvent(event, limits)
	case OpenAIResponses:
		return encodeResponsesEvent(event, limits)
	case Anthropic:
		return encodeAnthropicEvent(event, limits)
	case Gemini:
		return encodeGeminiEvent(event, limits)
	default:
		return nil, fail(ErrUnsupported, "protocol", "unknown protocol", nil)
	}
}

func validateEventCommon(event Event, limits EncodeLimits) error {
	dl := limits.decodeLimits()
	if event.Index < 0 || event.ContentIndex < 0 || event.ChoiceIndex < 0 {
		return fail(ErrValidation, "event.index", "indices cannot be negative", nil)
	}
	if err := checkString("event.text", event.Text, false, dl); err != nil {
		return err
	}
	if err := checkString("event.delta", event.Delta, false, dl); err != nil {
		return err
	}
	if err := validateID("event.response_id", event.ResponseID, false, dl); err != nil {
		return err
	}
	if err := validateID("event.item_id", event.ItemID, false, dl); err != nil {
		return err
	}
	if err := checkString("event.model", event.Model, false, dl); err != nil {
		return err
	}
	if event.SequenceNumber != nil && *event.SequenceNumber < 0 {
		return fail(ErrValidation, "event.sequence_number", "cannot be negative", nil)
	}
	if err := validateUsage(event.Usage); err != nil {
		return err
	}
	if event.Kind == EventError {
		if event.Error == nil {
			return fail(ErrValidation, "event.error", "nil error", nil)
		}
		if _, err := publicError(event.Error, dl); err != nil {
			return err
		}
	} else if event.Error != nil {
		return fail(ErrValidation, "event.error", "is only valid for an error event", nil)
	}
	return nil
}

func requireEventIdentity(event Event, created bool, limits EncodeLimits) error {
	dl := limits.decodeLimits()
	if err := validateID("event.response_id", event.ResponseID, true, dl); err != nil {
		return err
	}
	if err := checkString("event.model", event.Model, true, dl); err != nil {
		return err
	}
	if created {
		if _, err := parseNonnegativeInteger("event.created_at", event.CreatedAt); err != nil {
			return err
		}
	}
	return nil
}

func requireSequence(event Event) (int64, error) {
	if event.SequenceNumber == nil {
		return 0, fail(ErrValidation, "event.sequence_number", "is required for Responses events", nil)
	}
	return *event.SequenceNumber, nil
}

func validateStreamCall(call *ToolCall, field string, limits EncodeLimits, requireItem bool, requireArguments bool) error {
	if call == nil {
		return fail(ErrValidation, field, "nil tool call", nil)
	}
	dl := limits.decodeLimits()
	if err := validateID(field+".id", call.ID, true, dl); err != nil {
		return err
	}
	if requireItem {
		if err := validateID(field+".item_id", call.ItemID, true, dl); err != nil {
			return err
		}
	}
	if err := validateToolName(field+".name", call.Name); err != nil {
		return err
	}
	if requireArguments {
		return validateJSONObject(field+".arguments", call.Arguments, dl)
	}
	if len(call.Arguments) != 0 {
		return fail(ErrValidation, field+".arguments", "must be empty on a start event", nil)
	}
	return nil
}

func encodeChatEvent(event Event, limits EncodeLimits) ([]byte, error) {
	if event.Kind == EventDone {
		if event.ResponseID != "" || event.Model != "" || event.Usage != nil {
			return nil, fail(ErrValidation, "event.done", "DONE cannot carry fields", nil)
		}
		return []byte("data: [DONE]\n\n"), nil
	}
	if event.Kind != EventError {
		if err := requireEventIdentity(event, true, limits); err != nil {
			return nil, err
		}
	}
	delta := map[string]any{}
	choice := map[string]any{"index": event.ChoiceIndex, "delta": delta, "finish_reason": nil}
	result := map[string]any{"id": event.ResponseID, "object": "chat.completion.chunk", "created": event.CreatedAt, "model": event.Model, "choices": []any{choice}}
	switch event.Kind {
	case EventStarted:
		delta["role"] = "assistant"
	case EventTextDelta:
		if event.Text == "" {
			return nil, fail(ErrValidation, "event.text", "text delta must not be empty", nil)
		}
		delta["content"] = event.Text
	case EventToolCallStart:
		if err := validateStreamCall(event.ToolCall, "event.tool_call", limits, false, false); err != nil {
			return nil, err
		}
		if event.ToolCall.ItemID != "" {
			return nil, fail(ErrLossy, "event.tool_call.item_id", "Chat Completions cannot preserve item ID", nil)
		}
		delta["tool_calls"] = []any{map[string]any{"index": event.Index, "id": event.ToolCall.ID, "type": "function", "function": map[string]any{"name": event.ToolCall.Name, "arguments": ""}}}
	case EventToolCallDelta:
		if event.Delta == "" {
			return nil, fail(ErrValidation, "event.delta", "argument delta must not be empty", nil)
		}
		if event.ToolCall != nil {
			return nil, fail(ErrValidation, "event.tool_call", "tool delta uses index and delta only", nil)
		}
		delta["tool_calls"] = []any{map[string]any{"index": event.Index, "function": map[string]any{"arguments": event.Delta}}}
	case EventCompleted:
		if err := validateStopReason(OpenAIChat, event.StopReason, event.StopReason == StopToolUse); err != nil {
			return nil, err
		}
		choice["finish_reason"] = chatStop(event.StopReason)
		if event.Usage != nil {
			result["usage"] = chatUsage(event.Usage)
		}
	case EventError:
		wire, err := errorValue(OpenAIChat, event.Error, limits.decodeLimits())
		if err != nil {
			return nil, err
		}
		return sseData(wire, limits)
	default:
		return nil, fail(ErrUnsupported, "event.kind", "event is not representable for Chat Completions", nil)
	}
	return sseData(result, limits)
}

func encodeResponsesEvent(event Event, limits EncodeLimits) ([]byte, error) {
	sequence, err := requireSequence(event)
	if err != nil {
		return nil, err
	}
	base := map[string]any{"sequence_number": sequence}
	setType := func(name string) { base["type"] = name }
	switch event.Kind {
	case EventStarted:
		response, err := responseEventObject(event, limits, false)
		if err != nil {
			return nil, err
		}
		setType("response.created")
		base["response"] = response
		return namedSSE("response.created", base, limits)
	case EventOutputItemStart:
		if err := validateID("event.item_id", event.ItemID, true, limits.decodeLimits()); err != nil {
			return nil, err
		}
		setType("response.output_item.added")
		base["output_index"] = event.Index
		base["item"] = map[string]any{"id": event.ItemID, "type": "message", "role": "assistant", "status": "in_progress", "content": []any{}}
		return namedSSE("response.output_item.added", base, limits)
	case EventTextStart:
		if err := validateID("event.item_id", event.ItemID, true, limits.decodeLimits()); err != nil {
			return nil, err
		}
		setType("response.content_part.added")
		base["item_id"] = event.ItemID
		base["output_index"] = event.Index
		base["content_index"] = event.ContentIndex
		base["part"] = map[string]any{"type": "output_text", "text": "", "annotations": []any{}}
		return namedSSE("response.content_part.added", base, limits)
	case EventTextDelta:
		if event.Text == "" {
			return nil, fail(ErrValidation, "event.text", "text delta must not be empty", nil)
		}
		if err := validateID("event.item_id", event.ItemID, true, limits.decodeLimits()); err != nil {
			return nil, err
		}
		setType("response.output_text.delta")
		base["item_id"] = event.ItemID
		base["output_index"] = event.Index
		base["content_index"] = event.ContentIndex
		base["delta"] = event.Text
		return namedSSE("response.output_text.delta", base, limits)
	case EventTextDone:
		if err := validateID("event.item_id", event.ItemID, true, limits.decodeLimits()); err != nil {
			return nil, err
		}
		setType("response.output_text.done")
		base["item_id"] = event.ItemID
		base["output_index"] = event.Index
		base["content_index"] = event.ContentIndex
		base["text"] = event.Text
		return namedSSE("response.output_text.done", base, limits)
	case EventContentPartDone:
		if err := validateID("event.item_id", event.ItemID, true, limits.decodeLimits()); err != nil {
			return nil, err
		}
		setType("response.content_part.done")
		base["item_id"] = event.ItemID
		base["output_index"] = event.Index
		base["content_index"] = event.ContentIndex
		base["part"] = map[string]any{"type": "output_text", "text": event.Text, "annotations": []any{}}
		return namedSSE("response.content_part.done", base, limits)
	case EventToolCallStart:
		if err := validateStreamCall(event.ToolCall, "event.tool_call", limits, true, false); err != nil {
			return nil, err
		}
		call := event.ToolCall
		setType("response.output_item.added")
		base["output_index"] = event.Index
		base["item"] = map[string]any{"id": call.ItemID, "type": "function_call", "call_id": call.ID, "name": call.Name, "arguments": "", "status": "in_progress"}
		return namedSSE("response.output_item.added", base, limits)
	case EventToolCallDelta:
		if event.Delta == "" {
			return nil, fail(ErrValidation, "event.delta", "argument delta must not be empty", nil)
		}
		if err := validateID("event.item_id", event.ItemID, true, limits.decodeLimits()); err != nil {
			return nil, err
		}
		setType("response.function_call_arguments.delta")
		base["item_id"] = event.ItemID
		base["output_index"] = event.Index
		base["delta"] = event.Delta
		return namedSSE("response.function_call_arguments.delta", base, limits)
	case EventToolCallDone:
		if err := validateStreamCall(event.ToolCall, "event.tool_call", limits, true, true); err != nil {
			return nil, err
		}
		setType("response.function_call_arguments.done")
		base["item_id"] = event.ToolCall.ItemID
		base["output_index"] = event.Index
		base["arguments"] = string(event.ToolCall.Arguments)
		return namedSSE("response.function_call_arguments.done", base, limits)
	case EventOutputItemDone:
		setType("response.output_item.done")
		base["output_index"] = event.Index
		if event.ToolCall != nil {
			if err := validateStreamCall(event.ToolCall, "event.tool_call", limits, true, true); err != nil {
				return nil, err
			}
			call := event.ToolCall
			base["item"] = map[string]any{"id": call.ItemID, "type": "function_call", "call_id": call.ID, "name": call.Name, "arguments": string(call.Arguments), "status": "completed"}
		} else {
			if err := validateID("event.item_id", event.ItemID, true, limits.decodeLimits()); err != nil {
				return nil, err
			}
			base["item"] = map[string]any{"id": event.ItemID, "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": event.Text, "annotations": []any{}}}}
		}
		return namedSSE("response.output_item.done", base, limits)
	case EventCompleted:
		response, err := responseEventObject(event, limits, true)
		if err != nil {
			return nil, err
		}
		setType("response.completed")
		base["response"] = response
		return namedSSE("response.completed", base, limits)
	case EventError:
		public, err := publicError(event.Error, limits.decodeLimits())
		if err != nil {
			return nil, err
		}
		code, _, _ := normalizePublicError(event.Error)
		setType("error")
		base["code"] = string(code)
		base["message"] = public
		base["param"] = nil
		return namedSSE("error", base, limits)
	default:
		return nil, fail(ErrUnsupported, "event.kind", "event is not representable for Responses", nil)
	}
}

func responseEventObject(event Event, limits EncodeLimits, completed bool) (map[string]any, error) {
	if event.Response == nil {
		return nil, fail(ErrValidation, "event.response", "is required", nil)
	}
	response := *event.Response
	if event.ResponseID != "" && event.ResponseID != response.ID {
		return nil, fail(ErrValidation, "event.response_id", "does not match response", nil)
	}
	if event.Model != "" && event.Model != response.Model {
		return nil, fail(ErrValidation, "event.model", "does not match response", nil)
	}
	if completed {
		if err := validateResponseForProtocol(OpenAIResponses, response, limits); err != nil {
			return nil, err
		}
		value, err := encodeResponsesResponse(response)
		if err != nil {
			return nil, err
		}
		return value, nil
	}
	dl := limits.decodeLimits()
	if err := validateID("event.response.id", response.ID, true, dl); err != nil {
		return nil, err
	}
	if err := checkString("event.response.model", response.Model, true, dl); err != nil {
		return nil, err
	}
	if _, err := parseNonnegativeInteger("event.response.created_at", response.CreatedAt); err != nil {
		return nil, err
	}
	if response.Usage != nil {
		return nil, fail(ErrValidation, "event.response.usage", "must be unknown on response.created", nil)
	}
	result := map[string]any{"id": response.ID, "object": "response", "created_at": response.CreatedAt, "model": response.Model, "status": "in_progress", "output": []any{}}
	if response.ServiceTier != "" {
		result["service_tier"] = response.ServiceTier
	}
	return result, nil
}

func encodeAnthropicEvent(event Event, limits EncodeLimits) ([]byte, error) {
	switch event.Kind {
	case EventStarted:
		if err := requireEventIdentity(event, false, limits); err != nil {
			return nil, err
		}
		message := map[string]any{"id": event.ResponseID, "type": "message", "role": "assistant", "content": []any{}, "model": event.Model, "stop_reason": nil, "stop_sequence": nil}
		if event.Usage != nil {
			message["usage"] = map[string]any{"input_tokens": event.Usage.InputTokens, "output_tokens": event.Usage.OutputTokens}
		}
		return namedSSE("message_start", map[string]any{"type": "message_start", "message": message}, limits)
	case EventTextStart:
		return namedSSE("content_block_start", map[string]any{"type": "content_block_start", "index": event.Index, "content_block": map[string]any{"type": "text", "text": ""}}, limits)
	case EventTextDelta:
		if event.Text == "" {
			return nil, fail(ErrValidation, "event.text", "text delta must not be empty", nil)
		}
		return namedSSE("content_block_delta", map[string]any{"type": "content_block_delta", "index": event.Index, "delta": map[string]any{"type": "text_delta", "text": event.Text}}, limits)
	case EventTextDone:
		if event.Text != "" {
			return nil, fail(ErrLossy, "event.text", "Anthropic block-stop cannot preserve completed text", nil)
		}
		return namedSSE("content_block_stop", map[string]any{"type": "content_block_stop", "index": event.Index}, limits)
	case EventToolCallStart:
		if err := validateStreamCall(event.ToolCall, "event.tool_call", limits, false, false); err != nil {
			return nil, err
		}
		if event.ToolCall.ItemID != "" {
			return nil, fail(ErrLossy, "event.tool_call.item_id", "Anthropic cannot preserve function item ID", nil)
		}
		block := map[string]any{"type": "tool_use", "id": event.ToolCall.ID, "name": event.ToolCall.Name, "input": map[string]any{}}
		return namedSSE("content_block_start", map[string]any{"type": "content_block_start", "index": event.Index, "content_block": block}, limits)
	case EventToolCallDelta:
		if event.Delta == "" {
			return nil, fail(ErrValidation, "event.delta", "input JSON delta must not be empty", nil)
		}
		if event.ToolCall != nil {
			return nil, fail(ErrValidation, "event.tool_call", "tool delta uses index and delta only", nil)
		}
		delta := map[string]any{"type": "input_json_delta", "partial_json": event.Delta}
		return namedSSE("content_block_delta", map[string]any{"type": "content_block_delta", "index": event.Index, "delta": delta}, limits)
	case EventToolCallDone:
		if event.ToolCall != nil || event.Delta != "" {
			return nil, fail(ErrLossy, "event.tool_call", "Anthropic block-stop carries only the block index", nil)
		}
		return namedSSE("content_block_stop", map[string]any{"type": "content_block_stop", "index": event.Index}, limits)
	case EventCompleted:
		if err := validateStopReason(Anthropic, event.StopReason, event.StopReason == StopToolUse); err != nil {
			return nil, err
		}
		body := map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": anthropicStop(event.StopReason), "stop_sequence": nil}}
		if event.Usage != nil {
			body["usage"] = map[string]any{"output_tokens": event.Usage.OutputTokens}
		}
		return namedSSE("message_delta", body, limits)
	case EventDone:
		if event.Usage != nil || event.ResponseID != "" || event.Model != "" {
			return nil, fail(ErrValidation, "event.done", "message_stop cannot carry extra fields", nil)
		}
		return namedSSE("message_stop", map[string]any{"type": "message_stop"}, limits)
	case EventError:
		public, err := publicError(event.Error, limits.decodeLimits())
		if err != nil {
			return nil, err
		}
		errorType := anthropicErrorType(event.Error)
		return namedSSE("error", map[string]any{"type": "error", "error": map[string]any{"type": errorType, "message": public}}, limits)
	default:
		return nil, fail(ErrUnsupported, "event.kind", "event is not representable for Anthropic", nil)
	}
}

func encodeGeminiEvent(event Event, limits EncodeLimits) ([]byte, error) {
	if event.Kind == EventError {
		wire, err := errorValue(Gemini, event.Error, limits.decodeLimits())
		if err != nil {
			return nil, err
		}
		return sseData(wire, limits)
	}
	if err := requireEventIdentity(event, false, limits); err != nil {
		return nil, err
	}
	if event.CreatedAt != "" {
		return nil, fail(ErrLossy, "event.created_at", "Gemini cannot preserve created_at", nil)
	}
	content := map[string]any{"role": "model", "parts": []any{}}
	candidate := map[string]any{"index": event.Index, "content": content}
	result := map[string]any{"responseId": event.ResponseID, "modelVersion": event.Model, "candidates": []any{candidate}}
	switch event.Kind {
	case EventTextDelta:
		if event.Text == "" {
			return nil, fail(ErrValidation, "event.text", "text delta must not be empty", nil)
		}
		content["parts"] = []any{map[string]any{"text": event.Text}}
	case EventToolCallDone:
		if event.ToolCall == nil {
			return nil, fail(ErrValidation, "event.tool_call", "nil tool call", nil)
		}
		if err := validateToolCallForProtocol(Gemini, *event.ToolCall, "event.tool_call", limits.decodeLimits()); err != nil {
			return nil, err
		}
		var arguments any
		if err := json.Unmarshal(event.ToolCall.Arguments, &arguments); err != nil {
			return nil, err
		}
		content["parts"] = []any{map[string]any{"functionCall": map[string]any{"name": event.ToolCall.Name, "args": arguments}}}
	case EventCompleted:
		if err := validateStopReason(Gemini, event.StopReason, event.StopReason == StopToolUse); err != nil {
			return nil, err
		}
		candidate["finishReason"] = geminiStop(event.StopReason)
		delete(candidate, "content")
		if event.Usage != nil {
			result["usageMetadata"] = map[string]any{"promptTokenCount": event.Usage.InputTokens, "candidatesTokenCount": event.Usage.OutputTokens, "totalTokenCount": event.Usage.TotalTokens}
		}
	default:
		return nil, fail(ErrUnsupported, "event.kind", "event is not representable for Gemini streamGenerateContent", nil)
	}
	return sseData(result, limits)
}

func namedSSE(name string, value any, limits EncodeLimits) ([]byte, error) {
	data, err := marshalBounded(value, limits)
	if err != nil {
		return nil, err
	}
	framed := make([]byte, 0, len(name)+len(data)+17)
	framed = append(framed, "event: "...)
	framed = append(framed, name...)
	framed = append(framed, '\n')
	framed = append(framed, "data: "...)
	framed = append(framed, data...)
	framed = append(framed, '\n', '\n')
	if len(framed) > limits.MaxOutputBytes {
		return nil, fail(ErrLimit, "encode.output", "encoded event exceeds byte limit", nil)
	}
	return framed, nil
}
