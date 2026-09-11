package cloudflarebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/cloudflareprotocol"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// geminiGatewayForwarder deliberately adapts Gemini only to the already
// admitted OpenAI Responses vertical slice. It neither selects accounts nor
// retries them: those decisions remain authoritative in the Worker.
type geminiGatewayForwarder struct{ responses *service.OpenAIGatewayService }

func newGeminiGatewayForwarder(responses *service.OpenAIGatewayService) *geminiGatewayForwarder {
	return &geminiGatewayForwarder{responses: responses}
}

type geminiGatewayRequest struct {
	model  string
	stream bool
}

func parseGeminiGatewayRequest(c *gin.Context, body []byte) (geminiGatewayRequest, error) {
	if c == nil {
		return geminiGatewayRequest{}, errors.New("request context is required")
	}
	rawPath := strings.TrimSpace(c.Param("modelAction"))
	model, action, ok := strings.Cut(rawPath, ":")
	if !ok || model == "" || action == "" || strings.Contains(model, "/") || !service.IsSafeGeminiModelPathSegment(model) {
		return geminiGatewayRequest{}, errors.New("invalid Gemini model action path")
	}

	query := c.Request.URL.Query()
	stream := action == "streamGenerateContent"
	switch action {
	case "generateContent":
		if len(query) != 0 {
			return geminiGatewayRequest{}, errors.New("generateContent does not accept query parameters")
		}
	case "streamGenerateContent":
		if len(query) != 1 || query.Get("alt") != "sse" || len(query["alt"]) != 1 {
			return geminiGatewayRequest{}, errors.New("streamGenerateContent requires exactly alt=sse")
		}
	default:
		return geminiGatewayRequest{}, errors.New("unsupported Gemini action")
	}
	if _, err := cloudflareprotocol.DecodeRequestWithOptions(cloudflareprotocol.Gemini, body, cloudflareprotocol.DecodeOptions{Model: model}); err != nil {
		return geminiGatewayRequest{}, fmt.Errorf("invalid Gemini request: %w", err)
	}
	return geminiGatewayRequest{model: model, stream: stream}, nil
}

func (f *geminiGatewayForwarder) Forward(ctx context.Context, c *gin.Context, account *service.Account, body []byte, model, mappedModel string) (*service.OpenAIForwardResult, error) {
	if f == nil || f.responses == nil {
		return nil, errors.New("gemini gateway forwarder is unavailable")
	}
	request, err := cloudflareprotocol.DecodeRequestWithOptions(cloudflareprotocol.Gemini, body, cloudflareprotocol.DecodeOptions{Model: model})
	if err != nil {
		return nil, err
	}
	stream := strings.HasSuffix(c.Request.URL.Path, ":streamGenerateContent")
	// Responses streaming supplies the only complete, incremental usage signal
	// available to this bounded bridge. Non-streaming Gemini requests are still
	// buffered and returned as a single Gemini JSON document below.
	encoded, err := encodeGeminiAsResponsesRequest(request, true)
	if err != nil {
		return nil, err
	}

	originalWriter := c.Writer
	originalRequest := c.Request
	// The mature Responses forwarder derives its egress protocol from the
	// request path. Keep Gemini ingress out of that decision without changing
	// the request context, headers, or the public route seen by the bridge.
	forwardRequest := c.Request.Clone(ctx)
	forwardRequest.URL.Path = "/v1/responses"
	forwardRequest.URL.RawPath = ""
	c.Request = forwardRequest
	defer func() { c.Request = originalRequest }()
	capture := newDeferredResponseWriter(originalWriter)
	c.Writer = capture
	result, err := f.responses.ForwardCloudflareResponses(ctx, c, account, encoded, model, mappedModel)
	c.Writer = originalWriter
	if err != nil {
		return result, err
	}
	if stream {
		err = writeGeminiStream(ctx, c, capture.body.Bytes())
	} else {
		err = writeGeminiResponse(c, capture.body.Bytes())
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

func encodeGeminiAsResponsesRequest(request cloudflareprotocol.Request, stream bool) ([]byte, error) {
	if len(request.StopSequences) != 0 {
		return nil, errors.New("gemini generationConfig.stopSequences is not supported by the Cloudflare Responses bridge")
	}
	input := make([]any, 0, len(request.Messages))
	for _, message := range request.Messages {
		role := string(message.Role)
		switch message.Role {
		case cloudflareprotocol.RoleAssistant:
			role = "assistant"
		case cloudflareprotocol.RoleSystem, cloudflareprotocol.RoleDeveloper, cloudflareprotocol.RoleUser:
		default:
			return nil, fmt.Errorf("gemini message role %q is not supported", message.Role)
		}
		content := make([]any, 0, len(message.Parts))
		for _, part := range message.Parts {
			switch part.Kind {
			case cloudflareprotocol.PartText:
				typ := "input_text"
				if message.Role == cloudflareprotocol.RoleAssistant {
					typ = "output_text"
				}
				content = append(content, map[string]any{"type": typ, "text": part.Text})
			case cloudflareprotocol.PartToolResult:
				if part.Result == nil || len(part.Result.Content) != 1 || part.Result.Content[0].Kind != cloudflareprotocol.PartText {
					return nil, errors.New("Gemini functionResponse is not representable by the Cloudflare Responses bridge")
				}
				input = append(input, map[string]any{"type": "function_call_output", "call_id": part.Result.CallID, "output": part.Result.Content[0].Text})
			case cloudflareprotocol.PartMediaRef, cloudflareprotocol.PartToolCall:
				return nil, fmt.Errorf("Gemini %s parts are not supported by the Cloudflare Responses bridge", part.Kind)
			default:
				return nil, fmt.Errorf("Gemini %s parts are not supported", part.Kind)
			}
		}
		if len(content) != 0 {
			input = append(input, map[string]any{"role": role, "content": content})
		}
	}
	value := map[string]any{"model": request.Model, "input": input, "stream": stream}
	if request.MaxOutputTokens != "" {
		value["max_output_tokens"] = request.MaxOutputTokens
	}
	if len(request.Tools) != 0 {
		tools := make([]any, 0, len(request.Tools))
		for _, tool := range request.Tools {
			tools = append(tools, map[string]any{"type": "function", "name": tool.Name, "description": tool.Description, "parameters": json.RawMessage(tool.Schema)})
		}
		value["tools"] = tools
	}
	switch request.ToolChoice.Mode {
	case "", "auto", "none":
		if request.ToolChoice.Mode != "" {
			value["tool_choice"] = request.ToolChoice.Mode
		}
	case "required":
		value["tool_choice"] = "required"
	case "named":
		value["tool_choice"] = map[string]any{"type": "function", "name": request.ToolChoice.Name}
	default:
		return nil, fmt.Errorf("Gemini tool choice %q is not supported", request.ToolChoice.Mode)
	}
	return json.Marshal(value)
}

func writeGeminiResponse(c *gin.Context, body []byte) error {
	response, err := decodeOpenAIResponseOrStream(c.Request.Context(), body)
	if err != nil {
		return err
	}
	encoded, err := cloudflareprotocol.EncodeResponse(cloudflareprotocol.Gemini, response)
	if err != nil {
		return err
	}
	c.Header("Content-Type", "application/json")
	c.Status(http.StatusOK)
	_, err = c.Writer.Write(encoded)
	return err
}

func decodeOpenAIResponseOrStream(ctx context.Context, body []byte) (cloudflareprotocol.Response, error) {
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("data:")) {
		return decodeOpenAIResponse(body)
	}
	var final *cloudflareprotocol.Response
	err := cloudflareprotocol.ParseSSE(ctx, bytes.NewReader(body), cloudflareprotocol.SSELimits{}, func(frame cloudflareprotocol.SSEFrame) error {
		if bytes.Equal(frame.Data, []byte("[DONE]")) || gjson.GetBytes(frame.Data, "type").String() != "response.completed" {
			return nil
		}
		response, err := decodeOpenAIResponse([]byte(gjson.GetBytes(frame.Data, "response").Raw))
		if err != nil {
			return err
		}
		final = &response
		return nil
	})
	if err != nil {
		return cloudflareprotocol.Response{}, err
	}
	if final == nil {
		return cloudflareprotocol.Response{}, errors.New("upstream stream completed without a response")
	}
	return *final, nil
}

func writeGeminiStream(ctx context.Context, c *gin.Context, body []byte) error {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	var responseID, model string
	var emittedText bool
	return cloudflareprotocol.ParseSSE(ctx, bytes.NewReader(body), cloudflareprotocol.SSELimits{}, func(frame cloudflareprotocol.SSEFrame) error {
		if bytes.Equal(frame.Data, []byte("[DONE]")) {
			return nil
		}
		value := gjson.ParseBytes(frame.Data)
		if !value.IsObject() {
			return errors.New("invalid upstream stream event")
		}
		switch value.Get("type").String() {
		case "response.created":
			responseID = value.Get("response.id").String()
			model = value.Get("response.model").String()
			return nil
		case "response.output_text.delta":
			if responseID == "" || model == "" {
				return errors.New("upstream stream emitted text before response identity")
			}
			text := value.Get("delta").String()
			if text == "" {
				return errors.New("upstream stream emitted an empty text delta")
			}
			encoded, err := cloudflareprotocol.EncodeSSEEvent(cloudflareprotocol.Gemini, cloudflareprotocol.Event{Kind: cloudflareprotocol.EventTextDelta, ResponseID: responseID, Model: model, Text: text})
			if err != nil {
				return err
			}
			emittedText = true
			_, err = c.Writer.Write(encoded)
			return err
		case "response.completed":
			response, err := decodeOpenAIResponse([]byte(value.Get("response").Raw))
			if err != nil {
				return err
			}
			if !emittedText {
				for _, part := range response.Message.Parts {
					if part.Kind != cloudflareprotocol.PartText {
						return errors.New("upstream function calls are not representable by Gemini")
					}
					encoded, err := cloudflareprotocol.EncodeSSEEvent(cloudflareprotocol.Gemini, cloudflareprotocol.Event{Kind: cloudflareprotocol.EventTextDelta, ResponseID: response.ID, Model: response.Model, Text: part.Text})
					if err != nil {
						return err
					}
					if _, err := c.Writer.Write(encoded); err != nil {
						return err
					}
				}
			}
			encoded, err := cloudflareprotocol.EncodeSSEEvent(cloudflareprotocol.Gemini, cloudflareprotocol.Event{Kind: cloudflareprotocol.EventCompleted, ResponseID: response.ID, Model: response.Model, StopReason: response.StopReason, Usage: response.Usage})
			if err != nil {
				return err
			}
			_, err = c.Writer.Write(encoded)
			return err
		}
		return nil
	})
}

func decodeOpenAIResponse(body []byte) (cloudflareprotocol.Response, error) {
	var wire struct {
		ID        string      `json:"id"`
		Model     string      `json:"model"`
		CreatedAt json.Number `json:"created_at"`
		Status    string      `json:"status"`
		Output    []struct {
			Type      string `json:"type"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
			Content   []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
		Usage *struct {
			Input  json.Number `json:"input_tokens"`
			Output json.Number `json:"output_tokens"`
			Total  json.Number `json:"total_tokens"`
		} `json:"usage"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		return cloudflareprotocol.Response{}, errors.New("invalid upstream response")
	}
	if wire.ID == "" || wire.Model == "" || wire.Status != "completed" || len(wire.Output) == 0 {
		return cloudflareprotocol.Response{}, errors.New("upstream response is incomplete")
	}
	response := cloudflareprotocol.Response{ID: wire.ID, CreatedAt: wire.CreatedAt, Model: wire.Model, Message: cloudflareprotocol.Message{Role: cloudflareprotocol.RoleAssistant}, StopReason: cloudflareprotocol.StopEndTurn}
	for _, item := range wire.Output {
		switch item.Type {
		case "message":
			for _, part := range item.Content {
				if part.Type != "output_text" || part.Text == "" {
					return cloudflareprotocol.Response{}, errors.New("upstream response contains an unsupported output part")
				}
				response.Message.Parts = append(response.Message.Parts, cloudflareprotocol.Part{Kind: cloudflareprotocol.PartText, Text: part.Text})
			}
		case "function_call":
			return cloudflareprotocol.Response{}, errors.New("upstream function calls are not representable by Gemini")
		default:
			return cloudflareprotocol.Response{}, errors.New("upstream response contains an unsupported output item")
		}
	}
	if len(response.Message.Parts) == 0 {
		return cloudflareprotocol.Response{}, errors.New("upstream response has no text output")
	}
	if wire.Usage != nil {
		response.Usage = &cloudflareprotocol.Usage{InputTokens: wire.Usage.Input, OutputTokens: wire.Usage.Output, TotalTokens: wire.Usage.Total}
	}
	return response, nil
}
