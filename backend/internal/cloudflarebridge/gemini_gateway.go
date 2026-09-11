package cloudflarebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

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

const geminiStreamPendingFrameLimit = 64 << 10

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
	if err := rejectUnsupportedGeminiBridgeFeatures(body); err != nil {
		return geminiGatewayRequest{}, err
	}
	if _, err := cloudflareprotocol.DecodeRequestWithOptions(cloudflareprotocol.Gemini, body, cloudflareprotocol.DecodeOptions{Model: model}); err != nil {
		return geminiGatewayRequest{}, fmt.Errorf("invalid Gemini request: %w", err)
	}
	return geminiGatewayRequest{model: model, stream: stream}, nil
}

func rejectUnsupportedGeminiBridgeFeatures(body []byte) error {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		// The strict protocol decoder below owns malformed-request reporting.
		return nil
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if _, exists := root["tools"]; exists {
		return errors.New("gemini tools are not supported by the Cloudflare Responses bridge")
	}
	if _, exists := root["toolConfig"]; exists {
		return errors.New("gemini toolConfig is not supported by the Cloudflare Responses bridge")
	}
	for _, field := range [...]string{"systemInstruction", "contents"} {
		if jsonValueContainsKey(root[field], "functionCall") {
			return errors.New("gemini functionCall is not supported by the Cloudflare Responses bridge")
		}
		if jsonValueContainsKey(root[field], "functionResponse") {
			return errors.New("gemini functionResponse is not supported by the Cloudflare Responses bridge")
		}
	}
	return nil
}

func jsonValueContainsKey(value any, key string) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if jsonValueContainsKey(item, key) {
				return true
			}
		}
	case map[string]any:
		if _, exists := typed[key]; exists {
			return true
		}
		for _, item := range typed {
			if jsonValueContainsKey(item, key) {
				return true
			}
		}
	}
	return false
}

func (f *geminiGatewayForwarder) Forward(ctx context.Context, c *gin.Context, account *service.Account, body []byte, model, mappedModel string) (*service.OpenAIForwardResult, error) {
	if f == nil || f.responses == nil {
		return nil, errors.New("gemini gateway forwarder is unavailable")
	}
	if c == nil || c.Request == nil {
		return nil, errors.New("gemini request context is required")
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
	forwardCtx := ctx
	cancelForward := func(error) {}
	if stream {
		var cancel context.CancelCauseFunc
		forwardCtx, cancel = context.WithCancelCause(ctx)
		cancelForward = cancel
		defer cancel(nil)
	}
	forwardRequest := c.Request.Clone(forwardCtx)
	forwardRequest.URL.Path = "/v1/responses"
	forwardRequest.URL.RawPath = ""
	c.Request = forwardRequest
	defer func() {
		c.Request = originalRequest
		c.Writer = originalWriter
	}()
	if stream {
		relay := newGeminiStreamResponseWriter(originalWriter, forwardCtx, cancelForward)
		c.Writer = relay
		startedAt := time.Now()
		result, forwardErr := f.responses.ForwardCloudflareResponses(forwardCtx, c, account, encoded, model, mappedModel)
		result = mergeGeminiTerminalUsage(result, relay.terminalUsage, model, mappedModel, time.Since(startedAt))
		finishErr := relay.finish()
		if forwardErr != nil {
			return result, forwardErr
		}
		if finishErr != nil {
			return result, finishErr
		}
		return result, nil
	}
	capture := newDeferredResponseWriter(originalWriter)
	c.Writer = capture
	startedAt := time.Now()
	result, err := f.responses.ForwardCloudflareResponses(ctx, c, account, encoded, model, mappedModel)
	c.Writer = originalWriter
	result = mergeGeminiTerminalUsage(result, extractGeminiTerminalUsage(ctx, capture.body.Bytes()), model, mappedModel, time.Since(startedAt))
	if err != nil {
		if status, ok := extractGeminiTerminalStatus(ctx, capture.body.Bytes()); ok {
			if writeErr := writeGeminiTerminalErrorResponse(c, status); writeErr != nil {
				return result, errors.Join(err, writeErr)
			}
		}
		return result, err
	}
	err = writeGeminiResponse(c, capture.body.Bytes())
	if err != nil {
		if status, ok := extractGeminiTerminalStatus(ctx, capture.body.Bytes()); ok {
			if writeErr := writeGeminiTerminalErrorResponse(c, status); writeErr != nil {
				return result, errors.Join(err, writeErr)
			}
		}
		return result, err
	}
	return result, nil
}

func encodeGeminiAsResponsesRequest(request cloudflareprotocol.Request, stream bool) ([]byte, error) {
	if len(request.StopSequences) != 0 {
		return nil, errors.New("gemini generationConfig.stopSequences is not supported by the Cloudflare Responses bridge")
	}
	if len(request.Tools) != 0 || request.ToolChoice.Mode != "" {
		return nil, errors.New("gemini tools are not supported by the Cloudflare Responses bridge")
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
			case cloudflareprotocol.PartToolResult, cloudflareprotocol.PartToolCall:
				return nil, fmt.Errorf("gemini %s parts are not supported by the Cloudflare Responses bridge", part.Kind)
			case cloudflareprotocol.PartMediaRef:
				return nil, fmt.Errorf("gemini %s parts are not supported by the Cloudflare Responses bridge", part.Kind)
			default:
				return nil, fmt.Errorf("gemini %s parts are not supported", part.Kind)
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
	trimmed := bytes.TrimSpace(body)
	if !bytes.HasPrefix(trimmed, []byte("data:")) && !bytes.HasPrefix(trimmed, []byte("event:")) {
		return decodeOpenAIResponse(body)
	}
	var final *cloudflareprotocol.Response
	var text strings.Builder
	terminalSeen := false
	err := cloudflareprotocol.ParseSSE(ctx, bytes.NewReader(body), cloudflareprotocol.SSELimits{}, func(frame cloudflareprotocol.SSEFrame) error {
		if bytes.Equal(bytes.TrimSpace(frame.Data), []byte("[DONE]")) {
			return nil
		}
		eventType := openAIResponseEventType(frame)
		if eventType == "response.output_text.delta" {
			delta := gjson.GetBytes(frame.Data, "delta")
			if delta.Type != gjson.String || delta.String() == "" {
				return errors.New("upstream stream emitted an empty text delta")
			}
			_, _ = text.WriteString(delta.String())
			return nil
		}
		if !isOpenAIResponseTerminalEvent(eventType) {
			return nil
		}
		if terminalSeen {
			return errors.New("upstream stream emitted more than one terminal response")
		}
		terminalSeen = true
		response, status, err := decodeOpenAITerminalEvent(frame.Data, eventType)
		if err != nil {
			return err
		}
		switch status {
		case "completed", "incomplete":
			if len(response.Message.Parts) == 0 && text.Len() != 0 {
				response.Message.Parts = []cloudflareprotocol.Part{{Kind: cloudflareprotocol.PartText, Text: text.String()}}
			}
			if len(response.Message.Parts) == 0 {
				return errors.New("upstream response has no text output")
			}
			final = &response
		case "failed":
			return errors.New("upstream response failed")
		case "cancelled":
			return errors.New("upstream response was cancelled")
		}
		return nil
	})
	if err != nil {
		return cloudflareprotocol.Response{}, err
	}
	if !terminalSeen || final == nil {
		return cloudflareprotocol.Response{}, errors.New("upstream stream ended without a terminal response")
	}
	return *final, nil
}

type geminiStreamResponseWriter struct {
	gin.ResponseWriter
	ctx           context.Context
	cancel        func(error)
	header        http.Header
	status        int
	pending       []byte
	stickyErr     error
	terminalErr   error
	terminalUsage *cloudflareprotocol.Usage
	responseID    string
	model         string
	emittedText   bool
	terminalSeen  bool
	wrote         bool
}

func newGeminiStreamResponseWriter(parent gin.ResponseWriter, ctx context.Context, cancel func(error)) *geminiStreamResponseWriter {
	return &geminiStreamResponseWriter{
		ResponseWriter: parent,
		ctx:            ctx,
		cancel:         cancel,
		header:         make(http.Header),
		status:         http.StatusOK,
		pending:        make([]byte, 0, 4096),
	}
}

func (w *geminiStreamResponseWriter) Header() http.Header { return w.header }

func (w *geminiStreamResponseWriter) WriteHeader(status int) {
	if w.status == http.StatusOK {
		w.status = status
	}
}

func (w *geminiStreamResponseWriter) WriteHeaderNow() {}

func (w *geminiStreamResponseWriter) Write(data []byte) (int, error) {
	if w.stickyErr != nil {
		return 0, w.stickyErr
	}
	if err := context.Cause(w.ctx); err != nil {
		return 0, w.fail(err)
	}
	w.pending = append(w.pending, data...)
	for {
		end := nextSSEFrameEnd(w.pending)
		if end == 0 {
			break
		}
		if end > geminiStreamPendingFrameLimit {
			return 0, w.fail(errors.New("upstream SSE frame exceeds the Gemini bridge limit"))
		}
		frame := append([]byte(nil), w.pending[:end]...)
		w.pending = append(w.pending[:0], w.pending[end:]...)
		if err := w.processFrame(frame); err != nil {
			return 0, w.fail(err)
		}
	}
	if len(w.pending) > geminiStreamPendingFrameLimit {
		return 0, w.fail(errors.New("unfinished upstream SSE frame exceeds the Gemini bridge limit"))
	}
	return len(data), nil
}

func (w *geminiStreamResponseWriter) WriteString(value string) (int, error) {
	return w.Write([]byte(value))
}

func (w *geminiStreamResponseWriter) Flush() {
	if w.wrote {
		w.ResponseWriter.Flush()
	}
}

func (w *geminiStreamResponseWriter) finish() error {
	if w.stickyErr != nil {
		return w.stickyErr
	}
	if err := context.Cause(w.ctx); err != nil && !w.terminalSeen {
		return w.fail(err)
	}
	if len(bytes.TrimSpace(w.pending)) != 0 {
		return w.fail(errors.New("upstream stream ended with an incomplete SSE frame"))
	}
	if !w.terminalSeen {
		return w.fail(errors.New("upstream stream ended without a terminal response"))
	}
	return w.terminalErr
}

func (w *geminiStreamResponseWriter) fail(err error) error {
	if err == nil {
		err = errors.New("gemini stream relay failed")
	}
	if w.stickyErr == nil {
		w.stickyErr = err
		w.cancel(err)
	}
	return w.stickyErr
}

func (w *geminiStreamResponseWriter) processFrame(encoded []byte) error {
	return cloudflareprotocol.ParseSSE(w.ctx, bytes.NewReader(encoded), cloudflareprotocol.SSELimits{
		MaxLineBytes:  geminiStreamPendingFrameLimit,
		MaxEventBytes: geminiStreamPendingFrameLimit,
		MaxEvents:     1,
	}, w.processEvent)
}

func (w *geminiStreamResponseWriter) processEvent(frame cloudflareprotocol.SSEFrame) error {
	if bytes.Equal(bytes.TrimSpace(frame.Data), []byte("[DONE]")) {
		return nil
	}
	value := gjson.ParseBytes(frame.Data)
	if !value.IsObject() {
		return errors.New("invalid upstream stream event")
	}
	eventType := openAIResponseEventType(frame)
	if w.terminalSeen {
		return errors.New("upstream stream emitted data after its terminal response")
	}
	switch eventType {
	case "response.created", "response.in_progress", "response.queued":
		if id := strings.TrimSpace(value.Get("response.id").String()); id != "" {
			w.responseID = id
		}
		if model := strings.TrimSpace(value.Get("response.model").String()); model != "" {
			w.model = model
		}
		return nil
	case "response.output_text.delta":
		if w.responseID == "" || w.model == "" {
			return errors.New("upstream stream emitted text before response identity")
		}
		delta := value.Get("delta")
		if delta.Type != gjson.String || delta.String() == "" {
			return errors.New("upstream stream emitted an empty text delta")
		}
		encoded, err := cloudflareprotocol.EncodeSSEEvent(cloudflareprotocol.Gemini, cloudflareprotocol.Event{Kind: cloudflareprotocol.EventTextDelta, ResponseID: w.responseID, Model: w.model, Text: delta.String()})
		if err != nil {
			return err
		}
		if err := w.emit(encoded); err != nil {
			return err
		}
		w.emittedText = true
		return nil
	case "error":
		w.terminalSeen = true
		w.terminalErr = errors.New("upstream response failed")
		return w.emitGeminiError(cloudflareprotocol.UpstreamError(http.StatusBadGateway, false, false, ""))
	case "response.completed", "response.done", "response.incomplete", "response.failed", "response.cancelled", "response.canceled":
		return w.processTerminal(frame.Data, eventType)
	default:
		if strings.Contains(eventType, "function_call") {
			return errors.New("upstream function calls are not representable by Gemini")
		}
		return nil
	}
}

func (w *geminiStreamResponseWriter) processTerminal(data []byte, eventType string) error {
	response, status, err := decodeOpenAITerminalEvent(data, eventType)
	if err != nil {
		return err
	}
	w.terminalSeen = true
	w.terminalUsage = response.Usage
	if response.ID == "" {
		response.ID = w.responseID
	}
	if response.Model == "" {
		response.Model = w.model
	}
	switch status {
	case "failed":
		w.terminalErr = errors.New("upstream response failed")
		return w.emitGeminiError(cloudflareprotocol.UpstreamError(http.StatusBadGateway, false, w.wrote, ""))
	case "cancelled":
		w.terminalErr = errors.New("upstream response was cancelled")
		return w.emitGeminiError(&cloudflareprotocol.Error{Code: cloudflareprotocol.ErrCancelled, Message: "upstream response was cancelled", HTTPStatus: 499})
	case "completed", "incomplete":
		if response.ID == "" || response.Model == "" {
			return errors.New("terminal upstream response has no identity")
		}
		if !w.emittedText {
			if len(response.Message.Parts) == 0 {
				return errors.New("upstream response has no text output")
			}
			for _, part := range response.Message.Parts {
				encoded, encodeErr := cloudflareprotocol.EncodeSSEEvent(cloudflareprotocol.Gemini, cloudflareprotocol.Event{Kind: cloudflareprotocol.EventTextDelta, ResponseID: response.ID, Model: response.Model, Text: part.Text})
				if encodeErr != nil {
					return encodeErr
				}
				if emitErr := w.emit(encoded); emitErr != nil {
					return emitErr
				}
			}
		}
		encoded, encodeErr := cloudflareprotocol.EncodeSSEEvent(cloudflareprotocol.Gemini, cloudflareprotocol.Event{Kind: cloudflareprotocol.EventCompleted, ResponseID: response.ID, Model: response.Model, StopReason: response.StopReason, Usage: response.Usage})
		if encodeErr != nil {
			return encodeErr
		}
		return w.emit(encoded)
	default:
		return errors.New("unsupported upstream terminal status")
	}
}

func (w *geminiStreamResponseWriter) emitGeminiError(protocolErr *cloudflareprotocol.Error) error {
	encoded, err := cloudflareprotocol.EncodeSSEEvent(cloudflareprotocol.Gemini, cloudflareprotocol.Event{Kind: cloudflareprotocol.EventError, Error: protocolErr})
	if err != nil {
		return err
	}
	return w.emit(encoded)
}

func (w *geminiStreamResponseWriter) emit(encoded []byte) error {
	if err := context.Cause(w.ctx); err != nil {
		return err
	}
	if !w.wrote {
		headers := w.ResponseWriter.Header()
		headers.Set("Content-Type", "text/event-stream")
		headers.Set("Cache-Control", "no-cache")
		headers.Set("X-Accel-Buffering", "no")
		if requestID := strings.TrimSpace(w.header.Get("X-Request-Id")); requestID != "" {
			headers.Set("X-Request-Id", requestID)
		}
		w.ResponseWriter.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(encoded)
	if err != nil {
		return err
	}
	if n != len(encoded) {
		return io.ErrShortWrite
	}
	w.wrote = true
	w.ResponseWriter.Flush()
	return context.Cause(w.ctx)
}

func nextSSEFrameEnd(data []byte) int {
	lineStart := 0
	for i, character := range data {
		if character != '\n' {
			continue
		}
		line := data[lineStart:i]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			return i + 1
		}
		lineStart = i + 1
	}
	return 0
}

func openAIResponseEventType(frame cloudflareprotocol.SSEFrame) string {
	eventType := strings.TrimSpace(gjson.GetBytes(frame.Data, "type").String())
	if eventType == "" {
		eventType = strings.TrimSpace(frame.Event)
	}
	return eventType
}

func isOpenAIResponseTerminalEvent(eventType string) bool {
	switch strings.TrimSpace(eventType) {
	case "response.completed", "response.done", "response.incomplete", "response.failed", "response.cancelled", "response.canceled", "error":
		return true
	default:
		return false
	}
}

type openAIResponseWire struct {
	ID        string          `json:"id"`
	Model     string          `json:"model"`
	CreatedAt json.Number     `json:"created_at"`
	Status    string          `json:"status"`
	Output    []openAIOutput  `json:"output"`
	Usage     json.RawMessage `json:"usage"`
}

type openAIOutput struct {
	Type    string `json:"type"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func decodeOpenAITerminalEvent(data []byte, eventType string) (cloudflareprotocol.Response, string, error) {
	payload := data
	if nested := gjson.GetBytes(data, "response"); nested.IsObject() {
		payload = []byte(nested.Raw)
	}
	var wire openAIResponseWire
	if err := json.Unmarshal(payload, &wire); err != nil {
		return cloudflareprotocol.Response{}, "", errors.New("invalid upstream terminal response")
	}
	status, err := normalizedOpenAITerminalStatus(eventType, wire.Status)
	if err != nil {
		return cloudflareprotocol.Response{}, "", err
	}
	usage, err := decodeOpenAIUsage(wire.Usage)
	if err != nil {
		return cloudflareprotocol.Response{}, "", err
	}
	stopReason := cloudflareprotocol.StopEndTurn
	if status == "incomplete" {
		stopReason = cloudflareprotocol.StopMaxTokens
	}
	response := cloudflareprotocol.Response{ID: wire.ID, CreatedAt: wire.CreatedAt, Model: wire.Model, Message: cloudflareprotocol.Message{Role: cloudflareprotocol.RoleAssistant}, StopReason: stopReason, Usage: usage}
	if status == "failed" || status == "cancelled" {
		return response, status, nil
	}
	for _, item := range wire.Output {
		switch item.Type {
		case "message":
			for _, part := range item.Content {
				if part.Type != "output_text" || part.Text == "" {
					return cloudflareprotocol.Response{}, "", errors.New("upstream response contains an unsupported output part")
				}
				response.Message.Parts = append(response.Message.Parts, cloudflareprotocol.Part{Kind: cloudflareprotocol.PartText, Text: part.Text})
			}
		case "function_call":
			return cloudflareprotocol.Response{}, "", errors.New("upstream function calls are not representable by Gemini")
		default:
			return cloudflareprotocol.Response{}, "", errors.New("upstream response contains an unsupported output item")
		}
	}
	return response, status, nil
}

func normalizedOpenAITerminalStatus(eventType, status string) (string, error) {
	eventType = strings.TrimSpace(eventType)
	status = strings.TrimSpace(strings.ToLower(status))
	if status == "canceled" {
		status = "cancelled"
	}
	expected := ""
	switch eventType {
	case "response.completed":
		expected = "completed"
	case "response.incomplete":
		expected = "incomplete"
	case "response.failed", "error":
		expected = "failed"
	case "response.cancelled", "response.canceled":
		expected = "cancelled"
	case "", "response.done":
	default:
		return "", errors.New("unsupported upstream terminal event")
	}
	if expected != "" && status != expected {
		return "", errors.New("upstream terminal event and response status disagree")
	}
	switch status {
	case "completed", "incomplete", "failed", "cancelled":
		return status, nil
	default:
		return "", errors.New("unsupported upstream terminal status")
	}
}

func decodeOpenAIUsage(raw json.RawMessage) (*cloudflareprotocol.Usage, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var wire struct {
		Input  *json.Number `json:"input_tokens"`
		Output *json.Number `json:"output_tokens"`
		Total  *json.Number `json:"total_tokens"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil || wire.Input == nil || wire.Output == nil || wire.Total == nil {
		return nil, errors.New("upstream usage is incomplete")
	}
	for _, value := range []*json.Number{wire.Input, wire.Output, wire.Total} {
		parsed, err := strconv.ParseInt(value.String(), 10, 64)
		if err != nil || parsed < 0 {
			return nil, errors.New("upstream usage contains an invalid token count")
		}
	}
	return &cloudflareprotocol.Usage{InputTokens: *wire.Input, OutputTokens: *wire.Output, TotalTokens: *wire.Total}, nil
}

func decodeOpenAIResponse(body []byte) (cloudflareprotocol.Response, error) {
	response, status, err := decodeOpenAITerminalEvent(body, "")
	if err != nil {
		return cloudflareprotocol.Response{}, err
	}
	switch status {
	case "completed", "incomplete":
		if response.ID == "" || response.Model == "" || len(response.Message.Parts) == 0 {
			return cloudflareprotocol.Response{}, errors.New("upstream response is incomplete")
		}
		return response, nil
	case "failed":
		return cloudflareprotocol.Response{}, errors.New("upstream response failed")
	case "cancelled":
		return cloudflareprotocol.Response{}, errors.New("upstream response was cancelled")
	default:
		return cloudflareprotocol.Response{}, errors.New("unsupported upstream terminal status")
	}
}

func extractGeminiTerminalUsage(ctx context.Context, body []byte) *cloudflareprotocol.Usage {
	var usage *cloudflareprotocol.Usage
	_ = cloudflareprotocol.ParseSSE(ctx, bytes.NewReader(body), cloudflareprotocol.SSELimits{}, func(frame cloudflareprotocol.SSEFrame) error {
		eventType := openAIResponseEventType(frame)
		if !isOpenAIResponseTerminalEvent(eventType) || eventType == "error" {
			return nil
		}
		response, _, err := decodeOpenAITerminalEvent(frame.Data, eventType)
		if err == nil && response.Usage != nil {
			usage = response.Usage
		}
		return nil
	})
	return usage
}

func extractGeminiTerminalStatus(ctx context.Context, body []byte) (string, bool) {
	status := ""
	_ = cloudflareprotocol.ParseSSE(ctx, bytes.NewReader(body), cloudflareprotocol.SSELimits{}, func(frame cloudflareprotocol.SSEFrame) error {
		eventType := openAIResponseEventType(frame)
		if !isOpenAIResponseTerminalEvent(eventType) {
			return nil
		}
		if eventType == "error" {
			status = "failed"
			return nil
		}
		_, decodedStatus, err := decodeOpenAITerminalEvent(frame.Data, eventType)
		if err == nil {
			status = decodedStatus
		}
		return nil
	})
	return status, status == "failed" || status == "cancelled"
}

func writeGeminiTerminalErrorResponse(c *gin.Context, status string) error {
	statusCode := http.StatusBadGateway
	protocolErr := cloudflareprotocol.UpstreamError(statusCode, false, false, "")
	if status == "cancelled" {
		statusCode = 499
		protocolErr = &cloudflareprotocol.Error{Code: cloudflareprotocol.ErrCancelled, Message: "upstream response was cancelled", HTTPStatus: statusCode}
	}
	encoded, err := cloudflareprotocol.EncodeError(cloudflareprotocol.Gemini, protocolErr)
	if err != nil {
		return err
	}
	c.Header("Content-Type", "application/json")
	c.Status(statusCode)
	_, err = c.Writer.Write(encoded)
	return err
}

func mergeGeminiTerminalUsage(result *service.OpenAIForwardResult, usage *cloudflareprotocol.Usage, model, mappedModel string, duration time.Duration) *service.OpenAIForwardResult {
	if usage == nil {
		return result
	}
	inputTokens, inputErr := strconv.Atoi(usage.InputTokens.String())
	outputTokens, outputErr := strconv.Atoi(usage.OutputTokens.String())
	if inputErr != nil || outputErr != nil {
		return result
	}
	if result == nil {
		result = &service.OpenAIForwardResult{Model: model, UpstreamModel: mappedModel, Duration: duration}
	}
	result.Usage.InputTokens = inputTokens
	result.Usage.OutputTokens = outputTokens
	result.UsagePresent = true
	return result
}
