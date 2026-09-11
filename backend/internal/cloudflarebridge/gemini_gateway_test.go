//go:build unit

package cloudflarebridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai_compat"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestGeminiResponsesTerminalEventsSetProtocolUsageAndOutcome(t *testing.T) {
	tests := []struct {
		name          string
		eventType     string
		status        string
		wantOutcome   string
		wantHTTP      int
		wantFinish    string
		wantErrorCode string
	}{
		{name: "completed", eventType: "response.completed", status: "completed", wantOutcome: OutcomeSucceeded, wantHTTP: http.StatusOK, wantFinish: "STOP"},
		{name: "done", eventType: "response.done", status: "completed", wantOutcome: OutcomeSucceeded, wantHTTP: http.StatusOK, wantFinish: "STOP"},
		{name: "incomplete", eventType: "response.incomplete", status: "incomplete", wantOutcome: OutcomeSucceeded, wantHTTP: http.StatusOK, wantFinish: "MAX_TOKENS"},
		{name: "failed", eventType: "response.failed", status: "failed", wantOutcome: OutcomeFailed, wantHTTP: http.StatusBadGateway, wantErrorCode: "UNAVAILABLE"},
		{name: "cancelled", eventType: "response.cancelled", status: "cancelled", wantOutcome: OutcomeFailed, wantHTTP: 499, wantErrorCode: "CANCELLED"},
	}
	for _, stream := range []bool{false, true} {
		mode := "non-stream"
		path := "/v1beta/models/client-gemini:generateContent"
		if stream {
			mode = "stream"
			path = "/v1beta/models/client-gemini:streamGenerateContent?alt=sse"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					control := testControlPlane()
					control.account.Extra = map[string]any{openai_compat.ExtraKeyResponsesSupported: true}
					upstream := &fakeHTTPUpstream{contentType: "text/event-stream", responseBody: geminiTerminalSSE(tt.eventType, tt.status, "terminal text")}
					handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
					require.NoError(t, err)

					res := serveGatewayRequest(t, handler, path, "sk-cloudflare-unit-test", `{"contents":[{"parts":[{"text":"x"}]}]}`)

					wantHTTP := tt.wantHTTP
					if stream {
						wantHTTP = http.StatusOK
					}
					require.Equal(t, wantHTTP, res.Code, res.Body.String())
					if tt.wantFinish != "" {
						if stream {
							require.Contains(t, res.Body.String(), `"finishReason":"`+tt.wantFinish+`"`)
							require.Contains(t, res.Body.String(), `"promptTokenCount":2`)
						} else {
							require.Equal(t, tt.wantFinish, gjson.Get(res.Body.String(), "candidates.0.finishReason").String(), res.Body.String())
							require.Equal(t, int64(2), gjson.Get(res.Body.String(), "usageMetadata.promptTokenCount").Int(), res.Body.String())
						}
					} else if stream {
						require.Contains(t, res.Body.String(), `"status":"`+tt.wantErrorCode+`"`)
					} else {
						require.Equal(t, tt.wantErrorCode, gjson.Get(res.Body.String(), "error.status").String(), res.Body.String())
					}
					control.mu.Lock()
					require.NotNil(t, control.completion)
					require.Equal(t, tt.wantOutcome, control.completion.Outcome)
					require.Equal(t, UsageConfirmed, control.completion.UsageState)
					require.Equal(t, "2", control.completion.InputTokens)
					require.Equal(t, "1", control.completion.OutputTokens)
					control.mu.Unlock()
				})
			}
		})
	}
}

func TestGeminiStreamFlushesDeltaBeforeUpstreamCompletion(t *testing.T) {
	control := testControlPlane()
	control.account.Extra = map[string]any{openai_compat.ExtraKeyResponsesSupported: true}
	upstream := newLiveGeminiSSEUpstream()
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	writer := newGeminiObservingResponseWriter(false)
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(writer, geminiStreamingRequest(context.Background()))
		close(done)
	}()

	select {
	case <-writer.deltaSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("first Gemini delta was not flushed")
	}
	require.Contains(t, writer.bodyString(), `"text":"early"`)
	require.NotContains(t, writer.bodyString(), "finishReason")
	require.Greater(t, writer.flushCount(), 0)
	select {
	case <-done:
		t.Fatal("handler completed before the upstream terminal event was released")
	default:
	}

	close(upstream.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not complete after the upstream terminal event")
	}
	require.Contains(t, writer.bodyString(), `"finishReason":"STOP"`)
	require.Contains(t, writer.bodyString(), `"promptTokenCount":2`)
}

func TestGeminiStreamDownstreamWriteFailureCancelsUpstream(t *testing.T) {
	control := testControlPlane()
	control.account.Extra = map[string]any{openai_compat.ExtraKeyResponsesSupported: true}
	upstream := newLiveGeminiSSEUpstream()
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	writer := newGeminiObservingResponseWriter(true)
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(writer, geminiStreamingRequest(context.Background()))
		close(done)
	}()

	select {
	case <-upstream.cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream context was not cancelled after the downstream write failed")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not stop after the downstream write failed")
	}
	control.mu.Lock()
	require.NotNil(t, control.completion)
	require.Equal(t, OutcomeFailed, control.completion.Outcome)
	require.Zero(t, control.releaseCount)
	control.mu.Unlock()
}

func TestGeminiStreamBoundsUnfinishedFrameBuffer(t *testing.T) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	ctx, cancel := context.WithCancelCause(context.Background())
	relay := newGeminiStreamResponseWriter(c.Writer, ctx, cancel)

	_, err := relay.Write([]byte("data: " + strings.Repeat("x", geminiStreamPendingFrameLimit)))

	require.ErrorContains(t, err, "unfinished upstream SSE frame")
	require.Error(t, context.Cause(ctx))
}

func geminiTerminalSSE(eventType, status, text string) string {
	output := `[]`
	if status == "completed" || status == "incomplete" {
		output = `[{"type":"message","id":"msg_terminal","role":"assistant","status":"` + status + `","content":[{"type":"output_text","text":"` + text + `"}]}]`
	}
	return strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_terminal","object":"response","status":"in_progress","model":"mock-upstream-model","output":[]}}`,
		`data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"` + text + `"}`,
		`data: {"type":"` + eventType + `","response":{"id":"resp_terminal","object":"response","status":"` + status + `","model":"mock-upstream-model","output":` + output + `,"usage":{"input_tokens":2,"output_tokens":1,"total_tokens":3}}}`,
		"data: [DONE]",
		"",
	}, "\n\n")
}

func geminiStreamingRequest(ctx context.Context) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/client-gemini:streamGenerateContent?alt=sse", strings.NewReader(`{"contents":[{"parts":[{"text":"x"}]}]}`)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer sk-cloudflare-unit-test")
	req.Header.Set("Content-Type", "application/json")
	return req
}

type liveGeminiSSEUpstream struct {
	release   chan struct{}
	cancelled chan struct{}
	once      sync.Once
}

func newLiveGeminiSSEUpstream() *liveGeminiSSEUpstream {
	return &liveGeminiSSEUpstream{release: make(chan struct{}), cancelled: make(chan struct{})}
}

func (u *liveGeminiSSEUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	if err := service.MarkCloudflareUpstreamStarted(req.Context()); err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()
	go func() {
		if _, err := io.WriteString(writer, strings.Join([]string{
			`data: {"type":"response.created","response":{"id":"resp_live","object":"response","status":"in_progress","model":"mock-upstream-model","output":[]}}`,
			`data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"early"}`,
			"",
		}, "\n\n")); err != nil {
			_ = writer.CloseWithError(err)
			return
		}
		select {
		case <-req.Context().Done():
			u.once.Do(func() { close(u.cancelled) })
			_ = writer.CloseWithError(req.Context().Err())
		case <-u.release:
			_, _ = io.WriteString(writer, strings.Join([]string{
				`data: {"type":"response.completed","response":{"id":"resp_live","object":"response","status":"completed","model":"mock-upstream-model","output":[{"type":"message","id":"msg_live","role":"assistant","status":"completed","content":[{"type":"output_text","text":"early"}]}],"usage":{"input_tokens":2,"output_tokens":1,"total_tokens":3}}}`,
				"data: [DONE]",
				"",
			}, "\n\n"))
			_ = writer.Close()
		}
	}()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
			"X-Request-Id": []string{"upstream-live-gemini"},
		},
		Body: reader,
	}, nil
}

func (u *liveGeminiSSEUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, accountConcurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(req, proxyURL, accountID, accountConcurrency)
}

type geminiObservingResponseWriter struct {
	mu         sync.Mutex
	header     http.Header
	body       bytes.Buffer
	status     int
	flushes    int
	failWrites bool
	deltaSeen  chan struct{}
	once       sync.Once
}

func newGeminiObservingResponseWriter(failWrites bool) *geminiObservingResponseWriter {
	return &geminiObservingResponseWriter{header: make(http.Header), status: http.StatusOK, failWrites: failWrites, deltaSeen: make(chan struct{})}
}

func (w *geminiObservingResponseWriter) Header() http.Header { return w.header }

func (w *geminiObservingResponseWriter) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status = status
}

func (w *geminiObservingResponseWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if bytes.Contains(data, []byte(`"text":"early"`)) {
		w.once.Do(func() { close(w.deltaSeen) })
	}
	if w.failWrites {
		return 0, errors.New("injected downstream write failure")
	}
	return w.body.Write(data)
}

func (w *geminiObservingResponseWriter) Flush() {
	w.mu.Lock()
	w.flushes++
	w.mu.Unlock()
}

func (w *geminiObservingResponseWriter) bodyString() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.String()
}

func (w *geminiObservingResponseWriter) flushCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushes
}
