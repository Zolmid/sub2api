package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestCloudflareUsageKeyScannerRequiresTokenUsageObject(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
		want   bool
	}{
		{
			name:   "responses usage across reads",
			chunks: []string{`data: {"response":{"usage": {"input_`, `tokens":0,"output_tokens":0}}}`},
			want:   true,
		},
		{
			name:   "chat usage",
			chunks: []string{`{"usage":{"prompt_tokens":0,"completion_tokens":0}}`},
			want:   true,
		},
		{
			name:   "nested response usage",
			chunks: []string{`data: {"response":{"usage":{"input_tokens":0}}}`},
			want:   true,
		},
		{
			name:   "nested message usage",
			chunks: []string{`data: {"message":{"usage":{"input_tokens":0}}}`},
			want:   true,
		},
		{
			name:   "unrelated usage metadata with token-shaped fields",
			chunks: []string{`{"metadata":{"usage":{"prompt_tokens":99}}}`},
		},
		{
			name:   "generated text containing usage json",
			chunks: []string{`{"output":[{"text":"{\"usage\":{\"input_tokens\":99}}"}]}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scanner cloudflareUsageKeyScanner
			got := false
			for _, chunk := range tt.chunks {
				if scanner.Write([]byte(chunk)) {
					got = true
				}
			}
			if got != tt.want {
				t.Fatalf("scanner result = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestForwardCloudflareEmbeddingsUsesRequestLocalMappingAndRawUsage(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		wantUsage  bool
		wantTokens int
	}{
		{
			name:       "nonzero usage",
			response:   `{"object":"list","data":[],"usage":{"prompt_tokens":7,"total_tokens":7}}`,
			wantUsage:  true,
			wantTokens: 7,
		},
		{
			name:      "all-zero usage",
			response:  `{"object":"list","data":[],"usage":{"prompt_tokens":0,"total_tokens":0}}`,
			wantUsage: true,
		},
		{
			name:     "malformed usage",
			response: `{"object":"list","data":[],"usage":{"prompt_tokens":"zero","total_tokens":0}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(`{"model":"client-embedding-model","input":["hello","world"]}`)
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader(body))
			upstream := &httpUpstreamRecorder{resp: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(tt.response)),
			}}
			svc := NewCloudflareVerticalSliceOpenAIGatewayService(&config.Config{}, upstream)
			account := &Account{
				ID:       42,
				Platform: PlatformOpenAI,
				Type:     AccountTypeAPIKey,
				Credentials: map[string]any{
					"api_key":  "sk-test",
					"base_url": "https://api.example.test",
					"model_mapping": map[string]any{
						"client-embedding-model": "traditional-mapped-model",
					},
				},
			}

			result, err := svc.ForwardCloudflareEmbeddings(context.Background(), c, account, body, "client-embedding-model", "worker-mapped-model")

			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, tt.wantUsage, result.UsagePresent)
			require.Equal(t, tt.wantTokens, result.Usage.InputTokens)
			require.Equal(t, "worker-mapped-model", gjson.GetBytes(upstream.lastBody, "model").String())
			require.JSONEq(t, `{"model":"worker-mapped-model","input":["hello","world"]}`, string(upstream.lastBody))
			require.Equal(t, "traditional-mapped-model", account.GetModelMapping()["client-embedding-model"])
		})
	}
}

func TestCloudflareEmbeddingsUsageObserverBoundsCapturedUsageObject(t *testing.T) {
	var scanner cloudflareUsageKeyScanner
	oversizedUsage := `{"usage":{"prompt_tokens":0,"detail":"` + strings.Repeat("x", cloudflareEmbeddingsUsageCaptureMaxBytes) + `"}}`

	require.False(t, scanner.WriteEmbeddings([]byte(oversizedUsage)))
	require.True(t, scanner.capture.completed)
	require.True(t, scanner.capture.overflow)
	require.LessOrEqual(t, len(scanner.capture.body), cloudflareEmbeddingsUsageCaptureMaxBytes)
}
