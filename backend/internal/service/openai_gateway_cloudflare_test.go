package service

import "testing"

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
