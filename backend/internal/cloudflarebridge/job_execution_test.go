//go:build unit

package cloudflarebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func jobExecutionFixture(t *testing.T, route, payload string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(payload))
	return mustJSON(t, map[string]any{
		"v":      1,
		"method": "sub2api.cloudflare.jobs.execute",
		"params": map[string]any{
			"job": map[string]any{
				"id":             "job-1",
				"version":        2147483647,
				"route":          route,
				"type":           "refresh",
				"idempotencyKey": "idem-1",
			},
			"payload": map[string]any{
				"codec":  "json",
				"body":   payload,
				"digest": "sha256:" + stringHex(sum),
			},
		},
	})
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

func jobExecutionRequest(body []byte) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "http://sub2api.internal"+jobExecutionPrivatePath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	// NewRequest retains the absolute-form target in RequestURI, while a real
	// Container HTTP server receives origin-form. Exercise the production form.
	request.RequestURI = jobExecutionPrivatePath
	return request
}

func executeJobExecutionRequest(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestJobExecutionWorkerFixtureRoundTripsStrictResults(t *testing.T) {
	cases := []struct {
		name     string
		result   JobExecutionResult
		expected string
	}{
		{"succeeded", JobExecutionResult{Kind: "succeeded", ResultDigest: "sha256:result-1"}, `{"v":1,"kind":"succeeded","resultDigest":"sha256:result-1"}`},
		{"retryable", JobExecutionResult{Kind: "retryable_failure", ErrorCode: "provider_unavailable"}, `{"v":1,"kind":"retryable_failure","errorCode":"provider_unavailable"}`},
		{"permanent", JobExecutionResult{Kind: "permanent_failure", ErrorCode: "invalid_grant"}, `{"v":1,"kind":"permanent_failure","errorCode":"invalid_grant"}`},
		{"manual", JobExecutionResult{Kind: "manual_review", ReasonCode: "provider_state_unknown", EvidenceRef: "job:job-1"}, `{"v":1,"kind":"manual_review","reasonCode":"provider_state_unknown","evidenceRef":"job:job-1"}`},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			registry, err := NewJobExecutionRegistry(map[string]JobExecutionExecutor{
				"oauth-refresh.v1": JobExecutionExecutorFunc(func(ctx context.Context, input JobExecutionInput) (JobExecutionResult, error) {
					calls.Add(1)
					require.Equal(t, int64(2147483647), input.Version)
					require.Equal(t, "job-1", input.JobID)
					require.Equal(t, `{"a":"界"}`, input.PayloadBody)
					require.NoError(t, ctx.Err())
					return test.result, nil
				}),
			})
			require.NoError(t, err)
			recorder := executeJobExecutionRequest(newJobExecutionHandler(registry), jobExecutionRequest(jobExecutionFixture(t, "oauth-refresh.v1", `{"a":"界"}`)))
			require.Equal(t, http.StatusOK, recorder.Code)
			require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
			require.Equal(t, test.expected, recorder.Body.String())
			require.Equal(t, int32(1), calls.Load())
		})
	}
}

func TestJobExecutionUnconfiguredAndUnknownRoutesRequireManualReview(t *testing.T) {
	registry, err := NewJobExecutionRegistry(map[string]JobExecutionExecutor{})
	require.NoError(t, err)
	for _, route := range []string{"oauth-refresh.v1", "not-registered.v1"} {
		t.Run(route, func(t *testing.T) {
			recorder := executeJobExecutionRequest(newJobExecutionHandler(registry), jobExecutionRequest(jobExecutionFixture(t, route, "{}")))
			require.Equal(t, http.StatusOK, recorder.Code)
			require.Equal(t, `{"v":1,"kind":"manual_review","reasonCode":"route_unconfigured","evidenceRef":"job:job-1"}`, recorder.Body.String())
		})
	}

	// Production composition retains each currently registered route but leaves
	// its provider adapter explicitly unconfigured until that lane is added.
	for _, route := range registeredJobExecutionRoutes() {
		recorder := executeJobExecutionRequest(newJobExecutionHandler(defaultJobExecutionRegistry()), jobExecutionRequest(jobExecutionFixture(t, route, "{}")))
		require.Equal(t, http.StatusOK, recorder.Code)
		require.Contains(t, recorder.Body.String(), `"kind":"manual_review"`)
		require.NotContains(t, recorder.Body.String(), `"kind":"succeeded"`)
	}
}

func TestJobExecutionIsRegisteredOnlyAtPrivatePostPathInCloudflareComposition(t *testing.T) {
	handler, err := NewHandler(testRuntimeConfig(t), testControlPlane(), &fakeHTTPUpstream{})
	require.NoError(t, err)

	valid := jobExecutionRequest(jobExecutionFixture(t, "oauth-refresh.v1", "{}"))
	recorder := executeJobExecutionRequest(handler, valid)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"reasonCode":"route_adapter_unconfigured"`)

	wrongMethod := jobExecutionRequest(jobExecutionFixture(t, "oauth-refresh.v1", "{}"))
	wrongMethod.Method = http.MethodGet
	require.Equal(t, http.StatusNotFound, executeJobExecutionRequest(handler, wrongMethod).Code)

	encodedPath := jobExecutionRequest(jobExecutionFixture(t, "oauth-refresh.v1", "{}"))
	encodedPath.URL = &url.URL{Path: jobExecutionPrivatePath, RawPath: "/internal%2Fcloudflare/jobs/execute"}
	encodedPath.RequestURI = "/internal%2Fcloudflare/jobs/execute"
	require.NotEqual(t, http.StatusOK, executeJobExecutionRequest(handler, encodedPath).Code)

	var calls atomic.Int32
	registry, err := NewJobExecutionRegistry(map[string]JobExecutionExecutor{
		"oauth-refresh.v1": JobExecutionExecutorFunc(func(context.Context, JobExecutionInput) (JobExecutionResult, error) {
			calls.Add(1)
			return JobExecutionResult{Kind: "succeeded", ResultDigest: "composition-ok"}, nil
		}),
	})
	require.NoError(t, err)
	injected, err := NewHandlerWithJobExecutionRegistry(testRuntimeConfig(t), testControlPlane(), &fakeHTTPUpstream{}, registry)
	require.NoError(t, err)
	injectedResult := executeJobExecutionRequest(injected, jobExecutionRequest(jobExecutionFixture(t, "oauth-refresh.v1", "{}")))
	require.Equal(t, http.StatusOK, injectedResult.Code)
	require.Equal(t, `{"v":1,"kind":"succeeded","resultDigest":"composition-ok"}`, injectedResult.Body.String())
	require.Equal(t, int32(1), calls.Load())
}

func TestJobExecutionRejectsTransportAndSyntaxBeforeExecutor(t *testing.T) {
	var calls atomic.Int32
	registry, err := NewJobExecutionRegistry(map[string]JobExecutionExecutor{
		"oauth-refresh.v1": JobExecutionExecutorFunc(func(context.Context, JobExecutionInput) (JobExecutionResult, error) {
			calls.Add(1)
			return JobExecutionResult{Kind: "succeeded", ResultDigest: "ok"}, nil
		}),
	})
	require.NoError(t, err)
	handler := newJobExecutionHandler(registry)
	valid := jobExecutionFixture(t, "oauth-refresh.v1", "{}")

	cases := []struct {
		name    string
		request func() *http.Request
	}{
		{"wrong_method", func() *http.Request {
			request := jobExecutionRequest(valid)
			request.Method = http.MethodGet
			return request
		}},
		{"wrong_host", func() *http.Request {
			request := jobExecutionRequest(valid)
			request.Host = "example.invalid"
			return request
		}},
		{"wrong_content_type", func() *http.Request {
			request := jobExecutionRequest(valid)
			request.Header.Set("Content-Type", "text/plain")
			return request
		}},
		{"forwarded_header", func() *http.Request {
			request := jobExecutionRequest(valid)
			request.Header.Set("Forwarded", "host=sub2api.internal")
			return request
		}},
		{"query", func() *http.Request {
			request := jobExecutionRequest(valid)
			request.URL.RawQuery = "x=1"
			request.RequestURI += "?x=1"
			return request
		}},
		{"encoded_path", func() *http.Request {
			request := jobExecutionRequest(valid)
			request.URL = &url.URL{Path: jobExecutionPrivatePath, RawPath: "/internal%2Fcloudflare/jobs/execute"}
			request.RequestURI = "/internal%2Fcloudflare/jobs/execute"
			return request
		}},
		{"unknown_root", func() *http.Request {
			return jobExecutionRequest([]byte(`{"v":1,"method":"sub2api.cloudflare.jobs.execute","params":{},"extra":1}`))
		}},
		{"unknown_job", func() *http.Request {
			return jobExecutionRequest(bytes.Replace(valid, []byte(`"id":"job-1"`), []byte(`"id":"job-1","extra":1`), 1))
		}},
		{"unknown_payload", func() *http.Request {
			return jobExecutionRequest(bytes.Replace(valid, []byte(`"codec":"json"`), []byte(`"codec":"json","extra":1`), 1))
		}},
		{"duplicate_key", func() *http.Request {
			return jobExecutionRequest([]byte(`{"v":1,"v":1,"method":"sub2api.cloudflare.jobs.execute","params":{}}`))
		}},
		{"trailing_value", func() *http.Request { return jobExecutionRequest(append(valid, []byte(` {}`)...)) }},
		{"null_not_allowed", func() *http.Request {
			return jobExecutionRequest([]byte(`{"v":null,"method":"sub2api.cloudflare.jobs.execute","params":null}`))
		}},
		{"invalid_utf8", func() *http.Request { return jobExecutionRequest([]byte{'{', '"', 'v', '"', ':', 0xff, '}'}) }},
		{"wrong_version_type", func() *http.Request {
			return jobExecutionRequest(bytes.Replace(valid, []byte(`"version":2147483647`), []byte(`"version":"2147483647"`), 1))
		}},
		{"fractional_version", func() *http.Request {
			return jobExecutionRequest(bytes.Replace(valid, []byte(`"version":2147483647`), []byte(`"version":1.5`), 1))
		}},
		{"invalid_opaque", func() *http.Request {
			return jobExecutionRequest(bytes.Replace(valid, []byte(`"id":"job-1"`), []byte(`"id":" job-1"`), 1))
		}},
		{"invalid_codec_type", func() *http.Request {
			return jobExecutionRequest(bytes.Replace(valid, []byte(`"codec":"json"`), []byte(`"codec":null`), 1))
		}},
		{"invalid_body_type", func() *http.Request {
			return jobExecutionRequest(bytes.Replace(valid, []byte(`"body":"{}"`), []byte(`"body":{}`), 1))
		}},
		{"bad_digest", func() *http.Request {
			return jobExecutionRequest(bytes.Replace(valid, []byte("sha256:"), []byte("sha256:"+strings.Repeat("0", 64)+"x"), 1))
		}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			recorder := executeJobExecutionRequest(handler, test.request())
			require.Equal(t, http.StatusBadRequest, recorder.Code)
			require.Equal(t, `{"error":"invalid_request"}`, recorder.Body.String())
			require.Equal(t, int32(0), calls.Load())
		})
	}
}

func TestJobExecutionPayloadBoundariesAndMisleadingLength(t *testing.T) {
	var calls atomic.Int32
	registry, err := NewJobExecutionRegistry(map[string]JobExecutionExecutor{
		"oauth-refresh.v1": JobExecutionExecutorFunc(func(context.Context, JobExecutionInput) (JobExecutionResult, error) {
			calls.Add(1)
			return JobExecutionResult{Kind: "succeeded", ResultDigest: "ok"}, nil
		}),
	})
	require.NoError(t, err)
	handler := newJobExecutionHandler(registry)

	for _, test := range []struct {
		name string
		body string
		want int
	}{
		{"ascii_at_limit", strings.Repeat("a", maxJobExecutionPayloadBytes), http.StatusOK},
		{"ascii_over_limit", strings.Repeat("a", maxJobExecutionPayloadBytes+1), http.StatusBadRequest},
		{"multibyte_at_limit", strings.Repeat("界", 87381), http.StatusOK},
		{"multibyte_over_limit", strings.Repeat("界", 87382), http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := executeJobExecutionRequest(handler, jobExecutionRequest(jobExecutionFixture(t, "oauth-refresh.v1", test.body)))
			require.Equal(t, test.want, recorder.Code)
		})
	}

	largeEnvelope := jobExecutionFixture(t, "oauth-refresh.v1", strings.Repeat("a", maxJobExecutionPayloadBytes+1))
	misleading := jobExecutionRequest(largeEnvelope)
	misleading.ContentLength = 1
	misleading.Header.Set("Content-Length", "1")
	require.Equal(t, http.StatusBadRequest, executeJobExecutionRequest(handler, misleading).Code)

	chunked := jobExecutionRequest(largeEnvelope)
	chunked.ContentLength = -1
	chunked.Header.Del("Content-Length")
	chunked.TransferEncoding = []string{"chunked"}
	require.Equal(t, http.StatusBadRequest, executeJobExecutionRequest(handler, chunked).Code)
	require.Equal(t, int32(2), calls.Load(), "only the two valid boundary requests execute")
}

func TestJobExecutionExecutorFailureIsManualAndNeverLeaks(t *testing.T) {
	secret := "TOP_SECRET_PROVIDER_RESPONSE"
	cases := []struct {
		name     string
		executor JobExecutionExecutor
		wantCode string
	}{
		{"error", JobExecutionExecutorFunc(func(context.Context, JobExecutionInput) (JobExecutionResult, error) {
			return JobExecutionResult{}, errors.New(secret)
		}), "executor_uncertain"},
		{"panic", JobExecutionExecutorFunc(func(context.Context, JobExecutionInput) (JobExecutionResult, error) { panic(secret) }), "executor_uncertain"},
		{"invalid_result", JobExecutionExecutorFunc(func(context.Context, JobExecutionInput) (JobExecutionResult, error) {
			return JobExecutionResult{Kind: "succeeded", ResultDigest: secret, ErrorCode: "injected"}, nil
		}), "executor_invalid_result"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			registry, err := NewJobExecutionRegistry(map[string]JobExecutionExecutor{
				"oauth-refresh.v1": JobExecutionExecutorFunc(func(ctx context.Context, input JobExecutionInput) (JobExecutionResult, error) {
					calls.Add(1)
					return test.executor.Execute(ctx, input)
				}),
			})
			require.NoError(t, err)
			recorder := executeJobExecutionRequest(newJobExecutionHandler(registry), jobExecutionRequest(jobExecutionFixture(t, "oauth-refresh.v1", "{}")))
			require.Equal(t, http.StatusOK, recorder.Code)
			require.Contains(t, recorder.Body.String(), test.wantCode)
			require.NotContains(t, recorder.Body.String(), secret)
			require.Equal(t, int32(1), calls.Load())
		})
	}
}

func TestJobExecutionCancellationDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	registry, err := NewJobExecutionRegistry(map[string]JobExecutionExecutor{
		"oauth-refresh.v1": JobExecutionExecutorFunc(func(ctx context.Context, _ JobExecutionInput) (JobExecutionResult, error) {
			calls.Add(1)
			<-ctx.Done()
			return JobExecutionResult{}, ctx.Err()
		}),
	})
	require.NoError(t, err)

	request := jobExecutionRequest(jobExecutionFixture(t, "oauth-refresh.v1", "{}"))
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Millisecond)
	defer cancel()
	request = request.WithContext(ctx)
	recorder := executeJobExecutionRequest(newJobExecutionHandler(registry), request)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"reasonCode":"executor_uncertain"`)
	require.Equal(t, int32(1), calls.Load())
}
