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
	"github.com/stretchr/testify/require"
)

type fakeControlPlane struct {
	disabledTOTPControlPlane
	mu          sync.Mutex
	key         *service.APIKey
	account     *service.Account
	touchCount  int
	completion  *CompletionRequest
	release     *ReleaseRequest
	renewCount  int
	renewErr    error
	leaseExpiry time.Time
}

func (f *fakeControlPlane) ResolveAPIKey(_ context.Context, key string) (*service.APIKey, error) {
	if key != "sk-cloudflare-unit-test" {
		return nil, service.ErrAPIKeyNotFound
	}
	return f.key, nil
}

func (f *fakeControlPlane) TouchAPIKey(context.Context, int64, time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touchCount++
	return nil
}

func (f *fakeControlPlane) Admit(_ context.Context, request AdmissionRequest) (*Admission, error) {
	expiresAt := f.leaseExpiry
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Minute)
	}
	return &Admission{
		UpstreamModel: "mock-upstream-model",
		Account:       f.account,
		Lease: Lease{
			ID:        "lease-unit-test",
			RequestID: request.RequestID,
			AccountID: "3001",
			Owner:     "container-unit-test",
			Epoch:     "1",
			ExpiresAt: expiresAt,
		},
	}, nil
}

func (f *fakeControlPlane) Renew(_ context.Context, request RenewRequest) (*Lease, error) {
	f.mu.Lock()
	f.renewCount++
	renewErr := f.renewErr
	f.mu.Unlock()
	if renewErr != nil {
		return nil, renewErr
	}
	return &Lease{
		ID:        request.LeaseID,
		RequestID: request.RequestID,
		AccountID: request.AccountID,
		Owner:     request.Owner,
		Epoch:     request.Epoch,
		ExpiresAt: time.Now().Add(time.Duration(request.TTLSeconds) * time.Second),
	}, nil
}

func (f *fakeControlPlane) Complete(_ context.Context, request CompletionRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	copy := request
	f.completion = &copy
	return nil
}

func (f *fakeControlPlane) Release(_ context.Context, request ReleaseRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	copy := request
	f.release = &copy
	return nil
}

type fakeHTTPUpstream struct {
	mu             sync.Mutex
	requestURL     string
	authorization  string
	body           []byte
	requestContext context.Context
}

type blockingHTTPUpstream struct{}

func (blockingHTTPUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func (b blockingHTTPUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, accountConcurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return b.Do(req, proxyURL, accountID, accountConcurrency)
}

type delayedSSEHTTPUpstream struct {
	delay time.Duration
}

func (d delayedSSEHTTPUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	reader, writer := io.Pipe()
	go func() {
		select {
		case <-req.Context().Done():
			_ = writer.CloseWithError(req.Context().Err())
			return
		case <-time.After(d.delay):
		}
		_, _ = io.WriteString(writer, "data: {\"id\":\"chatcmpl_cf_sse\",\"object\":\"chat.completion.chunk\",\"model\":\"mock-upstream-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"streamed\"}}]}\n\n")
		_, _ = io.WriteString(writer, "data: {\"id\":\"chatcmpl_cf_sse\",\"object\":\"chat.completion.chunk\",\"model\":\"mock-upstream-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4,\"total_tokens\":15}}\n\n")
		_, _ = io.WriteString(writer, "data: [DONE]\n\n")
		_ = writer.Close()
	}()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
			"X-Request-Id": []string{"upstream-sse-unit-test"},
		},
		Body: reader,
	}, nil
}

func (d delayedSSEHTTPUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, accountConcurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return d.Do(req, proxyURL, accountID, accountConcurrency)
}

func (f *fakeHTTPUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	f.mu.Lock()
	f.requestURL = req.URL.String()
	f.authorization = req.Header.Get("Authorization")
	f.body, _ = io.ReadAll(req.Body)
	f.requestContext = req.Context()
	f.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
			"X-Request-Id": []string{"upstream-unit-test"},
		},
		Body: io.NopCloser(strings.NewReader(`{"id":"chatcmpl_cf","object":"chat.completion","model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)),
	}, nil
}

func (f *fakeHTTPUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, accountConcurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return f.Do(req, proxyURL, accountID, accountConcurrency)
}

func testRuntimeConfig(t *testing.T) *RuntimeConfig {
	t.Helper()
	setTestJWTSecret(t)
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "mock.upstream")
	t.Setenv("SUB2API_CF_ALLOW_TEST_FIXTURE", "")
	runtime, err := LoadRuntimeConfigFromEnv()
	require.NoError(t, err)
	return runtime
}

func testControlPlane() *fakeControlPlane {
	groupID := int64(2001)
	group := &service.Group{
		ID:       groupID,
		Name:     "cloudflare-unit-group",
		Platform: service.PlatformOpenAI,
		Status:   service.StatusActive,
		Hydrated: true,
	}
	user := &service.User{
		ID:          1001,
		Status:      service.StatusActive,
		Role:        service.RoleUser,
		Balance:     1,
		Concurrency: 2,
	}
	return &fakeControlPlane{
		key: &service.APIKey{
			ID:      4001,
			UserID:  user.ID,
			Name:    "cloudflare-unit-key",
			GroupID: &groupID,
			Status:  service.StatusActive,
			User:    user,
			Group:   group,
		},
		account: &service.Account{
			ID:          3001,
			Name:        "cloudflare-unit-account",
			Platform:    service.PlatformOpenAI,
			Type:        service.AccountTypeAPIKey,
			Status:      service.StatusActive,
			Schedulable: true,
			Concurrency: 1,
			Credentials: map[string]any{
				"api_key":  "fixture-upstream-token",
				"base_url": "https://mock.upstream",
			},
			Extra: map[string]any{openai_compat.ExtraKeyResponsesSupported: false},
		},
	}
}

func TestCloudflareHandlerUsesBaselineAuthAndOpenAIForwarder(t *testing.T) {
	control := testControlPlane()
	upstream := &fakeHTTPUpstream{}
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	body := []byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":false}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-cloudflare-unit-test")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	require.Contains(t, res.Body.String(), `"content":"ok"`)
	require.Equal(t, "https://mock.upstream/v1/chat/completions", upstream.requestURL)
	require.Equal(t, "Bearer fixture-upstream-token", upstream.authorization)
	require.JSONEq(t, `{"model":"mock-upstream-model","messages":[{"role":"user","content":"hello"}],"stream":false}`, string(upstream.body))
	require.ErrorIs(t, upstream.requestContext.Err(), context.Canceled,
		"the bridge must keep lease cancellation attached to the upstream request")

	control.mu.Lock()
	defer control.mu.Unlock()
	require.Equal(t, 1, control.touchCount)
	require.NotNil(t, control.completion)
	require.Equal(t, UsageSchemaVersion, control.completion.SchemaVersion)
	require.Equal(t, UsageEventType, control.completion.EventType)
	require.Equal(t, OutcomeSucceeded, control.completion.Outcome)
	require.Equal(t, UsageConfirmed, control.completion.UsageState)
	require.Equal(t, "3", control.completion.InputTokens)
	require.Equal(t, "2", control.completion.OutputTokens)
	require.Equal(t, "upstream-unit-test", control.completion.UpstreamID)
	require.NotNil(t, control.release)
	require.Equal(t, "lease-unit-test", control.release.LeaseID)
}

func TestCloudflareHandlerRejectsUnknownAPIKeyBeforeAdmission(t *testing.T) {
	control := testControlPlane()
	handler, err := NewHandler(testRuntimeConfig(t), control, &fakeHTTPUpstream{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test-model","messages":[]}`))
	req.Header.Set("Authorization", "Bearer wrong-key")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusUnauthorized, res.Code)
	control.mu.Lock()
	defer control.mu.Unlock()
	require.Nil(t, control.completion)
	require.Nil(t, control.release)
}

func TestLeaseKeeperRenewsAndStops(t *testing.T) {
	control := testControlPlane()
	ctx, cancel := context.WithCancelCause(context.Background())
	keeper := startLeaseKeeper(ctx, control, Lease{
		ID:        "lease-renew",
		RequestID: "request-renew",
		AccountID: "3001",
		Owner:     "container-unit-test",
		Epoch:     "7",
		ExpiresAt: time.Now().Add(3 * time.Second),
	}, 3, cancel)
	t.Cleanup(func() {
		keeper.Stop()
		cancel(nil)
	})

	require.Eventually(t, func() bool {
		control.mu.Lock()
		defer control.mu.Unlock()
		return control.renewCount > 0
	}, 2500*time.Millisecond, 25*time.Millisecond)
}

func TestLeaseExpiryCancelsActiveUpstreamRequest(t *testing.T) {
	control := testControlPlane()
	control.leaseExpiry = time.Now().Add(100 * time.Millisecond)
	control.renewErr = errors.New("injected renewal failure")
	runtime := testRuntimeConfig(t)
	runtime.LeaseTTLSeconds = 3
	handler, err := NewHandler(runtime, control, blockingHTTPUpstream{})
	require.NoError(t, err)

	body := []byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":false}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-cloudflare-unit-test")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	started := time.Now()
	handler.ServeHTTP(res, req)
	require.Less(t, time.Since(started), 2500*time.Millisecond)
	require.Equal(t, http.StatusServiceUnavailable, res.Code, res.Body.String())
	require.Contains(t, res.Body.String(), "ACCOUNT_LEASE_LOST")

	control.mu.Lock()
	defer control.mu.Unlock()
	require.GreaterOrEqual(t, control.renewCount, 1)
	require.NotNil(t, control.completion)
	require.Equal(t, OutcomeFailed, control.completion.Outcome)
	require.Equal(t, UsageUnknown, control.completion.UsageState)
	require.NotNil(t, control.release)
}

func TestLongSilentSSEStreamRenewsLeaseAndPersistsUsage(t *testing.T) {
	control := testControlPlane()
	control.leaseExpiry = time.Now().Add(3 * time.Second)
	runtime := testRuntimeConfig(t)
	runtime.LeaseTTLSeconds = 3
	handler, err := NewHandler(runtime, control, delayedSSEHTTPUpstream{delay: 3200 * time.Millisecond})
	require.NoError(t, err)

	body := []byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":true}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-cloudflare-unit-test")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	started := time.Now()
	handler.ServeHTTP(res, req)
	require.GreaterOrEqual(t, time.Since(started), 3*time.Second)
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	require.Contains(t, res.Body.String(), `"content":"streamed"`)
	require.Contains(t, res.Body.String(), "data: [DONE]")

	control.mu.Lock()
	defer control.mu.Unlock()
	require.GreaterOrEqual(t, control.renewCount, 3)
	require.NotNil(t, control.completion)
	require.Equal(t, OutcomeSucceeded, control.completion.Outcome)
	require.Equal(t, UsageConfirmed, control.completion.UsageState)
	require.Equal(t, "11", control.completion.InputTokens)
	require.Equal(t, "4", control.completion.OutputTokens)
	require.Equal(t, "upstream-sse-unit-test", control.completion.UpstreamID)
	require.NotNil(t, control.release)
}
