//go:build unit

package cloudflarebridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai_compat"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

type fakeControlPlane struct {
	disabledTOTPControlPlane
	mu             sync.Mutex
	key            *service.APIKey
	account        *service.Account
	touchCount     int
	admitCount     int
	admitErr       error
	startCount     int
	start          *StartRequest
	startErr       error
	completion     *CompletionRequest
	completionErr  error
	release        *ReleaseRequest
	releaseCount   int
	renewCount     int
	renewErr       error
	leaseExpiry    time.Time
	sessions       map[string]*service.RefreshTokenData
	userSessions   map[int64]map[string]struct{}
	familySessions map[string]map[string]struct{}
	settings       *cloudflareSettingsRepositoryStub
}

// cloudflareSettingsRepositoryStub is the explicit, deterministic settings
// seam used by fake ControlPlane tests. Production NewHandler cannot reach it.
type cloudflareSettingsRepositoryStub struct {
	mu     sync.Mutex
	values map[string]string
	err    error
}

func newCloudflareSettingsRepositoryStub(values map[string]string) *cloudflareSettingsRepositoryStub {
	copy := make(map[string]string, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return &cloudflareSettingsRepositoryStub{values: copy}
}

func (r *cloudflareSettingsRepositoryStub) Get(_ context.Context, key string) (*service.Setting, error) {
	value, err := r.GetValue(context.Background(), key)
	if err != nil {
		return nil, err
	}
	return &service.Setting{Key: key, Value: value}, nil
}

func (r *cloudflareSettingsRepositoryStub) GetValue(_ context.Context, key string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return "", r.err
	}
	value, ok := r.values[key]
	if !ok {
		return "", service.ErrSettingNotFound
	}
	return value, nil
}

func (r *cloudflareSettingsRepositoryStub) Set(_ context.Context, key, value string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values[key] = value
	return nil
}

func (r *cloudflareSettingsRepositoryStub) GetMultiple(_ context.Context, keys []string) (map[string]string, error) {
	result := make(map[string]string)
	for _, key := range keys {
		value, err := r.GetValue(context.Background(), key)
		if err == nil {
			result[key] = value
		}
	}
	return result, nil
}

func (r *cloudflareSettingsRepositoryStub) SetMultiple(_ context.Context, values map[string]string) error {
	for key, value := range values {
		if err := r.Set(context.Background(), key, value); err != nil {
			return err
		}
	}
	return nil
}

func (r *cloudflareSettingsRepositoryStub) GetAll(context.Context) (map[string]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make(map[string]string, len(r.values))
	for key, value := range r.values {
		result[key] = value
	}
	return result, r.err
}

func (r *cloudflareSettingsRepositoryStub) Delete(_ context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.values, key)
	return nil
}

func (f *fakeControlPlane) cloudflareSettingsRepository() service.SettingRepository {
	return f.settings
}

type noAuthSessionControlPlane struct {
	disabledTOTPControlPlane
}

func (noAuthSessionControlPlane) cloudflareSettingsRepository() service.SettingRepository {
	return newCloudflareSettingsRepositoryStub(map[string]string{
		service.SettingKeyBackendModeEnabled:    "false",
		service.SettingKeySessionBindingEnabled: "false",
	})
}

func (noAuthSessionControlPlane) ResolveAPIKey(context.Context, string) (*service.APIKey, error) {
	return nil, service.ErrAPIKeyNotFound
}

func (noAuthSessionControlPlane) TouchAPIKey(context.Context, int64, time.Time) error {
	return nil
}

func (noAuthSessionControlPlane) Admit(context.Context, AdmissionRequest) (*Admission, error) {
	return nil, ErrControlPlaneUnavailable
}

func (noAuthSessionControlPlane) Start(context.Context, StartRequest) error {
	return ErrControlPlaneUnavailable
}

func (noAuthSessionControlPlane) Renew(context.Context, RenewRequest) (*Lease, error) {
	return nil, ErrControlPlaneUnavailable
}

func (noAuthSessionControlPlane) Complete(context.Context, CompletionRequest) error {
	return ErrControlPlaneUnavailable
}

func (noAuthSessionControlPlane) Release(context.Context, ReleaseRequest) error {
	return nil
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
	f.mu.Lock()
	f.admitCount++
	admitErr := f.admitErr
	f.mu.Unlock()
	if admitErr != nil {
		return nil, admitErr
	}
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
	return f.completionErr
}

func (f *fakeControlPlane) Start(_ context.Context, request StartRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCount++
	copy := request
	f.start = &copy
	return f.startErr
}

func (f *fakeControlPlane) Release(_ context.Context, request ReleaseRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseCount++
	copy := request
	f.release = &copy
	return nil
}

func (f *fakeControlPlane) StoreRefreshToken(_ context.Context, tokenHash string, data *service.RefreshTokenData, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureAuthSessions()
	f.storeRefreshTokenLocked(tokenHash, data)
	return nil
}

func (f *fakeControlPlane) GetRefreshToken(_ context.Context, tokenHash string) (*service.RefreshTokenData, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureAuthSessions()
	data := f.sessions[tokenHash]
	if data == nil {
		return nil, service.ErrRefreshTokenNotFound
	}
	copy := *data
	return &copy, nil
}

func (f *fakeControlPlane) DeleteRefreshToken(_ context.Context, tokenHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureAuthSessions()
	f.deleteRefreshTokenLocked(tokenHash)
	return nil
}

func (f *fakeControlPlane) DeleteUserRefreshTokens(_ context.Context, userID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureAuthSessions()
	for tokenHash := range f.userSessions[userID] {
		f.deleteRefreshTokenLocked(tokenHash)
	}
	delete(f.userSessions, userID)
	return nil
}

func (f *fakeControlPlane) DeleteTokenFamily(_ context.Context, familyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureAuthSessions()
	for tokenHash := range f.familySessions[familyID] {
		f.deleteRefreshTokenLocked(tokenHash)
	}
	delete(f.familySessions, familyID)
	return nil
}

func (f *fakeControlPlane) AddToUserTokenSet(context.Context, int64, string, time.Duration) error {
	return nil
}

func (f *fakeControlPlane) AddToFamilyTokenSet(context.Context, string, string, time.Duration) error {
	return nil
}

func (f *fakeControlPlane) GetUserTokenHashes(_ context.Context, userID int64) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureAuthSessions()
	out := make([]string, 0, len(f.userSessions[userID]))
	for tokenHash := range f.userSessions[userID] {
		out = append(out, tokenHash)
	}
	return out, nil
}

func (f *fakeControlPlane) GetFamilyTokenHashes(_ context.Context, familyID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureAuthSessions()
	out := make([]string, 0, len(f.familySessions[familyID]))
	for tokenHash := range f.familySessions[familyID] {
		out = append(out, tokenHash)
	}
	return out, nil
}

func (f *fakeControlPlane) IsTokenInFamily(_ context.Context, familyID string, tokenHash string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureAuthSessions()
	_, ok := f.familySessions[familyID][tokenHash]
	return ok, nil
}

func (f *fakeControlPlane) RotateRefreshToken(_ context.Context, oldHash, newHash string, newData *service.RefreshTokenData, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureAuthSessions()
	old := f.sessions[oldHash]
	if old == nil {
		return service.ErrRefreshTokenReused
	}
	if newData == nil || newData.TokenVersion != old.TokenVersion {
		return service.ErrRefreshTokenReused
	}
	f.deleteRefreshTokenLocked(oldHash)
	f.storeRefreshTokenLocked(newHash, newData)
	return nil
}

func (f *fakeControlPlane) ensureAuthSessions() {
	if f.sessions == nil {
		f.sessions = map[string]*service.RefreshTokenData{}
	}
	if f.userSessions == nil {
		f.userSessions = map[int64]map[string]struct{}{}
	}
	if f.familySessions == nil {
		f.familySessions = map[string]map[string]struct{}{}
	}
}

func (f *fakeControlPlane) storeRefreshTokenLocked(tokenHash string, data *service.RefreshTokenData) {
	copy := *data
	f.sessions[tokenHash] = &copy
	if f.userSessions[copy.UserID] == nil {
		f.userSessions[copy.UserID] = map[string]struct{}{}
	}
	f.userSessions[copy.UserID][tokenHash] = struct{}{}
	if f.familySessions[copy.FamilyID] == nil {
		f.familySessions[copy.FamilyID] = map[string]struct{}{}
	}
	f.familySessions[copy.FamilyID][tokenHash] = struct{}{}
}

func (f *fakeControlPlane) deleteRefreshTokenLocked(tokenHash string) {
	data := f.sessions[tokenHash]
	if data == nil {
		return
	}
	delete(f.sessions, tokenHash)
	delete(f.userSessions[data.UserID], tokenHash)
	if len(f.userSessions[data.UserID]) == 0 {
		delete(f.userSessions, data.UserID)
	}
	delete(f.familySessions[data.FamilyID], tokenHash)
	if len(f.familySessions[data.FamilyID]) == 0 {
		delete(f.familySessions, data.FamilyID)
	}
}

type fakeHTTPUpstream struct {
	mu             sync.Mutex
	requestURL     string
	authorization  string
	body           []byte
	requestContext context.Context
	responseBody   string
	contentType    string
	responseStatus int
	responseErr    error
	networkCalls   int
	beforeNetwork  func()
}

type blockingHTTPUpstream struct{}

func (blockingHTTPUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	if err := service.MarkCloudflareUpstreamStarted(req.Context()); err != nil {
		return nil, err
	}
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func (b blockingHTTPUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, accountConcurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return b.Do(req, proxyURL, accountID, accountConcurrency)
}

type cancellableHTTPUpstream struct {
	started chan struct{}
	once    sync.Once
	mu      sync.Mutex
	calls   int
}

func (u *cancellableHTTPUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	if err := service.MarkCloudflareUpstreamStarted(req.Context()); err != nil {
		return nil, err
	}
	u.mu.Lock()
	u.calls++
	u.mu.Unlock()
	u.once.Do(func() { close(u.started) })
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func (u *cancellableHTTPUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, accountConcurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(req, proxyURL, accountID, accountConcurrency)
}

type delayedSSEHTTPUpstream struct {
	delay time.Duration
}

func (d delayedSSEHTTPUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	if err := service.MarkCloudflareUpstreamStarted(req.Context()); err != nil {
		return nil, err
	}
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
	// The production HTTPUpstream invokes the same marker immediately before
	// its transport round trip. Keep this fake at that boundary so bridge unit
	// tests can prove a failed marker dispatches zero upstream bytes.
	if err := service.MarkCloudflareUpstreamStarted(req.Context()); err != nil {
		return nil, err
	}
	if f.beforeNetwork != nil {
		f.beforeNetwork()
	}
	f.mu.Lock()
	f.networkCalls++
	f.requestURL = req.URL.String()
	f.authorization = req.Header.Get("Authorization")
	f.body, _ = io.ReadAll(req.Body)
	f.requestContext = req.Context()
	responseBody := f.responseBody
	contentType := f.contentType
	responseStatus := f.responseStatus
	responseErr := f.responseErr
	f.mu.Unlock()
	if responseErr != nil {
		return nil, responseErr
	}
	if responseBody == "" {
		responseBody = `{"id":"chatcmpl_cf","object":"chat.completion","model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`
	}
	if contentType == "" {
		contentType = "application/json"
	}
	if responseStatus == 0 {
		responseStatus = http.StatusOK
	}
	return &http.Response{
		StatusCode: responseStatus,
		Header: http.Header{
			"Content-Type": []string{contentType},
			"X-Request-Id": []string{"upstream-unit-test"},
		},
		Body: io.NopCloser(strings.NewReader(responseBody)),
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
		settings: newCloudflareSettingsRepositoryStub(map[string]string{
			service.SettingKeyBackendModeEnabled:    "false",
			service.SettingKeySessionBindingEnabled: "false",
		}),
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

func TestNewHandlerRejectsControlPlaneWithoutAuthSessions(t *testing.T) {
	handler, err := NewHandler(testRuntimeConfig(t), noAuthSessionControlPlane{}, &fakeHTTPUpstream{})
	require.Nil(t, handler)
	require.EqualError(t, err, "cloudflare auth session control plane is required")
}

func serveGatewayRequest(t *testing.T, handler http.Handler, path, apiKey, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func openAIResponsesSSE(id, model, text string, inputTokens, outputTokens int) string {
	return strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"` + id + `","object":"response","status":"in_progress","model":"` + model + `","output":[]}}`,
		`data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"` + text + `"}`,
		`data: {"type":"response.completed","response":{"id":"` + id + `","object":"response","status":"completed","model":"` + model + `","output":[{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"` + text + `"}]}],"usage":{"input_tokens":` + strconv.Itoa(inputTokens) + `,"output_tokens":` + strconv.Itoa(outputTokens) + `,"total_tokens":` + strconv.Itoa(inputTokens+outputTokens) + `}}}`,
		"data: [DONE]",
		"",
	}, "\n\n")
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
	require.Equal(t, 1, control.startCount)
	require.NotNil(t, control.start)
	require.Equal(t, "4001", control.start.APIKeyID)
	require.Equal(t, "3001", control.start.AccountID)
	require.Equal(t, "lease-unit-test", control.start.LeaseID)
	require.Equal(t, "1", control.start.LeaseEpoch)
	require.Equal(t, "test-model", control.start.Model)
	require.Equal(t, "mock-upstream-model", control.start.UpstreamModel)
	require.NotNil(t, control.completion)
	require.Equal(t, UsageSchemaVersion, control.completion.SchemaVersion)
	require.Equal(t, UsageEventType, control.completion.EventType)
	require.Equal(t, OutcomeSucceeded, control.completion.Outcome)
	require.Equal(t, UsageConfirmed, control.completion.UsageState)
	require.Equal(t, "3", control.completion.InputTokens)
	require.Equal(t, "2", control.completion.OutputTokens)
	require.Equal(t, "upstream-unit-test", control.completion.UpstreamID)
	require.Nil(t, control.release)
	require.Zero(t, control.releaseCount)
}

func TestCloudflareHandlerResponsesNonStreamUsesMappedModelAndLifecycle(t *testing.T) {
	control := testControlPlane()
	control.account.Extra = map[string]any{openai_compat.ExtraKeyResponsesSupported: true}
	upstream := &fakeHTTPUpstream{
		responseBody: `{"id":"resp_cf","object":"response","status":"completed","model":"mock-upstream-model","service_tier":"priority","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"response ok"}]}],"usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10}}`,
	}
	startBeforeNetwork := false
	upstream.beforeNetwork = func() {
		control.mu.Lock()
		defer control.mu.Unlock()
		startBeforeNetwork = control.startCount == 1
	}
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	res := serveGatewayRequest(t, handler, "/v1/responses", "sk-cloudflare-unit-test", `{"model":"client-responses-model","input":"hello","stream":false,"service_tier":"priority","reasoning":{"effort":"high"}}`)

	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	require.Equal(t, "resp_cf", gjson.Get(res.Body.String(), "id").String())
	require.True(t, startBeforeNetwork)
	upstream.mu.Lock()
	require.Equal(t, 1, upstream.networkCalls)
	require.Equal(t, "https://mock.upstream/v1/responses", upstream.requestURL)
	require.Equal(t, "mock-upstream-model", gjson.GetBytes(upstream.body, "model").String())
	upstream.mu.Unlock()
	control.mu.Lock()
	defer control.mu.Unlock()
	require.Equal(t, 1, control.admitCount)
	require.Equal(t, 1, control.startCount)
	require.NotNil(t, control.completion)
	require.Equal(t, "client-responses-model", control.completion.Model)
	require.Equal(t, "mock-upstream-model", control.completion.UpstreamModel)
	require.Equal(t, "7", control.completion.InputTokens)
	require.Equal(t, "3", control.completion.OutputTokens)
	require.Equal(t, UsageConfirmed, control.completion.UsageState)
	require.Equal(t, "priority", control.completion.ServiceTier)
	require.Equal(t, "high", control.completion.ReasoningEffort)
	require.Equal(t, "upstream-unit-test", control.completion.UpstreamID)
	require.Equal(t, control.completion.RequestID+":usage:v2", control.completion.EventID)
	require.Zero(t, control.releaseCount)
}

func TestCloudflareHandlerMessagesNonStreamUsesMappedModelAndLifecycle(t *testing.T) {
	control := testControlPlane()
	control.account.Extra = map[string]any{openai_compat.ExtraKeyResponsesSupported: true}
	upstream := &fakeHTTPUpstream{
		contentType:  "text/event-stream",
		responseBody: openAIResponsesSSE("resp_messages", "mock-upstream-model", "message ok", 5, 2),
	}
	startBeforeNetwork := false
	upstream.beforeNetwork = func() {
		control.mu.Lock()
		defer control.mu.Unlock()
		startBeforeNetwork = control.startCount == 1
	}
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	res := serveGatewayRequest(t, handler, "/v1/messages", "sk-cloudflare-unit-test", `{"model":"client-messages-model","max_tokens":32,"messages":[{"role":"user","content":"hello"}],"output_config":{"effort":"high"},"stream":false}`)

	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	require.Equal(t, "message ok", gjson.Get(res.Body.String(), "content.0.text").String())
	require.True(t, startBeforeNetwork)
	upstream.mu.Lock()
	require.Equal(t, 1, upstream.networkCalls)
	require.Equal(t, "https://mock.upstream/v1/responses", upstream.requestURL)
	require.Equal(t, "mock-upstream-model", gjson.GetBytes(upstream.body, "model").String())
	require.True(t, gjson.GetBytes(upstream.body, "stream").Bool())
	upstream.mu.Unlock()
	control.mu.Lock()
	defer control.mu.Unlock()
	require.Equal(t, 1, control.admitCount)
	require.Equal(t, 1, control.startCount)
	require.NotNil(t, control.completion)
	require.Equal(t, "client-messages-model", control.completion.Model)
	require.Equal(t, "mock-upstream-model", control.completion.UpstreamModel)
	require.Equal(t, "5", control.completion.InputTokens)
	require.Equal(t, "2", control.completion.OutputTokens)
	require.Equal(t, UsageConfirmed, control.completion.UsageState)
	require.Equal(t, "high", control.completion.ReasoningEffort)
	require.Equal(t, "upstream-unit-test", control.completion.UpstreamID)
	require.Zero(t, control.releaseCount)
}

func TestCloudflareHandlerEmbeddingsNonStreamUsesMappedModelAndLifecycle(t *testing.T) {
	control := testControlPlane()
	responseBody := `{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]},{"object":"embedding","index":1,"embedding":[0.3,0.4]}],"model":"mock-upstream-model","usage":{"prompt_tokens":13,"total_tokens":13}}`
	upstream := &fakeHTTPUpstream{responseBody: responseBody}
	startBeforeNetwork := false
	upstream.beforeNetwork = func() {
		control.mu.Lock()
		defer control.mu.Unlock()
		startBeforeNetwork = control.startCount == 1
	}
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	res := serveGatewayRequest(t, handler, "/v1/embeddings", "sk-cloudflare-unit-test", `{"model":"client-embedding-model","input":["hello","world"],"encoding_format":"float","dimensions":256}`)

	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	require.JSONEq(t, responseBody, res.Body.String())
	require.True(t, startBeforeNetwork)
	upstream.mu.Lock()
	require.Equal(t, 1, upstream.networkCalls)
	require.Equal(t, "https://mock.upstream/v1/embeddings", upstream.requestURL)
	require.JSONEq(t, `{"model":"mock-upstream-model","input":["hello","world"],"encoding_format":"float","dimensions":256}`, string(upstream.body))
	upstream.mu.Unlock()
	control.mu.Lock()
	defer control.mu.Unlock()
	require.Equal(t, 1, control.admitCount)
	require.Equal(t, 1, control.startCount)
	require.NotNil(t, control.completion)
	require.Equal(t, OutcomeSucceeded, control.completion.Outcome)
	require.Equal(t, UsageConfirmed, control.completion.UsageState)
	require.Equal(t, "13", control.completion.InputTokens)
	require.Equal(t, "0", control.completion.OutputTokens)
	require.Equal(t, "client-embedding-model", control.completion.Model)
	require.Equal(t, "mock-upstream-model", control.completion.UpstreamModel)
	require.Zero(t, control.releaseCount)
}

func TestCloudflareHandlerEmbeddingsAliasesShareLifecycle(t *testing.T) {
	for _, path := range []string{"/v1/embeddings", "/embeddings"} {
		t.Run(path, func(t *testing.T) {
			control := testControlPlane()
			upstream := &fakeHTTPUpstream{responseBody: `{"object":"list","data":[],"usage":{"prompt_tokens":1,"total_tokens":1}}`}
			handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
			require.NoError(t, err)

			res := serveGatewayRequest(t, handler, path, "sk-cloudflare-unit-test", `{"model":"client-embedding-model","input":"hello"}`)

			require.Equal(t, http.StatusOK, res.Code, res.Body.String())
			upstream.mu.Lock()
			require.Equal(t, 1, upstream.networkCalls)
			require.Equal(t, "https://mock.upstream/v1/embeddings", upstream.requestURL)
			require.Equal(t, "mock-upstream-model", gjson.GetBytes(upstream.body, "model").String())
			upstream.mu.Unlock()
			control.mu.Lock()
			defer control.mu.Unlock()
			require.Equal(t, 1, control.admitCount)
			require.Equal(t, 1, control.startCount)
			require.NotNil(t, control.completion)
			require.Equal(t, OutcomeSucceeded, control.completion.Outcome)
			require.Equal(t, UsageConfirmed, control.completion.UsageState)
			require.Zero(t, control.releaseCount)
		})
	}
}

func TestCloudflareHandlerEmbeddingsUsagePresence(t *testing.T) {
	tests := []struct {
		name          string
		responseBody  string
		expectedState string
		expectedInput string
	}{
		{
			name:          "nonzero usage",
			responseBody:  `{"object":"list","data":[],"usage":{"prompt_tokens":7,"total_tokens":7}}`,
			expectedState: UsageConfirmed,
			expectedInput: "7",
		},
		{
			name:          "explicit all-zero usage",
			responseBody:  `{"object":"list","data":[],"usage":{"prompt_tokens":0,"total_tokens":0}}`,
			expectedState: UsageConfirmed,
			expectedInput: "0",
		},
		{
			name:          "missing usage",
			responseBody:  `{"object":"list","data":[]}`,
			expectedState: UsageUnknown,
			expectedInput: "0",
		},
		{
			name:          "malformed usage values",
			responseBody:  `{"object":"list","data":[],"usage":{"prompt_tokens":"zero","total_tokens":0}}`,
			expectedState: UsageUnknown,
			expectedInput: "0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := testControlPlane()
			upstream := &fakeHTTPUpstream{responseBody: tt.responseBody}
			handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
			require.NoError(t, err)

			res := serveGatewayRequest(t, handler, "/v1/embeddings", "sk-cloudflare-unit-test", `{"model":"client-embedding-model","input":"hello"}`)

			require.Equal(t, http.StatusOK, res.Code, res.Body.String())
			control.mu.Lock()
			defer control.mu.Unlock()
			require.NotNil(t, control.completion)
			require.Equal(t, tt.expectedState, control.completion.UsageState)
			require.Equal(t, tt.expectedInput, control.completion.InputTokens)
			require.Equal(t, "0", control.completion.OutputTokens)
		})
	}
}

func TestCloudflareHandlerEmbeddingsRejectsBeforeUpstream(t *testing.T) {
	tests := []struct {
		name       string
		apiKey     string
		body       string
		admitErr   error
		wantAdmits int
		wantStatus int
	}{
		{name: "authentication", apiKey: "wrong-key", body: `{"model":"test-model","input":"hello"}`, wantStatus: http.StatusUnauthorized},
		{name: "admission", apiKey: "sk-cloudflare-unit-test", body: `{"model":"test-model","input":"hello"}`, admitErr: ErrAdmissionRejected, wantAdmits: 1, wantStatus: http.StatusTooManyRequests},
		{name: "missing model", apiKey: "sk-cloudflare-unit-test", body: `{"input":"hello"}`, wantStatus: http.StatusBadRequest},
		{name: "invalid model", apiKey: "sk-cloudflare-unit-test", body: `{"model":7,"input":"hello"}`, wantStatus: http.StatusBadRequest},
		{name: "streaming", apiKey: "sk-cloudflare-unit-test", body: `{"model":"test-model","input":"hello","stream":true}`, wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := testControlPlane()
			control.admitErr = tt.admitErr
			upstream := &fakeHTTPUpstream{}
			handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
			require.NoError(t, err)

			res := serveGatewayRequest(t, handler, "/v1/embeddings", tt.apiKey, tt.body)

			require.Equal(t, tt.wantStatus, res.Code, res.Body.String())
			upstream.mu.Lock()
			require.Zero(t, upstream.networkCalls)
			upstream.mu.Unlock()
			control.mu.Lock()
			defer control.mu.Unlock()
			require.Equal(t, tt.wantAdmits, control.admitCount)
			require.Zero(t, control.startCount)
			require.Nil(t, control.completion)
			require.Zero(t, control.releaseCount)
		})
	}
}

func TestCloudflareHandlerEmbeddingsRejectsUnsupportedAdmissionAndReleasesLease(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*service.Account)
	}{
		{
			name: "capability",
			mutate: func(account *service.Account) {
				account.Credentials["openai_capabilities"] = []any{"chat_completions"}
			},
		},
		{
			name: "inactive",
			mutate: func(account *service.Account) {
				account.Status = service.StatusDisabled
			},
		},
		{
			name: "wrong platform",
			mutate: func(account *service.Account) {
				account.Platform = service.PlatformAnthropic
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := testControlPlane()
			tt.mutate(control.account)
			upstream := &fakeHTTPUpstream{}
			handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
			require.NoError(t, err)

			res := serveGatewayRequest(t, handler, "/v1/embeddings", "sk-cloudflare-unit-test", `{"model":"test-model","input":"hello"}`)

			require.Equal(t, http.StatusServiceUnavailable, res.Code, res.Body.String())
			upstream.mu.Lock()
			require.Zero(t, upstream.networkCalls)
			upstream.mu.Unlock()
			control.mu.Lock()
			defer control.mu.Unlock()
			require.Equal(t, 1, control.admitCount)
			require.Zero(t, control.startCount)
			require.Nil(t, control.completion)
			require.Equal(t, 1, control.releaseCount)
			require.NotNil(t, control.release)
			require.Equal(t, "lease-unit-test", control.release.LeaseID)
			require.Equal(t, "3001", control.release.AccountID)
		})
	}
}

func TestCloudflareHandlerEmbeddingsReleasesCorruptAdmissionBeforeUpstream(t *testing.T) {
	control := testControlPlane()
	control.account = nil
	upstream := &fakeHTTPUpstream{}
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	res := serveGatewayRequest(t, handler, "/v1/embeddings", "sk-cloudflare-unit-test", `{"model":"test-model","input":"hello"}`)

	require.Equal(t, http.StatusServiceUnavailable, res.Code, res.Body.String())
	upstream.mu.Lock()
	require.Zero(t, upstream.networkCalls)
	upstream.mu.Unlock()
	control.mu.Lock()
	defer control.mu.Unlock()
	require.Equal(t, 1, control.admitCount)
	require.Zero(t, control.startCount)
	require.Nil(t, control.completion)
	require.Equal(t, 1, control.releaseCount)
	require.NotNil(t, control.release)
	require.Equal(t, "lease-unit-test", control.release.LeaseID)
	require.Equal(t, "3001", control.release.AccountID)
}

func TestCloudflareHandlerEmbeddingsUpstreamFailureDoesNotRetry(t *testing.T) {
	tests := []struct {
		name           string
		responseStatus int
		responseErr    error
	}{
		{name: "rate limited", responseStatus: http.StatusTooManyRequests},
		{name: "server error", responseStatus: http.StatusBadGateway},
		{name: "transport error", responseErr: errors.New("injected transport error")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := testControlPlane()
			upstream := &fakeHTTPUpstream{
				responseStatus: tt.responseStatus,
				responseErr:    tt.responseErr,
				responseBody:   `{"error":{"message":"injected upstream error"}}`,
			}
			handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
			require.NoError(t, err)

			res := serveGatewayRequest(t, handler, "/v1/embeddings", "sk-cloudflare-unit-test", `{"model":"test-model","input":"hello"}`)

			require.Equal(t, http.StatusBadGateway, res.Code, res.Body.String())
			upstream.mu.Lock()
			require.Equal(t, 1, upstream.networkCalls)
			upstream.mu.Unlock()
			control.mu.Lock()
			defer control.mu.Unlock()
			require.Equal(t, 1, control.startCount)
			require.NotNil(t, control.completion)
			require.Equal(t, OutcomeFailed, control.completion.Outcome)
			require.Zero(t, control.releaseCount)
		})
	}
}

func TestCloudflareHandlerEmbeddingsCompletionFailureHidesBufferedResponse(t *testing.T) {
	control := testControlPlane()
	control.completionErr = errors.New("injected completion failure")
	upstream := &fakeHTTPUpstream{responseBody: `{"object":"list","data":[],"usage":{"prompt_tokens":1,"total_tokens":1}}`}
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	res := serveGatewayRequest(t, handler, "/v1/embeddings", "sk-cloudflare-unit-test", `{"model":"test-model","input":"hello"}`)

	require.Equal(t, http.StatusBadGateway, res.Code, res.Body.String())
	require.Equal(t, "api_error", gjson.Get(res.Body.String(), "error.type").String())
	require.Equal(t, "Billing settlement could not be committed", gjson.Get(res.Body.String(), "error.message").String())
	require.NotContains(t, res.Body.String(), `"object":"list"`)
	upstream.mu.Lock()
	require.Equal(t, 1, upstream.networkCalls)
	upstream.mu.Unlock()
	control.mu.Lock()
	defer control.mu.Unlock()
	require.NotNil(t, control.completion)
	require.Equal(t, 1, control.releaseCount)
}

func TestCloudflareHandlerEmbeddingsClientCancellationSettlesWithoutRetry(t *testing.T) {
	control := testControlPlane()
	upstream := &cancellableHTTPUpstream{started: make(chan struct{})}
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	requestCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(`{"model":"test-model","input":"hello"}`)).WithContext(requestCtx)
	req.Header.Set("Authorization", "Bearer sk-cloudflare-unit-test")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(res, req)
		close(done)
	}()

	select {
	case <-upstream.started:
	case <-time.After(time.Second):
		t.Fatal("upstream request did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not observe client cancellation")
	}

	require.Equal(t, http.StatusBadGateway, res.Code, res.Body.String())
	upstream.mu.Lock()
	require.Equal(t, 1, upstream.calls)
	upstream.mu.Unlock()
	control.mu.Lock()
	defer control.mu.Unlock()
	require.Equal(t, 1, control.startCount)
	require.NotNil(t, control.completion)
	require.Equal(t, OutcomeFailed, control.completion.Outcome)
	require.Zero(t, control.releaseCount, "a started request is settled by completion, not a second release")
}

func TestCloudflareHandlerEmbeddingsLeaseLossCancelsUpstreamAndSettlesOnce(t *testing.T) {
	control := testControlPlane()
	control.leaseExpiry = time.Now().Add(100 * time.Millisecond)
	control.renewErr = errors.New("injected renewal failure")
	runtime := testRuntimeConfig(t)
	runtime.LeaseTTLSeconds = 3
	handler, err := NewHandler(runtime, control, blockingHTTPUpstream{})
	require.NoError(t, err)

	started := time.Now()
	res := serveGatewayRequest(t, handler, "/v1/embeddings", "sk-cloudflare-unit-test", `{"model":"test-model","input":"hello"}`)

	require.Less(t, time.Since(started), 2500*time.Millisecond)
	require.Equal(t, http.StatusBadGateway, res.Code, res.Body.String())
	require.Equal(t, "upstream_error", gjson.Get(res.Body.String(), "error.type").String())
	control.mu.Lock()
	defer control.mu.Unlock()
	require.Equal(t, 1, control.admitCount)
	require.Equal(t, 1, control.startCount)
	require.GreaterOrEqual(t, control.renewCount, 1)
	require.NotNil(t, control.completion)
	require.Equal(t, OutcomeFailed, control.completion.Outcome)
	require.Equal(t, UsageUnknown, control.completion.UsageState)
	require.Zero(t, control.releaseCount)
}

func TestCloudflareHandlerNewProtocolsStreamAndPersistUsage(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		wantOutput string
	}{
		{
			name:       "responses",
			path:       "/v1/responses",
			body:       `{"model":"client-stream-model","input":"hello","stream":true}`,
			wantOutput: "response.completed",
		},
		{
			name:       "messages",
			path:       "/v1/messages",
			body:       `{"model":"client-stream-model","max_tokens":32,"messages":[{"role":"user","content":"hello"}],"stream":true}`,
			wantOutput: "message_stop",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := testControlPlane()
			control.account.Extra = map[string]any{openai_compat.ExtraKeyResponsesSupported: true}
			upstream := &fakeHTTPUpstream{
				contentType:  "text/event-stream",
				responseBody: openAIResponsesSSE("resp_stream", "mock-upstream-model", "stream ok", 11, 4),
			}
			handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
			require.NoError(t, err)

			res := serveGatewayRequest(t, handler, tt.path, "sk-cloudflare-unit-test", tt.body)

			require.Equal(t, http.StatusOK, res.Code, res.Body.String())
			require.Contains(t, res.Body.String(), tt.wantOutput)
			control.mu.Lock()
			defer control.mu.Unlock()
			require.Equal(t, 1, control.admitCount)
			require.Equal(t, 1, control.startCount)
			require.NotNil(t, control.completion)
			require.Equal(t, OutcomeSucceeded, control.completion.Outcome)
			require.Equal(t, UsageConfirmed, control.completion.UsageState)
			require.Equal(t, "11", control.completion.InputTokens)
			require.Equal(t, "4", control.completion.OutputTokens)
			require.Zero(t, control.releaseCount)
		})
	}
}

func TestCloudflareHandlerNewProtocolsDoNotFabricateUsage(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		requestBody    string
		responseBody   string
		contentType    string
		expectedState  string
		expectedStatus int
	}{
		{
			name:           "responses explicit all-zero usage",
			path:           "/v1/responses",
			requestBody:    `{"model":"client-model","input":"hello","stream":false}`,
			responseBody:   `{"id":"resp_zero","object":"response","status":"completed","model":"mock-upstream-model","output":[],"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}`,
			contentType:    "application/json",
			expectedState:  UsageConfirmed,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "responses missing usage",
			path:           "/v1/responses",
			requestBody:    `{"model":"client-model","input":"hello","stream":false}`,
			responseBody:   `{"id":"resp_unknown","object":"response","status":"completed","model":"mock-upstream-model","output":[]}`,
			contentType:    "application/json",
			expectedState:  UsageUnknown,
			expectedStatus: http.StatusBadGateway,
		},
		{
			name:           "messages explicit all-zero usage",
			path:           "/v1/messages",
			requestBody:    `{"model":"client-model","max_tokens":16,"messages":[{"role":"user","content":"hello"}],"stream":false}`,
			responseBody:   openAIResponsesSSE("resp_messages_zero", "mock-upstream-model", "ok", 0, 0),
			contentType:    "text/event-stream",
			expectedState:  UsageConfirmed,
			expectedStatus: http.StatusOK,
		},
		{
			name:        "messages missing usage",
			path:        "/v1/messages",
			requestBody: `{"model":"client-model","max_tokens":16,"messages":[{"role":"user","content":"hello"}],"stream":false}`,
			responseBody: strings.Join([]string{
				`data: {"type":"response.completed","response":{"id":"resp_messages_unknown","object":"response","status":"completed","model":"mock-upstream-model","output":[{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"ok"}]}]}}`,
				"data: [DONE]",
				"",
			}, "\n\n"),
			contentType:    "text/event-stream",
			expectedState:  UsageUnknown,
			expectedStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := testControlPlane()
			control.account.Extra = map[string]any{openai_compat.ExtraKeyResponsesSupported: true}
			upstream := &fakeHTTPUpstream{responseBody: tt.responseBody, contentType: tt.contentType}
			handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
			require.NoError(t, err)

			res := serveGatewayRequest(t, handler, tt.path, "sk-cloudflare-unit-test", tt.requestBody)

			require.Equal(t, tt.expectedStatus, res.Code, res.Body.String())
			control.mu.Lock()
			defer control.mu.Unlock()
			require.NotNil(t, control.completion)
			require.Equal(t, tt.expectedState, control.completion.UsageState)
			require.Equal(t, "0", control.completion.InputTokens)
			require.Equal(t, "0", control.completion.OutputTokens)
		})
	}
}

func TestCloudflareHandlerNewProtocolsBufferUntilSettlement(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		requestBody  string
		upstreamBody string
		contentType  string
		privateValue string
		wantError    string
	}{
		{
			name:         "responses",
			path:         "/v1/responses",
			requestBody:  `{"model":"client-model","input":"hello","stream":false}`,
			upstreamBody: `{"id":"resp_private","object":"response","status":"completed","model":"mock-upstream-model","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`,
			contentType:  "application/json",
			privateValue: "resp_private",
			wantError:    "BILLING_COMMIT_FAILED",
		},
		{
			name:         "messages",
			path:         "/v1/messages",
			requestBody:  `{"model":"client-model","max_tokens":16,"messages":[{"role":"user","content":"hello"}],"stream":false}`,
			upstreamBody: openAIResponsesSSE("resp_private_messages", "mock-upstream-model", "private message", 1, 1),
			contentType:  "text/event-stream",
			privateValue: "private message",
			wantError:    `"type":"api_error"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := testControlPlane()
			control.account.Extra = map[string]any{openai_compat.ExtraKeyResponsesSupported: true}
			control.completionErr = errors.New("injected completion failure")
			upstream := &fakeHTTPUpstream{responseBody: tt.upstreamBody, contentType: tt.contentType}
			handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
			require.NoError(t, err)

			res := serveGatewayRequest(t, handler, tt.path, "sk-cloudflare-unit-test", tt.requestBody)

			require.Equal(t, http.StatusBadGateway, res.Code, res.Body.String())
			require.Contains(t, res.Body.String(), tt.wantError)
			require.NotContains(t, res.Body.String(), tt.privateValue)
			control.mu.Lock()
			defer control.mu.Unlock()
			require.NotNil(t, control.completion)
			require.Equal(t, 1, control.releaseCount)
		})
	}
}

func TestCloudflareHandlerStreamingSettlementFailureDoesNotAppendProtocolError(t *testing.T) {
	control := testControlPlane()
	control.account.Extra = map[string]any{openai_compat.ExtraKeyResponsesSupported: true}
	control.completionErr = errors.New("injected completion failure")
	upstream := &fakeHTTPUpstream{
		contentType:  "text/event-stream",
		responseBody: openAIResponsesSSE("resp_visible", "mock-upstream-model", "visible", 2, 1),
	}
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	res := serveGatewayRequest(t, handler, "/v1/responses", "sk-cloudflare-unit-test", `{"model":"client-model","input":"hello","stream":true}`)

	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	require.Contains(t, res.Body.String(), "resp_visible")
	require.NotContains(t, res.Body.String(), "BILLING_COMMIT_FAILED")
	require.NotContains(t, res.Body.String(), "UPSTREAM_ERROR")
	control.mu.Lock()
	defer control.mu.Unlock()
	require.NotNil(t, control.completion)
	require.Equal(t, 1, control.releaseCount)
}

func TestCloudflareHandlerNewProtocolsRejectBeforeUpstream(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		body         string
		apiKey       string
		admissionErr error
		wantAdmits   int
		wantStatus   int
	}{
		{name: "responses authentication", path: "/v1/responses", body: `{"model":"test-model","input":"hello"}`, apiKey: "wrong-key", wantStatus: http.StatusUnauthorized},
		{name: "responses admission", path: "/v1/responses", body: `{"model":"test-model","input":"hello"}`, apiKey: "sk-cloudflare-unit-test", admissionErr: ErrAdmissionRejected, wantAdmits: 1, wantStatus: http.StatusTooManyRequests},
		{name: "messages authentication", path: "/v1/messages", body: `{"model":"test-model","max_tokens":16,"messages":[]}`, apiKey: "wrong-key", wantStatus: http.StatusUnauthorized},
		{name: "messages admission", path: "/v1/messages", body: `{"model":"test-model","max_tokens":16,"messages":[]}`, apiKey: "sk-cloudflare-unit-test", admissionErr: ErrAdmissionRejected, wantAdmits: 1, wantStatus: http.StatusTooManyRequests},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := testControlPlane()
			control.admitErr = tt.admissionErr
			upstream := &fakeHTTPUpstream{}
			handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
			require.NoError(t, err)

			res := serveGatewayRequest(t, handler, tt.path, tt.apiKey, tt.body)

			require.Equal(t, tt.wantStatus, res.Code, res.Body.String())
			upstream.mu.Lock()
			require.Zero(t, upstream.networkCalls)
			upstream.mu.Unlock()
			control.mu.Lock()
			defer control.mu.Unlock()
			require.Equal(t, tt.wantAdmits, control.admitCount)
			require.Zero(t, control.startCount)
			require.Nil(t, control.completion)
			require.Zero(t, control.releaseCount)
		})
	}
}

func TestCloudflareResponsesLeaseLossCancelsUpstreamAndSettlesOnce(t *testing.T) {
	control := testControlPlane()
	control.account.Extra = map[string]any{openai_compat.ExtraKeyResponsesSupported: true}
	control.leaseExpiry = time.Now().Add(100 * time.Millisecond)
	control.renewErr = errors.New("injected renewal failure")
	runtime := testRuntimeConfig(t)
	runtime.LeaseTTLSeconds = 3
	handler, err := NewHandler(runtime, control, blockingHTTPUpstream{})
	require.NoError(t, err)

	started := time.Now()
	res := serveGatewayRequest(t, handler, "/v1/responses", "sk-cloudflare-unit-test", `{"model":"test-model","input":"hello","stream":false}`)

	require.Less(t, time.Since(started), 2500*time.Millisecond)
	require.Equal(t, http.StatusServiceUnavailable, res.Code, res.Body.String())
	require.Contains(t, res.Body.String(), "ACCOUNT_LEASE_LOST")
	control.mu.Lock()
	defer control.mu.Unlock()
	require.Equal(t, 1, control.admitCount)
	require.Equal(t, 1, control.startCount)
	require.GreaterOrEqual(t, control.renewCount, 1)
	require.NotNil(t, control.completion)
	require.Equal(t, OutcomeFailed, control.completion.Outcome)
	require.Equal(t, UsageUnknown, control.completion.UsageState)
	require.Zero(t, control.releaseCount)
}

func TestCloudflareHandlerBlocksNetworkWhenStartMarkerFails(t *testing.T) {
	control := testControlPlane()
	control.startErr = errors.New("injected start marker failure")
	upstream := &fakeHTTPUpstream{}
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":false}`))
	req.Header.Set("Authorization", "Bearer sk-cloudflare-unit-test")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusBadGateway, res.Code, res.Body.String())
	upstream.mu.Lock()
	require.Zero(t, upstream.networkCalls)
	upstream.mu.Unlock()
	control.mu.Lock()
	defer control.mu.Unlock()
	require.Equal(t, 1, control.startCount)
	require.Nil(t, control.completion)
	require.NotNil(t, control.release)
	require.Equal(t, 1, control.releaseCount)
}

func TestCloudflareHandlerDoesNotReleaseBufferedSuccessWhenCompletionCommitFails(t *testing.T) {
	control := testControlPlane()
	control.completionErr = errors.New("injected completion commit failure")
	upstream := &fakeHTTPUpstream{}
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/chat/completions",
		strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":false}`),
	)
	req.Header.Set("Authorization", "Bearer sk-cloudflare-unit-test")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusBadGateway, res.Code, res.Body.String())
	require.Contains(t, res.Body.String(), "BILLING_COMMIT_FAILED")
	require.NotContains(t, res.Body.String(), "chatcmpl_cf")
	control.mu.Lock()
	defer control.mu.Unlock()
	require.NotNil(t, control.completion)
	require.NotNil(t, control.release)
	require.Equal(t, 1, control.releaseCount)
}

func TestCloudflareHandlerSeparatesUsagePresenceFromZeroCounters(t *testing.T) {
	tests := []struct {
		name          string
		responseBody  string
		expectedState string
	}{
		{
			name:          "present all zero",
			responseBody:  `{"id":"chatcmpl_zero","object":"chat.completion","model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`,
			expectedState: UsageConfirmed,
		},
		{
			name:          "usage absent",
			responseBody:  `{"id":"chatcmpl_absent","object":"chat.completion","model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`,
			expectedState: UsageUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := testControlPlane()
			upstream := &fakeHTTPUpstream{responseBody: tt.responseBody}
			handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":false}`))
			req.Header.Set("Authorization", "Bearer sk-cloudflare-unit-test")
			req.Header.Set("Content-Type", "application/json")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)

			require.Equal(t, http.StatusOK, res.Code, res.Body.String())
			control.mu.Lock()
			defer control.mu.Unlock()
			require.NotNil(t, control.completion)
			require.Equal(t, tt.expectedState, control.completion.UsageState)
			require.Equal(t, "0", control.completion.InputTokens)
			require.Equal(t, "0", control.completion.OutputTokens)
			require.Equal(t, "0", control.completion.CacheReadTokens)
		})
	}
}

func TestUpstreamStartMarkerIsNoopForTraditionalContext(t *testing.T) {
	upstream := &fakeHTTPUpstream{}
	req := httptest.NewRequest(http.MethodPost, "https://mock.upstream/v1/chat/completions", strings.NewReader(`{}`))
	resp, err := upstream.Do(req, "", 1, 1)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Body.Close())
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	require.Equal(t, 1, upstream.networkCalls)
}

func TestCloudflareHandlerConfirmsAllZeroResponsesUsage(t *testing.T) {
	control := testControlPlane()
	control.account.Extra = map[string]any{openai_compat.ExtraKeyResponsesSupported: true}
	upstream := &fakeHTTPUpstream{
		contentType: "text/event-stream",
		responseBody: "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_zero\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"mock-upstream-model\",\"output\":[],\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0}}}\n\n" +
			"data: [DONE]\n\n",
	}
	handler, err := NewHandler(testRuntimeConfig(t), control, upstream)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"stream":false}`))
	req.Header.Set("Authorization", "Bearer sk-cloudflare-unit-test")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	control.mu.Lock()
	defer control.mu.Unlock()
	require.NotNil(t, control.completion)
	require.Equal(t, UsageConfirmed, control.completion.UsageState)
	require.Equal(t, "0", control.completion.InputTokens)
	require.Equal(t, "0", control.completion.OutputTokens)
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
	require.Nil(t, control.release)
	require.Zero(t, control.releaseCount)
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
	require.Nil(t, control.release)
	require.Zero(t, control.releaseCount)
}
