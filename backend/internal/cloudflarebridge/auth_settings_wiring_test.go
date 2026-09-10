//go:build unit

package cloudflarebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

// Run each settings scenario in a fresh test process. SettingService's
// backend-mode cache is intentionally process-wide in production; isolating
// deterministic fake repositories here avoids tests teaching each other a
// cached value while preserving the production cache semantics.
func TestCloudflareAuthSettingsWiring(t *testing.T) {
	scenario := os.Getenv("SUB2API_CF_AUTH_SETTINGS_SCENARIO")
	if scenario == "" {
		for _, childScenario := range []string{"http", "outage", "backend", "binding"} {
			cmd := exec.Command(os.Args[0], "-test.run=^TestCloudflareAuthSettingsWiring$")
			cmd.Env = append(os.Environ(), "SUB2API_CF_AUTH_SETTINGS_SCENARIO="+childScenario)
			output, err := cmd.CombinedOutput()
			require.NoErrorf(t, err, "scenario %s failed:\n%s", childScenario, output)
		}
		return
	}

	switch scenario {
	case "http":
		testHTTPControlPlaneSettingsComposition(t)
	case "outage":
		testSettingsOutagePublicOverlay(t)
	case "backend":
		testBackendModeAuthComposition(t)
	case "binding":
		testSessionBindingComposition(t)
	default:
		t.Fatalf("unknown settings scenario %q", scenario)
	}
}

type missingSettingsControlPlane struct{ ControlPlane }

func testHTTPControlPlaneSettingsComposition(t *testing.T) {
	t.Helper()

	missing, err := NewHandler(testRuntimeConfig(t), missingSettingsControlPlane{ControlPlane: testControlPlane()}, &fakeHTTPUpstream{})
	require.Nil(t, missing)
	require.EqualError(t, err, "cloudflare settings repository is required")

	var settingsReads int
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/private/settings/get-value", r.URL.Path)
		require.Equal(t, ProtocolVersion, r.Header.Get("X-Sub2API-Bridge-Version"))
		settingsReads++
		_, _ = w.Write([]byte(`"true"`))
	}))
	defer worker.Close()

	control, err := NewHTTPControlPlane(worker.URL, worker.Client())
	require.NoError(t, err)
	handler, err := NewHandler(testRuntimeConfig(t), control, &fakeHTTPUpstream{})
	require.NoError(t, err)
	public := callJSON(t, handler, http.MethodGet, "/api/v1/settings/public", "", "")
	require.Equal(t, http.StatusOK, public.Code, public.Body.String())
	require.Equal(t, 1, settingsReads, "production NewHandler must read via the HTTP settings adapter")
	require.Contains(t, public.Body.String(), `"backend_mode_enabled":true`)
}

func testSettingsOutagePublicOverlay(t *testing.T) {
	t.Helper()
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/private/settings/get-value", r.URL.Path)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"SETTINGS_UNAVAILABLE","message":"private detail"}}`))
	}))
	defer worker.Close()
	control, err := NewHTTPControlPlane(worker.URL, worker.Client())
	require.NoError(t, err)
	handler, err := NewHandler(testRuntimeConfig(t), control, &fakeHTTPUpstream{})
	require.NoError(t, err)
	public := callJSON(t, handler, http.MethodGet, "/api/v1/settings/public", "", "")
	require.Equal(t, http.StatusOK, public.Code, public.Body.String())
	require.Contains(t, public.Body.String(), `"backend_mode_enabled":false`)
	require.NotContains(t, public.Body.String(), "private detail")
}

func testBackendModeAuthComposition(t *testing.T) {
	t.Helper()
	control, password, userID := newTOTPUserControlPlane(t)
	require.NoError(t, control.settings.Set(context.Background(), service.SettingKeyBackendModeEnabled, "true"))
	runtime := testRuntimeConfig(t)
	handler, err := NewHandler(runtime, control, &fakeHTTPUpstream{})
	require.NoError(t, err)

	public := callJSON(t, handler, http.MethodGet, "/api/v1/settings/public", "", "")
	require.Contains(t, public.Body.String(), `"backend_mode_enabled":true`)
	settings := service.NewSettingService(control.settings, runtime.Application)
	injected, err := newCloudflareUserAPIHandler(nil, nil, nil, nil, settings).GetPublicSettingsForInjection(context.Background())
	require.NoError(t, err)
	require.True(t, injected.(dto.PublicSettings).BackendModeEnabled)

	control.mu.Lock()
	control.users[userID].TotpEnabled = true
	control.users[userID].Role = service.RoleUser
	control.mu.Unlock()
	userLogin := cloudflareSettingsRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"email":"user@example.test","password":"`+password+`"}`, "ua-one", "198.51.100.8:1234", "")
	require.Equal(t, http.StatusForbidden, userLogin.Code, userLogin.Body.String())
	require.NotContains(t, userLogin.Body.String(), "temp_token")
	require.NotContains(t, userLogin.Body.String(), "access_token")

	control.mu.Lock()
	control.users[userID].Role = service.RoleAdmin
	control.mu.Unlock()
	adminLogin := cloudflareSettingsRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"email":"user@example.test","password":"`+password+`"}`, "ua-one", "198.51.100.8:1234", "")
	require.Equal(t, http.StatusOK, adminLogin.Code, adminLogin.Body.String())
	challenge := cloudflareChallenge(t, adminLogin.Body.Bytes())

	control.mu.Lock()
	control.users[userID].Role = service.RoleUser
	control.mu.Unlock()
	staleRole := cloudflareSettingsRequest(t, handler, http.MethodPost, "/api/v1/auth/login/2fa", `{"temp_token":"`+challenge+`","totp_code":"123456"}`, "ua-one", "198.51.100.8:1234", "")
	require.Equal(t, http.StatusForbidden, staleRole.Code, staleRole.Body.String())

	control.mu.Lock()
	control.users[userID].Role = service.RoleAdmin
	control.mu.Unlock()
	adminLogin = cloudflareSettingsRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"email":"user@example.test","password":"`+password+`"}`, "ua-one", "198.51.100.8:1234", "")
	pair := cloudflareTokenPair(t, cloudflareSettingsRequest(t, handler, http.MethodPost, "/api/v1/auth/login/2fa", `{"temp_token":"`+cloudflareChallenge(t, adminLogin.Body.Bytes())+`","totp_code":"123456"}`, "ua-one", "198.51.100.8:1234", "").Body.Bytes())
	require.NotEmpty(t, pair.Access)
	require.NotEmpty(t, pair.Refresh)
	require.Equal(t, http.StatusOK, cloudflareSettingsRequest(t, handler, http.MethodGet, "/api/v1/admin/users", "", "ua-one", "198.51.100.8:1234", pair.Access).Code)

	control.mu.Lock()
	control.users[userID].Role = service.RoleUser
	control.mu.Unlock()
	rotatedDenied := cloudflareSettingsRequest(t, handler, http.MethodPost, "/api/v1/auth/refresh", `{"refresh_token":"`+pair.Refresh+`"}`, "ua-one", "198.51.100.8:1234", "")
	require.Equal(t, http.StatusForbidden, rotatedDenied.Code, rotatedDenied.Body.String())

	user := resolvedTestUser(control.users[userID])
	auth := service.NewAuthService(nil, NewAuthUserRepository(control), nil, control, runtime.Application, settings, nil, nil, nil, nil, nil, nil, nil)
	userToken, err := auth.GenerateToken(context.Background(), user)
	require.NoError(t, err)
	selfService := cloudflareSettingsRequest(t, handler, http.MethodGet, "/api/v1/auth/me", "", "ua-one", "198.51.100.8:1234", userToken)
	require.Equal(t, http.StatusForbidden, selfService.Code, selfService.Body.String())
}

func testSessionBindingComposition(t *testing.T) {
	t.Helper()
	control, password, _, _ := newUserAPIControlPlane(t)
	require.NoError(t, control.settings.Set(context.Background(), service.SettingKeySessionBindingEnabled, "true"))
	handler, err := NewHandler(testRuntimeConfig(t), control, &fakeHTTPUpstream{})
	require.NoError(t, err)

	pair := cloudflareTokenPair(t, cloudflareSettingsRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"email":"user@example.test","password":"`+password+`"}`, "ua-one", "198.51.100.9:1234", "").Body.Bytes())
	sameBinding := cloudflareSettingsRequest(t, handler, http.MethodGet, "/api/v1/auth/me", "", "ua-one", "198.51.100.9:1234", pair.Access)
	require.Equal(t, http.StatusOK, sameBinding.Code, sameBinding.Body.String())

	changedUA := cloudflareSettingsRequest(t, handler, http.MethodGet, "/api/v1/auth/me", "", "ua-two", "198.51.100.9:1234", pair.Access)
	require.Equal(t, http.StatusUnauthorized, changedUA.Code, changedUA.Body.String())
	revokedRefresh := cloudflareSettingsRequest(t, handler, http.MethodPost, "/api/v1/auth/refresh", `{"refresh_token":"`+pair.Refresh+`"}`, "ua-one", "198.51.100.9:1234", "")
	require.Equal(t, http.StatusUnauthorized, revokedRefresh.Code, revokedRefresh.Body.String())

	pair = cloudflareTokenPair(t, cloudflareSettingsRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"email":"user@example.test","password":"`+password+`"}`, "ua-one", "198.51.100.9:1234", "").Body.Bytes())
	changedIP := cloudflareSettingsRequest(t, handler, http.MethodGet, "/api/v1/auth/me", "", "ua-one", "198.51.100.10:1234", pair.Access)
	require.Equal(t, http.StatusUnauthorized, changedIP.Code, changedIP.Body.String())
}

type cloudflareTokens struct {
	Access  string
	Refresh string
}

func cloudflareSettingsRequest(t *testing.T, handler http.Handler, method, path, body, userAgent, remoteAddress, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.RemoteAddr = remoteAddress
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func cloudflareChallenge(t *testing.T, body []byte) string {
	t.Helper()
	var envelope struct {
		Data struct {
			TempToken string `json:"temp_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope), string(body))
	require.NotEmpty(t, envelope.Data.TempToken, string(body))
	return envelope.Data.TempToken
}

func cloudflareTokenPair(t *testing.T, body []byte) cloudflareTokens {
	t.Helper()
	var envelope struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope), string(body))
	require.NotEmpty(t, envelope.Data.AccessToken, string(body))
	require.NotEmpty(t, envelope.Data.RefreshToken, string(body))
	return cloudflareTokens{Access: envelope.Data.AccessToken, Refresh: envelope.Data.RefreshToken}
}
