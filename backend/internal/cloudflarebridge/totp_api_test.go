//go:build unit

package cloudflarebridge

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type totpUserControlPlane struct {
	*userAPIControlPlane

	mu               sync.Mutex
	status           CloudflareTOTPStatus
	setup            CloudflareTOTPSetup
	challenge        CloudflareTOTPLoginChallenge
	verifyLoginID    int64
	beginLoginCalls  int
	verifyLoginCalls int
	beginSetupCalls  int
	completeCalls    int
	disableCalls     int
	stepUpCalls      int
	lastSetupToken   string
	lastCode         string
	lastSessionID    string
}

func newTOTPUserControlPlane(t *testing.T) (*totpUserControlPlane, string, int64) {
	t.Helper()
	base, password, userID, _ := newUserAPIControlPlane(t)
	return &totpUserControlPlane{
		userAPIControlPlane: base,
		status:              CloudflareTOTPStatus{},
		setup: CloudflareTOTPSetup{
			Secret:     "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
			QRCodeURL:  "otpauth://totp/Sub2API:test?secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&issuer=Sub2API",
			SetupToken: strings.Repeat("b", 64),
			Countdown:  cloudflareTOTPSetupSeconds,
		},
		challenge: CloudflareTOTPLoginChallenge{
			TempToken: strconv.FormatInt(userID, 10) + "." + strings.Repeat("a", 64),
			Countdown: cloudflareTOTPSetupSeconds,
		},
		verifyLoginID: userID,
	}, password, userID
}

func (f *totpUserControlPlane) GetTOTPStatus(context.Context, int64) (*CloudflareTOTPStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status := f.status
	return &status, nil
}

func (f *totpUserControlPlane) BeginTOTPSetup(context.Context, int64) (*CloudflareTOTPSetup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beginSetupCalls++
	setup := f.setup
	return &setup, nil
}

func (f *totpUserControlPlane) CompleteTOTPSetup(_ context.Context, _ int64, setupToken, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completeCalls++
	f.lastSetupToken = setupToken
	f.lastCode = code
	return nil
}

func (f *totpUserControlPlane) DisableTOTP(context.Context, int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disableCalls++
	return nil
}

func (f *totpUserControlPlane) BeginTOTPLogin(context.Context, int64) (*CloudflareTOTPLoginChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beginLoginCalls++
	challenge := f.challenge
	return &challenge, nil
}

func (f *totpUserControlPlane) VerifyTOTPLogin(_ context.Context, tempToken, code string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifyLoginCalls++
	f.lastSetupToken = tempToken
	f.lastCode = code
	if code == "000000" {
		return 0, service.ErrTotpInvalidCode
	}
	return f.verifyLoginID, nil
}

func (f *totpUserControlPlane) VerifyTOTPStepUp(_ context.Context, _ int64, sessionID, code string) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stepUpCalls++
	f.lastSessionID = sessionID
	f.lastCode = code
	return cloudflareTOTPStepUpSeconds * time.Second, nil
}

func (f *totpUserControlPlane) HasTOTPStepUp(context.Context, int64, string) (bool, error) {
	return true, nil
}

func (f *totpUserControlPlane) RevokeTOTPTransient(context.Context, int64) error {
	return nil
}

func TestCloudflareTOTPLoginRequiresWorkerChallengeBeforeIssuingJWT(t *testing.T) {
	control, password, userID := newTOTPUserControlPlane(t)
	enabledAt := time.Now().UTC()
	control.users[userID].TotpEnabled = true
	control.users[userID].TotpEnabledAt = &enabledAt
	handler, err := NewHandler(testRuntimeConfig(t), control, &fakeHTTPUpstream{})
	require.NoError(t, err)

	login := callJSON(t, handler, http.MethodPost, "/api/v1/auth/login", "",
		`{"email":"user@example.test","password":"`+password+`"}`)
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	var challengeEnvelope struct {
		Data struct {
			Requires2FA bool   `json:"requires_2fa"`
			TempToken   string `json:"temp_token"`
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(login.Body.Bytes(), &challengeEnvelope))
	require.True(t, challengeEnvelope.Data.Requires2FA)
	require.Equal(t, control.challenge.TempToken, challengeEnvelope.Data.TempToken)
	require.Empty(t, challengeEnvelope.Data.AccessToken)
	require.Equal(t, 1, control.beginLoginCalls)

	invalidShape := callJSON(t, handler, http.MethodPost, "/api/v1/auth/login/2fa", "",
		`{"temp_token":"bad","totp_code":"123456"}`)
	require.Equal(t, http.StatusBadRequest, invalidShape.Code, invalidShape.Body.String())
	require.Equal(t, 0, control.verifyLoginCalls)
	unknownField := callJSON(t, handler, http.MethodPost, "/api/v1/auth/login/2fa", "",
		`{"temp_token":"`+control.challenge.TempToken+`","totp_code":"123456","extra":true}`)
	require.Equal(t, http.StatusBadRequest, unknownField.Code, unknownField.Body.String())
	require.Equal(t, 0, control.verifyLoginCalls)

	badCode := callJSON(t, handler, http.MethodPost, "/api/v1/auth/login/2fa", "",
		`{"temp_token":"`+control.challenge.TempToken+`","totp_code":"000000"}`)
	require.Equal(t, http.StatusBadRequest, badCode.Code, badCode.Body.String())
	require.Contains(t, badCode.Body.String(), "TOTP_INVALID_CODE")

	verified := callJSON(t, handler, http.MethodPost, "/api/v1/auth/login/2fa", "",
		`{"temp_token":"`+control.challenge.TempToken+`","totp_code":"123456"}`)
	require.Equal(t, http.StatusOK, verified.Code, verified.Body.String())
	var verifiedEnvelope struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
			TokenType    string `json:"token_type"`
			User         struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(verified.Body.Bytes(), &verifiedEnvelope))
	require.NotEmpty(t, verifiedEnvelope.Data.AccessToken)
	require.NotEmpty(t, verifiedEnvelope.Data.RefreshToken)
	require.NotZero(t, verifiedEnvelope.Data.ExpiresIn)
	require.Equal(t, "Bearer", verifiedEnvelope.Data.TokenType)
	require.Equal(t, strconv.FormatInt(userID, 10), verifiedEnvelope.Data.User.ID)

	current := callJSON(t, handler, http.MethodGet, "/api/v1/auth/me",
		verifiedEnvelope.Data.AccessToken, "")
	require.Equal(t, http.StatusOK, current.Code, current.Body.String())
}

func TestCloudflareTOTPProfileEndpointsRequirePasswordAndBindStepUpToJWT(t *testing.T) {
	control, password, userID := newTOTPUserControlPlane(t)
	handler, err := NewHandler(testRuntimeConfig(t), control, &fakeHTTPUpstream{})
	require.NoError(t, err)
	token := loginToken(t, handler, "user@example.test", password)

	method := callJSON(t, handler, http.MethodGet,
		"/api/v1/user/totp/verification-method", token, "")
	require.Equal(t, http.StatusOK, method.Code, method.Body.String())
	require.Contains(t, method.Body.String(), `"method":"password"`)
	emailCode := callJSON(t, handler, http.MethodPost,
		"/api/v1/user/totp/send-code", token, `{}`)
	require.Equal(t, http.StatusBadRequest, emailCode.Code, emailCode.Body.String())
	require.Contains(t, emailCode.Body.String(), "EMAIL_VERIFY_NOT_ENABLED")

	wrongPassword := callJSON(t, handler, http.MethodPost,
		"/api/v1/user/totp/setup", token, `{"password":"wrong"}`)
	require.Equal(t, http.StatusBadRequest, wrongPassword.Code, wrongPassword.Body.String())
	require.Equal(t, 0, control.beginSetupCalls)
	unknownField := callJSON(t, handler, http.MethodPost,
		"/api/v1/user/totp/setup", token, `{"password":"`+password+`","extra":true}`)
	require.Equal(t, http.StatusBadRequest, unknownField.Code, unknownField.Body.String())
	require.Equal(t, 0, control.beginSetupCalls)

	setup := callJSON(t, handler, http.MethodPost,
		"/api/v1/user/totp/setup", token, `{"password":"`+password+`"}`)
	require.Equal(t, http.StatusOK, setup.Code, setup.Body.String())
	require.Contains(t, setup.Body.String(), control.setup.Secret)
	require.Equal(t, 1, control.beginSetupCalls)

	enabled := callJSON(t, handler, http.MethodPost,
		"/api/v1/user/totp/enable", token,
		`{"totp_code":"123456","setup_token":"`+control.setup.SetupToken+`"}`)
	require.Equal(t, http.StatusOK, enabled.Code, enabled.Body.String())
	require.Equal(t, 1, control.completeCalls)
	require.Equal(t, control.setup.SetupToken, control.lastSetupToken)
	require.Equal(t, "123456", control.lastCode)

	stepUp := callJSON(t, handler, http.MethodPost,
		"/api/v1/user/totp/step-up", token, `{"code":"654321"}`)
	require.Equal(t, http.StatusOK, stepUp.Code, stepUp.Body.String())
	require.Contains(t, stepUp.Body.String(), `"expires_in":900`)
	require.Equal(t, 1, control.stepUpCalls)
	require.Regexp(t, `^[0-9a-f]{32}$`, control.lastSessionID)
	require.Equal(t, "654321", control.lastCode)

	wrongDisable := callJSON(t, handler, http.MethodPost,
		"/api/v1/user/totp/disable", token, `{"password":"wrong"}`)
	require.Equal(t, http.StatusBadRequest, wrongDisable.Code, wrongDisable.Body.String())
	require.Equal(t, 0, control.disableCalls)
	disabled := callJSON(t, handler, http.MethodPost,
		"/api/v1/user/totp/disable", token, `{"password":"`+password+`"}`)
	require.Equal(t, http.StatusOK, disabled.Code, disabled.Body.String())
	require.Equal(t, 1, control.disableCalls)

	control.mu.Lock()
	defer control.mu.Unlock()
	require.Equal(t, userID, control.verifyLoginID)
}
