package cloudflarebridge

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

const (
	cloudflareTOTPSetupSeconds  = 300
	cloudflareTOTPStepUpSeconds = 900
)

var (
	cloudflareTOTPSecretPattern = regexp.MustCompile(`^[A-Z2-7]{32}$`)
	cloudflareTOTPTokenPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	cloudflareTOTPLoginPattern  = regexp.MustCompile(`^[1-9][0-9]{0,19}\.[0-9a-f]{64}$`)
	cloudflareTOTPCodePattern   = regexp.MustCompile(`^[0-9]{6}$`)

	errCloudflareTOTPLoginExpired = infraerrors.BadRequest("TOTP_LOGIN_EXPIRED", "invalid or expired 2FA session")
	errCloudflareTOTPConflict     = infraerrors.Conflict("TOTP_STATE_CONFLICT", "totp state changed; retry the operation")
	errCloudflareTOTPUnavailable  = infraerrors.ServiceUnavailable("TOTP_UNAVAILABLE", "totp verification service unavailable")
	errCloudflareEmailUnavailable = infraerrors.BadRequest("EMAIL_VERIFY_NOT_ENABLED", "email verification is not enabled")
)

type CloudflareTOTPStatus struct {
	Enabled   bool
	EnabledAt *time.Time
	Revision  int64
}

type CloudflareTOTPSetup struct {
	Secret     string
	QRCodeURL  string
	SetupToken string
	Countdown  int
}

type CloudflareTOTPLoginChallenge struct {
	TempToken string
	Countdown int
}

// TOTPControlPlane keeps TOTP plaintext out of D1 and the Container's durable
// environment. The only plaintext returned by the Worker is the one-time setup
// response intentionally shown to the authenticated user.
type TOTPControlPlane interface {
	GetTOTPStatus(context.Context, int64) (*CloudflareTOTPStatus, error)
	BeginTOTPSetup(context.Context, int64) (*CloudflareTOTPSetup, error)
	CompleteTOTPSetup(context.Context, int64, string, string) error
	DisableTOTP(context.Context, int64) error
	BeginTOTPLogin(context.Context, int64) (*CloudflareTOTPLoginChallenge, error)
	VerifyTOTPLogin(context.Context, string, string) (int64, error)
	VerifyTOTPStepUp(context.Context, int64, string, string) (time.Duration, error)
	HasTOTPStepUp(context.Context, int64, string) (bool, error)
	RevokeTOTPTransient(context.Context, int64) error
}

func mapTOTPControlError(err error) error {
	if err == nil {
		return nil
	}
	var responseErr *controlPlaneResponseError
	if !errors.As(err, &responseErr) {
		return err
	}
	switch responseErr.Code {
	case "NOT_FOUND":
		return service.ErrUserNotFound
	case "TOTP_ALREADY_ENABLED":
		return service.ErrTotpAlreadyEnabled
	case "TOTP_NOT_SETUP":
		return service.ErrTotpNotSetup
	case "TOTP_SETUP_EXPIRED":
		return service.ErrTotpSetupExpired
	case "TOTP_INVALID_CODE":
		return service.ErrTotpInvalidCode
	case "TOTP_TOO_MANY_ATTEMPTS":
		return service.ErrTotpTooManyAttempts
	case "TOTP_LOGIN_EXPIRED":
		return errCloudflareTOTPLoginExpired
	case "TOTP_STATE_CONFLICT":
		return errCloudflareTOTPConflict
	case "TOTP_UNAVAILABLE", "CONTROL_PLANE_UNAVAILABLE":
		return errCloudflareTOTPUnavailable
	default:
		return err
	}
}

type totpStatusWire struct {
	Enabled   bool    `json:"enabled"`
	EnabledAt *string `json:"enabled_at"`
	Revision  int64   `json:"revision"`
}

func (c *HTTPControlPlane) GetTOTPStatus(ctx context.Context, userID int64) (*CloudflareTOTPStatus, error) {
	var wire totpStatusWire
	if err := c.post(ctx, "/v1/private/totp/status", map[string]string{
		"user_id": strconv.FormatInt(userID, 10),
	}, &wire); err != nil {
		return nil, mapTOTPControlError(err)
	}
	if wire.Revision < 0 || wire.Enabled != (wire.EnabledAt != nil) {
		return nil, ErrControlPlaneUnavailable
	}
	var enabledAt *time.Time
	if wire.EnabledAt != nil {
		parsed, err := requiredWireTime("totp enabled timestamp", *wire.EnabledAt)
		if err != nil {
			return nil, ErrControlPlaneUnavailable
		}
		enabledAt = &parsed
	}
	return &CloudflareTOTPStatus{
		Enabled: wire.Enabled, EnabledAt: enabledAt, Revision: wire.Revision,
	}, nil
}

func (c *HTTPControlPlane) BeginTOTPSetup(ctx context.Context, userID int64) (*CloudflareTOTPSetup, error) {
	var wire struct {
		Secret     string `json:"secret"`
		QRCodeURL  string `json:"qr_code_url"`
		SetupToken string `json:"setup_token"`
		Countdown  int    `json:"countdown"`
	}
	if err := c.post(ctx, "/v1/private/totp/setup/begin", map[string]string{
		"user_id": strconv.FormatInt(userID, 10),
	}, &wire); err != nil {
		return nil, mapTOTPControlError(err)
	}
	if !cloudflareTOTPSecretPattern.MatchString(wire.Secret) ||
		!cloudflareTOTPTokenPattern.MatchString(wire.SetupToken) ||
		wire.Countdown != cloudflareTOTPSetupSeconds ||
		len(wire.QRCodeURL) < 32 || len(wire.QRCodeURL) > 1024 ||
		!strings.HasPrefix(wire.QRCodeURL, "otpauth://totp/") ||
		!strings.Contains(wire.QRCodeURL, "secret="+wire.Secret) {
		return nil, ErrControlPlaneUnavailable
	}
	return &CloudflareTOTPSetup{
		Secret: wire.Secret, QRCodeURL: wire.QRCodeURL,
		SetupToken: wire.SetupToken, Countdown: wire.Countdown,
	}, nil
}

func (c *HTTPControlPlane) CompleteTOTPSetup(ctx context.Context, userID int64, setupToken, code string) error {
	err := c.post(ctx, "/v1/private/totp/setup/complete", map[string]string{
		"user_id": strconv.FormatInt(userID, 10), "setup_token": setupToken, "totp_code": code,
	}, nil)
	return mapTOTPControlError(err)
}

func (c *HTTPControlPlane) DisableTOTP(ctx context.Context, userID int64) error {
	err := c.post(ctx, "/v1/private/totp/disable", map[string]string{
		"user_id": strconv.FormatInt(userID, 10),
	}, nil)
	return mapTOTPControlError(err)
}

func (c *HTTPControlPlane) BeginTOTPLogin(ctx context.Context, userID int64) (*CloudflareTOTPLoginChallenge, error) {
	var wire struct {
		TempToken string `json:"temp_token"`
		Countdown int    `json:"countdown"`
	}
	if err := c.post(ctx, "/v1/private/totp/login/begin", map[string]string{
		"user_id": strconv.FormatInt(userID, 10),
	}, &wire); err != nil {
		return nil, mapTOTPControlError(err)
	}
	prefix := strconv.FormatInt(userID, 10) + "."
	if wire.Countdown != cloudflareTOTPSetupSeconds ||
		!strings.HasPrefix(wire.TempToken, prefix) ||
		!cloudflareTOTPTokenPattern.MatchString(strings.TrimPrefix(wire.TempToken, prefix)) {
		return nil, ErrControlPlaneUnavailable
	}
	return &CloudflareTOTPLoginChallenge{TempToken: wire.TempToken, Countdown: wire.Countdown}, nil
}

func (c *HTTPControlPlane) VerifyTOTPLogin(ctx context.Context, tempToken, code string) (int64, error) {
	var wire struct {
		UserID string `json:"user_id"`
	}
	if err := c.post(ctx, "/v1/private/totp/login/verify", map[string]string{
		"temp_token": tempToken, "totp_code": code,
	}, &wire); err != nil {
		return 0, mapTOTPControlError(err)
	}
	userID, err := parsePositiveID("totp user id", wire.UserID)
	if err != nil || !strings.HasPrefix(tempToken, wire.UserID+".") {
		return 0, ErrControlPlaneUnavailable
	}
	return userID, nil
}

func (c *HTTPControlPlane) VerifyTOTPStepUp(ctx context.Context, userID int64, sessionID, code string) (time.Duration, error) {
	var wire struct {
		ExpiresIn int64 `json:"expires_in"`
	}
	if err := c.post(ctx, "/v1/private/totp/step-up/verify", map[string]string{
		"user_id": strconv.FormatInt(userID, 10), "session_id": sessionID, "totp_code": code,
	}, &wire); err != nil {
		return 0, mapTOTPControlError(err)
	}
	if wire.ExpiresIn != cloudflareTOTPStepUpSeconds {
		return 0, ErrControlPlaneUnavailable
	}
	return time.Duration(wire.ExpiresIn) * time.Second, nil
}

func (c *HTTPControlPlane) HasTOTPStepUp(ctx context.Context, userID int64, sessionID string) (bool, error) {
	var wire struct {
		Granted *bool `json:"granted"`
	}
	if err := c.post(ctx, "/v1/private/totp/step-up/check", map[string]string{
		"user_id": strconv.FormatInt(userID, 10), "session_id": sessionID,
	}, &wire); err != nil {
		return false, mapTOTPControlError(err)
	}
	if wire.Granted == nil {
		return false, ErrControlPlaneUnavailable
	}
	return *wire.Granted, nil
}

func (c *HTTPControlPlane) RevokeTOTPTransient(ctx context.Context, userID int64) error {
	err := c.post(ctx, "/v1/private/totp/revoke", map[string]string{
		"user_id": strconv.FormatInt(userID, 10),
	}, nil)
	return mapTOTPControlError(err)
}

type cloudflareTOTPHandler struct {
	control   TOTPControlPlane
	authUsers *AuthUserRepository
}

func newCloudflareTOTPHandler(control ControlPlane, authUsers *AuthUserRepository) (*cloudflareTOTPHandler, error) {
	totp, ok := control.(TOTPControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return &cloudflareTOTPHandler{control: totp, authUsers: authUsers}, nil
}

func (h *cloudflareTOTPHandler) currentUser(c *gin.Context) (*service.User, bool) {
	subject, ok := authenticatedCloudflareUser(c)
	if !ok {
		return nil, false
	}
	user, err := h.authUsers.GetByID(c.Request.Context(), subject.UserID)
	if err != nil || !user.IsActive() {
		response.Unauthorized(c, "User not authenticated")
		return nil, false
	}
	return user, true
}

func (h *cloudflareTOTPHandler) verifyPassword(c *gin.Context, password string) (*service.User, bool) {
	user, ok := h.currentUser(c)
	if !ok {
		return nil, false
	}
	if password == "" {
		response.ErrorFrom(c, service.ErrPasswordRequired)
		return nil, false
	}
	if !user.CheckPassword(password) {
		response.ErrorFrom(c, service.ErrPasswordIncorrect)
		return nil, false
	}
	return user, true
}

func (h *cloudflareTOTPHandler) GetStatus(c *gin.Context) {
	user, ok := h.currentUser(c)
	if !ok {
		return
	}
	status, err := h.control.GetTOTPStatus(c.Request.Context(), user.ID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	var enabledAt *int64
	if status.EnabledAt != nil {
		value := status.EnabledAt.Unix()
		enabledAt = &value
	}
	response.Success(c, gin.H{
		"enabled": status.Enabled, "enabled_at": enabledAt, "feature_enabled": true,
	})
}

func (h *cloudflareTOTPHandler) GetVerificationMethod(c *gin.Context) {
	if _, ok := h.currentUser(c); !ok {
		return
	}
	response.Success(c, gin.H{"method": "password"})
}

func (h *cloudflareTOTPHandler) SendVerifyCode(c *gin.Context) {
	if _, ok := h.currentUser(c); !ok {
		return
	}
	response.ErrorFrom(c, errCloudflareEmailUnavailable)
}

type cloudflareTOTPPasswordRequest struct {
	EmailCode string `json:"email_code"`
	Password  string `json:"password"`
}

func (h *cloudflareTOTPHandler) InitiateSetup(c *gin.Context) {
	var request cloudflareTOTPPasswordRequest
	if err := decodeCloudflareJSON(c, &request); err != nil {
		response.BadRequest(c, "Invalid request")
		return
	}
	user, ok := h.verifyPassword(c, request.Password)
	if !ok {
		return
	}
	setup, err := h.control.BeginTOTPSetup(c.Request.Context(), user.ID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{
		"secret": setup.Secret, "qr_code_url": setup.QRCodeURL,
		"setup_token": setup.SetupToken, "countdown": setup.Countdown,
	})
}

type cloudflareTOTPEnableRequest struct {
	TOTPCode   string `json:"totp_code"`
	SetupToken string `json:"setup_token"`
}

func (h *cloudflareTOTPHandler) Enable(c *gin.Context) {
	user, ok := h.currentUser(c)
	if !ok {
		return
	}
	var request cloudflareTOTPEnableRequest
	if err := decodeCloudflareJSON(c, &request); err != nil ||
		!cloudflareTOTPCodePattern.MatchString(request.TOTPCode) ||
		!cloudflareTOTPTokenPattern.MatchString(request.SetupToken) {
		response.BadRequest(c, "Invalid request")
		return
	}
	if err := h.control.CompleteTOTPSetup(
		c.Request.Context(), user.ID, request.SetupToken, request.TOTPCode,
	); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"success": true})
}

func (h *cloudflareTOTPHandler) Disable(c *gin.Context) {
	var request cloudflareTOTPPasswordRequest
	if err := decodeCloudflareJSON(c, &request); err != nil {
		response.BadRequest(c, "Invalid request")
		return
	}
	user, ok := h.verifyPassword(c, request.Password)
	if !ok {
		return
	}
	if err := h.control.DisableTOTP(c.Request.Context(), user.ID); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"success": true})
}

type cloudflareTOTPStepUpRequest struct {
	Code string `json:"code"`
}

func (h *cloudflareTOTPHandler) StepUp(c *gin.Context) {
	user, ok := h.currentUser(c)
	if !ok {
		return
	}
	var request cloudflareTOTPStepUpRequest
	if err := decodeCloudflareJSON(c, &request); err != nil ||
		!cloudflareTOTPCodePattern.MatchString(request.Code) {
		response.BadRequest(c, "TOTP code is required")
		return
	}
	sessionID := c.GetString(middleware2.ContextKeySessionID)
	if len(sessionID) < 8 {
		response.Unauthorized(c, "Session-bound authentication required")
		return
	}
	ttl, err := h.control.VerifyTOTPStepUp(
		c.Request.Context(), user.ID, sessionID, request.Code,
	)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"verified": true, "expires_in": int64(ttl.Seconds())})
}

func (h *cloudflareTOTPHandler) HasStepUpGrant(ctx context.Context, userID int64, sessionID string) (bool, error) {
	if userID < 1 || len(sessionID) < 8 {
		return false, fmt.Errorf("invalid step-up identity")
	}
	return h.control.HasTOTPStepUp(ctx, userID, sessionID)
}

var _ TOTPControlPlane = (*HTTPControlPlane)(nil)
