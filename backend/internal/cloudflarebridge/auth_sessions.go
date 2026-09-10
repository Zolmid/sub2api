package cloudflarebridge

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

var (
	lowerSHA256HexPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	lowerSessionBindingHashRegex = regexp.MustCompile(`^[0-9a-f]{32}$`)
	authSessionFamilyIDPattern   = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

const authSessionTimestampLayout = "2006-01-02T15:04:05.000Z"

type authSessionWire struct {
	TokenHash    string `json:"token_hash"`
	UserID       string `json:"user_id"`
	TokenVersion string `json:"token_version"`
	FamilyID     string `json:"family_id"`
	BindingHash  string `json:"binding_hash"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
}

type authSessionRotateWire struct {
	OldTokenHash string `json:"old_token_hash"`
	TokenHash    string `json:"token_hash"`
	UserID       string `json:"user_id"`
	TokenVersion string `json:"token_version"`
	FamilyID     string `json:"family_id"`
	BindingHash  string `json:"binding_hash"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
}

func NewAuthSessionCache(control *HTTPControlPlane) service.RefreshTokenCache {
	return control
}

func (c *HTTPControlPlane) AuthSessionCache() service.RefreshTokenCache {
	return c
}

func (c *HTTPControlPlane) StoreRefreshToken(ctx context.Context, tokenHash string, data *service.RefreshTokenData, _ time.Duration) error {
	wire, err := encodeAuthSession(tokenHash, data)
	if err != nil {
		return err
	}
	return mapAuthSessionError(c.post(ctx, "/v1/auth-sessions/store", wire, nil))
}

func (c *HTTPControlPlane) GetRefreshToken(ctx context.Context, tokenHash string) (*service.RefreshTokenData, error) {
	if !isLowerSHA256Hex(tokenHash) {
		return nil, service.ErrRefreshTokenInvalid
	}
	var out struct {
		Session authSessionWire `json:"session"`
	}
	if err := c.post(ctx, "/v1/auth-sessions/get", map[string]string{"token_hash": tokenHash}, &out); err != nil {
		return nil, mapAuthSessionError(err)
	}
	return decodeAuthSession(tokenHash, out.Session)
}

func (c *HTTPControlPlane) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	if !isLowerSHA256Hex(tokenHash) {
		return service.ErrRefreshTokenInvalid
	}
	return mapAuthSessionError(c.post(ctx, "/v1/auth-sessions/delete", map[string]string{"token_hash": tokenHash}, nil))
}

func (c *HTTPControlPlane) DeleteUserRefreshTokens(ctx context.Context, userID int64) error {
	if userID < 1 {
		return service.ErrRefreshTokenInvalid
	}
	return mapAuthSessionError(c.post(ctx, "/v1/auth-sessions/revoke-user", map[string]string{"user_id": strconv.FormatInt(userID, 10)}, nil))
}

func (c *HTTPControlPlane) DeleteTokenFamily(ctx context.Context, familyID string) error {
	if !isAuthSessionFamilyID(familyID) {
		return service.ErrRefreshTokenInvalid
	}
	return mapAuthSessionError(c.post(ctx, "/v1/auth-sessions/revoke-family", map[string]string{"family_id": familyID}, nil))
}

func (c *HTTPControlPlane) AddToUserTokenSet(context.Context, int64, string, time.Duration) error {
	return nil
}

func (c *HTTPControlPlane) AddToFamilyTokenSet(context.Context, string, string, time.Duration) error {
	return nil
}

func (c *HTTPControlPlane) GetUserTokenHashes(ctx context.Context, userID int64) ([]string, error) {
	if userID < 1 {
		return nil, service.ErrRefreshTokenInvalid
	}
	var out struct {
		TokenHashes []string `json:"token_hashes"`
	}
	if err := c.post(ctx, "/v1/auth-sessions/list-user", map[string]string{"user_id": strconv.FormatInt(userID, 10)}, &out); err != nil {
		return nil, mapAuthSessionError(err)
	}
	return validateTokenHashList(out.TokenHashes)
}

func (c *HTTPControlPlane) GetFamilyTokenHashes(ctx context.Context, familyID string) ([]string, error) {
	if !isAuthSessionFamilyID(familyID) {
		return nil, service.ErrRefreshTokenInvalid
	}
	var out struct {
		TokenHashes []string `json:"token_hashes"`
	}
	if err := c.post(ctx, "/v1/auth-sessions/list-family", map[string]string{"family_id": familyID}, &out); err != nil {
		return nil, mapAuthSessionError(err)
	}
	return validateTokenHashList(out.TokenHashes)
}

func (c *HTTPControlPlane) IsTokenInFamily(ctx context.Context, familyID string, tokenHash string) (bool, error) {
	if !isAuthSessionFamilyID(familyID) || !isLowerSHA256Hex(tokenHash) {
		return false, service.ErrRefreshTokenInvalid
	}
	var out struct {
		Contains bool `json:"contains"`
	}
	if err := c.post(ctx, "/v1/auth-sessions/contains", map[string]string{"family_id": familyID, "token_hash": tokenHash}, &out); err != nil {
		return false, mapAuthSessionError(err)
	}
	return out.Contains, nil
}

func (c *HTTPControlPlane) RotateRefreshToken(ctx context.Context, oldHash, newHash string, newData *service.RefreshTokenData, _ time.Duration) error {
	if !isLowerSHA256Hex(oldHash) {
		return service.ErrRefreshTokenInvalid
	}
	wire, err := encodeAuthSession(newHash, newData)
	if err != nil {
		return err
	}
	return mapAuthSessionError(c.post(ctx, "/v1/auth-sessions/rotate", authSessionRotateWire{
		OldTokenHash: oldHash,
		TokenHash:    wire.TokenHash,
		UserID:       wire.UserID,
		TokenVersion: wire.TokenVersion,
		FamilyID:     wire.FamilyID,
		BindingHash:  wire.BindingHash,
		CreatedAt:    wire.CreatedAt,
		ExpiresAt:    wire.ExpiresAt,
	}, nil))
}

func encodeAuthSession(tokenHash string, data *service.RefreshTokenData) (authSessionWire, error) {
	if data == nil {
		return authSessionWire{}, errors.New("refresh token data is required")
	}
	createdAt := data.CreatedAt.UTC().Truncate(time.Millisecond)
	expiresAt := data.ExpiresAt.UTC().Truncate(time.Millisecond)
	if !isLowerSHA256Hex(tokenHash) ||
		data.UserID < 1 ||
		data.TokenVersion < 0 ||
		!isAuthSessionFamilyID(data.FamilyID) ||
		!isAuthSessionBindingHash(data.BindingHash) ||
		createdAt.IsZero() || expiresAt.IsZero() || !expiresAt.After(createdAt) {
		return authSessionWire{}, service.ErrRefreshTokenInvalid
	}
	return authSessionWire{
		TokenHash:    tokenHash,
		UserID:       strconv.FormatInt(data.UserID, 10),
		TokenVersion: strconv.FormatInt(data.TokenVersion, 10),
		FamilyID:     data.FamilyID,
		BindingHash:  data.BindingHash,
		CreatedAt:    createdAt.Format(authSessionTimestampLayout),
		ExpiresAt:    expiresAt.Format(authSessionTimestampLayout),
	}, nil
}

func decodeAuthSession(expectedHash string, wire authSessionWire) (*service.RefreshTokenData, error) {
	userID, err := parsePositiveID("auth session user id", wire.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid auth session response: %w", err)
	}
	tokenVersion, err := parseCanonicalInt64("auth session token version", wire.TokenVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid auth session response: %w", err)
	}
	if tokenVersion < 0 {
		return nil, errors.New("invalid auth session response")
	}
	createdAt, err := requiredAuthSessionUTCTime("auth session creation timestamp", wire.CreatedAt)
	if err != nil {
		return nil, err
	}
	expiresAt, err := requiredAuthSessionUTCTime("auth session expiry timestamp", wire.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if wire.TokenHash != expectedHash ||
		!isLowerSHA256Hex(wire.TokenHash) ||
		!isAuthSessionFamilyID(wire.FamilyID) ||
		!isAuthSessionBindingHash(wire.BindingHash) ||
		!expiresAt.After(createdAt) {
		return nil, errors.New("invalid auth session response")
	}
	return &service.RefreshTokenData{
		UserID:       userID,
		TokenVersion: tokenVersion,
		FamilyID:     wire.FamilyID,
		BindingHash:  wire.BindingHash,
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt,
	}, nil
}

func validateTokenHashList(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !isLowerSHA256Hex(value) {
			return nil, errors.New("invalid auth session response")
		}
		if _, exists := seen[value]; exists {
			return nil, errors.New("invalid auth session response")
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, nil
}

func mapAuthSessionError(err error) error {
	if err == nil {
		return nil
	}
	var responseErr *controlPlaneResponseError
	if !errors.As(err, &responseErr) {
		return err
	}
	switch responseErr.Code {
	case "AUTH_SESSION_NOT_FOUND":
		return service.ErrRefreshTokenNotFound
	case "AUTH_SESSION_EXPIRED":
		return service.ErrRefreshTokenExpired
	case "AUTH_SESSION_REVOKED":
		return service.ErrTokenRevoked
	case "AUTH_SESSION_REUSE", "AUTH_SESSION_CONFLICT":
		return service.ErrRefreshTokenReused
	case "AUTH_SESSION_UNAVAILABLE", "INVALID_REQUEST", "INTERNAL_ERROR":
		return ErrControlPlaneUnavailable
	default:
		return ErrControlPlaneUnavailable
	}
}

func requiredAuthSessionUTCTime(label, raw string) (time.Time, error) {
	parsed, err := time.Parse(authSessionTimestampLayout, raw)
	if err != nil || parsed.Format(authSessionTimestampLayout) != raw {
		return time.Time{}, fmt.Errorf("invalid %s", label)
	}
	return parsed, nil
}

func parseCanonicalInt64(label, raw string) (int64, error) {
	if !isCanonicalInt64Decimal(raw) {
		return 0, fmt.Errorf("invalid %s", label)
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s", label)
	}
	return value, nil
}

func isCanonicalInt64Decimal(value string) bool {
	if value == "" {
		return false
	}
	if value[0] == '-' {
		if len(value) == 1 || value[1] == '0' {
			return false
		}
		value = value[1:]
	}
	if len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func isLowerSHA256Hex(value string) bool {
	return lowerSHA256HexPattern.MatchString(value)
}

func isAuthSessionBindingHash(value string) bool {
	return value == "" || lowerSessionBindingHashRegex.MatchString(value)
}

func isAuthSessionFamilyID(value string) bool {
	return authSessionFamilyIDPattern.MatchString(value)
}

var _ service.RefreshTokenCache = (*HTTPControlPlane)(nil)
var _ service.RefreshTokenRotator = (*HTTPControlPlane)(nil)
