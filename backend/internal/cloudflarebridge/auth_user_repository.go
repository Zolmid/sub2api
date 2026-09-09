package cloudflarebridge

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// AuthUserControlPlane is deliberately separate from management reads because
// its response contains a password verifier. It is only used inside the
// Container for login and JWT revocation checks.
type AuthUserControlPlane interface {
	GetAuthUserByID(context.Context, int64) (*service.User, error)
	GetAuthUserByEmail(context.Context, string) (*service.User, error)
}

type AuthUserRepository struct {
	control ControlPlane
}

func NewAuthUserRepository(control ControlPlane) *AuthUserRepository {
	return &AuthUserRepository{control: control}
}

func (r *AuthUserRepository) auth() (AuthUserControlPlane, error) {
	auth, ok := r.control.(AuthUserControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return auth, nil
}

func (r *AuthUserRepository) GetByID(ctx context.Context, id int64) (*service.User, error) {
	auth, err := r.auth()
	if err != nil {
		return nil, err
	}
	return auth.GetAuthUserByID(ctx, id)
}

func (r *AuthUserRepository) GetByEmail(ctx context.Context, email string) (*service.User, error) {
	auth, err := r.auth()
	if err != nil {
		return nil, err
	}
	return auth.GetAuthUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
}

func (*AuthUserRepository) Create(context.Context, *service.User) error {
	return ErrNotMigrated
}

func (*AuthUserRepository) CreateWithEmailAliasGuard(context.Context, *service.User) error {
	return ErrNotMigrated
}

func (*AuthUserRepository) Update(context.Context, *service.User, service.UserUpdateFields) error {
	return ErrNotMigrated
}

func (*AuthUserRepository) Delete(context.Context, int64) error {
	return ErrNotMigrated
}

func (*AuthUserRepository) ExistsByEmail(context.Context, string) (bool, error) {
	return false, ErrNotMigrated
}

func (*AuthUserRepository) ExistsByEmailAlias(context.Context, string) (bool, error) {
	return false, ErrNotMigrated
}

// GetFirstAdmin exists solely to satisfy middleware.AdminUserReader. The
// Cloudflare slice has no settings persistence, so admin API-key
// authentication must fail closed and must not select an administrator.
func (*AuthUserRepository) GetFirstAdmin(context.Context) (*service.User, error) {
	return nil, ErrNotMigrated
}

type authUserWire struct {
	ID                   string   `json:"id"`
	Email                string   `json:"email"`
	Username             string   `json:"username"`
	PasswordHash         string   `json:"password_hash"`
	Status               string   `json:"status"`
	Role                 string   `json:"role"`
	Concurrency          int      `json:"concurrency"`
	RPMLimit             int      `json:"rpm_limit"`
	BalanceE8USD         string   `json:"balance_e8_usd"`
	AllowedGroupIDs      []string `json:"allowed_group_ids"`
	RestrictPublicGroups bool     `json:"restrict_public_groups"`
	CreatedAt            string   `json:"created_at"`
	UpdatedAt            string   `json:"updated_at"`
	TotpEnabled          bool     `json:"totp_enabled"`
	TotpEnabledAt        *string  `json:"totp_enabled_at"`
	TotpRevision         int64    `json:"totp_revision"`
}

func decodeAuthUser(wire authUserWire) (*service.User, error) {
	id, err := parsePositiveID("auth user id", wire.ID)
	if err != nil {
		return nil, err
	}
	createdAt, err := requiredWireTime("auth user creation timestamp", wire.CreatedAt)
	if err != nil {
		return nil, err
	}
	updatedAt, err := requiredWireTime("auth user update timestamp", wire.UpdatedAt)
	if err != nil {
		return nil, err
	}
	var totpEnabledAt *time.Time
	if wire.TotpEnabledAt != nil {
		parsed, parseErr := requiredWireTime("auth user totp enabled timestamp", *wire.TotpEnabledAt)
		if parseErr != nil {
			return nil, parseErr
		}
		totpEnabledAt = &parsed
	}
	normalizedEmail := strings.ToLower(strings.TrimSpace(wire.Email))
	if normalizedEmail == "" || len(wire.Email) > 255 || len(utf16.Encode([]rune(wire.Username))) > 100 || len(wire.PasswordHash) < 20 || len(wire.PasswordHash) > 255 ||
		(wire.Status != service.StatusActive && wire.Status != service.StatusDisabled) ||
		(wire.Role != service.RoleUser && wire.Role != service.RoleAdmin) ||
		wire.Concurrency < 1 || wire.Concurrency > 100000 || wire.RPMLimit < 0 || wire.RPMLimit > 1000000 ||
		len(wire.AllowedGroupIDs) > 100 || wire.TotpRevision < 0 ||
		(wire.TotpEnabled != (totpEnabledAt != nil)) {
		return nil, errors.New("invalid auth user response")
	}
	balance, err := displayBalanceFromE8USD(wire.BalanceE8USD)
	if err != nil {
		return nil, errors.New("invalid auth user response: balance")
	}
	allowedGroups := make([]int64, 0, len(wire.AllowedGroupIDs))
	seen := make(map[int64]struct{}, len(wire.AllowedGroupIDs))
	for _, raw := range wire.AllowedGroupIDs {
		groupID, err := parsePositiveID("auth user allowed group id", raw)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[groupID]; exists {
			return nil, errors.New("invalid auth user response: duplicate allowed group")
		}
		seen[groupID] = struct{}{}
		allowedGroups = append(allowedGroups, groupID)
	}
	material := normalizedEmail + "\n" + wire.PasswordHash
	sum := sha256.Sum256([]byte(material))
	tokenVersion := int64(binary.BigEndian.Uint64(sum[:8]) & 0x7fffffffffffffff)
	return &service.User{
		ID:                   id,
		Email:                wire.Email,
		Username:             wire.Username,
		PasswordHash:         wire.PasswordHash,
		Status:               wire.Status,
		Role:                 wire.Role,
		Concurrency:          wire.Concurrency,
		RPMLimit:             wire.RPMLimit,
		Balance:              balance,
		AllowedGroups:        allowedGroups,
		RestrictPublicGroups: wire.RestrictPublicGroups,
		TokenVersion:         tokenVersion,
		TokenVersionResolved: true,
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
		TotpEnabled:          wire.TotpEnabled,
		TotpEnabledAt:        totpEnabledAt,
	}, nil
}

func mapAuthUserError(err error) error {
	if err == nil {
		return nil
	}
	var responseErr *controlPlaneResponseError
	if errors.As(err, &responseErr) && responseErr.Code == "NOT_FOUND" {
		return service.ErrUserNotFound
	}
	return err
}

func (c *HTTPControlPlane) getAuthUser(ctx context.Context, request any) (*service.User, error) {
	var response struct {
		User authUserWire `json:"user"`
	}
	if err := c.post(ctx, "/v1/private/auth-users/get", request, &response); err != nil {
		return nil, mapAuthUserError(err)
	}
	user, err := decodeAuthUser(response.User)
	if err != nil {
		return nil, fmt.Errorf("invalid auth user response: %w", err)
	}
	return user, nil
}

func (c *HTTPControlPlane) GetAuthUserByID(ctx context.Context, id int64) (*service.User, error) {
	if id < 1 {
		return nil, service.ErrUserNotFound
	}
	user, err := c.getAuthUser(ctx, struct {
		ID string `json:"id"`
	}{ID: strconv.FormatInt(id, 10)})
	if err != nil {
		return nil, err
	}
	if user.ID != id {
		return nil, errors.New("invalid auth user response: identity mismatch")
	}
	return user, nil
}

func (c *HTTPControlPlane) GetAuthUserByEmail(ctx context.Context, email string) (*service.User, error) {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" || len(normalized) > 255 {
		return nil, service.ErrUserNotFound
	}
	user, err := c.getAuthUser(ctx, struct {
		Email string `json:"email"`
	}{Email: normalized})
	if err != nil {
		return nil, err
	}
	if strings.ToLower(strings.TrimSpace(user.Email)) != normalized {
		return nil, errors.New("invalid auth user response: email mismatch")
	}
	return user, nil
}

var _ service.AuthUserRepository = (*AuthUserRepository)(nil)
var _ AuthUserControlPlane = (*HTTPControlPlane)(nil)
