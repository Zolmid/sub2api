//go:build unit

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

var errNarrowAuthWriteNotImplemented = errors.New("narrow auth test write not implemented")

type narrowAuthUserRepository struct {
	user *User
}

func (r *narrowAuthUserRepository) Create(context.Context, *User) error {
	return errNarrowAuthWriteNotImplemented
}

func (r *narrowAuthUserRepository) CreateWithEmailAliasGuard(context.Context, *User) error {
	return errNarrowAuthWriteNotImplemented
}

func (r *narrowAuthUserRepository) GetByID(_ context.Context, id int64) (*User, error) {
	if r.user == nil || r.user.ID != id {
		return nil, ErrUserNotFound
	}
	copy := *r.user
	return &copy, nil
}

func (r *narrowAuthUserRepository) GetByEmail(_ context.Context, email string) (*User, error) {
	if r.user == nil || r.user.Email != email {
		return nil, ErrUserNotFound
	}
	copy := *r.user
	return &copy, nil
}

func (r *narrowAuthUserRepository) Update(context.Context, *User, UserUpdateFields) error {
	return errNarrowAuthWriteNotImplemented
}

func (r *narrowAuthUserRepository) Delete(context.Context, int64) error {
	return errNarrowAuthWriteNotImplemented
}

func (r *narrowAuthUserRepository) ExistsByEmail(_ context.Context, email string) (bool, error) {
	return r.user != nil && r.user.Email == email, nil
}

func (r *narrowAuthUserRepository) ExistsByEmailAlias(_ context.Context, email string) (bool, error) {
	return r.user != nil && r.user.Email == email, nil
}

func TestAuthServiceAcceptsNarrowUserRepositoryForPasswordLogin(t *testing.T) {
	user := &User{ID: 9007199254740993, Email: "reader@example.test", Role: RoleUser, Status: StatusActive}
	require.NoError(t, user.SetPassword("correct horse battery staple"))
	repository := &narrowAuthUserRepository{user: user}
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "unit-test-secret-that-is-at-least-32-bytes", ExpireHour: 1}}
	service := NewAuthService(nil, repository, nil, nil, cfg, nil, nil, nil, nil, nil, nil, nil, nil)

	token, loaded, err := service.Login(context.Background(), user.Email, "correct horse battery staple")
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.Equal(t, user.ID, loaded.ID)
	claims, err := service.ValidateToken(token)
	require.NoError(t, err)
	require.Equal(t, user.ID, claims.UserID)
}

var _ AuthUserRepository = (*narrowAuthUserRepository)(nil)
