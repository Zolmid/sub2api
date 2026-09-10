//go:build unit

package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type atomicRefreshTokenCacheStub struct {
	mu                sync.Mutex
	sessions          map[string]*RefreshTokenData
	rotations         int
	rotatedOldVersion int64
	rotatedNewVersion int64
	getErr            error
}

func newAtomicRefreshTokenCacheStub() *atomicRefreshTokenCacheStub {
	return &atomicRefreshTokenCacheStub{sessions: map[string]*RefreshTokenData{}}
}

func (s *atomicRefreshTokenCacheStub) StoreRefreshToken(_ context.Context, tokenHash string, data *RefreshTokenData, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *data
	s.sessions[tokenHash] = &copy
	return nil
}

func (s *atomicRefreshTokenCacheStub) GetRefreshToken(_ context.Context, tokenHash string) (*RefreshTokenData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return nil, s.getErr
	}
	data := s.sessions[tokenHash]
	if data == nil {
		return nil, ErrRefreshTokenNotFound
	}
	copy := *data
	return &copy, nil
}

func TestAuthServiceRefreshTokenPairPreservesLegacyMissingTokenContract(t *testing.T) {
	svc := NewAuthService(nil, nil, nil, &refreshTokenCacheStub{}, &config.Config{
		JWT: config.JWTConfig{Secret: "test-secret", ExpireHour: 1, AccessTokenExpireMinutes: 15, RefreshTokenExpireDays: 30},
	}, nil, nil, nil, nil, nil, nil, nil, nil)

	_, err := svc.RefreshTokenPair(context.Background(), refreshTokenPrefix+"missing")
	require.ErrorIs(t, err, ErrRefreshTokenInvalid)
}

func TestAuthServiceRefreshTokenPairMapsAtomicLookupOutcomes(t *testing.T) {
	tests := []struct {
		name string
		got  error
		want error
	}{
		{name: "not found is reuse", got: ErrRefreshTokenNotFound, want: ErrRefreshTokenReused},
		{name: "explicit reuse", got: ErrRefreshTokenReused, want: ErrRefreshTokenReused},
		{name: "expired", got: ErrRefreshTokenExpired, want: ErrRefreshTokenExpired},
		{name: "revoked", got: ErrTokenRevoked, want: ErrTokenRevoked},
		{name: "invalid", got: ErrRefreshTokenInvalid, want: ErrRefreshTokenInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := newAtomicRefreshTokenCacheStub()
			cache.getErr = tt.got
			svc := NewAuthService(nil, nil, nil, cache, &config.Config{
				JWT: config.JWTConfig{Secret: "test-secret", ExpireHour: 1, AccessTokenExpireMinutes: 15, RefreshTokenExpireDays: 30},
			}, nil, nil, nil, nil, nil, nil, nil, nil)

			_, err := svc.RefreshTokenPair(context.Background(), refreshTokenPrefix+"lookup")
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func (s *atomicRefreshTokenCacheStub) DeleteRefreshToken(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, tokenHash)
	return nil
}

func (s *atomicRefreshTokenCacheStub) DeleteUserRefreshTokens(context.Context, int64) error {
	return nil
}

func (s *atomicRefreshTokenCacheStub) DeleteTokenFamily(context.Context, string) error {
	return nil
}

func (s *atomicRefreshTokenCacheStub) AddToUserTokenSet(context.Context, int64, string, time.Duration) error {
	return nil
}

func (s *atomicRefreshTokenCacheStub) AddToFamilyTokenSet(context.Context, string, string, time.Duration) error {
	return nil
}

func (s *atomicRefreshTokenCacheStub) GetUserTokenHashes(context.Context, int64) ([]string, error) {
	return nil, nil
}

func (s *atomicRefreshTokenCacheStub) GetFamilyTokenHashes(context.Context, string) ([]string, error) {
	return nil, nil
}

func (s *atomicRefreshTokenCacheStub) IsTokenInFamily(context.Context, string, string) (bool, error) {
	return false, nil
}

func (s *atomicRefreshTokenCacheStub) RotateRefreshToken(_ context.Context, oldHash, newHash string, data *RefreshTokenData, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.sessions[oldHash]
	if old == nil {
		return ErrRefreshTokenReused
	}
	s.rotations++
	s.rotatedOldVersion = old.TokenVersion
	s.rotatedNewVersion = data.TokenVersion
	delete(s.sessions, oldHash)
	copy := *data
	s.sessions[newHash] = &copy
	return nil
}

func (s *atomicRefreshTokenCacheStub) rotationVersionSnapshot() (int, int64, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotations, s.rotatedOldVersion, s.rotatedNewVersion
}

func TestAuthServiceRefreshTokenPairUsesAtomicRotatorOnlyOneConcurrentRefreshWins(t *testing.T) {
	user := &User{ID: 101, Email: "user@example.test", Role: RoleUser, Status: StatusActive, PasswordHash: "stable-password-hash"}
	user.TokenVersion = resolvedTokenVersion(user)
	user.TokenVersionResolved = true
	cache := newAtomicRefreshTokenCacheStub()
	svc := NewAuthService(nil, &userRepoStub{user: user}, nil, cache, &config.Config{
		JWT: config.JWTConfig{Secret: "test-secret", ExpireHour: 1, AccessTokenExpireMinutes: 15, RefreshTokenExpireDays: 30},
	}, nil, nil, nil, nil, nil, nil, nil, nil)

	initial, err := svc.GenerateTokenPair(context.Background(), user, "")
	require.NoError(t, err)

	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]*TokenPairWithUser, 2)
	errs := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			results[index], errs[index] = svc.RefreshTokenPair(context.Background(), initial.RefreshToken)
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	failures := 0
	for i := range results {
		if errs[i] == nil {
			successes++
			require.NotNil(t, results[i])
			require.NotEmpty(t, results[i].AccessToken)
			require.NotEmpty(t, results[i].RefreshToken)
			require.NotEqual(t, initial.RefreshToken, results[i].RefreshToken)
			continue
		}
		failures++
		require.Nil(t, results[i])
		require.ErrorIs(t, errs[i], ErrRefreshTokenReused)
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, failures)
	rotations, oldVersion, newVersion := cache.rotationVersionSnapshot()
	require.Equal(t, 1, rotations)
	require.Equal(t, user.TokenVersion, oldVersion)
	require.Equal(t, oldVersion, newVersion)
}

func TestAuthServiceRefreshTokenPairWithGuardRejectsBeforeAtomicRotation(t *testing.T) {
	user := &User{ID: 102, Email: "user@example.test", Role: RoleUser, Status: StatusActive, PasswordHash: "stable-password-hash"}
	user.TokenVersion = resolvedTokenVersion(user)
	user.TokenVersionResolved = true
	cache := newAtomicRefreshTokenCacheStub()
	svc := NewAuthService(nil, &userRepoStub{user: user}, nil, cache, &config.Config{
		JWT: config.JWTConfig{Secret: "test-secret", ExpireHour: 1, AccessTokenExpireMinutes: 15, RefreshTokenExpireDays: 30},
	}, nil, nil, nil, nil, nil, nil, nil, nil)

	initial, err := svc.GenerateTokenPair(context.Background(), user, "")
	require.NoError(t, err)

	denied := errors.New("refresh not authorized")
	_, err = svc.RefreshTokenPairWithGuard(context.Background(), initial.RefreshToken, func(got *User) error {
		require.Same(t, user, got)
		return denied
	})
	require.ErrorIs(t, err, denied)
	rotations, _, _ := cache.rotationVersionSnapshot()
	require.Zero(t, rotations)

	rotated, err := svc.RefreshTokenPair(context.Background(), initial.RefreshToken)
	require.NoError(t, err)
	require.NotEqual(t, initial.RefreshToken, rotated.RefreshToken)
	rotations, _, _ = cache.rotationVersionSnapshot()
	require.Equal(t, 1, rotations)
}
