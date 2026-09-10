//go:build unit

package cloudflarebridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestHTTPControlPlaneAuthSessionsUseFixedContract(t *testing.T) {
	tokenHash := strings.Repeat("a", 64)
	newHash := strings.Repeat("b", 64)
	familyID := strings.Repeat("c", 64)
	bindingHash := strings.Repeat("d", 32)
	createdAt := time.Date(2026, 9, 10, 1, 2, 3, 456789, time.UTC)
	expiresAt := createdAt.Add(30 * 24 * time.Hour)
	session := &service.RefreshTokenData{
		UserID:       9007199254740993,
		TokenVersion: 9223372036854775807,
		FamilyID:     familyID,
		BindingHash:  bindingHash,
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt,
	}
	type observedRequest struct {
		Path string
		Body string
	}
	var observed []observedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, ProtocolVersion, r.Header.Get("X-Sub2API-Bridge-Version"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		observed = append(observed, observedRequest{Path: r.URL.Path, Body: string(body)})
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth-sessions/store", "/v1/auth-sessions/delete", "/v1/auth-sessions/revoke-user", "/v1/auth-sessions/revoke-family", "/v1/auth-sessions/rotate":
			w.WriteHeader(http.StatusNoContent)
		case "/v1/auth-sessions/get":
			_ = json.NewEncoder(w).Encode(map[string]any{"session": map[string]string{
				"token_hash": tokenHash, "user_id": "9007199254740993", "token_version": "9223372036854775807",
				"family_id": familyID, "binding_hash": bindingHash,
				"created_at": createdAt.Format(time.RFC3339Nano), "expires_at": expiresAt.Format(time.RFC3339Nano),
			}})
		case "/v1/auth-sessions/list-user", "/v1/auth-sessions/list-family":
			_ = json.NewEncoder(w).Encode(map[string]any{"token_hashes": []string{tokenHash, newHash}})
		case "/v1/auth-sessions/contains":
			_ = json.NewEncoder(w).Encode(map[string]any{"contains": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	require.NoError(t, control.StoreRefreshToken(context.Background(), tokenHash, session, time.Hour))
	got, err := control.GetRefreshToken(context.Background(), tokenHash)
	require.NoError(t, err)
	require.Equal(t, int64(9007199254740993), got.UserID)
	require.Equal(t, int64(9223372036854775807), got.TokenVersion)
	require.Equal(t, familyID, got.FamilyID)
	require.Equal(t, bindingHash, got.BindingHash)
	require.Equal(t, createdAt, got.CreatedAt)
	require.Equal(t, expiresAt, got.ExpiresAt)
	require.NoError(t, control.DeleteRefreshToken(context.Background(), tokenHash))
	require.NoError(t, control.DeleteUserRefreshTokens(context.Background(), 9007199254740993))
	require.NoError(t, control.DeleteTokenFamily(context.Background(), familyID))
	userHashes, err := control.GetUserTokenHashes(context.Background(), 9007199254740993)
	require.NoError(t, err)
	require.Equal(t, []string{tokenHash, newHash}, userHashes)
	familyHashes, err := control.GetFamilyTokenHashes(context.Background(), familyID)
	require.NoError(t, err)
	require.Equal(t, []string{tokenHash, newHash}, familyHashes)
	contains, err := control.IsTokenInFamily(context.Background(), familyID, tokenHash)
	require.NoError(t, err)
	require.True(t, contains)
	require.NoError(t, control.RotateRefreshToken(context.Background(), tokenHash, newHash, session, time.Hour))

	require.Len(t, observed, 9)
	require.Equal(t, "/v1/auth-sessions/store", observed[0].Path)
	require.JSONEq(t, `{
		"token_hash":"`+tokenHash+`",
		"user_id":"9007199254740993",
		"token_version":"9223372036854775807",
		"family_id":"`+familyID+`",
		"binding_hash":"`+bindingHash+`",
		"created_at":"`+createdAt.Format(time.RFC3339Nano)+`",
		"expires_at":"`+expiresAt.Format(time.RFC3339Nano)+`"
	}`, observed[0].Body)
	require.Equal(t, "/v1/auth-sessions/get", observed[1].Path)
	require.JSONEq(t, `{"token_hash":"`+tokenHash+`"}`, observed[1].Body)
	require.Equal(t, "/v1/auth-sessions/delete", observed[2].Path)
	require.JSONEq(t, `{"token_hash":"`+tokenHash+`"}`, observed[2].Body)
	require.Equal(t, "/v1/auth-sessions/revoke-user", observed[3].Path)
	require.JSONEq(t, `{"user_id":"9007199254740993"}`, observed[3].Body)
	require.Equal(t, "/v1/auth-sessions/revoke-family", observed[4].Path)
	require.JSONEq(t, `{"family_id":"`+familyID+`"}`, observed[4].Body)
	require.Equal(t, "/v1/auth-sessions/list-user", observed[5].Path)
	require.Equal(t, "/v1/auth-sessions/list-family", observed[6].Path)
	require.Equal(t, "/v1/auth-sessions/contains", observed[7].Path)
	require.JSONEq(t, `{"family_id":"`+familyID+`","token_hash":"`+tokenHash+`"}`, observed[7].Body)
	require.Equal(t, "/v1/auth-sessions/rotate", observed[8].Path)
	require.JSONEq(t, `{"old_token_hash":"`+tokenHash+`","new_session":{
		"token_hash":"`+newHash+`",
		"user_id":"9007199254740993",
		"token_version":"9223372036854775807",
		"family_id":"`+familyID+`",
		"binding_hash":"`+bindingHash+`",
		"created_at":"`+createdAt.Format(time.RFC3339Nano)+`",
		"expires_at":"`+expiresAt.Format(time.RFC3339Nano)+`"
	}}`, observed[8].Body)
}

func TestHTTPControlPlaneAuthSessionsRejectMalformedResponses(t *testing.T) {
	tokenHash := strings.Repeat("a", 64)
	familyID := strings.Repeat("c", 64)
	bindingHash := strings.Repeat("d", 32)
	createdAt := time.Date(2026, 9, 10, 1, 2, 3, 0, time.UTC)
	expiresAt := createdAt.Add(time.Hour)
	tests := map[string]string{
		"numeric token version": `{"session":{"token_hash":"` + tokenHash + `","user_id":"9007199254740993","token_version":9223372036854775807,"family_id":"` + familyID + `","binding_hash":"` + bindingHash + `","created_at":"` + createdAt.Format(time.RFC3339Nano) + `","expires_at":"` + expiresAt.Format(time.RFC3339Nano) + `"}}`,
		"unsafe id as number":   `{"session":{"token_hash":"` + tokenHash + `","user_id":9007199254740993,"token_version":"1","family_id":"` + familyID + `","binding_hash":"` + bindingHash + `","created_at":"` + createdAt.Format(time.RFC3339Nano) + `","expires_at":"` + expiresAt.Format(time.RFC3339Nano) + `"}}`,
		"negative version":      `{"session":{"token_hash":"` + tokenHash + `","user_id":"9007199254740993","token_version":"-1","family_id":"` + familyID + `","binding_hash":"` + bindingHash + `","created_at":"` + createdAt.Format(time.RFC3339Nano) + `","expires_at":"` + expiresAt.Format(time.RFC3339Nano) + `"}}`,
		"full binding hash":     `{"session":{"token_hash":"` + tokenHash + `","user_id":"9007199254740993","token_version":"1","family_id":"` + familyID + `","binding_hash":"` + strings.Repeat("d", 64) + `","created_at":"` + createdAt.Format(time.RFC3339Nano) + `","expires_at":"` + expiresAt.Format(time.RFC3339Nano) + `"}}`,
		"offset time":           `{"session":{"token_hash":"` + tokenHash + `","user_id":"9007199254740993","token_version":"1","family_id":"` + familyID + `","binding_hash":"` + bindingHash + `","created_at":"2026-09-10T09:02:03+08:00","expires_at":"` + expiresAt.Format(time.RFC3339Nano) + `"}}`,
		"mismatched hash":       `{"session":{"token_hash":"` + strings.Repeat("e", 64) + `","user_id":"9007199254740993","token_version":"1","family_id":"` + familyID + `","binding_hash":"` + bindingHash + `","created_at":"` + createdAt.Format(time.RFC3339Nano) + `","expires_at":"` + expiresAt.Format(time.RFC3339Nano) + `"}}`,
		"unknown field":         `{"session":{"token_hash":"` + tokenHash + `","user_id":"9007199254740993","token_version":"1","family_id":"` + familyID + `","binding_hash":"` + bindingHash + `","created_at":"` + createdAt.Format(time.RFC3339Nano) + `","expires_at":"` + expiresAt.Format(time.RFC3339Nano) + `","extra":true}}`,
		"trailing json":         `{"session":{"token_hash":"` + tokenHash + `","user_id":"9007199254740993","token_version":"1","family_id":"` + familyID + `","binding_hash":"` + bindingHash + `","created_at":"` + createdAt.Format(time.RFC3339Nano) + `","expires_at":"` + expiresAt.Format(time.RFC3339Nano) + `"}} {}`,
		"bad list":              `{"token_hashes":["` + tokenHash + `","` + tokenHash + `"]}`,
		"bad contains":          `{"contains":true,"extra":true}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			control, err := NewHTTPControlPlane(server.URL, server.Client())
			require.NoError(t, err)
			switch name {
			case "bad list":
				_, err = control.GetUserTokenHashes(context.Background(), 1)
			case "bad contains":
				_, err = control.IsTokenInFamily(context.Background(), familyID, tokenHash)
			default:
				_, err = control.GetRefreshToken(context.Background(), tokenHash)
			}
			require.Error(t, err)
		})
	}
}

func TestAuthSessionWireAcceptsZeroTokenVersionAndEmptyBinding(t *testing.T) {
	tokenHash := strings.Repeat("a", 64)
	familyID := strings.Repeat("c", 64)
	createdAt := time.Date(2026, 9, 10, 1, 2, 3, 0, time.UTC)
	expiresAt := createdAt.Add(time.Hour)
	session := &service.RefreshTokenData{
		UserID:       1,
		TokenVersion: 0,
		FamilyID:     familyID,
		BindingHash:  "",
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt,
	}
	wire, err := encodeAuthSession(tokenHash, session)
	require.NoError(t, err)
	require.Equal(t, "0", wire.TokenVersion)
	require.Empty(t, wire.BindingHash)
	decoded, err := decodeAuthSession(tokenHash, wire)
	require.NoError(t, err)
	require.Zero(t, decoded.TokenVersion)
	require.Empty(t, decoded.BindingHash)

	session.BindingHash = strings.Repeat("d", 64)
	_, err = encodeAuthSession(tokenHash, session)
	require.ErrorIs(t, err, service.ErrRefreshTokenInvalid)
}

func TestHTTPControlPlaneAuthSessionListsAreNotTruncated(t *testing.T) {
	tokenHashes := make([]string, 513)
	for i := range tokenHashes {
		tokenHashes[i] = strings.Repeat("0", 60) + fmt.Sprintf("%04x", i)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Contains(t, []string{"/v1/auth-sessions/list-user", "/v1/auth-sessions/list-family"}, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"token_hashes": tokenHashes})
	}))
	defer server.Close()
	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	got, err := control.GetUserTokenHashes(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, tokenHashes, got)
	got, err = control.GetFamilyTokenHashes(context.Background(), strings.Repeat("a", 64))
	require.NoError(t, err)
	require.Equal(t, tokenHashes, got)
}

func TestHTTPControlPlaneAuthSessionErrorMappingsAreBounded(t *testing.T) {
	tests := []struct {
		code string
		want error
	}{
		{"REFRESH_TOKEN_NOT_FOUND", service.ErrRefreshTokenNotFound},
		{"REFRESH_TOKEN_EXPIRED", service.ErrRefreshTokenExpired},
		{"SESSION_REVOKED", service.ErrTokenRevoked},
		{"REFRESH_TOKEN_REUSED", service.ErrRefreshTokenReused},
		{"REFRESH_TOKEN_CONFLICT", service.ErrRefreshTokenReused},
		{"AUTH_SESSION_UNAVAILABLE", ErrControlPlaneUnavailable},
		{"INVALID_REQUEST", ErrControlPlaneUnavailable},
		{"INTERNAL_ERROR", ErrControlPlaneUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, `{"error":{"code":"`+tt.code+`","message":"secret detail must not escape"}}`)
			}))
			defer server.Close()
			control, err := NewHTTPControlPlane(server.URL, server.Client())
			require.NoError(t, err)
			_, err = control.GetRefreshToken(context.Background(), strings.Repeat("a", 64))
			require.ErrorIs(t, err, tt.want)
			require.NotContains(t, err.Error(), "secret detail")
		})
	}
}

func TestHTTPControlPlaneAuthSessionsRedirectCancelAndOversizeFailClosed(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}))
		defer server.Close()
		control, err := NewHTTPControlPlane(server.URL, server.Client())
		require.NoError(t, err)
		_, err = control.GetRefreshToken(context.Background(), strings.Repeat("a", 64))
		require.ErrorIs(t, err, ErrControlPlaneUnavailable)
		require.Equal(t, 1, requests)
	})
	t.Run("cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()
		control, err := NewHTTPControlPlane(server.URL, server.Client())
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = control.GetRefreshToken(ctx, strings.Repeat("a", 64))
		require.Error(t, err)
		require.True(t, errors.Is(err, context.Canceled) || errors.Is(err, ErrControlPlaneUnavailable))
	})
	t.Run("oversize", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, strings.Repeat("x", int(maxControlPlaneResponseBytes)+1))
		}))
		defer server.Close()
		control, err := NewHTTPControlPlane(server.URL, server.Client())
		require.NoError(t, err)
		_, err = control.GetRefreshToken(context.Background(), strings.Repeat("a", 64))
		require.ErrorIs(t, err, ErrControlPlaneUnavailable)
	})
}
