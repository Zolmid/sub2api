//go:build unit

package cloudflarebridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyRepositoryCreateUsesPrivateManagementProtocol(t *testing.T) {
	t.Parallel()
	rawKey := "unit_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	const timestamp = "2026-09-06T12:34:56.123456Z"
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/manage/api-keys/create", r.URL.Path)
		require.Equal(t, ProtocolVersion, r.Header.Get("X-Sub2API-Bridge-Version"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
		response := map[string]any{
			"raw_key": rawKey,
			"api_key": map[string]any{
				"id":           captured["id"],
				"user_id":      captured["user_id"],
				"group_id":     captured["group_id"],
				"name":         captured["name"],
				"status":       captured["status"],
				"ip_whitelist": captured["ip_whitelist"],
				"ip_blacklist": captured["ip_blacklist"],
				"expires_at":   nil,
				"last_used_at": nil,
				"created_at":   timestamp,
				"updated_at":   timestamp,
				"deleted_at":   nil,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(response))
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	repository := NewAPIKeyRepository(control)
	groupID := int64(2001)
	key := &service.APIKey{
		UserID:      1001,
		Key:         rawKey,
		Name:        "managed key",
		GroupID:     &groupID,
		Status:      service.StatusAPIKeyActive,
		IPWhitelist: []string{"127.0.0.1"},
	}

	require.NoError(t, repository.Create(context.Background(), key))
	require.Positive(t, key.ID)
	require.Equal(t, rawKey, key.Key)
	require.Equal(t, int64(1001), key.UserID)
	require.Equal(t, groupID, *key.GroupID)
	require.Equal(t, timestamp, key.CreatedAt.UTC().Format(time.RFC3339Nano))
	require.Equal(t, rawKey, captured["raw_key"])
	require.Equal(t, "1001", captured["user_id"])
	require.Equal(t, "2001", captured["group_id"])
	require.NotEmpty(t, captured["operation_id"])
}

func TestAPIKeyRepositoryRejectsUnmigratedQuotaWithoutCallingWorker(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	repository := NewAPIKeyRepository(control)
	groupID := int64(2001)
	key := &service.APIKey{
		UserID:  1001,
		Key:     "unit_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		Name:    "quota key",
		GroupID: &groupID,
		Status:  service.StatusAPIKeyActive,
		Quota:   1,
	}

	require.ErrorIs(t, repository.Create(context.Background(), key), ErrNotMigrated)
	require.Zero(t, calls.Load())
	require.ErrorIs(t, repository.Update(context.Background(), key, service.APIKeyUpdateFields{Quota: true}), ErrNotMigrated)
	require.Zero(t, calls.Load())
}

func TestAPIKeyRepositoryOwnerDeleteIsAtomicAtWorkerBoundary(t *testing.T) {
	t.Parallel()
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/manage/api-keys/revoke", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"api_key":{"id":"3001"}}`))
	}))
	defer server.Close()
	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	repository := NewAPIKeyRepository(control)

	require.NoError(t, repository.DeleteWithAuditForOwner(context.Background(), 3001, 1001))
	require.Equal(t, "3001", captured["id"])
	require.Equal(t, "1001", captured["expected_user_id"])
	require.NotEmpty(t, captured["operation_id"])
}

func TestAPIKeyRepositoryOwnerDeleteMapsConflictWithoutResponseLeak(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"CONFLICT","message":"private row detail"}}`))
	}))
	defer server.Close()
	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	repository := NewAPIKeyRepository(control)

	err = repository.DeleteWithAuditForOwner(context.Background(), 3001, 9999)
	require.ErrorIs(t, err, service.ErrInsufficientPerms)
	require.NotContains(t, err.Error(), "private row detail")
}

func TestHTTPControlPlaneTreatsManagedTombstoneAsNotFound(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"api_key":{
				"id":"3001","user_id":"1001","group_id":"2001","name":"gone","status":"disabled",
				"ip_whitelist":[],"ip_blacklist":[],"expires_at":null,"last_used_at":null,
				"created_at":"2026-09-06T00:00:00Z","updated_at":"2026-09-06T01:00:00Z",
				"deleted_at":"2026-09-06T01:00:00Z"
			}
		}`))
	}))
	defer server.Close()
	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)

	_, err = control.GetManagedAPIKey(context.Background(), 3001)
	require.ErrorIs(t, err, service.ErrAPIKeyNotFound)
}
