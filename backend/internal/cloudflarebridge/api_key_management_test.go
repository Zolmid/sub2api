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
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
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
	require.Equal(t, int32(1), calls.Load())
}

func TestAPIKeyRepositoryCreateRecoversAmbiguousFailureWithSameOperationID(t *testing.T) {
	t.Parallel()
	const timestamp = "2026-09-06T12:34:56Z"
	var calls atomic.Int32
	var firstOperationID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		operationID, _ := body["operation_id"].(string)
		if calls.Add(1) == 1 {
			firstOperationID = operationID
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":"CONTROL_PLANE_UNAVAILABLE","message":"response lost"}}`))
			return
		}
		require.Equal(t, firstOperationID, operationID)
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"api_key": map[string]any{
				"id": body["id"], "user_id": body["user_id"], "group_id": body["group_id"],
				"name": body["name"], "status": body["status"],
				"ip_whitelist": body["ip_whitelist"], "ip_blacklist": body["ip_blacklist"],
				"expires_at": nil, "last_used_at": nil, "created_at": timestamp,
				"updated_at": timestamp, "deleted_at": nil,
			},
		}))
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	repository := NewAPIKeyRepository(control)
	groupID := int64(2001)
	key := &service.APIKey{
		UserID: 1001, Key: "unit_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		Name: "ambiguous recovery", GroupID: &groupID, Status: service.StatusAPIKeyActive,
	}
	require.NoError(t, repository.Create(context.Background(), key))
	require.Equal(t, int32(2), calls.Load())
	require.NotEmpty(t, firstOperationID)
}

func TestHTTPControlPlaneManagedMutationRetryClearsPartialResponse(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"raw_key":"stale-partial-value","api_key":{"id":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"api_key":{}}`))
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	var response managedAPIKeyResponse
	require.NoError(t, control.postManagedMutation(context.Background(), "/v1/manage/api-keys/create", map[string]string{"operation_id": "stable"}, &response))
	require.Equal(t, int32(2), calls.Load())
	require.Empty(t, response.RawKey)
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

func TestHTTPControlPlaneRebindManagedAPIKeyGroupUsesDedicatedProtocol(t *testing.T) {
	t.Parallel()
	const timestamp = "2026-09-07T01:02:03Z"
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/manage/api-keys/rebind-group", r.URL.Path)
		require.Equal(t, ProtocolVersion, r.Header.Get("X-Sub2API-Bridge-Version"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"api_key": map[string]any{
				"id": captured["id"], "user_id": "9007199254740993", "group_id": captured["group_id"],
				"name": "managed", "status": "active", "ip_whitelist": []string{}, "ip_blacklist": []string{},
				"expires_at": nil, "last_used_at": nil, "created_at": timestamp, "updated_at": timestamp, "deleted_at": nil,
			},
			"group": map[string]any{
				"id": captured["group_id"], "name": "exclusive", "platform": "openai", "status": "active",
				"is_exclusive": true, "subscription_type": "standard", "created_at": timestamp, "updated_at": timestamp, "deleted_at": nil,
			},
			"auto_granted_group_access": true,
			"granted_group_id":          captured["group_id"],
			"granted_group_name":        "exclusive",
		}))
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	result, err := control.RebindManagedAPIKeyGroup(context.Background(), 9007199254740995, 9007199254741197)
	require.NoError(t, err)
	require.Equal(t, "9007199254740995", captured["id"])
	require.Equal(t, "9007199254741197", captured["group_id"])
	require.NotEmpty(t, captured["operation_id"])
	require.NotContains(t, captured, "reset_rate_limit_usage")
	require.Equal(t, int64(9007199254740995), result.APIKey.ID)
	require.Equal(t, int64(9007199254741197), result.Group.ID)
	require.True(t, result.AutoGrantedGroupAccess)
	require.Equal(t, int64(9007199254741197), *result.GrantedGroupID)
	require.Equal(t, "exclusive", result.GrantedGroupName)
}

func TestHTTPControlPlaneRebindManagedAPIKeyGroupMapsErrorsWithoutLeakingBody(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/manage/api-keys/rebind-group", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"REFERENCE_REJECTED","message":"private subscription row detail"}}`))
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, err = control.RebindManagedAPIKeyGroup(context.Background(), 3001, 2001)
	require.ErrorIs(t, err, service.ErrGroupNotAllowed)
	require.NotContains(t, err.Error(), "private subscription row detail")
}
