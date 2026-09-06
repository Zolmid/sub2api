//go:build unit

package cloudflarebridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyRepositoryOwnerReadsPreserveStringIDs(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/private/api-keys/list-by-owner":
			require.Equal(t, "9007199254740993", body["user_id"])
			_, _ = w.Write([]byte(`{"api_keys":[{"id":"9007199254740995","user_id":"9007199254740993","group_id":"2001","name":"mine","status":"active","ip_whitelist":[],"ip_blacklist":[],"expires_at":null,"last_used_at":null,"created_at":"2026-09-06T00:00:00Z","updated_at":"2026-09-06T00:00:00Z","deleted_at":null}],"total":"1"}`))
		case "/v1/private/api-keys/count-by-owner":
			require.Equal(t, "9007199254740993", body["user_id"])
			_, _ = w.Write([]byte(`{"count":"1"}`))
		case "/v1/private/api-keys/exists":
			require.Equal(t, "CustomKey_123456789", body["raw_key"])
			_, _ = w.Write([]byte(`{"exists":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	repository := NewAPIKeyRepository(control)
	keys, page, err := repository.ListByUserID(context.Background(), 9007199254740993, pagination.PaginationParams{Page: 1, PageSize: 20, SortBy: "created_at", SortOrder: "desc"}, service.APIKeyListFilters{})
	require.NoError(t, err)
	require.Equal(t, int64(9007199254740995), keys[0].ID)
	require.Equal(t, int64(1), page.Total)
	count, err := repository.CountByUserID(context.Background(), 9007199254740993)
	require.NoError(t, err)
	require.Equal(t, int64(1), count)
	exists, err := repository.ExistsByKey(context.Background(), "CustomKey_123456789")
	require.NoError(t, err)
	require.True(t, exists)
}

func TestAPIKeyRepositoryRejectsCrossOwnerListResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"api_keys":[{"id":"3001","user_id":"1002","group_id":"2001","name":"other","status":"active","ip_whitelist":[],"ip_blacklist":[],"expires_at":null,"last_used_at":null,"created_at":"2026-09-06T00:00:00Z","updated_at":"2026-09-06T00:00:00Z","deleted_at":null}],"total":"1"}`))
	}))
	defer server.Close()
	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, _, err = NewAPIKeyRepository(control).ListByUserID(context.Background(), 1001, pagination.DefaultPagination(), service.APIKeyListFilters{})
	require.ErrorContains(t, err, "owner mismatch")
}
