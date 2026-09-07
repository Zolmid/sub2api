//go:build unit

package cloudflarebridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type adminAPIKeyListControlStub struct {
	*fakeControlPlane
	keys       []service.APIKey
	groups     map[int64]*service.Group
	lastOwner  int64
	lastParams pagination.PaginationParams
	calls      int
}

func (s *adminAPIKeyListControlStub) ListManagedAPIKeysByOwner(_ context.Context, owner int64, params pagination.PaginationParams, _ service.APIKeyListFilters) ([]service.APIKey, *pagination.PaginationResult, error) {
	s.lastOwner = owner
	s.lastParams = params
	s.calls++
	keys := make([]service.APIKey, len(s.keys))
	copy(keys, s.keys)
	return keys, &pagination.PaginationResult{Total: int64(len(keys)), Page: params.Page, PageSize: params.PageSize, Pages: 1}, nil
}

func (s *adminAPIKeyListControlStub) GetManagedGroup(_ context.Context, id int64) (*service.Group, error) {
	group := s.groups[id]
	if group == nil {
		return nil, service.ErrGroupNotFound
	}
	copy := *group
	return &copy, nil
}

func adminAPIKeyListRouter(control *adminAPIKeyListControlStub) http.Handler {
	router := gin.New()
	router.GET("/users/:id/api-keys", newCloudflareAdminAPIHandler(control).ListUserAPIKeys)
	return router
}

func TestCloudflareAdminListUserAPIKeysUsesBoundedPrivateContract(t *testing.T) {
	ownerID := int64(9007199254740993)
	keyID := int64(9007199254740995)
	groupID := int64(9007199254741197)
	control := &adminAPIKeyListControlStub{
		fakeControlPlane: testControlPlane(),
		keys: []service.APIKey{{
			ID: keyID, UserID: ownerID, GroupID: &groupID, Key: "never-return-this-raw-key", Name: "owner key", Status: service.StatusAPIKeyActive,
			CreatedAt: time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 9, 7, 1, 0, 0, 0, time.UTC),
		}},
		groups: map[int64]*service.Group{groupID: {
			ID: groupID, Name: "current group", Platform: service.PlatformOpenAI, Status: service.StatusActive,
			SubscriptionType: service.SubscriptionTypeStandard, RateMultiplier: 1, Hydrated: true,
		}},
	}
	handler := adminAPIKeyListRouter(control)

	recorded := httptest.NewRecorder()
	handler.ServeHTTP(recorded, httptest.NewRequest(http.MethodGet, "/users/9007199254740993/api-keys", nil))
	require.Equal(t, http.StatusOK, recorded.Code, recorded.Body.String())
	require.Equal(t, ownerID, control.lastOwner)
	require.Equal(t, pagination.PaginationParams{Page: 1, PageSize: 20, SortBy: "created_at", SortOrder: "desc"}, control.lastParams)
	require.NotContains(t, recorded.Body.String(), "never-return-this-raw-key")

	var envelope struct {
		Data struct {
			Items []struct {
				ID      string `json:"id"`
				UserID  string `json:"user_id"`
				Key     string `json:"key"`
				GroupID string `json:"group_id"`
				Group   struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"group"`
			} `json:"items"`
			Total    int64 `json:"total"`
			Page     int   `json:"page"`
			PageSize int   `json:"page_size"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(recorded.Body.Bytes(), &envelope))
	require.Equal(t, int64(1), envelope.Data.Total)
	require.Equal(t, 1, envelope.Data.Page)
	require.Equal(t, 20, envelope.Data.PageSize)
	require.Len(t, envelope.Data.Items, 1)
	require.Equal(t, "9007199254740995", envelope.Data.Items[0].ID)
	require.Equal(t, "9007199254740993", envelope.Data.Items[0].UserID)
	require.Empty(t, envelope.Data.Items[0].Key)
	require.Equal(t, "9007199254741197", envelope.Data.Items[0].GroupID)
	require.Equal(t, "9007199254741197", envelope.Data.Items[0].Group.ID)
	require.Equal(t, "current group", envelope.Data.Items[0].Group.Name)

	query := httptest.NewRecorder()
	handler.ServeHTTP(query, httptest.NewRequest(http.MethodGet, "/users/9007199254740993/api-keys?page=2&page_size=1&sort_by=name&sort_order=asc&timezone=Asia%2FShanghai", nil))
	require.Equal(t, http.StatusOK, query.Code, query.Body.String())
	require.Equal(t, pagination.PaginationParams{Page: 2, PageSize: 1, SortBy: "name", SortOrder: "asc"}, control.lastParams)
}

func TestCloudflareAdminListUserAPIKeysRejectsMalformedRequestsBeforeControlPlane(t *testing.T) {
	groupID := int64(2001)
	control := &adminAPIKeyListControlStub{
		fakeControlPlane: testControlPlane(),
		groups:           map[int64]*service.Group{groupID: {ID: groupID, Name: "group", Platform: service.PlatformOpenAI, Status: service.StatusActive, SubscriptionType: service.SubscriptionTypeStandard}},
	}
	handler := adminAPIKeyListRouter(control)
	for _, path := range []string{
		"/users/0/api-keys", "/users/01/api-keys", "/users/9223372036854775808/api-keys",
		"/users/1/api-keys?page=0", "/users/1/api-keys?page_size=101", "/users/1/api-keys?sort_by=id",
		"/users/1/api-keys?sort_order=sideways", "/users/1/api-keys?search=key", "/users/1/api-keys?page=1&page=2",
	} {
		recorded := httptest.NewRecorder()
		handler.ServeHTTP(recorded, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusBadRequest, recorded.Code, path+": "+recorded.Body.String())
	}
	require.Zero(t, control.calls)
}

func TestCloudflareAdminListUserAPIKeysFailsClosedForOwnerMismatch(t *testing.T) {
	ownerID := int64(1001)
	groupID := int64(2001)
	control := &adminAPIKeyListControlStub{
		fakeControlPlane: testControlPlane(),
		keys:             []service.APIKey{{ID: 3001, UserID: 1002, GroupID: &groupID, Name: "other", Status: service.StatusAPIKeyActive}},
		groups:           map[int64]*service.Group{groupID: {ID: groupID, Name: "wrong", Platform: service.PlatformOpenAI, Status: service.StatusActive, SubscriptionType: service.SubscriptionTypeStandard}},
	}
	recorded := httptest.NewRecorder()
	adminAPIKeyListRouter(control).ServeHTTP(recorded, httptest.NewRequest(http.MethodGet, "/users/1001/api-keys", nil))
	require.Equal(t, http.StatusInternalServerError, recorded.Code, recorded.Body.String())
	require.Equal(t, ownerID, control.lastOwner)
}

func TestHTTPControlPlaneListManagedAPIKeysByOwnerSendsDefaultPaginationBody(t *testing.T) {
	var requestBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/v1/private/api-keys/list-by-owner", request.URL.Path)
		require.NoError(t, json.NewDecoder(request.Body).Decode(&requestBody))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"api_keys":[],"total":"0"}`))
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	keys, result, err := control.ListManagedAPIKeysByOwner(context.Background(), 9007199254740993, pagination.PaginationParams{
		Page: 1, PageSize: 20, SortBy: "created_at", SortOrder: "desc",
	}, service.APIKeyListFilters{})
	require.NoError(t, err)
	require.Empty(t, keys)
	require.Equal(t, int64(0), result.Total)
	require.Equal(t, map[string]any{
		"user_id": "9007199254740993", "page": float64(1), "page_size": float64(20),
		"sort_by": "created_at", "sort_order": "desc",
	}, requestBody)
}
