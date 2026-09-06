package cloudflarebridge

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

type APIKeyReadControlPlane interface {
	ListManagedAPIKeysByOwner(context.Context, int64, pagination.PaginationParams, service.APIKeyListFilters) ([]service.APIKey, *pagination.PaginationResult, error)
	CountManagedAPIKeysByOwner(context.Context, int64) (int64, error)
	ManagedAPIKeyExists(context.Context, string) (bool, error)
}

func (r *APIKeyRepository) reads() (APIKeyReadControlPlane, error) {
	reads, ok := r.control.(APIKeyReadControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return reads, nil
}

func (c *HTTPControlPlane) ListManagedAPIKeysByOwner(ctx context.Context, userID int64, params pagination.PaginationParams, filters service.APIKeyListFilters) ([]service.APIKey, *pagination.PaginationResult, error) {
	if userID < 1 || filters.GroupID != nil && *filters.GroupID < 1 {
		return nil, nil, ErrNotMigrated
	}
	page := params.Page
	if page < 1 {
		page = 1
	}
	pageSize := params.Limit()
	sortBy := strings.ToLower(strings.TrimSpace(params.SortBy))
	if sortBy == "" {
		sortBy = "created_at"
	}
	sortOrder := params.NormalizedSortOrder(pagination.SortOrderDesc)
	request := map[string]any{
		"user_id":    strconv.FormatInt(userID, 10),
		"page":       page,
		"page_size":  pageSize,
		"sort_by":    sortBy,
		"sort_order": sortOrder,
	}
	if filters.Search != "" {
		request["search"] = filters.Search
	}
	if filters.Status != "" {
		request["status"] = filters.Status
	}
	if filters.GroupID != nil {
		request["group_id"] = strconv.FormatInt(*filters.GroupID, 10)
	}
	var response struct {
		APIKeys []managedAPIKeyWire `json:"api_keys"`
		Total   string              `json:"total"`
	}
	if err := c.post(ctx, "/v1/private/api-keys/list-by-owner", request, &response); err != nil {
		var responseErr *controlPlaneResponseError
		if errors.As(err, &responseErr) && responseErr.Code == "NOT_MIGRATED" {
			return nil, nil, ErrNotMigrated
		}
		return nil, nil, err
	}
	total, err := strconv.ParseInt(response.Total, 10, 64)
	if err != nil || total < 0 || len(response.APIKeys) > pageSize {
		return nil, nil, errors.New("invalid owner api key list response")
	}
	keys := make([]service.APIKey, 0, len(response.APIKeys))
	for _, wire := range response.APIKeys {
		key, err := decodeManagedAPIKey(wire)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid owner api key list response: %w", err)
		}
		if key.UserID != userID {
			return nil, nil, errors.New("invalid owner api key list response: owner mismatch")
		}
		keys = append(keys, *key)
	}
	pages := int((total + int64(pageSize) - 1) / int64(pageSize))
	if pages < 1 {
		pages = 1
	}
	return keys, &pagination.PaginationResult{Total: total, Page: page, PageSize: pageSize, Pages: pages}, nil
}

func (c *HTTPControlPlane) CountManagedAPIKeysByOwner(ctx context.Context, userID int64) (int64, error) {
	if userID < 1 {
		return 0, ErrNotMigrated
	}
	var response struct {
		Count string `json:"count"`
	}
	if err := c.post(ctx, "/v1/private/api-keys/count-by-owner", struct {
		UserID string `json:"user_id"`
	}{UserID: strconv.FormatInt(userID, 10)}, &response); err != nil {
		return 0, err
	}
	count, err := strconv.ParseInt(response.Count, 10, 64)
	if err != nil || count < 0 {
		return 0, errors.New("invalid owner api key count response")
	}
	return count, nil
}

func (c *HTTPControlPlane) ManagedAPIKeyExists(ctx context.Context, rawKey string) (bool, error) {
	if len(rawKey) < 16 || len(rawKey) > 128 {
		return false, nil
	}
	var response struct {
		Exists bool `json:"exists"`
	}
	if err := c.post(ctx, "/v1/private/api-keys/exists", struct {
		RawKey string `json:"raw_key"`
	}{RawKey: rawKey}, &response); err != nil {
		return false, err
	}
	return response.Exists, nil
}

var _ APIKeyReadControlPlane = (*HTTPControlPlane)(nil)
