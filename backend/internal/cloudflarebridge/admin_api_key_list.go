package cloudflarebridge

import (
	"context"
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// AdminAPIKeyListControlPlane is the non-secret private-data subset needed by
// the embedded admin user-key modal. It is deliberately separate from the
// mutation contract so deployments without the private owner-list route fail
// closed instead of attempting a traditional repository fallback.
type AdminAPIKeyListControlPlane interface {
	ListManagedAPIKeysByOwner(context.Context, int64, pagination.PaginationParams, service.APIKeyListFilters) ([]service.APIKey, *pagination.PaginationResult, error)
	GetManagedGroup(context.Context, int64) (*service.Group, error)
}

func (h *cloudflareAdminAPIHandler) apiKeyLists() (AdminAPIKeyListControlPlane, error) {
	reads, ok := h.control.(AdminAPIKeyListControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return reads, nil
}

func cloudflareAdminAPIKeyListQueryOK(c *gin.Context) bool {
	allowed := map[string]bool{
		"page": true, "page_size": true, "sort_by": true, "sort_order": true,
		// The shared frontend client appends the browser timezone to every GET.
		// This endpoint is timezone-independent, so accept and ignore that
		// compatibility parameter while continuing to reject real filters.
		"timezone": true,
	}
	for name := range c.Request.URL.Query() {
		if !allowed[name] {
			response.BadRequest(c, name+" is not migrated in Cloudflare mode")
			return false
		}
	}
	return true
}

// ListUserAPIKeys implements the traditional paginated admin endpoint while
// retaining the Cloudflare private-data boundary. Every returned key is
// re-enriched with its current group, because the list wire contract carries
// only group_id and the modal's initial badge must not reflect stale state.
func (h *cloudflareAdminAPIHandler) ListUserAPIKeys(c *gin.Context) {
	if !cloudflareAdminAPIKeyListQueryOK(c) {
		return
	}
	userID, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	page, ok := cloudflareAdminPositiveQuery(c, "page", 1, 1, 1_000_000)
	if !ok {
		return
	}
	// The private D1 owner-list contract deliberately caps each page at 100.
	// Reject larger public requests here instead of forwarding a request that
	// the next protocol boundary cannot represent.
	pageSize, ok := cloudflareAdminPositiveQuery(c, "page_size", 20, 1, 100)
	if !ok {
		return
	}
	sortBy, sortOrder, ok := cloudflareAdminSort(c, "created_at", pagination.SortOrderDesc, "created_at", "updated_at", "name", "status")
	if !ok {
		return
	}
	reads, err := h.apiKeyLists()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	keys, result, err := reads.ListManagedAPIKeysByOwner(c.Request.Context(), userID, pagination.PaginationParams{
		Page: page, PageSize: pageSize, SortBy: sortBy, SortOrder: sortOrder,
	}, service.APIKeyListFilters{})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if result == nil || result.Total < 0 || result.Page != page || result.PageSize != pageSize || result.Pages < 1 || len(keys) > pageSize {
		response.ErrorFrom(c, ErrControlPlaneUnavailable)
		return
	}

	out := make([]cloudflareAPIKeyDTO, 0, len(keys))
	for index := range keys {
		key := keys[index]
		if key.ID < 1 || key.UserID != userID || key.GroupID == nil || *key.GroupID < 1 {
			response.ErrorFrom(c, ErrControlPlaneUnavailable)
			return
		}
		group, err := reads.GetManagedGroup(c.Request.Context(), *key.GroupID)
		if err != nil || group == nil || group.ID != *key.GroupID {
			if err == nil {
				err = errors.New("managed api key group mismatch")
			}
			response.ErrorFrom(c, err)
			return
		}
		// The private list protocol intentionally never includes a raw key. Clear
		// this field again at the HTTP boundary so an alternate control plane
		// cannot leak a credential through dto.APIKey.
		key.Key = ""
		key.User = nil
		key.Group = group
		out = append(out, *newCloudflareAPIKeyDTO(&key))
	}
	response.Paginated(c, out, result.Total, result.Page, result.PageSize)
}
