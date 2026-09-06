package cloudflarebridge

import (
	"context"
	"errors"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// ErrNotMigrated is returned by management operations that are intentionally
// outside the first Cloudflare vertical slice. Returning an error is deliberate:
// Cloudflare mode must not silently fall back to memory, PostgreSQL, or Redis.
var ErrNotMigrated = errors.New("operation is not migrated to the cloudflare backend")

type APIKeyRepository struct {
	control ControlPlane
}

func NewAPIKeyRepository(control ControlPlane) *APIKeyRepository {
	return &APIKeyRepository{control: control}
}

func (r *APIKeyRepository) Create(context.Context, *service.APIKey) error {
	return ErrNotMigrated
}

func (r *APIKeyRepository) GetByID(context.Context, int64) (*service.APIKey, error) {
	return nil, ErrNotMigrated
}

func (r *APIKeyRepository) GetKeyAndOwnerID(context.Context, int64) (string, int64, error) {
	return "", 0, ErrNotMigrated
}

func (r *APIKeyRepository) GetByKey(ctx context.Context, key string) (*service.APIKey, error) {
	return r.control.ResolveAPIKey(ctx, key)
}

func (r *APIKeyRepository) GetByKeyForAuth(ctx context.Context, key string) (*service.APIKey, error) {
	return r.control.ResolveAPIKey(ctx, key)
}

func (r *APIKeyRepository) Update(context.Context, *service.APIKey, service.APIKeyUpdateFields) error {
	return ErrNotMigrated
}

func (r *APIKeyRepository) Delete(context.Context, int64) error {
	return ErrNotMigrated
}

func (r *APIKeyRepository) DeleteWithAudit(context.Context, int64) error {
	return ErrNotMigrated
}

func (r *APIKeyRepository) ListByUserID(context.Context, int64, pagination.PaginationParams, service.APIKeyListFilters) ([]service.APIKey, *pagination.PaginationResult, error) {
	return nil, nil, ErrNotMigrated
}

func (r *APIKeyRepository) VerifyOwnership(context.Context, int64, []int64) ([]int64, error) {
	return nil, ErrNotMigrated
}

func (r *APIKeyRepository) CountByUserID(context.Context, int64) (int64, error) {
	return 0, ErrNotMigrated
}

func (r *APIKeyRepository) ExistsByKey(context.Context, string) (bool, error) {
	return false, ErrNotMigrated
}

func (r *APIKeyRepository) ListByGroupID(context.Context, int64, pagination.PaginationParams) ([]service.APIKey, *pagination.PaginationResult, error) {
	return nil, nil, ErrNotMigrated
}

func (r *APIKeyRepository) SearchAPIKeys(context.Context, int64, string, int) ([]service.APIKey, error) {
	return nil, ErrNotMigrated
}

func (r *APIKeyRepository) ClearGroupIDByGroupID(context.Context, int64) (int64, error) {
	return 0, ErrNotMigrated
}

func (r *APIKeyRepository) UpdateGroupIDByUserAndGroup(context.Context, int64, int64, int64) (int64, error) {
	return 0, ErrNotMigrated
}

func (r *APIKeyRepository) CountByGroupID(context.Context, int64) (int64, error) {
	return 0, ErrNotMigrated
}

func (r *APIKeyRepository) ListKeysByUserID(context.Context, int64) ([]string, error) {
	return nil, ErrNotMigrated
}

func (r *APIKeyRepository) ListKeysByGroupID(context.Context, int64) ([]string, error) {
	return nil, ErrNotMigrated
}

func (r *APIKeyRepository) IncrementQuotaUsed(context.Context, int64, float64) (float64, error) {
	return 0, ErrNotMigrated
}

func (r *APIKeyRepository) UpdateLastUsed(ctx context.Context, id int64, usedAt time.Time) error {
	return r.control.TouchAPIKey(ctx, id, usedAt)
}

func (r *APIKeyRepository) IncrementRateLimitUsage(context.Context, int64, float64) error {
	return ErrNotMigrated
}

func (r *APIKeyRepository) ResetRateLimitWindows(context.Context, int64) error {
	return ErrNotMigrated
}

func (r *APIKeyRepository) GetRateLimitData(context.Context, int64) (*service.APIKeyRateLimitData, error) {
	return nil, ErrNotMigrated
}

var _ service.APIKeyRepository = (*APIKeyRepository)(nil)
