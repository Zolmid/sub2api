package cloudflarebridge

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
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

func (r *APIKeyRepository) management() (APIKeyManagementControlPlane, error) {
	management, ok := r.control.(APIKeyManagementControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return management, nil
}

func newPersistentID() (int64, error) {
	for range 4 {
		var value [8]byte
		if _, err := rand.Read(value[:]); err != nil {
			return 0, fmt.Errorf("generate persistent id: %w", err)
		}
		id := int64(binary.BigEndian.Uint64(value[:]) & uint64(^uint64(0)>>1))
		if id > 0 {
			return id, nil
		}
	}
	return 0, errors.New("generate persistent id: exhausted retries")
}

func supportsManagedAPIKeyCreate(key *service.APIKey) bool {
	return key != nil && key.UserID > 0 && key.GroupID != nil && *key.GroupID > 0 &&
		key.Key != "" && key.Name != "" &&
		(key.Status == service.StatusAPIKeyActive || key.Status == service.StatusAPIKeyDisabled) &&
		key.Quota == 0 && key.QuotaUsed == 0 && key.RateLimit5h == 0 &&
		key.RateLimit1d == 0 && key.RateLimit7d == 0 && key.Usage5h == 0 &&
		key.Usage1d == 0 && key.Usage7d == 0 && key.Window5hStart == nil &&
		key.Window1dStart == nil && key.Window7dStart == nil
}

func (r *APIKeyRepository) Create(ctx context.Context, key *service.APIKey) error {
	if !supportsManagedAPIKeyCreate(key) {
		return ErrNotMigrated
	}
	management, err := r.management()
	if err != nil {
		return err
	}
	candidate := *key
	if candidate.ID == 0 {
		candidate.ID, err = newPersistentID()
		if err != nil {
			return err
		}
	}
	if candidate.ID < 1 {
		return errors.New("api key id must be positive")
	}
	created, err := management.CreateManagedAPIKey(ctx, &candidate)
	if err != nil {
		return err
	}
	if created == nil {
		return errors.New("cloudflare api key create returned no record")
	}
	*key = *created
	return nil
}

func (r *APIKeyRepository) GetByID(ctx context.Context, id int64) (*service.APIKey, error) {
	management, err := r.management()
	if err != nil {
		return nil, err
	}
	return management.GetManagedAPIKey(ctx, id)
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

func (r *APIKeyRepository) Update(ctx context.Context, key *service.APIKey, fields service.APIKeyUpdateFields) error {
	if fields.IsEmpty() {
		return nil
	}
	if fields.GroupID || fields.Quota || fields.QuotaUsed || fields.RateLimits || fields.RateLimitUsage {
		return ErrNotMigrated
	}
	if key == nil || key.ID < 1 || key.UserID < 1 {
		return errors.New("api key identity is required")
	}
	if fields.Status && key.Status != service.StatusAPIKeyActive && key.Status != service.StatusAPIKeyDisabled {
		return ErrNotMigrated
	}
	management, err := r.management()
	if err != nil {
		return err
	}
	updated, err := management.UpdateManagedAPIKey(ctx, key, fields)
	if err != nil {
		return err
	}
	if updated == nil {
		return errors.New("cloudflare api key update returned no record")
	}
	key.UpdatedAt = updated.UpdatedAt
	return nil
}

func (r *APIKeyRepository) Delete(ctx context.Context, id int64) error {
	management, err := r.management()
	if err != nil {
		return err
	}
	return management.RevokeManagedAPIKey(ctx, id, nil)
}

func (r *APIKeyRepository) DeleteWithAudit(ctx context.Context, id int64) error {
	return r.Delete(ctx, id)
}

func (r *APIKeyRepository) DeleteWithAuditForOwner(ctx context.Context, id, userID int64) error {
	management, err := r.management()
	if err != nil {
		return err
	}
	return management.RevokeManagedAPIKey(ctx, id, &userID)
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
var _ service.APIKeyOwnerDeleteRepository = (*APIKeyRepository)(nil)
