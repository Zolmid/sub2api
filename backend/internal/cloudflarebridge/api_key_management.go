package cloudflarebridge

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
)

// APIKeyManagementControlPlane is intentionally separate from the gateway
// ControlPlane contract. Test doubles and deployments that only implement the
// first gateway slice continue to fail closed with ErrNotMigrated.
type APIKeyManagementControlPlane interface {
	CreateManagedAPIKey(context.Context, *service.APIKey) (*service.APIKey, error)
	GetManagedAPIKey(context.Context, int64) (*service.APIKey, error)
	UpdateManagedAPIKey(context.Context, *service.APIKey, service.APIKeyUpdateFields) (*service.APIKey, error)
	RevokeManagedAPIKey(context.Context, int64, *int64) error
}

type managedAPIKeyWire struct {
	ID          string   `json:"id"`
	UserID      string   `json:"user_id"`
	GroupID     string   `json:"group_id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	IPWhitelist []string `json:"ip_whitelist"`
	IPBlacklist []string `json:"ip_blacklist"`
	ExpiresAt   *string  `json:"expires_at"`
	LastUsedAt  *string  `json:"last_used_at"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	DeletedAt   *string  `json:"deleted_at"`
}

type managedAPIKeyResponse struct {
	APIKey managedAPIKeyWire `json:"api_key"`
	RawKey string            `json:"raw_key,omitempty"`
}

// postManagedMutation retries one ambiguous private-protocol failure. Every
// caller builds its operation ID before entering this helper, so both attempts
// carry the same idempotency identity and the Worker can replay a committed
// result instead of applying the mutation twice.
func (c *HTTPControlPlane) postManagedMutation(ctx context.Context, path string, input any, output *managedAPIKeyResponse) error {
	var target any
	if output != nil {
		target = output
	}
	err := c.post(ctx, path, input, target)
	if !shouldRecoverManagedMutation(ctx, err) {
		return err
	}
	if output != nil {
		*output = managedAPIKeyResponse{}
	}
	return c.post(ctx, path, input, target)
}

func shouldRecoverManagedMutation(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil || !errors.Is(err, ErrControlPlaneUnavailable) {
		return false
	}
	var responseErr *controlPlaneResponseError
	if errors.As(err, &responseErr) {
		return responseErr.StatusCode >= 500
	}
	return true
}

func managementOperationID(kind string) string {
	return kind + ":" + uuid.NewString()
}

func requiredWireTime(label, raw string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s", label)
	}
	return parsed, nil
}

func decodeManagedAPIKey(wire managedAPIKeyWire) (*service.APIKey, error) {
	if wire.DeletedAt != nil {
		return nil, service.ErrAPIKeyNotFound
	}
	id, err := parsePositiveID("api key id", wire.ID)
	if err != nil {
		return nil, err
	}
	userID, err := parsePositiveID("api key user id", wire.UserID)
	if err != nil {
		return nil, err
	}
	groupID, err := parsePositiveID("api key group id", wire.GroupID)
	if err != nil {
		return nil, err
	}
	expiresAt, err := parseOptionalTime(wire.ExpiresAt)
	if err != nil {
		return nil, errors.New("invalid api key expiry")
	}
	lastUsedAt, err := parseOptionalTime(wire.LastUsedAt)
	if err != nil {
		return nil, errors.New("invalid api key last-used timestamp")
	}
	createdAt, err := requiredWireTime("api key creation timestamp", wire.CreatedAt)
	if err != nil {
		return nil, err
	}
	updatedAt, err := requiredWireTime("api key update timestamp", wire.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(wire.Name) == "" || strings.TrimSpace(wire.Status) == "" {
		return nil, errors.New("invalid api key management response")
	}

	return &service.APIKey{
		ID:          id,
		UserID:      userID,
		GroupID:     &groupID,
		Name:        wire.Name,
		Status:      wire.Status,
		IPWhitelist: append([]string(nil), wire.IPWhitelist...),
		IPBlacklist: append([]string(nil), wire.IPBlacklist...),
		ExpiresAt:   expiresAt,
		LastUsedAt:  lastUsedAt,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}, nil
}

func mapManagedAPIKeyError(err error, conflict error) error {
	if err == nil {
		return nil
	}
	var responseErr *controlPlaneResponseError
	if !errors.As(err, &responseErr) {
		return err
	}
	switch responseErr.Code {
	case "NOT_FOUND", "API_KEY_NOT_FOUND":
		return service.ErrAPIKeyNotFound
	case "REFERENCE_REJECTED":
		return service.ErrGroupNotAllowed
	case "CONFLICT":
		if conflict != nil {
			return conflict
		}
	}
	return err
}

func (c *HTTPControlPlane) CreateManagedAPIKey(ctx context.Context, key *service.APIKey) (*service.APIKey, error) {
	if key == nil || key.GroupID == nil {
		return nil, ErrNotMigrated
	}
	request := struct {
		OperationID string   `json:"operation_id"`
		ID          string   `json:"id"`
		UserID      string   `json:"user_id"`
		GroupID     string   `json:"group_id"`
		Name        string   `json:"name"`
		Status      string   `json:"status"`
		RawKey      string   `json:"raw_key"`
		IPWhitelist []string `json:"ip_whitelist"`
		IPBlacklist []string `json:"ip_blacklist"`
		ExpiresAt   *string  `json:"expires_at"`
	}{
		OperationID: managementOperationID("api-key-create"),
		ID:          strconv.FormatInt(key.ID, 10),
		UserID:      strconv.FormatInt(key.UserID, 10),
		GroupID:     strconv.FormatInt(*key.GroupID, 10),
		Name:        key.Name,
		Status:      key.Status,
		RawKey:      key.Key,
		IPWhitelist: append([]string{}, key.IPWhitelist...),
		IPBlacklist: append([]string{}, key.IPBlacklist...),
	}
	if key.ExpiresAt != nil {
		value := key.ExpiresAt.UTC().Format(time.RFC3339Nano)
		request.ExpiresAt = &value
	}

	var response managedAPIKeyResponse
	if err := c.postManagedMutation(ctx, "/v1/manage/api-keys/create", request, &response); err != nil {
		return nil, mapManagedAPIKeyError(err, service.ErrAPIKeyExists)
	}
	created, err := decodeManagedAPIKey(response.APIKey)
	if err != nil {
		return nil, fmt.Errorf("invalid api key create response: %w", err)
	}
	if created.ID != key.ID || created.UserID != key.UserID || created.GroupID == nil || *created.GroupID != *key.GroupID {
		return nil, errors.New("invalid api key create response: identity mismatch")
	}
	if response.RawKey != "" && response.RawKey != key.Key {
		return nil, errors.New("invalid api key create response: credential mismatch")
	}
	created.Key = key.Key
	return created, nil
}

func (c *HTTPControlPlane) GetManagedAPIKey(ctx context.Context, id int64) (*service.APIKey, error) {
	var response managedAPIKeyResponse
	if err := c.post(ctx, "/v1/manage/api-keys/get", struct {
		ID string `json:"id"`
	}{ID: strconv.FormatInt(id, 10)}, &response); err != nil {
		return nil, mapManagedAPIKeyError(err, nil)
	}
	key, err := decodeManagedAPIKey(response.APIKey)
	if err != nil {
		return nil, fmt.Errorf("invalid api key get response: %w", err)
	}
	if key.ID != id {
		return nil, errors.New("invalid api key get response: identity mismatch")
	}
	return key, nil
}

func (c *HTTPControlPlane) UpdateManagedAPIKey(ctx context.Context, key *service.APIKey, fields service.APIKeyUpdateFields) (*service.APIKey, error) {
	if key == nil {
		return nil, errors.New("api key is required")
	}
	request := map[string]any{
		"operation_id": managementOperationID("api-key-update"),
		"id":           strconv.FormatInt(key.ID, 10),
	}
	if fields.Name {
		request["name"] = key.Name
	}
	if fields.Status {
		request["status"] = key.Status
	}
	if fields.IPRules {
		request["ip_whitelist"] = append([]string{}, key.IPWhitelist...)
		request["ip_blacklist"] = append([]string{}, key.IPBlacklist...)
	}
	if fields.ExpiresAt {
		if key.ExpiresAt == nil {
			request["expires_at"] = nil
		} else {
			request["expires_at"] = key.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
	}

	var response managedAPIKeyResponse
	if err := c.postManagedMutation(ctx, "/v1/manage/api-keys/update", request, &response); err != nil {
		return nil, mapManagedAPIKeyError(err, nil)
	}
	updated, err := decodeManagedAPIKey(response.APIKey)
	if err != nil {
		return nil, fmt.Errorf("invalid api key update response: %w", err)
	}
	if updated.ID != key.ID || updated.UserID != key.UserID {
		return nil, errors.New("invalid api key update response: identity mismatch")
	}
	return updated, nil
}

func (c *HTTPControlPlane) RevokeManagedAPIKey(ctx context.Context, id int64, expectedUserID *int64) error {
	request := map[string]any{
		"operation_id": managementOperationID("api-key-revoke"),
		"id":           strconv.FormatInt(id, 10),
	}
	if expectedUserID != nil {
		request["expected_user_id"] = strconv.FormatInt(*expectedUserID, 10)
	}
	err := c.postManagedMutation(ctx, "/v1/manage/api-keys/revoke", request, nil)
	conflict := error(nil)
	if expectedUserID != nil {
		conflict = service.ErrInsufficientPerms
	}
	return mapManagedAPIKeyError(err, conflict)
}

var _ APIKeyManagementControlPlane = (*HTTPControlPlane)(nil)
