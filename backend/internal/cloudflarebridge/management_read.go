package cloudflarebridge

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

const managedListPageSize = 100

const (
	microUSDPerUSD       = uint64(1_000_000)
	maxExactFloatInteger = uint64(1<<53 - 1)
)

// ManagementReadControlPlane is the non-secret read subset used by the first
// Cloudflare management slice. Authentication records containing password
// verifiers deliberately use a different protocol and interface.
type ManagementReadControlPlane interface {
	GetManagedUser(context.Context, int64) (*service.User, error)
	GetManagedGroup(context.Context, int64) (*service.Group, error)
	ListActiveManagedGroups(context.Context) ([]service.Group, error)
}

// AdminListControlPlane is intentionally separate from ManagementReadControlPlane.
// The existing three-method interface remains the narrow contract used by the
// user/API-key slice; only the administrator read handler needs full lists.
type AdminListControlPlane interface {
	ManagementReadControlPlane
	ListManagedUsers(context.Context) ([]service.User, error)
	ListManagedGroups(context.Context) ([]service.Group, error)
}

// ManagedUserReader adapts the private Worker management protocol to the
// narrow user dependency consumed by APIKeyService. It must not be used as a
// JWT reader: this response intentionally contains neither password hashes nor
// the resolved token-version fingerprint required by JWT validation.
type ManagedUserReader struct {
	control ControlPlane
}

func NewManagedUserReader(control ControlPlane) *ManagedUserReader {
	return &ManagedUserReader{control: control}
}

func (r *ManagedUserReader) GetByID(ctx context.Context, id int64) (*service.User, error) {
	management, ok := r.control.(ManagementReadControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return management.GetManagedUser(ctx, id)
}

// ManagedGroupReader adapts the private Worker protocol to APIKeyService's
// narrow group dependency. Only standard OpenAI groups are admitted until the
// remaining group fields and subscription entitlement model are migrated.
type ManagedGroupReader struct {
	control ControlPlane
}

func NewManagedGroupReader(control ControlPlane) *ManagedGroupReader {
	return &ManagedGroupReader{control: control}
}

func (r *ManagedGroupReader) GetByID(ctx context.Context, id int64) (*service.Group, error) {
	management, ok := r.control.(ManagementReadControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return management.GetManagedGroup(ctx, id)
}

func (r *ManagedGroupReader) ListActive(ctx context.Context) ([]service.Group, error) {
	management, ok := r.control.(ManagementReadControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return management.ListActiveManagedGroups(ctx)
}

type managedUserWire struct {
	ID                   string   `json:"id"`
	Email                string   `json:"email"`
	Username             string   `json:"username"`
	Notes                string   `json:"notes"`
	Status               string   `json:"status"`
	Role                 string   `json:"role"`
	Concurrency          int      `json:"concurrency"`
	RPMLimit             int      `json:"rpm_limit"`
	BalanceMicroUSD      string   `json:"balance_microusd"`
	AllowedGroupIDs      []string `json:"allowed_group_ids"`
	RestrictPublicGroups bool     `json:"restrict_public_groups"`
	CreatedAt            string   `json:"created_at"`
	UpdatedAt            string   `json:"updated_at"`
	DeletedAt            *string  `json:"deleted_at"`
}

type managedGroupWire struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	Platform         string  `json:"platform"`
	Status           string  `json:"status"`
	IsExclusive      bool    `json:"is_exclusive"`
	SubscriptionType string  `json:"subscription_type"`
	CreatedAt        string  `json:"created_at"`
	UpdatedAt        string  `json:"updated_at"`
	DeletedAt        *string `json:"deleted_at"`
}

func canonicalUnsignedDecimal(value string) bool {
	if value == "0" {
		return true
	}
	return isCanonicalPositiveDecimal(value)
}

// displayBalanceFromMicroUSD converts the fixed-point D1 representation only
// at the presentation read boundary. Requiring the integer coefficient to be
// exactly representable by float64 prevents a large D1 value from being
// silently rounded before it reaches legacy display DTOs.
func displayBalanceFromMicroUSD(value string) (float64, error) {
	if !canonicalUnsignedDecimal(value) || len(value) > 40 {
		return 0, errors.New("invalid balance_microusd")
	}
	microUSD, err := strconv.ParseUint(value, 10, 64)
	if err != nil || microUSD > maxExactFloatInteger {
		return 0, errors.New("balance_microusd is not exactly representable")
	}
	balance := float64(microUSD) / float64(microUSDPerUSD)
	if math.IsNaN(balance) || math.IsInf(balance, 0) || uint64(math.Round(balance*float64(microUSDPerUSD))) != microUSD {
		return 0, errors.New("balance_microusd is not exactly representable")
	}
	return balance, nil
}

func decodeManagedUser(wire managedUserWire) (*service.User, bool, error) {
	id, err := parsePositiveID("user id", wire.ID)
	if err != nil {
		return nil, false, err
	}
	createdAt, err := requiredWireTime("user creation timestamp", wire.CreatedAt)
	if err != nil {
		return nil, false, err
	}
	updatedAt, err := requiredWireTime("user update timestamp", wire.UpdatedAt)
	if err != nil {
		return nil, false, err
	}
	deletedAt, err := parseOptionalTime(wire.DeletedAt)
	if err != nil {
		return nil, false, errors.New("invalid user deletion timestamp")
	}
	if strings.TrimSpace(wire.Email) == "" || len(wire.Email) > 255 || len(wire.Username) > 100 || len(wire.Notes) > 4096 ||
		(wire.Status != service.StatusActive && wire.Status != service.StatusDisabled) ||
		(wire.Role != service.RoleUser && wire.Role != service.RoleAdmin) ||
		wire.Concurrency < 1 || wire.Concurrency > 100000 || wire.RPMLimit < 0 || wire.RPMLimit > 1000000 ||
		len(wire.AllowedGroupIDs) > 100 {
		return nil, false, errors.New("invalid managed user response")
	}
	balance, err := displayBalanceFromMicroUSD(wire.BalanceMicroUSD)
	if err != nil {
		return nil, false, errors.New("invalid managed user response: balance")
	}

	allowedGroups := make([]int64, 0, len(wire.AllowedGroupIDs))
	seen := make(map[int64]struct{}, len(wire.AllowedGroupIDs))
	for _, rawID := range wire.AllowedGroupIDs {
		groupID, err := parsePositiveID("allowed group id", rawID)
		if err != nil {
			return nil, false, err
		}
		if _, exists := seen[groupID]; exists {
			return nil, false, errors.New("invalid managed user response: duplicate allowed group")
		}
		seen[groupID] = struct{}{}
		allowedGroups = append(allowedGroups, groupID)
	}

	return &service.User{
		ID:                   id,
		Email:                wire.Email,
		Username:             wire.Username,
		Notes:                wire.Notes,
		Status:               wire.Status,
		Role:                 wire.Role,
		Concurrency:          wire.Concurrency,
		RPMLimit:             wire.RPMLimit,
		Balance:              balance,
		AllowedGroups:        allowedGroups,
		RestrictPublicGroups: wire.RestrictPublicGroups,
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
		DeletedAt:            deletedAt,
	}, deletedAt != nil, nil
}

func decodeManagedGroup(wire managedGroupWire) (*service.Group, bool, error) {
	id, err := parsePositiveID("group id", wire.ID)
	if err != nil {
		return nil, false, err
	}
	createdAt, err := requiredWireTime("group creation timestamp", wire.CreatedAt)
	if err != nil {
		return nil, false, err
	}
	updatedAt, err := requiredWireTime("group update timestamp", wire.UpdatedAt)
	if err != nil {
		return nil, false, err
	}
	deletedAt, err := parseOptionalTime(wire.DeletedAt)
	if err != nil {
		return nil, false, errors.New("invalid group deletion timestamp")
	}
	if strings.TrimSpace(wire.Name) == "" || len(wire.Name) > 100 || strings.TrimSpace(wire.Platform) == "" ||
		(wire.Status != service.StatusActive && wire.Status != service.StatusDisabled) ||
		(wire.SubscriptionType != service.SubscriptionTypeStandard && wire.SubscriptionType != service.SubscriptionTypeSubscription) {
		return nil, false, errors.New("invalid managed group response")
	}
	return &service.Group{
		ID:               id,
		Name:             wire.Name,
		Platform:         wire.Platform,
		RateMultiplier:   1,
		Status:           wire.Status,
		IsExclusive:      wire.IsExclusive,
		SubscriptionType: wire.SubscriptionType,
		Hydrated:         true,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
	}, deletedAt != nil, nil
}

func ensureManagedGroupInCurrentSlice(group *service.Group) error {
	if group == nil || group.Platform != service.PlatformOpenAI || group.SubscriptionType != service.SubscriptionTypeStandard {
		return ErrNotMigrated
	}
	return nil
}

func mapManagedReadError(err, notFound error) error {
	if err == nil {
		return nil
	}
	var responseErr *controlPlaneResponseError
	if errors.As(err, &responseErr) {
		switch responseErr.Code {
		case "NOT_FOUND", "USER_NOT_FOUND", "GROUP_NOT_FOUND":
			return notFound
		}
	}
	return err
}

func (c *HTTPControlPlane) GetManagedUser(ctx context.Context, id int64) (*service.User, error) {
	if id < 1 {
		return nil, service.ErrUserNotFound
	}
	var response struct {
		User managedUserWire `json:"user"`
	}
	if err := c.post(ctx, "/v1/manage/users/get", struct {
		ID string `json:"id"`
	}{ID: strconv.FormatInt(id, 10)}, &response); err != nil {
		return nil, mapManagedReadError(err, service.ErrUserNotFound)
	}
	user, deleted, err := decodeManagedUser(response.User)
	if err != nil {
		return nil, fmt.Errorf("invalid managed user response: %w", err)
	}
	if user.ID != id {
		return nil, errors.New("invalid managed user response: identity mismatch")
	}
	if deleted {
		return nil, service.ErrUserNotFound
	}
	return user, nil
}

func (c *HTTPControlPlane) GetManagedGroup(ctx context.Context, id int64) (*service.Group, error) {
	if id < 1 {
		return nil, service.ErrGroupNotFound
	}
	var response struct {
		Group managedGroupWire `json:"group"`
	}
	if err := c.post(ctx, "/v1/manage/groups/get", struct {
		ID string `json:"id"`
	}{ID: strconv.FormatInt(id, 10)}, &response); err != nil {
		return nil, mapManagedReadError(err, service.ErrGroupNotFound)
	}
	group, deleted, err := decodeManagedGroup(response.Group)
	if err != nil {
		return nil, fmt.Errorf("invalid managed group response: %w", err)
	}
	if group.ID != id {
		return nil, errors.New("invalid managed group response: identity mismatch")
	}
	if deleted {
		return nil, service.ErrGroupNotFound
	}
	if err := ensureManagedGroupInCurrentSlice(group); err != nil {
		return nil, err
	}
	return group, nil
}

func (c *HTTPControlPlane) ListActiveManagedGroups(ctx context.Context) ([]service.Group, error) {
	return c.listManagedGroups(ctx, true)
}

func (c *HTTPControlPlane) ListManagedUsers(ctx context.Context) ([]service.User, error) {
	cursor := "0"
	users := make([]service.User, 0)
	seen := make(map[int64]struct{})
	for page := 0; page < 100; page++ {
		var response struct {
			Users      []managedUserWire `json:"users"`
			NextCursor *string           `json:"next_cursor"`
		}
		request := struct {
			Cursor string `json:"cursor"`
			Limit  int    `json:"limit"`
		}{Cursor: cursor, Limit: managedListPageSize}
		if err := c.post(ctx, "/v1/manage/users/list", request, &response); err != nil {
			return nil, err
		}
		if response.Users == nil {
			return nil, errors.New("invalid managed user list response: users array is required")
		}
		if len(response.Users) > managedListPageSize {
			return nil, errors.New("invalid managed user list response: page too large")
		}
		previousID := cursor
		for _, wire := range response.Users {
			if !isCanonicalPositiveDecimal(wire.ID) || !decimalStringGreater(wire.ID, previousID) {
				return nil, errors.New("invalid managed user list response: user order did not advance")
			}
			previousID = wire.ID
			user, deleted, err := decodeManagedUser(wire)
			if err != nil {
				return nil, fmt.Errorf("invalid managed user list response: %w", err)
			}
			if _, exists := seen[user.ID]; exists {
				return nil, errors.New("invalid managed user list response: duplicate user")
			}
			seen[user.ID] = struct{}{}
			if !deleted {
				users = append(users, *user)
			}
		}
		if response.NextCursor == nil {
			return users, nil
		}
		next := *response.NextCursor
		if !isCanonicalPositiveDecimal(next) || !decimalStringGreater(next, cursor) {
			return nil, errors.New("invalid managed user list response: cursor did not advance")
		}
		if len(response.Users) == 0 || next != previousID {
			return nil, errors.New("invalid managed user list response: cursor does not match page")
		}
		cursor = next
	}
	return nil, errors.New("invalid managed user list response: too many pages")
}

func (c *HTTPControlPlane) ListManagedGroups(ctx context.Context) ([]service.Group, error) {
	return c.listManagedGroups(ctx, false)
}

func (c *HTTPControlPlane) listManagedGroups(ctx context.Context, activeOnly bool) ([]service.Group, error) {
	cursor := "0"
	groups := make([]service.Group, 0)
	seen := make(map[int64]struct{})
	for page := 0; page < 100; page++ {
		var response struct {
			Groups     []managedGroupWire `json:"groups"`
			NextCursor *string            `json:"next_cursor"`
		}
		request := struct {
			Cursor string `json:"cursor"`
			Limit  int    `json:"limit"`
		}{Cursor: cursor, Limit: managedListPageSize}
		if err := c.post(ctx, "/v1/manage/groups/list", request, &response); err != nil {
			return nil, err
		}
		if response.Groups == nil {
			return nil, errors.New("invalid managed group list response: groups array is required")
		}
		if len(response.Groups) > managedListPageSize {
			return nil, errors.New("invalid managed group list response: page too large")
		}
		previousID := cursor
		for _, wire := range response.Groups {
			if !isCanonicalPositiveDecimal(wire.ID) || !decimalStringGreater(wire.ID, previousID) {
				return nil, errors.New("invalid managed group list response: group order did not advance")
			}
			previousID = wire.ID
			group, deleted, err := decodeManagedGroup(wire)
			if err != nil {
				return nil, fmt.Errorf("invalid managed group list response: %w", err)
			}
			if _, exists := seen[group.ID]; exists {
				return nil, errors.New("invalid managed group list response: duplicate group")
			}
			seen[group.ID] = struct{}{}
			if deleted {
				continue
			}
			if activeOnly && group.Status != service.StatusActive {
				continue
			}
			if err := ensureManagedGroupInCurrentSlice(group); err != nil {
				return nil, err
			}
			groups = append(groups, *group)
		}
		if response.NextCursor == nil {
			return groups, nil
		}
		next := *response.NextCursor
		if !isCanonicalPositiveDecimal(next) || !decimalStringGreater(next, cursor) {
			return nil, errors.New("invalid managed group list response: cursor did not advance")
		}
		if len(response.Groups) == 0 || next != previousID {
			return nil, errors.New("invalid managed group list response: cursor does not match page")
		}
		cursor = next
	}
	return nil, errors.New("invalid managed group list response: too many pages")
}

func decimalStringGreater(left, right string) bool {
	left = strings.TrimLeft(left, "0")
	right = strings.TrimLeft(right, "0")
	if left == "" {
		left = "0"
	}
	if right == "" {
		right = "0"
	}
	if len(left) != len(right) {
		return len(left) > len(right)
	}
	return left > right
}

var _ ManagementReadControlPlane = (*HTTPControlPlane)(nil)
var _ service.APIKeyUserReader = (*ManagedUserReader)(nil)
var _ service.APIKeyGroupReader = (*ManagedGroupReader)(nil)
