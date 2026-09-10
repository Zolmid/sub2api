package cloudflarebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Subscription values deliberately retain D1 identifiers and E8 values as
// decimal strings.  They are not Go numeric DTOs: doing so would make a
// future public compatibility adapter silently lose precision.
type Subscription struct {
	ID, UserID, GroupID                                                           string
	PlanID                                                                        *string
	StartsAt, ExpiresAt                                                           time.Time
	Status                                                                        string
	InitialDailyBoundary, DailyWindowStart, WeeklyWindowStart, MonthlyWindowStart *time.Time
	WeeklyAnchorKind, MonthlyAnchorKind                                           *string
	DailyLimitE8USD, WeeklyLimitE8USD, MonthlyLimitE8USD                          *string
	DailyUsageE8USD, WeeklyUsageE8USD, MonthlyUsageE8USD                          string
	AssignedBy                                                                    *string
	AssignedAt                                                                    time.Time
	Notes                                                                         string
	Version                                                                       int
	CreatedAt, UpdatedAt                                                          time.Time
	DeletedAt                                                                     *time.Time
}

type SubscriptionGetRequest struct {
	ID             string
	IncludeDeleted bool
}
type SubscriptionListRequest struct {
	UserID, GroupID, Status *string
	IncludeDeleted          bool
	AfterID                 *string
	Limit                   int
}
type SubscriptionPage struct {
	Items       []Subscription
	NextAfterID *string
}
type SubscriptionAssignOrExtendRequest struct {
	OperationID, NewSubscriptionID, UserID, GroupID string
	PlanID, AssignedBy                              *string
	ValidityDays                                    int
	Notes                                           string
	Now, DailyBoundary                              time.Time
}
type SubscriptionRevokeRequest struct {
	OperationID, SubscriptionID, ActorUserID string
	ExpectedVersion                          int
	At                                       time.Time
}
type SubscriptionRestoreRequest struct {
	OperationID, SubscriptionID, ActorUserID string
	ExpectedVersion                          int
	Now                                      time.Time
}
type SubscriptionExtendRequest struct {
	OperationID, SubscriptionID, ActorUserID string
	ExpectedVersion, Days                    int
	Now                                      time.Time
}
type SubscriptionActivateWindowsRequest struct {
	OperationID, SubscriptionID string
	ExpectedVersion             int
	ActivatedAt, DailyBoundary  time.Time
}
type SubscriptionMaintainWindowsRequest struct {
	OperationID, SubscriptionID string
	ExpectedVersion             int
	Now, DailyBoundary          time.Time
}
type SubscriptionResetWindowsRequest struct {
	OperationID, SubscriptionID, ActorUserID string
	ExpectedVersion                          int
	ResetDaily, ResetWeekly, ResetMonthly    bool
	ResetAt, DailyBoundary                   time.Time
}
type SubscriptionReserveUsageRequest struct {
	OperationID, SubscriptionID, AmountE8USD string
	ExpectedVersion                          int
	At                                       time.Time
}
type SubscriptionSweepExpiredRequest struct {
	OperationID string
	Cutoff      time.Time
	AfterID     *string
	Limit       int
}
type SubscriptionMutationResult struct {
	Subscription *Subscription
	Extended     bool
}
type SubscriptionSweepResult struct {
	ExpiredIDs []string
	Count      int
}

var (
	ErrSubscriptionValidation          = errors.New("cloudflare subscription validation failed")
	ErrSubscriptionNotFound            = errors.New("cloudflare subscription not found")
	ErrSubscriptionConflict            = errors.New("cloudflare subscription conflict")
	ErrSubscriptionStaleVersion        = errors.New("cloudflare subscription stale version")
	ErrSubscriptionIdempotencyConflict = errors.New("cloudflare subscription idempotency conflict")
	ErrSubscriptionUnavailable         = errors.New("cloudflare subscription unavailable")
	ErrSubscriptionCursorContract      = errors.New("cloudflare subscription cursor contract cannot satisfy legacy list interface")
)

const maxSubscriptionVersion = 2147483647

const (
	apiKeySubscriptionPageSize = 100
	// Ten thousand live subscriptions for one user is far beyond the intended
	// entitlement cardinality while keeping corrupted or adversarial cursor
	// streams from causing unbounded work in API-key authorization.
	maxAPIKeySubscriptionPages = 100
)

var (
	maxSubscriptionE8, _    = new(big.Int).SetString("9223372036854775807", 10)
	subscriptionOperationRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	subscriptionErrorCodeRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
)

type subscriptionProtocolError struct {
	category error
	code     string
}

func (e *subscriptionProtocolError) Error() string { return e.category.Error() + ": " + e.code }
func (e *subscriptionProtocolError) Is(target error) bool {
	if target == e.category || (e.category == ErrSubscriptionStaleVersion && target == ErrSubscriptionConflict) ||
		(e.category == ErrSubscriptionIdempotencyConflict && target == ErrSubscriptionConflict) {
		return true
	}
	return false
}

func subscriptionError(err error) error {
	var response *controlPlaneResponseError
	if !errors.As(err, &response) {
		if errors.Is(err, ErrControlPlaneUnavailable) {
			return ErrSubscriptionUnavailable
		}
		return err
	}
	code := response.Code
	if !subscriptionErrorCodeRE.MatchString(code) {
		code = "SUBSCRIPTION_UNAVAILABLE"
	}
	category := ErrSubscriptionUnavailable
	switch response.StatusCode {
	case 400:
		category = ErrSubscriptionValidation
	case 404:
		category = ErrSubscriptionNotFound
	case 409:
		category = ErrSubscriptionConflict
		if code == "STALE_VERSION" {
			category = ErrSubscriptionStaleVersion
		}
		if code == "IDEMPOTENCY_CONFLICT" {
			category = ErrSubscriptionIdempotencyConflict
		}
	case 503:
		category = ErrSubscriptionUnavailable
	}
	return &subscriptionProtocolError{category: category, code: code}
}

func validSubscriptionID(value string) bool {
	if !isCanonicalPositiveDecimal(value) {
		return false
	}
	n, ok := new(big.Int).SetString(value, 10)
	return ok && n.Cmp(maxSubscriptionE8) <= 0
}

func validSubscriptionE8(value string) bool {
	if value == "0" {
		return true
	}
	if !isCanonicalPositiveDecimal(value) {
		return false
	}
	n, ok := new(big.Int).SetString(value, 10)
	return ok && n.Cmp(maxSubscriptionE8) <= 0
}

func validateSubscriptionID(label, value string) error {
	if !validSubscriptionID(value) {
		return fmt.Errorf("%w: invalid %s", ErrSubscriptionValidation, label)
	}
	return nil
}
func validateOptionalSubscriptionID(label string, value *string) error {
	if value != nil {
		return validateSubscriptionID(label, *value)
	}
	return nil
}
func validateOperationID(value string) error {
	if !subscriptionOperationRE.MatchString(value) {
		return fmt.Errorf("%w: invalid operation id", ErrSubscriptionValidation)
	}
	return nil
}
func validateVersion(value int) error {
	if value < 1 || value > maxSubscriptionVersion {
		return fmt.Errorf("%w: invalid expected version", ErrSubscriptionValidation)
	}
	return nil
}
func validateLimit(value int) error {
	if value < 1 || value > 100 {
		return fmt.Errorf("%w: invalid limit", ErrSubscriptionValidation)
	}
	return nil
}
func validateSubscriptionTime(label string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value.Nanosecond()%int(time.Millisecond) != 0 || value.Year() > 2099 {
		return fmt.Errorf("%w: invalid %s", ErrSubscriptionValidation, label)
	}
	return nil
}
func subscriptionTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
func validateBoundary(now, boundary time.Time) error {
	if boundary.After(now) {
		return fmt.Errorf("%w: daily boundary is in the future", ErrSubscriptionValidation)
	}
	return nil
}

func (c *HTTPControlPlane) subscriptionPost(ctx context.Context, path string, request any, response any) error {
	var raw json.RawMessage
	if err := c.post(ctx, path, request, &raw); err != nil {
		return subscriptionError(err)
	}
	if len(raw) == 0 {
		return fmt.Errorf("%w: empty response", ErrSubscriptionUnavailable)
	}
	if err := json.Unmarshal(raw, response); err != nil {
		return fmt.Errorf("%w: malformed response", ErrSubscriptionUnavailable)
	}
	return nil
}

// strictObject verifies every response object before any fields are decoded.
func strictSubscriptionObject(raw json.RawMessage, required ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return nil, errors.New("object required")
	}
	delimiter, ok := first.(json.Delim)
	if !ok || delimiter != '{' {
		return nil, errors.New("object required")
	}
	object := make(map[string]json.RawMessage, len(required))
	for decoder.More() {
		token, tokenErr := decoder.Token()
		key, keyOK := token.(string)
		if tokenErr != nil || !keyOK {
			return nil, errors.New("invalid object key")
		}
		if _, exists := object[key]; exists {
			return nil, errors.New("duplicate field")
		}
		var value json.RawMessage
		if valueErr := decoder.Decode(&value); valueErr != nil {
			return nil, errors.New("invalid field")
		}
		object[key] = value
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') {
		return nil, errors.New("object required")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON")
	}
	if len(object) != len(required) {
		return nil, errors.New("unknown or missing field")
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return nil, errors.New("missing field")
		}
	}
	return object, nil
}

var subscriptionFields = []string{
	"id", "user_id", "group_id", "plan_id", "starts_at", "expires_at", "status",
	"initial_daily_boundary", "daily_window_start", "weekly_window_start", "monthly_window_start",
	"weekly_anchor_kind", "monthly_anchor_kind", "daily_limit_e8_usd", "weekly_limit_e8_usd",
	"monthly_limit_e8_usd", "daily_usage_e8_usd", "weekly_usage_e8_usd", "monthly_usage_e8_usd",
	"assigned_by", "assigned_at", "notes", "version", "created_at", "updated_at", "deleted_at",
}

func rawString(object map[string]json.RawMessage, key string) (string, error) {
	var value string
	if err := json.Unmarshal(object[key], &value); err != nil {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return value, nil
}
func rawIsNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }
func rawNullableString(object map[string]json.RawMessage, key string) (*string, error) {
	if rawIsNull(object[key]) {
		return nil, nil
	}
	value, err := rawString(object, key)
	if err != nil {
		return nil, err
	}
	return &value, nil
}
func rawTime(object map[string]json.RawMessage, key string) (time.Time, error) {
	value, err := rawString(object, key)
	if err != nil {
		return time.Time{}, err
	}
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf("%s must be UTC", key)
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond()%int(time.Millisecond) != 0 || parsed.Year() > 2099 {
		return time.Time{}, fmt.Errorf("invalid %s", key)
	}
	return parsed, nil
}
func rawNullableTime(object map[string]json.RawMessage, key string) (*time.Time, error) {
	if rawIsNull(object[key]) {
		return nil, nil
	}
	value, err := rawTime(object, key)
	if err != nil {
		return nil, err
	}
	return &value, nil
}
func rawVersion(object map[string]json.RawMessage, key string) (int, error) {
	var value json.Number
	if err := json.Unmarshal(object[key], &value); err != nil {
		return 0, fmt.Errorf("%s must be a number", key)
	}
	parsed, err := strconv.Atoi(value.String())
	if err != nil || parsed < 1 || parsed > maxSubscriptionVersion {
		return 0, fmt.Errorf("invalid %s", key)
	}
	return parsed, nil
}
func rawE8(object map[string]json.RawMessage, key string, nullable bool) (*string, error) {
	if nullable && rawIsNull(object[key]) {
		return nil, nil
	}
	value, err := rawString(object, key)
	if err != nil {
		return nil, err
	}
	if !validSubscriptionE8(value) {
		return nil, fmt.Errorf("invalid %s", key)
	}
	return &value, nil
}

func decodeSubscription(raw json.RawMessage) (*Subscription, error) {
	object, err := strictSubscriptionObject(raw, subscriptionFields...)
	if err != nil {
		return nil, err
	}
	readID := func(key string, nullable bool) (*string, error) {
		if nullable && rawIsNull(object[key]) {
			return nil, nil
		}
		value, err := rawString(object, key)
		if err != nil || !validSubscriptionID(value) {
			return nil, fmt.Errorf("invalid %s", key)
		}
		return &value, nil
	}
	id, err := readID("id", false)
	if err != nil {
		return nil, err
	}
	userID, err := readID("user_id", false)
	if err != nil {
		return nil, err
	}
	groupID, err := readID("group_id", false)
	if err != nil {
		return nil, err
	}
	planID, err := readID("plan_id", true)
	if err != nil {
		return nil, err
	}
	startsAt, err := rawTime(object, "starts_at")
	if err != nil {
		return nil, err
	}
	expiresAt, err := rawTime(object, "expires_at")
	if err != nil || !expiresAt.After(startsAt) {
		return nil, errors.New("invalid expiry")
	}
	status, err := rawString(object, "status")
	if err != nil || (status != service.SubscriptionStatusActive && status != service.SubscriptionStatusExpired && status != service.SubscriptionStatusSuspended) {
		return nil, errors.New("invalid status")
	}
	initial, err := rawNullableTime(object, "initial_daily_boundary")
	if err != nil {
		return nil, err
	}
	daily, err := rawNullableTime(object, "daily_window_start")
	if err != nil {
		return nil, err
	}
	weekly, err := rawNullableTime(object, "weekly_window_start")
	if err != nil {
		return nil, err
	}
	monthly, err := rawNullableTime(object, "monthly_window_start")
	if err != nil {
		return nil, err
	}
	weeklyKind, err := rawNullableString(object, "weekly_anchor_kind")
	if err != nil {
		return nil, err
	}
	monthlyKind, err := rawNullableString(object, "monthly_anchor_kind")
	if err != nil {
		return nil, err
	}
	validKind := func(value *string) bool {
		return value == nil || *value == "activation" || *value == "manual" || *value == "legacy_initial"
	}
	if !validKind(weeklyKind) || !validKind(monthlyKind) {
		return nil, errors.New("invalid anchor kind")
	}
	dailyLimit, err := rawE8(object, "daily_limit_e8_usd", true)
	if err != nil {
		return nil, err
	}
	weeklyLimit, err := rawE8(object, "weekly_limit_e8_usd", true)
	if err != nil {
		return nil, err
	}
	monthlyLimit, err := rawE8(object, "monthly_limit_e8_usd", true)
	if err != nil {
		return nil, err
	}
	dailyUsage, err := rawE8(object, "daily_usage_e8_usd", false)
	if err != nil {
		return nil, err
	}
	weeklyUsage, err := rawE8(object, "weekly_usage_e8_usd", false)
	if err != nil {
		return nil, err
	}
	monthlyUsage, err := rawE8(object, "monthly_usage_e8_usd", false)
	if err != nil {
		return nil, err
	}
	assignedBy, err := readID("assigned_by", true)
	if err != nil {
		return nil, err
	}
	assignedAt, err := rawTime(object, "assigned_at")
	if err != nil {
		return nil, err
	}
	notes, err := rawString(object, "notes")
	if err != nil || !validAssignmentNotes(notes) {
		return nil, errors.New("invalid notes")
	}
	version, err := rawVersion(object, "version")
	if err != nil {
		return nil, err
	}
	createdAt, err := rawTime(object, "created_at")
	if err != nil {
		return nil, err
	}
	updatedAt, err := rawTime(object, "updated_at")
	if err != nil || updatedAt.Before(createdAt) {
		return nil, errors.New("invalid update timestamp")
	}
	deletedAt, err := rawNullableTime(object, "deleted_at")
	if err != nil {
		return nil, err
	}
	return &Subscription{ID: *id, UserID: *userID, GroupID: *groupID, PlanID: planID, StartsAt: startsAt, ExpiresAt: expiresAt, Status: status,
		InitialDailyBoundary: initial, DailyWindowStart: daily, WeeklyWindowStart: weekly, MonthlyWindowStart: monthly,
		WeeklyAnchorKind: weeklyKind, MonthlyAnchorKind: monthlyKind, DailyLimitE8USD: dailyLimit, WeeklyLimitE8USD: weeklyLimit, MonthlyLimitE8USD: monthlyLimit,
		DailyUsageE8USD: *dailyUsage, WeeklyUsageE8USD: *weeklyUsage, MonthlyUsageE8USD: *monthlyUsage, AssignedBy: assignedBy,
		AssignedAt: assignedAt, Notes: notes, Version: version, CreatedAt: createdAt, UpdatedAt: updatedAt, DeletedAt: deletedAt}, nil
}

func decodeSubscriptionEnvelope(raw json.RawMessage, extended *bool) (*Subscription, error) {
	fields := []string{"subscription"}
	if extended != nil {
		fields = append(fields, "extended")
	}
	object, err := strictSubscriptionObject(raw, fields...)
	if err != nil {
		return nil, err
	}
	if extended != nil {
		if err := json.Unmarshal(object["extended"], extended); err != nil {
			return nil, errors.New("extended must be boolean")
		}
	}
	return decodeSubscription(object["subscription"])
}

func subscriptionDecodeError(_ error) error {
	return fmt.Errorf("%w: invalid response", ErrSubscriptionUnavailable)
}

func (c *HTTPControlPlane) GetSubscription(ctx context.Context, request SubscriptionGetRequest) (*Subscription, error) {
	if err := validateSubscriptionID("subscription id", request.ID); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := c.subscriptionPost(ctx, "/v1/subscriptions/get", map[string]any{"id": request.ID, "include_deleted": request.IncludeDeleted}, &raw); err != nil {
		return nil, err
	}
	subscription, err := decodeSubscriptionEnvelope(raw, nil)
	if err != nil || subscription.ID != request.ID {
		return nil, subscriptionDecodeError(err)
	}
	return subscription, nil
}

func (c *HTTPControlPlane) ListSubscriptions(ctx context.Context, request SubscriptionListRequest) (*SubscriptionPage, error) {
	if err := validateOptionalSubscriptionID("user id", request.UserID); err != nil {
		return nil, err
	}
	if err := validateOptionalSubscriptionID("group id", request.GroupID); err != nil {
		return nil, err
	}
	if err := validateOptionalSubscriptionID("after id", request.AfterID); err != nil {
		return nil, err
	}
	if request.Status != nil && *request.Status != service.SubscriptionStatusActive && *request.Status != service.SubscriptionStatusExpired && *request.Status != service.SubscriptionStatusSuspended {
		return nil, fmt.Errorf("%w: invalid status", ErrSubscriptionValidation)
	}
	if err := validateLimit(request.Limit); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := c.subscriptionPost(ctx, "/v1/subscriptions/list", map[string]any{"user_id": request.UserID, "group_id": request.GroupID, "status": request.Status, "include_deleted": request.IncludeDeleted, "after_id": request.AfterID, "limit": request.Limit}, &raw); err != nil {
		return nil, err
	}
	object, err := strictSubscriptionObject(raw, "items", "next_after_id")
	if err != nil {
		return nil, subscriptionDecodeError(err)
	}
	var itemsRaw []json.RawMessage
	if err := json.Unmarshal(object["items"], &itemsRaw); err != nil || itemsRaw == nil || len(itemsRaw) > request.Limit {
		return nil, subscriptionDecodeError(err)
	}
	next, err := rawNullableString(object, "next_after_id")
	if err != nil || (next != nil && !validSubscriptionID(*next)) {
		return nil, subscriptionDecodeError(err)
	}
	items := make([]Subscription, 0, len(itemsRaw))
	previous := ""
	if request.AfterID != nil {
		previous = *request.AfterID
	}
	for _, itemRaw := range itemsRaw {
		item, decodeErr := decodeSubscription(itemRaw)
		if decodeErr != nil || !decimalStringGreater(item.ID, previous) {
			return nil, subscriptionDecodeError(decodeErr)
		}
		if request.UserID != nil && item.UserID != *request.UserID || request.GroupID != nil && item.GroupID != *request.GroupID || request.Status != nil && item.Status != *request.Status || !request.IncludeDeleted && item.DeletedAt != nil {
			return nil, subscriptionDecodeError(errors.New("filter mismatch"))
		}
		previous = item.ID
		items = append(items, *item)
	}
	if next != nil && (len(items) == 0 || *next != previous) {
		return nil, subscriptionDecodeError(errors.New("cursor mismatch"))
	}
	return &SubscriptionPage{Items: items, NextAfterID: next}, nil
}

func validAssignmentNotes(notes string) bool {
	if len(notes) > 4096 || !utf8.ValidString(notes) {
		return false
	}
	for _, value := range notes {
		if value <= 0x1f || (value >= 0x7f && value <= 0x9f) ||
			value == 0x202a || value == 0x202b || value == 0x202c || value == 0x202d || value == 0x202e ||
			value == 0x2066 || value == 0x2067 || value == 0x2068 || value == 0x2069 || value == 0xfeff {
			return false
		}
	}
	return true
}
func validateMutation(operationID, subscriptionID string, version int, at time.Time) error {
	if err := validateOperationID(operationID); err != nil {
		return err
	}
	if err := validateSubscriptionID("subscription id", subscriptionID); err != nil {
		return err
	}
	if err := validateVersion(version); err != nil {
		return err
	}
	return validateSubscriptionTime("timestamp", at)
}
func mutationResponse(c *HTTPControlPlane, ctx context.Context, path string, input map[string]any, expectedID string, expectedVersion int, validState func(*Subscription) bool) (*Subscription, error) {
	var raw json.RawMessage
	if err := c.subscriptionPost(ctx, path, input, &raw); err != nil {
		return nil, err
	}
	subscription, err := decodeSubscriptionEnvelope(raw, nil)
	if err != nil || subscription.ID != expectedID || subscription.Version != expectedVersion+1 || !validState(subscription) {
		return nil, subscriptionDecodeError(err)
	}
	return subscription, nil
}

func (c *HTTPControlPlane) AssignOrExtendSubscription(ctx context.Context, request SubscriptionAssignOrExtendRequest) (*SubscriptionMutationResult, error) {
	for label, value := range map[string]string{"new subscription id": request.NewSubscriptionID, "user id": request.UserID, "group id": request.GroupID} {
		if err := validateSubscriptionID(label, value); err != nil {
			return nil, err
		}
	}
	if err := validateOperationID(request.OperationID); err != nil {
		return nil, err
	}
	if err := validateOptionalSubscriptionID("plan id", request.PlanID); err != nil {
		return nil, err
	}
	if err := validateOptionalSubscriptionID("assigned by", request.AssignedBy); err != nil {
		return nil, err
	}
	if request.ValidityDays < 1 || request.ValidityDays > 36500 || !validAssignmentNotes(request.Notes) {
		return nil, fmt.Errorf("%w: invalid assignment", ErrSubscriptionValidation)
	}
	if err := validateSubscriptionTime("now", request.Now); err != nil {
		return nil, err
	}
	if err := validateSubscriptionTime("daily boundary", request.DailyBoundary); err != nil {
		return nil, err
	}
	if err := validateBoundary(request.Now, request.DailyBoundary); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	input := map[string]any{"operation_id": request.OperationID, "new_subscription_id": request.NewSubscriptionID, "user_id": request.UserID, "group_id": request.GroupID, "plan_id": request.PlanID, "validity_days": request.ValidityDays, "assigned_by": request.AssignedBy, "notes": request.Notes, "now": subscriptionTime(request.Now), "daily_boundary": subscriptionTime(request.DailyBoundary)}
	if err := c.subscriptionPost(ctx, "/v1/subscriptions/assign-or-extend", input, &raw); err != nil {
		return nil, err
	}
	extended := false
	subscription, err := decodeSubscriptionEnvelope(raw, &extended)
	if err != nil || subscription.UserID != request.UserID || subscription.GroupID != request.GroupID {
		return nil, subscriptionDecodeError(err)
	}
	return &SubscriptionMutationResult{Subscription: subscription, Extended: extended}, nil
}

func (c *HTTPControlPlane) RevokeSubscription(ctx context.Context, request SubscriptionRevokeRequest) (*Subscription, error) {
	if err := validateMutation(request.OperationID, request.SubscriptionID, request.ExpectedVersion, request.At); err != nil {
		return nil, err
	}
	if err := validateSubscriptionID("actor user id", request.ActorUserID); err != nil {
		return nil, err
	}
	return mutationResponse(c, ctx, "/v1/subscriptions/revoke", map[string]any{"operation_id": request.OperationID, "subscription_id": request.SubscriptionID, "expected_version": request.ExpectedVersion, "actor_user_id": request.ActorUserID, "at": subscriptionTime(request.At)}, request.SubscriptionID, request.ExpectedVersion, func(subscription *Subscription) bool {
		return subscription.DeletedAt != nil && subscription.DeletedAt.Equal(request.At)
	})
}
func (c *HTTPControlPlane) RestoreSubscription(ctx context.Context, request SubscriptionRestoreRequest) (*Subscription, error) {
	if err := validateMutation(request.OperationID, request.SubscriptionID, request.ExpectedVersion, request.Now); err != nil {
		return nil, err
	}
	if err := validateSubscriptionID("actor user id", request.ActorUserID); err != nil {
		return nil, err
	}
	return mutationResponse(c, ctx, "/v1/subscriptions/restore", map[string]any{"operation_id": request.OperationID, "subscription_id": request.SubscriptionID, "expected_version": request.ExpectedVersion, "actor_user_id": request.ActorUserID, "now": subscriptionTime(request.Now)}, request.SubscriptionID, request.ExpectedVersion, func(subscription *Subscription) bool {
		return subscription.DeletedAt == nil
	})
}
func (c *HTTPControlPlane) ExtendSubscription(ctx context.Context, request SubscriptionExtendRequest) (*Subscription, error) {
	if err := validateMutation(request.OperationID, request.SubscriptionID, request.ExpectedVersion, request.Now); err != nil {
		return nil, err
	}
	if err := validateSubscriptionID("actor user id", request.ActorUserID); err != nil {
		return nil, err
	}
	if request.Days < -36500 || request.Days > 36500 {
		return nil, fmt.Errorf("%w: invalid days", ErrSubscriptionValidation)
	}
	return mutationResponse(c, ctx, "/v1/subscriptions/extend", map[string]any{"operation_id": request.OperationID, "subscription_id": request.SubscriptionID, "expected_version": request.ExpectedVersion, "days": request.Days, "actor_user_id": request.ActorUserID, "now": subscriptionTime(request.Now)}, request.SubscriptionID, request.ExpectedVersion, func(subscription *Subscription) bool {
		return subscription.DeletedAt == nil && subscription.Status != service.SubscriptionStatusExpired && subscription.ExpiresAt.After(request.Now)
	})
}
func (c *HTTPControlPlane) ActivateSubscriptionWindows(ctx context.Context, request SubscriptionActivateWindowsRequest) (*Subscription, error) {
	if err := validateMutation(request.OperationID, request.SubscriptionID, request.ExpectedVersion, request.ActivatedAt); err != nil {
		return nil, err
	}
	if err := validateSubscriptionTime("daily boundary", request.DailyBoundary); err != nil {
		return nil, err
	}
	if err := validateBoundary(request.ActivatedAt, request.DailyBoundary); err != nil {
		return nil, err
	}
	return mutationResponse(c, ctx, "/v1/subscriptions/windows/activate", map[string]any{"operation_id": request.OperationID, "subscription_id": request.SubscriptionID, "expected_version": request.ExpectedVersion, "activated_at": subscriptionTime(request.ActivatedAt), "daily_boundary": subscriptionTime(request.DailyBoundary)}, request.SubscriptionID, request.ExpectedVersion, func(subscription *Subscription) bool {
		return subscription.DailyWindowStart != nil && subscription.DailyWindowStart.Equal(request.DailyBoundary) &&
			subscription.WeeklyWindowStart != nil && subscription.WeeklyWindowStart.Equal(request.ActivatedAt) &&
			subscription.MonthlyWindowStart != nil && subscription.MonthlyWindowStart.Equal(request.ActivatedAt) &&
			subscription.WeeklyAnchorKind != nil && *subscription.WeeklyAnchorKind == "activation" &&
			subscription.MonthlyAnchorKind != nil && *subscription.MonthlyAnchorKind == "activation"
	})
}
func (c *HTTPControlPlane) MaintainSubscriptionWindows(ctx context.Context, request SubscriptionMaintainWindowsRequest) (*Subscription, error) {
	if err := validateMutation(request.OperationID, request.SubscriptionID, request.ExpectedVersion, request.Now); err != nil {
		return nil, err
	}
	if err := validateSubscriptionTime("daily boundary", request.DailyBoundary); err != nil {
		return nil, err
	}
	if err := validateBoundary(request.Now, request.DailyBoundary); err != nil {
		return nil, err
	}
	return mutationResponse(c, ctx, "/v1/subscriptions/windows/maintain", map[string]any{"operation_id": request.OperationID, "subscription_id": request.SubscriptionID, "expected_version": request.ExpectedVersion, "now": subscriptionTime(request.Now), "daily_boundary": subscriptionTime(request.DailyBoundary)}, request.SubscriptionID, request.ExpectedVersion, func(subscription *Subscription) bool {
		return subscription.DailyWindowStart != nil && subscription.WeeklyWindowStart != nil && subscription.MonthlyWindowStart != nil
	})
}
func (c *HTTPControlPlane) ResetSubscriptionWindows(ctx context.Context, request SubscriptionResetWindowsRequest) (*Subscription, error) {
	if err := validateMutation(request.OperationID, request.SubscriptionID, request.ExpectedVersion, request.ResetAt); err != nil {
		return nil, err
	}
	if err := validateSubscriptionID("actor user id", request.ActorUserID); err != nil {
		return nil, err
	}
	if !request.ResetDaily && !request.ResetWeekly && !request.ResetMonthly {
		return nil, fmt.Errorf("%w: no windows selected", ErrSubscriptionValidation)
	}
	if err := validateSubscriptionTime("daily boundary", request.DailyBoundary); err != nil {
		return nil, err
	}
	if err := validateBoundary(request.ResetAt, request.DailyBoundary); err != nil {
		return nil, err
	}
	return mutationResponse(c, ctx, "/v1/subscriptions/windows/reset", map[string]any{"operation_id": request.OperationID, "subscription_id": request.SubscriptionID, "expected_version": request.ExpectedVersion, "reset_daily": request.ResetDaily, "reset_weekly": request.ResetWeekly, "reset_monthly": request.ResetMonthly, "reset_at": subscriptionTime(request.ResetAt), "daily_boundary": subscriptionTime(request.DailyBoundary), "actor_user_id": request.ActorUserID}, request.SubscriptionID, request.ExpectedVersion, func(subscription *Subscription) bool {
		dailyValid := !request.ResetDaily || subscription.DailyUsageE8USD == "0" && subscription.DailyWindowStart != nil && subscription.DailyWindowStart.Equal(request.DailyBoundary)
		weeklyValid := !request.ResetWeekly || subscription.WeeklyUsageE8USD == "0" && subscription.WeeklyWindowStart != nil && subscription.WeeklyWindowStart.Equal(request.ResetAt) && subscription.WeeklyAnchorKind != nil && *subscription.WeeklyAnchorKind == "manual"
		monthlyValid := !request.ResetMonthly || subscription.MonthlyUsageE8USD == "0" && subscription.MonthlyWindowStart != nil && subscription.MonthlyWindowStart.Equal(request.ResetAt) && subscription.MonthlyAnchorKind != nil && *subscription.MonthlyAnchorKind == "manual"
		return dailyValid && weeklyValid && monthlyValid
	})
}
func (c *HTTPControlPlane) ReserveSubscriptionUsage(ctx context.Context, request SubscriptionReserveUsageRequest) (*Subscription, error) {
	if err := validateMutation(request.OperationID, request.SubscriptionID, request.ExpectedVersion, request.At); err != nil {
		return nil, err
	}
	if !validSubscriptionE8(request.AmountE8USD) {
		return nil, fmt.Errorf("%w: invalid E8 amount", ErrSubscriptionValidation)
	}
	return mutationResponse(c, ctx, "/v1/subscriptions/usage/reserve", map[string]any{"operation_id": request.OperationID, "subscription_id": request.SubscriptionID, "expected_version": request.ExpectedVersion, "amount_e8_usd": request.AmountE8USD, "at": subscriptionTime(request.At)}, request.SubscriptionID, request.ExpectedVersion, func(subscription *Subscription) bool {
		return subscription.DeletedAt == nil && subscription.Status == service.SubscriptionStatusActive && subscription.ExpiresAt.After(request.At)
	})
}
func (c *HTTPControlPlane) SweepExpiredSubscriptions(ctx context.Context, request SubscriptionSweepExpiredRequest) (*SubscriptionSweepResult, error) {
	if err := validateOperationID(request.OperationID); err != nil {
		return nil, err
	}
	if err := validateSubscriptionTime("cutoff", request.Cutoff); err != nil {
		return nil, err
	}
	if err := validateOptionalSubscriptionID("after id", request.AfterID); err != nil {
		return nil, err
	}
	if err := validateLimit(request.Limit); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := c.subscriptionPost(ctx, "/v1/subscriptions/expiry/sweep", map[string]any{"operation_id": request.OperationID, "cutoff": subscriptionTime(request.Cutoff), "after_id": request.AfterID, "limit": request.Limit}, &raw); err != nil {
		return nil, err
	}
	object, err := strictSubscriptionObject(raw, "expired_ids", "count")
	if err != nil {
		return nil, subscriptionDecodeError(err)
	}
	var ids []string
	if err := json.Unmarshal(object["expired_ids"], &ids); err != nil || ids == nil || len(ids) > request.Limit {
		return nil, subscriptionDecodeError(err)
	}
	count, err := rawVersion(object, "count")
	if err != nil { // count may legally be zero.
		var number json.Number
		if decodeErr := json.Unmarshal(object["count"], &number); decodeErr != nil {
			return nil, subscriptionDecodeError(decodeErr)
		}
		parsed, parseErr := strconv.Atoi(number.String())
		if parseErr != nil || parsed < 0 || parsed != len(ids) {
			return nil, subscriptionDecodeError(parseErr)
		}
		count = parsed
	}
	previous := ""
	if request.AfterID != nil {
		previous = *request.AfterID
	}
	for _, id := range ids {
		if !validSubscriptionID(id) || !decimalStringGreater(id, previous) {
			return nil, subscriptionDecodeError(errors.New("invalid expired id"))
		}
		previous = id
	}
	if count != len(ids) {
		return nil, subscriptionDecodeError(errors.New("count mismatch"))
	}
	return &SubscriptionSweepResult{ExpiredIDs: ids, Count: count}, nil
}

// APIKeySubscriptionReader is deliberately a read-through adapter, not a
// UserSubscriptionRepository. It does not cache, compose, or mutate local
// entitlement state; the Worker snapshot is authoritative for every lookup.
type APIKeySubscriptionReader struct {
	control SubscriptionControlPlane
	now     func() time.Time
}

func NewAPIKeySubscriptionReader(control SubscriptionControlPlane) *APIKeySubscriptionReader {
	return &APIKeySubscriptionReader{control: control, now: time.Now}
}

func (r *APIKeySubscriptionReader) GetActiveByUserIDAndGroupID(ctx context.Context, userID, groupID int64) (*service.UserSubscription, error) {
	if r == nil || r.control == nil || userID < 1 || groupID < 1 {
		return nil, service.ErrSubscriptionNotFound
	}
	user := strconv.FormatInt(userID, 10)
	group := strconv.FormatInt(groupID, 10)
	status := service.SubscriptionStatusActive
	page, err := r.control.ListSubscriptions(ctx, SubscriptionListRequest{UserID: &user, GroupID: &group, Status: &status, IncludeDeleted: false, Limit: 1})
	if err != nil {
		if errors.Is(err, ErrSubscriptionNotFound) {
			return nil, service.ErrSubscriptionNotFound
		}
		return nil, err
	}
	if page == nil {
		return nil, subscriptionCursorContractError()
	}
	if len(page.Items) == 0 {
		return nil, service.ErrSubscriptionNotFound
	}
	if len(page.Items) != 1 || page.NextAfterID != nil {
		return nil, subscriptionCursorContractError()
	}
	subscription := page.Items[0]
	if subscription.UserID != user || subscription.GroupID != group || subscription.DeletedAt != nil || subscription.Status != service.SubscriptionStatusActive || !subscription.ExpiresAt.After(r.now().UTC()) {
		return nil, service.ErrSubscriptionNotFound
	}
	converted, err := subscriptionToLegacyService(subscription)
	if err != nil {
		return nil, service.ErrSubscriptionNotFound
	}
	return converted, nil
}

func subscriptionCursorContractError() error {
	return fmt.Errorf("%w: %w", ErrSubscriptionUnavailable, ErrSubscriptionCursorContract)
}

// ListActiveByUserID exhausts the Worker's exact cursor contract. It never
// treats a partial page set as complete and fails closed on corrupt pagination
// or an unexpectedly large entitlement set.
func (r *APIKeySubscriptionReader) ListActiveByUserID(ctx context.Context, userID int64) ([]service.UserSubscription, error) {
	if r == nil || r.control == nil || userID < 1 {
		return nil, service.ErrSubscriptionNotFound
	}
	user := strconv.FormatInt(userID, 10)
	status := service.SubscriptionStatusActive
	now := r.now().UTC()
	var afterID *string
	result := make([]service.UserSubscription, 0)
	seenGroups := make(map[int64]struct{})
	for pageNumber := 0; pageNumber < maxAPIKeySubscriptionPages; pageNumber++ {
		page, err := r.control.ListSubscriptions(ctx, SubscriptionListRequest{
			UserID:         &user,
			GroupID:        nil,
			Status:         &status,
			IncludeDeleted: false,
			AfterID:        afterID,
			Limit:          apiKeySubscriptionPageSize,
		})
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Items) > apiKeySubscriptionPageSize {
			return nil, subscriptionCursorContractError()
		}
		previousID := ""
		if afterID != nil {
			previousID = *afterID
		}
		for _, subscription := range page.Items {
			if !validSubscriptionID(subscription.ID) || !decimalStringGreater(subscription.ID, previousID) ||
				subscription.UserID != user || subscription.Status != service.SubscriptionStatusActive ||
				subscription.DeletedAt != nil || !subscription.ExpiresAt.After(now) {
				return nil, subscriptionCursorContractError()
			}
			converted, convertErr := subscriptionToLegacyService(subscription)
			if convertErr != nil {
				return nil, subscriptionCursorContractError()
			}
			if _, duplicate := seenGroups[converted.GroupID]; duplicate {
				return nil, subscriptionCursorContractError()
			}
			seenGroups[converted.GroupID] = struct{}{}
			result = append(result, *converted)
			previousID = subscription.ID
		}
		if page.NextAfterID == nil {
			return result, nil
		}
		if !validSubscriptionID(*page.NextAfterID) || len(page.Items) == 0 ||
			*page.NextAfterID != previousID || (afterID != nil && !decimalStringGreater(*page.NextAfterID, *afterID)) {
			return nil, subscriptionCursorContractError()
		}
		next := *page.NextAfterID
		afterID = &next
	}
	return nil, subscriptionCursorContractError()
}

func subscriptionToLegacyService(subscription Subscription) (*service.UserSubscription, error) {
	id, err := parsePositiveID("subscription id", subscription.ID)
	if err != nil {
		return nil, err
	}
	userID, err := parsePositiveID("subscription user id", subscription.UserID)
	if err != nil {
		return nil, err
	}
	groupID, err := parsePositiveID("subscription group id", subscription.GroupID)
	if err != nil {
		return nil, err
	}
	var assignedBy *int64
	if subscription.AssignedBy != nil {
		value, parseErr := parsePositiveID("subscription assigned by", *subscription.AssignedBy)
		if parseErr != nil {
			return nil, parseErr
		}
		assignedBy = &value
	}
	// Validate exact E8 values before the legacy float-only fields are filled.
	for _, value := range []string{subscription.DailyUsageE8USD, subscription.WeeklyUsageE8USD, subscription.MonthlyUsageE8USD} {
		if !validSubscriptionE8(value) {
			return nil, errors.New("invalid usage")
		}
	}
	daily, err := displayBalanceFromE8USD(subscription.DailyUsageE8USD)
	if err != nil {
		return nil, err
	}
	weekly, err := displayBalanceFromE8USD(subscription.WeeklyUsageE8USD)
	if err != nil {
		return nil, err
	}
	monthly, err := displayBalanceFromE8USD(subscription.MonthlyUsageE8USD)
	if err != nil {
		return nil, err
	}
	return &service.UserSubscription{ID: id, UserID: userID, GroupID: groupID, StartsAt: subscription.StartsAt, ExpiresAt: subscription.ExpiresAt,
		Status: subscription.Status, DailyWindowStart: subscription.DailyWindowStart, WeeklyWindowStart: subscription.WeeklyWindowStart,
		MonthlyWindowStart: subscription.MonthlyWindowStart, DailyUsageUSD: daily, WeeklyUsageUSD: weekly, MonthlyUsageUSD: monthly,
		AssignedBy: assignedBy, AssignedAt: subscription.AssignedAt, Notes: subscription.Notes, CreatedAt: subscription.CreatedAt,
		UpdatedAt: subscription.UpdatedAt, DeletedAt: subscription.DeletedAt}, nil
}

var _ SubscriptionControlPlane = (*HTTPControlPlane)(nil)
var _ service.APIKeySubscriptionReader = (*APIKeySubscriptionReader)(nil)
