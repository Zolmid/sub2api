package cloudflarebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/argon2"
)

// AdminUserMutationControlPlane is separate from the traditional repository
// graph so Cloudflare mode cannot silently fall back to PostgreSQL or Redis.
type AdminUserMutationControlPlane interface {
	CreateManagedUser(context.Context, string, *service.User, string, string, string) (*service.User, bool, error)
	UpdateManagedUser(context.Context, string, int64, ManagedUserUpdate) (*service.User, error)
	DeleteManagedUser(context.Context, string, int64) error
}

// AdminBalanceControlPlane is deliberately narrower than the legacy service:
// the Worker owns the atomic D1 projection and immutable audit ledger.
type AdminBalanceControlPlane interface {
	AdjustManagedUserBalance(context.Context, ManagedBalanceAdjustment) (*ManagedBalanceAdjustmentResult, error)
}

type ManagedBalanceAdjustment struct {
	OperationID    string
	ActorUserID    int64
	TargetUserID   int64
	Operation      string
	AmountMicroUSD string
	Reason         string
}

type ManagedBalanceAdjustmentResult struct {
	LedgerID              string
	BalanceBeforeMicroUSD string
	BalanceAfterMicroUSD  string
	DeltaMicroUSD         string
	Replayed              bool
}

// ManagedUserUpdate contains only fields owned by the current Worker schema.
// Role and balance deliberately have no representation here: role changes need
// step-up authentication and balance changes belong to the ledger endpoint.
type ManagedUserUpdate struct {
	Email                *string
	Username             *string
	Notes                *string
	Status               *string
	Concurrency          *int
	RPMLimit             *int
	AllowedGroups        *[]int64
	RestrictPublicGroups *bool
	PasswordHash         *string
}

type cloudflareUserMutationRequest struct {
	Email                *string
	Password             *string
	Username             *string
	Notes                *string
	Status               *string
	Role                 *string
	BalanceMicroUSD      *string
	Concurrency          *int
	RPMLimit             *int
	AllowedGroups        *[]int64
	RestrictPublicGroups *bool
}

type managedUserMutationResponse struct {
	User     managedUserWire `json:"user"`
	Replayed bool            `json:"replayed"`

	// These fields are never valid output. Decoding them lets the bridge fail
	// closed if a protocol regression exposes credential material at top level.
	PasswordHash   string `json:"password_hash,omitempty"`
	Password       string `json:"password,omitempty"`
	SemanticDigest string `json:"semantic_digest,omitempty"`
}

func (response managedUserMutationResponse) leaksCredential() bool {
	return response.PasswordHash != "" || response.Password != "" || response.SemanticDigest != ""
}

func (h *cloudflareAdminAPIHandler) userMutations() (AdminUserMutationControlPlane, error) {
	mutations, ok := h.control.(AdminUserMutationControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return mutations, nil
}

func (h *cloudflareAdminAPIHandler) balances() (AdminBalanceControlPlane, error) {
	control, ok := h.control.(AdminBalanceControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return control, nil
}

// UpdateBalance keeps the established public endpoint in Cloudflare mode. It
// accepts the existing decimal UI representation only at this public edge,
// converts it exactly once, then uses signed integer microusd across the
// Container-to-Worker boundary.
func (h *cloudflareAdminAPIHandler) UpdateBalance(c *gin.Context) {
	userID, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	var request struct {
		Balance   json.RawMessage `json:"balance"`
		Operation string          `json:"operation"`
		Notes     string          `json:"notes"`
	}
	if err := decodeCloudflareJSON(c, &request); err != nil {
		response.BadRequest(c, "Invalid request")
		return
	}
	amount, valid := microUSDFromJSON(request.Balance)
	if !valid || amount == "0" || (request.Operation != "set" && request.Operation != "add" && request.Operation != "subtract") || utf16Length(request.Notes) > 4096 {
		response.BadRequest(c, "Invalid balance adjustment")
		return
	}
	subject, authenticated := middleware.GetAuthSubjectFromContext(c)
	actorID := subject.UserID
	if !authenticated || actorID < 1 {
		response.Unauthorized(c, "Unauthorized")
		return
	}
	key, err := service.NormalizeIdempotencyKey(c.GetHeader("Idempotency-Key"))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if key == "" {
		response.ErrorFrom(c, service.ErrIdempotencyKeyRequired)
		return
	}
	balances, err := h.balances()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	operationID := "user-balance:" + strconv.FormatInt(actorID, 10) + ":" + service.HashIdempotencyKey(key)
	result, err := balances.AdjustManagedUserBalance(c.Request.Context(), ManagedBalanceAdjustment{OperationID: operationID, ActorUserID: actorID, TargetUserID: userID, Operation: request.Operation, AmountMicroUSD: amount, Reason: request.Notes})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if result == nil {
		response.ErrorFrom(c, errors.New("invalid balance adjustment response"))
		return
	}
	management, err := h.management()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	user, err := management.GetManagedUser(c.Request.Context(), userID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if result.Replayed {
		c.Header("X-Idempotency-Replayed", "true")
	}
	response.Success(c, newCloudflareAdminUserDTO(user))
}

func (h *cloudflareAdminAPIHandler) CreateUser(c *gin.Context) {
	idempotencyKey, err := service.NormalizeIdempotencyKey(c.GetHeader("Idempotency-Key"))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if idempotencyKey == "" {
		response.ErrorFrom(c, service.ErrIdempotencyKeyRequired)
		return
	}

	request, ok := decodeCloudflareUserMutation(c, true)
	if !ok {
		return
	}
	if request.Role != nil && *request.Role == service.RoleAdmin {
		response.Forbidden(c, "admin user creation requires step-up authentication")
		return
	}

	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID < 1 {
		response.ErrorFrom(c, service.ErrInsufficientPerms)
		return
	}
	userID, err := newPersistentID()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	user := &service.User{
		ID:                   userID,
		Email:                *request.Email,
		Username:             stringOr(request.Username, ""),
		Notes:                stringOr(request.Notes, ""),
		Status:               stringOr(request.Status, service.StatusActive),
		Role:                 stringOr(request.Role, service.RoleUser),
		Concurrency:          *request.Concurrency,
		RPMLimit:             intOr(request.RPMLimit, 0),
		AllowedGroups:        groupsOrEmpty(request.AllowedGroups),
		RestrictPublicGroups: boolOr(request.RestrictPublicGroups, false),
	}
	balanceMicroUSD := "0"
	if request.BalanceMicroUSD != nil {
		balanceMicroUSD = *request.BalanceMicroUSD
	}
	user.Balance, err = displayBalanceFromMicroUSD(balanceMicroUSD)
	if err != nil {
		response.BadRequest(c, "Invalid balance")
		return
	}
	if err := user.SetPassword(*request.Password); err != nil {
		response.BadRequest(c, "Invalid password")
		return
	}

	operationID := "user-create:" + strconv.FormatInt(subject.UserID, 10) + ":" + service.HashIdempotencyKey(idempotencyKey)
	semanticToken, err := cloudflareUserSemanticToken(operationID, user, balanceMicroUSD, *request.Password)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	mutations, err := h.userMutations()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	created, replayed, err := mutations.CreateManagedUser(
		c.Request.Context(), operationID, user, balanceMicroUSD, user.PasswordHash, semanticToken,
	)
	if err != nil {
		response.ErrorFrom(c, mapManagedUserMutationError(err))
		return
	}
	if created == nil || created.ID < 1 || created.ID > maxJavaScriptSafeInteger ||
		(!replayed && created.ID != user.ID) || !sameManagedUserFields(created, user) ||
		!created.CheckPassword(*request.Password) {
		response.ErrorFrom(c, errors.New("invalid user create response"))
		return
	}
	created.PasswordHash = ""
	response.Success(c, newCloudflareAdminUserDTO(created))
}

func (h *cloudflareAdminAPIHandler) UpdateUser(c *gin.Context) {
	userID, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	request, ok := decodeCloudflareUserMutation(c, false)
	if !ok {
		return
	}
	if request.BalanceMicroUSD != nil {
		response.BadRequest(c, "balance changes require the dedicated balance endpoint")
		return
	}

	management, err := h.management()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	before, err := management.GetManagedUser(c.Request.Context(), userID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if request.Role != nil && *request.Role != before.Role {
		response.Forbidden(c, "role changes require step-up authentication")
		return
	}
	if before.Role == service.RoleAdmin && request.Status != nil && *request.Status == service.StatusDisabled {
		response.Forbidden(c, "admin users cannot be disabled in Cloudflare mode")
		return
	}

	update := ManagedUserUpdate{
		Email:                request.Email,
		Username:             request.Username,
		Notes:                request.Notes,
		Status:               request.Status,
		Concurrency:          request.Concurrency,
		RPMLimit:             request.RPMLimit,
		AllowedGroups:        request.AllowedGroups,
		RestrictPublicGroups: request.RestrictPublicGroups,
	}
	if request.Password != nil {
		credential := &service.User{}
		if err := credential.SetPassword(*request.Password); err != nil {
			response.BadRequest(c, "Invalid password")
			return
		}
		update.PasswordHash = &credential.PasswordHash
	}
	// A same-role field from the legacy full-form UI is neutral. Returning the
	// fresh pre-read avoids a private no-op while never writing a stale role.
	if update.empty() {
		response.Success(c, newCloudflareAdminUserDTO(before))
		return
	}

	mutations, err := h.userMutations()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	updated, err := mutations.UpdateManagedUser(
		c.Request.Context(), managementOperationID("user-update"), userID, update,
	)
	if err != nil {
		response.ErrorFrom(c, mapManagedUserMutationError(err))
		return
	}
	if updated == nil || updated.ID != userID || !matchesManagedUserPatch(updated, update) ||
		(request.Password != nil && !updated.CheckPassword(*request.Password)) {
		response.ErrorFrom(c, errors.New("invalid user update response"))
		return
	}
	updated.PasswordHash = ""
	response.Success(c, newCloudflareAdminUserDTO(updated))
}

func (h *cloudflareAdminAPIHandler) DeleteUser(c *gin.Context) {
	userID, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	management, err := h.management()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	user, err := management.GetManagedUser(c.Request.Context(), userID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if user.Role == service.RoleAdmin {
		response.Forbidden(c, "admin users cannot be deleted in Cloudflare mode")
		return
	}

	mutations, err := h.userMutations()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if err := mutations.DeleteManagedUser(c.Request.Context(), managementOperationID("user-delete"), userID); err != nil {
		response.ErrorFrom(c, mapManagedUserMutationError(err))
		return
	}
	response.Success(c, gin.H{"message": "User deleted successfully"})
}

func decodeCloudflareUserMutation(c *gin.Context, create bool) (cloudflareUserMutationRequest, bool) {
	fields, ok := readStrictJSONObject(c)
	if !ok {
		return cloudflareUserMutationRequest{}, false
	}
	allowed := map[string]bool{
		"email": true, "password": true, "username": true, "notes": true,
		"status": true, "role": true, "balance": true, "concurrency": true,
		"rpm_limit": true, "allowed_groups": true, "restrict_public_groups": true,
	}
	for field := range fields {
		if !allowed[field] {
			response.BadRequest(c, field+" is not migrated in Cloudflare mode")
			return cloudflareUserMutationRequest{}, false
		}
	}

	var request cloudflareUserMutationRequest
	if raw, exists := fields["email"]; exists {
		value, valid := stringField(raw)
		if !valid || !validCloudflareEmail(value) {
			response.BadRequest(c, "Invalid email")
			return request, false
		}
		request.Email = &value
	}
	if raw, exists := fields["password"]; exists {
		value, valid := stringField(raw)
		if !valid || !validCloudflarePassword(value) {
			response.BadRequest(c, "Invalid password")
			return request, false
		}
		request.Password = &value
	}
	if raw, exists := fields["username"]; exists {
		value, valid := stringField(raw)
		if !valid || utf16Length(value) > 100 {
			response.BadRequest(c, "Invalid username")
			return request, false
		}
		request.Username = &value
	}
	if raw, exists := fields["notes"]; exists {
		value, valid := stringField(raw)
		if !valid || utf16Length(value) > 4096 {
			response.BadRequest(c, "Invalid notes")
			return request, false
		}
		request.Notes = &value
	}
	if raw, exists := fields["status"]; exists {
		value, valid := stringField(raw)
		if !valid || (value != service.StatusActive && value != service.StatusDisabled) ||
			(create && value != service.StatusActive) {
			response.BadRequest(c, "Invalid status")
			return request, false
		}
		request.Status = &value
	}
	if raw, exists := fields["role"]; exists {
		value, valid := stringField(raw)
		if !valid || (value != service.RoleUser && value != service.RoleAdmin) {
			response.BadRequest(c, "Invalid role")
			return request, false
		}
		request.Role = &value
	}
	if raw, exists := fields["balance"]; exists {
		if !create {
			response.BadRequest(c, "balance changes require the dedicated balance endpoint")
			return request, false
		}
		value, valid := microUSDFromJSON(raw)
		if !valid {
			response.BadRequest(c, "Invalid balance")
			return request, false
		}
		request.BalanceMicroUSD = &value
	}
	if raw, exists := fields["concurrency"]; exists {
		value, valid := boundedJSONInteger(raw, 1, 100000)
		if !valid {
			response.BadRequest(c, "Invalid concurrency")
			return request, false
		}
		request.Concurrency = &value
	}
	if raw, exists := fields["rpm_limit"]; exists {
		value, valid := boundedJSONInteger(raw, 0, 1000000)
		if !valid {
			response.BadRequest(c, "Invalid rpm_limit")
			return request, false
		}
		request.RPMLimit = &value
	}
	if raw, exists := fields["allowed_groups"]; exists {
		value, valid := cloudflareUserGroupIDs(raw)
		if !valid {
			response.BadRequest(c, "Invalid allowed_groups")
			return request, false
		}
		request.AllowedGroups = &value
	}
	if raw, exists := fields["restrict_public_groups"]; exists {
		value, valid := cloudflareJSONBool(raw)
		if !valid {
			response.BadRequest(c, "Invalid restrict_public_groups")
			return request, false
		}
		request.RestrictPublicGroups = &value
	}

	if create && (request.Email == nil || request.Password == nil || request.Concurrency == nil) {
		response.BadRequest(c, "email, password, and concurrency are required")
		return request, false
	}
	if !create && request.Email == nil && request.Password == nil && request.Username == nil &&
		request.Notes == nil && request.Status == nil && request.Role == nil &&
		request.Concurrency == nil && request.RPMLimit == nil && request.AllowedGroups == nil &&
		request.RestrictPublicGroups == nil {
		response.BadRequest(c, "No supported user fields to update")
		return request, false
	}
	return request, true
}

func validCloudflareEmail(value string) bool {
	if len(value) < 3 || len(value) > 255 || strings.Count(value, "@") != 1 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	parts := strings.SplitN(value, "@", 2)
	dot := strings.LastIndexByte(parts[1], '.')
	return parts[0] != "" && dot > 0 && dot < len(parts[1])-1
}

func validCloudflarePassword(value string) bool {
	return utf8.RuneCountInString(value) >= 6 && len(value) <= 72
}

func utf16Length(value string) int {
	return len(utf16.Encode([]rune(value)))
}

func stringOr(value *string, fallback string) string {
	if value == nil {
		return fallback
	}
	return *value
}

func intOr(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

func boolOr(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func groupsOrEmpty(value *[]int64) []int64 {
	if value == nil {
		return []int64{}
	}
	return append([]int64{}, (*value)...)
}

func cloudflareJSONBool(raw json.RawMessage) (bool, bool) {
	if isJSONBool(raw, true) {
		return true, true
	}
	if isJSONBool(raw, false) {
		return false, true
	}
	return false, false
}

func boundedJSONInteger(raw json.RawMessage, low, high int) (int, bool) {
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return 0, false
	}
	value, err := strconv.Atoi(number.String())
	return value, err == nil && value >= low && value <= high
}

func cloudflareUserGroupIDs(raw json.RawMessage) ([]int64, bool) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return []int64{}, true
	}
	var values []cloudflareRequestID
	if err := json.Unmarshal(raw, &values); err != nil || len(values) > 100 {
		return nil, false
	}
	seen := make(map[int64]struct{}, len(values))
	result := make([]int64, 0, len(values))
	for _, value := range values {
		groupID := int64(value)
		if _, exists := seen[groupID]; exists {
			return nil, false
		}
		seen[groupID] = struct{}{}
		result = append(result, groupID)
	}
	return result, true
}

func microUSDFromJSON(raw json.RawMessage) (string, bool) {
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return "", false
	}
	value, ok := new(big.Rat).SetString(number.String())
	if !ok || value.Sign() < 0 {
		return "", false
	}
	value.Mul(value, big.NewRat(int64(microUSDPerUSD), 1))
	maximum := big.NewInt(maxJavaScriptSafeInteger)
	if !value.IsInt() || value.Num().Cmp(maximum) > 0 {
		return "", false
	}
	return value.Num().String(), true
}

const (
	semanticTokenMemoryKiB uint32 = 19 * 1024
	semanticTokenTime      uint32 = 2
	semanticTokenThreads   uint8  = 1
)

// cloudflareUserSemanticToken derives a slow, operation-salted equality token
// for create retries. The Worker never receives plaintext or a fast reusable
// verifier, and the persisted management operation contains only an outer hash.
func cloudflareUserSemanticToken(operation string, user *service.User, balanceMicroUSD, password string) (string, error) {
	payload := struct {
		Email                string  `json:"email"`
		Password             string  `json:"password"`
		Username             string  `json:"username"`
		Notes                string  `json:"notes"`
		Status               string  `json:"status"`
		Role                 string  `json:"role"`
		BalanceMicroUSD      string  `json:"balance_microusd"`
		Concurrency          int     `json:"concurrency"`
		RPMLimit             int     `json:"rpm_limit"`
		AllowedGroups        []int64 `json:"allowed_group_ids"`
		RestrictPublicGroups bool    `json:"restrict_public_groups"`
	}{
		Email:                user.Email,
		Password:             password,
		Username:             user.Username,
		Notes:                user.Notes,
		Status:               user.Status,
		Role:                 user.Role,
		BalanceMicroUSD:      balanceMicroUSD,
		Concurrency:          user.Concurrency,
		RPMLimit:             user.RPMLimit,
		AllowedGroups:        user.AllowedGroups,
		RestrictPublicGroups: user.RestrictPublicGroups,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	salt := sha256.Sum256([]byte("sub2api:user-create:semantic:v1:" + operation))
	derived := argon2.IDKey(encoded, salt[:], semanticTokenTime, semanticTokenMemoryKiB, semanticTokenThreads, 32)
	token := hex.EncodeToString(derived)
	clear(encoded)
	clear(derived)
	return token, nil
}

func (update ManagedUserUpdate) empty() bool {
	return update.Email == nil && update.Username == nil && update.Notes == nil &&
		update.Status == nil && update.Concurrency == nil && update.RPMLimit == nil &&
		update.AllowedGroups == nil && update.RestrictPublicGroups == nil && update.PasswordHash == nil
}

func sameManagedUser(got, want *service.User) bool {
	return got != nil && want != nil && got.ID == want.ID && sameManagedUserFields(got, want)
}

func sameManagedUserFields(got, want *service.User) bool {
	return got != nil && want != nil && got.Email == want.Email && got.Username == want.Username &&
		got.Notes == want.Notes && got.Status == want.Status && got.Role == want.Role &&
		got.Concurrency == want.Concurrency && got.RPMLimit == want.RPMLimit &&
		got.Balance == want.Balance && got.RestrictPublicGroups == want.RestrictPublicGroups &&
		sameManagedGroups(got.AllowedGroups, want.AllowedGroups)
}

func sameManagedUserRecord(got, want *service.User) bool {
	return sameManagedUser(got, want) && got.CreatedAt.Equal(want.CreatedAt) &&
		got.UpdatedAt.Equal(want.UpdatedAt) && sameOptionalTime(got.DeletedAt, want.DeletedAt)
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func sameManagedGroups(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func matchesManagedUserPatch(user *service.User, update ManagedUserUpdate) bool {
	return user != nil &&
		(update.Email == nil || user.Email == *update.Email) &&
		(update.Username == nil || user.Username == *update.Username) &&
		(update.Notes == nil || user.Notes == *update.Notes) &&
		(update.Status == nil || user.Status == *update.Status) &&
		(update.Concurrency == nil || user.Concurrency == *update.Concurrency) &&
		(update.RPMLimit == nil || user.RPMLimit == *update.RPMLimit) &&
		(update.AllowedGroups == nil || sameManagedGroups(user.AllowedGroups, *update.AllowedGroups)) &&
		(update.RestrictPublicGroups == nil || user.RestrictPublicGroups == *update.RestrictPublicGroups)
}

func sameManagedAuthProjection(managed, auth *service.User) bool {
	return managed != nil && auth != nil && managed.ID == auth.ID && managed.Email == auth.Email &&
		managed.Username == auth.Username && managed.Status == auth.Status && managed.Role == auth.Role &&
		managed.Concurrency == auth.Concurrency && managed.RPMLimit == auth.RPMLimit &&
		managed.Balance == auth.Balance && managed.RestrictPublicGroups == auth.RestrictPublicGroups &&
		sameManagedGroups(managed.AllowedGroups, auth.AllowedGroups) &&
		managed.CreatedAt.Equal(auth.CreatedAt) && managed.UpdatedAt.Equal(auth.UpdatedAt)
}

func attachManagedUserCredential(managed, auth *service.User) error {
	if !sameManagedAuthProjection(managed, auth) {
		return errors.New("managed and auth user readbacks disagree")
	}
	managed.PasswordHash = auth.PasswordHash
	return nil
}

func mapManagedUserMutationError(err error) error {
	if err == nil {
		return nil
	}
	var responseErr *controlPlaneResponseError
	if !errors.As(err, &responseErr) {
		return err
	}
	switch responseErr.Code {
	case "NOT_FOUND", "USER_NOT_FOUND":
		return service.ErrUserNotFound
	case "EMAIL_EXISTS":
		return service.ErrEmailExists
	case "REFERENCE_REJECTED":
		return infraerrors.Conflict("GROUP_REFERENCED", "allowed group is unavailable")
	case "ROLE_PROTECTED":
		return infraerrors.Forbidden("ADMIN_ROLE_PROTECTED", "admin users cannot be disabled or deleted in Cloudflare mode")
	case "IDEMPOTENCY_CONFLICT":
		return infraerrors.Conflict("IDEMPOTENCY_CONFLICT", "idempotency key was reused with a different user payload")
	case "BALANCE_NEGATIVE":
		return infraerrors.Conflict("BALANCE_NEGATIVE", "balance cannot be negative")
	case "BALANCE_OVERFLOW":
		return infraerrors.Conflict("BALANCE_OVERFLOW", "balance exceeds the supported limit")
	case "STALE_BALANCE":
		return infraerrors.Conflict("STALE_BALANCE", "balance changed concurrently; retry with a new idempotency key")
	case "TARGET_NOT_FOUND":
		return service.ErrUserNotFound
	case "ACTOR_FORBIDDEN":
		return infraerrors.Forbidden("ADMIN_REQUIRED", "administrator access is required")
	case "CONFLICT":
		return infraerrors.Conflict("USER_CONFLICT", "user mutation conflicted with current state")
	}
	return err
}

func (c *HTTPControlPlane) CreateManagedUser(
	ctx context.Context,
	operation string,
	user *service.User,
	balanceMicroUSD string,
	passwordHash string,
	semanticToken string,
) (*service.User, bool, error) {
	if user == nil || user.ID < 1 || passwordHash == "" || len(semanticToken) != 64 {
		return nil, false, ErrNotMigrated
	}
	request := managedUserRequest(operation, user, balanceMicroUSD, passwordHash)
	request["semantic_digest"] = semanticToken
	var result managedUserMutationResponse
	if err := c.postManagedMutation(ctx, "/v1/manage/users/create", request, &result); err != nil {
		return nil, false, err
	}
	if result.leaksCredential() {
		return nil, false, errors.New("invalid user create response: credential material")
	}
	created, deleted, err := decodeManagedUser(result.User)
	if err != nil || deleted || (!result.Replayed && created.ID != user.ID) ||
		created.ID < 1 || created.ID > maxJavaScriptSafeInteger || !sameManagedUserFields(created, user) {
		return nil, false, errors.New("invalid user create response")
	}
	readback, err := c.readManagedUserIncludingTombstone(ctx, created.ID)
	if err != nil {
		return nil, false, err
	}
	if readback.deleted || !sameManagedUserRecord(readback.user, created) {
		return nil, false, errors.New("invalid user create readback")
	}
	auth, err := c.GetAuthUserByID(ctx, created.ID)
	if err != nil || attachManagedUserCredential(readback.user, auth) != nil {
		return nil, false, errors.New("invalid user create auth readback")
	}
	if !result.Replayed && readback.user.PasswordHash != passwordHash {
		return nil, false, errors.New("invalid user create credential readback")
	}
	return readback.user, result.Replayed, nil
}

func (c *HTTPControlPlane) UpdateManagedUser(
	ctx context.Context,
	operation string,
	userID int64,
	update ManagedUserUpdate,
) (*service.User, error) {
	if userID < 1 || update.empty() {
		return nil, ErrNotMigrated
	}
	request := managedUserPatchRequest(operation, userID, update)
	var result managedUserMutationResponse
	if err := c.postManagedMutation(ctx, "/v1/manage/users/update", request, &result); err != nil {
		return nil, err
	}
	if result.leaksCredential() {
		return nil, errors.New("invalid user update response: credential material")
	}
	updated, deleted, err := decodeManagedUser(result.User)
	if err != nil || deleted || updated.ID != userID || !matchesManagedUserPatch(updated, update) {
		return nil, errors.New("invalid user update response")
	}
	readback, err := c.readManagedUserIncludingTombstone(ctx, userID)
	if err != nil {
		return nil, err
	}
	if readback.deleted || !matchesManagedUserPatch(readback.user, update) {
		return nil, errors.New("invalid user update readback")
	}
	auth, err := c.GetAuthUserByID(ctx, userID)
	if err != nil || attachManagedUserCredential(readback.user, auth) != nil {
		return nil, errors.New("invalid user update auth readback")
	}
	if update.PasswordHash != nil && readback.user.PasswordHash != *update.PasswordHash {
		return nil, errors.New("invalid user update credential readback")
	}
	return readback.user, nil
}

func (c *HTTPControlPlane) DeleteManagedUser(ctx context.Context, operation string, userID int64) error {
	if userID < 1 {
		return service.ErrUserNotFound
	}
	var result managedUserMutationResponse
	if err := c.postManagedMutation(ctx, "/v1/manage/users/delete", map[string]any{
		"operation_id": operation,
		"id":           strconv.FormatInt(userID, 10),
	}, &result); err != nil {
		return err
	}
	if result.leaksCredential() {
		return errors.New("invalid user delete response: credential material")
	}
	user, deleted, err := decodeManagedUser(result.User)
	if err != nil || !deleted || user.ID != userID || user.Status != service.StatusDisabled || user.Role == service.RoleAdmin {
		return errors.New("invalid user delete response")
	}
	readback, err := c.readManagedUserIncludingTombstone(ctx, userID)
	if err != nil || !readback.deleted || !sameManagedUserRecord(readback.user, user) {
		return errors.New("invalid user delete readback")
	}
	if _, err := c.GetAuthUserByID(ctx, userID); !errors.Is(err, service.ErrUserNotFound) {
		return errors.New("deleted user remains available to authentication")
	}
	return nil
}

func managedUserRequest(
	operation string,
	user *service.User,
	balanceMicroUSD string,
	passwordHash string,
) map[string]any {
	return map[string]any{
		"operation_id":           operation,
		"id":                     strconv.FormatInt(user.ID, 10),
		"email":                  user.Email,
		"password_hash":          passwordHash,
		"username":               user.Username,
		"notes":                  user.Notes,
		"status":                 user.Status,
		"role":                   user.Role,
		"concurrency":            user.Concurrency,
		"rpm_limit":              user.RPMLimit,
		"balance_microusd":       balanceMicroUSD,
		"allowed_group_ids":      managedUserGroupIDs(user.AllowedGroups),
		"restrict_public_groups": user.RestrictPublicGroups,
	}
}

func managedUserPatchRequest(operation string, userID int64, update ManagedUserUpdate) map[string]any {
	request := map[string]any{
		"operation_id": operation,
		"id":           strconv.FormatInt(userID, 10),
	}
	if update.Email != nil {
		request["email"] = *update.Email
	}
	if update.PasswordHash != nil {
		request["password_hash"] = *update.PasswordHash
	}
	if update.Username != nil {
		request["username"] = *update.Username
	}
	if update.Notes != nil {
		request["notes"] = *update.Notes
	}
	if update.Status != nil {
		request["status"] = *update.Status
	}
	if update.Concurrency != nil {
		request["concurrency"] = *update.Concurrency
	}
	if update.RPMLimit != nil {
		request["rpm_limit"] = *update.RPMLimit
	}
	if update.AllowedGroups != nil {
		request["allowed_group_ids"] = managedUserGroupIDs(*update.AllowedGroups)
	}
	if update.RestrictPublicGroups != nil {
		request["restrict_public_groups"] = *update.RestrictPublicGroups
	}
	return request
}

type managedUserReadback struct {
	user    *service.User
	deleted bool
}

func (c *HTTPControlPlane) readManagedUserIncludingTombstone(ctx context.Context, userID int64) (*managedUserReadback, error) {
	var result managedUserMutationResponse
	if err := c.post(ctx, "/v1/manage/users/get", map[string]string{
		"id": strconv.FormatInt(userID, 10),
	}, &result); err != nil {
		return nil, err
	}
	if result.leaksCredential() {
		return nil, errors.New("invalid managed user readback: credential material")
	}
	user, deleted, err := decodeManagedUser(result.User)
	if err != nil {
		return nil, err
	}
	return &managedUserReadback{user: user, deleted: deleted}, nil
}

func managedUserGroupIDs(values []int64) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strconv.FormatInt(value, 10)
	}
	return result
}

var _ AdminUserMutationControlPlane = (*HTTPControlPlane)(nil)
var _ AdminBalanceControlPlane = (*HTTPControlPlane)(nil)

func (c *HTTPControlPlane) AdjustManagedUserBalance(ctx context.Context, adjustment ManagedBalanceAdjustment) (*ManagedBalanceAdjustmentResult, error) {
	if adjustment.ActorUserID < 1 || adjustment.TargetUserID < 1 || !isCanonicalPositiveDecimal(adjustment.AmountMicroUSD) || adjustment.AmountMicroUSD == "0" {
		return nil, ErrNotMigrated
	}
	var wire struct {
		Balance struct {
			LedgerID              string `json:"ledger_id"`
			BalanceBeforeMicroUSD string `json:"balance_before_microusd"`
			BalanceAfterMicroUSD  string `json:"balance_after_microusd"`
			DeltaMicroUSD         string `json:"delta_microusd"`
		} `json:"balance"`
		Replayed bool `json:"replayed"`
	}
	err := c.post(ctx, "/v1/manage/users/balance-adjust", map[string]any{"operation_id": adjustment.OperationID, "actor_user_id": strconv.FormatInt(adjustment.ActorUserID, 10), "target_user_id": strconv.FormatInt(adjustment.TargetUserID, 10), "operation": adjustment.Operation, "amount_microusd": adjustment.AmountMicroUSD, "reason": adjustment.Reason}, &wire)
	if err != nil {
		return nil, mapManagedUserMutationError(err)
	}
	if wire.Balance.LedgerID != adjustment.OperationID || !unsignedMicroUSDWire(wire.Balance.BalanceBeforeMicroUSD) || !unsignedMicroUSDWire(wire.Balance.BalanceAfterMicroUSD) || !signedMicroUSDWire(wire.Balance.DeltaMicroUSD) {
		return nil, errors.New("invalid balance adjustment response")
	}
	return &ManagedBalanceAdjustmentResult{LedgerID: wire.Balance.LedgerID, BalanceBeforeMicroUSD: wire.Balance.BalanceBeforeMicroUSD, BalanceAfterMicroUSD: wire.Balance.BalanceAfterMicroUSD, DeltaMicroUSD: wire.Balance.DeltaMicroUSD, Replayed: wire.Replayed}, nil
}

func signedMicroUSDWire(value string) bool {
	return value == "0" || isCanonicalPositiveDecimal(value) || (strings.HasPrefix(value, "-") && isCanonicalPositiveDecimal(strings.TrimPrefix(value, "-")))
}

func unsignedMicroUSDWire(value string) bool {
	return value == "0" || isCanonicalPositiveDecimal(value)
}
