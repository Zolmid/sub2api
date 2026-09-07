package cloudflarebridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// AdminAccountMutationControlPlane limits Cloudflare mode to Worker-managed
// OpenAI API-key accounts. OAuth, import, refresh, test, bulk and credential
// read operations have deliberately no representation here.
type AdminAccountMutationControlPlane interface {
	CreateManagedAccount(context.Context, string, *ManagedAccount, map[string]string) (*ManagedAccount, bool, error)
	UpdateManagedAccount(context.Context, string, int64, ManagedAccountUpdate) (*ManagedAccount, error)
	DeleteManagedAccount(context.Context, string, int64) error
}

type ManagedAccountUpdate struct {
	Name           *string
	Status         *string
	Schedulable    *bool
	Priority       *int
	MaxConcurrency *int
	Credentials    map[string]string
	Extra          *map[string]any
	GroupIDs       *[]int64
}

func (u ManagedAccountUpdate) empty() bool {
	return u.Name == nil && u.Status == nil && u.Schedulable == nil && u.Priority == nil && u.MaxConcurrency == nil && u.Credentials == nil && u.Extra == nil && u.GroupIDs == nil
}

type cloudflareAccountMutationRequest struct {
	Name           *string
	Platform       *string
	Type           *string
	Status         *string
	Schedulable    *bool
	Priority       *int
	MaxConcurrency *int
	Credentials    map[string]string
	Extra          *map[string]any
	GroupIDs       *[]int64
}

type managedAccountMutationResponse struct {
	Account            managedAccountWire `json:"account"`
	Replayed           *bool              `json:"replayed"`
	Credentials        json.RawMessage    `json:"credentials,omitempty"`
	CredentialEnvelope json.RawMessage    `json:"credential_envelope,omitempty"`
	APIKey             json.RawMessage    `json:"api_key,omitempty"`
	BaseURL            json.RawMessage    `json:"base_url,omitempty"`
	RawKey             json.RawMessage    `json:"raw_key,omitempty"`
}

func (r managedAccountMutationResponse) leaksCredential() bool {
	return len(r.Credentials) != 0 || len(r.CredentialEnvelope) != 0 || len(r.APIKey) != 0 ||
		len(r.BaseURL) != 0 || len(r.RawKey) != 0 || r.Account.leaksCredential()
}

func (h *cloudflareAdminAPIHandler) accountMutations() (AdminAccountMutationControlPlane, error) {
	mutations, ok := h.control.(AdminAccountMutationControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return mutations, nil
}

func (h *cloudflareAdminAPIHandler) CreateAccount(c *gin.Context) {
	key, err := service.NormalizeIdempotencyKey(c.GetHeader("Idempotency-Key"))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if key == "" {
		response.ErrorFrom(c, service.ErrIdempotencyKeyRequired)
		return
	}
	req, ok := decodeCloudflareAccountMutation(c, true)
	if !ok {
		return
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID < 1 {
		response.ErrorFrom(c, service.ErrInsufficientPerms)
		return
	}
	id, err := newPersistentID()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	account := &ManagedAccount{ID: id, Name: *req.Name, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: accountStatusOr(req.Status, service.StatusActive), Schedulable: boolOr(req.Schedulable, true), Priority: intOr(req.Priority, 0), MaxConcurrency: *req.MaxConcurrency, Extra: mapOrEmpty(req.Extra), GroupIDs: groupsOrEmpty(req.GroupIDs)}
	mutations, err := h.accountMutations()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	created, replayed, err := mutations.CreateManagedAccount(c.Request.Context(), "account-create:"+strconv.FormatInt(subject.UserID, 10)+":"+service.HashIdempotencyKey(key), account, req.Credentials)
	if err != nil {
		response.ErrorFrom(c, mapManagedAccountMutationError(err))
		return
	}
	if created == nil || created.ID < 1 || (!replayed && created.ID != account.ID) || !sameManagedAccountCreate(created, account) {
		response.ErrorFrom(c, errors.New("invalid account create response"))
		return
	}
	response.Success(c, newCloudflareAdminAccountDTO(created))
}

func (h *cloudflareAdminAPIHandler) UpdateAccount(c *gin.Context) {
	id, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	req, ok := decodeCloudflareAccountMutation(c, false)
	if !ok {
		return
	}
	update := ManagedAccountUpdate{Name: req.Name, Status: req.Status, Schedulable: req.Schedulable, Priority: req.Priority, MaxConcurrency: req.MaxConcurrency, Credentials: req.Credentials, Extra: req.Extra, GroupIDs: req.GroupIDs}
	if update.empty() {
		response.BadRequest(c, "No supported account fields to update")
		return
	}
	mutations, err := h.accountMutations()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	account, err := mutations.UpdateManagedAccount(c.Request.Context(), managementOperationID("account-update"), id, update)
	if err != nil {
		response.ErrorFrom(c, mapManagedAccountMutationError(err))
		return
	}
	if account == nil || account.ID != id || !matchesManagedAccountPatch(account, update) {
		response.ErrorFrom(c, errors.New("invalid account update response"))
		return
	}
	response.Success(c, newCloudflareAdminAccountDTO(account))
}

func (h *cloudflareAdminAPIHandler) DeleteAccount(c *gin.Context) {
	id, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	mutations, err := h.accountMutations()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if err := mutations.DeleteManagedAccount(c.Request.Context(), managementOperationID("account-delete"), id); err != nil {
		response.ErrorFrom(c, mapManagedAccountMutationError(err))
		return
	}
	response.Success(c, gin.H{"message": "Account deleted successfully"})
}

func decodeCloudflareAccountMutation(c *gin.Context, create bool) (cloudflareAccountMutationRequest, bool) {
	fields, ok := readStrictJSONObject(c)
	if !ok {
		return cloudflareAccountMutationRequest{}, false
	}
	allowed := map[string]bool{"name": true, "platform": true, "type": true, "status": true, "schedulable": true, "priority": true, "concurrency": true, "max_concurrency": true, "credentials": true, "extra": true, "group_ids": true}
	for name := range fields {
		if !allowed[name] {
			response.BadRequest(c, name+" is not migrated in Cloudflare mode")
			return cloudflareAccountMutationRequest{}, false
		}
	}
	var out cloudflareAccountMutationRequest
	for _, item := range []struct {
		name   string
		target **string
	}{{"name", &out.Name}, {"platform", &out.Platform}, {"type", &out.Type}, {"status", &out.Status}} {
		if raw, exists := fields[item.name]; exists {
			value, valid := stringField(raw)
			if !valid {
				response.BadRequest(c, "Invalid "+item.name)
				return out, false
			}
			*item.target = &value
		}
	}
	if out.Name != nil && (*out.Name == "" || *out.Name != strings.TrimSpace(*out.Name) || len(utf16.Encode([]rune(*out.Name))) > 100) {
		response.BadRequest(c, "Invalid name")
		return out, false
	}
	if out.Platform != nil && *out.Platform != service.PlatformOpenAI {
		response.BadRequest(c, "Only OpenAI API-key accounts are migrated in Cloudflare mode")
		return out, false
	}
	if out.Type != nil && *out.Type != service.AccountTypeAPIKey {
		response.BadRequest(c, "Only OpenAI API-key accounts are migrated in Cloudflare mode")
		return out, false
	}
	if out.Status != nil && *out.Status != service.StatusActive && *out.Status != "inactive" {
		response.BadRequest(c, "Invalid status")
		return out, false
	}
	if raw, exists := fields["schedulable"]; exists {
		value, valid := jsonBool(raw)
		if !valid {
			response.BadRequest(c, "Invalid schedulable")
			return out, false
		}
		out.Schedulable = &value
	}
	for _, item := range []struct {
		name     string
		target   **int
		min, max int
	}{{"priority", &out.Priority, -100000, 100000}, {"concurrency", &out.MaxConcurrency, 1, 100000}, {"max_concurrency", &out.MaxConcurrency, 1, 100000}} {
		if raw, exists := fields[item.name]; exists {
			value, valid := jsonInt(raw)
			if !valid || value < item.min || value > item.max || (*item.target != nil && **item.target != value) {
				response.BadRequest(c, "Invalid "+item.name)
				return out, false
			}
			*item.target = &value
		}
	}
	if raw, exists := fields["credentials"]; exists {
		value, valid := cloudflareAPIKeyCredentials(raw)
		if !valid {
			response.BadRequest(c, "Invalid credentials")
			return out, false
		}
		out.Credentials = value
	}
	if raw, exists := fields["extra"]; exists {
		value, valid := cloudflareAccountExtra(raw)
		if !valid {
			response.BadRequest(c, "Invalid extra")
			return out, false
		}
		out.Extra = &value
	}
	if raw, exists := fields["group_ids"]; exists {
		value, valid := cloudflareAccountGroupIDs(raw)
		if !valid {
			response.BadRequest(c, "Invalid group_ids")
			return out, false
		}
		out.GroupIDs = &value
	}
	if create && (out.Name == nil || out.Platform == nil || out.Type == nil || out.MaxConcurrency == nil || out.Credentials == nil || out.GroupIDs == nil || len(*out.GroupIDs) == 0) {
		response.BadRequest(c, "Missing required account fields")
		return out, false
	}
	return out, true
}
func jsonBool(raw json.RawMessage) (bool, bool) {
	var value bool
	return value, json.Unmarshal(raw, &value) == nil
}
func jsonInt(raw json.RawMessage) (int, bool) {
	var value int
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	return value, decoder.Decode(&value) == nil
}
func cloudflareAPIKeyCredentials(raw json.RawMessage) (map[string]string, bool) {
	fields, ok := strictRawObject(raw, "api_key", "base_url")
	if !ok || len(fields) != 2 {
		return nil, false
	}
	key, keyOK := requiredStringField(fields, "api_key")
	base, baseOK := requiredStringField(fields, "base_url")
	if !keyOK || !baseOK || key == "" || len(key) > 16384 || len(base) > 2048 {
		return nil, false
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, false
	}
	return map[string]string{"api_key": key, "base_url": strings.TrimRight(parsed.String(), "/")}, true
}
func cloudflareAccountExtra(raw json.RawMessage) (map[string]any, bool) {
	fields, ok := strictRawObject(raw, "privacy_mode")
	if !ok {
		return nil, false
	}
	if len(fields) == 0 {
		return map[string]any{}, true
	}
	mode, ok := requiredStringField(fields, "privacy_mode")
	if !ok || !cloudflareKnownOpenAIPrivacyMode(mode) {
		return nil, false
	}
	return map[string]any{"privacy_mode": mode}, true
}
func cloudflareAccountGroupIDs(raw json.RawMessage) ([]int64, bool) {
	var values []cloudflareRequestID
	if json.Unmarshal(raw, &values) != nil || len(values) == 0 || len(values) > 100 {
		return nil, false
	}
	seen := map[int64]struct{}{}
	out := make([]int64, 0, len(values))
	for _, value := range values {
		id := int64(value)
		if _, exists := seen[id]; exists {
			return nil, false
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, true
}
func accountStatusOr(value *string, fallback string) string {
	if value == nil {
		return fallback
	}
	if *value == "inactive" {
		return service.StatusDisabled
	}
	return *value
}
func mapOrEmpty(value *map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return *value
}
func matchesManagedAccountPatch(account *ManagedAccount, update ManagedAccountUpdate) bool {
	return account != nil && account.Platform == service.PlatformOpenAI && account.Type == service.AccountTypeAPIKey && (update.Name == nil || account.Name == *update.Name) && (update.Status == nil || cloudflareAdminAccountStatus(account.Status) == *update.Status) && (update.Schedulable == nil || account.Schedulable == *update.Schedulable) && (update.Priority == nil || account.Priority == *update.Priority) && (update.MaxConcurrency == nil || account.MaxConcurrency == *update.MaxConcurrency) && (update.Extra == nil || sameCloudflareAccountExtra(account.Extra, *update.Extra)) && (update.GroupIDs == nil || sameManagedAccountGroups(account.GroupIDs, *update.GroupIDs))
}
func sameCloudflareAccountExtra(left, right map[string]any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}
func sameManagedAccountCreate(actual, expected *ManagedAccount) bool {
	return actual != nil && expected != nil && actual.DeletedAt == nil && actual.Name == expected.Name &&
		actual.Platform == expected.Platform && actual.Type == expected.Type &&
		cloudflareAdminAccountStatus(actual.Status) == cloudflareAdminAccountStatus(expected.Status) &&
		actual.Schedulable == expected.Schedulable && actual.Priority == expected.Priority &&
		actual.MaxConcurrency == expected.MaxConcurrency && sameCloudflareAccountExtra(actual.Extra, expected.Extra) &&
		sameManagedAccountGroups(actual.GroupIDs, expected.GroupIDs)
}
func sameManagedAccountGroups(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[int64]int, len(left))
	for _, id := range left {
		counts[id]++
	}
	for _, id := range right {
		counts[id]--
		if counts[id] < 0 {
			return false
		}
	}
	return true
}
func sameManagedAccountRecord(actual, expected *ManagedAccount) bool {
	return actual != nil && expected != nil && actual.ID == expected.ID &&
		sameManagedAccountCreate(actual, expected) && actual.CreatedAt.Equal(expected.CreatedAt) &&
		actual.UpdatedAt.Equal(expected.UpdatedAt) && sameOptionalTime(actual.DeletedAt, expected.DeletedAt)
}
func mapManagedAccountMutationError(err error) error {
	var responseErr *controlPlaneResponseError
	if !errors.As(err, &responseErr) {
		return err
	}
	switch responseErr.Code {
	case "NOT_FOUND":
		return service.ErrAccountNotFound
	case "REFERENCE_REJECTED":
		return infraerrors.Conflict("ACCOUNT_GROUP_REFERENCE_REJECTED", "account group is not an active compatible OpenAI group")
	case "CONFLICT", "IDEMPOTENCY_CONFLICT":
		return infraerrors.Conflict("ACCOUNT_CONFLICT", "account operation conflicts with current state")
	}
	return err
}
func decimalIDs(ids []int64) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = strconv.FormatInt(id, 10)
	}
	return out
}

func (c *HTTPControlPlane) CreateManagedAccount(ctx context.Context, operation string, account *ManagedAccount, credentials map[string]string) (*ManagedAccount, bool, error) {
	if account == nil || credentials == nil {
		return nil, false, ErrNotMigrated
	}
	request := map[string]any{"operation_id": operation, "id": strconv.FormatInt(account.ID, 10), "name": account.Name, "platform": account.Platform, "status": account.Status, "schedulable": account.Schedulable, "priority": account.Priority, "max_concurrency": account.MaxConcurrency, "credentials": credentials, "extra": account.Extra, "group_ids": decimalIDs(account.GroupIDs)}
	var wire managedAccountMutationResponse
	if err := c.postManagedMutation(ctx, "/v1/manage/accounts/create", request, &wire); err != nil {
		return nil, false, mapManagedAccountMutationError(err)
	}
	if wire.leaksCredential() {
		return nil, false, errors.New("invalid account create response: unexpected credential")
	}
	created, deleted, err := decodeManagedAccount(wire.Account)
	if err != nil || deleted || wire.Replayed == nil || (!*wire.Replayed && created.ID != account.ID) ||
		!sameManagedAccountCreate(created, account) {
		return nil, false, errors.New("invalid account create response")
	}
	readback, err := c.GetManagedAccount(ctx, created.ID)
	if err != nil || !sameManagedAccountRecord(readback, created) {
		return nil, false, errors.New("invalid account create readback")
	}
	return created, *wire.Replayed, nil
}
func (c *HTTPControlPlane) UpdateManagedAccount(ctx context.Context, operation string, id int64, update ManagedAccountUpdate) (*ManagedAccount, error) {
	request := map[string]any{"operation_id": operation, "id": strconv.FormatInt(id, 10)}
	if update.Name != nil {
		request["name"] = *update.Name
	}
	if update.Status != nil {
		request["status"] = accountStatusOr(update.Status, "")
	}
	if update.Schedulable != nil {
		request["schedulable"] = *update.Schedulable
	}
	if update.Priority != nil {
		request["priority"] = *update.Priority
	}
	if update.MaxConcurrency != nil {
		request["max_concurrency"] = *update.MaxConcurrency
	}
	if update.Credentials != nil {
		request["credentials"] = update.Credentials
	}
	if update.Extra != nil {
		request["extra"] = *update.Extra
	}
	if update.GroupIDs != nil {
		request["group_ids"] = decimalIDs(*update.GroupIDs)
	}
	var wire managedAccountMutationResponse
	if err := c.postManagedMutation(ctx, "/v1/manage/accounts/update", request, &wire); err != nil {
		return nil, mapManagedAccountMutationError(err)
	}
	if wire.leaksCredential() {
		return nil, errors.New("invalid account update response: unexpected credential")
	}
	account, deleted, err := decodeManagedAccount(wire.Account)
	if err != nil || deleted || account.ID != id || !matchesManagedAccountPatch(account, update) {
		return nil, errors.New("invalid account update response")
	}
	return account, nil
}
func (c *HTTPControlPlane) DeleteManagedAccount(ctx context.Context, operation string, id int64) error {
	var wire managedAccountMutationResponse
	if err := c.postManagedMutation(ctx, "/v1/manage/accounts/delete", map[string]string{"operation_id": operation, "id": strconv.FormatInt(id, 10)}, &wire); err != nil {
		return mapManagedAccountMutationError(err)
	}
	if wire.leaksCredential() {
		return errors.New("invalid account delete response: unexpected credential")
	}
	account, deleted, err := decodeManagedAccount(wire.Account)
	if err != nil || !deleted || account.ID != id || account.Status != service.StatusDisabled || account.Schedulable {
		return errors.New("invalid account delete response")
	}
	return nil
}
