package cloudflarebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// AdminGroupMutationControlPlane is deliberately separate from the legacy
// AdminService and repository graph. The current Worker schema persists only
// standard OpenAI group identity, status and visibility fields.
type AdminGroupMutationControlPlane interface {
	CreateManagedGroup(context.Context, string, *service.Group) (*service.Group, bool, error)
	UpdateManagedGroup(context.Context, string, int64, ManagedGroupUpdate) (*service.Group, error)
	DeleteManagedGroup(context.Context, string, int64) error
}

type ManagedGroupUpdate struct {
	Name             *string
	Status           *string
	IsExclusive      *bool
	Platform         *string
	SubscriptionType *string
}

type managedGroupResponse struct {
	Group    managedGroupWire `json:"group"`
	Replayed bool             `json:"replayed"`
}

func (h *cloudflareAdminAPIHandler) mutations() (AdminGroupMutationControlPlane, error) {
	mutations, ok := h.control.(AdminGroupMutationControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return mutations, nil
}

func (h *cloudflareAdminAPIHandler) CreateGroup(c *gin.Context) {
	idempotencyKey, err := service.NormalizeIdempotencyKey(c.GetHeader("Idempotency-Key"))
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if idempotencyKey == "" {
		response.ErrorFrom(c, service.ErrIdempotencyKeyRequired)
		return
	}
	request, ok := decodeCloudflareCreateGroupRequest(c)
	if !ok {
		return
	}
	groupID, err := newPersistentID()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	group := &service.Group{
		ID:                           groupID,
		Name:                         request.Name,
		Platform:                     service.PlatformOpenAI,
		RateMultiplier:               1,
		Status:                       request.Status,
		IsExclusive:                  request.IsExclusive,
		SubscriptionType:             service.SubscriptionTypeStandard,
		LongContextPricingEnabled:    true,
		ImageRateMultiplier:          1,
		BatchImageDiscountMultiplier: 0.5,
		BatchImageHoldMultiplier:     0.6,
		VideoRateMultiplier:          1,
		PeakRateMultiplier:           1,
		MCPXMLInject:                 true,
		MaxReasoningEffortOverLimit:  service.ReasoningEffortOverLimitDowngrade,
		Hydrated:                     true,
	}
	mutations, err := h.mutations()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		response.ErrorFrom(c, service.ErrInsufficientPerms)
		return
	}
	operationID := "group-create:" + strconv.FormatInt(subject.UserID, 10) + ":" + service.HashIdempotencyKey(idempotencyKey)
	created, replayed, err := mutations.CreateManagedGroup(c.Request.Context(), operationID, group)
	if err != nil {
		response.ErrorFrom(c, mapManagedGroupMutationError(err, service.ErrGroupExists))
		return
	}
	if created == nil || created.ID < 1 || created.ID > maxJavaScriptSafeInteger {
		response.ErrorFrom(c, errors.New("invalid group create response: unsafe identity"))
		return
	}
	if !replayed && created.ID != group.ID {
		response.ErrorFrom(c, errors.New("invalid group create response: identity mismatch"))
		return
	}
	if created.Name != group.Name || created.Platform != service.PlatformOpenAI || created.Status != group.Status ||
		created.IsExclusive != group.IsExclusive || created.SubscriptionType != service.SubscriptionTypeStandard {
		response.ErrorFrom(c, errors.New("invalid group create response: field mismatch"))
		return
	}
	response.Success(c, newCloudflareAdminGroupDTO(created))
}

func (h *cloudflareAdminAPIHandler) UpdateGroup(c *gin.Context) {
	id, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	request, ok := decodeCloudflareUpdateGroupRequest(c)
	if !ok {
		return
	}
	mutations, err := h.mutations()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	updated, err := mutations.UpdateManagedGroup(c.Request.Context(), managementOperationID("group-update"), id, request)
	if err != nil {
		response.ErrorFrom(c, mapManagedGroupMutationError(err, service.ErrGroupExists))
		return
	}
	if updated == nil || updated.ID != id || updated.Platform != service.PlatformOpenAI ||
		updated.SubscriptionType != service.SubscriptionTypeStandard {
		response.ErrorFrom(c, errors.New("invalid group update response: identity mismatch"))
		return
	}
	response.Success(c, newCloudflareAdminGroupDTO(updated))
}

func (h *cloudflareAdminAPIHandler) DeleteGroup(c *gin.Context) {
	id, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	mutations, err := h.mutations()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if err := mutations.DeleteManagedGroup(c.Request.Context(), managementOperationID("group-delete"), id); err != nil {
		response.ErrorFrom(c, mapManagedGroupMutationError(err, nil))
		return
	}
	response.Success(c, gin.H{"message": "Group deleted successfully"})
}

type cloudflareCreateGroupRequest struct {
	Name        string
	Status      string
	IsExclusive bool
}

func decodeCloudflareCreateGroupRequest(c *gin.Context) (cloudflareCreateGroupRequest, bool) {
	fields, ok := readStrictJSONObject(c)
	if !ok {
		return cloudflareCreateGroupRequest{}, false
	}
	if !validateCloudflareGroupPayloadBoundary(c, fields, false) {
		return cloudflareCreateGroupRequest{}, false
	}
	name, ok := requiredStringField(fields, "name")
	if !ok || !validCloudflareGroupName(name) {
		response.BadRequest(c, "Invalid group name")
		return cloudflareCreateGroupRequest{}, false
	}
	status, ok := optionalGroupStatus(fields, service.StatusActive)
	if !ok {
		response.BadRequest(c, "Invalid group status")
		return cloudflareCreateGroupRequest{}, false
	}
	exclusive, ok := optionalBoolField(fields, "is_exclusive", false)
	if !ok {
		response.BadRequest(c, "Invalid is_exclusive")
		return cloudflareCreateGroupRequest{}, false
	}
	return cloudflareCreateGroupRequest{Name: name, Status: status, IsExclusive: exclusive}, true
}

func decodeCloudflareUpdateGroupRequest(c *gin.Context) (ManagedGroupUpdate, bool) {
	fields, ok := readStrictJSONObject(c)
	if !ok {
		return ManagedGroupUpdate{}, false
	}
	if !validateCloudflareGroupPayloadBoundary(c, fields, true) {
		return ManagedGroupUpdate{}, false
	}
	var update ManagedGroupUpdate
	if _, exists := fields["name"]; exists {
		name, ok := requiredStringField(fields, "name")
		if !ok || !validCloudflareGroupName(name) {
			response.BadRequest(c, "Invalid group name")
			return ManagedGroupUpdate{}, false
		}
		update.Name = &name
	}
	if _, exists := fields["status"]; exists {
		status, ok := optionalGroupStatus(fields, "")
		if !ok || status == "" {
			response.BadRequest(c, "Invalid group status")
			return ManagedGroupUpdate{}, false
		}
		update.Status = &status
	}
	if _, exists := fields["is_exclusive"]; exists {
		value, ok := optionalBoolField(fields, "is_exclusive", false)
		if !ok {
			response.BadRequest(c, "Invalid is_exclusive")
			return ManagedGroupUpdate{}, false
		}
		update.IsExclusive = &value
	}
	if _, exists := fields["platform"]; exists {
		value := service.PlatformOpenAI
		update.Platform = &value
	}
	if _, exists := fields["subscription_type"]; exists {
		value := service.SubscriptionTypeStandard
		update.SubscriptionType = &value
	}
	if update.Name == nil && update.Status == nil && update.IsExclusive == nil && update.Platform == nil && update.SubscriptionType == nil {
		response.BadRequest(c, "No supported group fields to update")
		return ManagedGroupUpdate{}, false
	}
	return update, true
}

func readStrictJSONObject(c *gin.Context) (map[string]json.RawMessage, bool) {
	raw, err := c.GetRawData()
	if err != nil {
		response.BadRequest(c, "Invalid request body")
		return nil, false
	}
	fields, err := strictJSONObject(raw)
	if err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return nil, false
	}
	return fields, true
}

func strictJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("body must be a JSON object")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("object key must be a string")
		}
		if _, exists := fields[name]; exists {
			return nil, fmt.Errorf("duplicate field %q", name)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[name] = value
	}
	token, err = decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return nil, errors.New("body must be a JSON object")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("trailing JSON is not allowed")
	}
	return fields, nil
}

func validateCloudflareGroupPayloadBoundary(c *gin.Context, fields map[string]json.RawMessage, update bool) bool {
	supported := map[string]bool{"name": true, "platform": true, "status": true, "is_exclusive": true, "subscription_type": true}
	for name, raw := range fields {
		if supported[name] {
			if !validateCloudflareSupportedGroupField(c, name, raw, update) {
				return false
			}
			continue
		}
		if !isNeutralLegacyGroupField(name, raw) {
			response.BadRequest(c, name+" is not migrated in Cloudflare mode")
			return false
		}
	}
	return true
}

func validateCloudflareSupportedGroupField(c *gin.Context, name string, raw json.RawMessage, update bool) bool {
	switch name {
	case "platform":
		value, ok := stringField(raw)
		if !ok || value != "" && value != service.PlatformOpenAI {
			response.BadRequest(c, "Invalid group platform")
			return false
		}
	case "status":
		value, ok := stringField(raw)
		valid := value == service.StatusActive || update && value == "inactive"
		if !ok || !valid {
			response.BadRequest(c, "Invalid group status")
			return false
		}
	case "subscription_type":
		value, ok := stringField(raw)
		if !ok || value != "" && value != service.SubscriptionTypeStandard {
			response.BadRequest(c, "Invalid subscription_type")
			return false
		}
	case "is_exclusive":
		if !isJSONBool(raw, true) && !isJSONBool(raw, false) {
			response.BadRequest(c, "Invalid is_exclusive")
			return false
		}
	case "name":
		if update && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			response.BadRequest(c, "Invalid group name")
			return false
		}
	}
	return true
}

func requiredStringField(fields map[string]json.RawMessage, name string) (string, bool) {
	raw, exists := fields[name]
	if !exists {
		return "", false
	}
	return stringField(raw)
}

func stringField(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func optionalGroupStatus(fields map[string]json.RawMessage, fallback string) (string, bool) {
	raw, exists := fields["status"]
	if !exists {
		return fallback, true
	}
	value, ok := stringField(raw)
	if !ok {
		return "", false
	}
	switch value {
	case service.StatusActive:
		return service.StatusActive, true
	case "inactive":
		return service.StatusDisabled, true
	default:
		return "", false
	}
}

func optionalBoolField(fields map[string]json.RawMessage, name string, fallback bool) (bool, bool) {
	raw, exists := fields[name]
	if !exists {
		return fallback, true
	}
	if isJSONBool(raw, true) {
		return true, true
	}
	if isJSONBool(raw, false) {
		return false, true
	}
	return false, false
}

func validCloudflareGroupName(name string) bool {
	return name != "" && name == strings.TrimSpace(name) && len(utf16.Encode([]rune(name))) <= 100
}

func isNeutralLegacyGroupField(name string, raw json.RawMessage) bool {
	if !isKnownLegacyGroupField(name) {
		return false
	}
	if isJSONNull(raw) {
		return true
	}
	switch name {
	case "description", "default_mapped_model", "peak_start", "peak_end", "max_reasoning_effort":
		return isJSONString(raw, "")
	case "max_reasoning_effort_over_limit":
		return isJSONString(raw, "") || isJSONString(raw, "downgrade")
	case "opus_mapped_model":
		return isJSONString(raw, "gpt-5.4")
	case "sonnet_mapped_model":
		return isJSONString(raw, "gpt-5.3-codex")
	case "haiku_mapped_model":
		return isJSONString(raw, "gpt-5.4-mini")
	case "rate_multiplier", "image_rate_multiplier", "batch_image_discount_multiplier", "batch_image_hold_multiplier", "video_rate_multiplier", "peak_rate_multiplier":
		return isJSONNumber(raw, 1) || (name == "batch_image_discount_multiplier" && isJSONNumber(raw, 0.5)) || (name == "batch_image_hold_multiplier" && isJSONNumber(raw, 0.6))
	case "rpm_limit", "profit_min_margin", "profit_safety_buffer":
		return isJSONNumber(raw, 0)
	case "daily_limit_usd", "weekly_limit_usd", "monthly_limit_usd":
		return false
	case "image_price_1k", "image_price_2k", "image_price_4k", "video_price_480p", "video_price_720p", "video_price_1080p", "web_search_price_per_call", "search_price_per_1k", "audio_realtime_price_per_min", "audio_tts_price_per_million_chars", "audio_stt_price_per_hour":
		return isJSONNumber(raw, -1)
	case "fallback_group_id", "fallback_group_id_on_invalid_request":
		return isJSONNumber(raw, 0)
	case "long_context_pricing_enabled", "mcp_xml_inject":
		return isJSONBool(raw, true)
	case "allow_image_generation", "allow_batch_image_generation", "image_rate_independent", "video_rate_independent", "peak_rate_enabled", "profit_control_enabled", "claude_code_only", "model_routing_enabled", "allow_messages_dispatch", "allow_live", "force_openai_fast", "free_openai_fast", "require_oauth_only", "require_privacy_set":
		return isJSONBool(raw, false)
	case "model_pricing", "supported_model_scopes", "reasoning_effort_mappings", "copy_accounts_from_group_ids", "exact_model_mappings":
		return isEmptyJSONArray(raw)
	case "video_model_prices", "model_routing":
		return isEmptyJSONObject(raw)
	case "models_list_config":
		return isNeutralModelsListConfig(raw)
	case "messages_dispatch_model_config":
		return isNeutralMessagesDispatchConfig(raw)
	case "codex_models_manifest_config":
		return isNeutralCodexManifestConfig(raw)
	}
	return false
}

func isKnownLegacyGroupField(name string) bool {
	switch name {
	case "description", "rate_multiplier", "daily_limit_usd", "weekly_limit_usd", "monthly_limit_usd",
		"long_context_pricing_enabled", "model_pricing", "allow_image_generation",
		"allow_batch_image_generation", "image_rate_independent", "image_rate_multiplier",
		"batch_image_discount_multiplier", "batch_image_hold_multiplier", "image_price_1k",
		"image_price_2k", "image_price_4k", "video_rate_independent", "video_rate_multiplier",
		"video_price_480p", "video_price_720p", "video_price_1080p", "video_model_prices",
		"web_search_price_per_call", "search_price_per_1k", "audio_realtime_price_per_min",
		"audio_tts_price_per_million_chars", "audio_stt_price_per_hour", "peak_rate_enabled",
		"peak_start", "peak_end", "peak_rate_multiplier", "profit_control_enabled",
		"profit_min_margin", "profit_safety_buffer", "claude_code_only", "fallback_group_id",
		"fallback_group_id_on_invalid_request", "model_routing", "model_routing_enabled",
		"mcp_xml_inject", "supported_model_scopes", "allow_messages_dispatch", "allow_live",
		"force_openai_fast", "free_openai_fast", "require_oauth_only", "require_privacy_set",
		"default_mapped_model", "opus_mapped_model", "sonnet_mapped_model", "haiku_mapped_model",
		"exact_model_mappings", "messages_dispatch_model_config", "models_list_config",
		"codex_models_manifest_config", "rpm_limit", "max_reasoning_effort",
		"max_reasoning_effort_over_limit", "reasoning_effort_mappings", "copy_accounts_from_group_ids":
		return true
	default:
		return false
	}
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func isJSONString(raw json.RawMessage, expected string) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return false
	}
	var value string
	return json.Unmarshal(raw, &value) == nil && value == expected
}

func isJSONBool(raw json.RawMessage, expected bool) bool {
	trimmed := bytes.TrimSpace(raw)
	if expected {
		return bytes.Equal(trimmed, []byte("true"))
	}
	return bytes.Equal(trimmed, []byte("false"))
}

func isJSONNumber(raw json.RawMessage, expected float64) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] == 'n' {
		return false
	}
	var value float64
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	return value == expected
}

func isEmptyJSONArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return false
	}
	var value []json.RawMessage
	return json.Unmarshal(raw, &value) == nil && len(value) == 0
}

func isEmptyJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	var value map[string]json.RawMessage
	return json.Unmarshal(raw, &value) == nil && len(value) == 0
}

func isNeutralModelsListConfig(raw json.RawMessage) bool {
	fields, ok := strictRawObject(raw, "enabled", "models")
	if !ok {
		return false
	}
	return isOptionalJSONBool(fields, "enabled", false) && isOptionalBoundedStringArray(fields, "models", 1000, 256)
}

func isNeutralMessagesDispatchConfig(raw json.RawMessage) bool {
	fields, ok := strictRawObject(raw, "opus_mapped_model", "sonnet_mapped_model", "haiku_mapped_model", "exact_model_mappings")
	if !ok {
		return false
	}
	return isOptionalJSONString(fields, "opus_mapped_model", "", "gpt-5.4") &&
		isOptionalJSONString(fields, "sonnet_mapped_model", "", "gpt-5.3-codex") &&
		isOptionalJSONString(fields, "haiku_mapped_model", "", "gpt-5.4-mini") &&
		isOptionalEmptyJSONObject(fields, "exact_model_mappings")
}

func isNeutralCodexManifestConfig(raw json.RawMessage) bool {
	fields, ok := strictRawObject(raw, "enabled", "account_ids", "fallback_to_scheduler")
	if !ok {
		return false
	}
	return isOptionalJSONBool(fields, "enabled", false) &&
		isOptionalEmptyNumberArray(fields, "account_ids") &&
		isOptionalJSONBool(fields, "fallback_to_scheduler", false)
}

func strictRawObject(raw json.RawMessage, allowed ...string) (map[string]json.RawMessage, bool) {
	fields, err := strictJSONObject(raw)
	if err != nil {
		return nil, false
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = true
	}
	for name := range fields {
		if !allowedSet[name] {
			return nil, false
		}
	}
	return fields, true
}

func isOptionalJSONBool(fields map[string]json.RawMessage, name string, expected bool) bool {
	raw, exists := fields[name]
	return !exists || isJSONBool(raw, expected)
}

func isOptionalJSONString(fields map[string]json.RawMessage, name string, expected ...string) bool {
	raw, exists := fields[name]
	if !exists {
		return true
	}
	for _, value := range expected {
		if isJSONString(raw, value) {
			return true
		}
	}
	return false
}

func isOptionalEmptyJSONObject(fields map[string]json.RawMessage, name string) bool {
	raw, exists := fields[name]
	return !exists || isEmptyJSONObject(raw)
}

func isOptionalBoundedStringArray(fields map[string]json.RawMessage, name string, maximumItems, maximumLength int) bool {
	raw, exists := fields[name]
	if !exists {
		return true
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return false
	}
	var value []string
	if json.Unmarshal(raw, &value) != nil || len(value) > maximumItems {
		return false
	}
	for _, item := range value {
		if len(item) > maximumLength {
			return false
		}
	}
	return true
}

func isOptionalEmptyNumberArray(fields map[string]json.RawMessage, name string) bool {
	raw, exists := fields[name]
	if !exists {
		return true
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return false
	}
	var value []json.Number
	return json.Unmarshal(raw, &value) == nil && len(value) == 0
}

func mapManagedGroupMutationError(err error, conflict error) error {
	if err == nil {
		return nil
	}
	var responseErr *controlPlaneResponseError
	if !errors.As(err, &responseErr) {
		return err
	}
	switch responseErr.Code {
	case "NOT_FOUND", "GROUP_NOT_FOUND":
		return service.ErrGroupNotFound
	case "REFERENCE_REJECTED":
		return infraerrors.Conflict("GROUP_REFERENCED", "group is referenced and cannot be deleted")
	case "CONFLICT":
		if conflict != nil {
			return conflict
		}
	}
	return err
}

func (c *HTTPControlPlane) CreateManagedGroup(ctx context.Context, operationID string, group *service.Group) (*service.Group, bool, error) {
	if group == nil {
		return nil, false, ErrNotMigrated
	}
	request := struct {
		OperationID      string `json:"operation_id"`
		ID               string `json:"id"`
		Name             string `json:"name"`
		Platform         string `json:"platform"`
		Status           string `json:"status"`
		IsExclusive      bool   `json:"is_exclusive"`
		SubscriptionType string `json:"subscription_type"`
	}{
		OperationID:      operationID,
		ID:               strconv.FormatInt(group.ID, 10),
		Name:             group.Name,
		Platform:         group.Platform,
		Status:           group.Status,
		IsExclusive:      group.IsExclusive,
		SubscriptionType: group.SubscriptionType,
	}
	var response managedGroupResponse
	if err := c.postManagedMutation(ctx, "/v1/manage/groups/create", request, &response); err != nil {
		return nil, false, err
	}
	created, deleted, err := decodeManagedGroup(response.Group)
	if err != nil {
		return nil, false, fmt.Errorf("invalid group create response: %w", err)
	}
	if deleted || (!response.Replayed && created.ID != group.ID) || created.ID < 1 || created.ID > maxJavaScriptSafeInteger ||
		created.Name != group.Name || created.Status != group.Status ||
		created.IsExclusive != group.IsExclusive || created.Platform != service.PlatformOpenAI || created.SubscriptionType != service.SubscriptionTypeStandard {
		return nil, false, errors.New("invalid group create response: identity mismatch")
	}
	readback, err := c.readManagedGroupIncludingTombstone(ctx, created.ID)
	if err != nil {
		return nil, false, err
	}
	if readback.deleted || readback.group.ID != created.ID || readback.group.Name != created.Name || readback.group.Status != created.Status ||
		readback.group.IsExclusive != created.IsExclusive || readback.group.Platform != service.PlatformOpenAI ||
		readback.group.SubscriptionType != service.SubscriptionTypeStandard {
		return nil, false, errors.New("invalid group create readback: identity mismatch")
	}
	return readback.group, response.Replayed, nil
}

func (c *HTTPControlPlane) UpdateManagedGroup(ctx context.Context, operationID string, id int64, update ManagedGroupUpdate) (*service.Group, error) {
	request := map[string]any{
		"operation_id": operationID,
		"id":           strconv.FormatInt(id, 10),
	}
	if update.Name != nil {
		request["name"] = *update.Name
	}
	if update.Status != nil {
		request["status"] = *update.Status
	}
	if update.IsExclusive != nil {
		request["is_exclusive"] = *update.IsExclusive
	}
	if update.Platform != nil {
		request["platform"] = *update.Platform
	}
	if update.SubscriptionType != nil {
		request["subscription_type"] = *update.SubscriptionType
	}
	var response managedGroupResponse
	if err := c.postManagedMutation(ctx, "/v1/manage/groups/update", request, &response); err != nil {
		return nil, err
	}
	updated, deleted, err := decodeManagedGroup(response.Group)
	if err != nil {
		return nil, fmt.Errorf("invalid group update response: %w", err)
	}
	if deleted || updated.ID != id || updated.Platform != service.PlatformOpenAI || updated.SubscriptionType != service.SubscriptionTypeStandard {
		return nil, errors.New("invalid group update response: identity mismatch")
	}
	if (update.Name != nil && updated.Name != *update.Name) ||
		(update.Status != nil && updated.Status != *update.Status) ||
		(update.IsExclusive != nil && updated.IsExclusive != *update.IsExclusive) {
		return nil, errors.New("invalid group update response: field mismatch")
	}
	readback, err := c.readManagedGroupIncludingTombstone(ctx, id)
	if err != nil {
		return nil, err
	}
	if readback.deleted || readback.group.ID != updated.ID || readback.group.Name != updated.Name || readback.group.Status != updated.Status ||
		readback.group.IsExclusive != updated.IsExclusive || readback.group.Platform != service.PlatformOpenAI ||
		readback.group.SubscriptionType != service.SubscriptionTypeStandard {
		return nil, errors.New("invalid group update readback: identity mismatch")
	}
	return readback.group, nil
}

func (c *HTTPControlPlane) DeleteManagedGroup(ctx context.Context, operationID string, id int64) error {
	request := map[string]any{
		"operation_id": operationID,
		"id":           strconv.FormatInt(id, 10),
	}
	var response managedGroupResponse
	if err := c.postManagedMutation(ctx, "/v1/manage/groups/delete", request, &response); err != nil {
		return err
	}
	deleted, tombstoned, err := decodeManagedGroup(response.Group)
	if err != nil {
		return fmt.Errorf("invalid group delete response: %w", err)
	}
	if deleted.ID != id || !tombstoned || deleted.Status != service.StatusDisabled {
		return errors.New("invalid group delete response: identity mismatch")
	}
	readback, err := c.readManagedGroupIncludingTombstone(ctx, id)
	if err != nil {
		return err
	}
	if !readback.deleted || readback.group.ID != id || readback.group.Status != service.StatusDisabled {
		return errors.New("invalid group delete readback: identity mismatch")
	}
	return nil
}

type managedGroupReadback struct {
	group   *service.Group
	deleted bool
}

func (c *HTTPControlPlane) readManagedGroupIncludingTombstone(ctx context.Context, id int64) (*managedGroupReadback, error) {
	var response managedGroupResponse
	if err := c.post(ctx, "/v1/manage/groups/get", struct {
		ID string `json:"id"`
	}{ID: strconv.FormatInt(id, 10)}, &response); err != nil {
		return nil, err
	}
	group, deleted, err := decodeManagedGroup(response.Group)
	if err != nil {
		return nil, fmt.Errorf("invalid group readback response: %w", err)
	}
	return &managedGroupReadback{group: group, deleted: deleted}, nil
}

var _ AdminGroupMutationControlPlane = (*HTTPControlPlane)(nil)
