package cloudflarebridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

const maxJavaScriptSafeInteger = int64(1<<53 - 1)

// cloudflareJSONID preserves the existing numeric JSON shape for ordinary IDs
// but emits decimal strings when a JavaScript Number could not preserve the
// int64 value. It is used only by the Cloudflare composition root.
type cloudflareJSONID int64

func (id cloudflareJSONID) MarshalJSON() ([]byte, error) {
	value := int64(id)
	if value < 1 {
		return nil, errors.New("invalid non-positive id")
	}
	decimal := strconv.FormatInt(value, 10)
	if value <= maxJavaScriptSafeInteger {
		return []byte(decimal), nil
	}
	return json.Marshal(decimal)
}

// cloudflareRequestID accepts decimal strings for all positive int64 IDs. A
// JSON number is accepted only while it is safe for a browser to represent.
type cloudflareRequestID int64

func (id *cloudflareRequestID) UnmarshalJSON(data []byte) error {
	if id == nil {
		return errors.New("nil id destination")
	}
	raw := strings.TrimSpace(string(data))
	quoted := len(raw) >= 2 && raw[0] == '"'
	if quoted {
		if err := json.Unmarshal(data, &raw); err != nil {
			return errors.New("id must be a canonical decimal string")
		}
	}
	parsed, err := parsePositiveID("id", raw)
	if err != nil {
		return err
	}
	if !quoted && parsed > maxJavaScriptSafeInteger {
		return errors.New("unsafe integer id must be encoded as a decimal string")
	}
	*id = cloudflareRequestID(parsed)
	return nil
}

// cloudflareOptionalRequestID distinguishes an omitted field from an explicit
// JSON null. Group removal is not migrated, so treating null as "no change"
// would incorrectly report a successful unsupported mutation.
type cloudflareOptionalRequestID struct {
	Present bool
	Null    bool
	Value   cloudflareRequestID
}

func (id *cloudflareOptionalRequestID) UnmarshalJSON(data []byte) error {
	if id == nil {
		return errors.New("nil optional id destination")
	}
	id.Present = true
	if strings.TrimSpace(string(data)) == "null" {
		id.Null = true
		return nil
	}
	var value cloudflareRequestID
	if err := value.UnmarshalJSON(data); err != nil {
		return err
	}
	id.Value = value
	return nil
}

func cloudflareIDPointer(id *int64) *cloudflareJSONID {
	if id == nil {
		return nil
	}
	value := cloudflareJSONID(*id)
	return &value
}

func cloudflareIDList(ids []int64) []cloudflareJSONID {
	out := make([]cloudflareJSONID, len(ids))
	for index, id := range ids {
		out[index] = cloudflareJSONID(id)
	}
	return out
}

type cloudflareUserDTO struct {
	*dto.User
	ID            cloudflareJSONID   `json:"id"`
	AllowedGroups []cloudflareJSONID `json:"allowed_groups"`
}

func newCloudflareUserDTO(user *service.User) *cloudflareUserDTO {
	if user == nil {
		return nil
	}
	return &cloudflareUserDTO{
		User:          dto.UserFromService(user),
		ID:            cloudflareJSONID(user.ID),
		AllowedGroups: cloudflareIDList(user.AllowedGroups),
	}
}

type cloudflareGroupDTO struct {
	*dto.Group
	ID                              cloudflareJSONID  `json:"id"`
	FallbackGroupID                 *cloudflareJSONID `json:"fallback_group_id"`
	FallbackGroupIDOnInvalidRequest *cloudflareJSONID `json:"fallback_group_id_on_invalid_request"`
}

func newCloudflareGroupDTO(group *service.Group) *cloudflareGroupDTO {
	if group == nil {
		return nil
	}
	return &cloudflareGroupDTO{
		Group:                           dto.GroupFromService(group),
		ID:                              cloudflareJSONID(group.ID),
		FallbackGroupID:                 cloudflareIDPointer(group.FallbackGroupID),
		FallbackGroupIDOnInvalidRequest: cloudflareIDPointer(group.FallbackGroupIDOnInvalidRequest),
	}
}

type cloudflareAPIKeyDTO struct {
	*dto.APIKey
	ID      cloudflareJSONID    `json:"id"`
	UserID  cloudflareJSONID    `json:"user_id"`
	GroupID *cloudflareJSONID   `json:"group_id"`
	Status  string              `json:"status"`
	User    *cloudflareUserDTO  `json:"user,omitempty"`
	Group   *cloudflareGroupDTO `json:"group,omitempty"`
}

func newCloudflareAPIKeyDTO(key *service.APIKey) *cloudflareAPIKeyDTO {
	if key == nil {
		return nil
	}
	return &cloudflareAPIKeyDTO{
		APIKey:  dto.APIKeyFromService(key),
		ID:      cloudflareJSONID(key.ID),
		UserID:  cloudflareJSONID(key.UserID),
		GroupID: cloudflareIDPointer(key.GroupID),
		Status:  cloudflareAPIKeyStatusForResponse(key.Status),
		User:    newCloudflareUserDTO(key.User),
		Group:   newCloudflareGroupDTO(key.Group),
	}
}

type cloudflareAuthResponse struct {
	AccessToken string             `json:"access_token"`
	TokenType   string             `json:"token_type"`
	User        *cloudflareUserDTO `json:"user"`
}

type cloudflareCreateAPIKeyRequest struct {
	Name          string               `json:"name"`
	GroupID       *cloudflareRequestID `json:"group_id"`
	CustomKey     *string              `json:"custom_key"`
	IPWhitelist   []string             `json:"ip_whitelist"`
	IPBlacklist   []string             `json:"ip_blacklist"`
	ExpiresInDays *int                 `json:"expires_in_days"`
}

type cloudflareUpdateAPIKeyRequest struct {
	Name                string                      `json:"name"`
	Status              string                      `json:"status"`
	GroupID             cloudflareOptionalRequestID `json:"group_id"`
	Quota               *float64                    `json:"quota"`
	RateLimit5h         *float64                    `json:"rate_limit_5h"`
	RateLimit1d         *float64                    `json:"rate_limit_1d"`
	RateLimit7d         *float64                    `json:"rate_limit_7d"`
	ResetQuota          *bool                       `json:"reset_quota"`
	ResetRateLimitUsage *bool                       `json:"reset_rate_limit_usage"`
	IPWhitelist         *[]string                   `json:"ip_whitelist"`
	IPBlacklist         *[]string                   `json:"ip_blacklist"`
	ExpiresAt           *string                     `json:"expires_at"`
}

type cloudflareUserAPIHandler struct {
	authService   *service.AuthService
	authUsers     *AuthUserRepository
	apiKeyService *service.APIKeyService
}

func newCloudflareUserAPIHandler(authService *service.AuthService, authUsers *AuthUserRepository, apiKeyService *service.APIKeyService) *cloudflareUserAPIHandler {
	return &cloudflareUserAPIHandler{authService: authService, authUsers: authUsers, apiKeyService: apiKeyService}
}

// GetPublicSettingsForInjection lets the embedded frontend use exactly the
// same deterministic configuration exposed by /api/v1/settings/public.
func (h *cloudflareUserAPIHandler) GetPublicSettingsForInjection(context.Context) (any, error) {
	return cloudflarePublicSettings(), nil
}

func cloudflarePublicSettings() dto.PublicSettings {
	return dto.PublicSettings{
		RegistrationEmailSuffixWhitelist:     []string{},
		LoginAgreementDocuments:              []dto.LoginAgreementDocument{},
		SiteName:                             "Sub2API",
		APIBaseURL:                           "",
		HideCcsImportButton:                  true,
		TableDefaultPageSize:                 20,
		TablePageSizeOptions:                 []int{10, 20, 50, 100},
		CustomMenuItems:                      []dto.CustomMenuItem{},
		CustomEndpoints:                      []dto.CustomEndpoint{},
		OIDCOAuthProviderName:                "OIDC",
		Version:                              "cloudflare",
		ServerTimezone:                       "UTC",
		ServerUTCOffset:                      "+00:00",
		ChannelMonitorMode:                   "v2",
		ChannelMonitorDefaultIntervalSeconds: 60,
	}
}

func (h *cloudflareUserAPIHandler) PublicSettings(c *gin.Context) {
	response.Success(c, cloudflarePublicSettings())
}

func decodeCloudflareJSON(c *gin.Context, target any) error {
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func (h *cloudflareUserAPIHandler) Login(c *gin.Context) {
	var request handler.LoginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	proof := service.CaptchaProof{
		TurnstileToken: request.TurnstileToken,
		TencentTicket:  request.TencentCaptchaTicket,
		TencentRandstr: request.TencentCaptchaRandstr,
	}
	if err := h.authService.VerifyCaptcha(c.Request.Context(), proof, ip.GetClientIP(c)); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	token, user, err := h.authService.Login(c.Request.Context(), request.Email, request.Password)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	h.authService.RecordSuccessfulLogin(c.Request.Context(), user.ID)
	response.Success(c, cloudflareAuthResponse{AccessToken: token, TokenType: "Bearer", User: newCloudflareUserDTO(user)})
}

func (h *cloudflareUserAPIHandler) CurrentUser(c *gin.Context) {
	subject, ok := authenticatedCloudflareUser(c)
	if !ok {
		return
	}
	user, err := h.authUsers.GetByID(c.Request.Context(), subject.UserID)
	if err != nil {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	response.Success(c, struct {
		*cloudflareUserDTO
		RunMode string `json:"run_mode"`
	}{cloudflareUserDTO: newCloudflareUserDTO(user), RunMode: "standard"})
}

func authenticatedCloudflareUser(c *gin.Context) (middleware2.AuthSubject, bool) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
	}
	return subject, ok
}

func (h *cloudflareUserAPIHandler) ListAPIKeys(c *gin.Context) {
	subject, ok := authenticatedCloudflareUser(c)
	if !ok {
		return
	}
	page, pageSize := response.ParsePagination(c)
	params := pagination.PaginationParams{Page: page, PageSize: pageSize, SortBy: c.DefaultQuery("sort_by", "created_at"), SortOrder: c.DefaultQuery("sort_order", "desc")}
	status, ok := cloudflareAPIKeyStatusForFilter(c.Query("status"))
	if !ok {
		response.BadRequest(c, "Invalid API key status")
		return
	}
	filters := service.APIKeyListFilters{Status: status}
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		if len(search) > 100 {
			search = search[:100]
		}
		filters.Search = search
	}
	if rawGroupID := c.Query("group_id"); rawGroupID != "" {
		groupID, err := parsePositiveID("group id", rawGroupID)
		if err != nil {
			response.BadRequest(c, "Invalid group ID")
			return
		}
		filters.GroupID = &groupID
	}
	keys, result, err := h.apiKeyService.List(c.Request.Context(), subject.UserID, params, filters)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	out := make([]cloudflareAPIKeyDTO, 0, len(keys))
	for index := range keys {
		out = append(out, *newCloudflareAPIKeyDTO(&keys[index]))
	}
	response.Paginated(c, out, result.Total, page, pageSize)
}

func parseCloudflarePathID(c *gin.Context) (int64, bool) {
	id, err := parsePositiveID("api key id", c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid key ID")
		return 0, false
	}
	return id, true
}

func (h *cloudflareUserAPIHandler) GetAPIKey(c *gin.Context) {
	subject, ok := authenticatedCloudflareUser(c)
	if !ok {
		return
	}
	keyID, ok := parseCloudflarePathID(c)
	if !ok {
		return
	}
	key, err := h.apiKeyService.GetByID(c.Request.Context(), keyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if key.UserID != subject.UserID {
		response.NotFound(c, "API key not found")
		return
	}
	response.Success(c, newCloudflareAPIKeyDTO(key))
}

func (h *cloudflareUserAPIHandler) CreateAPIKey(c *gin.Context) {
	subject, ok := authenticatedCloudflareUser(c)
	if !ok {
		return
	}
	var request cloudflareCreateAPIKeyRequest
	if err := decodeCloudflareJSON(c, &request); err != nil || strings.TrimSpace(request.Name) == "" || request.GroupID == nil || request.ExpiresInDays != nil && *request.ExpiresInDays <= 0 {
		response.BadRequest(c, "Invalid request")
		return
	}
	groupID := int64(*request.GroupID)
	key, err := h.apiKeyService.Create(c.Request.Context(), subject.UserID, service.CreateAPIKeyRequest{
		Name: request.Name, GroupID: &groupID, CustomKey: request.CustomKey,
		IPWhitelist: request.IPWhitelist, IPBlacklist: request.IPBlacklist, ExpiresInDays: request.ExpiresInDays,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, newCloudflareAPIKeyDTO(key))
}

func (h *cloudflareUserAPIHandler) UpdateAPIKey(c *gin.Context) {
	subject, ok := authenticatedCloudflareUser(c)
	if !ok {
		return
	}
	keyID, ok := parseCloudflarePathID(c)
	if !ok {
		return
	}
	var request cloudflareUpdateAPIKeyRequest
	if err := decodeCloudflareJSON(c, &request); err != nil {
		response.BadRequest(c, "Invalid request")
		return
	}
	key, err := h.apiKeyService.GetByID(c.Request.Context(), keyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if key.UserID != subject.UserID {
		response.NotFound(c, "API key not found")
		return
	}
	if !cloudflareUpdateNoOpsAllowed(key, request) {
		response.BadRequest(c, "Cloudflare mode does not support changing API key group, quota, rate limits, or usage counters")
		return
	}
	internalStatus, ok := cloudflareAPIKeyStatusForUpdate(request.Status)
	if !ok {
		response.BadRequest(c, "Invalid API key status")
		return
	}
	serviceRequest := service.UpdateAPIKeyRequest{IPWhitelist: request.IPWhitelist, IPBlacklist: request.IPBlacklist}
	if request.Name != "" {
		serviceRequest.Name = &request.Name
	}
	if internalStatus != "" {
		serviceRequest.Status = &internalStatus
	}
	if request.ExpiresAt != nil {
		if *request.ExpiresAt == "" {
			serviceRequest.ClearExpiration = true
		} else {
			expiresAt, err := time.Parse(time.RFC3339, *request.ExpiresAt)
			if err != nil {
				response.BadRequest(c, "Invalid expires_at format: "+err.Error())
				return
			}
			serviceRequest.ExpiresAt = &expiresAt
		}
	}
	key, err = h.apiKeyService.Update(c.Request.Context(), keyID, subject.UserID, serviceRequest)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, newCloudflareAPIKeyDTO(key))
}

func cloudflareAPIKeyStatusForResponse(status string) string {
	if status == service.StatusAPIKeyDisabled {
		return "inactive"
	}
	return status
}

func cloudflareAPIKeyStatusForFilter(status string) (string, bool) {
	switch status {
	case "", service.StatusAPIKeyActive:
		return status, true
	case "inactive":
		return service.StatusAPIKeyDisabled, true
	default:
		return "", false
	}
}

func cloudflareAPIKeyStatusForUpdate(status string) (string, bool) {
	switch status {
	case "", service.StatusAPIKeyActive:
		return status, true
	case "inactive":
		return service.StatusAPIKeyDisabled, true
	default:
		return "", false
	}
}

func cloudflareUpdateNoOpsAllowed(key *service.APIKey, request cloudflareUpdateAPIKeyRequest) bool {
	if key == nil {
		return false
	}
	if request.GroupID.Present {
		if request.GroupID.Null || key.GroupID == nil || int64(request.GroupID.Value) != *key.GroupID {
			return false
		}
	}
	for _, limit := range []struct {
		request *float64
		current float64
	}{
		{request.Quota, key.Quota},
		{request.RateLimit5h, key.RateLimit5h},
		{request.RateLimit1d, key.RateLimit1d},
		{request.RateLimit7d, key.RateLimit7d},
	} {
		if limit.request != nil && (*limit.request != 0 || limit.current != 0) {
			return false
		}
	}
	return (request.ResetQuota == nil || !*request.ResetQuota) &&
		(request.ResetRateLimitUsage == nil || !*request.ResetRateLimitUsage)
}

func (h *cloudflareUserAPIHandler) DeleteAPIKey(c *gin.Context) {
	subject, ok := authenticatedCloudflareUser(c)
	if !ok {
		return
	}
	keyID, ok := parseCloudflarePathID(c)
	if !ok {
		return
	}
	if err := h.apiKeyService.Delete(c.Request.Context(), keyID, subject.UserID); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"message": "API key deleted successfully"})
}

func (h *cloudflareUserAPIHandler) GetAvailableGroups(c *gin.Context) {
	subject, ok := authenticatedCloudflareUser(c)
	if !ok {
		return
	}
	groups, err := h.apiKeyService.GetAvailableGroups(c.Request.Context(), subject.UserID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	out := make([]cloudflareGroupDTO, 0, len(groups))
	for index := range groups {
		out = append(out, *newCloudflareGroupDTO(&groups[index]))
	}
	response.Success(c, out)
}

var _ json.Marshaler = cloudflareJSONID(0)
var _ json.Unmarshaler = (*cloudflareRequestID)(nil)
