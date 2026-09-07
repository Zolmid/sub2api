package cloudflarebridge

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// cloudflareAdminAPIHandler avoids the traditional AdminService graph. Fields
// outside the current Worker-managed subset retain the subset's fixed defaults
// and are not accepted as filters or mutations.
type cloudflareAdminAPIHandler struct {
	control ControlPlane
}

func newCloudflareAdminAPIHandler(control ControlPlane) *cloudflareAdminAPIHandler {
	return &cloudflareAdminAPIHandler{control: control}
}

func (h *cloudflareAdminAPIHandler) management() (AdminListControlPlane, error) {
	management, ok := h.control.(AdminListControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return management, nil
}

func (h *cloudflareAdminAPIHandler) accounts() (AdminAccountReadControlPlane, error) {
	accounts, ok := h.control.(AdminAccountReadControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return accounts, nil
}

func (h *cloudflareAdminAPIHandler) balanceHistory() (AdminBalanceHistoryControlPlane, error) {
	history, ok := h.control.(AdminBalanceHistoryControlPlane)
	if !ok {
		return nil, ErrNotMigrated
	}
	return history, nil
}

type cloudflareAdminBalanceHistoryDTO struct {
	ID            cloudflareJSONID `json:"id"`
	Code          string           `json:"code"`
	Type          string           `json:"type"`
	Value         float64          `json:"value"`
	Status        string           `json:"status"`
	UsedBy        cloudflareJSONID `json:"used_by"`
	UsedAt        string           `json:"used_at"`
	CreatedAt     string           `json:"created_at"`
	GroupID       any              `json:"group_id"`
	ValidityDays  int              `json:"validity_days"`
	Notes         string           `json:"notes"`
	BalanceBefore float64          `json:"balance_before"`
	BalanceAfter  float64          `json:"balance_after"`
}

// GetBalanceHistory preserves the traditional modal response shape while
// exposing only the Worker-owned, immutable balance ledger in Cloudflare mode.
func (h *cloudflareAdminAPIHandler) GetBalanceHistory(c *gin.Context) {
	userID, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	page, pageSize, ok := cloudflareAdminPage(c)
	if !ok || pageSize > 100 {
		if ok {
			response.BadRequest(c, "Invalid page_size")
		}
		return
	}
	codeType, ok := cloudflareAdminEnum(c, "type", "", "admin_balance", "balance", "affiliate_balance", "concurrency", "admin_concurrency", "subscription")
	if !ok {
		return
	}
	history, err := h.balanceHistory()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	result, err := history.GetManagedBalanceHistory(c.Request.Context(), userID, page, pageSize, codeType)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	items := make([]cloudflareAdminBalanceHistoryDTO, 0, len(result.Entries))
	for _, entry := range result.Entries {
		value, valueErr := signedDisplayBalanceFromMicroUSD(entry.DeltaMicroUSD)
		before, beforeErr := displayBalanceFromMicroUSD(entry.BalanceBeforeMicroUSD)
		after, afterErr := displayBalanceFromMicroUSD(entry.BalanceAfterMicroUSD)
		if valueErr != nil || beforeErr != nil || afterErr != nil {
			response.ErrorFrom(c, ErrControlPlaneUnavailable)
			return
		}
		stamp := entry.CreatedAt.Format(time.RFC3339Nano)
		items = append(items, cloudflareAdminBalanceHistoryDTO{
			ID: cloudflareJSONID(entry.ID), Code: "", Type: "admin_balance", Value: value,
			Status: service.StatusUsed, UsedBy: cloudflareJSONID(userID), UsedAt: stamp, CreatedAt: stamp,
			GroupID: nil, ValidityDays: 0, Notes: entry.Reason, BalanceBefore: before, BalanceAfter: after,
		})
	}
	pages := int((result.Total + int64(pageSize) - 1) / int64(pageSize))
	if pages < 1 {
		pages = 1
	}
	response.Success(c, gin.H{"items": items, "total": result.Total, "page": page, "page_size": pageSize, "pages": pages, "total_recharged": result.TotalRecharged})
}

// cloudflareAdminAccountDTO only represents fields persisted by the Worker.
// Do not embed dto.Account here: its defaults would suggest runtime, billing,
// expiry, or credential facts that the D1 account row does not contain.
type cloudflareAdminAccountDTO struct {
	ID          cloudflareJSONID   `json:"id"`
	Name        string             `json:"name"`
	Platform    string             `json:"platform"`
	Type        string             `json:"type"`
	Status      string             `json:"status"`
	Schedulable bool               `json:"schedulable"`
	Concurrency int                `json:"concurrency"`
	Priority    int                `json:"priority"`
	Extra       map[string]any     `json:"extra"`
	GroupIDs    []cloudflareJSONID `json:"group_ids"`
	CreatedAt   string             `json:"created_at"`
	UpdatedAt   string             `json:"updated_at"`
}

func newCloudflareAdminAccountDTO(account *ManagedAccount) *cloudflareAdminAccountDTO {
	if account == nil {
		return nil
	}
	return &cloudflareAdminAccountDTO{
		ID: cloudflareJSONID(account.ID), Name: account.Name, Platform: account.Platform, Type: account.Type,
		Status: cloudflareAdminAccountStatus(account.Status), Schedulable: account.Schedulable,
		Concurrency: account.MaxConcurrency, Priority: account.Priority, Extra: cloudflareAdminAccountExtra(account.Extra),
		GroupIDs: cloudflareIDList(account.GroupIDs), CreatedAt: account.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt: account.UpdatedAt.Format(time.RFC3339Nano),
	}
}

// extra is not a credential store in this response. The Worker schema allows
// arbitrary JSON here, so returning it wholesale could expose credential
// material accidentally placed in the legacy-shaped field. privacy_mode is
// the only currently supported AccountsView extra value and is safe to expose.
func cloudflareAdminAccountExtra(extra map[string]any) map[string]any {
	mode, ok := extra["privacy_mode"].(string)
	if !ok || !cloudflareKnownOpenAIPrivacyMode(mode) {
		return map[string]any{}
	}
	return map[string]any{"privacy_mode": mode}
}

func cloudflareKnownOpenAIPrivacyMode(mode string) bool {
	switch mode {
	case service.PrivacyModeTrainingOff, service.PrivacyModeFailed, service.PrivacyModeCFBlocked:
		return true
	default:
		return false
	}
}

func cloudflareAdminAccountStatus(status string) string {
	if status == service.StatusDisabled {
		return "inactive"
	}
	return status
}

type cloudflareAdminUserDTO struct {
	*dto.AdminUser
	ID            cloudflareJSONID   `json:"id"`
	AllowedGroups []cloudflareJSONID `json:"allowed_groups"`
}

func newCloudflareAdminUserDTO(user *service.User) *cloudflareAdminUserDTO {
	return &cloudflareAdminUserDTO{
		AdminUser:     dto.UserFromServiceAdmin(user),
		ID:            cloudflareJSONID(user.ID),
		AllowedGroups: cloudflareIDList(user.AllowedGroups),
	}
}

type cloudflareAdminGroupDTO struct {
	*dto.AdminGroup
	ID                              cloudflareJSONID  `json:"id"`
	Status                          string            `json:"status"`
	FallbackGroupID                 *cloudflareJSONID `json:"fallback_group_id"`
	FallbackGroupIDOnInvalidRequest *cloudflareJSONID `json:"fallback_group_id_on_invalid_request"`
}

func newCloudflareAdminGroupDTO(group *service.Group) *cloudflareAdminGroupDTO {
	return &cloudflareAdminGroupDTO{
		AdminGroup:                      dto.GroupFromServiceAdmin(group),
		ID:                              cloudflareJSONID(group.ID),
		Status:                          cloudflareAdminGroupStatus(group.Status),
		FallbackGroupID:                 cloudflareIDPointer(group.FallbackGroupID),
		FallbackGroupIDOnInvalidRequest: cloudflareIDPointer(group.FallbackGroupIDOnInvalidRequest),
	}
}

func cloudflareAdminGroupStatus(status string) string {
	if status == service.StatusDisabled {
		return "inactive"
	}
	return status
}

func cloudflareAdminPage(c *gin.Context) (int, int, bool) {
	page, ok := cloudflareAdminPositiveQuery(c, "page", 1, 1, 1_000_000)
	if !ok {
		return 0, 0, false
	}
	pageSize, ok := cloudflareAdminPositiveQuery(c, "page_size", 20, 1, 1000)
	if !ok {
		return 0, 0, false
	}
	return page, pageSize, true
}

func cloudflareAdminPositiveQuery(c *gin.Context, name string, fallback, minimum, maximum int) (int, bool) {
	values, exists := c.GetQueryArray(name)
	if !exists {
		return fallback, true
	}
	if len(values) != 1 {
		response.BadRequest(c, "Invalid "+name)
		return 0, false
	}
	value, err := strconv.Atoi(values[0])
	if err != nil || value < minimum || value > maximum {
		response.BadRequest(c, "Invalid "+name)
		return 0, false
	}
	return value, true
}

func cloudflareAdminIDParam(c *gin.Context, name string) (int64, bool) {
	id, err := parsePositiveID(name, c.Param(name))
	if err != nil {
		response.BadRequest(c, "Invalid "+name)
		return 0, false
	}
	return id, true
}

func cloudflareAdminEnum(c *gin.Context, name string, allowed ...string) (string, bool) {
	values, exists := c.GetQueryArray(name)
	if exists && len(values) != 1 {
		response.BadRequest(c, "Invalid "+name)
		return "", false
	}
	raw := ""
	if exists {
		raw = values[0]
	}
	if raw == "" {
		return "", true
	}
	for _, value := range allowed {
		if raw == value {
			return raw, true
		}
	}
	response.BadRequest(c, "Invalid "+name)
	return "", false
}

func cloudflareAdminSearch(c *gin.Context) (string, bool) {
	values, exists := c.GetQueryArray("search")
	if exists && len(values) != 1 {
		response.BadRequest(c, "Invalid search")
		return "", false
	}
	search := ""
	if exists {
		search = strings.TrimSpace(values[0])
	}
	if len([]rune(search)) > 100 {
		response.BadRequest(c, "Invalid search")
		return "", false
	}
	return strings.ToLower(search), true
}

func cloudflareAdminSort(c *gin.Context, defaultField, defaultOrder string, allowed ...string) (string, string, bool) {
	field := c.DefaultQuery("sort_by", defaultField)
	order := c.DefaultQuery("sort_order", defaultOrder)
	if _, ok := c.GetQueryArray("sort_by"); ok && len(c.QueryArray("sort_by")) != 1 {
		response.BadRequest(c, "Invalid sort_by")
		return "", "", false
	}
	if _, ok := c.GetQueryArray("sort_order"); ok && len(c.QueryArray("sort_order")) != 1 {
		response.BadRequest(c, "Invalid sort_order")
		return "", "", false
	}
	if order != "asc" && order != "desc" {
		response.BadRequest(c, "Invalid sort_order")
		return "", "", false
	}
	for _, candidate := range allowed {
		if field == candidate {
			return field, order, true
		}
	}
	response.BadRequest(c, "Invalid sort_by")
	return "", "", false
}

func cloudflareAdminSubscriptionsQueryOK(c *gin.Context) bool {
	values, exists := c.GetQueryArray("include_subscriptions")
	if !exists {
		return true
	}
	if len(values) != 1 || values[0] != "true" && values[0] != "false" {
		response.BadRequest(c, "Invalid include_subscriptions")
		return false
	}
	return true
}

func cloudflareAdminUnsupportedUserFiltersAbsent(c *gin.Context) bool {
	for _, name := range []string{"group_name", "api_key_group_id"} {
		values, exists := c.GetQueryArray(name)
		if exists && (len(values) != 1 || strings.TrimSpace(values[0]) != "") {
			response.BadRequest(c, name+" is not migrated in Cloudflare mode")
			return false
		}
	}
	for name, values := range c.Request.URL.Query() {
		if strings.HasPrefix(name, "attr[") {
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					response.BadRequest(c, "attribute filters are not migrated in Cloudflare mode")
					return false
				}
			}
		}
	}
	return true
}

func cloudflareAdminOptionalBool(c *gin.Context, name string) (*bool, bool) {
	values, exists := c.GetQueryArray(name)
	if !exists || len(values) == 1 && values[0] == "" {
		return nil, true
	}
	if len(values) != 1 || values[0] != "true" && values[0] != "false" {
		response.BadRequest(c, "Invalid "+name)
		return nil, false
	}
	value := values[0] == "true"
	return &value, true
}

func cloudflareAdminAccountProjectionFlags(c *gin.Context) bool {
	lite, exists := c.GetQueryArray("lite")
	if !exists || len(lite) != 1 || lite[0] != "1" {
		response.BadRequest(c, "Cloudflare account lists currently require lite=1")
		return false
	}
	scheduler, exists := c.GetQueryArray("include_scheduler_score")
	if !exists || len(scheduler) == 1 && (scheduler[0] == "" || scheduler[0] == "0") {
		return true
	}
	if len(scheduler) == 1 && scheduler[0] == "1" {
		response.BadRequest(c, "Scheduler scores are not migrated in Cloudflare mode")
		return false
	}
	response.BadRequest(c, "Invalid include_scheduler_score")
	return false
}

func cloudflareAdminAccountQueryOK(c *gin.Context) bool {
	allowed := map[string]bool{
		"page": true, "page_size": true, "platform": true, "type": true, "status": true,
		"privacy_mode": true, "group": true, "search": true, "lite": true,
		"include_scheduler_score": true, "sort_by": true, "sort_order": true, "timezone": true,
	}
	for name, values := range c.Request.URL.Query() {
		if allowed[name] {
			continue
		}
		if len(values) != 1 || strings.TrimSpace(values[0]) != "" {
			response.BadRequest(c, name+" is not migrated in Cloudflare mode")
			return false
		}
	}
	return true
}

func cloudflareAdminIgnoredTimezoneOK(c *gin.Context) bool {
	values, exists := c.GetQueryArray("timezone")
	if !exists || len(values) == 1 {
		return true
	}
	response.BadRequest(c, "Invalid timezone")
	return false
}

func cloudflareAdminAccountDetailQueryOK(c *gin.Context) bool {
	for name := range c.Request.URL.Query() {
		if name != "timezone" {
			response.BadRequest(c, "Account detail query parameters are not migrated in Cloudflare mode")
			return false
		}
	}
	return cloudflareAdminIgnoredTimezoneOK(c)
}

func cloudflareAdminAccountGroup(c *gin.Context) (string, bool) {
	values, exists := c.GetQueryArray("group")
	if !exists || len(values) == 1 && values[0] == "" {
		return "", true
	}
	if len(values) != 1 {
		response.BadRequest(c, "Invalid group")
		return "", false
	}
	value := values[0]
	if value == "ungrouped" {
		return value, true
	}
	if isCanonicalPositiveDecimal(value) {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil && parsed > 0 {
			return value, true
		}
	}
	response.BadRequest(c, "Invalid group")
	return "", false
}

func cloudflareAdminAccountPrivacyMode(c *gin.Context) (string, bool) {
	values, exists := c.GetQueryArray("privacy_mode")
	if !exists || len(values) == 1 && values[0] == "" {
		return "", true
	}
	if len(values) != 1 || (values[0] != service.AccountPrivacyModeUnsetFilter && !cloudflareKnownOpenAIPrivacyMode(values[0])) {
		response.BadRequest(c, "Invalid privacy_mode")
		return "", false
	}
	return values[0], true
}

func (h *cloudflareAdminAPIHandler) ListAccounts(c *gin.Context) {
	if !cloudflareAdminAccountQueryOK(c) || !cloudflareAdminIgnoredTimezoneOK(c) || !cloudflareAdminAccountProjectionFlags(c) {
		return
	}
	page, pageSize, ok := cloudflareAdminPage(c)
	if !ok {
		return
	}
	platform, ok := cloudflareAdminEnum(c, "platform", service.PlatformOpenAI)
	if !ok {
		return
	}
	accountType, ok := cloudflareAdminEnum(c, "type", service.AccountTypeAPIKey)
	if !ok {
		return
	}
	status, ok := cloudflareAdminEnum(c, "status", service.StatusActive, "inactive")
	if !ok {
		return
	}
	group, ok := cloudflareAdminAccountGroup(c)
	if !ok {
		return
	}
	privacyMode, ok := cloudflareAdminAccountPrivacyMode(c)
	if !ok {
		return
	}
	search, ok := cloudflareAdminSearch(c)
	if !ok {
		return
	}
	sortBy, sortOrder, ok := cloudflareAdminSort(c, "name", "asc", "id", "name", "status", "schedulable", "priority", "created_at")
	if !ok {
		return
	}
	accounts, err := h.accounts()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	items, err := accounts.ListManagedAccounts(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	filtered := make([]ManagedAccount, 0, len(items))
	for _, account := range items {
		if (platform != "" && account.Platform != platform) || (accountType != "" && account.Type != accountType) ||
			(status != "" && cloudflareAdminAccountStatus(account.Status) != status) ||
			(search != "" && !strings.Contains(strings.ToLower(account.Name), search)) ||
			(group == "ungrouped" && len(account.GroupIDs) != 0) ||
			(group != "" && group != "ungrouped" && !cloudflareAccountHasGroup(account.GroupIDs, group)) ||
			!cloudflareAccountMatchesPrivacyMode(account.Extra, privacyMode) {
			continue
		}
		filtered = append(filtered, account)
	}
	sortCloudflareAccounts(filtered, sortBy, sortOrder)
	response.Paginated(c, paginateCloudflareAccounts(filtered, page, pageSize), int64(len(filtered)), page, pageSize)
}

func cloudflareAccountHasGroup(ids []int64, expected string) bool {
	for _, id := range ids {
		if strconv.FormatInt(id, 10) == expected {
			return true
		}
	}
	return false
}

func cloudflareAccountMatchesPrivacyMode(extra map[string]any, expected string) bool {
	if expected == "" {
		return true
	}
	actual, _ := extra["privacy_mode"].(string)
	if expected == service.AccountPrivacyModeUnsetFilter {
		return strings.TrimSpace(actual) == ""
	}
	return actual == expected
}

func sortCloudflareAccounts(accounts []ManagedAccount, sortBy, sortOrder string) {
	compare := func(i, j int) int {
		left, right := accounts[i], accounts[j]
		var leftValue, rightValue string
		switch sortBy {
		case "id":
			if left.ID < right.ID {
				return -1
			}
			if left.ID > right.ID {
				return 1
			}
			return 0
		case "status":
			leftValue, rightValue = cloudflareAdminAccountStatus(left.Status), cloudflareAdminAccountStatus(right.Status)
		case "schedulable":
			leftValue, rightValue = strconv.FormatBool(left.Schedulable), strconv.FormatBool(right.Schedulable)
		case "priority":
			if left.Priority < right.Priority {
				return -1
			}
			if left.Priority > right.Priority {
				return 1
			}
		case "created_at":
			if left.CreatedAt.Before(right.CreatedAt) {
				return -1
			}
			if right.CreatedAt.Before(left.CreatedAt) {
				return 1
			}
		default:
			leftValue, rightValue = strings.ToLower(left.Name), strings.ToLower(right.Name)
		}
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
		// A canonical-ID tie breaker keeps page boundaries deterministic.
		if left.ID < right.ID {
			return -1
		}
		if left.ID > right.ID {
			return 1
		}
		return 0
	}
	sort.SliceStable(accounts, func(i, j int) bool {
		comparison := compare(i, j)
		if sortOrder == "desc" {
			return comparison > 0
		}
		return comparison < 0
	})
}

func paginateCloudflareAccounts(accounts []ManagedAccount, page, pageSize int) []*cloudflareAdminAccountDTO {
	start := (page - 1) * pageSize
	if start >= len(accounts) {
		return []*cloudflareAdminAccountDTO{}
	}
	end := start + pageSize
	if end > len(accounts) {
		end = len(accounts)
	}
	items := make([]*cloudflareAdminAccountDTO, 0, end-start)
	for i := start; i < end; i++ {
		items = append(items, newCloudflareAdminAccountDTO(&accounts[i]))
	}
	return items
}

func (h *cloudflareAdminAPIHandler) GetAccount(c *gin.Context) {
	if !cloudflareAdminAccountDetailQueryOK(c) {
		return
	}
	id, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	accounts, err := h.accounts()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	account, err := accounts.GetManagedAccount(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, newCloudflareAdminAccountDTO(account))
}

func (h *cloudflareAdminAPIHandler) ListUsers(c *gin.Context) {
	if !cloudflareAdminUnsupportedUserFiltersAbsent(c) {
		return
	}
	page, pageSize, ok := cloudflareAdminPage(c)
	if !ok {
		return
	}
	status, ok := cloudflareAdminEnum(c, "status", service.StatusActive, service.StatusDisabled)
	if !ok {
		return
	}
	role, ok := cloudflareAdminEnum(c, "role", service.RoleAdmin, service.RoleUser)
	if !ok {
		return
	}
	search, ok := cloudflareAdminSearch(c)
	if !ok {
		return
	}
	sortBy, sortOrder, ok := cloudflareAdminSort(c, "created_at", "desc", "created_at", "id", "email", "username", "status", "role", "balance", "concurrency")
	if !ok || !cloudflareAdminSubscriptionsQueryOK(c) {
		return
	}
	management, err := h.management()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	users, err := management.ListManagedUsers(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	filtered := make([]service.User, 0, len(users))
	for _, user := range users {
		if (status != "" && user.Status != status) || (role != "" && user.Role != role) || (search != "" && !strings.Contains(strings.ToLower(user.Email), search) && !strings.Contains(strings.ToLower(user.Username), search)) {
			continue
		}
		filtered = append(filtered, user)
	}
	sortCloudflareUsers(filtered, sortBy, sortOrder)
	response.Paginated(c, paginateCloudflareUsers(filtered, page, pageSize), int64(len(filtered)), page, pageSize)
}

func sortCloudflareUsers(users []service.User, sortBy, sortOrder string) {
	less := func(i, j int) bool {
		left, right := users[i], users[j]
		switch sortBy {
		case "id":
			return left.ID < right.ID
		case "email":
			return strings.ToLower(left.Email) < strings.ToLower(right.Email)
		case "username":
			return strings.ToLower(left.Username) < strings.ToLower(right.Username)
		case "status":
			return left.Status < right.Status
		case "role":
			return left.Role < right.Role
		case "balance":
			return left.Balance < right.Balance
		case "concurrency":
			return left.Concurrency < right.Concurrency
		default:
			return left.CreatedAt.Before(right.CreatedAt)
		}
	}
	sort.SliceStable(users, func(i, j int) bool {
		if sortOrder == "desc" {
			return less(j, i)
		}
		return less(i, j)
	})
}

func paginateCloudflareUsers(users []service.User, page, pageSize int) []*cloudflareAdminUserDTO {
	start := (page - 1) * pageSize
	if start >= len(users) {
		return []*cloudflareAdminUserDTO{}
	}
	end := start + pageSize
	if end > len(users) {
		end = len(users)
	}
	out := make([]*cloudflareAdminUserDTO, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, newCloudflareAdminUserDTO(&users[i]))
	}
	return out
}

func (h *cloudflareAdminAPIHandler) GetUser(c *gin.Context) {
	includeDeleted, ok := cloudflareAdminOptionalBool(c, "include_deleted")
	if !ok {
		return
	}
	if includeDeleted != nil && *includeDeleted {
		response.BadRequest(c, "include_deleted is not migrated in Cloudflare mode")
		return
	}
	id, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	management, err := h.management()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	user, err := management.GetManagedUser(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, newCloudflareAdminUserDTO(user))
}

func (h *cloudflareAdminAPIHandler) ListGroups(c *gin.Context) {
	page, pageSize, ok := cloudflareAdminPage(c)
	if !ok {
		return
	}
	sortBy, sortOrder, ok := cloudflareAdminSort(c, "sort_order", "asc", "sort_order", "id", "name", "status", "created_at")
	if !ok {
		return
	}
	groups, ok := h.filteredGroups(c, true)
	if !ok {
		return
	}
	sortCloudflareGroups(groups, sortBy, sortOrder)
	response.Paginated(c, paginateCloudflareGroups(groups, page, pageSize), int64(len(groups)), page, pageSize)
}

func (h *cloudflareAdminAPIHandler) ListAllGroups(c *gin.Context) {
	includeInactive, ok := cloudflareAdminOptionalBool(c, "include_inactive")
	if !ok {
		return
	}
	groups, ok := h.filteredGroups(c, includeInactive != nil && *includeInactive)
	if !ok {
		return
	}
	out := make([]*cloudflareAdminGroupDTO, 0, len(groups))
	for i := range groups {
		out = append(out, newCloudflareAdminGroupDTO(&groups[i]))
	}
	response.Success(c, out)
}

func (h *cloudflareAdminAPIHandler) filteredGroups(c *gin.Context, includeInactive bool) ([]service.Group, bool) {
	platform, ok := cloudflareAdminEnum(c, "platform", service.PlatformOpenAI)
	if !ok {
		return nil, false
	}
	status, ok := cloudflareAdminEnum(c, "status", service.StatusActive, service.StatusDisabled, "inactive")
	if !ok {
		return nil, false
	}
	if status == "inactive" {
		status = service.StatusDisabled
	}
	search, ok := cloudflareAdminSearch(c)
	if !ok {
		return nil, false
	}
	exclusive, ok := cloudflareAdminOptionalBool(c, "is_exclusive")
	if !ok {
		return nil, false
	}
	management, err := h.management()
	if err != nil {
		response.ErrorFrom(c, err)
		return nil, false
	}
	groups, err := management.ListManagedGroups(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return nil, false
	}
	filtered := make([]service.Group, 0, len(groups))
	for _, group := range groups {
		if (!includeInactive && group.Status != service.StatusActive) || (platform != "" && group.Platform != platform) || (status != "" && group.Status != status) || (search != "" && !strings.Contains(strings.ToLower(group.Name), search)) || (exclusive != nil && group.IsExclusive != *exclusive) {
			continue
		}
		filtered = append(filtered, group)
	}
	return filtered, true
}

func sortCloudflareGroups(groups []service.Group, sortBy, sortOrder string) {
	less := func(i, j int) bool {
		left, right := groups[i], groups[j]
		switch sortBy {
		case "id", "sort_order":
			return left.ID < right.ID
		case "name":
			return strings.ToLower(left.Name) < strings.ToLower(right.Name)
		case "status":
			return left.Status < right.Status
		default:
			return left.CreatedAt.Before(right.CreatedAt)
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if sortOrder == "desc" {
			return less(j, i)
		}
		return less(i, j)
	})
}

func paginateCloudflareGroups(groups []service.Group, page, pageSize int) []*cloudflareAdminGroupDTO {
	start := (page - 1) * pageSize
	if start >= len(groups) {
		return []*cloudflareAdminGroupDTO{}
	}
	end := start + pageSize
	if end > len(groups) {
		end = len(groups)
	}
	out := make([]*cloudflareAdminGroupDTO, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, newCloudflareAdminGroupDTO(&groups[i]))
	}
	return out
}

func (h *cloudflareAdminAPIHandler) GetGroup(c *gin.Context) {
	id, ok := cloudflareAdminIDParam(c, "id")
	if !ok {
		return
	}
	management, err := h.management()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	group, err := management.GetManagedGroup(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, newCloudflareAdminGroupDTO(group))
}
