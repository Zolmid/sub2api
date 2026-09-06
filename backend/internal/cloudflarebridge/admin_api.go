package cloudflarebridge

import (
	"sort"
	"strconv"
	"strings"

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
