//go:build unit

package cloudflarebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type userAPIControlPlane struct {
	*fakeControlPlane
	mu            sync.Mutex
	users         map[int64]*service.User
	groups        map[int64]*service.Group
	keys          map[int64]*service.APIKey
	raw           map[string]int64
	nextCreatedID int64
}

func resolvedTestUser(user *service.User) *service.User {
	copy := *user
	material := strings.ToLower(strings.TrimSpace(copy.Email)) + "\n" + copy.PasswordHash
	sum := sha256.Sum256([]byte(material))
	copy.TokenVersion = int64(binary.BigEndian.Uint64(sum[:8]) & 0x7fffffffffffffff)
	copy.TokenVersionResolved = true
	return &copy
}

func (f *userAPIControlPlane) GetAuthUserByID(_ context.Context, id int64) (*service.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	user := f.users[id]
	if user == nil || user.DeletedAt != nil {
		return nil, service.ErrUserNotFound
	}
	return resolvedTestUser(user), nil
}

func (f *userAPIControlPlane) GetAuthUserByEmail(_ context.Context, email string) (*service.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	normalized := strings.ToLower(strings.TrimSpace(email))
	var found *service.User
	for _, user := range f.users {
		if user.DeletedAt == nil && strings.ToLower(strings.TrimSpace(user.Email)) == normalized {
			if found != nil {
				return nil, ErrControlPlaneUnavailable
			}
			found = user
		}
	}
	if found == nil {
		return nil, service.ErrUserNotFound
	}
	return resolvedTestUser(found), nil
}

func (f *userAPIControlPlane) GetManagedGroup(_ context.Context, id int64) (*service.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	group := f.groups[id]
	if group == nil {
		return nil, service.ErrGroupNotFound
	}
	copy := *group
	return &copy, nil
}

func (f *userAPIControlPlane) ListActiveManagedGroups(context.Context) ([]service.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]service.Group, 0, len(f.groups))
	for _, group := range f.groups {
		if group.Status == service.StatusActive {
			result = append(result, *group)
		}
	}
	return result, nil
}

func (f *userAPIControlPlane) GetManagedUser(ctx context.Context, id int64) (*service.User, error) {
	return f.GetAuthUserByID(ctx, id)
}

func (f *userAPIControlPlane) ListManagedUsers(context.Context) ([]service.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	users := make([]service.User, 0, len(f.users))
	for _, user := range f.users {
		if user.DeletedAt == nil {
			users = append(users, *user)
		}
	}
	return users, nil
}

func (f *userAPIControlPlane) ListManagedGroups(context.Context) ([]service.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	groups := make([]service.Group, 0, len(f.groups))
	for _, group := range f.groups {
		groups = append(groups, *group)
	}
	return groups, nil
}

func (f *userAPIControlPlane) CreateManagedAPIKey(_ context.Context, key *service.APIKey) (*service.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.raw[key.Key]; exists {
		return nil, service.ErrAPIKeyExists
	}
	now := time.Now().UTC()
	stored := *key
	if f.nextCreatedID > 0 {
		stored.ID = f.nextCreatedID
	}
	stored.Key = ""
	stored.CreatedAt = now
	stored.UpdatedAt = now
	f.keys[stored.ID] = &stored
	f.raw[key.Key] = stored.ID
	result := stored
	result.Key = key.Key
	return &result, nil
}

func (f *userAPIControlPlane) GetManagedAPIKey(_ context.Context, id int64) (*service.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := f.keys[id]
	if key == nil {
		return nil, service.ErrAPIKeyNotFound
	}
	copy := *key
	return &copy, nil
}

func (f *userAPIControlPlane) UpdateManagedAPIKey(_ context.Context, key *service.APIKey, _ service.APIKeyUpdateFields) (*service.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	stored := f.keys[key.ID]
	if stored == nil || stored.UserID != key.UserID {
		return nil, service.ErrAPIKeyNotFound
	}
	copy := *key
	copy.Key = ""
	copy.UpdatedAt = time.Now().UTC()
	f.keys[key.ID] = &copy
	result := copy
	return &result, nil
}

func (f *userAPIControlPlane) RevokeManagedAPIKey(_ context.Context, id int64, owner *int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := f.keys[id]
	if key == nil || owner != nil && key.UserID != *owner {
		return service.ErrAPIKeyNotFound
	}
	delete(f.keys, id)
	return nil
}

func (f *userAPIControlPlane) ListManagedAPIKeysByOwner(_ context.Context, userID int64, params pagination.PaginationParams, filters service.APIKeyListFilters) ([]service.APIKey, *pagination.PaginationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	items := make([]service.APIKey, 0)
	for _, key := range f.keys {
		if key.UserID == userID && (filters.Status == "" || key.Status == filters.Status) && (filters.GroupID == nil || key.GroupID != nil && *key.GroupID == *filters.GroupID) && (filters.Search == "" || strings.Contains(key.Name, filters.Search)) {
			items = append(items, *key)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID > items[j].ID })
	total := int64(len(items))
	page := params.Page
	if page < 1 {
		page = 1
	}
	limit := params.Limit()
	offset := (page - 1) * limit
	if offset >= len(items) {
		items = []service.APIKey{}
	} else {
		end := offset + limit
		if end > len(items) {
			end = len(items)
		}
		items = items[offset:end]
	}
	return items, &pagination.PaginationResult{Total: total, Page: page, PageSize: limit, Pages: 1}, nil
}

func (f *userAPIControlPlane) CountManagedAPIKeysByOwner(ctx context.Context, userID int64) (int64, error) {
	_, result, err := f.ListManagedAPIKeysByOwner(ctx, userID, pagination.DefaultPagination(), service.APIKeyListFilters{})
	return result.Total, err
}

func (f *userAPIControlPlane) ManagedAPIKeyExists(_ context.Context, raw string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, exists := f.raw[raw]
	return exists, nil
}

func newUserAPIControlPlane(t *testing.T) (*userAPIControlPlane, string, int64, int64) {
	t.Helper()
	const userID int64 = 9007199254740993
	const otherID int64 = 9007199254740994
	groupID := int64(9007199254741097)
	password := "correct horse battery staple"
	user := &service.User{ID: userID, Email: "User@Example.test", Username: "user", Status: service.StatusActive, Role: service.RoleUser, Concurrency: 2, Balance: 2.5, AllowedGroups: []int64{groupID}, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	require.NoError(t, user.SetPassword(password))
	other := &service.User{ID: otherID, Email: "other@example.test", Username: "other", Status: service.StatusActive, Role: service.RoleUser, Concurrency: 1, Balance: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	require.NoError(t, other.SetPassword("other-password"))
	group := &service.Group{ID: groupID, Name: "standard", Platform: service.PlatformOpenAI, RateMultiplier: 1, Status: service.StatusActive, SubscriptionType: service.SubscriptionTypeStandard, Hydrated: true}
	return &userAPIControlPlane{
		fakeControlPlane: testControlPlane(),
		users:            map[int64]*service.User{userID: user, otherID: other},
		groups:           map[int64]*service.Group{groupID: group},
		keys: map[int64]*service.APIKey{
			9007199254740995: {ID: 9007199254740995, UserID: userID, GroupID: &groupID, Name: "mine", Status: service.StatusActive, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
			9007199254740996: {ID: 9007199254740996, UserID: otherID, GroupID: &groupID, Name: "other", Status: service.StatusActive, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		raw:           map[string]int64{},
		nextCreatedID: 9007199254741098,
	}, password, userID, otherID
}

func callJSON(t *testing.T, client http.Handler, method, path, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	client.ServeHTTP(recorder, req)
	return recorder
}

func loginToken(t *testing.T, client http.Handler, email, password string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"email": email, "password": password})
	require.NoError(t, err)
	response := callJSON(t, client, http.MethodPost, "/api/v1/auth/login", "", string(payload))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var envelope struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &envelope))
	require.NotEmpty(t, envelope.Data.AccessToken)
	return envelope.Data.AccessToken
}

func TestCloudflareUserAPIEndToEndLoginJWTAndOwnerIsolation(t *testing.T) {
	control, password, _, _ := newUserAPIControlPlane(t)
	runtime := testRuntimeConfig(t)
	handler, err := NewHandler(runtime, control, &fakeHTTPUpstream{})
	require.NoError(t, err)

	loginPayload, err := json.Marshal(map[string]string{"email": "USER@example.test", "password": password})
	require.NoError(t, err)
	login := callJSON(t, handler, http.MethodPost, "/api/v1/auth/login", "", string(loginPayload))
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	var loginEnvelope struct {
		Data struct {
			AccessToken string `json:"access_token"`
			User        struct {
				ID            string   `json:"id"`
				Balance       float64  `json:"balance"`
				AllowedGroups []string `json:"allowed_groups"`
			} `json:"user"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(login.Body.Bytes(), &loginEnvelope))
	require.Equal(t, "9007199254740993", loginEnvelope.Data.User.ID)
	require.Equal(t, 2.5, loginEnvelope.Data.User.Balance)
	require.Equal(t, []string{"9007199254741097"}, loginEnvelope.Data.User.AllowedGroups)
	token := loginEnvelope.Data.AccessToken
	require.NotEmpty(t, token)

	list := callJSON(t, handler, http.MethodGet, "/api/v1/keys", token, "")
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	var listEnvelope struct {
		Data struct {
			Items []struct {
				ID      string `json:"id"`
				UserID  string `json:"user_id"`
				GroupID string `json:"group_id"`
				Name    string `json:"name"`
			} `json:"items"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &listEnvelope))
	require.Equal(t, []struct {
		ID      string `json:"id"`
		UserID  string `json:"user_id"`
		GroupID string `json:"group_id"`
		Name    string `json:"name"`
	}{{ID: "9007199254740995", UserID: "9007199254740993", GroupID: "9007199254741097", Name: "mine"}}, listEnvelope.Data.Items)

	mine := callJSON(t, handler, http.MethodGet, "/api/v1/keys/9007199254740995", token, "")
	require.Equal(t, http.StatusOK, mine.Code, mine.Body.String())
	var mineEnvelope struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(mine.Body.Bytes(), &mineEnvelope))
	require.Equal(t, "9007199254740995", mineEnvelope.Data.ID)
	other := callJSON(t, handler, http.MethodGet, "/api/v1/keys/9007199254740996", token, "")
	require.Equal(t, http.StatusNotFound, other.Code, other.Body.String())

	groups := callJSON(t, handler, http.MethodGet, "/api/v1/groups/available", token, "")
	require.Equal(t, http.StatusOK, groups.Code, groups.Body.String())
	var groupEnvelope struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(groups.Body.Bytes(), &groupEnvelope))
	require.Equal(t, "9007199254741097", groupEnvelope.Data[0].ID)

	unsafeNumericGroup := callJSON(t, handler, http.MethodPost, "/api/v1/keys", token, `{"name":"unsafe","group_id":9007199254741097}`)
	require.Equal(t, http.StatusBadRequest, unsafeNumericGroup.Code, unsafeNumericGroup.Body.String())
	unsupportedField := callJSON(t, handler, http.MethodPost, "/api/v1/keys", token, `{"name":"unsupported","group_id":"9007199254741097","quota":1}`)
	require.Equal(t, http.StatusBadRequest, unsupportedField.Code, unsupportedField.Body.String())

	created := callJSON(t, handler, http.MethodPost, "/api/v1/keys", token, `{"name":"created","group_id":"9007199254741097"}`)
	require.Equal(t, http.StatusOK, created.Code, created.Body.String())
	var createdEnvelope struct {
		Data struct {
			ID      string `json:"id"`
			UserID  string `json:"user_id"`
			GroupID string `json:"group_id"`
			Key     string `json:"key"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &createdEnvelope))
	require.Equal(t, "9007199254741098", createdEnvelope.Data.ID)
	require.Equal(t, "9007199254740993", createdEnvelope.Data.UserID)
	require.Equal(t, "9007199254741097", createdEnvelope.Data.GroupID)
	require.NotEmpty(t, createdEnvelope.Data.Key)

	createdPath := "/api/v1/keys/" + createdEnvelope.Data.ID
	readCreated := callJSON(t, handler, http.MethodGet, createdPath, token, "")
	require.Equal(t, http.StatusOK, readCreated.Code, readCreated.Body.String())
	var readCreatedEnvelope struct {
		Data struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(readCreated.Body.Bytes(), &readCreatedEnvelope))
	require.Equal(t, createdEnvelope.Data.ID, readCreatedEnvelope.Data.ID)
	require.Empty(t, readCreatedEnvelope.Data.Key)

	updated := callJSON(t, handler, http.MethodPut, createdPath, token, `{"name":"renamed"}`)
	require.Equal(t, http.StatusOK, updated.Code, updated.Body.String())
	var updatedEnvelope struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(updated.Body.Bytes(), &updatedEnvelope))
	require.Equal(t, createdEnvelope.Data.ID, updatedEnvelope.Data.ID)

	deleted := callJSON(t, handler, http.MethodDelete, createdPath, token, "")
	require.Equal(t, http.StatusOK, deleted.Code, deleted.Body.String())
	afterDelete := callJSON(t, handler, http.MethodGet, createdPath, token, "")
	require.Equal(t, http.StatusNotFound, afterDelete.Code, afterDelete.Body.String())
}

func TestCloudflareUserAPIFailsClosedForBadPasswordDisabledDeletedAndTokenChange(t *testing.T) {
	control, password, userID, _ := newUserAPIControlPlane(t)
	handler, err := NewHandler(testRuntimeConfig(t), control, &fakeHTTPUpstream{})
	require.NoError(t, err)

	bad := callJSON(t, handler, http.MethodPost, "/api/v1/auth/login", "", `{"email":"user@example.test","password":"wrong"}`)
	require.Equal(t, http.StatusUnauthorized, bad.Code, bad.Body.String())
	token := loginToken(t, handler, "user@example.test", password)

	control.mu.Lock()
	originalHash := control.users[userID].PasswordHash
	control.users[userID].PasswordHash += "x"
	control.mu.Unlock()
	revoked := callJSON(t, handler, http.MethodGet, "/api/v1/keys", token, "")
	require.Equal(t, http.StatusUnauthorized, revoked.Code, revoked.Body.String())
	require.Contains(t, revoked.Body.String(), "TOKEN_REVOKED")

	control.mu.Lock()
	control.users[userID].PasswordHash = originalHash
	control.users[userID].Status = service.StatusDisabled
	control.mu.Unlock()
	disabled := callJSON(t, handler, http.MethodPost, "/api/v1/auth/login", "", `{"email":"user@example.test","password":"correct horse battery staple"}`)
	require.Equal(t, http.StatusForbidden, disabled.Code, disabled.Body.String())

	deletedAt := time.Now().UTC()
	control.mu.Lock()
	control.users[userID].Status = service.StatusActive
	control.users[userID].DeletedAt = &deletedAt
	control.mu.Unlock()
	deleted := callJSON(t, handler, http.MethodPost, "/api/v1/auth/login", "", `{"email":"user@example.test","password":"correct horse battery staple"}`)
	require.Equal(t, http.StatusUnauthorized, deleted.Code, deleted.Body.String())
}

func TestAuthUserRepositoryNormalizesEmailAndResolvesTokenVersion(t *testing.T) {
	user := &service.User{ID: 9007199254740993, Email: "User@Example.test", Username: "user", Status: service.StatusActive, Role: service.RoleUser, Concurrency: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	require.NoError(t, user.SetPassword("repository-password"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/private/auth-users/get", r.URL.Path)
		var request map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		require.Equal(t, "user@example.test", request["email"])
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"user": map[string]any{
			"id": "9007199254740993", "email": user.Email, "username": user.Username,
			"password_hash": user.PasswordHash, "status": user.Status, "role": user.Role,
			"concurrency": 1, "rpm_limit": 0, "balance_microusd": "2500000",
			"allowed_group_ids": []string{}, "restrict_public_groups": false,
			"created_at": user.CreatedAt.Format(time.RFC3339Nano), "updated_at": user.UpdatedAt.Format(time.RFC3339Nano),
		}})
	}))
	defer server.Close()
	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	repository := NewAuthUserRepository(control)
	loaded, err := repository.GetByEmail(context.Background(), "  USER@example.test ")
	require.NoError(t, err)
	require.True(t, loaded.TokenVersionResolved)
	require.Equal(t, resolvedTestUser(user).TokenVersion, loaded.TokenVersion)
	require.Equal(t, 2.5, loaded.Balance)

	runtime := testRuntimeConfig(t)
	authService := service.NewAuthService(nil, repository, nil, nil, runtime.Application, nil, nil, nil, nil, nil, nil, nil, nil)
	token, err := authService.GenerateToken(context.Background(), loaded)
	require.NoError(t, err)
	claims, err := authService.ValidateToken(token)
	require.NoError(t, err)
	require.Equal(t, loaded.TokenVersion, claims.TokenVersion)
}

func TestCloudflareJSONIDUsesNumbersOnlyInsideJavaScriptSafeRange(t *testing.T) {
	safe, err := json.Marshal(cloudflareJSONID(42))
	require.NoError(t, err)
	require.JSONEq(t, `42`, string(safe))
	unsafe, err := json.Marshal(cloudflareJSONID(9007199254740993))
	require.NoError(t, err)
	require.JSONEq(t, `"9007199254740993"`, string(unsafe))

	var accepted cloudflareRequestID
	require.NoError(t, json.Unmarshal([]byte(`"9007199254740993"`), &accepted))
	require.Equal(t, int64(9007199254740993), int64(accepted))
	require.Error(t, json.Unmarshal([]byte(`9007199254740993`), &accepted))
}

func TestCloudflarePersistentIDsStayWithinBrowserSafeRange(t *testing.T) {
	for range 256 {
		id, err := newPersistentID()
		require.NoError(t, err)
		require.Greater(t, id, int64(0))
		require.LessOrEqual(t, id, maxJavaScriptSafeInteger)
	}
}

func TestCloudflarePublicSettingsAreTruthfulAndFrontendCompatible(t *testing.T) {
	handler, err := NewHandler(testRuntimeConfig(t), testControlPlane(), &fakeHTTPUpstream{})
	require.NoError(t, err)

	settings := callJSON(t, handler, http.MethodGet, "/api/v1/settings/public", "", "")
	require.Equal(t, http.StatusOK, settings.Code, settings.Body.String())
	require.Equal(t, "nosniff", settings.Header().Get("X-Content-Type-Options"))
	require.Contains(t, settings.Header().Get("Content-Security-Policy"), "'nonce-")
	var envelope struct {
		Code int `json:"code"`
		Data struct {
			RegistrationEnabled  bool     `json:"registration_enabled"`
			PasswordResetEnabled bool     `json:"password_reset_enabled"`
			PaymentEnabled       bool     `json:"payment_enabled"`
			PluginEnabled        bool     `json:"plugin_management_enabled"`
			ModelPlazaEnabled    bool     `json:"model_plaza_enabled"`
			ChannelEnabled       bool     `json:"channel_monitor_enabled"`
			AffiliateEnabled     bool     `json:"affiliate_enabled"`
			RiskControlEnabled   bool     `json:"risk_control_enabled"`
			Suffixes             []string `json:"registration_email_suffix_whitelist"`
			TableOptions         []int    `json:"table_page_size_options"`
			MenuItems            []any    `json:"custom_menu_items"`
			Endpoints            []any    `json:"custom_endpoints"`
			Timezone             string   `json:"server_timezone"`
			UTCOffset            string   `json:"server_utc_offset"`
			APIBaseURL           string   `json:"api_base_url"`
			HideCCSImport        bool     `json:"hide_ccs_import_button"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(settings.Body.Bytes(), &envelope))
	require.Equal(t, 0, envelope.Code)
	require.False(t, envelope.Data.RegistrationEnabled)
	require.False(t, envelope.Data.PasswordResetEnabled)
	require.False(t, envelope.Data.PaymentEnabled)
	require.False(t, envelope.Data.PluginEnabled)
	require.False(t, envelope.Data.ModelPlazaEnabled)
	require.False(t, envelope.Data.ChannelEnabled)
	require.False(t, envelope.Data.AffiliateEnabled)
	require.False(t, envelope.Data.RiskControlEnabled)
	require.NotNil(t, envelope.Data.Suffixes)
	require.Equal(t, []int{10, 20, 50, 100}, envelope.Data.TableOptions)
	require.NotNil(t, envelope.Data.MenuItems)
	require.NotNil(t, envelope.Data.Endpoints)
	require.Equal(t, "UTC", envelope.Data.Timezone)
	require.Equal(t, "+00:00", envelope.Data.UTCOffset)
	require.Empty(t, envelope.Data.APIBaseURL)
	require.True(t, envelope.Data.HideCCSImport)
}

func TestCloudflareCurrentUserUsesJWTSubjectAndFailsClosed(t *testing.T) {
	control, password, userID, _ := newUserAPIControlPlane(t)
	handler, err := NewHandler(testRuntimeConfig(t), control, &fakeHTTPUpstream{})
	require.NoError(t, err)
	token := loginToken(t, handler, "user@example.test", password)

	current := callJSON(t, handler, http.MethodGet, "/api/v1/auth/me", token, "")
	require.Equal(t, http.StatusOK, current.Code, current.Body.String())
	var envelope struct {
		Data struct {
			ID      string  `json:"id"`
			Balance float64 `json:"balance"`
			RunMode string  `json:"run_mode"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(current.Body.Bytes(), &envelope))
	require.Equal(t, strconv.FormatInt(userID, 10), envelope.Data.ID)
	require.Equal(t, 2.5, envelope.Data.Balance)
	require.Equal(t, "standard", envelope.Data.RunMode)

	missing := callJSON(t, handler, http.MethodGet, "/api/v1/auth/me", "", "")
	require.Equal(t, http.StatusUnauthorized, missing.Code, missing.Body.String())
	invalid := callJSON(t, handler, http.MethodGet, "/api/v1/auth/me", "not-a-token", "")
	require.Equal(t, http.StatusUnauthorized, invalid.Code, invalid.Body.String())
}

func TestCloudflareAdminReadOnlyRoutesRequireActiveAdminJWTAndPreserveUnsafeIDs(t *testing.T) {
	control, password, userID, _ := newUserAPIControlPlane(t)
	disabledGroupID := int64(9007199254741098)
	control.mu.Lock()
	control.users[userID].Role = service.RoleAdmin
	control.groups[disabledGroupID] = &service.Group{ID: disabledGroupID, Name: "disabled", Platform: service.PlatformOpenAI, RateMultiplier: 1, Status: service.StatusDisabled, SubscriptionType: service.SubscriptionTypeStandard, Hydrated: true}
	control.mu.Unlock()
	handler, err := NewHandler(testRuntimeConfig(t), control, &fakeHTTPUpstream{})
	require.NoError(t, err)

	unauthenticated := callJSON(t, handler, http.MethodGet, "/api/v1/admin/users", "", "")
	require.Equal(t, http.StatusUnauthorized, unauthenticated.Code, unauthenticated.Body.String())
	ordinaryToken := loginToken(t, handler, "other@example.test", "other-password")
	ordinary := callJSON(t, handler, http.MethodGet, "/api/v1/admin/users", ordinaryToken, "")
	require.Equal(t, http.StatusForbidden, ordinary.Code, ordinary.Body.String())
	adminToken := loginToken(t, handler, "user@example.test", password)

	users := callJSON(t, handler, http.MethodGet, "/api/v1/admin/users?page=1&page_size=1&role=admin&include_subscriptions=true&sort_by=created_at&sort_order=desc", adminToken, "")
	require.Equal(t, http.StatusOK, users.Code, users.Body.String())
	var userEnvelope map[string]any
	require.NoError(t, json.Unmarshal(users.Body.Bytes(), &userEnvelope))
	data := userEnvelope["data"].(map[string]any)
	items := data["items"].([]any)
	require.Equal(t, int64(1), int64(data["total"].(float64)))
	require.Equal(t, strconv.FormatInt(userID, 10), items[0].(map[string]any)["id"])
	withoutSubscriptionExpansion := callJSON(t, handler, http.MethodGet, "/api/v1/admin/users?sort_by=balance&sort_order=desc", adminToken, "")
	require.Equal(t, http.StatusOK, withoutSubscriptionExpansion.Code, withoutSubscriptionExpansion.Body.String())
	explicitlyWithoutSubscriptions := callJSON(t, handler, http.MethodGet, "/api/v1/admin/users?include_subscriptions=false&sort_by=concurrency&sort_order=asc", adminToken, "")
	require.Equal(t, http.StatusOK, explicitlyWithoutSubscriptions.Code, explicitlyWithoutSubscriptions.Body.String())

	user := callJSON(t, handler, http.MethodGet, "/api/v1/admin/users/9007199254740993", adminToken, "")
	require.Equal(t, http.StatusOK, user.Code, user.Body.String())
	groups := callJSON(t, handler, http.MethodGet, "/api/v1/admin/groups?status=active&sort_by=sort_order&sort_order=asc", adminToken, "")
	require.Equal(t, http.StatusOK, groups.Code, groups.Body.String())
	allGroups := callJSON(t, handler, http.MethodGet, "/api/v1/admin/groups/all?platform=openai", adminToken, "")
	require.Equal(t, http.StatusOK, allGroups.Code, allGroups.Body.String())
	group := callJSON(t, handler, http.MethodGet, "/api/v1/admin/groups/9007199254741097", adminToken, "")
	require.Equal(t, http.StatusOK, group.Code, group.Body.String())
	inactiveGroups := callJSON(t, handler, http.MethodGet, "/api/v1/admin/groups?status=inactive&sort_by=status&sort_order=asc", adminToken, "")
	require.Equal(t, http.StatusOK, inactiveGroups.Code, inactiveGroups.Body.String())
	var inactiveEnvelope map[string]any
	require.NoError(t, json.Unmarshal(inactiveGroups.Body.Bytes(), &inactiveEnvelope))
	inactiveItems := inactiveEnvelope["data"].(map[string]any)["items"].([]any)
	require.Len(t, inactiveItems, 1)
	require.Equal(t, strconv.FormatInt(disabledGroupID, 10), inactiveItems[0].(map[string]any)["id"])
	require.Equal(t, "inactive", inactiveItems[0].(map[string]any)["status"])
	require.Equal(t, float64(1), inactiveItems[0].(map[string]any)["rate_multiplier"])

	invalidFilter := callJSON(t, handler, http.MethodGet, "/api/v1/admin/groups?platform=anthropic", adminToken, "")
	require.Equal(t, http.StatusBadRequest, invalidFilter.Code, invalidFilter.Body.String())
	unsupportedGroupFilter := callJSON(t, handler, http.MethodGet, "/api/v1/admin/users?group_name=standard&include_subscriptions=true", adminToken, "")
	require.Equal(t, http.StatusBadRequest, unsupportedGroupFilter.Code, unsupportedGroupFilter.Body.String())
	unsupportedAttributeFilter := callJSON(t, handler, http.MethodGet, "/api/v1/admin/users?attr%5B1%5D=company&include_subscriptions=true", adminToken, "")
	require.Equal(t, http.StatusBadRequest, unsupportedAttributeFilter.Code, unsupportedAttributeFilter.Body.String())
	unsupportedSort := callJSON(t, handler, http.MethodGet, "/api/v1/admin/users?include_subscriptions=true&sort_by=last_used_at&sort_order=desc", adminToken, "")
	require.Equal(t, http.StatusBadRequest, unsupportedSort.Code, unsupportedSort.Body.String())
	includeDeleted := callJSON(t, handler, http.MethodGet, "/api/v1/admin/users/9007199254740993?include_deleted=true", adminToken, "")
	require.Equal(t, http.StatusBadRequest, includeDeleted.Code, includeDeleted.Body.String())
	duplicateBoolean := callJSON(t, handler, http.MethodGet, "/api/v1/admin/groups/all?include_inactive=true&include_inactive=false", adminToken, "")
	require.Equal(t, http.StatusBadRequest, duplicateBoolean.Code, duplicateBoolean.Body.String())
	mutation := callJSON(t, handler, http.MethodPost, "/api/v1/admin/users", adminToken, "{}")
	require.Equal(t, http.StatusNotFound, mutation.Code, mutation.Body.String())

	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	request.Header.Set("x-api-key", "some-admin-key")
	apiKeyResponse := httptest.NewRecorder()
	handler.ServeHTTP(apiKeyResponse, request)
	require.Equal(t, http.StatusUnauthorized, apiKeyResponse.Code, apiKeyResponse.Body.String())
}

func TestCloudflareSetupStatusIsCompletedAndReadOnly(t *testing.T) {
	handler, err := NewHandler(testRuntimeConfig(t), testControlPlane(), &fakeHTTPUpstream{})
	require.NoError(t, err)
	status := callJSON(t, handler, http.MethodGet, "/setup/status", "", "")
	require.Equal(t, http.StatusOK, status.Code, status.Body.String())
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(status.Body.Bytes(), &envelope))
	data := envelope["data"].(map[string]any)
	require.Equal(t, false, data["needs_setup"])
	require.Equal(t, "completed", data["step"])
	mutation := callJSON(t, handler, http.MethodPost, "/setup/install", "", "{}")
	require.Equal(t, http.StatusNotFound, mutation.Code, mutation.Body.String())
}

func TestCloudflareAPIKeyHTTPStatusAndNoOpCompatibility(t *testing.T) {
	control, password, _, otherID := newUserAPIControlPlane(t)
	groupID := int64(9007199254741097)
	control.keys[9007199254740995].Status = service.StatusAPIKeyDisabled
	handler, err := NewHandler(testRuntimeConfig(t), control, &fakeHTTPUpstream{})
	require.NoError(t, err)
	token := loginToken(t, handler, "user@example.test", password)

	list := callJSON(t, handler, http.MethodGet, "/api/v1/keys?status=inactive", token, "")
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	var listEnvelope struct {
		Data struct {
			Items []struct {
				Status string `json:"status"`
			} `json:"items"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &listEnvelope))
	require.Len(t, listEnvelope.Data.Items, 1)
	require.Equal(t, "inactive", listEnvelope.Data.Items[0].Status)

	path := "/api/v1/keys/9007199254740995"
	noOp := callJSON(t, handler, http.MethodPut, path, token, "{\"status\":\"active\",\"group_id\":\"9007199254741097\",\"quota\":0,\"rate_limit_5h\":0,\"rate_limit_1d\":0,\"rate_limit_7d\":0,\"reset_quota\":false,\"reset_rate_limit_usage\":false}")
	require.Equal(t, http.StatusOK, noOp.Code, noOp.Body.String())
	var noOpEnvelope struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(noOp.Body.Bytes(), &noOpEnvelope))
	require.Equal(t, service.StatusAPIKeyActive, noOpEnvelope.Data.Status)

	inactive := callJSON(t, handler, http.MethodPut, path, token, "{\"status\":\"inactive\"}")
	require.Equal(t, http.StatusOK, inactive.Code, inactive.Body.String())
	stored, err := control.GetManagedAPIKey(context.Background(), 9007199254740995)
	require.NoError(t, err)
	require.Equal(t, service.StatusAPIKeyDisabled, stored.Status)

	for _, payload := range []string{
		"{\"group_id\":\"1\"}",
		"{\"group_id\":null}",
		"{\"quota\":1}",
		"{\"rate_limit_1d\":1}",
		"{\"reset_quota\":true}",
		"{\"reset_rate_limit_usage\":true}",
	} {
		result := callJSON(t, handler, http.MethodPut, path, token, payload)
		require.Equal(t, http.StatusBadRequest, result.Code, payload+": "+result.Body.String())
	}

	foreign := callJSON(t, handler, http.MethodPut, "/api/v1/keys/9007199254740996", token, "{\"group_id\":\"9007199254741097\"}")
	require.Equal(t, http.StatusNotFound, foreign.Code, foreign.Body.String())
	foreignKey, err := control.GetManagedAPIKey(context.Background(), 9007199254740996)
	require.NoError(t, err)
	require.Equal(t, otherID, foreignKey.UserID)
	require.Equal(t, groupID, *foreignKey.GroupID)
}
