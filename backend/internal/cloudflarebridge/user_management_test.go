package cloudflarebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type userCreateOperationStub struct {
	semanticToken string
	user          *service.User
}

type adminUserControlStub struct {
	mu sync.Mutex

	users      map[int64]*service.User
	operations map[string]userCreateOperationStub
	balances   map[string]ManagedBalanceAdjustmentResult

	createCalls           int
	updateCalls           int
	deleteCalls           int
	lastOperation         string
	lastBalanceMicroUSD   string
	lastSemanticToken     string
	lastUpdate            ManagedUserUpdate
	lastBalanceAdjustment ManagedBalanceAdjustment
}

func newAdminUserControlStub(users ...*service.User) *adminUserControlStub {
	indexed := make(map[int64]*service.User, len(users))
	for _, user := range users {
		copy := *user
		copy.AllowedGroups = append([]int64{}, user.AllowedGroups...)
		indexed[user.ID] = &copy
	}
	return &adminUserControlStub{
		users:      indexed,
		operations: map[string]userCreateOperationStub{},
		balances:   map[string]ManagedBalanceAdjustmentResult{},
	}
}

func (stub *adminUserControlStub) ResolveAPIKey(context.Context, string) (*service.APIKey, error) {
	return nil, service.ErrAPIKeyNotFound
}

func (*adminUserControlStub) TouchAPIKey(context.Context, int64, time.Time) error { return nil }

func (*adminUserControlStub) Admit(context.Context, AdmissionRequest) (*Admission, error) {
	return nil, ErrNotMigrated
}

func (*adminUserControlStub) Renew(context.Context, RenewRequest) (*Lease, error) {
	return nil, ErrNotMigrated
}

func (*adminUserControlStub) Complete(context.Context, CompletionRequest) error {
	return ErrNotMigrated
}

func (*adminUserControlStub) Release(context.Context, ReleaseRequest) error { return ErrNotMigrated }

func (stub *adminUserControlStub) GetManagedUser(_ context.Context, userID int64) (*service.User, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	user := stub.users[userID]
	if user == nil || user.DeletedAt != nil {
		return nil, service.ErrUserNotFound
	}
	copy := *user
	copy.AllowedGroups = append([]int64{}, user.AllowedGroups...)
	return &copy, nil
}

func (*adminUserControlStub) GetManagedGroup(context.Context, int64) (*service.Group, error) {
	return nil, service.ErrGroupNotFound
}

func (*adminUserControlStub) ListActiveManagedGroups(context.Context) ([]service.Group, error) {
	return []service.Group{}, nil
}

func (stub *adminUserControlStub) ListManagedUsers(context.Context) ([]service.User, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	result := make([]service.User, 0, len(stub.users))
	for _, user := range stub.users {
		if user.DeletedAt == nil {
			result = append(result, *user)
		}
	}
	return result, nil
}

func (*adminUserControlStub) ListManagedGroups(context.Context) ([]service.Group, error) {
	return []service.Group{}, nil
}

func (stub *adminUserControlStub) CreateManagedUser(
	_ context.Context,
	operation string,
	user *service.User,
	balanceMicroUSD string,
	passwordHash string,
	semanticToken string,
) (*service.User, bool, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.createCalls++
	stub.lastOperation = operation
	stub.lastBalanceMicroUSD = balanceMicroUSD
	stub.lastSemanticToken = semanticToken
	if prior, ok := stub.operations[operation]; ok {
		if prior.semanticToken != semanticToken || !sameManagedUserFields(prior.user, user) {
			return nil, false, &controlPlaneResponseError{StatusCode: http.StatusConflict, Code: "IDEMPOTENCY_CONFLICT"}
		}
		copy := *prior.user
		copy.AllowedGroups = append([]int64{}, prior.user.AllowedGroups...)
		return &copy, true, nil
	}
	stamp := time.Now().UTC()
	stored := *user
	stored.PasswordHash = passwordHash
	stored.CreatedAt = stamp
	stored.UpdatedAt = stamp
	stored.AllowedGroups = append([]int64{}, user.AllowedGroups...)
	stub.users[stored.ID] = &stored
	stub.operations[operation] = userCreateOperationStub{semanticToken: semanticToken, user: &stored}
	copy := stored
	return &copy, false, nil
}

func (stub *adminUserControlStub) UpdateManagedUser(
	_ context.Context,
	_ string,
	userID int64,
	update ManagedUserUpdate,
) (*service.User, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.updateCalls++
	stub.lastUpdate = update
	user := stub.users[userID]
	if user == nil || user.DeletedAt != nil {
		return nil, service.ErrUserNotFound
	}
	if update.Email != nil {
		user.Email = *update.Email
	}
	if update.Username != nil {
		user.Username = *update.Username
	}
	if update.Notes != nil {
		user.Notes = *update.Notes
	}
	if update.Status != nil {
		user.Status = *update.Status
	}
	if update.Concurrency != nil {
		user.Concurrency = *update.Concurrency
	}
	if update.RPMLimit != nil {
		user.RPMLimit = *update.RPMLimit
	}
	if update.AllowedGroups != nil {
		user.AllowedGroups = append([]int64{}, (*update.AllowedGroups)...)
	}
	if update.RestrictPublicGroups != nil {
		user.RestrictPublicGroups = *update.RestrictPublicGroups
	}
	if update.PasswordHash != nil {
		user.PasswordHash = *update.PasswordHash
	}
	user.UpdatedAt = time.Now().UTC()
	copy := *user
	copy.AllowedGroups = append([]int64{}, user.AllowedGroups...)
	return &copy, nil
}

func (stub *adminUserControlStub) AdjustManagedUserBalance(_ context.Context, adjustment ManagedBalanceAdjustment) (*ManagedBalanceAdjustmentResult, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.lastBalanceAdjustment = adjustment
	if prior, ok := stub.balances[adjustment.OperationID]; ok {
		prior.Replayed = true
		return &prior, nil
	}
	user := stub.users[adjustment.TargetUserID]
	if user == nil || user.DeletedAt != nil {
		return nil, service.ErrUserNotFound
	}
	before := user.Balance
	amount, _ := strconv.ParseInt(adjustment.AmountMicroUSD, 10, 64)
	if adjustment.Operation == "add" {
		user.Balance += float64(amount) / float64(microUSDPerUSD)
	}
	result := ManagedBalanceAdjustmentResult{LedgerID: adjustment.OperationID, BalanceBeforeMicroUSD: strconv.FormatInt(int64(before*float64(microUSDPerUSD)), 10), BalanceAfterMicroUSD: strconv.FormatInt(int64(user.Balance*float64(microUSDPerUSD)), 10), DeltaMicroUSD: adjustment.AmountMicroUSD}
	stub.balances[adjustment.OperationID] = result
	return &result, nil
}

func (stub *adminUserControlStub) DeleteManagedUser(_ context.Context, _ string, userID int64) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.deleteCalls++
	user := stub.users[userID]
	if user == nil || user.DeletedAt != nil {
		return service.ErrUserNotFound
	}
	stamp := time.Now().UTC()
	user.Status = service.StatusDisabled
	user.UpdatedAt = stamp
	user.DeletedAt = &stamp
	return nil
}

func adminUserMutationRouter(control *adminUserControlStub, actorID int64) http.Handler {
	handler := newCloudflareAdminAPIHandler(control)
	router := gin.New()
	withActor := func(next gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: actorID})
			next(c)
		}
	}
	router.POST("/users", withActor(handler.CreateUser))
	router.PUT("/users/:id", withActor(handler.UpdateUser))
	router.DELETE("/users/:id", withActor(handler.DeleteUser))
	router.POST("/users/:id/balance", withActor(handler.UpdateBalance))
	return router
}

func TestCloudflareAdminBalanceUsesExactControlPlaneContract(t *testing.T) {
	user := &service.User{ID: 2001, Email: "user@example.test", Status: service.StatusActive, Role: service.RoleUser, Balance: 1, Concurrency: 1}
	control := newAdminUserControlStub(user)
	handler := adminUserMutationRouter(control, 99)
	missing := callAdminUserMutation(t, handler, http.MethodPost, "/users/2001/balance", `{"balance":1.000001,"operation":"add","notes":"ledger note"}`, "")
	require.Equal(t, http.StatusBadRequest, missing.Code, missing.Body.String())
	require.Empty(t, control.lastBalanceAdjustment.OperationID)

	idempotencyKey := strings.Repeat("k", 128)
	result := callAdminUserMutation(t, handler, http.MethodPost, "/users/2001/balance", `{"balance":1.000001,"operation":"add","notes":"ledger note"}`, idempotencyKey)
	require.Equal(t, http.StatusOK, result.Code, result.Body.String())
	require.Equal(t, int64(99), control.lastBalanceAdjustment.ActorUserID)
	require.Equal(t, int64(2001), control.lastBalanceAdjustment.TargetUserID)
	require.Equal(t, "1000001", control.lastBalanceAdjustment.AmountMicroUSD)
	require.Equal(t, "add", control.lastBalanceAdjustment.Operation)
	require.Equal(t, "ledger note", control.lastBalanceAdjustment.Reason)
	expectedOperationID := "user-balance:99:" + service.HashIdempotencyKey(idempotencyKey)
	require.Equal(t, expectedOperationID, control.lastBalanceAdjustment.OperationID)
	require.LessOrEqual(t, len(control.lastBalanceAdjustment.OperationID), 128)
	require.NotContains(t, control.lastBalanceAdjustment.OperationID, idempotencyKey)
	require.Empty(t, result.Header().Get("X-Idempotency-Replayed"))

	replay := callAdminUserMutation(t, handler, http.MethodPost, "/users/2001/balance", `{"balance":1.000001,"operation":"add","notes":"ledger note"}`, idempotencyKey)
	require.Equal(t, http.StatusOK, replay.Code, replay.Body.String())
	require.Equal(t, "true", replay.Header().Get("X-Idempotency-Replayed"))
}

func callAdminUserMutation(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body string,
	idempotencyKey string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestCloudflareAdminCreateUserUsesStableSemanticIdempotencyWithoutReturningSecrets(t *testing.T) {
	control := newAdminUserControlStub()
	handler := adminUserMutationRouter(control, 42)
	body := `{"email":"managed@example.test","password":"correct horse battery staple","username":"managed","notes":"safe","role":"user","balance":1.000001,"concurrency":1,"rpm_limit":0,"allowed_groups":[],"restrict_public_groups":false}`

	first := callAdminUserMutation(t, handler, http.MethodPost, "/users", body, "browser-user-create")
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.NotContains(t, first.Body.String(), "correct horse battery staple")
	require.NotContains(t, first.Body.String(), "password_hash")
	require.Equal(t, "1000001", control.lastBalanceMicroUSD)
	require.Len(t, control.lastSemanticToken, 64)
	require.True(t, strings.HasPrefix(control.lastOperation, "user-create:42:"))

	var firstEnvelope struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(first.Body.Bytes(), &firstEnvelope))
	require.Positive(t, firstEnvelope.Data.ID)

	replay := callAdminUserMutation(t, handler, http.MethodPost, "/users", body, "browser-user-create")
	require.Equal(t, http.StatusOK, replay.Code, replay.Body.String())
	var replayEnvelope struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(replay.Body.Bytes(), &replayEnvelope))
	require.Equal(t, firstEnvelope.Data.ID, replayEnvelope.Data.ID)
	require.Equal(t, 2, control.createCalls)

	changedPassword := strings.Replace(body, "correct horse battery staple", "different password value", 1)
	conflict := callAdminUserMutation(t, handler, http.MethodPost, "/users", changedPassword, "browser-user-create")
	require.Equal(t, http.StatusConflict, conflict.Code, conflict.Body.String())
	require.Contains(t, conflict.Body.String(), "IDEMPOTENCY_CONFLICT")
}

func TestCloudflareAdminUserMutationSecurityBoundaries(t *testing.T) {
	user := &service.User{
		ID: 2001, Email: "user@example.test", Username: "before", Notes: "notes",
		Status: service.StatusActive, Role: service.RoleUser, Balance: 9.5,
		Concurrency: 2, RPMLimit: 3, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	require.NoError(t, user.SetPassword("existing password"))
	admin := &service.User{
		ID: 2002, Email: "admin@example.test", Username: "admin", Status: service.StatusActive,
		Role: service.RoleAdmin, Concurrency: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	require.NoError(t, admin.SetPassword("admin password"))
	control := newAdminUserControlStub(user, admin)
	handler := adminUserMutationRouter(control, 99)

	adminCreate := callAdminUserMutation(t, handler, http.MethodPost, "/users", `{"email":"new-admin@example.test","password":"valid password","role":"admin","concurrency":1}`, "create-admin")
	require.Equal(t, http.StatusForbidden, adminCreate.Code)
	require.Zero(t, control.createCalls)

	balance := callAdminUserMutation(t, handler, http.MethodPut, "/users/2001", `{"balance":10}`, "")
	require.Equal(t, http.StatusBadRequest, balance.Code)
	require.Zero(t, control.updateCalls)

	roleChange := callAdminUserMutation(t, handler, http.MethodPut, "/users/2001", `{"role":"admin"}`, "")
	require.Equal(t, http.StatusForbidden, roleChange.Code)
	require.Zero(t, control.updateCalls)

	sameRole := callAdminUserMutation(t, handler, http.MethodPut, "/users/2001", `{"role":"user"}`, "")
	require.Equal(t, http.StatusOK, sameRole.Code, sameRole.Body.String())
	require.Zero(t, control.updateCalls)

	shortUnicodePassword := callAdminUserMutation(t, handler, http.MethodPut, "/users/2001", `{"password":"密码"}`, "")
	require.Equal(t, http.StatusBadRequest, shortUnicodePassword.Code)
	require.Zero(t, control.updateCalls)

	patch := callAdminUserMutation(t, handler, http.MethodPut, "/users/2001", `{"username":"after","password":"密码安全测试"}`, "")
	require.Equal(t, http.StatusOK, patch.Code, patch.Body.String())
	require.Equal(t, 1, control.updateCalls)
	require.Nil(t, control.lastUpdate.Email)
	require.NotNil(t, control.lastUpdate.Username)
	require.NotNil(t, control.lastUpdate.PasswordHash)
	require.NotEqual(t, "密码安全测试", *control.lastUpdate.PasswordHash)
	require.Equal(t, 9.5, control.users[2001].Balance)
	require.Equal(t, service.RoleUser, control.users[2001].Role)
	require.True(t, control.users[2001].CheckPassword("密码安全测试"))
	require.NotContains(t, patch.Body.String(), "password_hash")

	disableAdmin := callAdminUserMutation(t, handler, http.MethodPut, "/users/2002", `{"status":"disabled"}`, "")
	require.Equal(t, http.StatusForbidden, disableAdmin.Code)
	require.Equal(t, 1, control.updateCalls)
	deleteAdmin := callAdminUserMutation(t, handler, http.MethodDelete, "/users/2002", `{}`, "")
	require.Equal(t, http.StatusForbidden, deleteAdmin.Code)
	require.Zero(t, control.deleteCalls)
}

func TestCloudflareUserValidationUsesExactFixedPointAndUnicodeBoundaries(t *testing.T) {
	require.False(t, validCloudflarePassword("密码")) // two runes, despite six UTF-8 bytes
	require.True(t, validCloudflarePassword("密码安全测试"))
	require.False(t, validCloudflarePassword(strings.Repeat("a", 73)))
	require.True(t, validCloudflareEmail("ASCII.User+tag@Example.test"))
	require.False(t, validCloudflareEmail("用户@example.test"))

	for _, test := range []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: "0", want: "0", ok: true},
		{raw: "1.000001", want: "1000001", ok: true},
		{raw: "0.000001", want: "1", ok: true},
		{raw: "0.0000001", ok: false},
		{raw: "-1", ok: false},
		{raw: "9007199254.740991", want: "9007199254740991", ok: true},
		{raw: "9007199254.740992", ok: false},
	} {
		got, ok := microUSDFromJSON(json.RawMessage(test.raw))
		require.Equal(t, test.ok, ok, test.raw)
		require.Equal(t, test.want, got, test.raw)
	}
}

func TestCloudflareUserSemanticTokenIgnoresCandidateIDAndChangesWithPassword(t *testing.T) {
	base := &service.User{
		ID: 1, Email: "semantic@example.test", Username: "semantic", Notes: "",
		Status: service.StatusActive, Role: service.RoleUser, Balance: 1,
		Concurrency: 1, RPMLimit: 0, AllowedGroups: []int64{},
	}
	otherID := *base
	otherID.ID = 2
	first, err := cloudflareUserSemanticToken("user-create:7:key", base, "1000000", "same password")
	require.NoError(t, err)
	second, err := cloudflareUserSemanticToken("user-create:7:key", &otherID, "1000000", "same password")
	require.NoError(t, err)
	changed, err := cloudflareUserSemanticToken("user-create:7:key", base, "1000000", "changed password")
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.NotEqual(t, first, changed)
	require.Regexp(t, "^[0-9a-f]{64}$", first)
}

func managedUserTestWire(userID, username, balance, updatedAt string, passwordHash *string) map[string]any {
	user := map[string]any{
		"id": userID, "email": "wire@example.test", "username": username, "notes": "notes",
		"status": "active", "role": "user", "concurrency": 1, "rpm_limit": 0,
		"balance_microusd": balance, "allowed_group_ids": []string{},
		"restrict_public_groups": false, "created_at": "2026-09-07T00:00:00Z",
		"updated_at": updatedAt, "deleted_at": nil,
	}
	if passwordHash != nil {
		user["password_hash"] = *passwordHash
	}
	return user
}

func TestHTTPControlPlaneUserUpdateReturnsFreshReadbackWithoutLostFieldAssumptions(t *testing.T) {
	credential := &service.User{}
	require.NoError(t, credential.SetPassword("wire password"))
	var updateRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/manage/users/update":
			require.NoError(t, json.NewDecoder(request.Body).Decode(&updateRequest))
			require.NoError(t, json.NewEncoder(writer).Encode(map[string]any{
				"user": managedUserTestWire("7101", "after", "1000000", "2026-09-07T00:01:00Z", nil),
			}))
		case "/v1/manage/users/get":
			require.NoError(t, json.NewEncoder(writer).Encode(map[string]any{
				"user": managedUserTestWire("7101", "after", "9000000", "2026-09-07T00:02:00Z", nil),
			}))
		case "/v1/private/auth-users/get":
			auth := managedUserTestWire("7101", "after", "9000000", "2026-09-07T00:02:00Z", &credential.PasswordHash)
			delete(auth, "notes")
			delete(auth, "deleted_at")
			require.NoError(t, json.NewEncoder(writer).Encode(map[string]any{"user": auth}))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	username := "after"
	updated, err := control.UpdateManagedUser(context.Background(), "wire-user-update", 7101, ManagedUserUpdate{Username: &username})
	require.NoError(t, err)
	require.Equal(t, 9.0, updated.Balance)
	require.Equal(t, "after", updated.Username)
	require.True(t, updated.CheckPassword("wire password"))
	require.Equal(t, map[string]any{
		"operation_id": "wire-user-update",
		"id":           "7101",
		"username":     "after",
	}, updateRequest)
}

func TestHTTPControlPlaneUserCreateReplayVerifiesThePersistedCredential(t *testing.T) {
	const password = "replayed password"
	originalCredential := &service.User{}
	freshCredential := &service.User{}
	require.NoError(t, originalCredential.SetPassword(password))
	require.NoError(t, freshCredential.SetPassword(password))
	require.NotEqual(t, originalCredential.PasswordHash, freshCredential.PasswordHash)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/manage/users/create":
			require.NoError(t, json.NewEncoder(writer).Encode(map[string]any{
				"user":     managedUserTestWire("7201", "wire", "1000000", "2026-09-07T00:00:00Z", nil),
				"replayed": true,
			}))
		case "/v1/manage/users/get":
			require.NoError(t, json.NewEncoder(writer).Encode(map[string]any{
				"user": managedUserTestWire("7201", "wire", "1000000", "2026-09-07T00:00:00Z", nil),
			}))
		case "/v1/private/auth-users/get":
			auth := managedUserTestWire("7201", "wire", "1000000", "2026-09-07T00:00:00Z", &originalCredential.PasswordHash)
			delete(auth, "notes")
			delete(auth, "deleted_at")
			require.NoError(t, json.NewEncoder(writer).Encode(map[string]any{"user": auth}))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	candidate := &service.User{
		ID: 7202, Email: "wire@example.test", Username: "wire", Notes: "notes",
		Status: service.StatusActive, Role: service.RoleUser, Balance: 1,
		Concurrency: 1, AllowedGroups: []int64{},
	}
	created, replayed, err := control.CreateManagedUser(
		context.Background(), "wire-user-create", candidate, "1000000",
		freshCredential.PasswordHash, strings.Repeat("a", 64),
	)
	require.NoError(t, err)
	require.True(t, replayed)
	require.EqualValues(t, 7201, created.ID)
	require.Equal(t, originalCredential.PasswordHash, created.PasswordHash)
	require.True(t, created.CheckPassword(password))
}

func TestHTTPControlPlaneBalanceAdjustmentDecodesReplay(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/v1/manage/users/balance-adjust", request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(writer).Encode(map[string]any{
			"balance": map[string]any{
				"ledger_id":               "user-balance:9:wire",
				"balance_before_microusd": "1000000",
				"balance_after_microusd":  "2000000",
				"delta_microusd":          "1000000",
			},
			"replayed": true,
		}))
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	result, err := control.AdjustManagedUserBalance(context.Background(), ManagedBalanceAdjustment{
		OperationID: "user-balance:9:wire", ActorUserID: 9, TargetUserID: 10,
		Operation: "add", AmountMicroUSD: "1000000", Reason: "wire replay",
	})
	require.NoError(t, err)
	require.True(t, result.Replayed)
	require.Equal(t, "2000000", result.BalanceAfterMicroUSD)
}

var _ ControlPlane = (*adminUserControlStub)(nil)
var _ AdminListControlPlane = (*adminUserControlStub)(nil)
var _ AdminUserMutationControlPlane = (*adminUserControlStub)(nil)
