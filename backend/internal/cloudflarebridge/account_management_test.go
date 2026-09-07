//go:build unit

package cloudflarebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestDecodeCloudflareAccountMutationRejectsUnsafeOrUnsupportedFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, body := range []string{
		`{"name":"account","platform":"openai","type":"apikey","concurrency":1,"credentials":{"api_key":"key","base_url":"https://example.test"},"extra":{"api_key":"secret"},"group_ids":["9007199254740993"]}`,
		`{"name":"account","platform":"openai","type":"oauth","concurrency":1,"credentials":{"api_key":"key","base_url":"https://example.test"},"group_ids":["9007199254740993"]}`,
		`{"name":"account","platform":"openai","type":"apikey","concurrency":1,"credentials":{"api_key":"key","base_url":"http://example.test"},"group_ids":["9007199254740993"]}`,
		`{"name":"account","platform":"openai","type":"apikey","concurrency":1,"credentials":{"api_key":"key","base_url":"https://example.test"},"group_ids":[9007199254740993]}`,
	} {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		_, ok := decodeCloudflareAccountMutation(ctx, true)
		require.False(t, ok, body)
	}
}

func TestDecodeCloudflareAccountMutationAcceptsLargeStringGroupID(t *testing.T) {
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"account","platform":"openai","type":"apikey","concurrency":2,"credentials":{"api_key":"key","base_url":"https://example.test"},"extra":{"privacy_mode":"training_off"},"group_ids":["9007199254740993"]}`))
	request, ok := decodeCloudflareAccountMutation(ctx, true)
	require.True(t, ok)
	require.Equal(t, int64(9007199254740993), (*request.GroupIDs)[0])
}

func TestManagedAccountNameUsesTheFrontendUTF16Limit(t *testing.T) {
	t.Parallel()
	wire := managedAccountWire{
		ID: "9007199254740994", Name: strings.Repeat("😀", 50),
		Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey,
		Status: service.StatusActive, Schedulable: true, MaxConcurrency: 1,
		Extra: map[string]any{}, GroupIDs: []string{"9007199254740993"},
		CreatedAt: "2026-09-07T00:00:00Z", UpdatedAt: "2026-09-07T00:00:00Z",
	}
	account, deleted, err := decodeManagedAccount(wire)
	require.NoError(t, err)
	require.False(t, deleted)
	require.Equal(t, wire.Name, account.Name)

	wire.Name = strings.Repeat("😀", 51)
	_, _, err = decodeManagedAccount(wire)
	require.ErrorContains(t, err, "invalid managed account response")
	wire.Name = " padded "
	_, _, err = decodeManagedAccount(wire)
	require.ErrorContains(t, err, "invalid managed account response")
}

type accountRouteControlPlane struct {
	*userAPIControlPlane
	createOperations map[string]int64
	createCalls      int
}

func copyManagedAccount(account *ManagedAccount) *ManagedAccount {
	if account == nil {
		return nil
	}
	copy := *account
	copy.Extra = make(map[string]any, len(account.Extra))
	for key, value := range account.Extra {
		copy.Extra[key] = value
	}
	copy.GroupIDs = append([]int64(nil), account.GroupIDs...)
	return &copy
}

func (f *accountRouteControlPlane) CreateManagedAccount(_ context.Context, operation string, account *ManagedAccount, _ map[string]string) (*ManagedAccount, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existingID, ok := f.createOperations[operation]; ok {
		return copyManagedAccount(f.accounts[existingID]), true, nil
	}
	f.createCalls++
	stored := copyManagedAccount(account)
	now := time.Now().UTC()
	stored.CreatedAt = now
	stored.UpdatedAt = now
	f.accounts[stored.ID] = stored
	f.createOperations[operation] = stored.ID
	return copyManagedAccount(stored), false, nil
}

func (f *accountRouteControlPlane) UpdateManagedAccount(_ context.Context, _ string, id int64, update ManagedAccountUpdate) (*ManagedAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	account := f.accounts[id]
	if account == nil || account.DeletedAt != nil {
		return nil, service.ErrAccountNotFound
	}
	if update.Name != nil {
		account.Name = *update.Name
	}
	if update.Status != nil {
		account.Status = accountStatusOr(update.Status, account.Status)
	}
	if update.Schedulable != nil {
		account.Schedulable = *update.Schedulable
	}
	if update.Priority != nil {
		account.Priority = *update.Priority
	}
	if update.MaxConcurrency != nil {
		account.MaxConcurrency = *update.MaxConcurrency
	}
	if update.Extra != nil {
		account.Extra = make(map[string]any, len(*update.Extra))
		for key, value := range *update.Extra {
			account.Extra[key] = value
		}
	}
	if update.GroupIDs != nil {
		account.GroupIDs = append([]int64(nil), (*update.GroupIDs)...)
	}
	account.UpdatedAt = time.Now().UTC()
	return copyManagedAccount(account), nil
}

func (f *accountRouteControlPlane) DeleteManagedAccount(_ context.Context, _ string, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	account := f.accounts[id]
	if account == nil {
		return service.ErrAccountNotFound
	}
	if account.DeletedAt == nil {
		now := time.Now().UTC()
		account.Status = service.StatusDisabled
		account.Schedulable = false
		account.UpdatedAt = now
		account.DeletedAt = &now
	}
	return nil
}

func callAccountJSON(t *testing.T, client http.Handler, method, path, token, idempotencyKey, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	recorder := httptest.NewRecorder()
	client.ServeHTTP(recorder, req)
	return recorder
}

func TestCloudflareAdminAccountMutationRoutesRequireAdminAndNeverDiscloseSecrets(t *testing.T) {
	base, password, userID, _ := newUserAPIControlPlane(t)
	base.mu.Lock()
	base.users[userID].Role = service.RoleAdmin
	base.mu.Unlock()
	control := &accountRouteControlPlane{
		userAPIControlPlane: base,
		createOperations:    map[string]int64{},
	}
	handler, err := NewHandler(testRuntimeConfig(t), control, &fakeHTTPUpstream{})
	require.NoError(t, err)
	token := loginToken(t, handler, "user@example.test", password)
	groupID := int64(9007199254741097)
	createBody := `{"name":"route account","platform":"openai","type":"apikey","status":"active","schedulable":true,"priority":4,"concurrency":2,"credentials":{"api_key":"route-upstream-secret","base_url":"https://mock.upstream"},"extra":{"privacy_mode":"training_off"},"group_ids":["9007199254741097"]}`

	unauthenticated := callAccountJSON(t, handler, http.MethodPost, "/api/v1/admin/accounts", "", "route-create", createBody)
	require.Equal(t, http.StatusUnauthorized, unauthenticated.Code, unauthenticated.Body.String())
	created := callAccountJSON(t, handler, http.MethodPost, "/api/v1/admin/accounts", token, "route-create", createBody)
	require.Equal(t, http.StatusOK, created.Code, created.Body.String())
	require.NotContains(t, created.Body.String(), "route-upstream-secret")
	require.NotContains(t, created.Body.String(), "mock.upstream")
	require.NotContains(t, created.Body.String(), "credentials")
	var createEnvelope struct {
		Data struct {
			ID       cloudflareRequestID   `json:"id"`
			GroupIDs []cloudflareRequestID `json:"group_ids"`
			Extra    map[string]any        `json:"extra"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &createEnvelope))
	require.Greater(t, int64(createEnvelope.Data.ID), int64(0))
	require.Equal(t, []cloudflareRequestID{cloudflareRequestID(groupID)}, createEnvelope.Data.GroupIDs)
	require.Equal(t, map[string]any{"privacy_mode": "training_off"}, createEnvelope.Data.Extra)

	replayed := callAccountJSON(t, handler, http.MethodPost, "/api/v1/admin/accounts", token, "route-create", createBody)
	require.Equal(t, http.StatusOK, replayed.Code, replayed.Body.String())
	var replayEnvelope struct {
		Data struct {
			ID cloudflareRequestID `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(replayed.Body.Bytes(), &replayEnvelope))
	require.Equal(t, createEnvelope.Data.ID, replayEnvelope.Data.ID)
	require.Equal(t, 1, control.createCalls)

	createdID := strconv.FormatInt(int64(createEnvelope.Data.ID), 10)
	path := "/api/v1/admin/accounts/" + createdID
	updated := callAccountJSON(t, handler, http.MethodPut, path, token, "", `{"name":"updated route account","status":"inactive","schedulable":false,"priority":8,"max_concurrency":3,"credentials":{"api_key":"replacement-secret","base_url":"https://mock.upstream"},"extra":{},"group_ids":["9007199254741097"]}`)
	require.Equal(t, http.StatusOK, updated.Code, updated.Body.String())
	require.NotContains(t, updated.Body.String(), "replacement-secret")
	require.NotContains(t, updated.Body.String(), "mock.upstream")
	require.NotContains(t, updated.Body.String(), "credentials")
	require.Contains(t, updated.Body.String(), `"status":"inactive"`)

	deleted := callAccountJSON(t, handler, http.MethodDelete, path, token, "", "")
	require.Equal(t, http.StatusOK, deleted.Code, deleted.Body.String())
	require.NotContains(t, deleted.Body.String(), "secret")
	accountID := int64(createEnvelope.Data.ID)
	control.mu.Lock()
	stored := copyManagedAccount(control.accounts[accountID])
	control.mu.Unlock()
	require.NotNil(t, stored.DeletedAt)
	require.Equal(t, service.StatusDisabled, stored.Status)
	require.False(t, stored.Schedulable)
}

func managedAccountResponse(id string, extra map[string]any, deleted bool) map[string]any {
	status := service.StatusActive
	schedulable := true
	var deletedAt any
	if deleted {
		status = service.StatusDisabled
		schedulable = false
		deletedAt = "2026-09-07T02:00:00Z"
	}
	return map[string]any{
		"id": id, "name": "bridge account", "platform": service.PlatformOpenAI,
		"type": service.AccountTypeAPIKey, "status": status, "schedulable": schedulable,
		"priority": 7, "max_concurrency": 3, "extra": extra,
		"group_ids":  []string{"9007199254740993"},
		"created_at": "2026-09-07T00:00:00Z", "updated_at": "2026-09-07T01:00:00Z",
		"deleted_at": deletedAt,
	}
}

func writeAccountTestJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	require.NoError(t, json.NewEncoder(w).Encode(value))
}

func TestHTTPControlPlaneAccountCreateRetriesOneAmbiguousFailureWithStableOperationID(t *testing.T) {
	t.Parallel()
	const candidateID int64 = 9007199254740994
	var createCalls atomic.Int32
	var firstOperation string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		switch r.URL.Path {
		case "/v1/manage/accounts/create":
			operation, _ := body["operation_id"].(string)
			if createCalls.Add(1) == 1 {
				firstOperation = operation
				writeAccountTestJSON(t, w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{"code": "CONTROL_PLANE_UNAVAILABLE"}})
				return
			}
			require.Equal(t, firstOperation, operation)
			require.Equal(t, strconv.FormatInt(candidateID, 10), body["id"])
			writeAccountTestJSON(t, w, http.StatusOK, map[string]any{"account": managedAccountResponse(body["id"].(string), map[string]any{"privacy_mode": "training_off"}, false), "replayed": true})
		case "/v1/manage/accounts/get":
			writeAccountTestJSON(t, w, http.StatusOK, map[string]any{"account": managedAccountResponse(body["id"].(string), map[string]any{"privacy_mode": "training_off"}, false)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	account := &ManagedAccount{ID: candidateID, Name: "bridge account", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true, Priority: 7, MaxConcurrency: 3, Extra: map[string]any{"privacy_mode": "training_off"}, GroupIDs: []int64{9007199254740993}}
	created, replayed, err := control.CreateManagedAccount(context.Background(), "stable-account-operation", account, map[string]string{"api_key": "private-secret", "base_url": "https://mock.upstream"})
	require.NoError(t, err)
	require.True(t, replayed)
	require.Equal(t, candidateID, created.ID)
	require.Equal(t, int32(2), createCalls.Load())
	require.Equal(t, "stable-account-operation", firstOperation)
}

func TestHTTPControlPlaneAccountCreateAcceptsSemanticReplayWithRegeneratedLargeID(t *testing.T) {
	t.Parallel()
	const originalID int64 = 9007199254740994
	const regeneratedID int64 = 9007199254740995
	var createIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		switch r.URL.Path {
		case "/v1/manage/accounts/create":
			createIDs = append(createIDs, body["id"].(string))
			replayed := len(createIDs) > 1
			response := managedAccountResponse(strconv.FormatInt(originalID, 10), map[string]any{"privacy_mode": "training_off"}, false)
			response["group_ids"] = []string{"9007199254740996", "9007199254740993"}
			writeAccountTestJSON(t, w, http.StatusOK, map[string]any{"account": response, "replayed": replayed})
		case "/v1/manage/accounts/get":
			require.Equal(t, strconv.FormatInt(originalID, 10), body["id"])
			response := managedAccountResponse(strconv.FormatInt(originalID, 10), map[string]any{"privacy_mode": "training_off"}, false)
			response["group_ids"] = []string{"9007199254740993", "9007199254740996"}
			writeAccountTestJSON(t, w, http.StatusOK, map[string]any{"account": response})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	makeAccount := func(id int64) *ManagedAccount {
		return &ManagedAccount{ID: id, Name: "bridge account", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true, Priority: 7, MaxConcurrency: 3, Extra: map[string]any{"privacy_mode": "training_off"}, GroupIDs: []int64{9007199254740993, 9007199254740996}}
	}
	credentials := map[string]string{"api_key": "private-secret", "base_url": "https://mock.upstream"}
	first, firstReplay, err := control.CreateManagedAccount(context.Background(), "browser-account-operation", makeAccount(originalID), credentials)
	require.NoError(t, err)
	require.False(t, firstReplay)
	require.Equal(t, originalID, first.ID)
	second, secondReplay, err := control.CreateManagedAccount(context.Background(), "browser-account-operation", makeAccount(regeneratedID), credentials)
	require.NoError(t, err)
	require.True(t, secondReplay)
	require.Equal(t, originalID, second.ID)
	require.Equal(t, []string{strconv.FormatInt(originalID, 10), strconv.FormatInt(regeneratedID, 10)}, createIDs)
}

func TestHTTPControlPlaneAccountCreateRejectsCredentialLeaksAndReadbackMismatch(t *testing.T) {
	t.Parallel()
	const accountID int64 = 9007199254740994
	account := &ManagedAccount{ID: accountID, Name: "bridge account", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true, Priority: 7, MaxConcurrency: 3, Extra: map[string]any{"privacy_mode": "training_off"}, GroupIDs: []int64{9007199254740993}}
	credentials := map[string]string{"api_key": "private-secret", "base_url": "https://mock.upstream"}

	for name, mutate := range map[string]func(map[string]any){
		"top-level credentials": func(response map[string]any) { response["credentials"] = map[string]string{} },
		"top-level envelope":    func(response map[string]any) { response["credential_envelope"] = "aes-gcm:v1:bad" },
		"nested raw api key": func(response map[string]any) {
			response["account"].(map[string]any)["api_key"] = "leaked"
		},
		"nested envelope": func(response map[string]any) {
			response["account"].(map[string]any)["credential_envelope"] = "aes-gcm:v1:bad"
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				response := map[string]any{"account": managedAccountResponse(strconv.FormatInt(accountID, 10), map[string]any{"privacy_mode": "training_off"}, false), "replayed": false}
				mutate(response)
				writeAccountTestJSON(t, w, http.StatusOK, response)
			}))
			defer server.Close()
			control, err := NewHTTPControlPlane(server.URL, server.Client())
			require.NoError(t, err)
			_, _, err = control.CreateManagedAccount(context.Background(), "leak-check", account, credentials)
			require.ErrorContains(t, err, "unexpected credential")
			require.NotContains(t, err.Error(), "private-secret")
		})
	}

	t.Run("safe extra readback mismatch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			responseExtra := map[string]any{"privacy_mode": "training_off"}
			if r.URL.Path == "/v1/manage/accounts/get" {
				responseExtra = map[string]any{}
			}
			writeAccountTestJSON(t, w, http.StatusOK, map[string]any{"account": managedAccountResponse(strconv.FormatInt(accountID, 10), responseExtra, false), "replayed": false})
		}))
		defer server.Close()
		control, err := NewHTTPControlPlane(server.URL, server.Client())
		require.NoError(t, err)
		_, _, err = control.CreateManagedAccount(context.Background(), "readback-check", account, credentials)
		require.ErrorContains(t, err, "invalid account create readback")
	})
}

func TestHTTPControlPlaneAccountMutationErrorMappingAndDeleteTombstoneValidation(t *testing.T) {
	t.Parallel()
	t.Run("idempotency conflict", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeAccountTestJSON(t, w, http.StatusConflict, map[string]any{"error": map[string]any{"code": "IDEMPOTENCY_CONFLICT"}})
		}))
		defer server.Close()
		control, err := NewHTTPControlPlane(server.URL, server.Client())
		require.NoError(t, err)
		account := &ManagedAccount{ID: 9007199254740994, Name: "bridge account", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true, Priority: 7, MaxConcurrency: 3, Extra: map[string]any{}, GroupIDs: []int64{9007199254740993}}
		_, _, err = control.CreateManagedAccount(context.Background(), "conflict", account, map[string]string{"api_key": "secret", "base_url": "https://mock.upstream"})
		require.True(t, infraerrors.IsConflict(err))
	})

	for name, mutate := range map[string]func(map[string]any){
		"valid":             func(map[string]any) {},
		"not deleted":       func(account map[string]any) { account["deleted_at"] = nil },
		"still active":      func(account map[string]any) { account["status"] = service.StatusActive },
		"still schedulable": func(account map[string]any) { account["schedulable"] = true },
		"wrong identity":    func(account map[string]any) { account["id"] = "9007199254740995" },
	} {
		t.Run("delete "+name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				account := managedAccountResponse("9007199254740994", map[string]any{}, true)
				mutate(account)
				writeAccountTestJSON(t, w, http.StatusOK, map[string]any{"account": account, "replayed": false})
			}))
			defer server.Close()
			control, err := NewHTTPControlPlane(server.URL, server.Client())
			require.NoError(t, err)
			err = control.DeleteManagedAccount(context.Background(), "delete-check", 9007199254740994)
			if name == "valid" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "invalid account delete response")
			}
		})
	}
}
