//go:build unit

package cloudflarebridge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestHTTPControlPlaneGetManagedUserUsesNonSecretDecimalContract(t *testing.T) {
	var requestBody string
	var requestPath string
	var version string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		version = r.Header.Get("X-Sub2API-Bridge-Version")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		requestBody = string(body)
		_, _ = io.WriteString(w, `{"user":{"id":"9007199254740993","email":"reader@example.test","username":"reader","notes":"safe","status":"active","role":"user","concurrency":3,"rpm_limit":9,"balance_e8_usd":"250000000","allowed_group_ids":["9007199254740994"],"restrict_public_groups":true,"created_at":"2026-09-06T01:02:03Z","updated_at":"2026-09-06T02:03:04Z","deleted_at":null}}`)
	}))
	defer server.Close()

	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	user, err := client.GetManagedUser(context.Background(), 9007199254740993)
	require.NoError(t, err)
	require.Equal(t, "/v1/manage/users/get", requestPath)
	require.JSONEq(t, `{"id":"9007199254740993"}`, requestBody)
	require.Equal(t, ProtocolVersion, version)
	require.Equal(t, int64(9007199254740993), user.ID)
	require.Equal(t, []int64{9007199254740994}, user.AllowedGroups)
	require.Equal(t, 2.5, user.Balance)
	require.Empty(t, user.PasswordHash)
	require.False(t, user.TokenVersionResolved)
	require.True(t, user.RestrictPublicGroups)
}

func TestDisplayBalanceFromE8USDConvertsOnlyAtThePresentationBoundary(t *testing.T) {
	require.Equal(t, 2.5, mustDisplayBalance(t, "250000000"))
	require.Equal(t, 0.00000001, mustDisplayBalance(t, "1"))
	require.Greater(t, mustDisplayBalance(t, maxPublicBalanceE8USDString), 9_000_000_000.0)
	for _, value := range []string{"", "01", "-1", "1.5", "10000000000000000000000000000000000000000"} {
		_, err := displayBalanceFromE8USD(value)
		require.Error(t, err, value)
	}
}

func TestHTTPControlPlaneManagedBalanceHistoryUsesNonSecretWireContract(t *testing.T) {
	var requestBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/v1/manage/users/balance-history", request.URL.Path)
		require.NoError(t, json.NewDecoder(request.Body).Decode(&requestBody))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"items":[{"id":"7","adjustment_type":"subtract","reason":"manual correction","delta_e8_usd":"-25000000","balance_before_e8_usd":"125000000","balance_after_e8_usd":"100000000","created_at":"2026-09-07T01:02:03Z"}],"total":"2","total_recharged_e8_usd":"125000000"}`)
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	history, err := control.GetManagedBalanceHistory(context.Background(), 9007199254740993, 2, 15, "admin_balance")
	require.NoError(t, err)
	require.Equal(t, map[string]any{"id": "9007199254740993", "page": float64(2), "page_size": float64(15), "type": "admin_balance"}, requestBody)
	require.Equal(t, int64(2), history.Total)
	require.Equal(t, "125000000", history.TotalRechargedE8USD)
	require.Len(t, history.Entries, 1)
	require.Equal(t, int64(7), history.Entries[0].ID)
	require.Equal(t, "-25000000", history.Entries[0].DeltaE8USD)
	require.Equal(t, "manual correction", history.Entries[0].Reason)
}

func TestHTTPControlPlaneManagedBalanceHistoryReasonUsesUTF16Limit(t *testing.T) {
	for _, test := range []struct {
		name    string
		reason  string
		wantErr bool
	}{
		{name: "maximum emoji reason", reason: strings.Repeat("😀", 2048)},
		{name: "oversized emoji reason", reason: strings.Repeat("😀", 2049), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				require.NoError(t, json.NewEncoder(writer).Encode(map[string]any{
					"items": []map[string]any{{
						"id": "7", "adjustment_type": "add", "reason": test.reason,
						"delta_e8_usd": "1", "balance_before_e8_usd": "0",
						"balance_after_e8_usd": "1", "created_at": "2026-09-07T01:02:03Z",
					}},
					"total": "1", "total_recharged_e8_usd": "1",
				}))
			}))
			defer server.Close()

			control, err := NewHTTPControlPlane(server.URL, server.Client())
			require.NoError(t, err)
			history, err := control.GetManagedBalanceHistory(context.Background(), 1, 1, 15, "admin_balance")
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.reason, history.Entries[0].Reason)
		})
	}
}

func mustDisplayBalance(t *testing.T, value string) float64 {
	t.Helper()
	balance, err := displayBalanceFromE8USD(value)
	require.NoError(t, err)
	return balance
}

func TestHTTPControlPlaneGetManagedUserTreatsTombstoneAsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"user":{"id":"41","email":"deleted@example.test","username":"","notes":"","status":"disabled","role":"user","concurrency":1,"rpm_limit":0,"balance_e8_usd":"0","allowed_group_ids":[],"restrict_public_groups":false,"created_at":"2026-09-06T01:02:03Z","updated_at":"2026-09-06T02:03:04Z","deleted_at":"2026-09-06T02:03:04Z"}}`)
	}))
	defer server.Close()
	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, err = client.GetManagedUser(context.Background(), 41)
	require.ErrorIs(t, err, service.ErrUserNotFound)
}

func TestHTTPControlPlaneListActiveManagedGroupsPaginatesAndFilters(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		switch calls.Add(1) {
		case 1:
			require.JSONEq(t, `{"cursor":"0","limit":100}`, string(body))
			_, _ = io.WriteString(w, `{"groups":[{"id":"9007199254740993","name":"active","platform":"openai","status":"active","is_exclusive":false,"subscription_type":"standard","created_at":"2026-09-06T01:02:03Z","updated_at":"2026-09-06T02:03:04Z","deleted_at":null},{"id":"9007199254740994","name":"disabled-subscription","platform":"openai","status":"disabled","is_exclusive":false,"subscription_type":"subscription","created_at":"2026-09-06T01:02:03Z","updated_at":"2026-09-06T02:03:04Z","deleted_at":null}],"next_cursor":"9007199254740994"}`)
		case 2:
			require.JSONEq(t, `{"cursor":"9007199254740994","limit":100}`, string(body))
			_, _ = io.WriteString(w, `{"groups":[{"id":"9007199254740995","name":"deleted","platform":"openai","status":"disabled","is_exclusive":false,"subscription_type":"standard","created_at":"2026-09-06T01:02:03Z","updated_at":"2026-09-06T02:03:04Z","deleted_at":"2026-09-06T02:03:04Z"}],"next_cursor":null}`)
		default:
			t.Fatal("unexpected extra page")
		}
	}))
	defer server.Close()

	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	groups, err := client.ListActiveManagedGroups(context.Background())
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Equal(t, int64(9007199254740993), groups[0].ID)
	require.Equal(t, float64(1), groups[0].RateMultiplier)
	require.True(t, groups[0].Hydrated)
	require.Equal(t, int32(2), calls.Load())
}

func TestHTTPControlPlaneManagedGroupFailsClosedOutsideCurrentSlice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"group":{"id":"42","name":"subscription","platform":"openai","status":"active","is_exclusive":false,"subscription_type":"subscription","created_at":"2026-09-06T01:02:03Z","updated_at":"2026-09-06T02:03:04Z","deleted_at":null}}`)
	}))
	defer server.Close()
	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, err = client.GetManagedGroup(context.Background(), 42)
	require.ErrorIs(t, err, ErrNotMigrated)
}

func TestHTTPControlPlaneManagedGroupListRejectsNonAdvancingCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"groups":[],"next_cursor":"0"}`)
	}))
	defer server.Close()
	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, err = client.ListActiveManagedGroups(context.Background())
	require.ErrorContains(t, err, "cursor did not advance")
}

func TestHTTPControlPlaneManagedGroupListRejectsMissingArray(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"next_cursor":null}`)
	}))
	defer server.Close()
	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, err = client.ListActiveManagedGroups(context.Background())
	require.ErrorContains(t, err, "groups array is required")
}

func TestHTTPControlPlaneManagedGroupListRejectsOutOfOrderRows(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"groups":[{"id":"42","name":"first","platform":"openai","status":"active","is_exclusive":false,"subscription_type":"standard","created_at":"2026-09-06T01:02:03Z","updated_at":"2026-09-06T02:03:04Z","deleted_at":null},{"id":"41","name":"second","platform":"openai","status":"active","is_exclusive":false,"subscription_type":"standard","created_at":"2026-09-06T01:02:03Z","updated_at":"2026-09-06T02:03:04Z","deleted_at":null}],"next_cursor":null}`)
	}))
	defer server.Close()
	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, err = client.ListActiveManagedGroups(context.Background())
	require.ErrorContains(t, err, "group order did not advance")
}

func TestHTTPControlPlaneManagedUserListFailsClosedOnMalformedPages(t *testing.T) {
	for _, body := range []string{
		"{\"next_cursor\":null}",
		"{\"users\":[],\"next_cursor\":\"0\"}",
		"{\"users\":[{\"id\":\"42\",\"email\":\"a@example.test\",\"username\":\"a\",\"notes\":\"\",\"status\":\"active\",\"role\":\"operator\",\"concurrency\":1,\"rpm_limit\":0,\"balance_e8_usd\":\"0\",\"allowed_group_ids\":[],\"restrict_public_groups\":false,\"created_at\":\"2026-09-06T01:02:03Z\",\"updated_at\":\"2026-09-06T02:03:04Z\",\"deleted_at\":null}],\"next_cursor\":null}",
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		}))
		client, err := NewHTTPControlPlane(server.URL, server.Client())
		require.NoError(t, err)
		_, err = client.ListManagedUsers(context.Background())
		require.Error(t, err, body)
		server.Close()
	}
}

func TestHTTPControlPlaneManagedUserListPaginatesAndSkipsTombstones(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		switch calls.Add(1) {
		case 1:
			require.JSONEq(t, `{"cursor":"0","limit":100}`, string(body))
			_, _ = io.WriteString(w, `{"users":[{"id":"42","email":"first@example.test","username":"first","notes":"","status":"active","role":"user","concurrency":1,"rpm_limit":0,"balance_e8_usd":"100000000","allowed_group_ids":[],"restrict_public_groups":false,"created_at":"2026-09-06T01:02:03Z","updated_at":"2026-09-06T02:03:04Z","deleted_at":null},{"id":"43","email":"deleted@example.test","username":"deleted","notes":"","status":"disabled","role":"user","concurrency":1,"rpm_limit":0,"balance_e8_usd":"0","allowed_group_ids":[],"restrict_public_groups":false,"created_at":"2026-09-06T01:02:03Z","updated_at":"2026-09-06T02:03:04Z","deleted_at":"2026-09-06T02:03:04Z"}],"next_cursor":"43"}`)
		case 2:
			require.JSONEq(t, `{"cursor":"43","limit":100}`, string(body))
			_, _ = io.WriteString(w, `{"users":[{"id":"9007199254740993","email":"second@example.test","username":"second","notes":"admin note","status":"active","role":"admin","concurrency":2,"rpm_limit":3,"balance_e8_usd":"250000000","allowed_group_ids":[],"restrict_public_groups":false,"created_at":"2026-09-06T01:02:03Z","updated_at":"2026-09-06T02:03:04Z","deleted_at":null}],"next_cursor":null}`)
		default:
			t.Fatal("unexpected extra page")
		}
	}))
	defer server.Close()

	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	users, err := client.ListManagedUsers(context.Background())
	require.NoError(t, err)
	require.Len(t, users, 2)
	require.Equal(t, int64(42), users[0].ID)
	require.Equal(t, int64(9007199254740993), users[1].ID)
	require.Equal(t, 2.5, users[1].Balance)
	require.Equal(t, int32(2), calls.Load())
}

func TestHTTPControlPlaneManagedAccountsPreserveUnsafeIDsAndSkipTombstones(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		switch calls.Add(1) {
		case 1:
			require.Equal(t, "/v1/manage/accounts/get", r.URL.Path)
			require.JSONEq(t, "{\"id\":\"9007199254741993\"}", string(body))
			_, _ = io.WriteString(w, "{\"account\":{\"id\":\"9007199254741993\",\"name\":\"safe\",\"platform\":\"openai\",\"type\":\"apikey\",\"status\":\"active\",\"schedulable\":true,\"priority\":2,\"max_concurrency\":3,\"extra\":{\"privacy_mode\":\"training_off\"},\"group_ids\":[\"9007199254741097\"],\"created_at\":\"2026-09-06T01:02:03Z\",\"updated_at\":\"2026-09-06T02:03:04Z\",\"deleted_at\":null}}")
		case 2:
			require.Equal(t, "/v1/manage/accounts/list", r.URL.Path)
			require.JSONEq(t, "{\"cursor\":\"0\",\"limit\":100}", string(body))
			_, _ = io.WriteString(w, "{\"accounts\":[{\"id\":\"41\",\"name\":\"deleted\",\"platform\":\"openai\",\"type\":\"apikey\",\"status\":\"disabled\",\"schedulable\":false,\"priority\":0,\"max_concurrency\":1,\"extra\":{},\"group_ids\":[],\"created_at\":\"2026-09-06T01:02:03Z\",\"updated_at\":\"2026-09-06T02:03:04Z\",\"deleted_at\":\"2026-09-06T02:03:04Z\"}],\"next_cursor\":\"41\"}")
		case 3:
			require.Equal(t, "/v1/manage/accounts/list", r.URL.Path)
			require.JSONEq(t, "{\"cursor\":\"41\",\"limit\":100}", string(body))
			_, _ = io.WriteString(w, "{\"accounts\":[{\"id\":\"9007199254741993\",\"name\":\"safe\",\"platform\":\"openai\",\"type\":\"apikey\",\"status\":\"active\",\"schedulable\":true,\"priority\":2,\"max_concurrency\":3,\"extra\":{\"privacy_mode\":\"training_off\"},\"group_ids\":[\"9007199254741097\"],\"created_at\":\"2026-09-06T01:02:03Z\",\"updated_at\":\"2026-09-06T02:03:04Z\",\"deleted_at\":null}],\"next_cursor\":null}")
		default:
			t.Fatal("unexpected control-plane call")
		}
	}))
	defer server.Close()

	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	account, err := client.GetManagedAccount(context.Background(), 9007199254741993)
	require.NoError(t, err)
	require.Equal(t, int64(9007199254741993), account.ID)
	require.Equal(t, []int64{9007199254741097}, account.GroupIDs)
	require.Equal(t, "training_off", account.Extra["privacy_mode"])
	accounts, err := client.ListManagedAccounts(context.Background())
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	require.Equal(t, int64(9007199254741993), accounts[0].ID)
	require.Equal(t, int32(3), calls.Load())
}

func TestHTTPControlPlaneManagedAccountRejectsMalformedPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "{\"accounts\":[{\"id\":\"42\",\"name\":\"bad\",\"platform\":\"openai\",\"type\":\"apikey\",\"status\":\"active\",\"schedulable\":true,\"priority\":0,\"max_concurrency\":1,\"extra\":{},\"group_ids\":[\"01\"],\"created_at\":\"2026-09-06T01:02:03Z\",\"updated_at\":\"2026-09-06T02:03:04Z\",\"deleted_at\":null}],\"next_cursor\":null}")
	}))
	defer server.Close()
	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, err = client.ListManagedAccounts(context.Background())
	require.ErrorContains(t, err, "account group id")
}

func TestManagedReadersFailClosedWithoutManagementCapability(t *testing.T) {
	control := &fakeControlPlane{}
	_, err := NewManagedUserReader(control).GetByID(context.Background(), 1)
	require.ErrorIs(t, err, ErrNotMigrated)
	_, err = NewManagedGroupReader(control).ListActive(context.Background())
	require.ErrorIs(t, err, ErrNotMigrated)
}
