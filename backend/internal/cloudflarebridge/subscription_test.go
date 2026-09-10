//go:build unit

package cloudflarebridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

const subscriptionFixture = `{"id":"9007199254740993","user_id":"9007199254740994","group_id":"9007199254740995","plan_id":null,"starts_at":"2026-01-01T00:00:00.000Z","expires_at":"2030-01-01T00:00:00.000Z","status":"active","initial_daily_boundary":null,"daily_window_start":"2026-01-01T00:00:00.000Z","weekly_window_start":"2026-01-01T00:00:00.000Z","monthly_window_start":"2026-01-01T00:00:00.000Z","weekly_anchor_kind":"activation","monthly_anchor_kind":"activation","daily_limit_e8_usd":"0","weekly_limit_e8_usd":null,"monthly_limit_e8_usd":"9223372036854775807","daily_usage_e8_usd":"0","weekly_usage_e8_usd":"1","monthly_usage_e8_usd":"9007199254740991","assigned_by":"9007199254740996","assigned_at":"2026-01-01T00:00:00.000Z","notes":"fixture","version":7,"created_at":"2026-01-01T00:00:00.000Z","updated_at":"2026-01-01T00:00:00.000Z","deleted_at":null}`

func subscriptionNow() time.Time { return time.Date(2026, 9, 11, 1, 2, 3, 0, time.UTC) }

func TestHTTPControlPlaneSubscriptionPrivateRoutesUseExactBodies(t *testing.T) {
	now := subscriptionNow()
	type routeCall struct {
		path     string
		invoke   func(*HTTPControlPlane) error
		required []string
	}
	user, group, actor := "9007199254740994", "9007199254740995", "9007199254740996"
	expectedOperations := map[string]string{
		"/v1/subscriptions/assign-or-extend": "assign:1",
		"/v1/subscriptions/revoke":           "revoke:1",
		"/v1/subscriptions/restore":          "restore:1",
		"/v1/subscriptions/extend":           "extend:1",
		"/v1/subscriptions/windows/activate": "activate:1",
		"/v1/subscriptions/windows/maintain": "maintain:1",
		"/v1/subscriptions/windows/reset":    "reset:1",
		"/v1/subscriptions/usage/reserve":    "reserve:1",
		"/v1/subscriptions/expiry/sweep":     "sweep:1",
	}
	routes := []routeCall{
		{"/v1/subscriptions/get", func(c *HTTPControlPlane) error {
			_, e := c.GetSubscription(context.Background(), SubscriptionGetRequest{ID: "9007199254740993", IncludeDeleted: false})
			return e
		}, []string{"id", "include_deleted"}},
		{"/v1/subscriptions/list", func(c *HTTPControlPlane) error {
			_, e := c.ListSubscriptions(context.Background(), SubscriptionListRequest{UserID: &user, GroupID: &group, IncludeDeleted: false, Limit: 1})
			return e
		}, []string{"user_id", "group_id", "status", "include_deleted", "after_id", "limit"}},
		{"/v1/subscriptions/assign-or-extend", func(c *HTTPControlPlane) error {
			_, e := c.AssignOrExtendSubscription(context.Background(), SubscriptionAssignOrExtendRequest{OperationID: "assign:1", NewSubscriptionID: "9007199254740993", UserID: user, GroupID: group, AssignedBy: &actor, ValidityDays: 30, Now: now, DailyBoundary: now})
			return e
		}, []string{"operation_id", "new_subscription_id", "user_id", "group_id", "plan_id", "validity_days", "assigned_by", "notes", "now", "daily_boundary"}},
		{"/v1/subscriptions/revoke", func(c *HTTPControlPlane) error {
			_, e := c.RevokeSubscription(context.Background(), SubscriptionRevokeRequest{OperationID: "revoke:1", SubscriptionID: "9007199254740993", ExpectedVersion: 7, ActorUserID: "9007199254740996", At: now})
			return e
		}, []string{"operation_id", "subscription_id", "expected_version", "actor_user_id", "at"}},
		{"/v1/subscriptions/restore", func(c *HTTPControlPlane) error {
			_, e := c.RestoreSubscription(context.Background(), SubscriptionRestoreRequest{OperationID: "restore:1", SubscriptionID: "9007199254740993", ExpectedVersion: 7, ActorUserID: "9007199254740996", Now: now})
			return e
		}, []string{"operation_id", "subscription_id", "expected_version", "actor_user_id", "now"}},
		{"/v1/subscriptions/extend", func(c *HTTPControlPlane) error {
			_, e := c.ExtendSubscription(context.Background(), SubscriptionExtendRequest{OperationID: "extend:1", SubscriptionID: "9007199254740993", ExpectedVersion: 7, Days: 1, ActorUserID: "9007199254740996", Now: now})
			return e
		}, []string{"operation_id", "subscription_id", "expected_version", "days", "actor_user_id", "now"}},
		{"/v1/subscriptions/windows/activate", func(c *HTTPControlPlane) error {
			_, e := c.ActivateSubscriptionWindows(context.Background(), SubscriptionActivateWindowsRequest{OperationID: "activate:1", SubscriptionID: "9007199254740993", ExpectedVersion: 7, ActivatedAt: now, DailyBoundary: now})
			return e
		}, []string{"operation_id", "subscription_id", "expected_version", "activated_at", "daily_boundary"}},
		{"/v1/subscriptions/windows/maintain", func(c *HTTPControlPlane) error {
			_, e := c.MaintainSubscriptionWindows(context.Background(), SubscriptionMaintainWindowsRequest{OperationID: "maintain:1", SubscriptionID: "9007199254740993", ExpectedVersion: 7, Now: now, DailyBoundary: now})
			return e
		}, []string{"operation_id", "subscription_id", "expected_version", "now", "daily_boundary"}},
		{"/v1/subscriptions/windows/reset", func(c *HTTPControlPlane) error {
			_, e := c.ResetSubscriptionWindows(context.Background(), SubscriptionResetWindowsRequest{OperationID: "reset:1", SubscriptionID: "9007199254740993", ExpectedVersion: 7, ResetDaily: true, ActorUserID: "9007199254740996", ResetAt: now, DailyBoundary: now})
			return e
		}, []string{"operation_id", "subscription_id", "expected_version", "reset_daily", "reset_weekly", "reset_monthly", "reset_at", "daily_boundary", "actor_user_id"}},
		{"/v1/subscriptions/usage/reserve", func(c *HTTPControlPlane) error {
			_, e := c.ReserveSubscriptionUsage(context.Background(), SubscriptionReserveUsageRequest{OperationID: "reserve:1", SubscriptionID: "9007199254740993", ExpectedVersion: 7, AmountE8USD: "0", At: now})
			return e
		}, []string{"operation_id", "subscription_id", "expected_version", "amount_e8_usd", "at"}},
		{"/v1/subscriptions/expiry/sweep", func(c *HTTPControlPlane) error {
			_, e := c.SweepExpiredSubscriptions(context.Background(), SubscriptionSweepExpiredRequest{OperationID: "sweep:1", Cutoff: now, Limit: 1})
			return e
		}, []string{"operation_id", "cutoff", "after_id", "limit"}},
	}
	for _, test := range routes {
		t.Run(test.path, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodPost, r.Method)
				require.Equal(t, test.path, r.URL.Path)
				require.Equal(t, ProtocolVersion, r.Header.Get("X-Sub2API-Bridge-Version"))
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				var fields map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(body, &fields))
				require.Len(t, fields, len(test.required))
				for _, key := range test.required {
					require.Contains(t, fields, key)
				}
				if operation, ok := fields["operation_id"]; ok {
					var value string
					require.NoError(t, json.Unmarshal(operation, &value))
					require.Equal(t, expectedOperations[test.path], value)
				}
				if version, ok := fields["expected_version"]; ok {
					require.JSONEq(t, `7`, string(version))
				}
				if actor, ok := fields["actor_user_id"]; ok {
					require.JSONEq(t, `"9007199254740996"`, string(actor))
				}
				if assignedBy, ok := fields["assigned_by"]; ok {
					require.JSONEq(t, `"9007199254740996"`, string(assignedBy))
				}
				responseFixture := subscriptionFixture
				if _, ok := fields["expected_version"]; ok {
					responseFixture = strings.Replace(subscriptionFixture, `"version":7`, `"version":8`, 1)
				}
				if test.path == "/v1/subscriptions/revoke" {
					responseFixture = strings.Replace(responseFixture, `"deleted_at":null`, `"deleted_at":"2026-09-11T01:02:03.000Z"`, 1)
				}
				if test.path == "/v1/subscriptions/windows/activate" {
					responseFixture = strings.ReplaceAll(responseFixture, `"2026-01-01T00:00:00.000Z"`, `"2026-09-11T01:02:03.000Z"`)
				}
				if test.path == "/v1/subscriptions/windows/reset" {
					responseFixture = strings.Replace(responseFixture, `"daily_window_start":"2026-01-01T00:00:00.000Z"`, `"daily_window_start":"2026-09-11T01:02:03.000Z"`, 1)
				}
				if test.path == "/v1/subscriptions/list" {
					_, _ = io.WriteString(w, `{"items":[`+responseFixture+`],"next_after_id":null}`)
				} else if test.path == "/v1/subscriptions/expiry/sweep" {
					_, _ = io.WriteString(w, `{"expired_ids":[],"count":0}`)
				} else if test.path == "/v1/subscriptions/assign-or-extend" {
					_, _ = io.WriteString(w, `{"subscription":`+responseFixture+`,"extended":false}`)
				} else {
					_, _ = io.WriteString(w, `{"subscription":`+responseFixture+`}`)
				}
			}))
			defer server.Close()
			client, err := NewHTTPControlPlane(server.URL, server.Client())
			require.NoError(t, err)
			require.NoError(t, test.invoke(client))
		})
	}
}

func TestSubscriptionMutationReplayRetainsStableOperationIDAndBody(t *testing.T) {
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		bodies = append(bodies, string(body))
		responseFixture := strings.Replace(subscriptionFixture, `"version":7`, `"version":8`, 1)
		responseFixture = strings.Replace(responseFixture, `"deleted_at":null`, `"deleted_at":"2026-09-11T01:02:03.000Z"`, 1)
		_, _ = io.WriteString(w, `{"subscription":`+responseFixture+`}`)
	}))
	defer server.Close()
	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	request := SubscriptionRevokeRequest{OperationID: "revoke:replay", SubscriptionID: "9007199254740993", ExpectedVersion: 7, ActorUserID: "9007199254740996", At: subscriptionNow()}
	_, err = client.RevokeSubscription(context.Background(), request)
	require.NoError(t, err)
	_, err = client.RevokeSubscription(context.Background(), request)
	require.NoError(t, err)
	require.Len(t, bodies, 2)
	require.JSONEq(t, bodies[0], bodies[1])
}

func TestSubscriptionMutationRejectsMismatchedVersionAndState(t *testing.T) {
	validDeleted := strings.Replace(subscriptionFixture, `"deleted_at":null`, `"deleted_at":"2026-09-11T01:02:03.000Z"`, 1)
	validVersion := strings.Replace(subscriptionFixture, `"version":7`, `"version":8`, 1)
	for name, responseFixture := range map[string]string{
		"version": validDeleted,
		"state":   validVersion,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"subscription":`+responseFixture+`}`)
			}))
			defer server.Close()
			client, err := NewHTTPControlPlane(server.URL, server.Client())
			require.NoError(t, err)
			_, err = client.RevokeSubscription(context.Background(), SubscriptionRevokeRequest{
				OperationID:     "revoke:invalid-response",
				SubscriptionID:  "9007199254740993",
				ExpectedVersion: 7,
				ActorUserID:     "9007199254740996",
				At:              subscriptionNow(),
			})
			require.ErrorIs(t, err, ErrSubscriptionUnavailable)
		})
	}
}

func TestSubscriptionWireDecimalAndStrictDecoding(t *testing.T) {
	for _, raw := range []string{"", "00", "01", "+1", "-1", "1.0", "9223372036854775808"} {
		require.False(t, validSubscriptionE8(raw), raw)
	}
	for _, raw := range []string{"0", "1", "9007199254740993", "9223372036854775807"} {
		require.True(t, validSubscriptionE8(raw), raw)
	}
	for _, raw := range []string{"0", "01", "9223372036854775808"} {
		require.False(t, validSubscriptionID(raw), raw)
	}
	for _, raw := range []string{"1", "9007199254740993", "9223372036854775807"} {
		require.True(t, validSubscriptionID(raw), raw)
	}
	subscription, err := decodeSubscription(json.RawMessage(subscriptionFixture))
	require.NoError(t, err)
	require.NotNil(t, subscription.DailyLimitE8USD)
	require.Equal(t, "0", *subscription.DailyLimitE8USD)
	require.Nil(t, subscription.WeeklyLimitE8USD)
	require.Equal(t, "9223372036854775807", *subscription.MonthlyLimitE8USD)
	for name, replacement := range map[string]string{
		"unknown field":  `"notes":"fixture","unexpected":true`,
		"null usage":     `"daily_usage_e8_usd":null`,
		"leading zero":   `"daily_usage_e8_usd":"01"`,
		"money overflow": `"daily_usage_e8_usd":"9223372036854775808"`,
	} {
		t.Run(name, func(t *testing.T) {
			field := `"notes":"fixture"`
			if strings.Contains(replacement, "daily_usage_e8_usd") {
				field = `"daily_usage_e8_usd":"0"`
			}
			bad := strings.Replace(subscriptionFixture, field, replacement, 1)
			_, err := decodeSubscription(json.RawMessage(bad))
			require.Error(t, err)
		})
	}
}

func TestSubscriptionTimestampsMatchWorkerUTCNormalization(t *testing.T) {
	for _, value := range []string{"2026-09-11T01:02:03Z", "2026-09-11T01:02:03.1Z", "2026-09-11T01:02:03.12Z", "2026-09-11T01:02:03.123Z"} {
		_, err := rawTime(map[string]json.RawMessage{"at": json.RawMessage(strconv.Quote(value))}, "at")
		require.NoError(t, err, value)
	}
	for _, value := range []string{"2026-09-11T01:02:03.1234Z", "2026-09-11T01:02:03+00:00", "2100-01-01T00:00:00Z"} {
		_, err := rawTime(map[string]json.RawMessage{"at": json.RawMessage(strconv.Quote(value))}, "at")
		require.Error(t, err, value)
	}
}

func TestSubscriptionResponseErrorsRemainTypedAndRedacted(t *testing.T) {
	for _, test := range []struct {
		status int
		code   string
		want   error
	}{{400, "INVALID_INPUT", ErrSubscriptionValidation}, {404, "SUBSCRIPTION_NOT_FOUND", ErrSubscriptionNotFound}, {409, "STALE_VERSION", ErrSubscriptionStaleVersion}, {409, "IDEMPOTENCY_CONFLICT", ErrSubscriptionIdempotencyConflict}, {503, "SUBSCRIPTION_UNAVAILABLE", ErrSubscriptionUnavailable}} {
		t.Run(test.code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, `{"error":{"code":"`+test.code+`","message":"D1 SQL secret"}}`)
			}))
			defer server.Close()
			client, err := NewHTTPControlPlane(server.URL, server.Client())
			require.NoError(t, err)
			_, err = client.GetSubscription(context.Background(), SubscriptionGetRequest{ID: "9007199254740993"})
			require.ErrorIs(t, err, test.want)
			if test.status == http.StatusConflict {
				require.ErrorIs(t, err, ErrSubscriptionConflict)
			}
			if test.want == ErrSubscriptionStaleVersion {
				require.NotErrorIs(t, err, ErrSubscriptionIdempotencyConflict)
			}
			if test.want == ErrSubscriptionIdempotencyConflict {
				require.NotErrorIs(t, err, ErrSubscriptionStaleVersion)
			}
			require.NotContains(t, err.Error(), "D1 SQL")
		})
	}
}

func TestHTTPControlPlaneSubscriptionListEncodesOptionalFiltersAsExplicitNull(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var fields map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(body, &fields))
		for _, field := range []string{"user_id", "group_id", "status", "after_id"} {
			require.Contains(t, fields, field)
			require.Equal(t, "null", string(fields[field]))
		}
		_, _ = io.WriteString(w, `{"items":[],"next_after_id":null}`)
	}))
	defer server.Close()
	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	page, err := client.ListSubscriptions(context.Background(), SubscriptionListRequest{Limit: 100})
	require.NoError(t, err)
	require.Empty(t, page.Items)
}

func TestHTTPControlPlaneSubscriptionRejectsMalformedTrailingDuplicateAndUnknownResponses(t *testing.T) {
	responses := map[string]string{
		"malformed":        `{"subscription":`,
		"trailing":         `{"subscription":` + subscriptionFixture + `} {}`,
		"duplicate":        `{"subscription":` + subscriptionFixture + `,"subscription":` + subscriptionFixture + `}`,
		"unknown envelope": `{"subscription":` + subscriptionFixture + `,"private_sql":"secret"}`,
		"unknown record":   `{"subscription":` + strings.Replace(subscriptionFixture, `"notes":"fixture"`, `"notes":"fixture","unknown":true`, 1) + `}`,
	}
	for name, responseBody := range responses {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, responseBody)
			}))
			defer server.Close()
			client, err := NewHTTPControlPlane(server.URL, server.Client())
			require.NoError(t, err)
			_, err = client.GetSubscription(context.Background(), SubscriptionGetRequest{ID: "9007199254740993"})
			require.ErrorIs(t, err, ErrSubscriptionUnavailable)
			require.NotContains(t, err.Error(), "private_sql")
			require.NotContains(t, err.Error(), "secret")
		})
	}
}

func TestSubscriptionResponseNotesUseStrictTextContract(t *testing.T) {
	require.True(t, validAssignmentNotes(strings.Repeat("a", 4096)))
	for _, notes := range []string{strings.Repeat("a", 4097), "line\nbreak", "\u202e", "\ufeff", string([]byte{0xff})} {
		require.False(t, validAssignmentNotes(notes))
	}
	for name, encodedNotes := range map[string]string{
		"control":  `"line\nbreak"`,
		"bidi":     `"\u202e"`,
		"bom":      `"\ufeff"`,
		"oversize": `"` + strings.Repeat("a", 4097) + `"`,
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(subscriptionFixture, `"notes":"fixture"`, `"notes":`+encodedNotes, 1)
			_, err := decodeSubscription(json.RawMessage(body))
			require.Error(t, err)
		})
	}
}

type subscriptionReaderControl struct {
	pages    []*SubscriptionPage
	err      error
	requests []SubscriptionListRequest
}

func (c subscriptionReaderControl) GetSubscription(context.Context, SubscriptionGetRequest) (*Subscription, error) {
	return nil, errors.New("unused")
}
func (c *subscriptionReaderControl) ListSubscriptions(_ context.Context, request SubscriptionListRequest) (*SubscriptionPage, error) {
	c.requests = append(c.requests, request)
	if c.err != nil {
		return nil, c.err
	}
	index := len(c.requests) - 1
	if index >= len(c.pages) {
		return nil, errors.New("unexpected page request")
	}
	return c.pages[index], nil
}
func (c *subscriptionReaderControl) AssignOrExtendSubscription(context.Context, SubscriptionAssignOrExtendRequest) (*SubscriptionMutationResult, error) {
	return nil, errors.New("unused")
}
func (c *subscriptionReaderControl) RevokeSubscription(context.Context, SubscriptionRevokeRequest) (*Subscription, error) {
	return nil, errors.New("unused")
}
func (c *subscriptionReaderControl) RestoreSubscription(context.Context, SubscriptionRestoreRequest) (*Subscription, error) {
	return nil, errors.New("unused")
}
func (c *subscriptionReaderControl) ExtendSubscription(context.Context, SubscriptionExtendRequest) (*Subscription, error) {
	return nil, errors.New("unused")
}
func (c *subscriptionReaderControl) ActivateSubscriptionWindows(context.Context, SubscriptionActivateWindowsRequest) (*Subscription, error) {
	return nil, errors.New("unused")
}
func (c *subscriptionReaderControl) MaintainSubscriptionWindows(context.Context, SubscriptionMaintainWindowsRequest) (*Subscription, error) {
	return nil, errors.New("unused")
}
func (c *subscriptionReaderControl) ResetSubscriptionWindows(context.Context, SubscriptionResetWindowsRequest) (*Subscription, error) {
	return nil, errors.New("unused")
}
func (c *subscriptionReaderControl) ReserveSubscriptionUsage(context.Context, SubscriptionReserveUsageRequest) (*Subscription, error) {
	return nil, errors.New("unused")
}
func (c *subscriptionReaderControl) SweepExpiredSubscriptions(context.Context, SubscriptionSweepExpiredRequest) (*SubscriptionSweepResult, error) {
	return nil, errors.New("unused")
}

func TestAPIKeySubscriptionReaderFailsClosed(t *testing.T) {
	base, err := decodeSubscription(json.RawMessage(subscriptionFixture))
	require.NoError(t, err)
	for _, test := range []struct {
		name   string
		mutate func(*Subscription)
		want   bool
	}{
		{"active", func(*Subscription) {}, true}, {"expired", func(s *Subscription) { s.ExpiresAt = subscriptionNow() }, false}, {"revoked", func(s *Subscription) { at := subscriptionNow(); s.DeletedAt = &at }, false}, {"suspended", func(s *Subscription) { s.Status = service.SubscriptionStatusSuspended }, false}, {"mismatched-user", func(s *Subscription) { s.UserID = "1" }, false}, {"mismatched-group", func(s *Subscription) { s.GroupID = "1" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := *base
			test.mutate(&copy)
			reader := NewAPIKeySubscriptionReader(&subscriptionReaderControl{pages: []*SubscriptionPage{{Items: []Subscription{copy}}}})
			reader.now = subscriptionNow
			_, got := reader.GetActiveByUserIDAndGroupID(context.Background(), 9007199254740994, 9007199254740995)
			if test.want {
				require.NoError(t, got)
			} else {
				require.ErrorIs(t, got, service.ErrSubscriptionNotFound)
			}
		})
	}
	missing := NewAPIKeySubscriptionReader(&subscriptionReaderControl{pages: []*SubscriptionPage{{}}})
	_, err = missing.GetActiveByUserIDAndGroupID(context.Background(), 1, 2)
	require.ErrorIs(t, err, service.ErrSubscriptionNotFound)
}

func TestAPIKeySubscriptionReaderRejectsAdditionalMatchingCursor(t *testing.T) {
	base, err := decodeSubscription(json.RawMessage(subscriptionFixture))
	require.NoError(t, err)
	next := base.ID
	control := &subscriptionReaderControl{pages: []*SubscriptionPage{{Items: []Subscription{*base}, NextAfterID: &next}}}
	reader := NewAPIKeySubscriptionReader(control)
	reader.now = subscriptionNow
	_, err = reader.GetActiveByUserIDAndGroupID(context.Background(), 9007199254740994, 9007199254740995)
	require.ErrorIs(t, err, ErrSubscriptionUnavailable)
	require.ErrorIs(t, err, ErrSubscriptionCursorContract)
}

func TestAPIKeySubscriptionReaderListsAllCursorPages(t *testing.T) {
	first, err := decodeSubscription(json.RawMessage(subscriptionFixture))
	require.NoError(t, err)
	second := *first
	second.ID = "9007199254740997"
	second.GroupID = "9007199254740998"
	next := first.ID
	control := &subscriptionReaderControl{pages: []*SubscriptionPage{
		{Items: []Subscription{*first}, NextAfterID: &next},
		{Items: []Subscription{second}},
	}}
	reader := NewAPIKeySubscriptionReader(control)
	reader.now = subscriptionNow
	subscriptions, err := reader.ListActiveByUserID(context.Background(), 9007199254740994)
	require.NoError(t, err)
	require.Len(t, subscriptions, 2)
	require.Equal(t, []int64{9007199254740995, 9007199254740998}, []int64{subscriptions[0].GroupID, subscriptions[1].GroupID})
	require.Len(t, control.requests, 2)
	for _, request := range control.requests {
		require.NotNil(t, request.UserID)
		require.Equal(t, "9007199254740994", *request.UserID)
		require.Nil(t, request.GroupID)
		require.NotNil(t, request.Status)
		require.Equal(t, service.SubscriptionStatusActive, *request.Status)
		require.False(t, request.IncludeDeleted)
		require.Equal(t, apiKeySubscriptionPageSize, request.Limit)
	}
	require.Nil(t, control.requests[0].AfterID)
	require.NotNil(t, control.requests[1].AfterID)
	require.Equal(t, next, *control.requests[1].AfterID)
}

func TestAPIKeySubscriptionReaderRejectsInvalidRowsAndCursors(t *testing.T) {
	base, err := decodeSubscription(json.RawMessage(subscriptionFixture))
	require.NoError(t, err)
	deletedAt := subscriptionNow()
	for _, test := range []struct {
		name   string
		mutate func(*Subscription)
	}{
		{"wrong user", func(subscription *Subscription) { subscription.UserID = "1" }},
		{"not active", func(subscription *Subscription) { subscription.Status = service.SubscriptionStatusSuspended }},
		{"deleted", func(subscription *Subscription) { subscription.DeletedAt = &deletedAt }},
		{"expired boundary", func(subscription *Subscription) { subscription.ExpiresAt = subscriptionNow() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := *base
			test.mutate(&copy)
			reader := NewAPIKeySubscriptionReader(&subscriptionReaderControl{pages: []*SubscriptionPage{{Items: []Subscription{copy}}}})
			reader.now = subscriptionNow
			_, err := reader.ListActiveByUserID(context.Background(), 9007199254740994)
			require.ErrorIs(t, err, ErrSubscriptionUnavailable)
			require.ErrorIs(t, err, ErrSubscriptionCursorContract)
		})
	}

	first := *base
	next := first.ID
	control := &subscriptionReaderControl{pages: []*SubscriptionPage{
		{Items: []Subscription{first}, NextAfterID: &next},
		{Items: []Subscription{first}, NextAfterID: &next},
	}}
	reader := NewAPIKeySubscriptionReader(control)
	reader.now = subscriptionNow
	_, err = reader.ListActiveByUserID(context.Background(), 9007199254740994)
	require.ErrorIs(t, err, ErrSubscriptionUnavailable)
	require.ErrorIs(t, err, ErrSubscriptionCursorContract)
}

func TestAPIKeySubscriptionReaderEnforcesPaginationSafetyCeiling(t *testing.T) {
	base, err := decodeSubscription(json.RawMessage(subscriptionFixture))
	require.NoError(t, err)
	pages := make([]*SubscriptionPage, 0, maxAPIKeySubscriptionPages)
	for index := 0; index < maxAPIKeySubscriptionPages; index++ {
		subscription := *base
		subscription.ID = strconv.Itoa(1000 + index)
		subscription.UserID = "1"
		subscription.GroupID = strconv.Itoa(2000 + index)
		next := subscription.ID
		pages = append(pages, &SubscriptionPage{Items: []Subscription{subscription}, NextAfterID: &next})
	}
	reader := NewAPIKeySubscriptionReader(&subscriptionReaderControl{pages: pages})
	reader.now = subscriptionNow
	_, err = reader.ListActiveByUserID(context.Background(), 1)
	require.ErrorIs(t, err, ErrSubscriptionUnavailable)
	require.ErrorIs(t, err, ErrSubscriptionCursorContract)
}
