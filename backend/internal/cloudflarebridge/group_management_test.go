package cloudflarebridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestHTTPControlPlaneGroupCreateRequiresCandidateIdentityUnlessReplayed(t *testing.T) {
	t.Parallel()
	const timestamp = "2026-09-07T00:00:00Z"

	for _, tt := range []struct {
		name       string
		returnedID string
		replayed   bool
		wantError  bool
	}{
		{name: "first apply", returnedID: "7001"},
		{name: "mismatched first apply", returnedID: "7002", wantError: true},
		{name: "replayed prior identity", returnedID: "7002", replayed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/manage/groups/create":
					var body map[string]any
					require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
					require.Equal(t, "group-operation", body["operation_id"])
					require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
						"group": map[string]any{
							"id": tt.returnedID, "name": "browser", "platform": "openai",
							"status": "active", "is_exclusive": false, "subscription_type": "standard",
							"created_at": timestamp, "updated_at": timestamp, "deleted_at": nil,
						},
						"replayed": tt.replayed,
					}))
				case "/v1/manage/groups/get":
					require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
						"group": map[string]any{
							"id": tt.returnedID, "name": "browser", "platform": "openai",
							"status": "active", "is_exclusive": false, "subscription_type": "standard",
							"created_at": timestamp, "updated_at": timestamp, "deleted_at": nil,
						},
					}))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			control, err := NewHTTPControlPlane(server.URL, server.Client())
			require.NoError(t, err)
			created, replayed, err := control.CreateManagedGroup(context.Background(), "group-operation", &service.Group{
				ID: 7001, Name: "browser", Platform: service.PlatformOpenAI, Status: service.StatusActive,
				SubscriptionType: service.SubscriptionTypeStandard,
			})
			if tt.wantError {
				require.ErrorContains(t, err, "identity mismatch")
				require.Nil(t, created)
				require.False(t, replayed)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.returnedID, strconv.FormatInt(created.ID, 10))
			require.Equal(t, tt.replayed, replayed)
		})
	}
}

func TestCloudflareGroupNeutralPayloadFieldsAreExplicitAndTypeStrict(t *testing.T) {
	t.Parallel()
	require.False(t, isNeutralLegacyGroupField("unexpected", json.RawMessage(`false`)))
	require.False(t, isNeutralLegacyGroupField("unexpected", json.RawMessage(`null`)))
	require.False(t, isNeutralLegacyGroupField("unexpected", json.RawMessage(`[]`)))
	require.True(t, isNeutralLegacyGroupField("allow_live", json.RawMessage(`false`)))
	require.True(t, isNeutralLegacyGroupField("web_search_price_per_call", json.RawMessage(`-1`)))
	require.True(t, isNeutralLegacyGroupField("fallback_group_id", json.RawMessage(`0`)))
	require.False(t, isNeutralLegacyGroupField("rate_multiplier", json.RawMessage(`"1"`)))
	require.False(t, isNeutralLegacyGroupField("model_pricing", json.RawMessage(`nullx`)))
	require.True(t, isNeutralLegacyGroupField("models_list_config", json.RawMessage(`{"enabled":false,"models":["gpt-5"]}`)))
	require.False(t, isNeutralLegacyGroupField("models_list_config", json.RawMessage(`{"enabled":true,"models":[]}`)))
	require.False(t, isNeutralLegacyGroupField("models_list_config", json.RawMessage(`{"enabled":null,"models":[]}`)))
	require.False(t, isNeutralLegacyGroupField("messages_dispatch_model_config", json.RawMessage(`{"opus_mapped_model":null}`)))
	require.ErrorIs(t, mapManagedGroupMutationError(
		&controlPlaneResponseError{StatusCode: http.StatusConflict, Code: "CONFLICT"},
		service.ErrGroupExists,
	), service.ErrGroupExists)
}

func TestCloudflareGroupNameUsesWorkerUTF16Limit(t *testing.T) {
	t.Parallel()
	require.True(t, validCloudflareGroupName(strings.Repeat("界", 100)))
	require.False(t, validCloudflareGroupName(strings.Repeat("界", 101)))
	require.True(t, validCloudflareGroupName(strings.Repeat("😀", 50)))
	require.False(t, validCloudflareGroupName(strings.Repeat("😀", 51)))
	require.False(t, validCloudflareGroupName(" padded "))
}

func TestDecodeManagedGroupAppliesCloudflareFixedDefaults(t *testing.T) {
	t.Parallel()
	group, deleted, err := decodeManagedGroup(managedGroupWire{
		ID: "7001", Name: "browser", Platform: service.PlatformOpenAI, Status: service.StatusActive,
		SubscriptionType: service.SubscriptionTypeStandard, CreatedAt: "2026-09-07T00:00:00Z",
		UpdatedAt: "2026-09-07T00:00:00Z",
	})
	require.NoError(t, err)
	require.False(t, deleted)
	require.True(t, group.LongContextPricingEnabled)
	require.Equal(t, 1.0, group.ImageRateMultiplier)
	require.Equal(t, 0.5, group.BatchImageDiscountMultiplier)
	require.Equal(t, 0.6, group.BatchImageHoldMultiplier)
	require.Equal(t, 1.0, group.VideoRateMultiplier)
	require.Equal(t, 1.0, group.PeakRateMultiplier)
	require.True(t, group.MCPXMLInject)
	require.Equal(t, service.ReasoningEffortOverLimitDowngrade, group.MaxReasoningEffortOverLimit)
}

func TestHTTPControlPlaneGroupUpdateRequiresRequestedFields(t *testing.T) {
	t.Parallel()
	const timestamp = "2026-09-07T00:00:00Z"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"group": map[string]any{
				"id": "7001", "name": "unchanged", "platform": "openai",
				"status": "active", "is_exclusive": false, "subscription_type": "standard",
				"created_at": timestamp, "updated_at": timestamp, "deleted_at": nil,
			},
		}))
	}))
	defer server.Close()

	control, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	name := "requested"
	updated, err := control.UpdateManagedGroup(
		context.Background(),
		"group-update",
		7001,
		ManagedGroupUpdate{Name: &name},
	)
	require.ErrorContains(t, err, "field mismatch")
	require.Nil(t, updated)
}
