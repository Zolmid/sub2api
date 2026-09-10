//go:build unit

package cloudflarebridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type nonCloneTransport struct{}

func (nonCloneTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("must not be called")
}

func TestHTTPControlPlaneRejectsNonStandardDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = nonCloneTransport{}
	t.Cleanup(func() { http.DefaultTransport = original })

	client, err := NewHTTPControlPlane("http://sub2api.internal", nil)
	require.Nil(t, client)
	require.EqualError(t, err, "default HTTP transport is not configurable")
}

func TestHTTPControlPlaneResolveUsesBodyAndVersionedInternalProtocol(t *testing.T) {
	const rawKey = "sk-cloudflare-control-client-test"
	var requestURI string
	var requestBody string
	var protocolVersion string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURI = r.RequestURI
		protocolVersion = r.Header.Get("X-Sub2API-Bridge-Version")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		requestBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"api_key":{"id":"4001","user_id":"1001","name":"test","status":"active","group_id":"2001","ip_whitelist":[],"ip_blacklist":[]},
			"user":{"id":"1001","status":"active","role":"user","concurrency":2,"balance_positive":true,"allowed_group_ids":[],"restrict_public_groups":false},
			"group":{"id":"2001","name":"group","platform":"openai","status":"active","is_exclusive":false,"subscription_type":"standard"}
		}`)
	}))
	defer server.Close()

	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	key, err := client.ResolveAPIKey(context.Background(), rawKey)
	require.NoError(t, err)

	require.NotContains(t, requestURI, rawKey)
	require.JSONEq(t, `{"key":"`+rawKey+`"}`, requestBody)
	require.Equal(t, ProtocolVersion, protocolVersion)
	require.Equal(t, int64(4001), key.ID)
	require.Equal(t, int64(1001), key.User.ID)
	require.Equal(t, float64(1), key.User.Balance)
	require.Equal(t, int64(2001), key.Group.ID)
	require.True(t, key.Group.Hydrated)
}

func TestHTTPControlPlaneStartUsesVersionedPrivateEndpoint(t *testing.T) {
	var requestURI string
	var requestBody string
	var protocolVersion string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURI = r.RequestURI
		protocolVersion = r.Header.Get("X-Sub2API-Bridge-Version")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		requestBody = string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	start := StartRequest{
		RequestID:     "request-start-test",
		APIKeyID:      "4001",
		AccountID:     "3001",
		LeaseID:       "lease-start-test",
		LeaseEpoch:    "7",
		Model:         "client-model",
		UpstreamModel: "mapped-model",
	}
	require.NoError(t, client.Start(context.Background(), start))

	require.Equal(t, "/v1/requests/start", requestURI)
	require.Equal(t, ProtocolVersion, protocolVersion)
	require.JSONEq(t, `{
		"request_id":"request-start-test",
		"api_key_id":"4001",
		"account_id":"3001",
		"lease_id":"lease-start-test",
		"lease_epoch":"7",
		"model":"client-model",
		"upstream_model":"mapped-model"
	}`, requestBody)
}

func TestHTTPControlPlaneMapsNotFoundWithoutLeakingResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":{"code":"API_KEY_NOT_FOUND","message":"internal detail must not escape"}}`)
	}))
	defer server.Close()

	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, err = client.ResolveAPIKey(context.Background(), "unknown")
	require.ErrorIs(t, err, service.ErrAPIKeyNotFound)
	require.NotContains(t, err.Error(), "internal detail")
}

func TestHTTPControlPlaneRejectsMismatchedLeaseIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		card := testAdmittedCard()
		card.Rule.ModelPattern = "test-model"
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"upstream_model": "fixture-upstream",
			"price_card":     card,
			"account": map[string]any{
				"id": "3001", "name": "fixture", "platform": "openai", "type": "apikey",
				"concurrency": 1, "credentials": map[string]any{"api_key": "fixture-secret"}, "extra": map[string]any{},
			},
			"lease": map[string]any{
				"lease_id": "lease", "request_id": "different-request", "account_id": "3001",
				"owner": "container", "epoch": "1", "expires_at": "2030-01-01T00:00:00Z",
			},
		}))
	}))
	defer server.Close()

	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, err = client.Admit(context.Background(), AdmissionRequest{
		RequestID:       "expected-request",
		APIKeyID:        "4001",
		GroupID:         "2001",
		Model:           "test-model",
		LeaseTTLSeconds: 90,
	})
	require.ErrorContains(t, err, "incomplete lease")
}

func TestHTTPControlPlaneAdmissionPreservesMappedModelAndDecimalLeaseIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		card := testAdmittedCard()
		card.Rule.ModelPattern = "client-model"
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"upstream_model": "mapped-model",
			"price_card":     card,
			"account": map[string]any{
				"id": "9007199254740993", "name": "fixture", "platform": "openai", "type": "apikey",
				"concurrency": 1,
				"credentials": map[string]any{"api_key": "fixture-secret", "base_url": "https://mock.upstream"},
				"extra":       map[string]any{"openai_responses_supported": false},
			},
			"lease": map[string]any{
				"lease_id": "lease", "request_id": "expected-request", "account_id": "9007199254740993",
				"owner": "container", "epoch": "9007199254740994", "expires_at": "2030-01-01T00:00:00Z",
			},
		}))
	}))
	defer server.Close()

	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	admission, err := client.Admit(context.Background(), AdmissionRequest{
		RequestID:       "expected-request",
		APIKeyID:        "4001",
		GroupID:         "2001",
		Model:           "client-model",
		LeaseTTLSeconds: 90,
	})
	require.NoError(t, err)
	require.Equal(t, "mapped-model", admission.UpstreamModel)
	require.Equal(t, "9007199254740994", admission.Lease.Epoch)
	require.Equal(t, int64(9007199254740993), admission.Account.ID)
	require.Equal(t, "2026-09-09.test", admission.PriceCard.VersionID)
}

func TestHTTPControlPlaneRejectsPriceCardForAnotherModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		card := testAdmittedCard()
		card.Rule.ModelPattern = "other-model"
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"upstream_model": "mapped-model", "price_card": card,
			"account": map[string]any{
				"id": "3001", "name": "fixture", "platform": "openai", "type": "apikey",
				"concurrency": 1, "credentials": map[string]any{"api_key": "fixture-secret"}, "extra": map[string]any{},
			},
			"lease": map[string]any{
				"lease_id": "lease", "request_id": "expected-request", "account_id": "3001",
				"owner": "container", "epoch": "1", "expires_at": "2030-01-01T00:00:00Z",
			},
		}))
	}))
	defer server.Close()
	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, err = client.Admit(context.Background(), AdmissionRequest{
		RequestID: "expected-request", APIKeyID: "4001", GroupID: "2001",
		Model: "client-model", LeaseTTLSeconds: 90,
	})
	require.ErrorContains(t, err, "price card")
}

func TestHTTPControlPlaneRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.Repeat("x", int(maxControlPlaneResponseBytes)+1))
	}))
	defer server.Close()

	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	_, err = client.ResolveAPIKey(context.Background(), "unknown")
	require.ErrorIs(t, err, ErrControlPlaneUnavailable)
	require.ErrorContains(t, err, "response exceeds")
}

func TestHTTPControlPlaneStrictlyRejectsUnknownAndTrailingResponseJSON(t *testing.T) {
	valid := `{
		"api_key":{"id":"4001","user_id":"1001","name":"test","status":"active","group_id":"2001","ip_whitelist":[],"ip_blacklist":[]},
		"user":{"id":"1001","status":"active","role":"user","concurrency":2,"balance_positive":true,"allowed_group_ids":[],"restrict_public_groups":false},
		"group":{"id":"2001","name":"group","platform":"openai","status":"active","is_exclusive":false,"subscription_type":"standard"}
	}`
	for _, response := range []string{
		strings.TrimSuffix(valid, "}") + `,"unknown":true}`,
		valid + ` {}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, response)
		}))
		client, err := NewHTTPControlPlane(server.URL, server.Client())
		require.NoError(t, err)
		_, err = client.ResolveAPIKey(context.Background(), "fixture")
		require.ErrorIs(t, err, ErrControlPlaneUnavailable)
		server.Close()
	}
}

func TestHTTPControlPlanePropagatesContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("canceled request must not reach the server")
	}))
	defer server.Close()
	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.ResolveAPIKey(ctx, "fixture")
	require.ErrorIs(t, err, context.Canceled)
}

func TestHTTPControlPlaneDoesNotReportFailedCompletionAsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":{"code":"BILLING_COMMIT_FAILED","message":"private detail"}}`)
	}))
	defer server.Close()
	client, err := NewHTTPControlPlane(server.URL, server.Client())
	require.NoError(t, err)
	err = client.Complete(context.Background(), CompletionRequest{})
	require.ErrorIs(t, err, ErrControlPlaneUnavailable)
	var responseErr *controlPlaneResponseError
	require.True(t, errors.As(err, &responseErr))
	require.Equal(t, http.StatusConflict, responseErr.StatusCode)
	require.Equal(t, "BILLING_COMMIT_FAILED", responseErr.Code)
	require.NotContains(t, err.Error(), "private detail")
}
