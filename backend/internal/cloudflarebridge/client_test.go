//go:build unit

package cloudflarebridge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

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
		_, _ = io.WriteString(w, `{
			"upstream_model":"fixture-upstream",
			"account":{"id":"3001","name":"fixture","platform":"openai","type":"apikey","concurrency":1,"credentials":{"api_key":"fixture-secret"},"extra":{}},
			"lease":{"lease_id":"lease","request_id":"different-request","account_id":"3001","owner":"container","epoch":"1","expires_at":"2030-01-01T00:00:00Z"}
		}`)
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
		_, _ = io.WriteString(w, `{
			"upstream_model":"mapped-model",
			"account":{"id":"9007199254740993","name":"fixture","platform":"openai","type":"apikey","concurrency":1,"credentials":{"api_key":"fixture-secret","base_url":"https://mock.upstream"},"extra":{"openai_responses_supported":false}},
			"lease":{"lease_id":"lease","request_id":"expected-request","account_id":"9007199254740993","owner":"container","epoch":"9007199254740994","expires_at":"2030-01-01T00:00:00Z"}
		}`)
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
