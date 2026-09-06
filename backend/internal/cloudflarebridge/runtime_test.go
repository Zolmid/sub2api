//go:build unit

package cloudflarebridge

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuntimeConfigFailsClosedWithoutAuthorizedUpstreamHosts(t *testing.T) {
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "")
	t.Setenv("SUB2API_CF_ALLOW_TEST_FIXTURE", "")
	t.Setenv("SUB2API_CF_LEASE_TTL_SECONDS", "")

	_, err := LoadRuntimeConfigFromEnv()
	require.ErrorContains(t, err, "SUB2API_CF_UPSTREAM_ALLOWED_HOSTS")
}

func TestRuntimeConfigFixtureUsesOnlyVirtualMockHost(t *testing.T) {
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "")
	t.Setenv("SUB2API_CF_ALLOW_TEST_FIXTURE", "true")
	t.Setenv("SUB2API_CF_LEASE_TTL_SECONDS", "7")

	runtime, err := LoadRuntimeConfigFromEnv()
	require.NoError(t, err)
	require.Equal(t, []string{"mock.upstream"}, runtime.AllowedHosts)
	require.True(t, runtime.Application.Security.URLAllowlist.Enabled)
	require.True(t, runtime.Application.Security.URLAllowlist.AllowInsecureHTTP)
	require.True(t, runtime.Application.Security.URLAllowlist.AllowPrivateHosts)
	require.Equal(t, 7, runtime.LeaseTTLSeconds)
}

func TestRuntimeConfigFixtureRejectsAdditionalHosts(t *testing.T) {
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "mock.upstream,api.openai.com")
	t.Setenv("SUB2API_CF_ALLOW_TEST_FIXTURE", "true")
	t.Setenv("SUB2API_CF_LEASE_TTL_SECONDS", "")

	_, err := LoadRuntimeConfigFromEnv()
	require.ErrorContains(t, err, "only permits the virtual mock.upstream host")
}

func TestRuntimeConfigRejectsInvalidLeaseTTL(t *testing.T) {
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "api.openai.com")
	t.Setenv("SUB2API_CF_LEASE_TTL_SECONDS", "2")

	_, err := LoadRuntimeConfigFromEnv()
	require.ErrorContains(t, err, "SUB2API_CF_LEASE_TTL_SECONDS")
}

func TestRuntimeConfigRejectsPublicControlPlaneURL(t *testing.T) {
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "https://api.cloudflare.com/client/v4")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "api.openai.com")

	_, err := LoadRuntimeConfigFromEnv()
	require.ErrorContains(t, err, "must be http://sub2api.internal")
}

func TestRuntimeConfigNormalizesAuthorizedHosts(t *testing.T) {
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "API.Example.com.,api.example.com")
	t.Setenv("SUB2API_CF_ALLOW_TEST_FIXTURE", "")

	runtime, err := LoadRuntimeConfigFromEnv()
	require.NoError(t, err)
	require.Equal(t, []string{"api.example.com"}, runtime.AllowedHosts)
}
