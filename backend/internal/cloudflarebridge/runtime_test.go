//go:build unit

package cloudflarebridge

import (
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func setTestJWTSecret(t *testing.T) {
	t.Helper()
	t.Setenv(JWTSecretEnv, strings.Repeat("t", 32))
}

func TestRuntimeConfigFailsClosedWithoutAuthorizedUpstreamHosts(t *testing.T) {
	setTestJWTSecret(t)
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "")
	t.Setenv("SUB2API_CF_ALLOW_TEST_FIXTURE", "")
	t.Setenv("SUB2API_CF_LEASE_TTL_SECONDS", "")

	_, err := LoadRuntimeConfigFromEnv()
	require.ErrorContains(t, err, "SUB2API_CF_UPSTREAM_ALLOWED_HOSTS")
}

func TestRuntimeConfigFixtureUsesOnlyVirtualMockHost(t *testing.T) {
	setTestJWTSecret(t)
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "")
	t.Setenv("SUB2API_CF_ALLOW_TEST_FIXTURE", "true")
	t.Setenv("SUB2API_CF_LEASE_TTL_SECONDS", "7")

	runtime, err := LoadRuntimeConfigFromEnv()
	require.NoError(t, err)
	require.Equal(t, []string{"mock.upstream"}, runtime.AllowedHosts)
	require.True(t, runtime.Application.Security.CSP.Enabled)
	require.Equal(t, config.DefaultCSPPolicy, runtime.Application.Security.CSP.Policy)
	require.True(t, runtime.Application.Security.URLAllowlist.Enabled)
	require.True(t, runtime.Application.Security.URLAllowlist.AllowInsecureHTTP)
	require.True(t, runtime.Application.Security.URLAllowlist.AllowPrivateHosts)
	require.Equal(t, 7, runtime.LeaseTTLSeconds)
}

func TestRuntimeConfigFixtureRejectsAdditionalHosts(t *testing.T) {
	setTestJWTSecret(t)
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "mock.upstream,api.openai.com")
	t.Setenv("SUB2API_CF_ALLOW_TEST_FIXTURE", "true")
	t.Setenv("SUB2API_CF_LEASE_TTL_SECONDS", "")

	_, err := LoadRuntimeConfigFromEnv()
	require.ErrorContains(t, err, "only permits the virtual mock.upstream host")
}

func TestRuntimeConfigRejectsInvalidLeaseTTL(t *testing.T) {
	setTestJWTSecret(t)
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "api.openai.com")
	t.Setenv("SUB2API_CF_LEASE_TTL_SECONDS", "2")

	_, err := LoadRuntimeConfigFromEnv()
	require.ErrorContains(t, err, "SUB2API_CF_LEASE_TTL_SECONDS")
}

func TestRuntimeConfigRejectsPublicControlPlaneURL(t *testing.T) {
	setTestJWTSecret(t)
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "https://api.cloudflare.com/client/v4")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "api.openai.com")

	_, err := LoadRuntimeConfigFromEnv()
	require.ErrorContains(t, err, "must be http://sub2api.internal")
}

func TestRuntimeConfigNormalizesAuthorizedHosts(t *testing.T) {
	setTestJWTSecret(t)
	t.Setenv("SUB2API_CF_CONTROL_PLANE_URL", "")
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "API.Example.com.,api.example.com")
	t.Setenv("SUB2API_CF_ALLOW_TEST_FIXTURE", "")

	runtime, err := LoadRuntimeConfigFromEnv()
	require.NoError(t, err)
	require.Equal(t, []string{"api.example.com"}, runtime.AllowedHosts)
}

func TestRuntimeConfigRequiresStrongCloudflareJWTSecret(t *testing.T) {
	t.Setenv(JWTSecretEnv, strings.Repeat("x", 31))
	_, err := LoadRuntimeConfigFromEnv()
	require.ErrorContains(t, err, JWTSecretEnv)

	t.Setenv(JWTSecretEnv, strings.Repeat("密", 11))
	t.Setenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS", "api.example.com")
	runtime, err := LoadRuntimeConfigFromEnv()
	require.NoError(t, err)
	require.Equal(t, defaultJWTExpireMinutes, runtime.Application.JWT.AccessTokenExpireMinutes)
}
