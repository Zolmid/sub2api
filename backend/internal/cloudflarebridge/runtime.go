package cloudflarebridge

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

const (
	DeploymentModeEnv   = "SUB2API_DEPLOYMENT_MODE"
	DeploymentModeValue = "cloudflare"
	JWTSecretEnv        = "SUB2API_CF_JWT_SECRET"

	defaultControlPlaneURL  = "http://" + InternalHost
	defaultServerHost       = "0.0.0.0"
	defaultServerPort       = 8080
	defaultMaxBodyBytes     = 16 << 20
	defaultTextBodyBytes    = 4 << 20
	defaultLeaseTTLSeconds  = 90
	defaultJWTExpireMinutes = 60
)

type RuntimeConfig struct {
	Address          string
	ControlPlaneURL  string
	AllowedHosts     []string
	AllowTestFixture bool
	LeaseTTLSeconds  int
	Application      *config.Config
}

func EnabledFromEnv() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(DeploymentModeEnv)), DeploymentModeValue)
}

func LoadRuntimeConfigFromEnv() (*RuntimeConfig, error) {
	jwtSecret := strings.TrimSpace(os.Getenv(JWTSecretEnv))
	if len([]byte(jwtSecret)) < 32 {
		return nil, fmt.Errorf("%s must contain at least 32 bytes", JWTSecretEnv)
	}
	controlPlaneURL := strings.TrimSpace(os.Getenv("SUB2API_CF_CONTROL_PLANE_URL"))
	if controlPlaneURL == "" {
		controlPlaneURL = defaultControlPlaneURL
	}
	parsed, err := url.Parse(controlPlaneURL)
	if err != nil {
		return nil, fmt.Errorf("parse SUB2API_CF_CONTROL_PLANE_URL: %w", err)
	}
	// Production code must use the private Container outbound-handler hostname,
	// never Cloudflare's public account-management REST API.
	if parsed.Scheme != "http" || parsed.Host != InternalHost || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("SUB2API_CF_CONTROL_PLANE_URL must be %s", defaultControlPlaneURL)
	}

	host := strings.TrimSpace(os.Getenv("SERVER_HOST"))
	if host == "" {
		host = defaultServerHost
	}
	port := defaultServerPort
	if raw := strings.TrimSpace(os.Getenv("SERVER_PORT")); raw != "" {
		port, err = strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("SERVER_PORT must be an integer from 1 to 65535")
		}
	}

	allowTestFixture := parseEnvBool(os.Getenv("SUB2API_CF_ALLOW_TEST_FIXTURE"))
	leaseTTLSeconds := defaultLeaseTTLSeconds
	if raw := strings.TrimSpace(os.Getenv("SUB2API_CF_LEASE_TTL_SECONDS")); raw != "" {
		leaseTTLSeconds, err = strconv.Atoi(raw)
		if err != nil || leaseTTLSeconds < 3 || leaseTTLSeconds > 3600 {
			return nil, errors.New("SUB2API_CF_LEASE_TTL_SECONDS must be an integer from 3 to 3600")
		}
	}
	allowedHosts := parseHostList(os.Getenv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS"))
	if allowTestFixture && len(allowedHosts) == 0 {
		allowedHosts = []string{"mock.upstream"}
	}
	if allowTestFixture && (len(allowedHosts) != 1 || allowedHosts[0] != "mock.upstream") {
		return nil, errors.New("SUB2API_CF_ALLOW_TEST_FIXTURE only permits the virtual mock.upstream host")
	}
	if len(allowedHosts) == 0 {
		return nil, errors.New("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS must list at least one authorized upstream host")
	}

	app := &config.Config{
		RunMode: config.RunModeStandard,
		Server: config.ServerConfig{
			Host:                     host,
			Port:                     port,
			Mode:                     "release",
			ReadHeaderTimeout:        30,
			IdleTimeout:              120,
			MaxHeaderBytes:           128 << 10,
			MaxRequestBodySize:       defaultMaxBodyBytes,
			TrustedProxies:           []string{},
			TrustedProxiesConfigured: true,
		},
		Security: config.SecurityConfig{
			CSP: config.CSPConfig{
				Enabled: true,
				Policy:  config.DefaultCSPPolicy,
			},
			URLAllowlist: config.URLAllowlistConfig{
				Enabled:       true,
				UpstreamHosts: allowedHosts,
				// The Container egress proxy may resolve its fixture-only virtual
				// hostname to an internal address. This relaxation is safe only
				// because fixture mode above permits exactly mock.upstream.
				AllowPrivateHosts: allowTestFixture,
				AllowInsecureHTTP: allowTestFixture,
			},
		},
		Gateway: config.GatewayConfig{
			MaxBodySize:                  defaultMaxBodyBytes,
			TextMaxBodySize:              defaultTextBodyBytes,
			UpstreamResponseReadMaxBytes: config.DefaultUpstreamResponseReadMaxBytes,
		},
		JWT: config.JWTConfig{
			Secret:                   jwtSecret,
			ExpireHour:               1,
			AccessTokenExpireMinutes: defaultJWTExpireMinutes,
			RefreshTokenExpireDays:   30,
			RefreshWindowMinutes:     15,
		},
		Default: config.DefaultConfig{APIKeyPrefix: "sk-"},
	}

	return &RuntimeConfig{
		Address:          net.JoinHostPort(host, strconv.Itoa(port)),
		ControlPlaneURL:  defaultControlPlaneURL,
		AllowedHosts:     allowedHosts,
		AllowTestFixture: allowTestFixture,
		LeaseTTLSeconds:  leaseTTLSeconds,
		Application:      app,
	}, nil
}

func parseEnvBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseHostList(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(part)), ".")
		if host == "" || len(host) > 253 || strings.ContainsAny(host, "/?#@") {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		result = append(result, host)
	}
	return result
}
