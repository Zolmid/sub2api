package cloudflarebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

const maxControlPlaneResponseBytes int64 = 1 << 20

var (
	ErrControlPlaneUnavailable = errors.New("cloudflare control plane unavailable")
	ErrAdmissionRejected       = errors.New("cloudflare admission rejected")
	ErrInsufficientBalance     = errors.New("cloudflare insufficient balance")
)

// controlPlaneResponseError preserves the bounded machine-readable status from
// the private Worker protocol without retaining or exposing its response body.
// It still unwraps to ErrControlPlaneUnavailable so existing gateway callers
// keep their fail-closed behavior while management adapters can map known
// domain outcomes precisely.
type controlPlaneResponseError struct {
	StatusCode int
	Code       string
}

func (e *controlPlaneResponseError) Error() string {
	return fmt.Sprintf("%s: status=%d code=%s", ErrControlPlaneUnavailable, e.StatusCode, e.Code)
}

func (e *controlPlaneResponseError) Unwrap() error {
	return ErrControlPlaneUnavailable
}

type HTTPControlPlane struct {
	baseURL string
	client  *http.Client
}

func NewHTTPControlPlane(baseURL string, client *http.Client) (*HTTPControlPlane, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, fmt.Errorf("parse control plane url: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("control plane url must be an absolute http(s) URL")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("control plane url must not include a query or fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if client == nil {
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("default HTTP transport is not configurable")
		}
		transport := defaultTransport.Clone()
		// The virtual outbound-handler hostname must never be sent through a
		// user-supplied HTTP(S)_PROXY or redirected to a public endpoint.
		transport.Proxy = nil
		client = &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	} else if client.CheckRedirect == nil {
		copy := *client
		copy.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		client = &copy
	}
	return &HTTPControlPlane{baseURL: parsed.String(), client: client}, nil
}

type wireErrorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *HTTPControlPlane) post(ctx context.Context, path string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode control plane request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build control plane request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Sub2API-Bridge-Version", ProtocolVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("control plane request canceled: %w", ctxErr)
		}
		return fmt.Errorf("%w: %v", ErrControlPlaneUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	limited := io.LimitReader(resp.Body, maxControlPlaneResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("%w: read response: %v", ErrControlPlaneUnavailable, err)
	}
	if int64(len(responseBody)) > maxControlPlaneResponseBytes {
		return fmt.Errorf("%w: response exceeds %d bytes", ErrControlPlaneUnavailable, maxControlPlaneResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope wireErrorEnvelope
		_ = json.Unmarshal(responseBody, &envelope)
		code := strings.TrimSpace(envelope.Error.Code)
		if code == "API_KEY_NOT_FOUND" {
			return service.ErrAPIKeyNotFound
		}
		if code == "INSUFFICIENT_BALANCE" || resp.StatusCode == http.StatusPaymentRequired {
			return ErrInsufficientBalance
		}
		if code == "ADMISSION_REJECTED" || resp.StatusCode == http.StatusTooManyRequests {
			return ErrAdmissionRejected
		}
		if code == "" {
			code = http.StatusText(resp.StatusCode)
		}
		return &controlPlaneResponseError{StatusCode: resp.StatusCode, Code: code}
	}
	if output == nil || len(responseBody) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("%w: decode response: %v", ErrControlPlaneUnavailable, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: decode response: trailing JSON value", ErrControlPlaneUnavailable)
	}
	return nil
}

type authRequest struct {
	Key string `json:"key"`
}

type authResponse struct {
	APIKey struct {
		ID          string   `json:"id"`
		UserID      string   `json:"user_id"`
		Name        string   `json:"name"`
		Status      string   `json:"status"`
		GroupID     *string  `json:"group_id"`
		IPWhitelist []string `json:"ip_whitelist"`
		IPBlacklist []string `json:"ip_blacklist"`
		ExpiresAt   *string  `json:"expires_at"`
	} `json:"api_key"`
	User struct {
		ID                   string   `json:"id"`
		Status               string   `json:"status"`
		Role                 string   `json:"role"`
		Concurrency          int      `json:"concurrency"`
		BalancePositive      bool     `json:"balance_positive"`
		AllowedGroupIDs      []string `json:"allowed_group_ids"`
		RestrictPublicGroups bool     `json:"restrict_public_groups"`
	} `json:"user"`
	Group *struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		Platform         string `json:"platform"`
		Status           string `json:"status"`
		IsExclusive      bool   `json:"is_exclusive"`
		SubscriptionType string `json:"subscription_type"`
	} `json:"group"`
}

func parsePositiveID(label, raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if !isCanonicalPositiveDecimal(raw) {
		return 0, fmt.Errorf("invalid %s", label)
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid %s", label)
	}
	return id, nil
}

func parseOptionalTime(raw *string) (*time.Time, error) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(*raw))
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func (c *HTTPControlPlane) ResolveAPIKey(ctx context.Context, key string) (*service.APIKey, error) {
	var response authResponse
	if err := c.post(ctx, "/v1/auth/resolve", authRequest{Key: key}, &response); err != nil {
		return nil, err
	}
	keyID, err := parsePositiveID("api key id", response.APIKey.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid auth response: %w", err)
	}
	userID, err := parsePositiveID("user id", response.User.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid auth response: %w", err)
	}
	if declaredUserID, err := parsePositiveID("api key user id", response.APIKey.UserID); err != nil || declaredUserID != userID {
		return nil, errors.New("invalid auth response: api key owner mismatch")
	}
	expiresAt, err := parseOptionalTime(response.APIKey.ExpiresAt)
	if err != nil {
		return nil, errors.New("invalid auth response: invalid expiry")
	}

	allowedGroups := make([]int64, 0, len(response.User.AllowedGroupIDs))
	for _, rawID := range response.User.AllowedGroupIDs {
		id, err := parsePositiveID("allowed group id", rawID)
		if err != nil {
			return nil, fmt.Errorf("invalid auth response: %w", err)
		}
		allowedGroups = append(allowedGroups, id)
	}

	userBalance := float64(0)
	if response.User.BalancePositive {
		// The legacy middleware only compares Balance to zero. The actual amount
		// remains an exact fixed-point integer in D1 and is never transported as
		// a JavaScript/Go float by this bridge.
		userBalance = 1
	}
	user := &service.User{
		ID:                   userID,
		Status:               response.User.Status,
		Role:                 response.User.Role,
		Concurrency:          response.User.Concurrency,
		Balance:              userBalance,
		AllowedGroups:        allowedGroups,
		RestrictPublicGroups: response.User.RestrictPublicGroups,
	}

	var groupID *int64
	var group *service.Group
	if response.APIKey.GroupID != nil {
		id, err := parsePositiveID("group id", *response.APIKey.GroupID)
		if err != nil {
			return nil, fmt.Errorf("invalid auth response: %w", err)
		}
		groupID = &id
	}
	if response.Group != nil {
		id, err := parsePositiveID("group id", response.Group.ID)
		if err != nil {
			return nil, fmt.Errorf("invalid auth response: %w", err)
		}
		if groupID == nil || *groupID != id {
			return nil, errors.New("invalid auth response: group mismatch")
		}
		group = &service.Group{
			ID:               id,
			Name:             response.Group.Name,
			Platform:         response.Group.Platform,
			Status:           response.Group.Status,
			IsExclusive:      response.Group.IsExclusive,
			SubscriptionType: response.Group.SubscriptionType,
			Hydrated:         true,
		}
	}

	return &service.APIKey{
		ID:          keyID,
		UserID:      userID,
		Name:        response.APIKey.Name,
		Status:      response.APIKey.Status,
		GroupID:     groupID,
		IPWhitelist: response.APIKey.IPWhitelist,
		IPBlacklist: response.APIKey.IPBlacklist,
		ExpiresAt:   expiresAt,
		User:        user,
		Group:       group,
	}, nil
}

func (c *HTTPControlPlane) TouchAPIKey(ctx context.Context, keyID int64, usedAt time.Time) error {
	return c.post(ctx, "/v1/auth/touch", struct {
		APIKeyID string `json:"api_key_id"`
		UsedAt   string `json:"used_at"`
	}{APIKeyID: strconv.FormatInt(keyID, 10), UsedAt: usedAt.UTC().Format(time.RFC3339Nano)}, nil)
}

type admissionResponse struct {
	UpstreamModel string            `json:"upstream_model"`
	PriceCard     AdmittedPriceCard `json:"price_card"`
	Account       struct {
		ID          string         `json:"id"`
		Name        string         `json:"name"`
		Platform    string         `json:"platform"`
		Type        string         `json:"type"`
		Concurrency int            `json:"concurrency"`
		Credentials map[string]any `json:"credentials"`
		Extra       map[string]any `json:"extra"`
	} `json:"account"`
	Lease Lease `json:"lease"`
}

func (c *HTTPControlPlane) Admit(ctx context.Context, request AdmissionRequest) (*Admission, error) {
	var response admissionResponse
	if err := c.post(ctx, "/v1/requests/admit", request, &response); err != nil {
		return nil, err
	}
	accountID, err := parsePositiveID("account id", response.Account.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid admission response: %w", err)
	}
	if response.Account.Platform != service.PlatformOpenAI || response.Account.Type != service.AccountTypeAPIKey {
		return nil, errors.New("invalid admission response: unsupported account kind")
	}
	if response.Account.Concurrency < 1 {
		return nil, errors.New("invalid admission response: invalid account concurrency")
	}
	if strings.TrimSpace(response.UpstreamModel) == "" {
		return nil, errors.New("invalid admission response: upstream model is required")
	}
	if err := ValidateAdmittedPriceCardForModel(response.PriceCard, request.Model); err != nil {
		return nil, errors.New("invalid admission response: price card")
	}
	apiKey, ok := response.Account.Credentials["api_key"].(string)
	if !ok || strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("invalid admission response: account credential is required")
	}
	leaseAccountID, err := parsePositiveID("lease account id", response.Lease.AccountID)
	if err != nil || leaseAccountID != accountID {
		return nil, errors.New("invalid admission response: lease account mismatch")
	}
	if response.Lease.ID == "" || response.Lease.RequestID != request.RequestID || response.Lease.Owner == "" || !isCanonicalPositiveDecimal(response.Lease.Epoch) {
		return nil, errors.New("invalid admission response: incomplete lease")
	}
	if !response.Lease.ExpiresAt.After(time.Now()) {
		return nil, errors.New("invalid admission response: lease is already expired")
	}
	account := &service.Account{
		ID:          accountID,
		Name:        response.Account.Name,
		Platform:    response.Account.Platform,
		Type:        response.Account.Type,
		Concurrency: response.Account.Concurrency,
		Credentials: response.Account.Credentials,
		Extra:       response.Account.Extra,
		Status:      service.StatusActive,
		Schedulable: true,
	}
	return &Admission{Account: account, Lease: response.Lease, UpstreamModel: response.UpstreamModel, PriceCard: response.PriceCard}, nil
}

func isCanonicalPositiveDecimal(value string) bool {
	if value == "" || value[0] < '1' || value[0] > '9' {
		return false
	}
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func (c *HTTPControlPlane) Complete(ctx context.Context, request CompletionRequest) error {
	return c.post(ctx, "/v1/requests/complete", request, nil)
}

func (c *HTTPControlPlane) Start(ctx context.Context, request StartRequest) error {
	return c.post(ctx, "/v1/requests/start", request, nil)
}

func (c *HTTPControlPlane) Renew(ctx context.Context, request RenewRequest) (*Lease, error) {
	var response struct {
		Lease Lease `json:"lease"`
	}
	if err := c.post(ctx, "/v1/leases/renew", request, &response); err != nil {
		return nil, err
	}
	if response.Lease.ID != request.LeaseID || response.Lease.RequestID != request.RequestID ||
		response.Lease.AccountID != request.AccountID || response.Lease.Owner != request.Owner ||
		response.Lease.Epoch != request.Epoch {
		return nil, errors.New("invalid renewal response: lease identity changed")
	}
	if !response.Lease.ExpiresAt.After(time.Now()) {
		return nil, errors.New("invalid renewal response: lease is already expired")
	}
	return &response.Lease, nil
}

func (c *HTTPControlPlane) Release(ctx context.Context, request ReleaseRequest) error {
	return c.post(ctx, "/v1/leases/release", request, nil)
}
