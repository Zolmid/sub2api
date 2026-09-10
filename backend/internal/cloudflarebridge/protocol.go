package cloudflarebridge

import (
	"context"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

const (
	// ProtocolVersion is sent on every Container-to-Worker control-plane request.
	// Changes that are not backward compatible must use a new version and route.
	ProtocolVersion    = "2026-09-09.v3"
	UsageSchemaVersion = "2026-09-09.v2"
	InternalHost       = "sub2api.internal"
	UsageEventType     = "gateway.usage.v2"
)

const (
	OutcomeSucceeded = "succeeded"
	OutcomeFailed    = "failed"

	UsageConfirmed = "confirmed"
	UsageUnknown   = "unknown"
)

// ControlPlane is the narrow, versioned boundary between the Go gateway in a
// Container and bindings owned by the Worker. Implementations must not log raw
// API keys or account credentials.
type ControlPlane interface {
	ResolveAPIKey(ctx context.Context, key string) (*service.APIKey, error)
	TouchAPIKey(ctx context.Context, keyID int64, usedAt time.Time) error
	Admit(ctx context.Context, request AdmissionRequest) (*Admission, error)
	Start(ctx context.Context, request StartRequest) error
	Renew(ctx context.Context, request RenewRequest) (*Lease, error)
	Complete(ctx context.Context, request CompletionRequest) error
	Release(ctx context.Context, request ReleaseRequest) error
}

// SubscriptionControlPlane is the private, authoritative subscription runtime
// contract.  It intentionally exposes Worker records and cursor pagination,
// rather than the traditional PostgreSQL repository contract.
type SubscriptionControlPlane interface {
	GetSubscription(context.Context, SubscriptionGetRequest) (*Subscription, error)
	ListSubscriptions(context.Context, SubscriptionListRequest) (*SubscriptionPage, error)
	AssignOrExtendSubscription(context.Context, SubscriptionAssignOrExtendRequest) (*SubscriptionMutationResult, error)
	RevokeSubscription(context.Context, SubscriptionRevokeRequest) (*Subscription, error)
	RestoreSubscription(context.Context, SubscriptionRestoreRequest) (*Subscription, error)
	ExtendSubscription(context.Context, SubscriptionExtendRequest) (*Subscription, error)
	ActivateSubscriptionWindows(context.Context, SubscriptionActivateWindowsRequest) (*Subscription, error)
	MaintainSubscriptionWindows(context.Context, SubscriptionMaintainWindowsRequest) (*Subscription, error)
	ResetSubscriptionWindows(context.Context, SubscriptionResetWindowsRequest) (*Subscription, error)
	ReserveSubscriptionUsage(context.Context, SubscriptionReserveUsageRequest) (*Subscription, error)
	SweepExpiredSubscriptions(context.Context, SubscriptionSweepExpiredRequest) (*SubscriptionSweepResult, error)
}

// AdmissionRequest uses decimal strings for all persistent identifiers so the
// Go int64 -> JSON -> JavaScript -> D1 boundary never relies on IEEE-754 safe
// integer coercion.
type AdmissionRequest struct {
	RequestID       string `json:"request_id"`
	APIKeyID        string `json:"api_key_id"`
	GroupID         string `json:"group_id"`
	Model           string `json:"model"`
	LeaseTTLSeconds int    `json:"lease_ttl_seconds"`
}

type Lease struct {
	ID        string    `json:"lease_id"`
	RequestID string    `json:"request_id"`
	AccountID string    `json:"account_id"`
	Owner     string    `json:"owner"`
	Epoch     string    `json:"epoch"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Admission struct {
	Account       *service.Account
	Lease         Lease
	UpstreamModel string
	PriceCard     AdmittedPriceCard
}

type CompletionRequest struct {
	SchemaVersion         string `json:"schema_version"`
	EventType             string `json:"event_type"`
	EventID               string `json:"event_id"`
	RequestID             string `json:"request_id"`
	APIKeyID              string `json:"api_key_id"`
	AccountID             string `json:"account_id"`
	LeaseID               string `json:"lease_id"`
	LeaseEpoch            string `json:"lease_epoch"`
	Outcome               string `json:"outcome"`
	UsageState            string `json:"usage_state"`
	InputTokens           string `json:"input_tokens"`
	ImageInputTokens      string `json:"image_input_tokens"`
	OutputTokens          string `json:"output_tokens"`
	ImageOutputTokens     string `json:"image_output_tokens"`
	CacheCreationTokens   string `json:"cache_creation_tokens"`
	CacheCreation5mTokens string `json:"cache_creation_5m_tokens"`
	CacheCreation1hTokens string `json:"cache_creation_1h_tokens"`
	CacheReadTokens       string `json:"cache_read_tokens"`
	ServiceTier           string `json:"service_tier"`
	ReasoningEffort       string `json:"reasoning_effort"`
	Model                 string `json:"model"`
	UpstreamModel         string `json:"upstream_model"`
	UpstreamID            string `json:"upstream_request_id,omitempty"`
	DurationMillis        string `json:"duration_ms"`
}

type StartRequest struct {
	RequestID     string `json:"request_id"`
	APIKeyID      string `json:"api_key_id"`
	AccountID     string `json:"account_id"`
	LeaseID       string `json:"lease_id"`
	LeaseEpoch    string `json:"lease_epoch"`
	Model         string `json:"model"`
	UpstreamModel string `json:"upstream_model"`
}

type RenewRequest struct {
	RequestID  string `json:"request_id"`
	AccountID  string `json:"account_id"`
	LeaseID    string `json:"lease_id"`
	Owner      string `json:"owner"`
	Epoch      string `json:"epoch"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type ReleaseRequest struct {
	RequestID string `json:"request_id"`
	AccountID string `json:"account_id"`
	LeaseID   string `json:"lease_id"`
	Owner     string `json:"owner"`
	Epoch     string `json:"epoch"`
}
