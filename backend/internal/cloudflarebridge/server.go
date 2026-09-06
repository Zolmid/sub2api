package cloudflarebridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/Wei-Shaw/sub2api/internal/web"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var ErrLeaseLost = errors.New("cloudflare account lease lost")

type gatewayHandler struct {
	control         ControlPlane
	forwarder       *service.OpenAIGatewayService
	leaseTTLSeconds int
}

func NewHandler(runtime *RuntimeConfig, control ControlPlane, upstream service.HTTPUpstream) (http.Handler, error) {
	if runtime == nil || runtime.Application == nil {
		return nil, errors.New("cloudflare runtime config is required")
	}
	if control == nil {
		return nil, errors.New("cloudflare control plane is required")
	}
	if upstream == nil {
		return nil, errors.New("upstream transport is required")
	}
	if runtime.LeaseTTLSeconds < 3 {
		return nil, errors.New("lease TTL must be at least three seconds")
	}

	gin.SetMode(runtime.Application.Server.Mode)
	router := gin.New()
	router.Use(middleware.Recovery())
	router.Use(middleware.SecurityHeaders(runtime.Application.Security.CSP, nil))
	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, fmt.Errorf("disable trusted proxies: %w", err)
	}

	apiKeyRepo := NewAPIKeyRepository(control)
	authUserRepo := NewAuthUserRepository(control)
	groupReader := NewManagedGroupReader(control)
	apiKeyService := service.NewAPIKeyService(apiKeyRepo, authUserRepo, groupReader, emptySubscriptionReader{}, nil, nil, runtime.Application)
	apiKeyAuthMiddleware := middleware.NewAPIKeyAuthMiddleware(apiKeyService, nil, runtime.Application)
	userAuthService := service.NewAuthService(nil, authUserRepo, nil, nil, runtime.Application, nil, nil, nil, nil, nil, nil, nil, nil)
	userAPIHandler := newCloudflareUserAPIHandler(userAuthService, authUserRepo, apiKeyService)
	adminAPIHandler := newCloudflareAdminAPIHandler(control)
	jwtAuthMiddleware := middleware.NewJWTAuthMiddlewareWithReader(userAuthService, authUserRepo, nil, nil, nil)
	adminAuthMiddleware := middleware.NewAdminAuthMiddlewareWithReader(userAuthService, authUserRepo, nil, nil)
	forwarder := service.NewCloudflareVerticalSliceOpenAIGatewayService(runtime.Application, upstream)
	handler := &gatewayHandler{
		control:         control,
		forwarder:       forwarder,
		leaseTTLSeconds: runtime.LeaseTTLSeconds,
	}

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "deployment_mode": DeploymentModeValue})
	})
	router.GET("/setup/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"data": gin.H{"needs_setup": false, "step": "completed"},
		})
	})

	v1 := router.Group("/api/v1")
	v1.GET("/settings/public", userAPIHandler.PublicSettings)
	v1.POST("/auth/login", userAPIHandler.Login)
	authenticated := v1.Group("")
	authenticated.Use(gin.HandlerFunc(jwtAuthMiddleware))
	keys := authenticated.Group("/keys")
	keys.GET("", userAPIHandler.ListAPIKeys)
	keys.GET("/:id", userAPIHandler.GetAPIKey)
	keys.POST("", userAPIHandler.CreateAPIKey)
	keys.PUT("/:id", userAPIHandler.UpdateAPIKey)
	keys.DELETE("/:id", userAPIHandler.DeleteAPIKey)
	authenticated.GET("/groups/available", userAPIHandler.GetAvailableGroups)
	authenticated.GET("/auth/me", userAPIHandler.CurrentUser)
	admin := v1.Group("/admin")
	admin.Use(gin.HandlerFunc(adminAuthMiddleware))
	admin.GET("/users", adminAPIHandler.ListUsers)
	admin.GET("/users/:id", adminAPIHandler.GetUser)
	admin.GET("/groups", adminAPIHandler.ListGroups)
	admin.GET("/groups/all", adminAPIHandler.ListAllGroups)
	admin.GET("/groups/:id", adminAPIHandler.GetGroup)
	admin.POST("/groups", adminAPIHandler.CreateGroup)
	admin.PUT("/groups/:id", adminAPIHandler.UpdateGroup)
	admin.DELETE("/groups/:id", adminAPIHandler.DeleteGroup)
	admin.GET("/accounts", adminAPIHandler.ListAccounts)
	admin.GET("/accounts/:id", adminAPIHandler.GetAccount)

	gateway := router.Group("/v1")
	gateway.Use(middleware.RequestBodyLimit(runtime.Application.Gateway.TextMaxBodySize))
	gateway.Use(middleware.ClientRequestID())
	gateway.Use(gin.HandlerFunc(apiKeyAuthMiddleware))
	gateway.POST("/chat/completions", handler.chatCompletions)

	// The embedded middleware deliberately bypasses API and gateway paths, then
	// serves static assets and SPA fallbacks. The non-embed build remains useful
	// for traditional unit checks and does not install this composition layer.
	if web.HasEmbeddedFrontend() {
		frontend, err := web.NewFrontendServer(userAPIHandler)
		if err != nil {
			return nil, fmt.Errorf("initialize embedded frontend: %w", err)
		}
		router.Use(frontend.Middleware())
	}

	return router, nil
}

// emptySubscriptionReader is intentionally narrow: the current Cloudflare
// slice admits standard OpenAI groups only. A direct subscription lookup is an
// unsupported capability and therefore fails closed.
type emptySubscriptionReader struct{}

func (emptySubscriptionReader) GetActiveByUserIDAndGroupID(context.Context, int64, int64) (*service.UserSubscription, error) {
	return nil, ErrNotMigrated
}

func (emptySubscriptionReader) ListActiveByUserID(context.Context, int64) ([]service.UserSubscription, error) {
	return []service.UserSubscription{}, nil
}

func (h *gatewayHandler) chatCompletions(c *gin.Context) {
	apiKey, ok := middleware.GetAPIKeyFromContext(c)
	if !ok || apiKey == nil || apiKey.GroupID == nil {
		writeGatewayError(c, http.StatusForbidden, "GROUP_REQUIRED", "API key must be assigned to a migrated group")
		return
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		writeGatewayError(c, http.StatusBadRequest, "INVALID_REQUEST", "Failed to read request body")
		return
	}
	parsed, err := service.ParseGatewayRequest(service.NewRequestBodyRef(body), "chat_completions")
	if err != nil {
		writeGatewayError(c, http.StatusBadRequest, "INVALID_REQUEST", "Failed to parse request body")
		return
	}
	if strings.TrimSpace(parsed.Model) == "" {
		writeGatewayError(c, http.StatusBadRequest, "INVALID_REQUEST", "model is required")
		return
	}
	if _, err := service.ValidateOpenAIServiceTierField(body); err != nil {
		writeGatewayError(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	requestID := uuid.NewString()
	admission, err := h.control.Admit(c.Request.Context(), AdmissionRequest{
		RequestID:       requestID,
		APIKeyID:        strconv.FormatInt(apiKey.ID, 10),
		GroupID:         strconv.FormatInt(*apiKey.GroupID, 10),
		Model:           parsed.Model,
		LeaseTTLSeconds: h.leaseTTLSeconds,
	})
	if err != nil {
		status := http.StatusServiceUnavailable
		code := "ADMISSION_UNAVAILABLE"
		if errors.Is(err, ErrAdmissionRejected) {
			status = http.StatusTooManyRequests
			code = "ACCOUNT_CONCURRENCY_EXHAUSTED"
		}
		writeGatewayError(c, status, code, "No account capacity is currently available")
		return
	}
	if admission == nil || admission.Account == nil {
		writeGatewayError(c, http.StatusServiceUnavailable, "ADMISSION_INVALID", "Account admission returned no account")
		return
	}

	leaseCtx, cancelRequest := context.WithCancelCause(c.Request.Context())
	requestCtx := service.WithCloudflareLeaseBoundUpstreamContext(leaseCtx)
	c.Request = c.Request.WithContext(requestCtx)
	keeper := startLeaseKeeper(requestCtx, h.control, admission.Lease, h.leaseTTLSeconds, cancelRequest)
	defer func() {
		keeper.Stop()
		lease := keeper.Lease()
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.control.Release(releaseCtx, ReleaseRequest{
			RequestID: lease.RequestID,
			AccountID: lease.AccountID,
			LeaseID:   lease.ID,
			Owner:     lease.Owner,
			Epoch:     lease.Epoch,
		}); err != nil {
			slog.Error("cloudflare lease release failed", "request_id", requestID, "account_id", lease.AccountID, "error", err)
		}
		cancelRequest(nil)
	}()

	startedAt := time.Now()
	result, forwardErr := h.forwarder.ForwardAsChatCompletions(requestCtx, c, admission.Account, body, "", admission.UpstreamModel)
	outcome := OutcomeSucceeded
	usageState := UsageUnknown
	completion := CompletionRequest{
		SchemaVersion:   ProtocolVersion,
		EventType:       UsageEventType,
		EventID:         requestID + ":usage:v1",
		RequestID:       requestID,
		APIKeyID:        strconv.FormatInt(apiKey.ID, 10),
		AccountID:       strconv.FormatInt(admission.Account.ID, 10),
		LeaseID:         admission.Lease.ID,
		LeaseEpoch:      admission.Lease.Epoch,
		Outcome:         outcome,
		UsageState:      usageState,
		InputTokens:     "0",
		OutputTokens:    "0",
		CacheReadTokens: "0",
		Model:           parsed.Model,
		UpstreamModel:   admission.UpstreamModel,
		DurationMillis:  strconv.FormatInt(time.Since(startedAt).Milliseconds(), 10),
	}
	if forwardErr != nil {
		completion.Outcome = OutcomeFailed
	}
	if result != nil {
		completion.InputTokens = strconv.Itoa(result.Usage.InputTokens)
		completion.OutputTokens = strconv.Itoa(result.Usage.OutputTokens)
		completion.CacheReadTokens = strconv.Itoa(result.Usage.CacheReadInputTokens)
		if strings.TrimSpace(result.UpstreamModel) != "" {
			completion.UpstreamModel = result.UpstreamModel
		}
		completion.UpstreamID = result.RequestID
		completion.DurationMillis = strconv.FormatInt(result.Duration.Milliseconds(), 10)
		if result.Usage.InputTokens != 0 || result.Usage.OutputTokens != 0 || result.Usage.CacheReadInputTokens != 0 {
			completion.UsageState = UsageConfirmed
		}
	}

	completionCtx, cancelCompletion := context.WithTimeout(context.Background(), 10*time.Second)
	completionErr := h.control.Complete(completionCtx, completion)
	cancelCompletion()
	if completionErr != nil {
		// The D1 admission row remains pending for reconciliation. A successful
		// upstream response may already be streaming, so replacing it with a late
		// synthetic error would corrupt the protocol.
		slog.Error("cloudflare completion persistence failed", "request_id", requestID, "account_id", completion.AccountID, "error", completionErr)
	}

	if forwardErr != nil && !c.Writer.Written() {
		status := http.StatusBadGateway
		code := "UPSTREAM_ERROR"
		if errors.Is(context.Cause(requestCtx), ErrLeaseLost) {
			status = http.StatusServiceUnavailable
			code = "ACCOUNT_LEASE_LOST"
		}
		writeGatewayError(c, status, code, "Upstream request failed")
	}
}

func writeGatewayError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{
		"error": gin.H{
			"type":    code,
			"message": message,
		},
	})
}

type leaseKeeper struct {
	control ControlPlane
	ttl     int
	cancel  context.CancelCauseFunc

	mu    sync.RWMutex
	lease Lease
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
}

func startLeaseKeeper(ctx context.Context, control ControlPlane, lease Lease, ttl int, cancel context.CancelCauseFunc) *leaseKeeper {
	keeper := &leaseKeeper{
		control: control,
		ttl:     ttl,
		cancel:  cancel,
		lease:   lease,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go keeper.run(ctx)
	return keeper
}

func (k *leaseKeeper) run(ctx context.Context) {
	defer close(k.done)
	interval := time.Duration(k.ttl) * time.Second / 3
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-k.stop:
			return
		case <-ticker.C:
			lease := k.Lease()
			renewCtx, cancel := context.WithTimeout(context.Background(), minDuration(5*time.Second, interval))
			renewed, err := k.control.Renew(renewCtx, RenewRequest{
				RequestID:  lease.RequestID,
				AccountID:  lease.AccountID,
				LeaseID:    lease.ID,
				Owner:      lease.Owner,
				Epoch:      lease.Epoch,
				TTLSeconds: k.ttl,
			})
			cancel()
			if err == nil && renewed != nil {
				k.mu.Lock()
				k.lease = *renewed
				k.mu.Unlock()
				continue
			}
			if time.Now().After(lease.ExpiresAt) {
				k.cancel(ErrLeaseLost)
				return
			}
		}
	}
}

func (k *leaseKeeper) Lease() Lease {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.lease
}

func (k *leaseKeeper) Stop() {
	k.once.Do(func() { close(k.stop) })
	<-k.done
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
