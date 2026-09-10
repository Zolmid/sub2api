package cloudflarebridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	geminiForwarder *geminiGatewayForwarder
	leaseTTLSeconds int
}

type gatewayProtocol int

const (
	gatewayProtocolChatCompletions gatewayProtocol = iota
	gatewayProtocolResponses
	gatewayProtocolMessages
	gatewayProtocolEmbeddings
	gatewayProtocolGemini
)

// deferredResponseWriter keeps a non-streaming upstream response private until
// the authoritative billing completion has committed. Streaming responses
// cannot be retracted after bytes are flushed and therefore bypass this buffer.
type deferredResponseWriter struct {
	gin.ResponseWriter
	header http.Header
	body   bytes.Buffer
	status int
}

func newDeferredResponseWriter(parent gin.ResponseWriter) *deferredResponseWriter {
	return &deferredResponseWriter{
		ResponseWriter: parent,
		header:         make(http.Header),
		status:         http.StatusOK,
	}
}

func (w *deferredResponseWriter) Header() http.Header { return w.header }

func (w *deferredResponseWriter) WriteHeader(status int) {
	if w.Written() {
		return
	}
	w.status = status
}

func (w *deferredResponseWriter) WriteHeaderNow() {}

func (w *deferredResponseWriter) Write(data []byte) (int, error) {
	return w.body.Write(data)
}

func (w *deferredResponseWriter) WriteString(value string) (int, error) {
	return w.body.WriteString(value)
}

func (w *deferredResponseWriter) Status() int { return w.status }
func (w *deferredResponseWriter) Size() int   { return w.body.Len() }
func (w *deferredResponseWriter) Written() bool {
	return w.body.Len() > 0 || w.status != http.StatusOK
}
func (w *deferredResponseWriter) Flush() {}

func (w *deferredResponseWriter) commit() error {
	for key, values := range w.header {
		w.ResponseWriter.Header()[key] = append([]string(nil), values...)
	}
	w.ResponseWriter.WriteHeader(w.status)
	_, err := w.ResponseWriter.Write(w.body.Bytes())
	return err
}

func NewHandler(runtime *RuntimeConfig, control ControlPlane, upstream service.HTTPUpstream) (http.Handler, error) {
	return NewHandlerWithJobExecutionRegistry(runtime, control, upstream, defaultJobExecutionRegistry())
}

// NewHandlerWithJobExecutionRegistry provides the narrow composition seam for
// future internal route adapters. NewHandler remains deterministic and only
// supplies the built-in manual-review adapters.
func NewHandlerWithJobExecutionRegistry(runtime *RuntimeConfig, control ControlPlane, upstream service.HTTPUpstream, jobExecutors JobExecutionRegistry) (http.Handler, error) {
	settingsRepository, err := cloudflareSettingsRepository(control)
	if err != nil {
		return nil, err
	}
	return newHandler(runtime, control, upstream, settingsRepository, jobExecutors)
}

// cloudflareSettingsRepository selects the production-only Worker adapter.
//
// The bridge must not fall back to the traditional PostgreSQL/Redis settings
// stack: that would make auth decisions depend on a different authority than
// the Worker-backed session store. Package-local tests can inject a deterministic
// repository through cloudflareSettingsRepositoryProvider; production callers
// can only reach the HTTPControlPlane branch.
func cloudflareSettingsRepository(control ControlPlane) (service.SettingRepository, error) {
	if httpControl, ok := control.(*HTTPControlPlane); ok {
		if httpControl == nil {
			return nil, errors.New("cloudflare HTTP settings control plane is required")
		}
		return NewSettingsRepository(httpControl), nil
	}
	provider, ok := control.(cloudflareSettingsRepositoryProvider)
	if !ok {
		return nil, errors.New("cloudflare settings repository is required")
	}
	repository := provider.cloudflareSettingsRepository()
	if repository == nil {
		return nil, errors.New("cloudflare settings repository is required")
	}
	return repository, nil
}

// cloudflareSettingsRepositoryProvider is deliberately package-private. It is
// an explicit test seam for fake ControlPlanes, not a production fallback.
type cloudflareSettingsRepositoryProvider interface {
	cloudflareSettingsRepository() service.SettingRepository
}

func newHandler(runtime *RuntimeConfig, control ControlPlane, upstream service.HTTPUpstream, settingsRepository service.SettingRepository, jobExecutors JobExecutionRegistry) (http.Handler, error) {
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
	if settingsRepository == nil {
		return nil, errors.New("cloudflare settings repository is required")
	}

	gin.SetMode(runtime.Application.Server.Mode)
	router := gin.New()
	router.Use(middleware.Recovery())
	router.Use(middleware.SecurityHeaders(runtime.Application.Security.CSP, nil))
	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, fmt.Errorf("disable trusted proxies: %w", err)
	}
	// Keep token issuance and JWT/refresh validation on one bounded client
	// fingerprint, matching the traditional composition root.
	router.Use(middleware.SessionBindingContext(runtime.Application))

	apiKeyRepo := NewAPIKeyRepository(control)
	authUserRepo := NewAuthUserRepository(control)
	totpControl, ok := control.(TOTPControlPlane)
	if !ok {
		return nil, errors.New("cloudflare totp control plane is required")
	}
	authSessionCache, ok := control.(service.RefreshTokenCache)
	if !ok {
		return nil, errors.New("cloudflare auth session control plane is required")
	}
	groupReader := NewManagedGroupReader(control)
	settingService := service.NewSettingService(settingsRepository, runtime.Application)
	apiKeyService := service.NewAPIKeyService(apiKeyRepo, authUserRepo, groupReader, emptySubscriptionReader{}, nil, nil, runtime.Application)
	apiKeyAuthMiddleware := middleware.NewAPIKeyAuthMiddleware(apiKeyService, nil, runtime.Application)
	userAuthService := service.NewAuthService(nil, authUserRepo, nil, authSessionCache, runtime.Application, settingService, nil, nil, nil, nil, nil, nil, nil)
	userAPIHandler := newCloudflareUserAPIHandler(userAuthService, authUserRepo, apiKeyService, totpControl, settingService)
	totpAPIHandler, err := newCloudflareTOTPHandler(control, authUserRepo)
	if err != nil {
		return nil, fmt.Errorf("initialize cloudflare totp handler: %w", err)
	}
	adminAPIHandler := newCloudflareAdminAPIHandler(control)
	jwtAuthMiddleware := middleware.NewJWTAuthMiddlewareWithReader(userAuthService, authUserRepo, nil, settingService, nil)
	adminAuthMiddleware := middleware.NewAdminAuthMiddlewareWithReader(userAuthService, authUserRepo, settingService, nil)
	forwarder := service.NewCloudflareVerticalSliceOpenAIGatewayService(runtime.Application, upstream)
	handler := &gatewayHandler{
		control:         control,
		forwarder:       forwarder,
		geminiForwarder: newGeminiGatewayForwarder(forwarder),
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
	// This private Container RPC is deliberately registered as one exact route.
	// Its handler repeats the authority and path checks because Container-facing
	// routing must not make an externally forwarded request trusted.
	router.POST(jobExecutionPrivatePath, gin.WrapH(newJobExecutionHandler(jobExecutors)))

	v1 := router.Group("/api/v1")
	v1.GET("/settings/public", userAPIHandler.PublicSettings)
	v1.POST("/auth/login", userAPIHandler.Login)
	v1.POST("/auth/login/2fa", userAPIHandler.Login2FA)
	v1.POST("/auth/refresh", userAPIHandler.RefreshToken)
	v1.POST("/auth/logout", userAPIHandler.Logout)
	authenticated := v1.Group("")
	authenticated.Use(gin.HandlerFunc(jwtAuthMiddleware))
	authenticated.Use(middleware.BackendModeUserGuard(settingService))
	keys := authenticated.Group("/keys")
	keys.GET("", userAPIHandler.ListAPIKeys)
	keys.GET("/:id", userAPIHandler.GetAPIKey)
	keys.POST("", userAPIHandler.CreateAPIKey)
	keys.PUT("/:id", userAPIHandler.UpdateAPIKey)
	keys.DELETE("/:id", userAPIHandler.DeleteAPIKey)
	authenticated.GET("/groups/available", userAPIHandler.GetAvailableGroups)
	authenticated.GET("/auth/me", userAPIHandler.CurrentUser)
	authenticated.POST("/auth/revoke-all-sessions", userAPIHandler.RevokeAllSessions)
	totp := authenticated.Group("/user/totp")
	totp.GET("/status", totpAPIHandler.GetStatus)
	totp.GET("/verification-method", totpAPIHandler.GetVerificationMethod)
	totp.POST("/send-code", totpAPIHandler.SendVerifyCode)
	totp.POST("/setup", totpAPIHandler.InitiateSetup)
	totp.POST("/enable", totpAPIHandler.Enable)
	totp.POST("/disable", totpAPIHandler.Disable)
	totp.POST("/step-up", totpAPIHandler.StepUp)
	admin := v1.Group("/admin")
	admin.Use(gin.HandlerFunc(adminAuthMiddleware))
	admin.GET("/users", adminAPIHandler.ListUsers)
	admin.GET("/users/:id", adminAPIHandler.GetUser)
	admin.GET("/users/:id/api-keys", adminAPIHandler.ListUserAPIKeys)
	admin.GET("/users/:id/balance-history", adminAPIHandler.GetBalanceHistory)
	admin.POST("/users", adminAPIHandler.CreateUser)
	admin.PUT("/users/:id", adminAPIHandler.UpdateUser)
	admin.DELETE("/users/:id", adminAPIHandler.DeleteUser)
	admin.POST("/users/:id/balance", adminAPIHandler.UpdateBalance)
	admin.GET("/groups", adminAPIHandler.ListGroups)
	admin.GET("/groups/all", adminAPIHandler.ListAllGroups)
	admin.GET("/groups/:id", adminAPIHandler.GetGroup)
	admin.POST("/groups", adminAPIHandler.CreateGroup)
	admin.PUT("/groups/:id", adminAPIHandler.UpdateGroup)
	admin.DELETE("/groups/:id", adminAPIHandler.DeleteGroup)
	admin.GET("/accounts", adminAPIHandler.ListAccounts)
	admin.GET("/accounts/:id", adminAPIHandler.GetAccount)
	admin.POST("/accounts", adminAPIHandler.CreateAccount)
	admin.PUT("/accounts/:id", adminAPIHandler.UpdateAccount)
	admin.DELETE("/accounts/:id", adminAPIHandler.DeleteAccount)
	admin.PUT("/api-keys/:id", adminAPIHandler.RebindAPIKeyGroup)

	gateway := router.Group("/v1")
	gateway.Use(middleware.RequestBodyLimit(runtime.Application.Gateway.TextMaxBodySize))
	gateway.Use(middleware.ClientRequestID())
	gateway.Use(gin.HandlerFunc(apiKeyAuthMiddleware))
	gateway.POST("/chat/completions", handler.chatCompletions)
	gateway.POST("/responses", handler.responses)
	gateway.POST("/messages", handler.messages)
	gateway.POST("/embeddings", handler.embeddings)
	gemini := router.Group("/v1beta")
	gemini.Use(middleware.RequestBodyLimit(runtime.Application.Gateway.TextMaxBodySize))
	gemini.Use(middleware.ClientRequestID())
	gemini.Use(gin.HandlerFunc(apiKeyAuthMiddleware))
	gemini.POST("/models/:modelAction", handler.gemini)
	embeddingsAlias := router.Group("")
	embeddingsAlias.Use(middleware.RequestBodyLimit(runtime.Application.Gateway.TextMaxBodySize))
	embeddingsAlias.Use(middleware.ClientRequestID())
	embeddingsAlias.Use(gin.HandlerFunc(apiKeyAuthMiddleware))
	embeddingsAlias.POST("/embeddings", handler.embeddings)

	// The embedded middleware deliberately bypasses API and gateway paths, then
	// serves static assets and SPA fallbacks. The non-embed build remains useful
	// for traditional unit checks and does not install this composition layer.
	if web.HasEmbeddedFrontend() {
		//nolint:staticcheck // The embed-tag implementation can return either outcome.
		frontend, err := web.NewFrontendServer(userAPIHandler)
		if err != nil { //nolint:staticcheck // Default-build analysis cannot see the guarded embed-tag implementation.
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
	h.serveGateway(c, gatewayProtocolChatCompletions)
}

func (h *gatewayHandler) responses(c *gin.Context) {
	h.serveGateway(c, gatewayProtocolResponses)
}

func (h *gatewayHandler) messages(c *gin.Context) {
	h.serveGateway(c, gatewayProtocolMessages)
}

func (h *gatewayHandler) embeddings(c *gin.Context) {
	h.serveGateway(c, gatewayProtocolEmbeddings)
}

func (h *gatewayHandler) gemini(c *gin.Context) {
	h.serveGateway(c, gatewayProtocolGemini)
}

func (h *gatewayHandler) serveGateway(c *gin.Context, protocol gatewayProtocol) {
	apiKey, ok := middleware.GetAPIKeyFromContext(c)
	if !ok || apiKey == nil || apiKey.GroupID == nil {
		writeGatewayProtocolError(c, protocol, http.StatusForbidden, "GROUP_REQUIRED", "API key must be assigned to a migrated group")
		return
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeGatewayProtocolError(c, protocol, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body exceeds the configured limit")
			return
		}
		writeGatewayProtocolError(c, protocol, http.StatusBadRequest, "INVALID_REQUEST", "Failed to read request body")
		return
	}
	model := ""
	stream := false
	outputEffort := ""
	if protocol == gatewayProtocolGemini {
		parsed, err := parseGeminiGatewayRequest(c, body)
		if err != nil {
			writeGatewayProtocolError(c, protocol, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		model, stream = parsed.model, parsed.stream
	} else {
		parsed, err := service.ParseGatewayRequest(service.NewRequestBodyRef(body), protocol.parserName())
		if err != nil {
			writeGatewayProtocolError(c, protocol, http.StatusBadRequest, "INVALID_REQUEST", "Failed to parse request body")
			return
		}
		body = parsed.Body.Bytes()
		model, stream, outputEffort = parsed.Model, parsed.Stream, parsed.OutputEffort
		if strings.TrimSpace(model) == "" {
			writeGatewayProtocolError(c, protocol, http.StatusBadRequest, "INVALID_REQUEST", "model is required")
			return
		}
	}
	if protocol == gatewayProtocolEmbeddings && stream {
		writeGatewayProtocolError(c, protocol, http.StatusBadRequest, "INVALID_REQUEST", "streaming is not supported for embeddings")
		return
	}
	if protocol != gatewayProtocolMessages && protocol != gatewayProtocolGemini {
		if _, err := service.ValidateOpenAIServiceTierField(body); err != nil {
			writeGatewayProtocolError(c, protocol, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
	}

	requestID := uuid.NewString()
	admission, err := h.control.Admit(c.Request.Context(), AdmissionRequest{
		RequestID:       requestID,
		APIKeyID:        strconv.FormatInt(apiKey.ID, 10),
		GroupID:         strconv.FormatInt(*apiKey.GroupID, 10),
		Model:           model,
		LeaseTTLSeconds: h.leaseTTLSeconds,
	})
	if err != nil {
		status := http.StatusServiceUnavailable
		code := "ADMISSION_UNAVAILABLE"
		message := "No account capacity is currently available"
		if errors.Is(err, ErrInsufficientBalance) {
			status = http.StatusPaymentRequired
			code = "INSUFFICIENT_BALANCE"
			message = "Insufficient balance"
		} else if errors.Is(err, ErrAdmissionRejected) {
			status = http.StatusTooManyRequests
			code = "ACCOUNT_CONCURRENCY_EXHAUSTED"
		}
		writeGatewayProtocolError(c, protocol, status, code, message)
		return
	}
	if admission == nil || admission.Account == nil {
		if admission != nil {
			h.releaseAdmissionLease(requestID, admission.Lease)
		}
		writeGatewayProtocolError(c, protocol, http.StatusServiceUnavailable, "ADMISSION_INVALID", "Account admission returned no account")
		return
	}
	if !protocol.supportsAdmittedAccount(admission.Account) {
		h.releaseAdmissionLease(requestID, admission.Lease)
		writeGatewayProtocolError(c, protocol, http.StatusServiceUnavailable, "ADMISSION_INVALID", "Admitted account is not a supported OpenAI API-key account")
		return
	}

	leaseCtx, cancelRequest := context.WithCancelCause(c.Request.Context())
	var markerStarted atomic.Bool
	requestCtx := service.WithCloudflareLeaseBoundUpstreamContext(leaseCtx)
	requestCtx = service.WithCloudflareUpstreamStartMarker(requestCtx, func(ctx context.Context) error {
		err := h.control.Start(ctx, StartRequest{
			RequestID: requestID, APIKeyID: strconv.FormatInt(apiKey.ID, 10),
			AccountID: strconv.FormatInt(admission.Account.ID, 10),
			LeaseID:   admission.Lease.ID, LeaseEpoch: admission.Lease.Epoch,
			Model: model, UpstreamModel: admission.UpstreamModel,
		})
		if err == nil {
			markerStarted.Store(true)
		}
		return err
	})
	c.Request = c.Request.WithContext(requestCtx)
	keeper := startLeaseKeeper(requestCtx, h.control, admission.Lease, h.leaseTTLSeconds, cancelRequest)
	completionCommitted := false
	defer func() {
		keeper.Stop()
		if !completionCommitted {
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
				slog.Error("cloudflare reservation release failed", "request_id", requestID, "account_id", lease.AccountID, "error", err)
			}
		}
		cancelRequest(nil)
	}()

	startedAt := time.Now()
	originalWriter := c.Writer
	var deferred *deferredResponseWriter
	if !stream {
		deferred = newDeferredResponseWriter(originalWriter)
		c.Writer = deferred
	}
	result, forwardErr := h.forward(protocol, requestCtx, c, admission.Account, body, model, admission.UpstreamModel)
	outcome := OutcomeSucceeded
	usageState := UsageUnknown
	completion := CompletionRequest{
		SchemaVersion:         UsageSchemaVersion,
		EventType:             UsageEventType,
		EventID:               requestID + ":usage:v2",
		RequestID:             requestID,
		APIKeyID:              strconv.FormatInt(apiKey.ID, 10),
		AccountID:             strconv.FormatInt(admission.Account.ID, 10),
		LeaseID:               admission.Lease.ID,
		LeaseEpoch:            admission.Lease.Epoch,
		Outcome:               outcome,
		UsageState:            usageState,
		InputTokens:           "0",
		ImageInputTokens:      "0",
		OutputTokens:          "0",
		ImageOutputTokens:     "0",
		CacheCreationTokens:   "0",
		CacheCreation5mTokens: "0",
		CacheCreation1hTokens: "0",
		CacheReadTokens:       "0",
		Model:                 model,
		UpstreamModel:         admission.UpstreamModel,
		DurationMillis:        strconv.FormatInt(time.Since(startedAt).Milliseconds(), 10),
	}
	if forwardErr != nil {
		completion.Outcome = OutcomeFailed
	}
	if result != nil {
		completion.InputTokens = strconv.Itoa(result.Usage.InputTokens)
		completion.ImageInputTokens = strconv.Itoa(result.Usage.ImageInputTokens)
		completion.OutputTokens = strconv.Itoa(result.Usage.OutputTokens)
		completion.ImageOutputTokens = strconv.Itoa(result.Usage.ImageOutputTokens)
		completion.CacheCreationTokens = strconv.Itoa(result.Usage.CacheCreationInputTokens)
		completion.CacheReadTokens = strconv.Itoa(result.Usage.CacheReadInputTokens)
		if result.ServiceTier != nil {
			completion.ServiceTier = *result.ServiceTier
		}
		if result.ReasoningEffort != nil {
			completion.ReasoningEffort = *result.ReasoningEffort
		} else if protocol == gatewayProtocolMessages && strings.TrimSpace(outputEffort) != "" {
			completion.ReasoningEffort = strings.TrimSpace(outputEffort)
		}
		if strings.TrimSpace(result.UpstreamModel) != "" {
			completion.UpstreamModel = result.UpstreamModel
		}
		completion.UpstreamID = result.RequestID
		completion.DurationMillis = strconv.FormatInt(result.Duration.Milliseconds(), 10)
		if result.UsagePresent {
			completion.UsageState = UsageConfirmed
		}
	}

	var completionErr error
	if markerStarted.Load() {
		completionCtx, cancelCompletion := context.WithTimeout(context.Background(), 10*time.Second)
		completionErr = h.control.Complete(completionCtx, completion)
		cancelCompletion()
		completionCommitted = completionErr == nil
	}
	if markerStarted.Load() && completionErr != nil {
		if deferred != nil {
			c.Writer = originalWriter
			writeGatewayProtocolError(c, protocol, http.StatusBadGateway, "BILLING_COMMIT_FAILED", "Billing settlement could not be committed")
			return
		}
		// The D1 admission row remains pending for reconciliation. A successful
		// upstream response may already be streaming, so replacing it with a late
		// synthetic error would corrupt the protocol.
		slog.Error("cloudflare completion persistence failed", "request_id", requestID, "account_id", completion.AccountID, "error", completionErr)
	}
	if deferred != nil {
		c.Writer = originalWriter
		if deferred.Written() {
			if err := deferred.commit(); err != nil {
				slog.Error("cloudflare buffered response commit failed", "request_id", requestID, "error", err)
				return
			}
		}
	}

	if forwardErr != nil && !c.Writer.Written() {
		status := http.StatusBadGateway
		code := "UPSTREAM_ERROR"
		if errors.Is(context.Cause(requestCtx), ErrLeaseLost) {
			status = http.StatusServiceUnavailable
			code = "ACCOUNT_LEASE_LOST"
		}
		writeGatewayProtocolError(c, protocol, status, code, "Upstream request failed")
	}
}

func (p gatewayProtocol) parserName() string {
	switch p {
	case gatewayProtocolResponses:
		return "responses"
	case gatewayProtocolMessages:
		return service.PlatformAnthropic
	case gatewayProtocolEmbeddings:
		return "embeddings"
	case gatewayProtocolGemini:
		return "gemini"
	default:
		return "chat_completions"
	}
}

func (p gatewayProtocol) supportsAdmittedAccount(account *service.Account) bool {
	if account == nil || account.Platform != service.PlatformOpenAI || account.Type != service.AccountTypeAPIKey {
		return false
	}
	if p == gatewayProtocolEmbeddings {
		return account.IsActive() && account.SupportsOpenAIEndpointCapability(service.OpenAIEndpointCapabilityEmbeddings)
	}
	if p == gatewayProtocolGemini {
		return account.IsActive() && account.SupportsOpenAIEndpointCapability(service.OpenAIEndpointCapabilityResponses)
	}
	return account.IsActive()
}

func (h *gatewayHandler) releaseAdmissionLease(requestID string, lease Lease) {
	releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.control.Release(releaseCtx, ReleaseRequest{
		RequestID: lease.RequestID,
		AccountID: lease.AccountID,
		LeaseID:   lease.ID,
		Owner:     lease.Owner,
		Epoch:     lease.Epoch,
	}); err != nil {
		slog.Error("cloudflare unsupported reservation release failed", "request_id", requestID, "account_id", lease.AccountID, "error", err)
	}
}

func (h *gatewayHandler) forward(
	protocol gatewayProtocol,
	ctx context.Context,
	c *gin.Context,
	account *service.Account,
	body []byte,
	requestedModel string,
	mappedModel string,
) (*service.OpenAIForwardResult, error) {
	switch protocol {
	case gatewayProtocolResponses:
		return h.forwarder.ForwardCloudflareResponses(ctx, c, account, body, requestedModel, mappedModel)
	case gatewayProtocolMessages:
		return h.forwarder.ForwardCloudflareMessages(ctx, c, account, body, requestedModel, mappedModel)
	case gatewayProtocolEmbeddings:
		return h.forwarder.ForwardCloudflareEmbeddings(ctx, c, account, body, requestedModel, mappedModel)
	case gatewayProtocolGemini:
		return h.geminiForwarder.Forward(ctx, c, account, body, requestedModel, mappedModel)
	default:
		return h.forwarder.ForwardAsChatCompletions(ctx, c, account, body, "", mappedModel)
	}
}

func writeGatewayProtocolError(c *gin.Context, protocol gatewayProtocol, status int, code, message string) {
	if protocol == gatewayProtocolGemini {
		c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": status, "status": code, "message": message}})
		return
	}
	if protocol == gatewayProtocolMessages {
		errorType := "api_error"
		switch status {
		case http.StatusBadRequest:
			errorType = "invalid_request_error"
		case http.StatusUnauthorized:
			errorType = "authentication_error"
		case http.StatusForbidden, http.StatusPaymentRequired:
			errorType = "permission_error"
		case http.StatusTooManyRequests:
			errorType = "rate_limit_error"
		}
		c.AbortWithStatusJSON(status, gin.H{
			"type": "error",
			"error": gin.H{
				"type":    errorType,
				"message": message,
			},
		})
		return
	}
	if protocol == gatewayProtocolEmbeddings {
		errorType := "api_error"
		switch status {
		case http.StatusBadRequest:
			errorType = "invalid_request_error"
		case http.StatusUnauthorized:
			errorType = "authentication_error"
		case http.StatusForbidden, http.StatusPaymentRequired:
			errorType = "permission_error"
		case http.StatusTooManyRequests:
			errorType = "rate_limit_error"
		}
		c.AbortWithStatusJSON(status, gin.H{
			"error": gin.H{
				"type":    errorType,
				"message": message,
			},
		})
		return
	}
	writeGatewayError(c, status, code, message)
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
