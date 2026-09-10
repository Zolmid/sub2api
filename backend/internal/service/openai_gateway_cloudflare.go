package service

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// NewCloudflareVerticalSliceOpenAIGatewayService composes the existing OpenAI
// protocol forwarder without the PostgreSQL/Redis-backed scheduling graph. It
// is intentionally narrow: authentication, admission, account selection,
// leases, and usage persistence are supplied by the Cloudflare bridge before
// and after this service runs. It must not be used to claim that management or
// billing repositories have been fully migrated.
func NewCloudflareVerticalSliceOpenAIGatewayService(cfg *config.Config, httpUpstream HTTPUpstream) *OpenAIGatewayService {
	return NewOpenAIGatewayService(
		nil, // account repository: selection is performed by the Worker control plane
		nil, // usage log repository: completion is persisted through the bridge
		nil, // usage billing repository
		nil, // user repository
		nil, // subscription repository
		nil, // user-group rate repository
		nil, // gateway cache
		cfg,
		nil, // scheduler snapshot
		nil, // concurrency service: AccountLeaseDO owns the admitted lease
		nil, // billing service
		nil, // rate-limit service
		nil, // billing cache service
		cloudflareUsageObservingUpstream{next: httpUpstream},
		nil, // deferred service
		nil, // OpenAI token provider: first slice uses API-key accounts
		nil, // Grok token provider
		nil, // model pricing resolver
		nil, // channel service
		nil, // balance notification service
		nil, // setting service
		nil, // user platform quota repository
	)
}

// ForwardCloudflareResponses keeps the mature Responses forwarding path while
// making the Worker's admitted model authoritative for this one request. The
// account is cloned so concurrent requests and traditional deployments never
// observe the temporary mapping.
func (s *OpenAIGatewayService) ForwardCloudflareResponses(
	ctx context.Context,
	c *gin.Context,
	account *Account,
	body []byte,
	requestedModel string,
	mappedModel string,
) (*OpenAIForwardResult, error) {
	return s.forwardCloudflareObserved(ctx, account, requestedModel, mappedModel, false, func(observedCtx context.Context, mappedAccount *Account) (*OpenAIForwardResult, error) {
		return s.Forward(observedCtx, c, mappedAccount, body)
	})
}

// ForwardCloudflareMessages applies the same request-local model authority to
// the existing Anthropic Messages compatibility path.
func (s *OpenAIGatewayService) ForwardCloudflareMessages(
	ctx context.Context,
	c *gin.Context,
	account *Account,
	body []byte,
	requestedModel string,
	mappedModel string,
) (*OpenAIForwardResult, error) {
	return s.forwardCloudflareObserved(ctx, account, requestedModel, mappedModel, false, func(observedCtx context.Context, mappedAccount *Account) (*OpenAIForwardResult, error) {
		return s.ForwardAsAnthropic(observedCtx, c, mappedAccount, body, "", mappedModel)
	})
}

// ForwardCloudflareEmbeddings reuses the existing OpenAI embeddings forwarder
// while making the Worker's per-request model mapping authoritative. Unlike
// converted protocols, embeddings has a raw JSON response, so confirm usage
// only after the raw upstream usage object is structurally valid.
func (s *OpenAIGatewayService) ForwardCloudflareEmbeddings(
	ctx context.Context,
	c *gin.Context,
	account *Account,
	body []byte,
	requestedModel string,
	mappedModel string,
) (*OpenAIForwardResult, error) {
	return s.forwardCloudflareObserved(ctx, account, requestedModel, mappedModel, true, func(observedCtx context.Context, mappedAccount *Account) (*OpenAIForwardResult, error) {
		return s.ForwardEmbeddings(observedCtx, c, mappedAccount, body, mappedModel)
	})
}

func (s *OpenAIGatewayService) forwardCloudflareObserved(
	ctx context.Context,
	account *Account,
	requestedModel string,
	mappedModel string,
	validateEmbeddingsUsage bool,
	forward func(context.Context, *Account) (*OpenAIForwardResult, error),
) (*OpenAIForwardResult, error) {
	observation := &cloudflareUsageObservation{validateEmbeddingsUsage: validateEmbeddingsUsage}
	observedCtx := context.WithValue(ctx, cloudflareUsageObservationKey{}, observation)
	result, err := forward(observedCtx, cloudflareAccountWithMappedModel(account, requestedModel, mappedModel))
	if result != nil && observation.UsagePresent() {
		result.UsagePresent = true
	}
	return result, err
}

func cloudflareAccountWithMappedModel(account *Account, requestedModel, mappedModel string) *Account {
	requestedModel = strings.TrimSpace(requestedModel)
	mappedModel = strings.TrimSpace(mappedModel)
	if account == nil || requestedModel == "" || mappedModel == "" {
		return account
	}

	clone := *account
	clone.Credentials = make(map[string]any, len(account.Credentials)+1)
	for key, value := range account.Credentials {
		clone.Credentials[key] = value
	}
	mapping := make(map[string]any)
	for key, value := range account.GetModelMapping() {
		mapping[key] = value
	}
	mapping[requestedModel] = mappedModel
	clone.Credentials["model_mapping"] = mapping
	clone.modelMappingCache = nil
	clone.modelMappingCacheReady = false
	return &clone
}

type cloudflareUsageObservationKey struct{}

type cloudflareUsageObservation struct {
	present                 atomic.Bool
	validateEmbeddingsUsage bool
	scanner                 cloudflareUsageKeyScanner
}

func (o *cloudflareUsageObservation) Write(data []byte) bool {
	if o == nil {
		return false
	}
	if o.validateEmbeddingsUsage {
		return o.scanner.WriteEmbeddings(data)
	}
	return o.scanner.Write(data)
}

func (o *cloudflareUsageObservation) UsagePresent() bool {
	if o == nil {
		return false
	}
	return o.present.Load()
}

func hasValidCloudflareEmbeddingsUsageObject(usage gjson.Result) bool {
	if !usage.Exists() || !usage.IsObject() {
		return false
	}

	found := false
	for _, key := range [...]string{"prompt_tokens", "completion_tokens", "input_tokens", "output_tokens", "total_tokens"} {
		value := usage.Get(key)
		if !value.Exists() {
			continue
		}
		found = true
		if value.Type != gjson.Number {
			return false
		}
		count, err := strconv.ParseInt(value.Raw, 10, 64)
		if err != nil || count < 0 {
			return false
		}
	}
	return found
}

// cloudflareUsageObservingUpstream observes the upstream wire representation,
// before protocol conversion can synthesize an empty usage object. It records
// presence only; the mature forwarder remains authoritative for token values.
type cloudflareUsageObservingUpstream struct {
	next HTTPUpstream
}

func (u cloudflareUsageObservingUpstream) Do(req *http.Request, proxyURL string, accountID int64, accountConcurrency int) (*http.Response, error) {
	resp, err := u.next.Do(req, proxyURL, accountID, accountConcurrency)
	return wrapCloudflareUsageResponse(req, resp), err
}

func (u cloudflareUsageObservingUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, accountConcurrency int, profile *tlsfingerprint.Profile) (*http.Response, error) {
	resp, err := u.next.DoWithTLS(req, proxyURL, accountID, accountConcurrency, profile)
	return wrapCloudflareUsageResponse(req, resp), err
}

func wrapCloudflareUsageResponse(req *http.Request, resp *http.Response) *http.Response {
	if req == nil || resp == nil || resp.Body == nil {
		return resp
	}
	observation, _ := req.Context().Value(cloudflareUsageObservationKey{}).(*cloudflareUsageObservation)
	if observation == nil {
		return resp
	}
	resp.Body = &cloudflareUsageObservingBody{ReadCloser: resp.Body, observation: observation}
	return resp
}

type cloudflareUsageObservingBody struct {
	io.ReadCloser
	observation *cloudflareUsageObservation
}

func (b *cloudflareUsageObservingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 && (b.observation.validateEmbeddingsUsage || !b.observation.present.Load()) && b.observation.Write(p[:n]) {
		b.observation.present.Store(true)
	}
	return n, err
}

// cloudflareUsageKeyScanner recognizes a JSON object named "usage" that has a
// direct token-count field. It is incremental across arbitrary Read boundaries
// and ignores matching text inside JSON strings, so metadata or generated text
// containing a nested object named usage cannot confirm billing by itself.
type cloudflareUsageKeyScanner struct {
	inString       bool
	escaped        bool
	stringValue    [24]byte
	stringLength   int
	stringOverflow bool
	waitingColon   bool
	waitingValue   bool
	pendingKey     string
	objectDepth    int
	objectParents  [16]string
	usageDepth     int
	embeddings     bool
	capture        cloudflareEmbeddingsUsageCapture
}

// cloudflareEmbeddingsUsageCapture keeps only the raw top-level usage object,
// never the embedding vector payload. The cap is deliberately far below the
// existing upstream response limit; an oversized usage object is unconfirmed.
const cloudflareEmbeddingsUsageCaptureMaxBytes = 64 << 10

type cloudflareEmbeddingsUsageCapture struct {
	active    bool
	completed bool
	overflow  bool
	inString  bool
	escaped   bool
	depth     int
	body      []byte
}

func (c *cloudflareEmbeddingsUsageCapture) Start(ch byte) {
	c.active = true
	c.Write(ch)
}

func (c *cloudflareEmbeddingsUsageCapture) Write(ch byte) bool {
	if !c.active {
		return false
	}
	if len(c.body) >= cloudflareEmbeddingsUsageCaptureMaxBytes {
		c.overflow = true
		c.active = false
		c.completed = true
		return false
	}
	c.body = append(c.body, ch)
	if c.inString {
		if c.escaped {
			c.escaped = false
			return false
		}
		if ch == '\\' {
			c.escaped = true
			return false
		}
		if ch == '"' {
			c.inString = false
		}
		return false
	}
	switch ch {
	case '"':
		c.inString = true
	case '{':
		c.depth++
	case '}':
		c.depth--
		if c.depth == 0 {
			c.active = false
			c.completed = true
			return !c.overflow && gjson.ValidBytes(c.body) && hasValidCloudflareEmbeddingsUsageObject(gjson.ParseBytes(c.body))
		}
	}
	return false
}

func (s *cloudflareUsageKeyScanner) WriteEmbeddings(data []byte) bool {
	s.embeddings = true
	return s.Write(data)
}

func (s *cloudflareUsageKeyScanner) Write(data []byte) bool {
	for _, ch := range data {
		if s.embeddings && s.capture.active {
			if s.capture.Write(ch) {
				return true
			}
			continue
		}
		if s.inString {
			if s.escaped {
				s.escaped = false
				s.stringOverflow = true
				continue
			}
			if ch == '\\' {
				s.escaped = true
				continue
			}
			if ch == '"' {
				s.inString = false
				s.pendingKey = ""
				if !s.stringOverflow {
					s.pendingKey = string(s.stringValue[:s.stringLength])
				}
				s.waitingColon = true
				continue
			}
			if s.stringLength < len(s.stringValue) {
				s.stringValue[s.stringLength] = ch
			} else {
				s.stringOverflow = true
			}
			s.stringLength++
			continue
		}

		if s.waitingColon {
			if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
				continue
			}
			s.waitingColon = false
			if ch == ':' {
				if !s.embeddings && s.usageDepth > 0 && s.objectDepth == s.usageDepth &&
					isCloudflareUsageTokenKey(s.pendingKey) {
					return true
				}
				s.waitingValue = true
				continue
			}
			s.pendingKey = ""
		}
		if s.waitingValue {
			if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
				continue
			}
			key := s.pendingKey
			s.waitingValue = false
			s.pendingKey = ""
			if ch == '{' {
				captureUsage := s.embeddings && !s.capture.completed && key == "usage" && s.objectDepth == 1
				s.openObject(key)
				if captureUsage {
					s.capture.Start(ch)
				}
				continue
			}
		}
		switch ch {
		case '{':
			s.openObject("")
			continue
		case '}':
			if s.objectDepth == s.usageDepth {
				s.usageDepth = 0
			}
			if s.objectDepth > 0 {
				if s.objectDepth < len(s.objectParents) {
					s.objectParents[s.objectDepth] = ""
				}
				s.objectDepth--
			}
			continue
		}
		if ch == '"' {
			s.inString = true
			s.escaped = false
			s.stringLength = 0
			s.stringOverflow = false
		}
	}
	return false
}

func (s *cloudflareUsageKeyScanner) openObject(key string) {
	containingDepth := s.objectDepth
	s.objectDepth++
	if s.objectDepth < len(s.objectParents) {
		s.objectParents[s.objectDepth] = key
	}
	if key != "usage" || s.usageDepth != 0 {
		return
	}
	if containingDepth == 1 {
		s.usageDepth = s.objectDepth
		return
	}
	if containingDepth == 2 && containingDepth < len(s.objectParents) {
		parent := s.objectParents[containingDepth]
		if parent == "response" || parent == "message" {
			s.usageDepth = s.objectDepth
		}
	}
}

func isCloudflareUsageTokenKey(value string) bool {
	switch value {
	case "input_tokens", "output_tokens", "prompt_tokens", "completion_tokens", "total_tokens":
		return true
	default:
		return false
	}
}
