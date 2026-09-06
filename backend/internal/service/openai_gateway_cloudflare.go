package service

import "github.com/Wei-Shaw/sub2api/internal/config"

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
		httpUpstream,
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
