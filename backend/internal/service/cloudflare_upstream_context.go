package service

import "context"

type cloudflareLeaseBoundUpstreamContextKey struct{}

// WithCloudflareLeaseBoundUpstreamContext marks an upstream request as owned by
// a Cloudflare business lease. Unlike ordinary gateway requests, lease-bound
// work must remain cancelable: continuing after the lease is lost could let two
// owners use the same account concurrently.
//
// Traditional deployments never add this marker, so their existing behavior of
// finishing an upstream request after the client disconnects is unchanged.
func WithCloudflareLeaseBoundUpstreamContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, cloudflareLeaseBoundUpstreamContextKey{}, true)
}

func isCloudflareLeaseBoundUpstreamContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	marked, _ := ctx.Value(cloudflareLeaseBoundUpstreamContextKey{}).(bool)
	return marked
}
