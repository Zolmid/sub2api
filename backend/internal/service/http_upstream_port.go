package service

import (
	"context"
	"net/http"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

type upstreamStartMarker struct {
	once sync.Once
	fn   func(context.Context) error
	err  error
}
type upstreamStartMarkerKey struct{}
type cloudflareUpstreamBoundaryKey struct{}

func WithCloudflareUpstreamStartMarker(ctx context.Context, fn func(context.Context) error) context.Context {
	if fn == nil {
		return ctx
	}
	// The marker is installed only for a Cloudflare lease-backed gateway
	// attempt. Keep that fact with the request so the shared Go transport can
	// apply the stricter egress boundary without changing traditional mode.
	ctx = context.WithValue(ctx, cloudflareUpstreamBoundaryKey{}, true)
	return context.WithValue(ctx, upstreamStartMarkerKey{}, &upstreamStartMarker{fn: fn})
}

// HTTPUpstreamCloudflareBoundary reports whether this request belongs to the
// Cloudflare-native gateway path. It is intentionally coupled to the start
// marker: an ordinary deployment receives no new egress restrictions.
func HTTPUpstreamCloudflareBoundary(ctx context.Context) bool {
	return ctx != nil && ctx.Value(cloudflareUpstreamBoundaryKey{}) == true
}

// MarkCloudflareUpstreamStarted is a no-op in traditional mode. In Cloudflare
// mode it persists the D1 start transition exactly once before network dispatch.
func MarkCloudflareUpstreamStarted(ctx context.Context) error {
	marker, _ := ctx.Value(upstreamStartMarkerKey{}).(*upstreamStartMarker)
	if marker == nil {
		return nil
	}
	marker.once.Do(func() { marker.err = marker.fn(ctx) })
	return marker.err
}

// HTTPUpstream 上游 HTTP 请求接口
// 用于向上游 API（Claude、OpenAI、Gemini 等）发送请求
type HTTPUpstream interface {
	// Do 执行 HTTP 请求（不启用 TLS 指纹）
	Do(req *http.Request, proxyURL string, accountID int64, accountConcurrency int) (*http.Response, error)

	// DoWithTLS 执行带 TLS 指纹伪装的 HTTP 请求
	//
	// profile 参数:
	//   - nil: 不启用 TLS 指纹，行为与 Do 方法相同
	//   - non-nil: 使用指定的 Profile 进行 TLS 指纹伪装
	//
	// Profile 由调用方通过 TLSFingerprintProfileService 解析后传入，
	// 支持按账号绑定的数据库 profile 或内置默认 profile。
	DoWithTLS(req *http.Request, proxyURL string, accountID int64, accountConcurrency int, profile *tlsfingerprint.Profile) (*http.Response, error)
}
