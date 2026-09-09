// Package cloudflareloadcheck runs bounded, dependency-free HTTP load checks.
package cloudflareloadcheck

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	SchemaVersion            = "cloudflare-loadcheck/v2"
	MaxRequests              = 10_000
	MaxConcurrency           = 64
	MaxTimeout               = 2 * time.Minute
	DefaultCancelAfter       = 2 * time.Minute
	MaxCancelAfter           = 10 * time.Minute
	MaxTotalResponseBytes    = 512 << 20
	MaxTotalRequestBodyBytes = 64 << 20
	MaxBaseURLBytes          = 2 << 10
	MaxPathBytes             = 2 << 10
	MaxQueryBytes            = 2 << 10
	MaxMethodBytes           = 32
	MaxHeaderCount           = 32
	MaxHeaderBytes           = 16 << 10
	MaxHeaderNameBytes       = 256
	MaxHeaderValueBytes      = 4 << 10
	MaxRequestBodyBytes      = 1 << 20
	DefaultMaxResponseBytes  = 4 << 20
	MaxResponseBytes         = 64 << 20
)

var errBodyTooLarge = errors.New("response body exceeds configured limit")

// Header is a request header accepted by the tool. Credential-bearing headers are rejected.
type Header struct {
	Name  string
	Value string
}

// Config controls a single bounded run.
type Config struct {
	BaseURL                string
	Path                   string
	Requests               int
	Concurrency            int
	Method                 string
	Body                   string
	Headers                []Header
	Timeout                time.Duration
	MaxResponseBytes       int64
	CancelAfter            time.Duration
	AuthorizedRemoteTarget bool
}

// DefaultConfig is safe to run only against a local gateway unless remote use is authorized explicitly.
func DefaultConfig() Config {
	return Config{
		BaseURL:          "http://127.0.0.1:8787",
		Path:             "/",
		Requests:         1,
		Concurrency:      1,
		Method:           http.MethodGet,
		Timeout:          10 * time.Second,
		MaxResponseBytes: DefaultMaxResponseBytes,
		CancelAfter:      DefaultCancelAfter,
	}
}

// Validate checks bounds, target authorization, and that no credential material is configured.
func (c Config) Validate() error {
	if _, err := c.targetURL(); err != nil {
		return err
	}
	if c.Requests < 1 || c.Requests > MaxRequests {
		return fmt.Errorf("requests must be between 1 and %d", MaxRequests)
	}
	if c.Concurrency < 1 || c.Concurrency > MaxConcurrency || c.Concurrency > c.Requests {
		return fmt.Errorf("concurrency must be between 1 and the smaller of requests and %d", MaxConcurrency)
	}
	if c.Timeout <= 0 || c.Timeout > MaxTimeout {
		return fmt.Errorf("timeout must be positive and no greater than %s", MaxTimeout)
	}
	if c.CancelAfter < 0 || c.CancelAfter > MaxCancelAfter {
		return fmt.Errorf("cancel-after must be between zero and %s", MaxCancelAfter)
	}
	if c.MaxResponseBytes < 1 || c.MaxResponseBytes > MaxResponseBytes {
		return fmt.Errorf("max-response-bytes must be between 1 and %d", MaxResponseBytes)
	}
	if exceedsTotalBytes(c.Requests, c.MaxResponseBytes+1, MaxTotalResponseBytes) {
		return fmt.Errorf("aggregate response read budget exceeds %d bytes", MaxTotalResponseBytes)
	}
	if len(c.Body) > MaxRequestBodyBytes {
		return fmt.Errorf("request body exceeds %d bytes", MaxRequestBodyBytes)
	}
	if exceedsTotalBytes(c.Requests, int64(len(c.Body)), MaxTotalRequestBodyBytes) {
		return fmt.Errorf("aggregate request body budget exceeds %d bytes", MaxTotalRequestBodyBytes)
	}
	if len(c.Method) > MaxMethodBytes {
		return fmt.Errorf("method exceeds %d bytes", MaxMethodBytes)
	}
	if strings.TrimSpace(c.Method) == "" {
		return fmt.Errorf("method must not be empty")
	}
	if _, err := http.NewRequest(c.Method, "http://validation.invalid/", nil); err != nil {
		return fmt.Errorf("method is invalid")
	}
	if len(c.Headers) > MaxHeaderCount {
		return fmt.Errorf("header count exceeds %d", MaxHeaderCount)
	}
	headerBytes := 0
	for _, h := range c.Headers {
		if len(h.Name) > MaxHeaderNameBytes {
			return fmt.Errorf("header name exceeds %d bytes", MaxHeaderNameBytes)
		}
		if len(h.Value) > MaxHeaderValueBytes {
			return fmt.Errorf("header value exceeds %d bytes", MaxHeaderValueBytes)
		}
		if !validHeaderName(h.Name) || !validHeaderValue(h.Value) {
			return fmt.Errorf("headers must have valid single-line names and values")
		}
		if isCredentialHeader(h.Name) {
			return fmt.Errorf("credential-bearing headers are not allowed")
		}
		headerBytes += len(h.Name) + len(h.Value) + 4
	}
	if headerBytes > MaxHeaderBytes {
		return fmt.Errorf("combined header size exceeds %d bytes", MaxHeaderBytes)
	}
	return nil
}

func (c Config) targetURL() (*url.URL, error) {
	if len(c.BaseURL) > MaxBaseURLBytes {
		return nil, fmt.Errorf("base URL exceeds %d bytes", MaxBaseURLBytes)
	}
	base, err := url.ParseRequestURI(c.BaseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("base URL must be an absolute http(s) URL")
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("base URL scheme must be http or https")
	}
	if base.User != nil {
		return nil, fmt.Errorf("base URL must not contain credentials")
	}
	if base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("base URL must not contain a query or fragment")
	}
	if len(c.Path) > MaxPathBytes+MaxQueryBytes+1 {
		return nil, fmt.Errorf("path and query exceed configured bounds")
	}
	if !strings.HasPrefix(c.Path, "/") || strings.HasPrefix(c.Path, "//") {
		return nil, fmt.Errorf("path must be an absolute path beginning with one /")
	}
	relative, err := url.ParseRequestURI(c.Path)
	if err != nil || relative.IsAbs() || relative.Host != "" || relative.Fragment != "" {
		return nil, fmt.Errorf("path must be a valid path and optional query, not a URL")
	}
	if len(relative.EscapedPath()) > MaxPathBytes {
		return nil, fmt.Errorf("path exceeds %d bytes", MaxPathBytes)
	}
	if len(relative.RawQuery) > MaxQueryBytes {
		return nil, fmt.Errorf("query exceeds %d bytes", MaxQueryBytes)
	}
	target := base.ResolveReference(relative)
	if !c.AuthorizedRemoteTarget && !isLoopbackHost(target.Hostname()) {
		return nil, fmt.Errorf("remote target requires --authorized-remote-target")
	}
	return target, nil
}

func exceedsTotalBytes(count int, perRequest, limit int64) bool {
	if count < 0 || perRequest < 0 || limit < 0 {
		return true
	}
	if count == 0 || perRequest == 0 {
		return false
	}
	return int64(count) > limit/perRequest
}

func (c Config) effectiveCancelAfter() time.Duration {
	if c.CancelAfter > 0 {
		return c.CancelAfter
	}
	return DefaultCancelAfter
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alphaNumeric := (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9')
		if !alphaNumeric && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if (value[i] < 0x20 && value[i] != '\t') || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func isCredentialHeader(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	compact := strings.NewReplacer("-", "", "_", "").Replace(normalized)
	return normalized == "authorization" || normalized == "proxy-authorization" ||
		normalized == "cookie" || normalized == "set-cookie" ||
		strings.Contains(compact, "token") || strings.Contains(compact, "secret") || strings.Contains(compact, "apikey")
}

// Report has a fixed field layout so its JSON is stable for automation.
type Report struct {
	SchemaVersion         string      `json:"schema_version"`
	Requested             int         `json:"requested"`
	Attempted             int         `json:"attempted"`
	Completed             int         `json:"completed"`
	Cancelled             int         `json:"cancelled"`
	Failures              Failures    `json:"failures"`
	ElapsedMS             float64     `json:"elapsed_ms"`
	ThroughputRPS         float64     `json:"throughput_rps"`
	ResponseHeaderLatency Percentiles `json:"response_header_latency_ms"`
	FirstBodyByteLatency  Percentiles `json:"first_body_byte_latency_ms"`
	FirstBodyByteAbsent   int         `json:"first_body_byte_absent"`
	EndToEndLatency       Percentiles `json:"end_to_end_latency_ms"`
}

// Failures are deterministic aggregate counters. HTTP and body categories may both count one response.
type Failures struct {
	HTTP3xx          int64 `json:"http_3xx"`
	HTTP4xx          int64 `json:"http_4xx"`
	HTTP5xx          int64 `json:"http_5xx"`
	HTTPUnexpected   int64 `json:"http_unexpected"`
	TransportTimeout int64 `json:"transport_timeout"`
	TransportCancel  int64 `json:"transport_cancelled"`
	TransportOther   int64 `json:"transport_other"`
	BodyTimeout      int64 `json:"body_timeout"`
	BodyCancel       int64 `json:"body_cancelled"`
	BodyTooLarge     int64 `json:"body_too_large"`
	BodyTruncated    int64 `json:"body_truncated"`
	BodyOther        int64 `json:"body_other"`
}

type Percentiles struct {
	Count int     `json:"count"`
	P50   float64 `json:"p50"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
}

type measurements struct {
	mu              sync.Mutex
	responseHeader  []float64
	firstBodyByte   []float64
	firstBodyAbsent int
	endToEnd        []float64
}

func (m *measurements) append(responseHeader float64, hasResponseHeader bool, firstBodyByte float64, hasFirstBodyByte bool, bodyComplete bool, endToEnd float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if hasResponseHeader {
		m.responseHeader = append(m.responseHeader, responseHeader)
		if hasFirstBodyByte {
			m.firstBodyByte = append(m.firstBodyByte, firstBodyByte)
		} else if bodyComplete {
			m.firstBodyAbsent++
		}
	}
	m.endToEnd = append(m.endToEnd, endToEnd)
}

type atomicFailures struct {
	http3xx, http4xx, http5xx, httpUnexpected                       atomic.Int64
	transportTimeout, transportCancel, transportOther               atomic.Int64
	bodyTimeout, bodyCancel, bodyTooLarge, bodyTruncated, bodyOther atomic.Int64
}

func (f *atomicFailures) snapshot() Failures {
	return Failures{
		HTTP3xx:          f.http3xx.Load(),
		HTTP4xx:          f.http4xx.Load(),
		HTTP5xx:          f.http5xx.Load(),
		HTTPUnexpected:   f.httpUnexpected.Load(),
		TransportTimeout: f.transportTimeout.Load(),
		TransportCancel:  f.transportCancel.Load(),
		TransportOther:   f.transportOther.Load(),
		BodyTimeout:      f.bodyTimeout.Load(),
		BodyCancel:       f.bodyCancel.Load(),
		BodyTooLarge:     f.bodyTooLarge.Load(),
		BodyTruncated:    f.bodyTruncated.Load(),
		BodyOther:        f.bodyOther.Load(),
	}
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func isNilValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// Run sends at most Config.Requests requests. It does not perform retries or follow redirects.
func Run(ctx context.Context, cfg Config) (Report, error) {
	if isNilValue(ctx) {
		return Report{}, fmt.Errorf("context must not be nil")
	}
	client := &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return runWithDoer(ctx, cfg, client)
}

func runWithDoer(ctx context.Context, cfg Config, client httpDoer) (Report, error) {
	if isNilValue(ctx) {
		return Report{}, fmt.Errorf("context must not be nil")
	}
	if isNilValue(client) {
		return Report{}, fmt.Errorf("HTTP doer must not be nil")
	}
	if err := cfg.Validate(); err != nil {
		return Report{}, err
	}
	target, _ := cfg.targetURL()
	runCtx, cancel := context.WithTimeout(ctx, cfg.effectiveCancelAfter())
	defer cancel()

	started := time.Now()
	var next, attempted, completed, cancelled atomic.Int64
	var failures atomicFailures
	var samples measurements
	var workers sync.WaitGroup
	for range cfg.Concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				if runCtx.Err() != nil {
					return
				}
				requestNumber := int(next.Add(1))
				if requestNumber > cfg.Requests {
					return
				}
				attempted.Add(1)
				if runOne(runCtx, cfg, target.String(), client, &failures, &cancelled, &samples) {
					completed.Add(1)
				}
			}
		}()
	}
	workers.Wait()
	elapsed := time.Since(started)

	samples.mu.Lock()
	responseHeader := percentiles(samples.responseHeader)
	firstBodyByte := percentiles(samples.firstBodyByte)
	firstBodyAbsent := samples.firstBodyAbsent
	endToEnd := percentiles(samples.endToEnd)
	samples.mu.Unlock()
	report := Report{
		SchemaVersion:         SchemaVersion,
		Requested:             cfg.Requests,
		Attempted:             int(attempted.Load()),
		Completed:             int(completed.Load()),
		Cancelled:             int(cancelled.Load()),
		Failures:              failures.snapshot(),
		ElapsedMS:             milliseconds(elapsed),
		ResponseHeaderLatency: responseHeader,
		FirstBodyByteLatency:  firstBodyByte,
		FirstBodyByteAbsent:   firstBodyAbsent,
		EndToEndLatency:       endToEnd,
	}
	if elapsed > 0 {
		report.ThroughputRPS = float64(report.Completed) / elapsed.Seconds()
	}
	return report, nil
}

func runOne(ctx context.Context, cfg Config, target string, client httpDoer, failures *atomicFailures, cancelled *atomic.Int64, samples *measurements) bool {
	requestStart := time.Now()
	req, err := http.NewRequestWithContext(ctx, cfg.Method, target, strings.NewReader(cfg.Body))
	if err != nil {
		failures.transportOther.Add(1)
		samples.append(0, false, 0, false, false, milliseconds(time.Since(requestStart)))
		return false
	}
	for _, h := range cfg.Headers {
		req.Header.Add(h.Name, h.Value)
	}
	resp, err := client.Do(req)
	if err != nil {
		classifyTransportError(err, failures, cancelled)
		samples.append(0, false, 0, false, false, milliseconds(time.Since(requestStart)))
		return false
	}
	if resp == nil {
		failures.transportOther.Add(1)
		samples.append(0, false, 0, false, false, milliseconds(time.Since(requestStart)))
		return false
	}
	responseHeaderMS := milliseconds(time.Since(requestStart))
	classifyHTTPStatus(resp.StatusCode, failures)
	if isNilValue(resp.Body) {
		failures.bodyOther.Add(1)
		samples.append(responseHeaderMS, true, 0, false, false, milliseconds(time.Since(requestStart)))
		return false
	}
	readResult := discardBody(resp.Body, cfg.MaxResponseBytes, requestStart)
	closeErr := resp.Body.Close()
	if readResult.err != nil {
		classifyBodyError(readResult.err, failures, cancelled)
		samples.append(responseHeaderMS, true, readResult.firstByteMS, readResult.hasFirstByte, false, milliseconds(time.Since(requestStart)))
		return false
	} else if closeErr != nil {
		failures.bodyOther.Add(1)
		samples.append(responseHeaderMS, true, readResult.firstByteMS, readResult.hasFirstByte, false, milliseconds(time.Since(requestStart)))
		return false
	}
	samples.append(responseHeaderMS, true, readResult.firstByteMS, readResult.hasFirstByte, true, milliseconds(time.Since(requestStart)))
	return true
}

type bodyReadResult struct {
	firstByteMS  float64
	hasFirstByte bool
	err          error
}

func discardBody(body io.Reader, limit int64, started time.Time) bodyReadResult {
	buffer := make([]byte, 32<<10)
	var result bodyReadResult
	var total int64
	emptyReads := 0
	for {
		remaining := limit + 1 - total
		if remaining <= 0 {
			result.err = errBodyTooLarge
			return result
		}
		readSize := len(buffer)
		if int64(readSize) > remaining {
			readSize = int(remaining)
		}
		n, err := body.Read(buffer[:readSize])
		if n > 0 {
			emptyReads = 0
			if !result.hasFirstByte {
				result.firstByteMS = milliseconds(time.Since(started))
				result.hasFirstByte = true
			}
			total += int64(n)
			if total > limit {
				result.err = errBodyTooLarge
				return result
			}
		} else if err == nil {
			emptyReads++
			if emptyReads >= 100 {
				result.err = io.ErrNoProgress
				return result
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return result
			}
			result.err = err
			return result
		}
	}
}

func classifyHTTPStatus(status int, failures *atomicFailures) {
	switch {
	case status >= 300 && status < 400:
		failures.http3xx.Add(1)
	case status >= 400 && status < 500:
		failures.http4xx.Add(1)
	case status >= 500 && status < 600:
		failures.http5xx.Add(1)
	case status < 200 || status >= 600:
		failures.httpUnexpected.Add(1)
	}
}

func classifyTransportError(err error, failures *atomicFailures, cancelled *atomic.Int64) {
	switch {
	case errors.Is(err, context.Canceled):
		cancelled.Add(1)
		failures.transportCancel.Add(1)
	case isTimeout(err):
		failures.transportTimeout.Add(1)
	default:
		failures.transportOther.Add(1)
	}
}

func classifyBodyError(err error, failures *atomicFailures, cancelled *atomic.Int64) {
	switch {
	case errors.Is(err, context.Canceled):
		cancelled.Add(1)
		failures.bodyCancel.Add(1)
	case isTimeout(err):
		failures.bodyTimeout.Add(1)
	case errors.Is(err, errBodyTooLarge):
		failures.bodyTooLarge.Add(1)
	case errors.Is(err, io.ErrUnexpectedEOF):
		failures.bodyTruncated.Add(1)
	default:
		failures.bodyOther.Add(1)
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration.Microseconds()) / 1000
}

func percentiles(values []float64) Percentiles {
	if len(values) == 0 {
		return Percentiles{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	return Percentiles{
		Count: len(sorted),
		P50:   nearestRank(sorted, .50),
		P95:   nearestRank(sorted, .95),
		P99:   nearestRank(sorted, .99),
	}
}

func nearestRank(values []float64, percentile float64) float64 {
	index := int(math.Ceil(percentile*float64(len(values)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}

type headerFlags []string

func (h *headerFlags) String() string { return "<redacted>" }
func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

type runFunc func(context.Context, Config) (Report, error)

// RunCLI parses command arguments, validates them before execution, and returns a process exit code.
func RunCLI(args []string, stdout, stderr io.Writer) int {
	return runCLI(args, stdout, stderr, Run)
}

func runCLI(args []string, stdout, stderr io.Writer, execute runFunc) int {
	defaults := DefaultConfig()
	cfg := defaults
	var rawHeaders headerFlags
	flags := flag.NewFlagSet("cloudflare-loadcheck", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.BaseURL, "base-url", defaults.BaseURL, "local or explicitly authorized remote base URL")
	flags.StringVar(&cfg.Path, "path", defaults.Path, "route path beginning with /")
	flags.IntVar(&cfg.Requests, "requests", defaults.Requests, "number of requests")
	flags.IntVar(&cfg.Concurrency, "concurrency", defaults.Concurrency, "maximum in-flight requests")
	flags.StringVar(&cfg.Method, "method", defaults.Method, "HTTP method")
	flags.StringVar(&cfg.Body, "body", "", "non-sensitive request body")
	flags.DurationVar(&cfg.Timeout, "timeout", defaults.Timeout, "per-request timeout including response body")
	flags.Int64Var(&cfg.MaxResponseBytes, "max-response-bytes", defaults.MaxResponseBytes, "maximum response bytes read per request")
	flags.DurationVar(&cfg.CancelAfter, "cancel-after", defaults.CancelAfter, "hard run deadline; zero uses the safe default")
	flags.BoolVar(&cfg.AuthorizedRemoteTarget, "authorized-remote-target", false, "confirm authorization for a non-loopback target")
	flags.Var(&rawHeaders, "header", "repeatable non-credential request header: Name: Value")
	if err := flags.Parse(args); err != nil {
		writeConfigError(stdout, "invalid command arguments")
		return 2
	}
	if flags.NArg() != 0 {
		writeConfigError(stdout, "unexpected positional arguments")
		return 2
	}
	for _, raw := range rawHeaders {
		name, value, ok := strings.Cut(raw, ":")
		if !ok {
			writeConfigError(stdout, "header must use Name: Value syntax")
			return 2
		}
		cfg.Headers = append(cfg.Headers, Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	if err := cfg.Validate(); err != nil {
		writeConfigError(stdout, err.Error())
		return 2
	}
	report, err := execute(context.Background(), cfg)
	if err != nil {
		writeConfigError(stdout, "run failed")
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to write JSON report")
		return 1
	}
	return 0
}

func writeConfigError(output io.Writer, message string) {
	_ = json.NewEncoder(output).Encode(struct {
		SchemaVersion string `json:"schema_version"`
		Error         string `json:"error"`
	}{SchemaVersion: SchemaVersion, Error: message})
}
