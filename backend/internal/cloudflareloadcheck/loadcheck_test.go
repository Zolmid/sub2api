package cloudflareloadcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunCLIRejectsIllegalParametersBeforeExecute(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false

	code := runCLI([]string{"--requests", "1000001"}, &stdout, &stderr, func(context.Context, Config) (Report, error) {
		called = true
		return Report{}, nil
	})

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if called {
		t.Fatal("execute was called for invalid config")
	}
	if strings.Contains(stdout.String(), "http://") || strings.Contains(stdout.String(), "https://") {
		t.Fatalf("config error leaked URL: %s", stdout.String())
	}
}

func TestRunCLIRejectsRemoteTargetBeforeNetwork(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var calls atomic.Int64

	code := runCLI([]string{"--base-url", "https://example.com", "--path", "/healthz"}, &stdout, &stderr, func(context.Context, Config) (Report, error) {
		calls.Add(1)
		return Report{}, nil
	})

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if calls.Load() != 0 {
		t.Fatalf("network execute calls = %d, want 0", calls.Load())
	}
	if !strings.Contains(stdout.String(), "remote target requires --authorized-remote-target") {
		t.Fatalf("missing remote guard error: %s", stdout.String())
	}
}

func TestRunCLIAuthorizedRemoteTargetOnlyMarksOperatorAuthorization(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var got Config

	code := runCLI([]string{"--base-url", "https://example.com", "--path", "/healthz", "--authorized-remote-target"}, &stdout, &stderr, func(_ context.Context, cfg Config) (Report, error) {
		got = cfg
		return Report{SchemaVersion: SchemaVersion, Requested: cfg.Requests}, nil
	})

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !got.AuthorizedRemoteTarget {
		t.Fatal("AuthorizedRemoteTarget was not passed to execute")
	}
	if strings.Contains(stdout.String(), "example.com") {
		t.Fatalf("report leaked target host: %s", stdout.String())
	}
}

func TestRunDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			redirected.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer server.Close()

	report, err := Run(context.Background(), Config{
		BaseURL:          server.URL,
		Path:             "/start?secret=not-reported",
		Requests:         1,
		Concurrency:      1,
		Method:           http.MethodGet,
		Timeout:          time.Second,
		MaxResponseBytes: DefaultMaxResponseBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect target was requested %d times", redirected.Load())
	}
	if report.Completed != 1 || report.Failures.HTTP3xx != 1 {
		t.Fatalf("report = %+v, want one completed 3xx response", report)
	}
}

func TestRunBodyTooLargeIsFailureNotCompleted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("abcd"))
	}))
	defer server.Close()

	report, err := Run(context.Background(), Config{
		BaseURL:          server.URL,
		Path:             "/",
		Requests:         1,
		Concurrency:      1,
		Method:           http.MethodGet,
		Timeout:          time.Second,
		MaxResponseBytes: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Completed != 0 || report.Failures.BodyTooLarge != 1 {
		t.Fatalf("report = %+v, want body-too-large failure without completion", report)
	}
}

func TestRunUnexpectedEOFIsTruncatedFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "10")
		_, _ = w.Write([]byte("short"))
	}))
	defer server.Close()

	report, err := Run(context.Background(), Config{
		BaseURL:          server.URL,
		Path:             "/",
		Requests:         1,
		Concurrency:      1,
		Method:           http.MethodGet,
		Timeout:          time.Second,
		MaxResponseBytes: DefaultMaxResponseBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Completed != 0 || report.Failures.BodyTruncated != 1 {
		t.Fatalf("report = %+v, want truncated body failure without completion", report)
	}
}

func TestRunCloseErrorIsFailureNotCompleted(t *testing.T) {
	report, err := runWithDoer(context.Background(), DefaultConfig(), staticDoer{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       closeErrorBody{Reader: strings.NewReader("")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Completed != 0 || report.Failures.BodyOther != 1 || report.FirstBodyByteAbsent != 0 {
		t.Fatalf("report = %+v, want zero-byte close failure without completion or absent-body count", report)
	}
}

func TestRunZeroByteReadErrorDoesNotRecordAbsent(t *testing.T) {
	report, err := runWithDoer(context.Background(), DefaultConfig(), staticDoer{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       errorReadCloser{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Completed != 0 || report.Failures.BodyOther != 1 || report.FirstBodyByteLatency.Count != 0 || report.FirstBodyByteAbsent != 0 {
		t.Fatalf("report = %+v, want zero-byte read failure without completion or absent-body count", report)
	}
}

func TestRunEmptyBodyRecordsFirstBodyByteAbsent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	report, err := Run(context.Background(), Config{
		BaseURL:          server.URL,
		Path:             "/",
		Requests:         1,
		Concurrency:      1,
		Method:           http.MethodGet,
		Timeout:          time.Second,
		MaxResponseBytes: DefaultMaxResponseBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Completed != 1 || report.ResponseHeaderLatency.Count != 1 || report.FirstBodyByteLatency.Count != 0 || report.FirstBodyByteAbsent != 1 {
		t.Fatalf("report = %+v, want header timing and explicit absent first body byte", report)
	}
}

func TestRunAlwaysRecordsSSEFirstBodyByteSeparatelyFromHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("response writer cannot flush")
		}
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write([]byte("data: ready\n\n"))
	}))
	defer server.Close()

	report, err := Run(context.Background(), Config{
		BaseURL:          server.URL,
		Path:             "/events",
		Requests:         1,
		Concurrency:      1,
		Method:           http.MethodGet,
		Timeout:          time.Second,
		MaxResponseBytes: DefaultMaxResponseBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Completed != 1 || report.ResponseHeaderLatency.Count != 1 || report.FirstBodyByteLatency.Count != 1 {
		t.Fatalf("report = %+v, want header and first body timings", report)
	}
	if report.FirstBodyByteLatency.P50 < report.ResponseHeaderLatency.P50 {
		t.Fatalf("first body byte %f was before headers %f", report.FirstBodyByteLatency.P50, report.ResponseHeaderLatency.P50)
	}
}

func TestRunBodyTimeoutIsFailureNotCompleted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("response writer cannot flush")
		}
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	defer server.Close()

	report, err := Run(context.Background(), Config{
		BaseURL:          server.URL,
		Path:             "/slow",
		Requests:         1,
		Concurrency:      1,
		Method:           http.MethodGet,
		Timeout:          50 * time.Millisecond,
		MaxResponseBytes: DefaultMaxResponseBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Completed != 0 || report.Failures.BodyTimeout != 1 || report.FirstBodyByteLatency.Count != 0 || report.FirstBodyByteAbsent != 0 {
		t.Fatalf("report = %+v, want zero-byte body timeout without completion or absent-body count", report)
	}
}

func TestValidateRejectsAggregateByteBudgets(t *testing.T) {
	t.Run("response", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Requests = MaxRequests
		cfg.MaxResponseBytes = MaxTotalResponseBytes/int64(cfg.Requests) + 1
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "aggregate response read budget") {
			t.Fatalf("Validate() error = %v, want aggregate response budget error", err)
		}
	})

	t.Run("request body", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Requests = 1_000
		cfg.MaxResponseBytes = 1
		cfg.Body = strings.Repeat("x", MaxTotalRequestBodyBytes/cfg.Requests+1)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "aggregate request body budget") {
			t.Fatalf("Validate() error = %v, want aggregate request body budget error", err)
		}
	})

	t.Run("documented baseline", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Requests = 100
		cfg.Concurrency = 10
		if err := cfg.Validate(); err != nil {
			t.Fatalf("documented baseline rejected: %v", err)
		}
	})
}

func TestExceedsTotalBytesIsOverflowSafe(t *testing.T) {
	large := int64(1) << 62
	if !exceedsTotalBytes(2, large, int64(^uint64(0)>>1)) {
		t.Fatal("overflowing product was not rejected")
	}
}

func TestValidateRejectsOversizedTextFields(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*Config)
		wantSubstr string
	}{
		{
			name: "base URL",
			configure: func(cfg *Config) {
				cfg.BaseURL = strings.Repeat("x", MaxBaseURLBytes+1)
			},
			wantSubstr: "base URL exceeds",
		},
		{
			name: "path",
			configure: func(cfg *Config) {
				cfg.Path = "/" + strings.Repeat("x", MaxPathBytes)
			},
			wantSubstr: "path exceeds",
		},
		{
			name: "query",
			configure: func(cfg *Config) {
				cfg.Path = "/?q=" + strings.Repeat("x", MaxQueryBytes)
			},
			wantSubstr: "query exceeds",
		},
		{
			name: "method",
			configure: func(cfg *Config) {
				cfg.Method = strings.Repeat("X", MaxMethodBytes+1)
			},
			wantSubstr: "method exceeds",
		},
		{
			name: "header name",
			configure: func(cfg *Config) {
				cfg.Headers = []Header{{Name: strings.Repeat("X", MaxHeaderNameBytes+1), Value: "ok"}}
			},
			wantSubstr: "header name exceeds",
		},
		{
			name: "header value",
			configure: func(cfg *Config) {
				cfg.Headers = []Header{{Name: "X-Test", Value: strings.Repeat("x", MaxHeaderValueBytes+1)}}
			},
			wantSubstr: "header value exceeds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.configure(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantSubstr)
			}
		})
	}
}

func TestRunRejectsNilContext(t *testing.T) {
	var typedNil *triggeredContext
	for _, tt := range []struct {
		name string
		ctx  context.Context
	}{
		{name: "nil interface", ctx: nil},
		{name: "typed nil", ctx: typedNil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Run(tt.ctx, DefaultConfig()); err == nil {
				t.Fatal("Run(nil, cfg) succeeded")
			}
		})
	}
}

func TestRunWithDoerRejectsNilDoer(t *testing.T) {
	var doer *typedNilDoer
	if _, err := runWithDoer(context.Background(), DefaultConfig(), doer); err == nil {
		t.Fatal("runWithDoer accepted a typed nil doer")
	}
}

func TestRunWithDoerHandlesNilResponse(t *testing.T) {
	report, err := runWithDoer(context.Background(), DefaultConfig(), staticDoer{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Attempted != 1 || report.Completed != 0 || report.Failures.TransportOther != 1 || report.ResponseHeaderLatency.Count != 0 {
		t.Fatalf("report = %+v, want one safe nil-response transport failure", report)
	}
}

func TestRunWithDoerHandlesNilResponseBody(t *testing.T) {
	report, err := runWithDoer(context.Background(), DefaultConfig(), staticDoer{
		resp: &http.Response{StatusCode: http.StatusOK},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Attempted != 1 || report.Completed != 0 || report.Failures.BodyOther != 1 || report.ResponseHeaderLatency.Count != 1 || report.FirstBodyByteAbsent != 0 {
		t.Fatalf("report = %+v, want one safe nil-body failure without absent-body count", report)
	}
}

func TestRunWithDoerAppliesDefaultWallClockDeadline(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CancelAfter = 0
	var remaining time.Duration

	_, err := runWithDoer(context.Background(), cfg, doerFunc(func(req *http.Request) (*http.Response, error) {
		deadline, ok := req.Context().Deadline()
		if !ok {
			return nil, errors.New("request context has no deadline")
		}
		remaining = time.Until(deadline)
		return nil, errors.New("stop")
	}))
	if err != nil {
		t.Fatal(err)
	}
	if remaining <= DefaultCancelAfter-time.Second || remaining > DefaultCancelAfter {
		t.Fatalf("default deadline remaining = %s, want approximately %s", remaining, DefaultCancelAfter)
	}
}

func TestRunWithDoerAccountsContextTerminationDeterministically(t *testing.T) {
	tests := []struct {
		name             string
		terminalError    error
		wantCancelled    int
		wantCancelErrors int64
		wantTimeouts     int64
	}{
		{name: "cancel", terminalError: context.Canceled, wantCancelled: 2, wantCancelErrors: 2},
		{name: "deadline", terminalError: context.DeadlineExceeded, wantTimeouts: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newTriggeredContext(tt.terminalError)
			cfg := DefaultConfig()
			cfg.Requests = 5
			cfg.Concurrency = 2
			var entered atomic.Int64
			doer := doerFunc(func(req *http.Request) (*http.Response, error) {
				if entered.Add(1) == int64(cfg.Concurrency) {
					ctx.trigger()
				}
				<-req.Context().Done()
				return nil, req.Context().Err()
			})

			report, err := runWithDoer(ctx, cfg, doer)
			if err != nil {
				t.Fatal(err)
			}
			if report.Attempted != 2 || report.Completed != 0 || report.Cancelled != tt.wantCancelled || report.Failures.TransportCancel != tt.wantCancelErrors || report.Failures.TransportTimeout != tt.wantTimeouts {
				t.Fatalf("report = %+v, want deterministic context accounting", report)
			}
			if report.Requested-report.Attempted != 3 {
				t.Fatalf("unstarted requests = %d, want 3", report.Requested-report.Attempted)
			}
		})
	}
}

func TestRunCLIRejectsRemovedStreamingFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	code := runCLI([]string{"--streaming"}, &stdout, &stderr, func(context.Context, Config) (Report, error) {
		called = true
		return Report{}, nil
	})
	if code != 2 || called {
		t.Fatalf("exit code = %d, execute called = %t; want rejected before execute", code, called)
	}
	if !strings.Contains(stdout.String(), "invalid command arguments") || strings.Contains(stdout.String(), "--streaming") || stderr.Len() != 0 {
		t.Fatalf("unexpected parse output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunCLIRejectsCredentialHeaderWithoutEcho(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"--header", "Authorization: super-secret"}, &stdout, &stderr, func(context.Context, Config) (Report, error) {
		return Report{}, nil
	})
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	for _, forbidden := range []string{"Authorization", "super-secret"} {
		if strings.Contains(stdout.String(), forbidden) || strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("validation output leaked %q: stdout=%q stderr=%q", forbidden, stdout.String(), stderr.String())
		}
	}
}

func TestPercentilesUseDeterministicNearestRank(t *testing.T) {
	got := percentiles([]float64{100, 1, 50, 5, 20})
	want := Percentiles{Count: 5, P50: 20, P95: 100, P99: 100}
	if got != want {
		t.Fatalf("percentiles = %+v, want %+v", got, want)
	}
}

func TestRunReportsTTFBAsResponseHeaderLatency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = server.URL
	report, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if report.TTFBLatency != report.ResponseHeaderLatency || report.TTFBLatency.Count != 1 || report.EndToEndLatency.Count != 1 {
		t.Fatalf("report timing fields = %+v, want explicit TTFB/header and end-to-end samples", report)
	}
}

func TestRunMatrixCoversVariantsModesAndConcurrency(t *testing.T) {
	var mu sync.Mutex
	requestsByPathAndMode := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mode := "warm"
		if r.Close {
			mode = "cold"
		}
		mu.Lock()
		requestsByPathAndMode[r.URL.Path+":"+mode]++
		mu.Unlock()
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Error("streaming test server does not support flushing")
				return
			}
			flusher.Flush()
			time.Sleep(time.Millisecond)
			_, _ = w.Write([]byte("data: ready\n\n"))
			return
		}
		_, _ = w.Write([]byte("body"))
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = server.URL
	cfg.Requests = 10
	cfg.Timeout = time.Second
	matrix, err := RunMatrix(context.Background(), MatrixConfig{
		Config:             cfg,
		BodyPath:           "/body",
		StreamPath:         "/stream",
		PlatformOperations: map[string]int64{"d1.reads": 2, "queue.ops": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(matrix.Rows), 12; got != want {
		t.Fatalf("matrix rows = %d, want %d", got, want)
	}
	if got, want := matrix.ConcurrencyMatrix, []int{1, 3, 10}; !reflect.DeepEqual(got, want) {
		t.Fatalf("concurrency matrix = %v, want %v", got, want)
	}
	for _, row := range matrix.Rows {
		if row.Report.Completed != 10 || row.Report.TTFBLatency.Count != 10 || row.Report.EndToEndLatency.Count != 10 {
			t.Fatalf("row %s/%s report = %+v, want ten timing samples", row.Variant, row.ConnectionMode, row.Report)
		}
		if row.Report.TTFBLatency.P50 > row.Report.TTFBLatency.P95 || row.Report.TTFBLatency.P95 > row.Report.TTFBLatency.P99 {
			t.Fatalf("row %s/%s has invalid TTFB percentiles: %+v", row.Variant, row.ConnectionMode, row.Report.TTFBLatency)
		}
		if row.PlatformOperations == nil || row.PlatformOperations.EstimatedForCompletedRequests["d1.reads"] != 20 || row.PlatformOperations.EstimatedForCompletedRequests["queue.ops"] != 10 {
			t.Fatalf("row %s/%s operations = %+v, want transparent completed-request estimates", row.Variant, row.ConnectionMode, row.PlatformOperations)
		}
		if row.ConnectionMode == ConnectionCold && !strings.Contains(row.ModeSemantics, "not a Cloudflare Worker cold-start") {
			t.Fatalf("cold semantics = %q", row.ModeSemantics)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/body", "/stream"} {
		if requestsByPathAndMode[path+":cold"] != 30 || requestsByPathAndMode[path+":warm"] != 30 {
			t.Fatalf("requests by path/mode = %+v, want thirty per path and connection mode", requestsByPathAndMode)
		}
	}
	if strings.Contains(strings.ToLower(matrix.ResourceMetricsNote), "measured") {
		t.Fatalf("resource note must not imply RSS/CPU were measured: %q", matrix.ResourceMetricsNote)
	}
}

func TestRunMatrixRequiresBothVariantsAndTenRequests(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Requests = 9
	_, err := RunMatrix(context.Background(), MatrixConfig{Config: cfg, BodyPath: "/body", StreamPath: "/stream"})
	if err == nil || !strings.Contains(err.Error(), "at least 10") {
		t.Fatalf("RunMatrix() error = %v, want requests guard", err)
	}
	cfg.Requests = 10
	_, err = RunMatrix(context.Background(), MatrixConfig{Config: cfg, BodyPath: "/body"})
	if err == nil || !strings.Contains(err.Error(), "both body-path and stream-path") {
		t.Fatalf("RunMatrix() error = %v, want both variants guard", err)
	}
}

func TestRunCLIConcurrencyMatrixPassesOnlyValidatedInputs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	calledSingle := false
	var got MatrixConfig
	code := runCLIWithMatrix([]string{
		"--concurrency-matrix", "--requests", "10", "--body-path", "/body", "--stream-path", "/stream",
		"--platform-operation", "d1.reads=2", "--platform-operation", "queue.ops=1",
	}, &stdout, &stderr, func(context.Context, Config) (Report, error) {
		calledSingle = true
		return Report{}, nil
	}, func(_ context.Context, cfg MatrixConfig) (MatrixReport, error) {
		got = cfg
		return MatrixReport{SchemaVersion: SchemaVersion, ConcurrencyMatrix: []int{1, 3, 10}}, nil
	})
	if code != 0 || calledSingle {
		t.Fatalf("exit code = %d, single execute = %t; stdout=%s stderr=%s", code, calledSingle, stdout.String(), stderr.String())
	}
	if got.BodyPath != "/body" || got.StreamPath != "/stream" || got.PlatformOperations["d1.reads"] != 2 || got.PlatformOperations["queue.ops"] != 1 {
		t.Fatalf("matrix config = %+v, want validated variants and operation counts", got)
	}
	var report MatrixReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || report.SchemaVersion != SchemaVersion {
		t.Fatalf("matrix JSON = %q, unmarshal error = %v", stdout.String(), err)
	}
}

func TestRunCLIRejectsMatrixOnlyFlagsWithoutMatrix(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	code := runCLI([]string{"--platform-operation", "d1.reads=2"}, &stdout, &stderr, func(context.Context, Config) (Report, error) {
		called = true
		return Report{}, nil
	})
	if code != 2 || called || !strings.Contains(stdout.String(), "matrix options require") {
		t.Fatalf("exit=%d called=%t stdout=%q, want rejected matrix-only flag", code, called, stdout.String())
	}
}

func TestRunCLIReportDoesNotLeakSensitiveInputs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCLI([]string{
		"--path", "/api/check?api_key=secret",
		"--body", "secret-body",
		"--header", "X-Safe: not-secret",
	}, &stdout, &stderr, func(_ context.Context, cfg Config) (Report, error) {
		return Report{SchemaVersion: SchemaVersion, Requested: cfg.Requests, Completed: 1}, nil
	})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var report Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON report: %v: %s", err, stdout.String())
	}
	for _, forbidden := range []string{"api_key", "secret", "secret-body", "X-Safe"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("report leaked %q: %s", forbidden, stdout.String())
		}
	}
}

type staticDoer struct {
	resp *http.Response
	err  error
}

func (d staticDoer) Do(*http.Request) (*http.Response, error) {
	return d.resp, d.err
}

type closeErrorBody struct {
	io.Reader
}

func (b closeErrorBody) Close() error {
	return errors.New("close failed")
}

type errorReadCloser struct{}

func (errorReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func (errorReadCloser) Close() error { return nil }

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

type typedNilDoer struct{}

func (*typedNilDoer) Do(*http.Request) (*http.Response, error) {
	panic("typed nil doer was called")
}

type triggeredContext struct {
	context.Context
	done chan struct{}
	err  error
	once sync.Once
}

func newTriggeredContext(err error) *triggeredContext {
	return &triggeredContext{Context: context.Background(), done: make(chan struct{}), err: err}
}

func (c *triggeredContext) Done() <-chan struct{} { return c.done }

func (c *triggeredContext) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

func (c *triggeredContext) trigger() {
	c.once.Do(func() { close(c.done) })
}
