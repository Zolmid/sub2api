package cloudflarebridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	jobExecutionPrivatePath       = "/internal/cloudflare/jobs/execute"
	jobExecutionInternalAuthority = "sub2api.internal"
	jobExecutionRPCVersion        = 1
	maxJobExecutionPayloadBytes   = 262_144
	maxJobExecutionResponseBytes  = 8_192
	// JSON string escaping can expand a one-byte control character to six bytes.
	// This remains bounded while accepting every Worker-generated valid payload.
	maxJobExecutionEnvelopeBytes = maxJobExecutionPayloadBytes*6 + 4_096
)

var (
	jobExecutionOpaque        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	jobExecutionVersion       = regexp.MustCompile(`^[1-9][0-9]*$`)
	jobExecutionDigest        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	errInvalidJobExecutionRPC = errors.New("invalid job execution RPC")
)

const (
	jobExecutionOAuthRefreshRoute          = "oauth-refresh.v1"
	jobExecutionEmailDeliveryRoute         = "email-delivery.v1"
	jobExecutionPaymentReconciliationRoute = "payment-reconciliation.v1"
)

func registeredJobExecutionRoutes() []string {
	return []string{
		jobExecutionOAuthRefreshRoute,
		jobExecutionEmailDeliveryRoute,
		jobExecutionPaymentReconciliationRoute,
	}
}

// JobExecutionInput contains the only validated data an internal route adapter
// may observe. PayloadBody is copied before dispatch so an executor cannot
// mutate request-owned memory.
type JobExecutionInput struct {
	JobID          string
	Version        int64
	Route          string
	Type           string
	IdempotencyKey string
	PayloadCodec   string
	PayloadBody    string
	PayloadDigest  string
}

// JobExecutionResult is the strictly serializable Container RPC result.
type JobExecutionResult struct {
	Kind         string
	ResultDigest string
	ErrorCode    string
	ReasonCode   string
	EvidenceRef  string
}

// JobExecutionExecutor is intentionally narrow: route adapters receive the
// request context and validated identity/payload, never the raw HTTP request.
type JobExecutionExecutor interface {
	Execute(context.Context, JobExecutionInput) (JobExecutionResult, error)
}

type JobExecutionExecutorFunc func(context.Context, JobExecutionInput) (JobExecutionResult, error)

func (f JobExecutionExecutorFunc) Execute(ctx context.Context, input JobExecutionInput) (JobExecutionResult, error) {
	return f(ctx, input)
}

// JobExecutionRegistry is immutable after construction. Keeping this explicit
// makes future provider adapters injectable without package-global mutation.
type JobExecutionRegistry struct {
	executors map[string]JobExecutionExecutor
}

func NewJobExecutionRegistry(entries map[string]JobExecutionExecutor) (JobExecutionRegistry, error) {
	registry := JobExecutionRegistry{executors: make(map[string]JobExecutionExecutor, len(entries))}
	for route, executor := range entries {
		if !isRegisteredJobExecutionRoute(route) || executor == nil {
			return JobExecutionRegistry{}, errors.New("invalid job execution registry")
		}
		registry.executors[route] = executor
	}
	return registry, nil
}

func isRegisteredJobExecutionRoute(route string) bool {
	switch route {
	case jobExecutionOAuthRefreshRoute, jobExecutionEmailDeliveryRoute, jobExecutionPaymentReconciliationRoute:
		return true
	default:
		return false
	}
}

func defaultJobExecutionRegistry() JobExecutionRegistry {
	routes := registeredJobExecutionRoutes()
	entries := make(map[string]JobExecutionExecutor, len(routes))
	for _, route := range routes {
		entries[route] = JobExecutionExecutorFunc(func(_ context.Context, input JobExecutionInput) (JobExecutionResult, error) {
			return manualReview("route_adapter_unconfigured", jobExecutionEvidence(input.JobID)), nil
		})
	}
	registry, err := NewJobExecutionRegistry(entries)
	if err != nil {
		panic("invalid built-in job execution registry")
	}
	return registry
}

func newJobExecutionHandler(registry JobExecutionRegistry) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		if !validJobExecutionTransport(request) {
			writeJobExecutionTransportError(writer)
			return
		}
		input, err := parseJobExecutionRequest(request)
		if err != nil {
			writeJobExecutionTransportError(writer)
			return
		}

		executor, registered := registry.executors[input.Route]
		if !registered {
			// This includes unknown routes and known routes intentionally omitted
			// from an injected registry. Neither case may pretend it executed.
			writeJobExecutionResult(writer, manualReview("route_unconfigured", jobExecutionEvidence(input.JobID)))
			return
		}
		result := runJobExecutionExecutor(request.Context(), executor, input)
		writeJobExecutionResult(writer, result)
	})
}

func validJobExecutionTransport(request *http.Request) bool {
	if request.Method != http.MethodPost || request.Host != jobExecutionInternalAuthority ||
		request.URL == nil || request.URL.Path != jobExecutionPrivatePath ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.Opaque != "" ||
		request.URL.EscapedPath() != jobExecutionPrivatePath || request.RequestURI != jobExecutionPrivatePath {
		return false
	}
	if request.Header.Get("Content-Type") != "application/json" || hasForwardingHeader(request.Header) {
		return false
	}
	if request.ContentLength > maxJobExecutionEnvelopeBytes {
		return false
	}
	if values, ok := request.Header["Content-Type"]; !ok || len(values) != 1 {
		return false
	}
	if contentLength := request.Header.Get("Content-Length"); contentLength != "" {
		if !canonicalBoundedDecimal(contentLength, maxJobExecutionEnvelopeBytes) {
			return false
		}
	}
	return request.Body != nil
}

func hasForwardingHeader(headers http.Header) bool {
	for key := range headers {
		lower := strings.ToLower(key)
		if lower == "forwarded" || lower == "x-real-ip" ||
			strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-original-") ||
			lower == "x-rewrite-url" {
			return true
		}
	}
	return false
}

func canonicalBoundedDecimal(value string, maximum int) bool {
	if value == "0" {
		return true
	}
	if !jobExecutionVersion.MatchString(value) {
		return false
	}
	limit := int64(maximum)
	var parsed int64
	for _, digit := range value {
		if parsed > (limit-int64(digit-'0'))/10 {
			return false
		}
		parsed = parsed*10 + int64(digit-'0')
	}
	return parsed <= limit
}

func parseJobExecutionRequest(request *http.Request) (JobExecutionInput, error) {
	body, err := io.ReadAll(io.LimitReader(request.Body, maxJobExecutionEnvelopeBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxJobExecutionEnvelopeBytes || !utf8.Valid(body) {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	root, err := strictObject(body, []string{"v", "method", "params"})
	if err != nil || !strictVersion(root["v"]) || !strictString(root["method"], "sub2api.cloudflare.jobs.execute") {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	params, err := strictObject(root["params"], []string{"job", "payload"})
	if err != nil {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	job, err := strictObject(params["job"], []string{"id", "version", "route", "type", "idempotencyKey"})
	if err != nil {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	payload, err := strictObject(params["payload"], []string{"codec", "body", "digest"})
	if err != nil {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}

	input := JobExecutionInput{}
	if input.JobID, err = strictOpaque(job["id"], 160); err != nil {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	if input.Version, err = strictPositiveVersion(job["version"]); err != nil {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	if input.Route, err = strictOpaque(job["route"], 96); err != nil {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	if input.Type, err = strictOpaque(job["type"], 96); err != nil {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	if input.IdempotencyKey, err = strictOpaque(job["idempotencyKey"], 192); err != nil {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	if input.PayloadCodec, err = strictPayloadCodec(payload["codec"]); err != nil {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	if input.PayloadBody, err = strictPayloadBody(payload["body"]); err != nil {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	if input.PayloadDigest, err = strictPayloadDigest(payload["digest"], input.PayloadBody); err != nil {
		return JobExecutionInput{}, errInvalidJobExecutionRPC
	}
	return input, nil
}

func strictObject(raw json.RawMessage, expected []string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return nil, errInvalidJobExecutionRPC
	}
	values := make(map[string]json.RawMessage, len(expected))
	allowed := make(map[string]struct{}, len(expected))
	for _, key := range expected {
		allowed[key] = struct{}{}
	}
	for decoder.More() {
		field, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := field.(string)
		if !ok {
			return nil, errInvalidJobExecutionRPC
		}
		if _, ok := allowed[key]; !ok {
			return nil, errInvalidJobExecutionRPC
		}
		if _, duplicate := values[key]; duplicate {
			return nil, errInvalidJobExecutionRPC
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		values[key] = value
	}
	if token, err = decoder.Token(); err != nil {
		return nil, err
	} else if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return nil, errInvalidJobExecutionRPC
	}
	if decoder.More() {
		return nil, errInvalidJobExecutionRPC
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errInvalidJobExecutionRPC
	}
	if len(values) != len(expected) {
		return nil, errInvalidJobExecutionRPC
	}
	return values, nil
}

func strictVersion(raw json.RawMessage) bool {
	value, err := strictJSONNumber(raw)
	return err == nil && value == "1"
}

func strictPositiveVersion(raw json.RawMessage) (int64, error) {
	value, err := strictJSONNumber(raw)
	if err != nil || !jobExecutionVersion.MatchString(value) || !canonicalBoundedDecimal(value, 2_147_483_647) {
		return 0, errInvalidJobExecutionRPC
	}
	var version int64
	for _, digit := range value {
		version = version*10 + int64(digit-'0')
	}
	return version, nil
}

func strictJSONNumber(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || raw[0] == '"' || raw[0] == 'n' || raw[0] == '[' || raw[0] == '{' || raw[0] == 't' || raw[0] == 'f' {
		return "", errInvalidJobExecutionRPC
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value json.Number
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return "", err
	}
	return value.String(), nil
}

func strictString(raw json.RawMessage, expected string) bool {
	value, err := strictJSONString(raw)
	return err == nil && value == expected
}

func strictOpaque(raw json.RawMessage, maximum int) (string, error) {
	value, err := strictJSONString(raw)
	if err != nil || len(value) == 0 || len(value) > maximum || strings.TrimSpace(value) != value || !jobExecutionOpaque.MatchString(value) {
		return "", errInvalidJobExecutionRPC
	}
	return value, nil
}

func strictPayloadCodec(raw json.RawMessage) (string, error) {
	value, err := strictJSONString(raw)
	if err != nil || (value != "json" && value != "app_encrypted_v1") {
		return "", errInvalidJobExecutionRPC
	}
	return value, nil
}

func strictPayloadBody(raw json.RawMessage) (string, error) {
	value, err := strictJSONString(raw)
	if err != nil || len(value) == 0 || len([]byte(value)) > maxJobExecutionPayloadBytes || !utf8.ValidString(value) {
		return "", errInvalidJobExecutionRPC
	}
	return string(append([]byte(nil), value...)), nil
}

func strictPayloadDigest(raw json.RawMessage, body string) (string, error) {
	value, err := strictOpaque(raw, 160)
	if err != nil || !jobExecutionDigest.MatchString(value) {
		return "", errInvalidJobExecutionRPC
	}
	expected := "sha256:" + stringHex(sha256.Sum256([]byte(body)))
	if subtle.ConstantTimeCompare([]byte(value), []byte(expected)) != 1 {
		return "", errInvalidJobExecutionRPC
	}
	return value, nil
}

func strictJSONString(raw json.RawMessage) (string, error) {
	if len(raw) < 2 || raw[0] != '"' {
		return "", errInvalidJobExecutionRPC
	}
	var value string
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return "", err
	}
	return value, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errInvalidJobExecutionRPC
	}
	return nil
}

func stringHex(sum [sha256.Size]byte) string {
	const digits = "0123456789abcdef"
	output := make([]byte, len(sum)*2)
	for index, value := range sum {
		output[index*2] = digits[value>>4]
		output[index*2+1] = digits[value&0x0f]
	}
	return string(output)
}

func runJobExecutionExecutor(ctx context.Context, executor JobExecutionExecutor, input JobExecutionInput) (result JobExecutionResult) {
	if ctx.Err() != nil {
		return manualReview("request_cancelled", jobExecutionEvidence(input.JobID))
	}
	defer func() {
		if recover() != nil {
			result = manualReview("executor_uncertain", jobExecutionEvidence(input.JobID))
		}
	}()
	result, err := executor.Execute(ctx, input)
	if err != nil {
		return manualReview("executor_uncertain", jobExecutionEvidence(input.JobID))
	}
	if !validJobExecutionResult(result) {
		return manualReview("executor_invalid_result", jobExecutionEvidence(input.JobID))
	}
	// A route adapter can explicitly classify a known retryable failure even if
	// cancellation raced with its completion. Every other uncertain outcome is
	// quarantined for review rather than re-executed here.
	if ctx.Err() != nil && result.Kind != "retryable_failure" {
		return manualReview("request_cancelled", jobExecutionEvidence(input.JobID))
	}
	return result
}

func validJobExecutionResult(result JobExecutionResult) bool {
	switch result.Kind {
	case "succeeded":
		return validJobExecutionOpaque(result.ResultDigest, 160) && result.ErrorCode == "" && result.ReasonCode == "" && result.EvidenceRef == ""
	case "retryable_failure", "permanent_failure":
		return validJobExecutionOpaque(result.ErrorCode, 96) && result.ResultDigest == "" && result.ReasonCode == "" && result.EvidenceRef == ""
	case "manual_review":
		return validJobExecutionOpaque(result.ReasonCode, 96) && validJobExecutionOpaque(result.EvidenceRef, 256) && result.ResultDigest == "" && result.ErrorCode == ""
	default:
		return false
	}
}

func validJobExecutionOpaque(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && strings.TrimSpace(value) == value && jobExecutionOpaque.MatchString(value)
}

func manualReview(reasonCode, evidenceRef string) JobExecutionResult {
	return JobExecutionResult{Kind: "manual_review", ReasonCode: reasonCode, EvidenceRef: evidenceRef}
}

func jobExecutionEvidence(jobID string) string { return "job:" + jobID }

func writeJobExecutionTransportError(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusBadRequest)
	_, _ = writer.Write([]byte(`{"error":"invalid_request"}`))
}

func writeJobExecutionResult(writer http.ResponseWriter, result JobExecutionResult) {
	if !validJobExecutionResult(result) {
		result = manualReview("executor_invalid_result", "job:unknown")
	}
	body := marshalJobExecutionResult(result)
	if len(body) > maxJobExecutionResponseBytes {
		body = marshalJobExecutionResult(manualReview("executor_invalid_result", "job:unknown"))
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}

func marshalJobExecutionResult(result JobExecutionResult) []byte {
	// All values were validated above; assembling this fixed schema avoids any
	// accidental serialization of an adapter's arbitrary struct or error value.
	switch result.Kind {
	case "succeeded":
		return []byte(`{"v":1,"kind":"succeeded","resultDigest":` + quoteJSON(result.ResultDigest) + `}`)
	case "retryable_failure", "permanent_failure":
		return []byte(`{"v":1,"kind":` + quoteJSON(result.Kind) + `,"errorCode":` + quoteJSON(result.ErrorCode) + `}`)
	default:
		return []byte(`{"v":1,"kind":"manual_review","reasonCode":` + quoteJSON(result.ReasonCode) + `,"evidenceRef":` + quoteJSON(result.EvidenceRef) + `}`)
	}
}

func quoteJSON(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
