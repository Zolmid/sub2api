package cloudflareprotocol

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

type ErrorCode string

const (
	ErrMalformed   ErrorCode = "malformed_request"
	ErrValidation  ErrorCode = "validation_error"
	ErrUnsupported ErrorCode = "unsupported_field"
	ErrLossy       ErrorCode = "lossy_conversion"
	ErrLimit       ErrorCode = "limit_exceeded"
	ErrCancelled   ErrorCode = "cancelled"
	ErrUpstream    ErrorCode = "upstream_error"
)

type Error struct {
	Code                    ErrorCode
	Field, Message          string
	Cause                   error
	HTTPStatus              int
	Retryable, BeforeOutput bool
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Field != "" {
		return fmt.Sprintf("%s: %s: %s", e.Code, e.Field, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func fail(code ErrorCode, field, message string, cause error) *Error {
	status := 400
	if code == ErrLimit {
		status = 413
	}
	if code == ErrCancelled {
		status = 499
	}
	return &Error{Code: code, Field: field, Message: message, Cause: cause, HTTPStatus: status, BeforeOutput: true}
}

// UpstreamError never retains caller-supplied upstream detail in public state.
func UpstreamError(status int, retryable, beforeOutput bool, _ string) *Error {
	if status < 400 || status > 599 {
		status = 502
	}
	return &Error{Code: ErrUpstream, Message: "upstream request failed", HTTPStatus: status, Retryable: retryable, BeforeOutput: beforeOutput}
}

func EncodeError(p Protocol, e *Error) ([]byte, error) {
	if e == nil {
		return nil, fail(ErrValidation, "error", "nil protocol error", nil)
	}
	code, status, message := normalizePublicError(e)
	switch p {
	case OpenAIChat, OpenAIResponses:
		typ := "invalid_request_error"
		if code == ErrUpstream {
			typ = "server_error"
		}
		if code == ErrCancelled {
			typ = "request_cancelled"
		}
		return json.Marshal(map[string]any{"error": map[string]any{"message": message, "type": typ, "code": string(code)}})
	case Anthropic:
		typ := "invalid_request_error"
		if code == ErrLimit {
			typ = "request_too_large"
		}
		if code == ErrUpstream {
			typ = "api_error"
		}
		if code == ErrCancelled {
			typ = "request_cancelled"
		}
		return json.Marshal(map[string]any{"type": "error", "error": map[string]any{"type": typ, "message": message}})
	case Gemini:
		gs := "INVALID_ARGUMENT"
		if code == ErrLimit {
			gs = "RESOURCE_EXHAUSTED"
		}
		if code == ErrCancelled {
			gs = "CANCELLED"
		}
		if code == ErrUpstream {
			if status == 429 {
				gs = "RESOURCE_EXHAUSTED"
			} else if status >= 500 {
				gs = "UNAVAILABLE"
			} else {
				gs = "UNKNOWN"
			}
		}
		return json.Marshal(map[string]any{"error": map[string]any{"code": status, "status": gs, "message": message}})
	default:
		return nil, fail(ErrUnsupported, "protocol", "unknown protocol", nil)
	}
}

func publicError(e *Error, limits DecodeLimits) (string, error) {
	if e == nil {
		return "", fail(ErrValidation, "error", "nil protocol error", nil)
	}
	_, _, message := normalizePublicError(e)
	if err := checkString("error.message", message, true, limits); err != nil {
		return "", err
	}
	return message, nil
}

func anthropicErrorType(e *Error) string {
	switch e.Code {
	case ErrLimit:
		return "request_too_large"
	case ErrCancelled:
		return "request_cancelled"
	case ErrUpstream:
		return "api_error"
	default:
		return "invalid_request_error"
	}
}

func errorValue(protocol Protocol, e *Error, limits DecodeLimits) (any, error) {
	message, err := publicError(e, limits)
	if err != nil {
		return nil, err
	}
	code, status, _ := normalizePublicError(e)
	switch protocol {
	case OpenAIChat, OpenAIResponses:
		typeName := "invalid_request_error"
		if code == ErrUpstream {
			typeName = "server_error"
		}
		if code == ErrCancelled {
			typeName = "request_cancelled"
		}
		return map[string]any{"error": map[string]any{"message": message, "type": typeName, "code": string(code)}}, nil
	case Anthropic:
		return map[string]any{"type": "error", "error": map[string]any{"type": anthropicErrorType(e), "message": message}}, nil
	case Gemini:
		googleStatus := "INVALID_ARGUMENT"
		if code == ErrLimit {
			googleStatus = "RESOURCE_EXHAUSTED"
		}
		if code == ErrCancelled {
			googleStatus = "CANCELLED"
		}
		if code == ErrUpstream {
			if status == 429 {
				googleStatus = "RESOURCE_EXHAUSTED"
			} else if status >= 500 {
				googleStatus = "UNAVAILABLE"
			} else {
				googleStatus = "UNKNOWN"
			}
		}
		return map[string]any{"error": map[string]any{"code": status, "status": googleStatus, "message": message}}, nil
	default:
		return nil, fail(ErrUnsupported, "protocol", "unknown protocol", nil)
	}
}

func normalizePublicError(e *Error) (ErrorCode, int, string) {
	code := e.Code
	switch code {
	case ErrMalformed, ErrValidation, ErrUnsupported, ErrLossy, ErrLimit, ErrCancelled, ErrUpstream:
	default:
		code = ErrUpstream
	}
	status := e.HTTPStatus
	if status < 400 || status > 599 {
		status = 400
		if code == ErrLimit {
			status = 413
		}
		if code == ErrCancelled {
			status = 499
		}
		if code == ErrUpstream {
			status = 502
		}
	}
	message := "upstream request failed"
	if code != ErrUpstream {
		message = sanitizePublicDetail(e.Message)
		if e.Field != "" {
			field := sanitizePublicDetail(e.Field)
			if field != "" {
				message = field + ": " + message
			}
		}
	}
	if len(message) > 1024 {
		message = message[:1024]
	}
	return code, status, message
}
func sanitizePublicDetail(s string) string {
	if len(s) > 1024 {
		s = s[:1024]
	}
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			b.WriteByte(' ')
		} else if !unicode.IsControl(r) {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	lower := strings.ToLower(out)
	for _, marker := range []string{"authorization", "bearer ", "api_key", "apikey", "token=", "password", "secret"} {
		if strings.Contains(lower, marker) {
			return "request could not be processed"
		}
	}
	if out == "" {
		return "request could not be processed"
	}
	return out
}
