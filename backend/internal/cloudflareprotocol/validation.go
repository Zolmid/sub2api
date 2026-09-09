package cloudflareprotocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
)

const (
	defaultMaxBodyBytes       = 2 << 20
	defaultMaxJSONDepth       = 32
	defaultMaxCollectionItems = 1024
	defaultMaxStringBytes     = 1 << 20
	maxConfiguredBodyBytes    = 64 << 20
	maxConfiguredJSONDepth    = 128
	maxConfiguredItems        = 100000
	maxConfiguredStringBytes  = 16 << 20
)

type DecodeLimits struct {
	MaxBodyBytes       int
	MaxJSONDepth       int
	MaxCollectionItems int
	MaxStringBytes     int
}

type DecodeOptions struct {
	// Model is required for Gemini because generateContent identifies the model
	// in the URL path rather than the JSON body.
	Model     string
	RequestID string
	Limits    DecodeLimits
}

func normalizeDecodeLimits(l DecodeLimits) (DecodeLimits, error) {
	if l.MaxBodyBytes < 0 || l.MaxJSONDepth < 0 || l.MaxCollectionItems < 0 || l.MaxStringBytes < 0 {
		return DecodeLimits{}, fail(ErrValidation, "limits", "limits cannot be negative", nil)
	}
	if l.MaxBodyBytes == 0 {
		l.MaxBodyBytes = defaultMaxBodyBytes
	}
	if l.MaxJSONDepth == 0 {
		l.MaxJSONDepth = defaultMaxJSONDepth
	}
	if l.MaxCollectionItems == 0 {
		l.MaxCollectionItems = defaultMaxCollectionItems
	}
	if l.MaxStringBytes == 0 {
		l.MaxStringBytes = defaultMaxStringBytes
	}
	if l.MaxBodyBytes > maxConfiguredBodyBytes || l.MaxJSONDepth > maxConfiguredJSONDepth || l.MaxCollectionItems > maxConfiguredItems || l.MaxStringBytes > maxConfiguredStringBytes {
		return DecodeLimits{}, fail(ErrValidation, "limits", "configured limit exceeds hard maximum", nil)
	}
	return l, nil
}

func validateJSONEnvelope(body []byte, l DecodeLimits) error {
	if len(body) == 0 {
		return fail(ErrMalformed, "body", "empty JSON body", nil)
	}
	if len(body) > l.MaxBodyBytes {
		return fail(ErrLimit, "body", "body exceeds byte limit", nil)
	}
	depth := 0
	inString := false
	escaped := false
	stringBytes := 0
	for _, b := range body {
		if inString {
			if escaped {
				escaped = false
				stringBytes++
				continue
			}
			switch b {
			case '\\':
				escaped = true
			case '"':
				inString = false
			default:
				stringBytes++
			}
			if stringBytes > l.MaxStringBytes {
				return fail(ErrLimit, "body.string", "JSON string exceeds byte limit", nil)
			}
			continue
		}
		switch b {
		case '"':
			inString = true
			stringBytes = 0
		case '{', '[':
			depth++
			if depth > l.MaxJSONDepth {
				return fail(ErrLimit, "body.depth", "JSON nesting exceeds limit", nil)
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return fail(ErrMalformed, "body", "invalid JSON delimiters", nil)
			}
		}
	}
	if inString || depth != 0 || !json.Valid(body) {
		return fail(ErrMalformed, "body", "invalid JSON", nil)
	}
	return rejectDuplicateJSONKeys(body, l)
}

// rejectDuplicateJSONKeys recursively tokenizes without decoding numbers into
// float64. It also bounds every nested object/array, key, and string.
func rejectDuplicateJSONKeys(raw []byte, l DecodeLimits) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := scanJSONValue(d, l, 0, "body"); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fail(ErrMalformed, "body", "trailing JSON value", err)
	}
	return nil
}

func scanJSONValue(d *json.Decoder, l DecodeLimits, depth int, field string) error {
	if depth > l.MaxJSONDepth {
		return fail(ErrLimit, field, "JSON nesting exceeds limit", nil)
	}
	tok, err := d.Token()
	if err != nil {
		return fail(ErrMalformed, field, "invalid JSON", err)
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			seen := make(map[string]struct{})
			count := 0
			for d.More() {
				keyTok, err := d.Token()
				if err != nil {
					return fail(ErrMalformed, field, "invalid object key", err)
				}
				key, ok := keyTok.(string)
				if !ok {
					return fail(ErrMalformed, field, "invalid object key", nil)
				}
				if len(key) > l.MaxStringBytes {
					return fail(ErrLimit, field, "JSON key exceeds byte limit", nil)
				}
				if _, ok := seen[key]; ok {
					return fail(ErrMalformed, field+"."+key, "duplicate JSON object key", nil)
				}
				seen[key] = struct{}{}
				count++
				if count > l.MaxCollectionItems {
					return fail(ErrLimit, field, "object exceeds member limit", nil)
				}
				if err := scanJSONValue(d, l, depth+1, field+"."+key); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return fail(ErrMalformed, field, "unterminated JSON object", err)
			}
		case '[':
			count := 0
			for d.More() {
				if count >= l.MaxCollectionItems {
					return fail(ErrLimit, field, "array exceeds item limit", nil)
				}
				if err := scanJSONValue(d, l, depth+1, fmt.Sprintf("%s[%d]", field, count)); err != nil {
					return err
				}
				count++
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return fail(ErrMalformed, field, "unterminated JSON array", err)
			}
		default:
			return fail(ErrMalformed, field, "unexpected JSON delimiter", nil)
		}
	case string:
		if len(v) > l.MaxStringBytes {
			return fail(ErrLimit, field, "JSON string exceeds byte limit", nil)
		}
	}
	return nil
}

func decodeStrict(raw []byte, dst any, field string) error {
	defaults, _ := normalizeDecodeLimits(DecodeLimits{})
	if len(raw) > defaults.MaxBodyBytes {
		return fail(ErrLimit, field, "JSON value exceeds byte limit", nil)
	}
	if !json.Valid(raw) {
		return fail(ErrMalformed, field, "invalid JSON", nil)
	}
	if err := rejectDuplicateJSONKeys(raw, defaults); err != nil {
		return fail(errorCode(err), field, "invalid JSON object structure", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fail(ErrMalformed, field, "invalid or unsupported JSON shape", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fail(ErrMalformed, field, "trailing JSON value", nil)
		}
		return fail(ErrMalformed, field, "invalid trailing JSON", err)
	}
	return nil
}

func checkCount(field string, n int, l DecodeLimits) error {
	if n > l.MaxCollectionItems {
		return fail(ErrLimit, field, "collection exceeds item limit", nil)
	}
	return nil
}

func checkString(field, value string, required bool, l DecodeLimits) error {
	if required && strings.TrimSpace(value) == "" {
		return fail(ErrValidation, field, "is required", nil)
	}
	if len(value) > l.MaxStringBytes {
		return fail(ErrLimit, field, "string exceeds byte limit", nil)
	}
	return nil
}

var toolNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$`)

func validateToolName(field, name string) error {
	if !toolNamePattern.MatchString(name) {
		return fail(ErrValidation, field, "invalid tool name", nil)
	}
	return nil
}

func validateID(field, id string, required bool, l DecodeLimits) error {
	if err := checkString(field, id, required, l); err != nil {
		return err
	}
	if strings.ContainsAny(id, "\r\n\x00") {
		return fail(ErrValidation, field, "contains a control delimiter", nil)
	}
	return nil
}

func validateJSONObject(field string, raw json.RawMessage, l DecodeLimits) error {
	if err := validateJSONEnvelope(raw, l); err != nil {
		return fail(errorCode(err), field, "must be a bounded JSON object", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return fail(ErrValidation, field, "must be a JSON object", err)
	}
	return nil
}

func errorCode(err error) ErrorCode {
	if protocolErr, ok := err.(*Error); ok {
		return protocolErr.Code
	}
	return ErrValidation
}

func validateUsage(usage *Usage) error {
	if usage == nil {
		return nil
	}
	input, err := parseNonnegativeInteger("usage.input_tokens", usage.InputTokens)
	if err != nil {
		return err
	}
	output, err := parseNonnegativeInteger("usage.output_tokens", usage.OutputTokens)
	if err != nil {
		return err
	}
	total, err := parseNonnegativeInteger("usage.total_tokens", usage.TotalTokens)
	if err != nil {
		return err
	}
	want := new(big.Int).Add(input, output)
	if want.Cmp(total) != 0 {
		return fail(ErrValidation, "usage.total_tokens", "must equal input_tokens plus output_tokens", nil)
	}
	return nil
}

func validateRole(field string, role Role, allowed ...Role) error {
	for _, candidate := range allowed {
		if role == candidate {
			return nil
		}
	}
	return fail(ErrValidation, field, "role is not valid for this shape", nil)
}

func parseNonnegativeInteger(field string, number json.Number) (*big.Int, error) {
	value := number.String()
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return nil, fail(ErrValidation, field, "must be a canonical nonnegative integer", nil)
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return nil, fail(ErrValidation, field, "must be a canonical nonnegative integer", nil)
		}
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, fail(ErrValidation, field, "invalid integer", nil)
	}
	return parsed, nil
}

func validateStopReason(protocol Protocol, reason StopReason, hasToolCall bool) error {
	if reason == "" {
		return fail(ErrValidation, "stop_reason", "is required", nil)
	}
	switch protocol {
	case OpenAIChat:
		if reason == StopEndTurn || reason == StopMaxTokens || reason == StopToolUse || reason == StopContentFilter {
			return nil
		}
	case OpenAIResponses:
		if reason == StopEndTurn || reason == StopMaxTokens || reason == StopContentFilter || (reason == StopToolUse && hasToolCall) {
			return nil
		}
	case Anthropic:
		if reason == StopEndTurn || reason == StopMaxTokens || (reason == StopToolUse && hasToolCall) {
			return nil
		}
	case Gemini:
		if reason == StopEndTurn || reason == StopMaxTokens || reason == StopContentFilter || (reason == StopToolUse && hasToolCall) {
			return nil
		}
	}
	return fail(ErrUnsupported, "stop_reason", "is not representable for protocol", nil)
}
