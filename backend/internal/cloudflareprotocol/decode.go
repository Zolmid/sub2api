package cloudflareprotocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func DecodeRequest(protocol Protocol, body []byte) (Request, error) {
	return DecodeRequestWithOptions(protocol, body, DecodeOptions{})
}

func DecodeRequestWithOptions(protocol Protocol, body []byte, options DecodeOptions) (Request, error) {
	limits, err := normalizeDecodeLimits(options.Limits)
	if err != nil {
		return Request{}, err
	}
	if err := validateJSONEnvelope(body, limits); err != nil {
		return Request{}, err
	}

	var request Request
	switch protocol {
	case OpenAIChat:
		request, err = decodeChatRequest(body, limits)
	case OpenAIResponses:
		request, err = decodeResponsesRequest(body, limits)
	case Anthropic:
		request, err = decodeAnthropicRequest(body, limits)
	case Gemini:
		if err := checkString("options.model", options.Model, true, limits); err != nil {
			return Request{}, err
		}
		request, err = decodeGeminiRequest(body, options.Model, limits)
	default:
		return Request{}, fail(ErrUnsupported, "protocol", "unknown protocol", nil)
	}
	if err != nil {
		return Request{}, err
	}
	if options.Model != "" && protocol != Gemini && options.Model != request.Model {
		return Request{}, fail(ErrValidation, "options.model", "does not match body model", nil)
	}
	if err := validateID("options.request_id", options.RequestID, false, limits); err != nil {
		return Request{}, err
	}
	request.RequestID = options.RequestID
	if err := validateRequest(request, limits); err != nil {
		return Request{}, err
	}
	return request, nil
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), raw...)
}

func decodeStopSequences(raw json.RawMessage, field string, limits DecodeLimits) ([]string, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if err := checkString(field, one, true, limits); err != nil {
			return nil, err
		}
		return []string{one}, nil
	}
	var many []string
	if err := decodeStrict(raw, &many, field); err != nil {
		return nil, err
	}
	if err := checkCount(field, len(many), limits); err != nil {
		return nil, err
	}
	for i, value := range many {
		if err := checkString(fmt.Sprintf("%s[%d]", field, i), value, true, limits); err != nil {
			return nil, err
		}
	}
	return many, nil
}

func decodeTokenLimit(field string, value json.Number) (json.Number, error) {
	if value == "" {
		return "", nil
	}
	parsed, err := parseNonnegativeInteger(field, value)
	if err != nil {
		return "", err
	}
	if parsed.Sign() == 0 {
		return "", fail(ErrValidation, field, "must be greater than zero", nil)
	}
	return value, nil
}

func validateMediaURI(field, value string, limits DecodeLimits) error {
	if err := checkString(field, value, true, limits); err != nil {
		return err
	}
	if value != strings.TrimSpace(value) || strings.ContainsAny(value, "\\\r\n\x00") {
		return fail(ErrValidation, field, "contains unsafe URI characters", nil)
	}
	u, err := url.Parse(value)
	if err != nil {
		return fail(ErrValidation, field, "invalid external URI", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fail(ErrUnsupported, field, "only http and https external references are supported", nil)
	}
	if u.Opaque != "" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fail(ErrValidation, field, "URI must have a host and no credentials or fragment", nil)
	}
	if !strings.HasPrefix(value, u.Scheme+"://") {
		return fail(ErrValidation, field, "URI uses an unsafe or ambiguous form", nil)
	}
	return nil
}
