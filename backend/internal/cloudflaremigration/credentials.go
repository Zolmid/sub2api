package cloudflaremigration

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
)

const (
	credentialEnvelopePrefix = "aes-gcm:v1:"
	totpEnvelopePrefix       = "aes-gcm:v1:totp:"
	totpEnvelopeAAD          = "sub2api:totp:v1"
)

var totpSecretPattern = regexp.MustCompile(`^[A-Z2-7]{32}$`)

// CredentialTransformer converts legacy secrets without ever returning their
// plaintext. TargetKey is the Worker's base64-decoded 32-byte
// CREDENTIAL_ENCRYPTION_KEY. LegacyTOTPKey is the old 32-byte hex-decoded key.
type CredentialTransformer struct {
	TargetKey            []byte
	LegacyTOTPKey        []byte
	AllowedUpstreamHosts []string
	Random               io.Reader
}

func DecodeTargetCredentialKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("target credential key must be base64 encoding of exactly 32 bytes")
	}
	return decoded, nil
}

func DecodeLegacyTOTPKey(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("legacy TOTP key must be exactly 64 hexadecimal characters")
	}
	return decoded, nil
}

func ParseAllowedUpstreamHosts(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS is required when accounts are exported")
	}
	seen := map[string]bool{}
	result := []string{}
	for _, raw := range strings.Split(value, ",") {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		base := strings.TrimPrefix(host, "*.")
		if host == "" || len(host) > 253 || base == "" || strings.ContainsAny(host, "/?#@:") || strings.Contains(base, "*") || containsControl(host) {
			return nil, errors.New("upstream host allowlist contains an invalid hostname pattern")
		}
		if !seen[host] {
			seen[host] = true
			result = append(result, host)
		}
	}
	return result, nil
}

func (transformer CredentialTransformer) encryptAccountCredentials(accountID, platform string, raw json.RawMessage) (string, error) {
	if len(transformer.TargetKey) != 32 {
		return "", fmt.Errorf("account %s requires the target credential key via environment or file descriptor", accountID)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return "", fmt.Errorf("account %s credentials JSON is invalid", accountID)
	}
	var source map[string]json.RawMessage
	if err := json.Unmarshal(raw, &source); err != nil || source == nil {
		return "", fmt.Errorf("account %s credentials must be a JSON object", accountID)
	}
	for key := range source {
		if key != "api_key" && key != "base_url" {
			return "", fmt.Errorf("account %s has unsupported legacy credential field %q; no secret was exported", accountID, key)
		}
	}
	apiKey, err := requiredString(source, "api_key")
	if err != nil || apiKey == "" || len(apiKey) > 16_384 || containsControl(apiKey) {
		return "", fmt.Errorf("account %s has an invalid legacy api_key; no secret was exported", accountID)
	}
	baseURL := ""
	if rawBaseURL, ok := source["base_url"]; ok {
		if err := json.Unmarshal(rawBaseURL, &baseURL); err != nil {
			return "", fmt.Errorf("account %s has a non-string legacy base_url", accountID)
		}
	}
	if strings.TrimSpace(baseURL) == "" {
		if platform != "openai" {
			return "", fmt.Errorf("account %s lacks base_url and platform %q has no audited D1 default", accountID, platform)
		}
		baseURL = "https://api.openai.com"
	}
	normalizedURL, err := validateCredentialURL(baseURL, transformer.AllowedUpstreamHosts)
	if err != nil {
		return "", fmt.Errorf("account %s base_url is not accepted by the Worker credential contract: %w", accountID, err)
	}
	plaintext, err := json.Marshal(struct {
		APIKey  string `json:"api_key"`
		BaseURL string `json:"base_url"`
	}{APIKey: apiKey, BaseURL: normalizedURL})
	if err != nil {
		return "", fmt.Errorf("account %s credentials could not be canonicalized", accountID)
	}
	defer zeroBytes(plaintext)
	return transformer.encrypt(credentialEnvelopePrefix, plaintext, nil)
}

func (transformer CredentialTransformer) reencryptTOTP(userID, legacyEnvelope string) (string, error) {
	if len(transformer.LegacyTOTPKey) != 32 {
		return "", fmt.Errorf("user %s has enabled TOTP and requires the legacy TOTP key via environment or file descriptor", userID)
	}
	if len(transformer.TargetKey) != 32 {
		return "", fmt.Errorf("user %s has enabled TOTP and requires the target credential key via environment or file descriptor", userID)
	}
	encoded, err := base64.StdEncoding.DecodeString(legacyEnvelope)
	if err != nil {
		return "", fmt.Errorf("user %s legacy TOTP envelope is not valid base64", userID)
	}
	block, err := aes.NewCipher(transformer.LegacyTOTPKey)
	if err != nil {
		return "", fmt.Errorf("user %s legacy TOTP key is unusable", userID)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(encoded) < gcm.NonceSize()+gcm.Overhead()+1 {
		return "", fmt.Errorf("user %s legacy TOTP envelope is truncated", userID)
	}
	secret, err := gcm.Open(nil, encoded[:gcm.NonceSize()], encoded[gcm.NonceSize():], nil)
	if err != nil || !totpSecretPattern.Match(secret) {
		return "", fmt.Errorf("user %s legacy TOTP envelope cannot be decrypted into the required 32-character base32 secret", userID)
	}
	defer zeroBytes(secret)
	return transformer.encrypt(totpEnvelopePrefix, secret, []byte(totpEnvelopeAAD))
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (transformer CredentialTransformer) encrypt(prefix string, plaintext, aad []byte) (string, error) {
	block, err := aes.NewCipher(transformer.TargetKey)
	if err != nil {
		return "", errors.New("target credential key is unusable")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("target credential cipher is unavailable")
	}
	nonce := make([]byte, gcm.NonceSize())
	random := transformer.Random
	if random == nil {
		random = rand.Reader
	}
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", errors.New("secure credential nonce generation failed")
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return prefix + base64.StdEncoding.EncodeToString(nonce) + ":" + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func validateCredentialURL(value string, allowed []string) (string, error) {
	if len(value) > 2_048 || containsControl(value) {
		return "", errors.New("URL is empty, oversized, or contains a control character")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("URL must be HTTPS without userinfo, query, or fragment")
	}
	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if hostname == "" || parsed.Port() != "" {
		return "", errors.New("URL hostname is invalid or includes an unsupported explicit port")
	}
	matched := false
	for _, pattern := range allowed {
		if pattern == hostname || strings.HasPrefix(pattern, "*.") && len(hostname) > len(pattern)-1 && strings.HasSuffix(hostname, pattern[1:]) {
			matched = true
			break
		}
	}
	if !matched {
		return "", errors.New("hostname is absent from SUB2API_CF_UPSTREAM_ALLOWED_HOSTS")
	}
	parsed.Scheme = "https"
	if port := parsed.Port(); port != "" {
		parsed.Host = net.JoinHostPort(hostname, port)
	} else {
		parsed.Host = hostname
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}
