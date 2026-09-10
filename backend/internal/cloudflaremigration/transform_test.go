package cloudflaremigration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestLegacyUserAndAPIKeyTransform(t *testing.T) {
	user := legacyUserFixture()
	transformed, err := TransformLegacyRow("users", mustJSON(t, user), CredentialTransformer{})
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]any
	if err := json.Unmarshal(transformed, &output); err != nil {
		t.Fatal(err)
	}
	if output["balance_e8_usd"] != "123456789" || output["notes"] != "" {
		t.Fatalf("legacy balance or valid empty notes transformed incorrectly: %s", transformed)
	}
	if _, exists := output["frozen_balance"]; exists {
		t.Fatal("dropped source field escaped into safe snapshot")
	}

	apiKey := legacyAPIKeyFixture("synthetic-api-key-plaintext")
	transformed, err = TransformLegacyRow("api_keys", mustJSON(t, apiKey), CredentialTransformer{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(transformed, []byte("synthetic-api-key-plaintext")) {
		t.Fatal("API-key plaintext leaked into transformed row")
	}
	digest := sha256.Sum256([]byte("synthetic-api-key-plaintext"))
	if !bytes.Contains(transformed, []byte(hex.EncodeToString(digest[:]))) {
		t.Fatal("API-key hash was not emitted")
	}
}

func TestLegacyAccountTransformIsDeterministicWithInjectedNonceAndNoLeak(t *testing.T) {
	account := legacyAccountFixture("upstream-secret-value")
	key := bytes.Repeat([]byte{0x55}, 32)
	first, err := TransformLegacyRow("accounts", mustJSON(t, account), CredentialTransformer{
		TargetKey: key, AllowedUpstreamHosts: []string{"api.openai.com"},
		Random: bytes.NewReader(bytes.Repeat([]byte{0x09}, 12)),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := TransformLegacyRow("accounts", mustJSON(t, account), CredentialTransformer{
		TargetKey: key, AllowedUpstreamHosts: []string{"api.openai.com"},
		Random: bytes.NewReader(bytes.Repeat([]byte{0x09}, 12)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("canonical source transform is not deterministic for a fixed nonce source")
	}
	if bytes.Contains(first, []byte("upstream-secret-value")) {
		t.Fatal("account credential plaintext leaked into transformed row")
	}
}

func TestLegacyTransformFailsClosed(t *testing.T) {
	user := legacyUserFixture()
	user["unknown_new_column"] = true
	if _, err := TransformLegacyRow("users", mustJSON(t, user), CredentialTransformer{}); err == nil || !strings.Contains(err.Error(), "mapping profile") {
		t.Fatalf("unknown source column was not blocked: %v", err)
	}
	user = legacyUserFixture()
	user["id"] = "9223372036854775808"
	if _, err := TransformLegacyRow("users", mustJSON(t, user), CredentialTransformer{}); err == nil {
		t.Fatal("unsigned identifier above SQLite int64 maximum accepted")
	}
	user = legacyUserFixture()
	user["frozen_balance"] = "0.00000001"
	if _, err := TransformLegacyRow("users", mustJSON(t, user), CredentialTransformer{}); err == nil || !strings.Contains(err.Error(), "reservations") {
		t.Fatalf("nonzero frozen balance was not an actionable blocker: %v", err)
	}
	account := legacyAccountFixture("secret")
	account["type"] = "oauth"
	if _, err := TransformLegacyRow("accounts", mustJSON(t, account), CredentialTransformer{}); err == nil || !strings.Contains(err.Error(), "cannot be represented") {
		t.Fatalf("unsupported credential type was not blocked: %v", err)
	}
}

func legacyUserFixture() map[string]any {
	return map[string]any{
		"id": "7", "email": "user@example.invalid", "password_hash": "$2a$10$already-hashed", "role": "user",
		"balance": "1.23456789", "frozen_balance": "0", "concurrency": 5, "status": "active",
		"username": "user", "notes": "", "totp_secret_encrypted": nil, "totp_enabled": false,
		"totp_enabled_at": nil, "signup_source": "email", "last_login_at": nil, "last_active_at": nil,
		"restrict_public_groups": false, "balance_notify_enabled": true, "balance_notify_threshold_type": "fixed",
		"balance_notify_threshold": nil, "balance_notify_extra_emails": "[]", "total_recharged": "0",
		"rpm_limit": 0, "created_at": "2026-09-09 00:00:00+00:00", "updated_at": "2026-09-09T00:00:00Z",
		"deleted_at": nil,
	}
}

func legacyAccountFixture(secret string) map[string]any {
	return map[string]any{
		"id": "11", "name": "account", "notes": "", "platform": "openai", "type": "api_key",
		"credentials": map[string]any{"api_key": secret}, "extra": map[string]any{}, "proxy_id": nil,
		"proxy_fallback_origin_id": nil, "concurrency": 3, "load_factor": nil, "priority": 50,
		"rate_multiplier": "1.0000", "status": "active", "error_message": nil, "last_used_at": nil,
		"expires_at": nil, "auto_pause_on_expired": true, "schedulable": true, "rate_limited_at": nil,
		"rate_limit_reset_at": nil, "overload_until": nil, "temp_unschedulable_until": nil,
		"temp_unschedulable_reason": nil, "session_window_start": nil, "session_window_end": nil,
		"session_window_status": nil, "parent_account_id": nil, "quota_dimension": "global",
		"created_at": "2026-09-09T00:00:00Z", "updated_at": "2026-09-09T00:00:00Z", "deleted_at": nil,
	}
}

func legacyAPIKeyFixture(secret string) map[string]any {
	return map[string]any{
		"id": "20", "user_id": "7", "key": secret, "name": "key", "group_id": "10", "status": "active",
		"last_used_at": nil, "ip_whitelist": []any{}, "ip_blacklist": []any{}, "quota": "0",
		"quota_used": "0", "expires_at": nil, "rate_limit_5h": "0", "rate_limit_1d": "0",
		"rate_limit_7d": "0", "usage_5h": "0", "usage_1d": "0", "usage_7d": "0",
		"window_5h_start": nil, "window_1d_start": nil, "window_7d_start": nil,
		"created_at": "2026-09-09T00:00:00Z", "updated_at": "2026-09-09T00:00:00Z", "deleted_at": nil,
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
