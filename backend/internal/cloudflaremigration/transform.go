package cloudflaremigration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

var legacySourceColumns = map[string][]string{
	"groups": {
		"id", "name", "description", "rate_multiplier", "peak_rate_enabled", "peak_start", "peak_end", "peak_rate_multiplier",
		"is_exclusive", "status", "duplicate_operation_id", "platform", "subscription_type", "daily_limit_usd", "weekly_limit_usd",
		"monthly_limit_usd", "default_validity_days", "allow_image_generation", "allow_batch_image_generation", "image_rate_independent",
		"image_rate_multiplier", "image_price_1k", "image_price_2k", "image_price_4k", "batch_image_discount_multiplier",
		"batch_image_hold_multiplier", "video_rate_independent", "video_rate_multiplier", "video_price_480p", "video_price_720p",
		"video_price_1080p", "video_model_prices", "web_search_price_per_call", "search_price_per_1k", "audio_realtime_price_per_min",
		"audio_tts_price_per_million_chars", "audio_stt_price_per_hour", "long_context_pricing_enabled", "model_pricing",
		"claude_code_only", "fallback_group_id", "fallback_group_id_on_invalid_request", "model_routing", "model_routing_enabled",
		"mcp_xml_inject", "supported_model_scopes", "sort_order", "allow_messages_dispatch", "allow_live", "force_openai_fast",
		"free_openai_fast", "require_oauth_only", "require_privacy_set", "default_mapped_model", "messages_dispatch_model_config",
		"models_list_config", "codex_models_manifest_config", "rpm_limit", "max_reasoning_effort", "max_reasoning_effort_over_limit",
		"reasoning_effort_mappings", "profit_control_enabled", "profit_min_margin", "profit_safety_buffer", "created_at", "updated_at", "deleted_at",
	},
	"users":                  {"id", "email", "password_hash", "role", "balance", "frozen_balance", "concurrency", "status", "username", "notes", "totp_secret_encrypted", "totp_enabled", "totp_enabled_at", "signup_source", "last_login_at", "last_active_at", "restrict_public_groups", "balance_notify_enabled", "balance_notify_threshold_type", "balance_notify_threshold", "balance_notify_extra_emails", "total_recharged", "rpm_limit", "created_at", "updated_at", "deleted_at"},
	"accounts":               {"id", "name", "notes", "platform", "type", "credentials", "extra", "proxy_id", "proxy_fallback_origin_id", "concurrency", "load_factor", "priority", "rate_multiplier", "status", "error_message", "last_used_at", "expires_at", "auto_pause_on_expired", "schedulable", "rate_limited_at", "rate_limit_reset_at", "overload_until", "temp_unschedulable_until", "temp_unschedulable_reason", "session_window_start", "session_window_end", "session_window_status", "parent_account_id", "quota_dimension", "created_at", "updated_at", "deleted_at"},
	"account_groups":         {"account_id", "group_id", "priority", "created_at"},
	"user_allowed_groups":    {"user_id", "group_id", "created_at"},
	"api_keys":               {"id", "user_id", "key", "name", "group_id", "status", "last_used_at", "ip_whitelist", "ip_blacklist", "quota", "quota_used", "expires_at", "rate_limit_5h", "rate_limit_1d", "rate_limit_7d", "usage_5h", "usage_1d", "usage_7d", "window_5h_start", "window_1d_start", "window_7d_start", "created_at", "updated_at", "deleted_at"},
	"schema_migrations":      {"filename", "checksum", "applied_at"},
	"atlas_schema_revisions": {"version", "description", "type", "applied", "total", "executed_at", "execution_time", "error", "error_stmt", "hash", "partial_hashes", "operator_version"},
}

func expectedPostgreSQLColumns(table string) ([]string, bool) {
	if columns, ok := legacySourceColumns[table]; ok {
		return append([]string(nil), columns...), true
	}
	switch table {
	case "pricing_versions", "pricing_rules", "pricing_active_version", "model_aliases", "balance_ledger":
		columns := make([]string, 0, len(targetSchemas[table].fields))
		for column := range targetSchemas[table].fields {
			columns = append(columns, column)
		}
		return columns, true
	default:
		return nil, false
	}
}

// TransformLegacyRow converts a PostgreSQL row_to_json result into the
// secret-safe v2 snapshot representation. Unknown columns and unsupported
// non-default state fail closed.
func TransformLegacyRow(table string, raw json.RawMessage, credentials CredentialTransformer) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > MaxRowBytes {
		return nil, fmt.Errorf("%s source row is empty or oversized", table)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, fmt.Errorf("%s source row JSON is invalid", table)
	}
	var row map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&row); err != nil || row == nil {
		return nil, fmt.Errorf("%s source row must be an object", table)
	}
	if err := ensureEOF(decoder); err != nil {
		return nil, fmt.Errorf("%s source row has trailing JSON", table)
	}

	var transformed map[string]any
	var err error
	switch table {
	case "groups":
		transformed, err = transformLegacyGroup(row)
	case "users":
		transformed, err = transformLegacyUser(row, credentials)
	case "accounts":
		transformed, err = transformLegacyAccount(row, credentials)
	case "account_groups":
		transformed, err = transformLegacyAccountGroup(row)
	case "user_allowed_groups":
		transformed, err = transformLegacyUserAllowedGroup(row)
	case "api_keys":
		transformed, err = transformLegacyAPIKey(row)
	case "pricing_versions", "pricing_rules", "pricing_active_version", "model_aliases", "balance_ledger":
		return normalizeTargetLikeRow(table, row)
	case "schema_migrations":
		transformed, err = transformSchemaMigration(row)
	case "atlas_schema_revisions":
		transformed, err = transformAtlasRevision(row)
	default:
		return nil, fmt.Errorf("source table %q has no row transformer", table)
	}
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(transformed)
	if err != nil {
		return nil, fmt.Errorf("%s transformed row could not be encoded", table)
	}
	canonical, err := CanonicalJSON(encoded)
	if err != nil {
		return nil, err
	}
	switch table {
	case "groups", "accounts", "account_groups", "api_keys":
		validated, _, validationErr := validateAndCanonicalizeRow(table, canonical)
		return validated, validationErr
	default:
		return canonical, nil
	}
}

func transformLegacyGroup(row map[string]json.RawMessage) (map[string]any, error) {
	if err := requireExactColumns("groups", row, legacySourceColumns["groups"]); err != nil {
		return nil, err
	}
	for _, field := range []string{"description", "duplicate_operation_id", "daily_limit_usd", "weekly_limit_usd", "monthly_limit_usd", "image_price_1k", "image_price_2k", "image_price_4k", "video_price_480p", "video_price_720p", "video_price_1080p", "web_search_price_per_call", "search_price_per_1k", "audio_realtime_price_per_min", "audio_tts_price_per_million_chars", "audio_stt_price_per_hour", "fallback_group_id", "fallback_group_id_on_invalid_request"} {
		if err := requireNull("groups", row, field); err != nil {
			return nil, err
		}
	}
	for _, field := range []string{"peak_rate_enabled", "allow_image_generation", "allow_batch_image_generation", "image_rate_independent", "video_rate_independent", "claude_code_only", "model_routing_enabled", "allow_messages_dispatch", "allow_live", "force_openai_fast", "free_openai_fast", "require_oauth_only", "require_privacy_set", "profit_control_enabled"} {
		if err := requireBoolDefault("groups", row, field, false); err != nil {
			return nil, err
		}
	}
	for _, field := range []string{"long_context_pricing_enabled", "mcp_xml_inject"} {
		if err := requireBoolDefault("groups", row, field, true); err != nil {
			return nil, err
		}
	}
	for field, expected := range map[string]string{"peak_start": "", "peak_end": "", "default_mapped_model": "", "max_reasoning_effort": "", "max_reasoning_effort_over_limit": "downgrade"} {
		if err := requireStringDefault("groups", row, field, expected); err != nil {
			return nil, err
		}
	}
	for field, expected := range map[string]string{"rate_multiplier": "1", "peak_rate_multiplier": "1", "image_rate_multiplier": "1", "batch_image_discount_multiplier": "0.5", "batch_image_hold_multiplier": "0.6", "video_rate_multiplier": "1", "profit_min_margin": "0", "profit_safety_buffer": "0"} {
		if err := requireDecimalDefault("groups", row, field, expected); err != nil {
			return nil, err
		}
	}
	for field, expected := range map[string]int64{"default_validity_days": 30, "sort_order": 0, "rpm_limit": 0} {
		if err := requireIntDefault("groups", row, field, expected); err != nil {
			return nil, err
		}
	}
	for _, field := range []string{"video_model_prices", "model_pricing", "model_routing", "messages_dispatch_model_config", "models_list_config", "codex_models_manifest_config"} {
		if err := requireNullOrEmptyObject("groups", row, field); err != nil {
			return nil, err
		}
	}
	if err := requireJSONDefault("groups", row, "reasoning_effort_mappings", `[]`); err != nil {
		return nil, err
	}
	if err := requireJSONDefault("groups", row, "supported_model_scopes", `["claude","gemini_text","gemini_image"]`); err != nil {
		return nil, err
	}
	return normalizeSelectedTarget("groups", row, []string{"id", "name", "platform", "status", "is_exclusive", "subscription_type", "created_at", "updated_at", "deleted_at"})
}

func transformLegacyUser(row map[string]json.RawMessage, credentials CredentialTransformer) (map[string]any, error) {
	if err := requireExactColumns("users", row, legacySourceColumns["users"]); err != nil {
		return nil, err
	}
	if err := requireDecimalDefault("users", row, "frozen_balance", "0"); err != nil {
		return nil, errors.New("users.frozen_balance is nonzero; migrate reservations and settlements before exporting")
	}
	for _, field := range []string{"last_login_at", "last_active_at", "balance_notify_threshold"} {
		if err := requireNull("users", row, field); err != nil {
			return nil, err
		}
	}
	for field, expected := range map[string]string{"signup_source": "email", "balance_notify_threshold_type": "fixed", "balance_notify_extra_emails": "[]"} {
		if err := requireStringDefault("users", row, field, expected); err != nil {
			return nil, err
		}
	}
	if err := requireBoolDefault("users", row, "balance_notify_enabled", true); err != nil {
		return nil, err
	}
	if err := requireDecimalDefault("users", row, "total_recharged", "0"); err != nil {
		return nil, err
	}
	id, err := legacyID(row["id"])
	if err != nil {
		return nil, errors.New("users.id is invalid")
	}
	balance, err := rawDecimalToE8(row["balance"])
	if err != nil {
		return nil, fmt.Errorf("user %s balance cannot be represented exactly as E8: %w", id, err)
	}
	enabled, err := legacyBool(row["totp_enabled"])
	if err != nil {
		return nil, fmt.Errorf("user %s totp_enabled is invalid", id)
	}
	enabledAt, err := legacyNullableTimestamp(row["totp_enabled_at"])
	if err != nil {
		return nil, fmt.Errorf("user %s totp_enabled_at is invalid", id)
	}
	var targetSecret any
	revision := int64(0)
	if enabled {
		legacySecret, secretErr := legacyString(row["totp_secret_encrypted"])
		if secretErr != nil || legacySecret == "" || enabledAt == nil {
			return nil, fmt.Errorf("user %s has incomplete enabled TOTP state", id)
		}
		envelope, reencryptErr := credentials.reencryptTOTP(id, legacySecret)
		if reencryptErr != nil {
			return nil, reencryptErr
		}
		targetSecret, revision = envelope, 1
	} else {
		if !isNull(row["totp_secret_encrypted"]) || enabledAt != nil {
			return nil, fmt.Errorf("user %s has a disabled TOTP secret; refusing to discard it", id)
		}
		targetSecret = nil
	}
	selected, err := normalizeSelectedTarget("users", row, []string{"status", "role", "concurrency", "restrict_public_groups", "created_at", "email", "password_hash", "username", "notes", "rpm_limit", "updated_at", "deleted_at"})
	if err != nil {
		return nil, err
	}
	selected["id"] = id
	selected["balance_e8_usd"] = balance
	selected["totp_secret_envelope"] = targetSecret
	selected["totp_enabled"] = enabled
	selected["totp_enabled_at"] = enabledAt
	selected["totp_revision"] = revision
	return selected, nil
}

func transformLegacyAccount(row map[string]json.RawMessage, credentials CredentialTransformer) (map[string]any, error) {
	if err := requireExactColumns("accounts", row, legacySourceColumns["accounts"]); err != nil {
		return nil, err
	}
	for _, field := range []string{"proxy_id", "proxy_fallback_origin_id", "load_factor", "error_message", "last_used_at", "expires_at", "rate_limited_at", "rate_limit_reset_at", "overload_until", "temp_unschedulable_until", "temp_unschedulable_reason", "session_window_start", "session_window_end", "session_window_status", "parent_account_id"} {
		if err := requireNullOrEmptyString("accounts", row, field); err != nil {
			return nil, err
		}
	}
	if err := requireNullOrEmptyString("accounts", row, "notes"); err != nil {
		return nil, errors.New("accounts.notes is nonempty and target 0001-0008 has no account notes column")
	}
	if err := requireDecimalDefault("accounts", row, "rate_multiplier", "1"); err != nil {
		return nil, err
	}
	if err := requireBoolDefault("accounts", row, "auto_pause_on_expired", true); err != nil {
		return nil, err
	}
	if err := requireStringDefault("accounts", row, "quota_dimension", "global"); err != nil {
		return nil, err
	}
	id, idErr := legacyID(row["id"])
	typeName, typeErr := legacyString(row["type"])
	platform, platformErr := legacyString(row["platform"])
	if idErr != nil || typeErr != nil || platformErr != nil {
		return nil, errors.New("accounts identity, type, or platform is invalid")
	}
	if typeName != "api_key" {
		return nil, fmt.Errorf("account %s type %q cannot be represented by the canonical Worker credential contract", id, typeName)
	}
	envelope, err := credentials.encryptAccountCredentials(id, platform, row["credentials"])
	if err != nil {
		return nil, err
	}
	extra, err := canonicalJSONObjectString(row["extra"])
	if err != nil {
		return nil, fmt.Errorf("account %s extra JSON is invalid", id)
	}
	var extraValue any
	if json.Unmarshal([]byte(extra), &extraValue) != nil || containsSecretField(extraValue) {
		return nil, fmt.Errorf("account %s extra JSON contains a secret-shaped field and cannot be written to the snapshot", id)
	}
	selected, err := normalizeSelectedTarget("accounts", row, []string{"name", "platform", "type", "status", "schedulable", "priority", "created_at", "updated_at", "deleted_at"})
	if err != nil {
		return nil, err
	}
	selected["id"] = id
	selected["max_concurrency"], err = legacyInteger(row["concurrency"])
	if err != nil {
		return nil, errors.New("accounts.concurrency is invalid")
	}
	selected["credential_envelope"] = envelope
	selected["extra_json"] = extra
	return selected, nil
}

func transformLegacyAccountGroup(row map[string]json.RawMessage) (map[string]any, error) {
	if err := requireExactColumns("account_groups", row, legacySourceColumns["account_groups"]); err != nil {
		return nil, err
	}
	if err := requireIntDefault("account_groups", row, "priority", 50); err != nil {
		return nil, err
	}
	if _, err := legacyTimestamp(row["created_at"]); err != nil {
		return nil, errors.New("account_groups.created_at is invalid")
	}
	accountID, accountErr := legacyID(row["account_id"])
	groupID, groupErr := legacyID(row["group_id"])
	if accountErr != nil || groupErr != nil {
		return nil, errors.New("account_groups identity is invalid")
	}
	return map[string]any{"account_id": accountID, "group_id": groupID}, nil
}

func transformLegacyUserAllowedGroup(row map[string]json.RawMessage) (map[string]any, error) {
	if err := requireExactColumns("user_allowed_groups", row, legacySourceColumns["user_allowed_groups"]); err != nil {
		return nil, err
	}
	if _, err := legacyTimestamp(row["created_at"]); err != nil {
		return nil, errors.New("user_allowed_groups.created_at is invalid")
	}
	userID, userErr := legacyID(row["user_id"])
	groupID, groupErr := legacyID(row["group_id"])
	if userErr != nil || groupErr != nil {
		return nil, errors.New("user_allowed_groups identity is invalid")
	}
	return map[string]any{"user_id": userID, "group_id": groupID}, nil
}

func transformLegacyAPIKey(row map[string]json.RawMessage) (map[string]any, error) {
	if err := requireExactColumns("api_keys", row, legacySourceColumns["api_keys"]); err != nil {
		return nil, err
	}
	for _, field := range []string{"quota", "quota_used", "rate_limit_5h", "rate_limit_1d", "rate_limit_7d", "usage_5h", "usage_1d", "usage_7d"} {
		if err := requireDecimalDefault("api_keys", row, field, "0"); err != nil {
			return nil, fmt.Errorf("api_keys.%s is nonzero; target 0001-0008 cannot preserve this quota state", field)
		}
	}
	for _, field := range []string{"window_5h_start", "window_1d_start", "window_7d_start"} {
		if err := requireNull("api_keys", row, field); err != nil {
			return nil, err
		}
	}
	id, idErr := legacyID(row["id"])
	userID, userErr := legacyID(row["user_id"])
	groupID, groupErr := legacyID(row["group_id"])
	plaintext, keyErr := legacyString(row["key"])
	if idErr != nil || userErr != nil || groupErr != nil || keyErr != nil || plaintext == "" || containsControl(plaintext) {
		return nil, errors.New("api_keys identity, group, or plaintext key is invalid")
	}
	digest := sha256.Sum256([]byte(plaintext))
	whitelist, whitelistErr := canonicalJSONArrayString(row["ip_whitelist"])
	blacklist, blacklistErr := canonicalJSONArrayString(row["ip_blacklist"])
	if whitelistErr != nil || blacklistErr != nil {
		return nil, fmt.Errorf("api_key %s IP list JSON is invalid", id)
	}
	selected, err := normalizeSelectedTarget("api_keys", row, []string{"name", "status", "expires_at", "last_used_at", "created_at", "updated_at", "deleted_at"})
	if err != nil {
		return nil, err
	}
	selected["id"], selected["user_id"], selected["group_id"] = id, userID, groupID
	selected["key_hash"] = hex.EncodeToString(digest[:])
	selected["ip_whitelist_json"], selected["ip_blacklist_json"] = whitelist, blacklist
	return selected, nil
}

func transformSchemaMigration(row map[string]json.RawMessage) (map[string]any, error) {
	if err := requireExactColumns("schema_migrations", row, legacySourceColumns["schema_migrations"]); err != nil {
		return nil, err
	}
	filename, filenameErr := legacyString(row["filename"])
	checksum, checksumErr := legacyString(row["checksum"])
	appliedAt, timestampErr := legacyTimestamp(row["applied_at"])
	if filenameErr != nil || checksumErr != nil || timestampErr != nil || filename == "" || containsControl(filename) || validateLowerSHA256(checksum) != nil {
		return nil, errors.New("schema_migrations row is invalid")
	}
	return map[string]any{"filename": filename, "checksum": checksum, "applied_at": appliedAt}, nil
}

func transformAtlasRevision(row map[string]json.RawMessage) (map[string]any, error) {
	if err := requireExactColumns("atlas_schema_revisions", row, legacySourceColumns["atlas_schema_revisions"]); err != nil {
		return nil, err
	}
	result := map[string]any{}
	for key, raw := range row {
		if key == "executed_at" {
			value, err := legacyTimestamp(raw)
			if err != nil {
				return nil, errors.New("atlas_schema_revisions.executed_at is invalid")
			}
			result[key] = value
			continue
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil || containsControlInValue(value) {
			return nil, fmt.Errorf("atlas_schema_revisions.%s is invalid", key)
		}
		result[key] = value
	}
	return result, nil
}

func normalizeTargetLikeRow(table string, row map[string]json.RawMessage) (json.RawMessage, error) {
	fields := make([]string, 0, len(targetSchemas[table].fields))
	for field := range targetSchemas[table].fields {
		fields = append(fields, field)
	}
	if err := requireExactColumns(table, row, fields); err != nil {
		return nil, err
	}
	normalized, err := normalizeSelectedTarget(table, row, fields)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	canonical, _, err := validateAndCanonicalizeRow(table, encoded)
	return canonical, err
}

func normalizeSelectedTarget(table string, row map[string]json.RawMessage, fields []string) (map[string]any, error) {
	result := make(map[string]any, len(fields))
	for _, field := range fields {
		kind, ok := targetSchemas[table].fields[field]
		if !ok {
			return nil, fmt.Errorf("%s.%s is not in the pinned target schema", table, field)
		}
		raw, ok := row[field]
		if !ok {
			return nil, fmt.Errorf("%s source row is missing column %q", table, field)
		}
		value, err := normalizeLegacyTargetField(kind, raw)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", table, field, err)
		}
		result[field] = value
	}
	return result, nil
}

func normalizeLegacyTargetField(kind fieldKind, raw json.RawMessage) (any, error) {
	if isNull(raw) {
		if kind == nullableTextField || kind == nullableTimestampField {
			return nil, nil
		}
		return nil, errors.New("value may not be null")
	}
	switch kind {
	case textField, nullableTextField, hexDigestField:
		return legacyString(raw)
	case boolField:
		return legacyBool(raw)
	case integerField:
		return legacyInteger(raw)
	case unsignedIDField:
		return legacyID(raw)
	case unsignedE8Field, signedE8Field:
		value, err := legacyDecimalText(raw)
		if err != nil || strings.Contains(value, ".") || strings.ContainsAny(value, "eE+") {
			return nil, errors.New("E8 value must already be an exact integer")
		}
		if err := validateE8(value, kind == signedE8Field); err != nil {
			return nil, err
		}
		return value, nil
	case timestampField:
		return legacyTimestamp(raw)
	case nullableTimestampField:
		return legacyNullableTimestamp(raw)
	case jsonArrayField:
		return canonicalJSONArrayString(raw)
	case jsonObjectField:
		return canonicalJSONObjectString(raw)
	default:
		return nil, errors.New("unsupported target field kind")
	}
}

func requireExactColumns(table string, row map[string]json.RawMessage, columns []string) error {
	wanted := make(map[string]bool, len(columns))
	for _, column := range columns {
		wanted[column] = true
		if _, ok := row[column]; !ok {
			return fmt.Errorf("%s source row is missing required column %q", table, column)
		}
	}
	for column := range row {
		if !wanted[column] {
			return fmt.Errorf("%s source row has unknown column %q; mapping profile %s must be extended explicitly", table, column, MappingProfileVersion)
		}
	}
	return nil
}

func requireNull(table string, row map[string]json.RawMessage, field string) error {
	if !isNull(row[field]) {
		return fmt.Errorf("%s.%s must be null because target 0001-0008 cannot preserve it", table, field)
	}
	return nil
}

func requireNullOrEmptyString(table string, row map[string]json.RawMessage, field string) error {
	if isNull(row[field]) {
		return nil
	}
	value, err := legacyString(row[field])
	if err != nil || value != "" {
		return fmt.Errorf("%s.%s must be null or empty because target 0001-0008 cannot preserve it", table, field)
	}
	return nil
}

func requireNullOrEmptyObject(table string, row map[string]json.RawMessage, field string) error {
	if isNull(row[field]) {
		return nil
	}
	value, err := canonicalJSONObjectString(row[field])
	if err != nil || value != "{}" {
		return fmt.Errorf("%s.%s must be null or an empty object because target 0001-0008 cannot preserve it", table, field)
	}
	return nil
}

func requireBoolDefault(table string, row map[string]json.RawMessage, field string, expected bool) error {
	value, err := legacyBool(row[field])
	if err != nil || value != expected {
		return fmt.Errorf("%s.%s differs from required safe default %t", table, field, expected)
	}
	return nil
}

func requireStringDefault(table string, row map[string]json.RawMessage, field, expected string) error {
	value, err := legacyString(row[field])
	if err != nil || value != expected {
		return fmt.Errorf("%s.%s differs from its required safe default", table, field)
	}
	return nil
}

func requireIntDefault(table string, row map[string]json.RawMessage, field string, expected int64) error {
	value, err := legacyInteger(row[field])
	if err != nil || value != expected {
		return fmt.Errorf("%s.%s differs from required safe default %d", table, field, expected)
	}
	return nil
}

func requireDecimalDefault(table string, row map[string]json.RawMessage, field, expected string) error {
	value, err := legacyDecimalText(row[field])
	left, leftOK := new(big.Rat).SetString(value)
	right, rightOK := new(big.Rat).SetString(expected)
	if err != nil || !leftOK || !rightOK || left.Cmp(right) != 0 {
		return fmt.Errorf("%s.%s differs from required safe default %s", table, field, expected)
	}
	return nil
}

func requireJSONDefault(table string, row map[string]json.RawMessage, field, expected string) error {
	actual, err := canonicalJSONText(row[field])
	canonicalExpected, expectedErr := CanonicalJSON([]byte(expected))
	if err != nil || expectedErr != nil || actual != string(canonicalExpected) {
		return fmt.Errorf("%s.%s differs from its required safe JSON default", table, field)
	}
	return nil
}

func rawDecimalToE8(raw json.RawMessage) (string, error) {
	value, err := legacyDecimalText(raw)
	if err != nil {
		return "", err
	}
	return decimalToE8(value)
}

func legacyDecimalText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || isNull(raw) {
		return "", errors.New("decimal is missing")
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if text == "" || containsControl(text) {
			return "", errors.New("decimal is invalid")
		}
		return text, nil
	}
	text = string(bytes.TrimSpace(raw))
	if strings.ContainsAny(text, "eE+") {
		return "", errors.New("decimal exponent or plus sign is not accepted")
	}
	if _, ok := new(big.Rat).SetString(text); !ok {
		return "", errors.New("decimal is invalid")
	}
	return text, nil
}

func legacyID(raw json.RawMessage) (string, error) {
	value, err := legacyDecimalText(raw)
	if err != nil || !canonicalUnsignedID(value) {
		return "", errors.New("identifier must be in 1..9223372036854775807")
	}
	return value, nil
}

func legacyInteger(raw json.RawMessage) (int64, error) {
	value, err := legacyDecimalText(raw)
	if err != nil || strings.Contains(value, ".") {
		return 0, errors.New("integer is invalid")
	}
	return strconv.ParseInt(value, 10, 64)
}

func legacyBool(raw json.RawMessage) (bool, error) {
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, errors.New("boolean is invalid")
	}
	return value, nil
}

func legacyString(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || containsControl(value) {
		return "", errors.New("text is invalid or contains a control character")
	}
	return value, nil
}

func legacyTimestamp(raw json.RawMessage) (string, error) {
	value, err := legacyString(raw)
	if err != nil {
		return "", err
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00"} {
		parsed, parseErr := time.Parse(layout, value)
		if parseErr == nil {
			return parsed.UTC().Format(time.RFC3339Nano), nil
		}
	}
	return "", errors.New("timestamp is not RFC3339-compatible")
}

func legacyNullableTimestamp(raw json.RawMessage) (any, error) {
	if isNull(raw) {
		return nil, nil
	}
	return legacyTimestamp(raw)
}

func canonicalJSONArrayString(raw json.RawMessage) (string, error) {
	return canonicalJSONShapeString(raw, '[')
}

func canonicalJSONObjectString(raw json.RawMessage) (string, error) {
	return canonicalJSONShapeString(raw, '{')
}

func canonicalJSONShapeString(raw json.RawMessage, shape byte) (string, error) {
	if isNull(raw) {
		if shape == '[' {
			return "[]", nil
		}
		return "{}", nil
	}
	text := string(raw)
	var encoded string
	if json.Unmarshal(raw, &encoded) == nil {
		text = encoded
	}
	canonical, err := CanonicalJSON([]byte(text))
	if err != nil || len(canonical) == 0 || canonical[0] != shape {
		return "", errors.New("JSON has the wrong canonical shape")
	}
	return string(canonical), nil
}

func canonicalJSONText(raw json.RawMessage) (string, error) {
	if isNull(raw) {
		return "null", nil
	}
	text := string(raw)
	var encoded string
	if json.Unmarshal(raw, &encoded) == nil && (strings.HasPrefix(encoded, "[") || strings.HasPrefix(encoded, "{")) {
		text = encoded
	}
	canonical, err := CanonicalJSON([]byte(text))
	return string(canonical), err
}

func isNull(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func containsControlInValue(value any) bool {
	switch typed := value.(type) {
	case string:
		return containsControl(typed)
	case map[string]any:
		for key, child := range typed {
			if containsControl(key) || containsControlInValue(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsControlInValue(child) {
				return true
			}
		}
	}
	return false
}
