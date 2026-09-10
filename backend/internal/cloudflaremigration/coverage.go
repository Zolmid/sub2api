package cloudflaremigration

// Classification describes what happens to a traditional PostgreSQL table.
// Rebuilt tables are permitted only when empty: their Cloudflare runtime state
// is deterministically recreated from an empty state after cutover.
type Classification string

const (
	Transformed Classification = "transformed"
	Rebuilt     Classification = "rebuilt"
	Blocked     Classification = "blocked"
)

type CoverageSpec struct {
	SourceTable    string
	Classification Classification
	TargetTables   []string
	Rule           string
}

// CoverageMatrix is intentionally explicit. It is the union of tables found
// in the tracked Ent schemas and PostgreSQL migrations at the time this
// contract was written. Unknown tables are handled by the exporter and are
// allowed only when empty.
var CoverageMatrix = []CoverageSpec{
	{SourceTable: "account_groups", Classification: Transformed, TargetTables: []string{"account_groups"}, Rule: "edge identity is copied; source priority must be its default"},
	{SourceTable: "accounts", Classification: Transformed, TargetTables: []string{"accounts"}, Rule: "legacy API-key JSONB credentials are validated and re-encrypted into the D1 AES-GCM envelope; unsupported credential types and non-default dropped state block export"},
	{SourceTable: "announcement_reads", Classification: Blocked, Rule: "no canonical D1 mapping"},
	{SourceTable: "announcements", Classification: Blocked, Rule: "no canonical D1 mapping"},
	{SourceTable: "api_keys", Classification: Transformed, TargetTables: []string{"api_keys"}, Rule: "plaintext source key is SHA-256 transformed in memory and never emitted; unsupported quota state must be empty"},
	{SourceTable: "balance_ledger", Classification: Transformed, TargetTables: []string{"balance_ledger"}, Rule: "immutable E8 ledger rows are copied only after arithmetic, uniqueness, and user-reference validation"},
	{SourceTable: "balance_reservations", Classification: Blocked, Rule: "target schema 0001-0008 has no reservation settlement table; nonempty state blocks cutover"},
	{SourceTable: "balance_settlements", Classification: Blocked, Rule: "target schema 0001-0008 has no reservation settlement table; nonempty state blocks cutover"},
	{SourceTable: "audit_logs", Classification: Blocked, Rule: "no canonical D1 mapping"},
	{SourceTable: "atlas_schema_revisions", Classification: Transformed, Rule: "migration metadata is fingerprinted but is not imported as application state"},
	{SourceTable: "auth_cache_invalidation_outbox", Classification: Rebuilt, Rule: "must be empty; Cloudflare runtime starts with an empty invalidation outbox"},
	{SourceTable: "auth_identities", Classification: Blocked, Rule: "identity migration requires a separate authenticated mapping"},
	{SourceTable: "auth_identity_channels", Classification: Blocked, Rule: "identity migration requires a separate authenticated mapping"},
	{SourceTable: "auth_identity_migration_reports", Classification: Blocked, Rule: "historical report has no canonical D1 mapping"},
	{SourceTable: "batch_image_events", Classification: Blocked, Rule: "no canonical D1 mapping"},
	{SourceTable: "batch_image_items", Classification: Blocked, Rule: "no canonical D1 mapping"},
	{SourceTable: "batch_image_jobs", Classification: Blocked, Rule: "no canonical D1 mapping"},
	{SourceTable: "billing_usage_entries", Classification: Blocked, Rule: "billing history cannot be inferred as canonical usage events"},
	{SourceTable: "channel_account_stats_model_pricing", Classification: Blocked, Rule: "pricing conversion is not implemented"},
	{SourceTable: "channel_account_stats_pricing_intervals", Classification: Blocked, Rule: "pricing conversion is not implemented"},
	{SourceTable: "channel_account_stats_pricing_rules", Classification: Blocked, Rule: "pricing conversion is not implemented"},
	{SourceTable: "channel_groups", Classification: Blocked, Rule: "channel topology has no canonical D1 mapping"},
	{SourceTable: "channel_model_pricing", Classification: Blocked, Rule: "pricing conversion is not implemented"},
	{SourceTable: "channel_monitor_aggregation_watermark", Classification: Blocked, Rule: "monitor history has no canonical D1 mapping"},
	{SourceTable: "channel_monitor_daily_rollups", Classification: Blocked, Rule: "monitor history has no canonical D1 mapping"},
	{SourceTable: "channel_monitor_histories", Classification: Blocked, Rule: "monitor history has no canonical D1 mapping"},
	{SourceTable: "channel_monitor_request_templates", Classification: Blocked, Rule: "monitor templates have no canonical D1 mapping"},
	{SourceTable: "channel_monitor_v2_config", Classification: Blocked, Rule: "monitor state has no canonical D1 mapping"},
	{SourceTable: "channel_monitor_v2_error_metrics_1m", Classification: Blocked, Rule: "monitor metrics have no canonical D1 mapping"},
	{SourceTable: "channel_monitor_v2_error_metrics_rollup", Classification: Blocked, Rule: "monitor metrics have no canonical D1 mapping"},
	{SourceTable: "channel_monitor_v2_latency_histograms_1m", Classification: Blocked, Rule: "monitor metrics have no canonical D1 mapping"},
	{SourceTable: "channel_monitor_v2_latency_histograms_rollup", Classification: Blocked, Rule: "monitor metrics have no canonical D1 mapping"},
	{SourceTable: "channel_monitor_v2_metrics_1m", Classification: Blocked, Rule: "monitor metrics have no canonical D1 mapping"},
	{SourceTable: "channel_monitor_v2_metrics_rollup", Classification: Blocked, Rule: "monitor metrics have no canonical D1 mapping"},
	{SourceTable: "channel_monitor_v2_user_metrics_1m", Classification: Blocked, Rule: "monitor metrics have no canonical D1 mapping"},
	{SourceTable: "channel_monitor_v2_user_metrics_rollup", Classification: Blocked, Rule: "monitor metrics have no canonical D1 mapping"},
	{SourceTable: "channel_monitor_v2_watermarks", Classification: Blocked, Rule: "monitor state has no canonical D1 mapping"},
	{SourceTable: "channel_monitors", Classification: Blocked, Rule: "monitor state has no canonical D1 mapping"},
	{SourceTable: "channel_pricing_intervals", Classification: Blocked, Rule: "pricing conversion is not implemented"},
	{SourceTable: "channels", Classification: Blocked, Rule: "channel credentials and pricing have no canonical D1 mapping"},
	{SourceTable: "composite_model_routes", Classification: Blocked, Rule: "no canonical D1 mapping"},
	{SourceTable: "content_moderation_logs", Classification: Blocked, Rule: "no canonical D1 mapping"},
	{SourceTable: "deleted_api_key_audits", Classification: Blocked, Rule: "audit history has no canonical D1 mapping"},
	{SourceTable: "error_passthrough_rules", Classification: Blocked, Rule: "no canonical D1 mapping"},
	{SourceTable: "groups", Classification: Transformed, TargetTables: []string{"groups"}, Rule: "canonical group fields are copied and every unsupported policy field must equal its declared safe default"},
	{SourceTable: "model_aliases", Classification: Transformed, TargetTables: []string{"model_aliases"}, Rule: "copy explicit canonical model aliases in dependency order"},
	{SourceTable: "groups_video_price_backup_220", Classification: Blocked, Rule: "backup table must be handled explicitly outside this toolkit"},
	{SourceTable: "idempotency_records", Classification: Rebuilt, Rule: "must be empty; request idempotency state is rebuilt empty"},
	{SourceTable: "identity_adoption_decisions", Classification: Blocked, Rule: "identity migration requires a separate authenticated mapping"},
	{SourceTable: "ops_alert_events", Classification: Blocked, Rule: "operations history has no canonical D1 mapping"},
	{SourceTable: "ops_alert_rules", Classification: Blocked, Rule: "operations configuration has no canonical D1 mapping"},
	{SourceTable: "ops_alert_silences", Classification: Blocked, Rule: "operations state has no canonical D1 mapping"},
	{SourceTable: "ops_error_logs", Classification: Blocked, Rule: "operations history has no canonical D1 mapping"},
	{SourceTable: "ops_ingress_reject_aggregates", Classification: Blocked, Rule: "operations history has no canonical D1 mapping"},
	{SourceTable: "ops_job_heartbeats", Classification: Blocked, Rule: "operations state has no canonical D1 mapping"},
	{SourceTable: "ops_metrics_daily", Classification: Blocked, Rule: "operations history has no canonical D1 mapping"},
	{SourceTable: "ops_metrics_hourly", Classification: Blocked, Rule: "operations history has no canonical D1 mapping"},
	{SourceTable: "ops_retry_attempts", Classification: Blocked, Rule: "operations history has no canonical D1 mapping"},
	{SourceTable: "ops_system_log_cleanup_audits", Classification: Blocked, Rule: "operations history has no canonical D1 mapping"},
	{SourceTable: "ops_system_logs", Classification: Blocked, Rule: "operations history has no canonical D1 mapping"},
	{SourceTable: "ops_system_metrics", Classification: Blocked, Rule: "operations history has no canonical D1 mapping"},
	{SourceTable: "orphan_allowed_groups_audit", Classification: Blocked, Rule: "migration audit must be resolved before export"},
	{SourceTable: "passkey_credentials", Classification: Blocked, Rule: "authentication credentials require a separate migration"},
	{SourceTable: "passkey_user_handles", Classification: Blocked, Rule: "authentication credentials require a separate migration"},
	{SourceTable: "payment_audit_logs", Classification: Blocked, Rule: "payment history has no canonical D1 mapping"},
	{SourceTable: "payment_orders", Classification: Blocked, Rule: "payment state has no canonical D1 mapping"},
	{SourceTable: "payment_provider_instances", Classification: Blocked, Rule: "payment credentials have no canonical D1 mapping"},
	{SourceTable: "pending_auth_sessions", Classification: Blocked, Rule: "live authentication state must expire or be handled separately"},
	{SourceTable: "promo_code_usages", Classification: Blocked, Rule: "promotion history has no canonical D1 mapping"},
	{SourceTable: "promo_codes", Classification: Blocked, Rule: "promotion state has no canonical D1 mapping"},
	{SourceTable: "prompt_audit_events", Classification: Blocked, Rule: "prompt audit history has no canonical D1 mapping"},
	{SourceTable: "prompt_audit_jobs", Classification: Blocked, Rule: "prompt audit state has no canonical D1 mapping"},
	{SourceTable: "proxies", Classification: Blocked, Rule: "proxy credentials and topology have no canonical D1 mapping"},
	{SourceTable: "pricing_active_version", Classification: Transformed, TargetTables: []string{"pricing_active_version"}, Rule: "copy the singleton pointer only after its immutable pricing version and rules"},
	{SourceTable: "pricing_rules", Classification: Transformed, TargetTables: []string{"pricing_rules"}, Rule: "copy exact canonical E8 pricing rules with version references and no numeric coercion"},
	{SourceTable: "pricing_versions", Classification: Transformed, TargetTables: []string{"pricing_versions"}, Rule: "copy immutable pricing version digest and reservation ceiling"},
	{SourceTable: "redeem_codes", Classification: Blocked, Rule: "redemption state has no canonical D1 mapping"},
	{SourceTable: "scheduled_test_plans", Classification: Blocked, Rule: "scheduler test configuration has no canonical D1 mapping"},
	{SourceTable: "scheduled_test_results", Classification: Blocked, Rule: "scheduler test history has no canonical D1 mapping"},
	{SourceTable: "scheduler_outbox", Classification: Rebuilt, Rule: "must be empty; scheduler outbox is rebuilt empty"},
	{SourceTable: "schema_migrations", Classification: Transformed, Rule: "migration filename/checksum metadata is fingerprinted but is not imported as application state"},
	{SourceTable: "security_secrets", Classification: Blocked, Rule: "secret store requires an explicit re-encryption migration"},
	{SourceTable: "settings", Classification: Blocked, Rule: "traditional settings are not equivalent to Cloudflare bindings"},
	{SourceTable: "sora_accounts", Classification: Blocked, Rule: "legacy table has no canonical D1 mapping"},
	{SourceTable: "sora_generations", Classification: Blocked, Rule: "legacy table has no canonical D1 mapping"},
	{SourceTable: "subscription_plans", Classification: Blocked, Rule: "subscription commerce has no canonical D1 mapping"},
	{SourceTable: "sub2api_plugin_bindings", Classification: Blocked, Rule: "plugin bindings have no canonical D1 mapping"},
	{SourceTable: "sub2api_plugin_installations", Classification: Blocked, Rule: "plugin installations have no canonical D1 mapping"},
	{SourceTable: "tls_fingerprint_profiles", Classification: Blocked, Rule: "network profile state has no canonical D1 mapping"},
	{SourceTable: "usage_billing_dedup", Classification: Blocked, Rule: "billing deduplication state cannot be discarded"},
	{SourceTable: "usage_billing_dedup_archive", Classification: Blocked, Rule: "billing deduplication history cannot be discarded"},
	{SourceTable: "usage_cleanup_tasks", Classification: Rebuilt, Rule: "must be empty; cleanup task state is rebuilt empty"},
	{SourceTable: "usage_dashboard_aggregation_watermark", Classification: Blocked, Rule: "usage aggregation state has no canonical D1 mapping"},
	{SourceTable: "usage_dashboard_daily", Classification: Blocked, Rule: "usage aggregation history has no canonical D1 mapping"},
	{SourceTable: "usage_dashboard_daily_users", Classification: Blocked, Rule: "usage aggregation history has no canonical D1 mapping"},
	{SourceTable: "usage_dashboard_hourly", Classification: Blocked, Rule: "usage aggregation history has no canonical D1 mapping"},
	{SourceTable: "usage_dashboard_hourly_users", Classification: Blocked, Rule: "usage aggregation history has no canonical D1 mapping"},
	{SourceTable: "usage_group_daily_rollups", Classification: Blocked, Rule: "usage aggregation history has no canonical D1 mapping"},
	{SourceTable: "usage_group_rollup_state", Classification: Blocked, Rule: "usage aggregation state has no canonical D1 mapping"},
	{SourceTable: "usage_logs", Classification: Blocked, Rule: "traditional usage rows are not canonical gateway usage events"},
	{SourceTable: "user_affiliate_ledger", Classification: Blocked, Rule: "affiliate financial history has no canonical D1 mapping"},
	{SourceTable: "user_affiliates", Classification: Blocked, Rule: "affiliate state has no canonical D1 mapping"},
	{SourceTable: "user_allowed_groups", Classification: Transformed, TargetTables: []string{"users"}, Rule: "relation rows are deterministically folded into users.allowed_group_ids_json in ascending numeric order"},
	{SourceTable: "user_attribute_definitions", Classification: Blocked, Rule: "custom identity attributes have no canonical D1 mapping"},
	{SourceTable: "user_attribute_values", Classification: Blocked, Rule: "custom identity attributes have no canonical D1 mapping"},
	{SourceTable: "user_avatars", Classification: Blocked, Rule: "avatar objects have no canonical D1 mapping"},
	{SourceTable: "user_group_rate_multipliers", Classification: Blocked, Rule: "pricing overrides have no canonical D1 mapping"},
	{SourceTable: "user_platform_quotas", Classification: Blocked, Rule: "quota state has no canonical D1 mapping"},
	{SourceTable: "user_provider_default_grants", Classification: Blocked, Rule: "identity grants have no canonical D1 mapping"},
	{SourceTable: "user_subscriptions", Classification: Blocked, Rule: "subscription state has no canonical D1 mapping"},
	{SourceTable: "users", Classification: Transformed, TargetTables: []string{"users"}, Rule: "canonical identity fields and exact E8 balance are copied; unsupported user state must equal declared safe defaults"},
}

func coverageSpec(table string) (CoverageSpec, bool) {
	for _, spec := range CoverageMatrix {
		if spec.SourceTable == table {
			return spec, true
		}
	}
	return CoverageSpec{}, false
}
