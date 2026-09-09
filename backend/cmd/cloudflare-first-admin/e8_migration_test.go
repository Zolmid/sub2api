package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func applyCanonicalMigrations(t *testing.T, db *sql.DB, names []string) int {
	t.Helper()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS test_d1_migrations(name TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	pending := 0
	for _, name := range names {
		var applied int
		if err := db.QueryRow(`SELECT count(*) FROM test_d1_migrations WHERE name=?`, name).Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if applied != 0 {
			continue
		}
		pending++
		path := filepath.Join("..", "..", "..", "deploy", "cloudflare", "migrations", name)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
		if _, err := db.Exec(`INSERT INTO test_d1_migrations(name) VALUES(?)`, name); err != nil {
			t.Fatal(err)
		}
	}
	return pending
}

func TestE8MigrationBackfillsCanonicalMoneyAndHasNoRepeatPendingMigration(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	before := []string{
		"0001_initial.sql", "0002_management_control_plane.sql", "0003_group_live_name_unique.sql",
		"0004_user_live_email_identity.sql", "0005_balance_ledger.sql", "0006_totp_security.sql", "0007_admin_role_management.sql",
	}
	if got := applyCanonicalMigrations(t, db, before); got != len(before) {
		t.Fatalf("initial pending = %d, want %d", got, len(before))
	}
	if _, err := db.Exec(`INSERT INTO users(id,status,role,concurrency,balance_microusd,allowed_group_ids_json,restrict_public_groups,created_at,email,password_hash,username,notes,rpm_limit,updated_at)
VALUES('1001','active','user',1,'1250000','[]',0,'2026-09-09T00:00:00Z','e8@example.test','hash','e8','',0,'2026-09-09T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO balance_ledger(id,operation_id,actor_user_id,target_user_id,adjustment_type,reason,delta_microusd,balance_before_microusd,balance_after_microusd,created_at)
VALUES('ledger-1','operation-1','1001','1001','add','migration test','1250000','0','1250000','2026-09-09T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if got := applyCanonicalMigrations(t, db, []string{"0008_e8_money_and_pricing.sql"}); got != 1 {
		t.Fatalf("0008 pending = %d, want 1", got)
	}
	var balance, delta, beforeE8, after string
	if err := db.QueryRow(`SELECT balance_e8_usd FROM users WHERE id='1001'`).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT delta_e8_usd,balance_before_e8_usd,balance_after_e8_usd FROM balance_ledger WHERE id='ledger-1'`).Scan(&delta, &beforeE8, &after); err != nil {
		t.Fatal(err)
	}
	if balance != "125000000" || delta != "125000000" || beforeE8 != "0" || after != "125000000" {
		t.Fatalf("unexpected e8 backfill users=%s ledger=(%s,%s,%s)", balance, delta, beforeE8, after)
	}
	for key, want := range map[string]string{
		"cloudflare_e8_money_scale":         "8",
		"cloudflare_pricing_schema_version": "2026-09-08.v1",
	} {
		var got string
		if err := db.QueryRow(`SELECT value FROM schema_metadata WHERE key=?`, key).Scan(&got); err != nil || got != want {
			t.Fatalf("metadata %s = %q, %v; want %q", key, got, err, want)
		}
	}
	if _, err := db.Exec(`UPDATE balance_ledger SET delta_e8_usd='1' WHERE id='ledger-1'`); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("post-migration ledger update error = %v, want immutable", err)
	}
	if _, err := db.Exec(`INSERT INTO users(id,status,role,concurrency,balance_e8_usd,allowed_group_ids_json,restrict_public_groups,created_at,email,password_hash,username,notes,rpm_limit,updated_at)
VALUES('1002','active','user',1,'1','[]',0,'2026-09-09T00:00:00Z','e8-exact@example.test','hash','e8-exact','',0,'2026-09-09T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO balance_ledger(id,operation_id,actor_user_id,target_user_id,adjustment_type,reason,delta_e8_usd,balance_before_e8_usd,balance_after_e8_usd,created_at)
VALUES('ledger-2','operation-2','1001','1002','set','exact e8','1','0','1','2026-09-09T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if got := applyCanonicalMigrations(t, db, []string{"0008_e8_money_and_pricing.sql"}); got != 0 {
		t.Fatalf("repeat pending = %d, want 0", got)
	}
}

func insertPricingRule(t *testing.T, db *sql.DB, version, pattern, kind string) error {
	t.Helper()
	_, err := db.Exec(`INSERT INTO pricing_rules(
version_id,model_pattern,match_kind,input_e8_per_million,output_e8_per_million,
cache_read_e8_per_million,cache_write_e8_per_million,cache_write_5m_e8_per_million,
cache_write_1h_e8_per_million,image_input_e8_per_million,image_output_e8_per_million,
priority_input_e8_per_million,priority_output_e8_per_million,
priority_cache_read_e8_per_million,priority_cache_write_e8_per_million,
fast_multiplier_bps,flex_multiplier_bps,max_reasoning_effort_multiplier_bps)
VALUES(?,?,?,'0','0','0','0','0','0','0','0','0','0','0','0','0','0','10000')`,
		version, pattern, kind)
	return err
}

func TestPricingVersionsStayFrozenAfterTheyAreNoLongerActive(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	applyCanonicalMigrations(t, db, []string{
		"0001_initial.sql", "0002_management_control_plane.sql", "0003_group_live_name_unique.sql",
		"0004_user_live_email_identity.sql", "0005_balance_ledger.sql", "0006_totp_security.sql",
		"0007_admin_role_management.sql", "0008_e8_money_and_pricing.sql",
	})
	for _, version := range []string{"price-v1", "price-v2"} {
		if _, err := db.Exec(`INSERT INTO pricing_versions(version_id,digest,max_reservation_e8_usd,created_at) VALUES(?,?,'1','now')`, version, strings.Repeat("a", 64)); err != nil {
			t.Fatal(err)
		}
	}
	if err := insertPricingRule(t, db, "price-v1", "gpt-*", "family"); err != nil {
		t.Fatalf("canonical family rule: %v", err)
	}
	if err := insertPricingRule(t, db, "price-v2", "claude-fable-5.1*", "family"); err == nil || !strings.Contains(err.Error(), "invalid pricing rule pattern") {
		t.Fatalf("non-normalized Claude rule error = %v", err)
	}
	if err := insertPricingRule(t, db, "price-v2", "claude-fable-5-1*", "family"); err != nil {
		t.Fatalf("normalized Claude family rule: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO pricing_active_version(singleton,version_id,activated_at) VALUES(1,'price-v1','first')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE pricing_active_version SET version_id='price-v2',activated_at='second' WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if err := insertPricingRule(t, db, "price-v1", "gpt-5.6", "exact"); err == nil || !strings.Contains(err.Error(), "active pricing version is immutable") {
		t.Fatalf("formerly active version insert error = %v", err)
	}
	if _, err := db.Exec(`UPDATE pricing_rules SET input_e8_per_million='1' WHERE version_id='price-v1'`); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("pricing update error = %v", err)
	}
	if _, err := db.Exec(`DELETE FROM pricing_version_activations WHERE version_id='price-v1'`); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("activation deletion error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO gateway_requests(request_id,api_key_id,account_id,lease_id,lease_epoch,owner,model,upstream_model,state,created_at) VALUES('missing-price','1','1','lease','1','owner','gpt','gpt','admitted','now')`); err == nil || !strings.Contains(err.Error(), "requires admitted pricing") {
		t.Fatalf("unpriced gateway insert error = %v", err)
	}
}

func TestE8MigrationRejectsLegacyOverflowInsteadOfTruncating(t *testing.T) {
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	before := []string{
		"0001_initial.sql", "0002_management_control_plane.sql", "0003_group_live_name_unique.sql",
		"0004_user_live_email_identity.sql", "0005_balance_ledger.sql", "0006_totp_security.sql", "0007_admin_role_management.sql",
	}
	applyCanonicalMigrations(t, db, before)
	overflow := "1" + strings.Repeat("0", 38)
	if _, err := db.Exec(`INSERT INTO users(id,status,role,concurrency,balance_microusd,allowed_group_ids_json,restrict_public_groups,created_at,email,password_hash,username,notes,rpm_limit,updated_at)
VALUES('1001','active','user',1,?,'[]',0,'2026-09-09T00:00:00Z','overflow@example.test','hash','overflow','',0,'2026-09-09T00:00:00Z')`, overflow); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "..", "deploy", "cloudflare", "migrations", "0008_e8_money_and_pricing.sql")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(body)); err == nil || !strings.Contains(err.Error(), "overflowing legacy user balance") {
		t.Fatalf("overflow migration error = %v", err)
	}
}
