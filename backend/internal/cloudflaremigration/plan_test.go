package cloudflaremigration

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestPlanUsesCanonicalDependencyOrderAndNoSilentConflict(t *testing.T) {
	plan, err := BuildSQLPlan(validManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan.SQL, "ON CONFLICT") || strings.Contains(plan.SQL, "BEGIN") || strings.Contains(plan.SQL, "COMMIT") {
		t.Fatal("D1 upload plan contains forbidden conflict or transaction syntax")
	}
	if !strings.Contains(plan.SQL, "Remote whole-file atomicity is not assumed") {
		t.Fatal("remote SQL plan does not carry the verify-first warning")
	}
	groupAt := strings.Index(plan.SQL, "-- table groups")
	userAt := strings.Index(plan.SQL, "-- table users")
	accountAt := strings.Index(plan.SQL, "-- table accounts")
	keyAt := strings.Index(plan.SQL, "-- table api_keys")
	if groupAt >= userAt || userAt >= accountAt || accountAt >= keyAt {
		t.Fatalf("dependency order is wrong: %d %d %d %d", groupAt, userAt, accountAt, keyAt)
	}
	if !strings.Contains(plan.SQL, "O''Reilly") {
		quoted := validManifest(t)
		quoted.Tables[1].Rows[0] = testUserRow("O'Reilly")
		quoted.Tables[1].SHA256, _ = DigestRows(quoted.Tables[1].Rows)
		plan, err = BuildSQLPlan(quoted)
		if err != nil || !strings.Contains(plan.SQL, "O''Reilly") {
			t.Fatal("SQLite literal quoting is not correct")
		}
	}
}

func TestPlanRehearsesAgainstTrackedCanonicalMigrations(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Errorf("close rehearsal database: %v", closeErr)
		}
	})
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	migrations := []string{
		"deploy/cloudflare/migrations/0001_initial.sql",
		"deploy/cloudflare/migrations/0002_management_control_plane.sql",
		"deploy/cloudflare/migrations/0003_group_live_name_unique.sql",
		"deploy/cloudflare/migrations/0004_user_live_email_identity.sql",
		"deploy/cloudflare/migrations/0005_balance_ledger.sql",
		"deploy/cloudflare/migrations/0006_totp_security.sql",
		"deploy/cloudflare/migrations/0007_admin_role_management.sql",
		"deploy/cloudflare/migrations/0008_e8_money_and_pricing.sql",
	}
	for _, relative := range migrations {
		contents, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatalf("read tracked migration %s: %v", relative, err)
		}
		if _, err := database.Exec(string(contents)); err != nil {
			t.Fatalf("apply tracked migration %s: %v", relative, err)
		}
	}
	plan, err := BuildSQLPlan(validManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := ExecuteSQLitePlan(context.Background(), database, plan.SQL); err != nil {
		t.Fatalf("first rehearsal failed: %v", err)
	}
	var firstDigest string
	if err := database.QueryRow(`SELECT value FROM schema_metadata WHERE key='offline_migration/v3/bundle'`).Scan(&firstDigest); err != nil {
		t.Fatalf("first rehearsal omitted provenance: %v", err)
	}
	if err := ExecuteSQLitePlan(context.Background(), database, plan.SQL); err != nil {
		t.Fatalf("identical replay failed: %v", err)
	}
	if _, err := database.Exec(`UPDATE users SET notes='divergent' WHERE id='9007199254740993'`); err != nil {
		t.Fatal(err)
	}
	if err := ExecuteSQLitePlan(context.Background(), database, plan.SQL); err == nil {
		t.Fatal("divergent preexisting row did not abort")
	}
	var notes string
	if err := database.QueryRow(`SELECT notes FROM users WHERE id='9007199254740993'`).Scan(&notes); err != nil || notes != "divergent" {
		t.Fatalf("failed replay was not rolled back: notes=%q err=%v", notes, err)
	}
	var digest string
	if err := database.QueryRow(`SELECT value FROM schema_metadata WHERE key='offline_migration/v3/bundle'`).Scan(&digest); err != nil || digest != plan.BundleDigest {
		t.Fatalf("bundle provenance mismatch: %q %v", digest, err)
	}
}
