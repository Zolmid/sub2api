package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/cloudflaremigration"
)

type testSourceHeader struct {
	Type            string `json:"type"`
	Format          string `json:"format"`
	MappingProfile  string `json:"mapping_profile"`
	SnapshotID      string `json:"snapshot_id"`
	SchemaName      string `json:"schema_name"`
	ServerVersion   string `json:"server_version"`
	MigrationCount  string `json:"migration_count"`
	MigrationSHA256 string `json:"migration_sha256"`
	CapturedAt      string `json:"captured_at"`
	Complete        bool   `json:"complete_inventory"`
}

type testTableSummary struct {
	Table    string `json:"table"`
	Present  bool   `json:"present"`
	RowCount string `json:"row_count"`
	SHA256   string `json:"sha256"`
}

type testSnapshotDigest struct {
	Format          string             `json:"format"`
	MappingProfile  string             `json:"mapping_profile"`
	SnapshotID      string             `json:"snapshot_id"`
	SchemaName      string             `json:"schema_name"`
	ServerVersion   string             `json:"server_version"`
	MigrationCount  string             `json:"migration_count"`
	MigrationSHA256 string             `json:"migration_sha256"`
	CapturedAt      string             `json:"captured_at"`
	Tables          []testTableSummary `json:"tables"`
}

func emptyBundle(t *testing.T) []byte {
	t.Helper()
	bundle, err := cloudflaremigration.ExportJSONL(bytes.NewReader(emptySourceSnapshot(t)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func emptySourceSnapshot(t *testing.T) []byte {
	return emptySourceSnapshotOmitting(t, "")
}

func emptySourceSnapshotOmitting(t *testing.T, omitted string) []byte {
	t.Helper()
	emptyDigest, err := cloudflaremigration.DigestRows(nil)
	if err != nil {
		t.Fatal(err)
	}
	header := testSourceHeader{Type: "source", Format: cloudflaremigration.SourceFormatVersion,
		MappingProfile: cloudflaremigration.MappingProfileVersion, SnapshotID: "1:2:", SchemaName: "public",
		ServerVersion: "170000", MigrationCount: "0", MigrationSHA256: emptyDigest,
		CapturedAt: "2026-09-09T00:00:00Z", Complete: true}
	tables := make([]string, 0, len(cloudflaremigration.CoverageMatrix))
	for _, spec := range cloudflaremigration.CoverageMatrix {
		if spec.SourceTable != omitted {
			tables = append(tables, spec.SourceTable)
		}
	}
	sort.Strings(tables)
	summaries := make([]testTableSummary, 0, len(tables))
	var output bytes.Buffer
	writeLine := func(value any) {
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, err := output.Write(encoded); err != nil {
			t.Fatal(err)
		}
		if err := output.WriteByte('\n'); err != nil {
			t.Fatal(err)
		}
	}
	writeLine(header)
	for _, table := range tables {
		writeLine(map[string]any{"type": "table", "table": table, "present": true})
		summary := testTableSummary{Table: table, Present: true, RowCount: "0", SHA256: emptyDigest}
		summaries = append(summaries, summary)
		writeLine(map[string]any{"type": "table_end", "table": table, "row_count": "0", "sha256": emptyDigest})
	}
	digestInput := testSnapshotDigest{Format: header.Format, MappingProfile: header.MappingProfile,
		SnapshotID: header.SnapshotID, SchemaName: header.SchemaName, ServerVersion: header.ServerVersion,
		MigrationCount: header.MigrationCount, MigrationSHA256: header.MigrationSHA256,
		CapturedAt: header.CapturedAt, Tables: summaries}
	digestBytes, _ := json.Marshal(digestInput)
	digest := sha256.Sum256(digestBytes)
	writeLine(map[string]any{"type": "snapshot_end", "table_count": strconv.Itoa(len(tables)), "row_count": "0", "sha256": hex.EncodeToString(digest[:])})
	return output.Bytes()
}

func TestExportCommandIsDeterministicAndRejectsMissingInventory(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.jsonl")
	first := filepath.Join(directory, "first.json")
	second := filepath.Join(directory, "second.json")
	if err := os.WriteFile(source, emptySourceSnapshot(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	for _, output := range []string{first, second} {
		if code := run([]string{"export", "-source-jsonl", source, "-out", output}, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("deterministic export failed: code=%d stderr=%s", code, stderr.String())
		}
	}
	firstBytes, _ := os.ReadFile(first)
	secondBytes, _ := os.ReadFile(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("same reviewed snapshot produced different bundles")
	}
	incomplete := filepath.Join(directory, "incomplete.jsonl")
	if err := os.WriteFile(incomplete, emptySourceSnapshotOmitting(t, "users"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := run([]string{"export", "-source-jsonl", incomplete, "-out", filepath.Join(directory, "rejected.json")}, strings.NewReader(""), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "missing table") {
		t.Fatalf("incomplete source was not rejected: code=%d stderr=%s", code, stderr.String())
	}
}

func TestPlanCommandWritesPrivateOutputs(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.jsonl")
	input := filepath.Join(directory, "input.json")
	canonical := filepath.Join(directory, "canonical.json")
	plan := filepath.Join(directory, "plan.sql")
	validation := filepath.Join(directory, "validation.sql")
	if err := os.WriteFile(source, emptySourceSnapshot(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, emptyBundle(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "-source-jsonl", source, "-bundle", input, "-canonical-bundle", canonical, "-sql-plan", plan, "-validation-sql", validation}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	for _, path := range []string{canonical, plan, validation} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%o", path, info.Mode().Perm())
		}
	}
	planBytes, err := os.ReadFile(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(planBytes), "ON CONFLICT") || strings.Contains(string(planBytes), "BEGIN") {
		t.Fatal("unsafe SQL emitted")
	}
}

func TestCLIExitAndOfflineSourceErrorRedaction(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("missing command code=%d", code)
	}
	secret := "very-secret-password"
	directory := t.TempDir()
	source := filepath.Join(directory, "source.jsonl")
	if err := os.WriteFile(source, []byte(`{"type":"source","format":"bad","snapshot_id":"`+secret+`"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	code := run([]string{"export", "-out", filepath.Join(directory, "bundle.json"), "-source-jsonl", source}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 || strings.Contains(stderr.String(), secret) {
		t.Fatalf("export code=%d leaked=%q", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"plan"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("missing plan flags code=%d", code)
	}
}

func TestRemoteArgvOnlyPlan(t *testing.T) {
	directory := t.TempDir()
	deployDirectory := filepath.Join(directory, "deploy", "cloudflare")
	if err := os.MkdirAll(deployDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(deployDirectory, "wrangler.jsonc")
	if err := os.WriteFile(filepath.Join(deployDirectory, "package.json"), []byte("{\"devDependencies\":{\"wrangler\":\"4.129.0\"}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	validLock := `lockfileVersion: '9.0'
importers:
  .:
    devDependencies:
      wrangler:
        specifier: 4.129.0
        version: 4.129.0(@cloudflare/workers-types@5.20260905.1)
`
	lockPath := filepath.Join(deployDirectory, "pnpm-lock.yaml")
	if err := os.WriteFile(lockPath, []byte(validLock), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(directory, "plan.sql")
	validationPath := filepath.Join(directory, "validation.sql")
	if err := os.WriteFile(planPath, []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(validationPath, []byte("PRAGMA quick_check;"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(directory, "before.sql")
	remote, err := cloudflaremigration.PlanRemoteImport(cloudflaremigration.RemoteAcknowledgement, "sub2api-prod", backupPath, planPath, validationPath, deployDirectory, configPath)
	if err != nil {
		t.Fatal(err)
	}
	expected := "pnpm exec wrangler --config " + configPath + " d1 execute sub2api-prod --remote --file " + planPath
	resolvedDeploy, _ := filepath.EvalSymlinks(deployDirectory)
	if strings.Join(remote.ImportArgs, " ") != expected || remote.WorkingDirectory != resolvedDeploy || remote.WranglerVersion != "4.129.0" {
		t.Fatalf("unexpected import argv: %#v", remote.ImportArgs)
	}
	if !strings.Contains(strings.Join(remote.RestoreArgsPrefix, " "), "time-travel restore sub2api-prod --bookmark") {
		t.Fatalf("restore checkpoint argv is missing: %#v", remote.RestoreArgsPrefix)
	}
	invalidLocks := map[string]string{
		"missing root importer": "lockfileVersion: '9.0'\nimporters: {}\n",
		"specifier mismatch": `importers:
  .:
    devDependencies:
      wrangler:
        specifier: 4.128.0
        version: 4.129.0
`,
		"resolved version mismatch": `importers:
  .:
    devDependencies:
      wrangler:
        specifier: 4.129.0
        version: 4.128.0(@cloudflare/workers-types@5.20260905.1)
`,
		"malformed peer suffix": `importers:
  .:
    devDependencies:
      wrangler:
        specifier: 4.129.0
        version: 4.129.0(@cloudflare/workers-types@5.20260905.1
`,
		"non-object dependency": `importers:
  .:
    devDependencies:
      wrangler: 4.129.0
`,
	}
	for name, lock := range invalidLocks {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(lockPath, []byte(lock), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := cloudflaremigration.PlanRemoteImport(cloudflaremigration.RemoteAcknowledgement, "sub2api-prod", backupPath, planPath, validationPath, deployDirectory, configPath); err == nil {
				t.Fatal("inconsistent Wrangler lock was accepted")
			}
		})
	}
	if err := os.WriteFile(lockPath, []byte(validLock), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, []byte("stale backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cloudflaremigration.PlanRemoteImport(cloudflaremigration.RemoteAcknowledgement, "sub2api-prod", backupPath, planPath, validationPath, deployDirectory, configPath); err == nil {
		t.Fatal("existing pre-import backup path was accepted")
	}
}

func TestCLIRejectsAliasedPathsBeforeWrite(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.jsonl")
	path := filepath.Join(directory, "same.json")
	if err := os.WriteFile(source, emptySourceSnapshot(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, emptyBundle(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "-source-jsonl", source, "-bundle", path, "-canonical-bundle", path, "-sql-plan", filepath.Join(directory, "plan.sql"), "-validation-sql", filepath.Join(directory, "validation.sql")}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "alias") {
		t.Fatalf("aliased paths were not rejected: code=%d stderr=%s", code, stderr.String())
	}
}
