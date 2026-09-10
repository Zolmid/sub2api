package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

func emptyRestoreSourceSnapshot(t *testing.T) []byte {
	return emptyRestoreSourceSnapshotWith(t, cloudflaremigration.RestoreSourceFormatVersion, cloudflaremigration.RestoreMappingProfileVersion)
}

func emptyRestoreSourceSnapshot0018(t *testing.T) []byte {
	return emptyRestoreSourceSnapshotWith(t, cloudflaremigration.Restore0018SourceFormatVersion, cloudflaremigration.Restore0018MappingProfileVersion)
}

func emptyRestoreSourceSnapshotWith(t *testing.T, sourceFormatVersion, mappingProfileVersion string) []byte {
	t.Helper()
	emptyDigest, err := cloudflaremigration.DigestRows(nil)
	if err != nil {
		t.Fatal(err)
	}
	header := testSourceHeader{Type: "source", Format: sourceFormatVersion,
		MappingProfile: mappingProfileVersion, SnapshotID: "1:2:", SchemaName: "public",
		ServerVersion: "170000", MigrationCount: "0", MigrationSHA256: emptyDigest,
		CapturedAt: "2026-09-09T00:00:00Z", Complete: true}
	tables := make([]string, 0, len(cloudflaremigration.RestoreCoverageMatrix()))
	for _, spec := range cloudflaremigration.RestoreCoverageMatrix() {
		tables = append(tables, spec.SourceTable)
	}
	sort.Strings(tables)
	summaries := make([]testTableSummary, 0, len(tables))
	var output bytes.Buffer
	writeJSONLine := func(value any) {
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		_, _ = output.Write(encoded)
		_ = output.WriteByte('\n')
	}
	writeJSONLine(header)
	for _, table := range tables {
		writeJSONLine(map[string]any{"type": "table", "table": table, "present": true})
		summary := testTableSummary{Table: table, Present: true, RowCount: "0", SHA256: emptyDigest}
		summaries = append(summaries, summary)
		writeJSONLine(map[string]any{"type": "table_end", "table": table, "row_count": "0", "sha256": emptyDigest})
	}
	digestInput := testSnapshotDigest{Format: header.Format, MappingProfile: header.MappingProfile,
		SnapshotID: header.SnapshotID, SchemaName: header.SchemaName, ServerVersion: header.ServerVersion,
		MigrationCount: header.MigrationCount, MigrationSHA256: header.MigrationSHA256,
		CapturedAt: header.CapturedAt, Tables: summaries}
	digestBytes, _ := json.Marshal(digestInput)
	digest := sha256.Sum256(digestBytes)
	writeJSONLine(map[string]any{"type": "snapshot_end", "table_count": strconv.Itoa(len(tables)), "row_count": "0", "sha256": hex.EncodeToString(digest[:])})
	return output.Bytes()
}

func emptyRestoreBundle(t *testing.T) []byte {
	t.Helper()
	bundle, err := cloudflaremigration.ExportRestoreJSONL(bytes.NewReader(emptyRestoreSourceSnapshot(t)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
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

func TestRestore0017CommandsAreDeterministicAndPublishAllOrNothing(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source-0017.jsonl")
	firstBundle := filepath.Join(directory, "first-0017.json")
	secondBundle := filepath.Join(directory, "second-0017.json")
	if err := os.WriteFile(source, emptyRestoreSourceSnapshot(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	for _, output := range []string{firstBundle, secondBundle} {
		if code := run([]string{"export-0017", "-source-jsonl", source, "-out", output}, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("export-0017 failed: code=%d stderr=%s", code, stderr.String())
		}
	}
	first, _ := os.ReadFile(firstBundle)
	second, _ := os.ReadFile(secondBundle)
	if !bytes.Equal(first, second) {
		t.Fatal("identical 0017 snapshots produced different bundles")
	}
	canonical := filepath.Join(directory, "canonical-0017.json")
	plan := filepath.Join(directory, "restore-0017.sql")
	validation := filepath.Join(directory, "validate-0017.sql")
	stderr.Reset()
	code := run([]string{"plan-0017", "-source-jsonl", source, "-bundle", firstBundle, "-canonical-bundle", canonical, "-sql-plan", plan, "-validation-sql", validation}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("plan-0017 failed: code=%d stderr=%s", code, stderr.String())
	}
	for _, path := range []string{canonical, plan, validation} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("restore output %s missing: %v", path, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("restore output %s mode=%v", path, info.Mode())
		}
	}
	originalPlan, _ := os.ReadFile(plan)
	stderr.Reset()
	if code := run([]string{"plan-0017", "-source-jsonl", source, "-bundle", firstBundle, "-canonical-bundle", canonical, "-sql-plan", plan, "-validation-sql", validation}, strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Fatalf("existing accepted outputs were overwritten: code=%d stderr=%s", code, stderr.String())
	}
	afterPlan, _ := os.ReadFile(plan)
	if !bytes.Equal(originalPlan, afterPlan) {
		t.Fatal("failed repeated publication changed an accepted plan")
	}

	failureDirectory := filepath.Join(directory, "publish-failure")
	if err := os.Mkdir(failureDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	partialCanonical := filepath.Join(failureDirectory, "canonical.json")
	partialPlan := filepath.Join(failureDirectory, "plan.sql")
	missingValidation := filepath.Join(failureDirectory, "missing", "validation.sql")
	stderr.Reset()
	code = run([]string{"plan-0017", "-source-jsonl", source, "-bundle", firstBundle, "-canonical-bundle", partialCanonical, "-sql-plan", partialPlan, "-validation-sql", missingValidation}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("conditional output failure returned code=%d stderr=%s", code, stderr.String())
	}
	for _, path := range []string{partialCanonical, partialPlan, missingValidation} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed publication left partial accepted output %s: %v", path, err)
		}
	}
}

func TestPrivateOutputPublicationRollbackRemovesPartialAcceptedFiles(t *testing.T) {
	directory := t.TempDir()
	outputs := []privateOutput{
		{path: filepath.Join(directory, "one"), data: []byte("one")},
		{path: filepath.Join(directory, "two"), data: []byte("two")},
		{path: filepath.Join(directory, "three"), data: []byte("three")},
	}
	originalPublish := linkPrivateOutput
	t.Cleanup(func() { linkPrivateOutput = originalPublish })
	publications := 0
	linkPrivateOutput = func(oldPath, newPath string) error {
		publications++
		if publications == 2 {
			return errors.New("injected publication failure")
		}
		return originalPublish(oldPath, newPath)
	}
	if err := writePrivateFilesAtomically(outputs); err == nil {
		t.Fatal("injected publication failure was accepted")
	}
	for _, output := range outputs {
		if _, err := os.Stat(output.path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("publication rollback left partial accepted output %s: %v", output.path, err)
		}
	}
}

func TestPrivateOutputPublicationDoesNotOverwriteRacingDestination(t *testing.T) {
	directory := t.TempDir()
	outputs := []privateOutput{
		{path: filepath.Join(directory, "one"), data: []byte("one")},
		{path: filepath.Join(directory, "two"), data: []byte("two")},
		{path: filepath.Join(directory, "three"), data: []byte("three")},
	}
	originalPublish := linkPrivateOutput
	t.Cleanup(func() { linkPrivateOutput = originalPublish })
	publications := 0
	linkPrivateOutput = func(oldPath, newPath string) error {
		publications++
		if publications == 1 {
			if err := os.WriteFile(outputs[1].path, []byte("competitor"), 0o600); err != nil {
				return err
			}
		}
		return originalPublish(oldPath, newPath)
	}
	if err := writePrivateFilesAtomically(outputs); err == nil {
		t.Fatal("racing destination was overwritten")
	}
	if _, err := os.Stat(outputs[0].path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publication rollback left first accepted output: %v", err)
	}
	contents, err := os.ReadFile(outputs[1].path)
	if err != nil {
		t.Fatalf("racing destination missing: %v", err)
	}
	if string(contents) != "competitor" {
		t.Fatalf("racing destination was overwritten: %q", contents)
	}
	if _, err := os.Stat(outputs[2].path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publication created trailing output: %v", err)
	}
}

func TestSnapshot0017RefusesExistingOutputBeforeOpeningPostgreSQL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.jsonl")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"snapshot-postgres-0017", "-out", path}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("existing snapshot output reached PostgreSQL setup: code=%d stderr=%s", code, stderr.String())
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "keep" {
		t.Fatalf("existing snapshot output changed: contents=%q err=%v", contents, err)
	}
}

func TestRestore0017CommandsRejectCorruptionAndVersionMismatch(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.jsonl")
	corrupt := filepath.Join(directory, "corrupt.json")
	mismatch := filepath.Join(directory, "mismatch.json")
	if err := os.WriteFile(source, emptyRestoreSourceSnapshot(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corrupt, []byte(`{"manifest":`), 0o600); err != nil {
		t.Fatal(err)
	}
	var bundle cloudflaremigration.RestoreBundle
	if err := json.Unmarshal(emptyRestoreBundle(t), &bundle); err != nil {
		t.Fatal(err)
	}
	bundle.Manifest.TargetSchema = "cloudflare-d1/0001-0016"
	encoded, _ := json.Marshal(bundle)
	if err := os.WriteFile(mismatch, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	for name, input := range map[string]string{"corrupt": corrupt, "version mismatch": mismatch} {
		t.Run(name, func(t *testing.T) {
			canonical := filepath.Join(directory, strings.ReplaceAll(name, " ", "-")+"-canonical.json")
			plan := filepath.Join(directory, strings.ReplaceAll(name, " ", "-")+"-plan.sql")
			validation := filepath.Join(directory, strings.ReplaceAll(name, " ", "-")+"-validation.sql")
			stderr.Reset()
			code := run([]string{"plan-0017", "-source-jsonl", source, "-bundle", input, "-canonical-bundle", canonical, "-sql-plan", plan, "-validation-sql", validation}, strings.NewReader(""), &stdout, &stderr)
			if code != 1 {
				t.Fatalf("bad restore bundle accepted: code=%d stderr=%s", code, stderr.String())
			}
			for _, path := range []string{canonical, plan, validation} {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rejected restore emitted %s", path)
				}
			}
		})
	}
}

func TestUpgrade0017CommandIsDeterministic(t *testing.T) {
	directory := t.TempDir()
	legacyPath := filepath.Join(directory, "legacy.json")
	first := filepath.Join(directory, "first.json")
	second := filepath.Join(directory, "second.json")
	if err := os.WriteFile(legacyPath, emptyBundle(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	for index, output := range []string{first, second} {
		plan := filepath.Join(directory, fmt.Sprintf("plan-%d.sql", index))
		validation := filepath.Join(directory, fmt.Sprintf("validation-%d.sql", index))
		if code := run([]string{"upgrade-0017", "-bundle", legacyPath, "-out", output, "-sql-plan", plan, "-validation-sql", validation}, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("upgrade-0017 failed: code=%d stderr=%s", code, stderr.String())
		}
	}
	firstBytes, _ := os.ReadFile(first)
	secondBytes, _ := os.ReadFile(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("upgrade-0017 output was not deterministic")
	}
}

func TestRestore0018CommandsAndUpgradeAreDeterministic(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source-0018.jsonl")
	firstBundle := filepath.Join(directory, "first-0018.json")
	secondBundle := filepath.Join(directory, "second-0018.json")
	if err := os.WriteFile(source, emptyRestoreSourceSnapshot0018(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	for _, output := range []string{firstBundle, secondBundle} {
		if code := run([]string{"export-0018", "-source-jsonl", source, "-out", output}, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("export-0018 failed: code=%d stderr=%s", code, stderr.String())
		}
	}
	first, _ := os.ReadFile(firstBundle)
	second, _ := os.ReadFile(secondBundle)
	if !bytes.Equal(first, second) {
		t.Fatal("identical 0018 snapshots produced different bundles")
	}
	var decoded cloudflaremigration.RestoreBundle
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Manifest.TargetSchema != cloudflaremigration.Restore0018TargetSchemaVersion || decoded.Manifest.MappingProfile != cloudflaremigration.Restore0018MappingProfileVersion {
		t.Fatal("export-0018 did not publish the 0018 canonical profile")
	}
	if len(decoded.Manifest.TargetMigrations) != 18 || decoded.Manifest.TargetMigrations[17].Filename != "0018_auth_sessions.sql" || decoded.Manifest.TargetMigrations[17].SHA256 != "f39e75c2351cb3535e951034d4e85af167b68d33d3f5eabde49c6e78f39168e4" {
		t.Fatal("export-0018 omitted the pinned 0018 migration fingerprint")
	}
	for _, table := range []string{"auth_sessions", "auth_session_family_revocations", "auth_session_audit_events", "auth_session_rotation_witnesses"} {
		found := false
		for _, item := range decoded.Manifest.OperationalInitialization {
			if item.Entity == table && item.Mode == "empty-before-import" {
				found = true
			}
		}
		if !found {
			t.Fatalf("export-0018 omitted pristine auth-session state %s", table)
		}
	}

	canonical := filepath.Join(directory, "canonical-0018.json")
	plan := filepath.Join(directory, "restore-0018.sql")
	validation := filepath.Join(directory, "validate-0018.sql")
	if code := run([]string{"plan-0018", "-source-jsonl", source, "-bundle", firstBundle, "-canonical-bundle", canonical, "-sql-plan", plan, "-validation-sql", validation}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("plan-0018 failed: code=%d stderr=%s", code, stderr.String())
	}
	planBytes, _ := os.ReadFile(plan)
	if !strings.Contains(string(planBytes), "0018 auth session schema") || !strings.Contains(string(planBytes), "offline_migration/v5/bundle") {
		t.Fatal("plan-0018 omitted auth-session schema assertion or v5 provenance")
	}

	restore0017 := filepath.Join(directory, "source-0017.json")
	if err := os.WriteFile(restore0017, emptyRestoreBundle(t), 0o600); err != nil {
		t.Fatal(err)
	}
	upgradedA := filepath.Join(directory, "upgraded-a.json")
	upgradedB := filepath.Join(directory, "upgraded-b.json")
	for index, output := range []string{upgradedA, upgradedB} {
		planPath := filepath.Join(directory, fmt.Sprintf("upgrade-0018-plan-%d.sql", index))
		validationPath := filepath.Join(directory, fmt.Sprintf("upgrade-0018-validation-%d.sql", index))
		if code := run([]string{"upgrade-0018", "-bundle", restore0017, "-out", output, "-sql-plan", planPath, "-validation-sql", validationPath}, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("upgrade-0018 failed: code=%d stderr=%s", code, stderr.String())
		}
	}
	upgradedABytes, _ := os.ReadFile(upgradedA)
	upgradedBBytes, _ := os.ReadFile(upgradedB)
	if !bytes.Equal(upgradedABytes, upgradedBBytes) {
		t.Fatal("upgrade-0018 output was not deterministic")
	}
}

func TestRestore0018CommandsRejectVersionMismatchAndRollbackPublication(t *testing.T) {
	directory := t.TempDir()
	source0018 := filepath.Join(directory, "source-0018.jsonl")
	bundle0017 := filepath.Join(directory, "bundle-0017.json")
	if err := os.WriteFile(source0018, emptyRestoreSourceSnapshot0018(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle0017, emptyRestoreBundle(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	canonical := filepath.Join(directory, "bad-canonical.json")
	plan := filepath.Join(directory, "bad-plan.sql")
	validation := filepath.Join(directory, "bad-validation.sql")
	if code := run([]string{"plan-0018", "-source-jsonl", source0018, "-bundle", bundle0017, "-canonical-bundle", canonical, "-sql-plan", plan, "-validation-sql", validation}, strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Fatalf("plan-0018 accepted a 0017 bundle: code=%d stderr=%s", code, stderr.String())
	}
	for _, path := range []string{canonical, plan, validation} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected plan-0018 emitted %s", path)
		}
	}

	originalPublish := linkPrivateOutput
	t.Cleanup(func() { linkPrivateOutput = originalPublish })
	publications := 0
	linkPrivateOutput = func(oldPath, newPath string) error {
		publications++
		if publications == 2 {
			return errors.New("injected 0018 publication failure")
		}
		return originalPublish(oldPath, newPath)
	}
	outputs := []string{
		filepath.Join(directory, "rollback-bundle.json"),
		filepath.Join(directory, "rollback-plan.sql"),
		filepath.Join(directory, "rollback-validation.sql"),
	}
	if code := run([]string{"upgrade-0018", "-bundle", bundle0017, "-out", outputs[0], "-sql-plan", outputs[1], "-validation-sql", outputs[2]}, strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Fatalf("upgrade-0018 publication failure returned code=%d stderr=%s", code, stderr.String())
	}
	for _, path := range outputs {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed upgrade-0018 publication left partial output %s: %v", path, err)
		}
	}
}
