package cloudflaremigration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func validManifest(t *testing.T) Manifest {
	t.Helper()
	rows := map[string][]json.RawMessage{
		"groups": {testGroupRow("10", "default")},
		"users":  {testUserRow("")},
	}
	chunks := []TableChunk{}
	for _, table := range TableOrder {
		tableChunks, err := NewTableChunks(table, rows[table])
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, tableChunks...)
	}
	coverage := make([]CoverageRecord, 0, len(CoverageMatrix))
	for _, spec := range CoverageMatrix {
		coverage = append(coverage, CoverageRecord{SourceTable: spec.SourceTable,
			Classification: spec.Classification, TargetTables: append([]string(nil), spec.TargetTables...),
			Rule: spec.Rule, SourceRowCount: "0", SourceSHA256: emptyDigest()})
	}
	return Manifest{Format: FormatVersion, TargetSchema: TargetSchemaVersion, MappingProfile: MappingProfileVersion,
		Source: SourceFingerprint{Engine: "postgresql-offline-export", SnapshotID: "1:2:", SchemaName: "public",
			ServerVersion: "170000", MigrationCount: "1", MigrationSHA256: strings.Repeat("a", 64),
			SnapshotSHA256: strings.Repeat("b", 64), CapturedAt: "2026-09-09T00:00:00Z"},
		Coverage: coverage, DependencyOrder: append([]string(nil), TableOrder...), Warnings: []string{},
		Blockers: []string{}, Tables: chunks}
}

func testGroupRow(id, name string) json.RawMessage {
	encoded, _ := json.Marshal(map[string]any{
		"id": id, "name": name, "platform": "openai", "status": "active", "is_exclusive": false,
		"subscription_type": "standard", "created_at": "2026-09-09T00:00:00Z",
		"updated_at": "2026-09-09T00:00:00Z", "deleted_at": nil,
	})
	return encoded
}

func testUserRow(notes string) json.RawMessage {
	encoded, _ := json.Marshal(map[string]any{
		"id": "9007199254740993", "status": "active", "role": "admin", "concurrency": 1,
		"balance_e8_usd": "100000000", "allowed_group_ids_json": "[]", "restrict_public_groups": false,
		"created_at": "2026-09-09T00:00:00Z", "email": "admin@example.invalid", "password_hash": "$2a$10$already-hashed",
		"username": "admin", "notes": notes, "rpm_limit": 0, "updated_at": "2026-09-09T00:00:00Z",
		"deleted_at": nil, "totp_secret_envelope": nil, "totp_enabled": false, "totp_enabled_at": nil,
		"totp_revision": 0,
	})
	return encoded
}

func safeSourceUserRow(t *testing.T, notes string) json.RawMessage {
	t.Helper()
	var row map[string]any
	if err := json.Unmarshal(testUserRow(notes), &row); err != nil {
		t.Fatal(err)
	}
	delete(row, "allowed_group_ids_json")
	encoded, _ := json.Marshal(row)
	return encoded
}

func migrationFingerprintForTest(t *testing.T, rows []json.RawMessage) (string, string) {
	t.Helper()
	type projection struct {
		filename string
		encoded  json.RawMessage
	}
	projections := make([]projection, 0, len(rows))
	for _, raw := range rows {
		row, err := sourceObject(raw, legacySourceColumns["schema_migrations"])
		if err != nil {
			t.Fatal(err)
		}
		transformed, err := transformSchemaMigration(row)
		if err != nil {
			t.Fatal(err)
		}
		filename := transformed["filename"].(string)
		encoded, err := json.Marshal(map[string]string{
			"filename": filename,
			"checksum": transformed["checksum"].(string),
		})
		if err != nil {
			t.Fatal(err)
		}
		projections = append(projections, projection{filename: filename, encoded: encoded})
	}
	sort.Slice(projections, func(left, right int) bool {
		return projections[left].filename < projections[right].filename
	})
	encoded := make([]json.RawMessage, len(projections))
	for index := range projections {
		encoded[index] = projections[index].encoded
	}
	digest, err := DigestRows(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return strconv.Itoa(len(encoded)), digest
}

func snapshotJSONL(t *testing.T, rows map[string][]json.RawMessage, omitted map[string]bool) string {
	t.Helper()
	migrationCount, migrationDigest := migrationFingerprintForTest(t, rows["schema_migrations"])
	header := sourceHeader{Type: "source", Format: SourceFormatVersion, MappingProfile: MappingProfileVersion,
		SnapshotID: "1:2:", SchemaName: "public", ServerVersion: "170000", MigrationCount: migrationCount,
		MigrationSHA256: migrationDigest, CapturedAt: "2026-09-09T00:00:00Z", Complete: true}
	inventory := map[string]bool{}
	for _, spec := range CoverageMatrix {
		if !omitted[spec.SourceTable] {
			inventory[spec.SourceTable] = true
		}
	}
	for table := range rows {
		inventory[table] = true
	}
	tables := make([]string, 0, len(inventory))
	for table := range inventory {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	var output bytes.Buffer
	if err := writeJSONLine(&output, header); err != nil {
		t.Fatal(err)
	}
	summaries := make([]snapshotTableSummary, 0, len(tables))
	totalRows := 0
	for _, table := range tables {
		present := true
		if err := writeJSONLine(&output, sourceTableStart{Type: "table", Table: table, Present: &present}); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows[table] {
			if err := writeJSONLine(&output, sourceRow{Type: "row", Table: table, Row: row}); err != nil {
				t.Fatal(err)
			}
		}
		digest, err := DigestRows(rows[table])
		if err != nil {
			t.Fatal(err)
		}
		summary := snapshotTableSummary{Table: table, Present: true, RowCount: strconv.Itoa(len(rows[table])), SHA256: digest}
		summaries = append(summaries, summary)
		totalRows += len(rows[table])
		if err := writeJSONLine(&output, sourceTableEnd{Type: "table_end", Table: table, RowCount: summary.RowCount, SHA256: digest}); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := snapshotDigest(header, summaries)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSONLine(&output, sourceSnapshotEnd{Type: "snapshot_end", TableCount: strconv.Itoa(len(tables)), RowCount: strconv.Itoa(totalRows), SHA256: digest}); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func rewriteSourceHeaderForTest(t *testing.T, source string, mutate func(*sourceHeader)) string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(source, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatal("source snapshot has no body")
	}
	var header sourceHeader
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatal(err)
	}
	mutate(&header)
	summaries := []snapshotTableSummary{}
	for _, line := range lines[1:] {
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Type == "table_end" {
			var summary sourceTableEnd
			if err := json.Unmarshal([]byte(line), &summary); err != nil {
				t.Fatal(err)
			}
			summaries = append(summaries, snapshotTableSummary{
				Table: summary.Table, Present: true, RowCount: summary.RowCount, SHA256: summary.SHA256,
			})
		}
	}
	digest, err := snapshotDigest(header, summaries)
	if err != nil {
		t.Fatal(err)
	}
	var end sourceSnapshotEnd
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &end); err != nil {
		t.Fatal(err)
	}
	end.SHA256 = digest
	headerJSON, _ := json.Marshal(header)
	endJSON, _ := json.Marshal(end)
	lines[0], lines[len(lines)-1] = string(headerJSON), string(endJSON)
	return strings.Join(lines, "\n") + "\n"
}

func TestValidEmptyNotesAndTamperDetection(t *testing.T) {
	manifest := validManifest(t)
	if _, err := Canonicalize(manifest); err != nil {
		t.Fatalf("valid empty notes rejected: %v", err)
	}
	manifest.Tables[1].SHA256 = strings.Repeat("0", 64)
	if _, err := Canonicalize(manifest); err == nil {
		t.Fatal("tampered chunk hash accepted")
	}
}

func TestCanonicalManifestOrdersCoverageAndWarnings(t *testing.T) {
	manifest := validManifest(t)
	for left, right := 0, len(manifest.Coverage)-1; left < right; left, right = left+1, right-1 {
		manifest.Coverage[left], manifest.Coverage[right] = manifest.Coverage[right], manifest.Coverage[left]
	}
	manifest.Warnings = []string{"z warning", "a warning"}
	canonical, err := Canonicalize(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.Coverage[0].SourceTable > canonical.Coverage[len(canonical.Coverage)-1].SourceTable || !equalStrings(canonical.Warnings, []string{"a warning", "z warning"}) {
		t.Fatal("manifest coverage or warnings were not canonically ordered")
	}
	manifest.Warnings = []string{"same warning", "same warning"}
	if _, err := Canonicalize(manifest); err == nil {
		t.Fatal("duplicate manifest warnings were accepted")
	}
}

func TestStrictNumbersIDsDigestsTimestampsAndText(t *testing.T) {
	if _, err := CanonicalJSON([]byte("{\"a\":1,\"a\":2}")); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
	for _, value := range []string{"1.000000001", "1e2", "92233720369"} {
		if _, err := decimalToE8(value); err == nil {
			t.Fatalf("invalid amount %q accepted", value)
		}
	}
	for _, id := range []string{"0", "9223372036854775808"} {
		var object map[string]any
		_ = json.Unmarshal(testUserRow(""), &object)
		object["id"] = id
		encoded, _ := json.Marshal(object)
		if _, _, err := validateAndCanonicalizeRow("users", encoded); err == nil {
			t.Fatalf("out-of-range id %q accepted", id)
		}
	}
	if _, _, err := validateAndCanonicalizeRow("users", testUserRow("line\nbreak")); err == nil {
		t.Fatal("control character accepted")
	}
	var object map[string]any
	_ = json.Unmarshal(testUserRow(""), &object)
	object["created_at"] = "2026-09-09T08:00:00+08:00"
	encoded, _ := json.Marshal(object)
	if _, _, err := validateAndCanonicalizeRow("users", encoded); err == nil {
		t.Fatal("non-canonical timestamp accepted")
	}
	manifest := validManifest(t)
	manifest.Coverage[0].SourceSHA256 = strings.Repeat("G", 64)
	if _, err := Canonicalize(manifest); err == nil {
		t.Fatal("non-hex coverage digest accepted")
	}
}

func TestDuplicatePrimaryKeyAndMissingReference(t *testing.T) {
	manifest := validManifest(t)
	duplicate, err := NewTableChunk("users", []json.RawMessage{testUserRow(""), testUserRow("")})
	if err != nil {
		t.Fatal(err)
	}
	manifest.Tables[1] = duplicate
	if _, err := Canonicalize(manifest); err == nil {
		t.Fatal("duplicate primary key accepted")
	}
	manifest = validManifest(t)
	key, _ := json.Marshal(map[string]any{
		"id": "20", "user_id": "404", "group_id": "10", "name": "key", "status": "active",
		"key_hash": strings.Repeat("a", 64), "ip_whitelist_json": "[]", "ip_blacklist_json": "[]",
		"expires_at": nil, "last_used_at": nil, "created_at": "2026-09-09T00:00:00Z",
		"updated_at": "2026-09-09T00:00:00Z", "deleted_at": nil,
	})
	chunk, err := NewTableChunk("api_keys", []json.RawMessage{key})
	if err != nil {
		t.Fatal(err)
	}
	replaceChunk(manifest.Tables, chunk)
	if _, err := Canonicalize(manifest); err == nil {
		t.Fatal("missing foreign key accepted")
	}
}

func TestCompleteInventoryAndEmptyDatabase(t *testing.T) {
	rows := map[string][]json.RawMessage{
		"groups": {testGroupRow("10", "default")},
		"users":  {safeSourceUserRow(t, "")},
	}
	bundle, err := ExportJSONL(strings.NewReader(snapshotJSONL(t, rows, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Manifest.Coverage) != len(CoverageMatrix) {
		t.Fatal("complete inventory was not preserved")
	}
	empty, err := ExportJSONL(strings.NewReader(snapshotJSONL(t, nil, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range empty.Manifest.Tables {
		if chunk.RowCount != "0" {
			t.Fatalf("empty export produced rows in %s", chunk.Table)
		}
	}
	if _, err := ExportJSONL(strings.NewReader(snapshotJSONL(t, nil, map[string]bool{"users": true}))); err == nil || !strings.Contains(err.Error(), "missing table") {
		t.Fatal("partial inventory accepted")
	}
	var headerOnly bytes.Buffer
	header := sourceHeader{Type: "source", Format: SourceFormatVersion, MappingProfile: MappingProfileVersion,
		SnapshotID: "1:2:", SchemaName: "public", ServerVersion: "170000", MigrationCount: "0",
		MigrationSHA256: emptyDigest(), CapturedAt: "2026-09-09T00:00:00Z", Complete: true}
	_ = writeJSONLine(&headerOnly, header)
	if _, err := ExportJSONL(&headerOnly); err == nil {
		t.Fatal("header-only source accepted")
	}
}

func TestSourceMigrationFingerprintIsBoundToSchemaMigrationRows(t *testing.T) {
	checksum := strings.Repeat("a", 64)
	migration, err := json.Marshal(map[string]any{
		"filename":   "0001_test.sql",
		"checksum":   checksum,
		"applied_at": "2026-09-09T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	source := snapshotJSONL(t, map[string][]json.RawMessage{
		"schema_migrations": {migration},
	}, nil)
	if _, err := ExportJSONL(strings.NewReader(source)); err != nil {
		t.Fatalf("valid migration fingerprint rejected: %v", err)
	}
	wrongCount := rewriteSourceHeaderForTest(t, source, func(header *sourceHeader) {
		header.MigrationCount = "0"
	})
	if _, err := ExportJSONL(strings.NewReader(wrongCount)); err == nil || !strings.Contains(err.Error(), "migration count") {
		t.Fatalf("forged migration count accepted: %v", err)
	}
	wrongDigest := rewriteSourceHeaderForTest(t, source, func(header *sourceHeader) {
		header.MigrationSHA256 = strings.Repeat("b", 64)
	})
	if _, err := ExportJSONL(strings.NewReader(wrongDigest)); err == nil || !strings.Contains(err.Error(), "migration sha256") {
		t.Fatalf("forged migration digest accepted: %v", err)
	}
}

func TestBlockedUnknownAndTamperedSnapshot(t *testing.T) {
	blocked := map[string][]json.RawMessage{"balance_reservations": {json.RawMessage("{\"id\":\"1\"}")}}
	if _, err := ExportJSONL(strings.NewReader(snapshotJSONL(t, blocked, nil))); err == nil {
		t.Fatal("nonempty blocked state accepted")
	}
	unknown := snapshotJSONL(t, map[string][]json.RawMessage{"unknown_empty": nil}, nil)
	bundle, err := ExportJSONL(strings.NewReader(unknown))
	if err != nil || len(bundle.Manifest.Warnings) == 0 {
		t.Fatalf("unknown empty table handling failed: %v", err)
	}
	nonemptyUnknown := map[string][]json.RawMessage{"unknown_state": {json.RawMessage("{\"id\":\"1\"}")}}
	if _, err := ExportJSONL(strings.NewReader(snapshotJSONL(t, nonemptyUnknown, nil))); err == nil {
		t.Fatal("unknown nonempty table accepted")
	}
	source := snapshotJSONL(t, nil, nil)
	last := strings.LastIndex(source, "\"sha256\":\"")
	tampered := source[:last+10] + strings.Repeat("0", 64) + source[last+74:]
	if _, err := ExportJSONL(strings.NewReader(tampered)); err == nil {
		t.Fatal("tampered snapshot hash accepted")
	}
}

func TestChunkingIsBoundedAndDeterministic(t *testing.T) {
	rows := make([]json.RawMessage, 0, MaxRowsPerChunk+1)
	for index := MaxRowsPerChunk + 1; index > 0; index-- {
		rows = append(rows, testGroupRow(strconv.Itoa(index), fmt.Sprintf("group-%06d", index)))
	}
	first, err := NewTableChunks("groups", rows)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTableChunks("groups", rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 2 || fmt.Sprint(first) != fmt.Sprint(second) {
		t.Fatal("bounded chunking is not deterministic")
	}
}

func TestPricingAndImmutableLedgerValidation(t *testing.T) {
	manifest := validManifest(t)
	version, _ := json.Marshal(map[string]any{"version_id": "v1", "digest": strings.Repeat("b", 64), "max_reservation_e8_usd": "100000000", "created_at": "2026-09-09T00:00:00Z"})
	rule := map[string]any{"version_id": "v1", "model_pattern": "gpt-*", "match_kind": "family"}
	for _, field := range []string{"input_e8_per_million", "output_e8_per_million", "cache_read_e8_per_million", "cache_write_e8_per_million", "cache_write_5m_e8_per_million", "cache_write_1h_e8_per_million", "image_input_e8_per_million", "image_output_e8_per_million", "priority_input_e8_per_million", "priority_output_e8_per_million", "priority_cache_read_e8_per_million", "priority_cache_write_e8_per_million"} {
		rule[field] = "0"
	}
	rule["input_e8_per_million"], rule["output_e8_per_million"] = "1", "2"
	rule["fast_multiplier_bps"], rule["flex_multiplier_bps"], rule["max_reasoning_effort_multiplier_bps"] = "10000", "10000", "10000"
	ruleRow, _ := json.Marshal(rule)
	active, _ := json.Marshal(map[string]any{"singleton": 1, "version_id": "v1", "activated_at": "2026-09-09T00:00:00Z"})
	ledger, _ := json.Marshal(map[string]any{"id": "ledger-1", "operation_id": "op-1", "actor_user_id": "9007199254740993", "target_user_id": "9007199254740993", "adjustment_type": "subtract", "reason": "", "delta_e8_usd": "-1", "balance_before_e8_usd": "100", "balance_after_e8_usd": "99", "created_at": "2026-09-09T00:00:00Z"})
	for table, tableRows := range map[string][]json.RawMessage{
		"pricing_versions": {version}, "pricing_rules": {ruleRow}, "pricing_active_version": {active}, "balance_ledger": {ledger},
	} {
		chunk, err := NewTableChunk(table, tableRows)
		if err != nil {
			t.Fatal(err)
		}
		replaceChunk(manifest.Tables, chunk)
	}
	if _, err := Canonicalize(manifest); err != nil {
		t.Fatalf("valid pricing and ledger rejected: %v", err)
	}
	zeroVersion, _ := json.Marshal(map[string]any{"version_id": "v1", "digest": strings.Repeat("b", 64), "max_reservation_e8_usd": "0", "created_at": "2026-09-09T00:00:00Z"})
	zeroChunk, err := NewTableChunk("pricing_versions", []json.RawMessage{zeroVersion})
	if err != nil {
		t.Fatal(err)
	}
	replaceChunk(manifest.Tables, zeroChunk)
	if _, err := Canonicalize(manifest); err == nil {
		t.Fatal("non-positive pricing reservation ceiling accepted")
	}
	versionChunk, _ := NewTableChunk("pricing_versions", []json.RawMessage{version})
	replaceChunk(manifest.Tables, versionChunk)

	oversizedMultiplier := make(map[string]any, len(rule))
	for field, value := range rule {
		oversizedMultiplier[field] = value
	}
	oversizedMultiplier["fast_multiplier_bps"] = "100000000"
	oversizedRow, _ := json.Marshal(oversizedMultiplier)
	oversizedChunk, err := NewTableChunk("pricing_rules", []json.RawMessage{oversizedRow})
	if err != nil {
		t.Fatal(err)
	}
	replaceChunk(manifest.Tables, oversizedChunk)
	if _, err := Canonicalize(manifest); err == nil {
		t.Fatal("nine-digit pricing multiplier accepted")
	}
	replaceChunk(manifest.Tables, mustChunk(t, "pricing_rules", []json.RawMessage{ruleRow}))

	overlap := make(map[string]any, len(rule))
	for field, value := range rule {
		overlap[field] = value
	}
	overlap["model_pattern"] = "gpt-4*"
	overlapRow, _ := json.Marshal(overlap)
	replaceChunk(manifest.Tables, mustChunk(t, "pricing_rules", []json.RawMessage{ruleRow, overlapRow}))
	if _, err := Canonicalize(manifest); err == nil {
		t.Fatal("overlapping pricing wildcard families accepted")
	}
	replaceChunk(manifest.Tables, mustChunk(t, "pricing_rules", []json.RawMessage{ruleRow}))

	var bad map[string]any
	_ = json.Unmarshal(ledger, &bad)
	bad["balance_after_e8_usd"] = "98"
	badLedger, _ := json.Marshal(bad)
	chunk, err := NewTableChunk("balance_ledger", []json.RawMessage{badLedger})
	if err != nil {
		t.Fatal(err)
	}
	replaceChunk(manifest.Tables, chunk)
	if _, err := Canonicalize(manifest); err == nil {
		t.Fatal("inconsistent immutable ledger arithmetic accepted")
	}
}

func mustChunk(t *testing.T, table string, rows []json.RawMessage) TableChunk {
	t.Helper()
	chunk, err := NewTableChunk(table, rows)
	if err != nil {
		t.Fatal(err)
	}
	return chunk
}

func replaceChunk(chunks []TableChunk, replacement TableChunk) {
	for index := range chunks {
		if chunks[index].Table == replacement.Table {
			chunks[index] = replacement
			return
		}
	}
}
