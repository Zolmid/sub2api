package cloudflaremigration

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

type sourceHeader struct {
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

type sourceTableStart struct {
	Type    string `json:"type"`
	Table   string `json:"table"`
	Present *bool  `json:"present"`
}

type sourceRow struct {
	Type  string          `json:"type"`
	Table string          `json:"table"`
	Row   json.RawMessage `json:"row"`
}

type sourceTableEnd struct {
	Type     string `json:"type"`
	Table    string `json:"table"`
	RowCount string `json:"row_count"`
	SHA256   string `json:"sha256"`
}

type sourceSnapshotEnd struct {
	Type       string `json:"type"`
	TableCount string `json:"table_count"`
	RowCount   string `json:"row_count"`
	SHA256     string `json:"sha256"`
}

type snapshotTableSummary struct {
	Table    string `json:"table"`
	Present  bool   `json:"present"`
	RowCount string `json:"row_count"`
	SHA256   string `json:"sha256"`
}

type snapshotDigestInput struct {
	Format          string                 `json:"format"`
	MappingProfile  string                 `json:"mapping_profile"`
	SnapshotID      string                 `json:"snapshot_id"`
	SchemaName      string                 `json:"schema_name"`
	ServerVersion   string                 `json:"server_version"`
	MigrationCount  string                 `json:"migration_count"`
	MigrationSHA256 string                 `json:"migration_sha256"`
	CapturedAt      string                 `json:"captured_at"`
	Tables          []snapshotTableSummary `json:"tables"`
}

// ExportJSONL consumes the repository-owned, secret-safe PostgreSQL snapshot
// stream. Every table has a start, zero or more one-row records, and an end.
// The final snapshot_end binds the complete inventory and detects truncation.
func ExportJSONL(reader io.Reader) (Bundle, error) {
	if reader == nil {
		return Bundle{}, errors.New("source JSONL reader is nil")
	}
	scanner := bufio.NewScanner(io.LimitReader(reader, MaxSnapshotBytes+1))
	scanner.Buffer(make([]byte, 64<<10), MaxRowBytes+(64<<10))
	lineNumber, totalBytes, totalRows := 0, 0, 0
	var header sourceHeader
	var active *sourceTableStart
	activeRows := []json.RawMessage(nil)
	tables := map[string][]json.RawMessage{}
	present := map[string]bool{}
	seen := map[string]bool{}
	summaries := []snapshotTableSummary{}
	lastTable, snapshotSHA := "", ""
	finished := false

	for scanner.Scan() {
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		totalBytes += len(scanner.Bytes()) + 1
		if totalBytes > MaxSnapshotBytes {
			return Bundle{}, fmt.Errorf("source JSONL exceeds %d-byte hard limit", MaxSnapshotBytes)
		}
		if len(line) == 0 {
			return Bundle{}, fmt.Errorf("source JSONL line %d is empty", lineNumber)
		}
		if finished {
			return Bundle{}, errors.New("source JSONL has records after snapshot_end")
		}
		if err := rejectDuplicateKeys(line); err != nil {
			return Bundle{}, fmt.Errorf("source JSONL line %d: %w", lineNumber, err)
		}
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			return Bundle{}, fmt.Errorf("source JSONL line %d is invalid JSON", lineNumber)
		}
		if lineNumber == 1 {
			if envelope.Type != "source" {
				return Bundle{}, errors.New("source JSONL must start with a source record")
			}
			if err := decodeStrict(line, &header); err != nil {
				return Bundle{}, fmt.Errorf("source record rejected: %w", err)
			}
			if err := validateSourceHeader(header); err != nil {
				return Bundle{}, err
			}
			continue
		}

		switch envelope.Type {
		case "table":
			if active != nil {
				return Bundle{}, fmt.Errorf("source table %q is missing table_end", active.Table)
			}
			var start sourceTableStart
			if err := decodeStrict(line, &start); err != nil || start.Present == nil {
				return Bundle{}, errors.New("source table record is incomplete")
			}
			if !sourceIdentifier(start.Table) {
				return Bundle{}, errors.New("source table name is unsafe")
			}
			if seen[start.Table] {
				return Bundle{}, fmt.Errorf("duplicate source table %q", start.Table)
			}
			if lastTable != "" && start.Table <= lastTable {
				return Bundle{}, errors.New("source tables are not in deterministic lexical order")
			}
			seen[start.Table] = true
			lastTable = start.Table
			active = &start
			activeRows = []json.RawMessage{}
		case "row":
			if active == nil {
				return Bundle{}, errors.New("source row occurs outside a table section")
			}
			var record sourceRow
			if err := decodeStrict(line, &record); err != nil || record.Table != active.Table || len(record.Row) == 0 {
				return Bundle{}, fmt.Errorf("source row for table %q is malformed", active.Table)
			}
			if !*active.Present {
				return Bundle{}, fmt.Errorf("absent source table %q contains a row", active.Table)
			}
			spec, known := coverageSpec(active.Table)
			if !known {
				return Bundle{}, fmt.Errorf("unknown source table %q is nonempty", active.Table)
			}
			if spec.Classification != Transformed {
				return Bundle{}, fmt.Errorf("%s source table %q is nonempty", spec.Classification, active.Table)
			}
			canonical, err := CanonicalJSON(record.Row)
			if err != nil {
				return Bundle{}, fmt.Errorf("source table %q row rejected: %w", active.Table, err)
			}
			activeRows = append(activeRows, canonical)
			totalRows++
			if len(activeRows) > MaxRowsPerTable || totalRows > MaxRows {
				return Bundle{}, fmt.Errorf("source table %q exceeds configured row capacity", active.Table)
			}
		case "table_end":
			if active == nil {
				return Bundle{}, errors.New("table_end occurs outside a table section")
			}
			var end sourceTableEnd
			if err := decodeStrict(line, &end); err != nil || end.Table != active.Table {
				return Bundle{}, fmt.Errorf("source table_end for %q is malformed", active.Table)
			}
			count, err := parseBoundedCount(end.RowCount, MaxRowsPerTable)
			if err != nil || count != len(activeRows) || validateLowerSHA256(end.SHA256) != nil {
				return Bundle{}, fmt.Errorf("source table %q count or sha256 is invalid", active.Table)
			}
			digest, err := DigestRows(activeRows)
			if err != nil || digest != end.SHA256 {
				return Bundle{}, fmt.Errorf("source table %q sha256 mismatch", active.Table)
			}
			tables[active.Table] = append([]json.RawMessage(nil), activeRows...)
			present[active.Table] = *active.Present
			summaries = append(summaries, snapshotTableSummary{Table: active.Table, Present: *active.Present, RowCount: end.RowCount, SHA256: end.SHA256})
			active, activeRows = nil, nil
		case "snapshot_end":
			if active != nil {
				return Bundle{}, fmt.Errorf("source table %q is missing table_end", active.Table)
			}
			var end sourceSnapshotEnd
			if err := decodeStrict(line, &end); err != nil {
				return Bundle{}, errors.New("snapshot_end is malformed")
			}
			tableCount, tableErr := parseBoundedCount(end.TableCount, len(CoverageMatrix)+10_000)
			rowCount, rowErr := parseBoundedCount(end.RowCount, MaxRows)
			if tableErr != nil || rowErr != nil || tableCount != len(summaries) || rowCount != totalRows || validateLowerSHA256(end.SHA256) != nil {
				return Bundle{}, errors.New("snapshot_end count or sha256 is invalid")
			}
			digest, err := snapshotDigest(header, summaries)
			if err != nil || digest != end.SHA256 {
				return Bundle{}, errors.New("snapshot_end sha256 mismatch")
			}
			for _, spec := range CoverageMatrix {
				if !seen[spec.SourceTable] {
					return Bundle{}, fmt.Errorf("source inventory is incomplete: missing table %q", spec.SourceTable)
				}
			}
			finished, snapshotSHA = true, end.SHA256
		default:
			return Bundle{}, fmt.Errorf("source JSONL line %d has unknown record type", lineNumber)
		}
	}
	if err := scanner.Err(); err != nil {
		return Bundle{}, fmt.Errorf("source JSONL line exceeds %d bytes or stream is unreadable", MaxRowBytes+(64<<10))
	}
	if lineNumber == 0 {
		return Bundle{}, errors.New("source JSONL is empty")
	}
	if !finished {
		return Bundle{}, errors.New("source JSONL is truncated or missing snapshot_end")
	}
	return buildOfflineBundle(header, snapshotSHA, summaries, present, tables)
}

func buildOfflineBundle(header sourceHeader, snapshotSHA string, inventory []snapshotTableSummary, present map[string]bool, sourceRows map[string][]json.RawMessage) (Bundle, error) {
	if err := validateSourceMigrationFingerprint(header, present, sourceRows); err != nil {
		return Bundle{}, err
	}
	warnings := []string{}
	for _, item := range inventory {
		spec, known := coverageSpec(item.Table)
		if !known {
			warnings = append(warnings, "unknown empty source table explicitly blocked: "+item.Table)
			continue
		}
		if !present[item.Table] {
			warnings = append(warnings, "known source table absent and explicitly represented as empty: "+item.Table)
		}
		if spec.Classification != Transformed && len(sourceRows[item.Table]) != 0 {
			return Bundle{}, fmt.Errorf("%s source table %q is nonempty", spec.Classification, item.Table)
		}
	}

	allowedGroups, err := transformAllowedGroups(sourceRows["user_allowed_groups"])
	if err != nil {
		return Bundle{}, err
	}
	targetRows := make(map[string][]json.RawMessage, len(TableOrder))
	for _, table := range TableOrder {
		targetRows[table] = []json.RawMessage{}
	}
	mappings := []struct{ source, target string }{
		{"groups", "groups"}, {"users", "users"}, {"pricing_versions", "pricing_versions"},
		{"pricing_rules", "pricing_rules"}, {"pricing_active_version", "pricing_active_version"},
		{"accounts", "accounts"}, {"account_groups", "account_groups"}, {"api_keys", "api_keys"},
		{"model_aliases", "model_aliases"}, {"balance_ledger", "balance_ledger"},
	}
	for _, mapping := range mappings {
		for _, row := range sourceRows[mapping.source] {
			converted, transformErr := transformSourceRow(mapping.source, row, allowedGroups)
			if transformErr != nil {
				return Bundle{}, fmt.Errorf("transform %s row: %w", mapping.source, transformErr)
			}
			targetRows[mapping.target] = append(targetRows[mapping.target], converted)
		}
	}

	coverage := make([]CoverageRecord, 0, len(inventory))
	for _, item := range inventory {
		rows := sourceRows[item.Table]
		digest, err := DigestRows(rows)
		if err != nil {
			return Bundle{}, err
		}
		if spec, known := coverageSpec(item.Table); known {
			coverage = append(coverage, CoverageRecord{SourceTable: spec.SourceTable, Classification: spec.Classification,
				TargetTables: append([]string(nil), spec.TargetTables...), Rule: spec.Rule,
				SourceRowCount: strconv.Itoa(len(rows)), SourceSHA256: digest})
		} else {
			coverage = append(coverage, CoverageRecord{SourceTable: item.Table, Classification: Blocked,
				TargetTables: []string{}, Rule: "unknown empty table; no mapping", SourceRowCount: "0", SourceSHA256: digest})
		}
	}
	sort.Slice(coverage, func(i, j int) bool { return coverage[i].SourceTable < coverage[j].SourceTable })
	chunks := []TableChunk{}
	for _, table := range TableOrder {
		tableChunks, err := NewTableChunks(table, targetRows[table])
		if err != nil {
			return Bundle{}, err
		}
		chunks = append(chunks, tableChunks...)
	}
	manifest := Manifest{Format: FormatVersion, TargetSchema: TargetSchemaVersion, MappingProfile: MappingProfileVersion,
		Source: SourceFingerprint{Engine: "postgresql-offline-export", SnapshotID: header.SnapshotID,
			SchemaName: header.SchemaName, ServerVersion: header.ServerVersion, MigrationCount: header.MigrationCount,
			MigrationSHA256: header.MigrationSHA256, SnapshotSHA256: snapshotSHA, CapturedAt: header.CapturedAt},
		Coverage: coverage, DependencyOrder: append([]string(nil), TableOrder...), Warnings: warnings,
		Blockers: []string{}, Tables: chunks}
	canonical, err := Canonicalize(manifest)
	if err != nil {
		return Bundle{}, fmt.Errorf("offline export failed canonical validation: %w", err)
	}
	return Bundle{Manifest: canonical}, nil
}

func validateSourceMigrationFingerprint(header sourceHeader, present map[string]bool, sourceRows map[string][]json.RawMessage) error {
	if !present["schema_migrations"] {
		return errors.New("source schema_migrations table must be present for migration fingerprint verification")
	}
	type migrationProjection struct {
		filename string
		encoded  json.RawMessage
	}
	projections := make([]migrationProjection, 0, len(sourceRows["schema_migrations"]))
	seen := make(map[string]bool, len(sourceRows["schema_migrations"]))
	for _, raw := range sourceRows["schema_migrations"] {
		row, err := sourceObject(raw, legacySourceColumns["schema_migrations"])
		if err != nil {
			return fmt.Errorf("schema_migrations fingerprint row rejected: %w", err)
		}
		transformed, err := transformSchemaMigration(row)
		if err != nil {
			return fmt.Errorf("schema_migrations fingerprint row rejected: %w", err)
		}
		filename, filenameOK := transformed["filename"].(string)
		checksum, checksumOK := transformed["checksum"].(string)
		if !filenameOK || !checksumOK || seen[filename] {
			return errors.New("schema_migrations fingerprint contains a duplicate or invalid filename")
		}
		seen[filename] = true
		encoded, err := json.Marshal(map[string]string{"filename": filename, "checksum": checksum})
		if err != nil {
			return errors.New("encode schema_migrations fingerprint failed")
		}
		projections = append(projections, migrationProjection{filename: filename, encoded: encoded})
	}
	sort.Slice(projections, func(left, right int) bool {
		return projections[left].filename < projections[right].filename
	})
	rows := make([]json.RawMessage, len(projections))
	for index := range projections {
		rows[index] = projections[index].encoded
	}
	count, err := parseBoundedCount(header.MigrationCount, MaxRowsPerTable)
	if err != nil || count != len(rows) {
		return errors.New("source migration count does not match schema_migrations")
	}
	digest, err := DigestRows(rows)
	if err != nil || digest != header.MigrationSHA256 {
		return errors.New("source migration sha256 does not match schema_migrations")
	}
	return nil
}

func transformAllowedGroups(rows []json.RawMessage) (map[string][]string, error) {
	result := map[string][]string{}
	seen := map[string]bool{}
	for _, raw := range rows {
		row, err := sourceObject(raw, []string{"user_id", "group_id"})
		if err != nil {
			return nil, err
		}
		userID, userErr := requiredString(row, "user_id")
		groupID, groupErr := requiredString(row, "group_id")
		if userErr != nil || groupErr != nil || !canonicalUnsignedID(userID) || !canonicalUnsignedID(groupID) {
			return nil, errors.New("user_allowed_groups identity is invalid")
		}
		key := userID + "\x1f" + groupID
		if seen[key] {
			return nil, errors.New("duplicate user_allowed_groups primary key")
		}
		seen[key] = true
		result[userID] = append(result[userID], groupID)
	}
	for userID := range result {
		sort.Slice(result[userID], func(i, j int) bool {
			left, _ := strconv.ParseInt(result[userID][i], 10, 64)
			right, _ := strconv.ParseInt(result[userID][j], 10, 64)
			return left < right
		})
	}
	return result, nil
}

func transformSourceRow(table string, raw json.RawMessage, allowedGroups map[string][]string) (json.RawMessage, error) {
	var row map[string]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil || row == nil {
		return nil, errors.New("row must be an object")
	}
	if table == "users" {
		id, err := requiredString(row, "id")
		if err != nil {
			return nil, err
		}
		allowed, _ := json.Marshal(allowedGroups[id])
		if allowedGroups[id] == nil {
			allowed = []byte("[]")
		}
		if existing, ok := row["allowed_group_ids_json"]; ok {
			var existingText string
			if json.Unmarshal(existing, &existingText) != nil || existingText != string(allowed) {
				return nil, errors.New("users.allowed_group_ids_json conflicts with user_allowed_groups")
			}
		}
		row["allowed_group_ids_json"], _ = json.Marshal(string(allowed))
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		return nil, err
	}
	canonical, _, err := validateAndCanonicalizeRow(table, encoded)
	return canonical, err
}

func decimalToE8(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "eE+") || strings.HasPrefix(value, "-") {
		return "", errors.New("amount is empty, signed, or uses exponent notation")
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 || !canonicalUnsignedAllowZero(parts[0]) {
		return "", errors.New("amount is not canonical decimal")
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
		if fraction == "" || len(fraction) > 8 {
			return "", errors.New("amount has invalid E8 precision")
		}
		for _, character := range fraction {
			if character < '0' || character > '9' {
				return "", errors.New("amount has invalid E8 precision")
			}
		}
	}
	fraction += strings.Repeat("0", 8-len(fraction))
	whole, _ := new(big.Int).SetString(parts[0], 10)
	whole.Mul(whole, big.NewInt(100_000_000))
	fractionInt, _ := new(big.Int).SetString(fraction, 10)
	whole.Add(whole, fractionInt)
	result := whole.String()
	if err := validateE8(result, false); err != nil {
		return "", err
	}
	return result, nil
}

func validateSourceHeader(header sourceHeader) error {
	if header.Type != "source" || header.Format != SourceFormatVersion || header.MappingProfile != MappingProfileVersion || !header.Complete {
		return errors.New("source record must declare the supported format, mapping profile, and complete_inventory=true")
	}
	if header.SnapshotID == "" || header.SchemaName == "" || header.ServerVersion == "" || containsControl(header.SnapshotID+header.SchemaName+header.ServerVersion) {
		return errors.New("source record fingerprint is incomplete or contains control characters")
	}
	if _, err := parseBoundedCount(header.MigrationCount, MaxRows); err != nil || validateLowerSHA256(header.MigrationSHA256) != nil {
		return errors.New("source migration fingerprint is invalid")
	}
	if !canonicalTimestamp(header.CapturedAt) {
		return errors.New("source captured_at must be canonical UTC RFC3339")
	}
	return nil
}

func snapshotDigest(header sourceHeader, tables []snapshotTableSummary) (string, error) {
	input := snapshotDigestInput{Format: header.Format, MappingProfile: header.MappingProfile,
		SnapshotID: header.SnapshotID, SchemaName: header.SchemaName, ServerVersion: header.ServerVersion,
		MigrationCount: header.MigrationCount, MigrationSHA256: header.MigrationSHA256,
		CapturedAt: header.CapturedAt, Tables: append([]snapshotTableSummary(nil), tables...)}
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func sourceObject(raw json.RawMessage, allowed []string) (map[string]json.RawMessage, error) {
	var row map[string]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil || row == nil {
		return nil, errors.New("source row must be an object")
	}
	allowedSet := map[string]bool{}
	for _, field := range allowed {
		allowedSet[field] = true
	}
	for field := range row {
		if !allowedSet[field] {
			return nil, fmt.Errorf("source row has unknown field %q", field)
		}
	}
	if len(row) != len(allowed) {
		return nil, errors.New("source row has missing fields")
	}
	return row, nil
}

func requiredString(row map[string]json.RawMessage, field string) (string, error) {
	raw, ok := row[field]
	if !ok {
		return "", fmt.Errorf("missing field %q", field)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("field %q must be a string", field)
	}
	return value, nil
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return ensureEOF(decoder)
}

func sourceIdentifier(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for index, character := range value {
		isLetter := character >= 'a' && character <= 'z'
		isNonLeadingDigit := index > 0 && character >= '0' && character <= '9'
		if character != '_' && !isLetter && !isNonLeadingDigit {
			return false
		}
	}
	return true
}
