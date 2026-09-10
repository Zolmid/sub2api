package cloudflaremigration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	FormatVersion         = "sub2api-cloudflare-offline-bundle/v3"
	SourceFormatVersion   = "sub2api-postgresql-jsonl/v2"
	TargetSchemaVersion   = "cloudflare-d1/0001-0008"
	MappingProfileVersion = "legacy-postgresql-to-d1-0008/v1"
	MaxBundleBytes        = 64 << 20
	MaxSnapshotBytes      = 128 << 20
	MaxRowBytes           = 2 << 20
	MaxChunkBytes         = 4 << 20
	MaxRows               = 1_000_000
	MaxRowsPerTable       = 250_000
	MaxRowsPerChunk       = 2_000
)

var TableOrder = []string{
	"groups",
	"users",
	"pricing_versions",
	"pricing_rules",
	"pricing_active_version",
	"accounts",
	"account_groups",
	"api_keys",
	"model_aliases",
	"balance_ledger",
}

type Bundle struct {
	Manifest Manifest `json:"manifest"`
}

type Manifest struct {
	Format          string            `json:"format"`
	TargetSchema    string            `json:"target_schema"`
	MappingProfile  string            `json:"mapping_profile"`
	Source          SourceFingerprint `json:"source"`
	Coverage        []CoverageRecord  `json:"coverage"`
	DependencyOrder []string          `json:"dependency_order"`
	Warnings        []string          `json:"warnings"`
	Blockers        []string          `json:"blockers"`
	Tables          []TableChunk      `json:"tables"`
}

type SourceFingerprint struct {
	Engine          string `json:"engine"`
	SnapshotID      string `json:"snapshot_id"`
	SchemaName      string `json:"schema_name"`
	ServerVersion   string `json:"server_version"`
	MigrationCount  string `json:"migration_count"`
	MigrationSHA256 string `json:"migration_sha256"`
	SnapshotSHA256  string `json:"snapshot_sha256"`
	CapturedAt      string `json:"captured_at"`
}

type CoverageRecord struct {
	SourceTable    string         `json:"source_table"`
	Classification Classification `json:"classification"`
	TargetTables   []string       `json:"target_tables"`
	Rule           string         `json:"rule"`
	SourceRowCount string         `json:"source_row_count"`
	SourceSHA256   string         `json:"source_sha256"`
}

type TableChunk struct {
	Table    string            `json:"table"`
	ID       string            `json:"id"`
	RowCount string            `json:"row_count"`
	SHA256   string            `json:"sha256"`
	Rows     []json.RawMessage `json:"rows"`
}

type fieldKind int

const (
	textField fieldKind = iota
	nullableTextField
	boolField
	integerField
	unsignedIDField
	unsignedE8Field
	signedE8Field
	jsonArrayField
	jsonObjectField
	hexDigestField
	timestampField
	nullableTimestampField
)

type rowSchema struct {
	primaryKey []string
	fields     map[string]fieldKind
}

var targetSchemas = map[string]rowSchema{
	"groups": schema([]string{"id"}, map[string]fieldKind{
		"id": unsignedIDField, "name": textField, "platform": textField, "status": textField,
		"is_exclusive": boolField, "subscription_type": textField, "created_at": timestampField,
		"updated_at": timestampField, "deleted_at": nullableTimestampField,
	}),
	"users": schema([]string{"id"}, map[string]fieldKind{
		"id": unsignedIDField, "status": textField, "role": textField, "concurrency": integerField,
		"balance_e8_usd": unsignedE8Field, "allowed_group_ids_json": jsonArrayField,
		"restrict_public_groups": boolField, "created_at": timestampField, "email": textField,
		"password_hash": textField, "username": textField, "notes": textField, "rpm_limit": integerField,
		"updated_at": timestampField, "deleted_at": nullableTimestampField,
		"totp_secret_envelope": nullableTextField, "totp_enabled": boolField,
		"totp_enabled_at": nullableTimestampField, "totp_revision": integerField,
	}),
	"pricing_versions": schema([]string{"version_id"}, map[string]fieldKind{
		"version_id": textField, "digest": hexDigestField, "max_reservation_e8_usd": unsignedE8Field,
		"created_at": timestampField,
	}),
	"pricing_rules": schema([]string{"version_id", "model_pattern"}, map[string]fieldKind{
		"version_id": textField, "model_pattern": textField, "match_kind": textField,
		"input_e8_per_million": unsignedE8Field, "output_e8_per_million": unsignedE8Field,
		"cache_read_e8_per_million": unsignedE8Field, "cache_write_e8_per_million": unsignedE8Field,
		"cache_write_5m_e8_per_million": unsignedE8Field, "cache_write_1h_e8_per_million": unsignedE8Field,
		"image_input_e8_per_million": unsignedE8Field, "image_output_e8_per_million": unsignedE8Field,
		"priority_input_e8_per_million": unsignedE8Field, "priority_output_e8_per_million": unsignedE8Field,
		"priority_cache_read_e8_per_million": unsignedE8Field, "priority_cache_write_e8_per_million": unsignedE8Field,
		"fast_multiplier_bps": unsignedE8Field, "flex_multiplier_bps": unsignedE8Field,
		"max_reasoning_effort_multiplier_bps": unsignedE8Field,
	}),
	"pricing_active_version": schema([]string{"singleton"}, map[string]fieldKind{
		"singleton": integerField, "version_id": textField, "activated_at": timestampField,
	}),
	"accounts": schema([]string{"id"}, map[string]fieldKind{
		"id": unsignedIDField, "name": textField, "platform": textField, "type": textField,
		"status": textField, "schedulable": boolField, "priority": integerField,
		"max_concurrency": integerField, "credential_envelope": textField, "extra_json": jsonObjectField,
		"created_at": timestampField, "updated_at": timestampField, "deleted_at": nullableTimestampField,
	}),
	"account_groups": schema([]string{"account_id", "group_id"}, map[string]fieldKind{
		"account_id": unsignedIDField, "group_id": unsignedIDField,
	}),
	"api_keys": schema([]string{"id"}, map[string]fieldKind{
		"id": unsignedIDField, "user_id": unsignedIDField, "group_id": unsignedIDField,
		"name": textField, "status": textField, "key_hash": hexDigestField,
		"ip_whitelist_json": jsonArrayField, "ip_blacklist_json": jsonArrayField,
		"expires_at": nullableTimestampField, "last_used_at": nullableTimestampField,
		"created_at": timestampField, "updated_at": timestampField, "deleted_at": nullableTimestampField,
	}),
	"model_aliases": schema([]string{"alias"}, map[string]fieldKind{
		"alias": textField, "upstream_model": textField, "status": textField, "updated_at": timestampField,
	}),
	"balance_ledger": schema([]string{"id"}, map[string]fieldKind{
		"id": textField, "operation_id": textField, "actor_user_id": unsignedIDField,
		"target_user_id": unsignedIDField, "adjustment_type": textField, "reason": textField,
		"delta_e8_usd": signedE8Field, "balance_before_e8_usd": unsignedE8Field,
		"balance_after_e8_usd": unsignedE8Field, "created_at": timestampField,
	}),
}

func schema(primary []string, fields map[string]fieldKind) rowSchema {
	return rowSchema{primaryKey: primary, fields: fields}
}

func DecodeBundle(input []byte) (Bundle, error) {
	if len(input) == 0 || len(input) > MaxBundleBytes {
		return Bundle{}, errors.New("bundle is empty or exceeds size bound")
	}
	if err := rejectDuplicateKeys(input); err != nil {
		return Bundle{}, err
	}
	var bundle Bundle
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("decode bundle: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func Canonicalize(manifest Manifest) (Manifest, error) {
	if manifest.Format != FormatVersion || manifest.TargetSchema != TargetSchemaVersion || manifest.MappingProfile != MappingProfileVersion {
		return Manifest{}, errors.New("unsupported bundle format, target schema, or mapping profile")
	}
	if err := validateSource(manifest.Source); err != nil {
		return Manifest{}, err
	}
	if len(manifest.Blockers) != 0 {
		return Manifest{}, fmt.Errorf("manifest contains blocking items: %s", strings.Join(manifest.Blockers, "; "))
	}
	if len(manifest.DependencyOrder) == 0 {
		manifest.DependencyOrder = append([]string(nil), TableOrder...)
	}
	if !equalStrings(manifest.DependencyOrder, TableOrder) {
		return Manifest{}, errors.New("dependency_order does not match canonical order")
	}
	if manifest.Warnings == nil {
		manifest.Warnings = []string{}
	}
	for _, warning := range manifest.Warnings {
		if warning == "" || len(warning) > 4<<10 || containsControl(warning) {
			return Manifest{}, errors.New("manifest warning is empty, oversized, or contains a control character")
		}
	}
	if manifest.Blockers == nil {
		manifest.Blockers = []string{}
	}
	if err := validateCoverage(manifest.Coverage); err != nil {
		return Manifest{}, err
	}
	sort.Slice(manifest.Coverage, func(left, right int) bool {
		return manifest.Coverage[left].SourceTable < manifest.Coverage[right].SourceTable
	})
	sort.Strings(manifest.Warnings)
	for index := 1; index < len(manifest.Warnings); index++ {
		if manifest.Warnings[index] == manifest.Warnings[index-1] {
			return Manifest{}, errors.New("manifest contains duplicate warnings")
		}
	}
	byTable := make(map[string][]TableChunk, len(TableOrder))
	seenChunkIDs := map[string]bool{}
	totalRows := 0
	for _, chunk := range manifest.Tables {
		if _, ok := targetSchemas[chunk.Table]; !ok {
			return Manifest{}, fmt.Errorf("unknown target table %q", chunk.Table)
		}
		if seenChunkIDs[chunk.ID] {
			return Manifest{}, fmt.Errorf("duplicate target chunk id %q", chunk.ID)
		}
		seenChunkIDs[chunk.ID] = true
		validated, err := validateChunk(chunk)
		if err != nil {
			return Manifest{}, err
		}
		byTable[chunk.Table] = append(byTable[chunk.Table], validated)
		totalRows += len(validated.Rows)
		if totalRows > MaxRows {
			return Manifest{}, errors.New("manifest exceeds total row bound")
		}
	}
	manifest.Tables = make([]TableChunk, 0, len(manifest.Tables))
	for _, table := range TableOrder {
		chunks := byTable[table]
		if len(chunks) == 0 {
			return Manifest{}, fmt.Errorf("missing target table chunk %q", table)
		}
		sort.Slice(chunks, func(i, j int) bool { return chunks[i].ID < chunks[j].ID })
		seenRows := map[string]bool{}
		tableRows := 0
		previousIdentity := ""
		for index, chunk := range chunks {
			expectedID := fmt.Sprintf("%s/%06d", table, index+1)
			if chunk.ID != expectedID {
				return Manifest{}, fmt.Errorf("target table %q has non-contiguous chunk ids", table)
			}
			for _, row := range chunk.Rows {
				identity, _ := rowIdentity(table, row)
				if seenRows[identity] {
					return Manifest{}, fmt.Errorf("target table %q has duplicate primary key", table)
				}
				if previousIdentity != "" && identity <= previousIdentity {
					return Manifest{}, fmt.Errorf("target table %q rows are not in canonical primary-key order", table)
				}
				seenRows[identity] = true
				previousIdentity = identity
				tableRows++
			}
			manifest.Tables = append(manifest.Tables, chunk)
		}
		if tableRows > MaxRowsPerTable {
			return Manifest{}, fmt.Errorf("target table %q exceeds row bound", table)
		}
	}
	if err := validateRelations(manifest.Tables); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func NewTableChunk(table string, rows []json.RawMessage) (TableChunk, error) {
	chunks, err := NewTableChunks(table, rows)
	if err != nil {
		return TableChunk{}, err
	}
	if len(chunks) != 1 {
		return TableChunk{}, fmt.Errorf("target table %q requires %d chunks; use NewTableChunks", table, len(chunks))
	}
	return chunks[0], nil
}

func NewTableChunks(table string, rows []json.RawMessage) ([]TableChunk, error) {
	if _, ok := targetSchemas[table]; !ok {
		return nil, fmt.Errorf("unknown target table %q", table)
	}
	if rows == nil {
		rows = []json.RawMessage{}
	}
	if len(rows) > MaxRowsPerTable {
		return nil, fmt.Errorf("target table %q exceeds row bound %d", table, MaxRowsPerTable)
	}
	canonicalRows := make([]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		canonical, _, err := validateAndCanonicalizeRow(table, row)
		if err != nil {
			return nil, err
		}
		canonicalRows = append(canonicalRows, canonical)
	}
	sort.Slice(canonicalRows, func(i, j int) bool {
		left, _ := rowIdentity(table, canonicalRows[i])
		right, _ := rowIdentity(table, canonicalRows[j])
		return left < right
	})
	chunks := []TableChunk{}
	start := 0
	for start < len(canonicalRows) {
		end := start
		size := 0
		for end < len(canonicalRows) && end-start < MaxRowsPerChunk {
			rowSize := len(canonicalRows[end]) + 8
			if end > start && size+rowSize > MaxChunkBytes {
				break
			}
			if rowSize > MaxChunkBytes {
				return nil, fmt.Errorf("target table %q row exceeds chunk byte bound", table)
			}
			size += rowSize
			end++
		}
		chunkRows := append([]json.RawMessage(nil), canonicalRows[start:end]...)
		digest, err := DigestRows(chunkRows)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, TableChunk{Table: table, ID: fmt.Sprintf("%s/%06d", table, len(chunks)+1), RowCount: strconv.Itoa(len(chunkRows)), SHA256: digest, Rows: chunkRows})
		start = end
	}
	if len(chunks) == 0 {
		digest, _ := DigestRows(nil)
		chunks = append(chunks, TableChunk{Table: table, ID: table + "/000001", RowCount: "0", SHA256: digest, Rows: []json.RawMessage{}})
	}
	return chunks, nil
}

func validateChunk(chunk TableChunk) (TableChunk, error) {
	if len(chunk.Rows) > MaxRowsPerChunk {
		return TableChunk{}, fmt.Errorf("target chunk %q exceeds row bound", chunk.ID)
	}
	count, err := parseBoundedCount(chunk.RowCount, MaxRowsPerChunk)
	if err != nil || count != len(chunk.Rows) {
		return TableChunk{}, fmt.Errorf("target chunk %q row count mismatch", chunk.ID)
	}
	if err := validateLowerSHA256(chunk.SHA256); err != nil {
		return TableChunk{}, fmt.Errorf("target chunk %q has invalid sha256", chunk.ID)
	}
	canonicalRows := make([]json.RawMessage, 0, len(chunk.Rows))
	bytesUsed := 0
	for _, row := range chunk.Rows {
		canonical, _, err := validateAndCanonicalizeRow(chunk.Table, row)
		if err != nil {
			return TableChunk{}, err
		}
		bytesUsed += len(canonical) + 8
		canonicalRows = append(canonicalRows, canonical)
	}
	if bytesUsed > MaxChunkBytes {
		return TableChunk{}, fmt.Errorf("target chunk %q exceeds byte bound", chunk.ID)
	}
	sort.Slice(canonicalRows, func(i, j int) bool {
		left, _ := rowIdentity(chunk.Table, canonicalRows[i])
		right, _ := rowIdentity(chunk.Table, canonicalRows[j])
		return left < right
	})
	digest, err := DigestRows(canonicalRows)
	if err != nil || digest != chunk.SHA256 {
		return TableChunk{}, fmt.Errorf("target chunk %q sha256 mismatch", chunk.ID)
	}
	seen := map[string]bool{}
	for _, row := range canonicalRows {
		identity, _ := rowIdentity(chunk.Table, row)
		if seen[identity] {
			return TableChunk{}, fmt.Errorf("target table %q has duplicate primary key", chunk.Table)
		}
		seen[identity] = true
	}
	return TableChunk{Table: chunk.Table, ID: chunk.ID, RowCount: chunk.RowCount, SHA256: digest, Rows: canonicalRows}, nil
}

func validateAndCanonicalizeRow(table string, raw json.RawMessage) (json.RawMessage, string, error) {
	if len(raw) == 0 || len(raw) > MaxRowBytes {
		return nil, "", fmt.Errorf("%s row is empty or oversized", table)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, "", fmt.Errorf("%s row: %w", table, err)
	}
	schema, ok := targetSchemas[table]
	if !ok {
		return nil, "", fmt.Errorf("unknown target table %q", table)
	}
	var row map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&row); err != nil || row == nil {
		return nil, "", fmt.Errorf("%s row must be an object", table)
	}
	if err := ensureEOF(decoder); err != nil {
		return nil, "", err
	}
	if len(row) != len(schema.fields) {
		return nil, "", fmt.Errorf("%s row has missing or unknown fields", table)
	}
	for name, value := range row {
		kind, exists := schema.fields[name]
		if !exists {
			return nil, "", fmt.Errorf("%s row has unknown field %q", table, name)
		}
		if err := validateField(table, name, kind, value); err != nil {
			return nil, "", err
		}
	}
	canonical, err := CanonicalJSON(raw)
	if err != nil {
		return nil, "", err
	}
	identity, err := rowIdentity(table, canonical)
	if err != nil {
		return nil, "", err
	}
	return canonical, identity, nil
}

func validateField(table, name string, kind fieldKind, raw json.RawMessage) error {
	if bytes.Equal(raw, []byte("null")) {
		if kind == nullableTextField || kind == nullableTimestampField {
			return nil
		}
		return fmt.Errorf("%s.%s may not be null", table, name)
	}
	switch kind {
	case textField, nullableTextField, timestampField, nullableTimestampField, jsonArrayField, jsonObjectField, hexDigestField, unsignedIDField, unsignedE8Field, signedE8Field:
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("%s.%s must be a string", table, name)
		}
		if len(value) > 1<<20 {
			return fmt.Errorf("%s.%s exceeds text bound", table, name)
		}
		if containsControl(value) {
			return fmt.Errorf("%s.%s contains a control character", table, name)
		}
		switch kind {
		case timestampField, nullableTimestampField:
			if !canonicalTimestamp(value) {
				return fmt.Errorf("%s.%s is not canonical UTC RFC3339", table, name)
			}
		case jsonArrayField, jsonObjectField:
			canonical, err := CanonicalJSON([]byte(value))
			if err != nil || len(canonical) == 0 || kind == jsonArrayField && canonical[0] != '[' || kind == jsonObjectField && canonical[0] != '{' || string(canonical) != value {
				return fmt.Errorf("%s.%s must contain canonical JSON of the required shape", table, name)
			}
		case hexDigestField:
			if len(value) != 64 || strings.ToLower(value) != value {
				return fmt.Errorf("%s.%s must be lowercase sha256", table, name)
			}
			if _, err := hex.DecodeString(value); err != nil {
				return fmt.Errorf("%s.%s must be lowercase sha256", table, name)
			}
		case unsignedIDField:
			if !canonicalUnsignedID(value) {
				return fmt.Errorf("%s.%s is not a canonical unsigned identifier", table, name)
			}
		case unsignedE8Field:
			if err := validateE8(value, false); err != nil {
				return fmt.Errorf("%s.%s: %w", table, name, err)
			}
		case signedE8Field:
			if err := validateE8(value, true); err != nil {
				return fmt.Errorf("%s.%s: %w", table, name, err)
			}
		}
	case boolField:
		if !bytes.Equal(raw, []byte("true")) && !bytes.Equal(raw, []byte("false")) {
			return fmt.Errorf("%s.%s must be boolean", table, name)
		}
	case integerField:
		var number json.Number
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&number); err != nil || strings.ContainsAny(number.String(), ".eE") {
			return fmt.Errorf("%s.%s must be an integer", table, name)
		}
		if _, err := strconv.ParseInt(number.String(), 10, 64); err != nil {
			return fmt.Errorf("%s.%s overflows int64", table, name)
		}
	}
	return validateSemanticField(table, name, raw)
}

func validateSemanticField(table, name string, raw json.RawMessage) error {
	var text string
	_ = json.Unmarshal(raw, &text)
	if name == "status" && table != "user_subscriptions" && text != "active" && text != "disabled" {
		return fmt.Errorf("%s.status is unsupported", table)
	}
	if table == "users" && name == "role" && text != "user" && text != "admin" {
		return errors.New("users.role is unsupported")
	}
	if table == "accounts" && name == "credential_envelope" && !validEnvelope(text, false) {
		return errors.New("accounts.credential_envelope is not a D1 envelope")
	}
	if table == "users" && name == "totp_secret_envelope" && text != "" && !validEnvelope(text, true) {
		return errors.New("users.totp_secret_envelope is not a D1 TOTP envelope")
	}
	if table == "accounts" && name == "extra_json" {
		var value any
		if err := json.Unmarshal([]byte(text), &value); err != nil || containsSecretField(value) {
			return errors.New("accounts.extra_json contains invalid or secret-shaped data")
		}
	}
	return nil
}

func validateRelations(chunks []TableChunk) error {
	rows := map[string][]map[string]json.RawMessage{}
	for _, chunk := range chunks {
		for _, raw := range chunk.Rows {
			var row map[string]json.RawMessage
			_ = json.Unmarshal(raw, &row)
			rows[chunk.Table] = append(rows[chunk.Table], row)
		}
	}
	ids := func(table, field string) map[string]bool {
		result := map[string]bool{}
		for _, row := range rows[table] {
			result[jsonString(row[field])] = true
		}
		return result
	}
	groups, users, accounts := ids("groups", "id"), ids("users", "id"), ids("accounts", "id")
	versions := ids("pricing_versions", "version_id")
	groupNames := map[string]bool{}
	for _, row := range rows["groups"] {
		if bytes.Equal(row["deleted_at"], []byte("null")) {
			name := jsonString(row["name"])
			if groupNames[name] {
				return errors.New("groups contains a duplicate live name")
			}
			groupNames[name] = true
		}
	}
	emails := map[string]bool{}
	for _, row := range rows["users"] {
		concurrency, rpm := jsonInteger(row["concurrency"]), jsonInteger(row["rpm_limit"])
		revision := jsonInteger(row["totp_revision"])
		if concurrency < 1 || rpm < 0 || revision < 0 || revision > 9007199254740991 {
			return errors.New("users contains an out-of-range control integer")
		}
		enabled := bytes.Equal(row["totp_enabled"], []byte("true"))
		hasSecret := !bytes.Equal(row["totp_secret_envelope"], []byte("null"))
		hasEnabledAt := !bytes.Equal(row["totp_enabled_at"], []byte("null"))
		if enabled != hasSecret || enabled != hasEnabledAt {
			return errors.New("users contains inconsistent TOTP state")
		}
		if hasSecret && len(jsonString(row["totp_secret_envelope"])) > 512 {
			return errors.New("users TOTP envelope exceeds the target schema bound")
		}
		if bytes.Equal(row["deleted_at"], []byte("null")) {
			email := strings.ToLower(strings.TrimSpace(jsonString(row["email"])))
			if email != "" && emails[email] {
				return errors.New("users contains a duplicate live email identity")
			}
			emails[email] = email != ""
		}
		var allowed []string
		if err := json.Unmarshal([]byte(jsonString(row["allowed_group_ids_json"])), &allowed); err != nil {
			return errors.New("users.allowed_group_ids_json must be an array of ids")
		}
		seen := map[string]bool{}
		for _, id := range allowed {
			if !groups[id] || seen[id] {
				return errors.New("users.allowed_group_ids_json has missing or duplicate group")
			}
			seen[id] = true
		}
	}
	for _, row := range rows["account_groups"] {
		if !accounts[jsonString(row["account_id"])] || !groups[jsonString(row["group_id"])] {
			return errors.New("account_groups contains a missing reference")
		}
	}
	for _, row := range rows["accounts"] {
		if jsonInteger(row["max_concurrency"]) < 1 {
			return errors.New("accounts.max_concurrency must be positive")
		}
	}
	seenHashes := map[string]bool{}
	for _, row := range rows["api_keys"] {
		hash := jsonString(row["key_hash"])
		if !users[jsonString(row["user_id"])] || !groups[jsonString(row["group_id"])] {
			return errors.New("api_keys contains a missing reference")
		}
		if seenHashes[hash] {
			return errors.New("api_keys contains duplicate key_hash")
		}
		seenHashes[hash] = true
	}
	for _, row := range rows["pricing_versions"] {
		versionID := jsonString(row["version_id"])
		if !canonicalPricingIdentifier(versionID) || jsonString(row["max_reservation_e8_usd"]) == "0" {
			return errors.New("pricing_versions contains an invalid version or non-positive reservation ceiling")
		}
	}
	pricingFamilies := map[string][]string{}
	for _, row := range rows["pricing_rules"] {
		versionID := jsonString(row["version_id"])
		pattern := jsonString(row["model_pattern"])
		kind := jsonString(row["match_kind"])
		if !versions[versionID] {
			return errors.New("pricing_rules contains a missing version")
		}
		if !validPricingPattern(pattern, kind) {
			return errors.New("pricing_rules contains an invalid canonical model pattern")
		}
		for _, field := range []string{"fast_multiplier_bps", "flex_multiplier_bps", "max_reasoning_effort_multiplier_bps"} {
			value := jsonString(row[field])
			if len(value) > 8 || field == "max_reasoning_effort_multiplier_bps" && value == "0" {
				return errors.New("pricing_rules contains an out-of-range multiplier")
			}
		}
		if kind == "family" {
			prefix := strings.TrimSuffix(pattern, "*")
			for _, prior := range pricingFamilies[versionID] {
				if strings.HasPrefix(prefix, prior) || strings.HasPrefix(prior, prefix) {
					return errors.New("pricing_rules contains overlapping wildcard families")
				}
			}
			pricingFamilies[versionID] = append(pricingFamilies[versionID], prefix)
		}
	}
	for _, row := range rows["pricing_active_version"] {
		if jsonInteger(row["singleton"]) != 1 || !versions[jsonString(row["version_id"])] {
			return errors.New("pricing_active_version is invalid")
		}
	}
	seenOps := map[string]bool{}
	for _, row := range rows["balance_ledger"] {
		if !users[jsonString(row["actor_user_id"])] || !users[jsonString(row["target_user_id"])] {
			return errors.New("balance_ledger contains a missing user reference")
		}
		id := jsonString(row["id"])
		op := jsonString(row["operation_id"])
		reason := jsonString(row["reason"])
		adjustmentType := jsonString(row["adjustment_type"])
		if id == "" || len(id) > 128 || op == "" || len(reason) > 4096 || adjustmentType != "set" && adjustmentType != "add" && adjustmentType != "subtract" {
			return errors.New("balance_ledger contains an invalid identity, adjustment type, or reason")
		}
		if seenOps[op] {
			return errors.New("balance_ledger contains duplicate operation_id")
		}
		seenOps[op] = true
		before, _ := new(big.Int).SetString(jsonString(row["balance_before_e8_usd"]), 10)
		delta, _ := new(big.Int).SetString(jsonString(row["delta_e8_usd"]), 10)
		after, _ := new(big.Int).SetString(jsonString(row["balance_after_e8_usd"]), 10)
		if new(big.Int).Add(before, delta).Cmp(after) != 0 {
			return errors.New("balance_ledger arithmetic is inconsistent")
		}
	}
	return nil
}

func canonicalPricingIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		isLetter := character >= 'a' && character <= 'z'
		isDigit := character >= '0' && character <= '9'
		if !isLetter && !isDigit && !strings.ContainsRune("._:-", character) {
			return false
		}
	}
	return true
}

func validPricingPattern(value, kind string) bool {
	if len(value) == 0 || len(value) > 257 || kind != "exact" && kind != "family" {
		return false
	}
	core := value
	if kind == "family" {
		if !strings.HasSuffix(value, "*") || len(value) == 1 {
			return false
		}
		core = strings.TrimSuffix(value, "*")
	} else if strings.Contains(value, "*") {
		return false
	}
	for _, character := range core {
		isLetter := character >= 'a' && character <= 'z'
		isDigit := character >= '0' && character <= '9'
		if !isLetter && !isDigit && !strings.ContainsRune("._:/-", character) {
			return false
		}
	}
	return !strings.HasPrefix(core, "claude-") || !strings.Contains(core, ".")
}

func validEnvelope(value string, totp bool) bool {
	prefix := "aes-gcm:v1:"
	minimumCiphertext := 17
	if totp {
		prefix = "aes-gcm:v1:totp:"
		minimumCiphertext = 32
	}
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, prefix), ":")
	if len(parts) != 2 {
		return false
	}
	iv, ivErr := base64.StdEncoding.DecodeString(parts[0])
	ciphertext, cipherErr := base64.StdEncoding.DecodeString(parts[1])
	if ivErr != nil || cipherErr != nil || len(iv) != 12 || len(ciphertext) < minimumCiphertext || base64.StdEncoding.EncodeToString(iv) != parts[0] || base64.StdEncoding.EncodeToString(ciphertext) != parts[1] {
		return false
	}
	return !totp || len(ciphertext) == 48 && len(value) <= 512
}

func containsSecretField(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
			for _, marker := range []string{"password", "secret", "token", "api_key", "credential", "private_key"} {
				if strings.Contains(normalized, marker) {
					return true
				}
			}
			if containsSecretField(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSecretField(child) {
				return true
			}
		}
	}
	return false
}

func validateCoverage(records []CoverageRecord) error {
	seen := map[string]bool{}
	for _, record := range records {
		if !sourceIdentifier(record.SourceTable) || record.Rule == "" || containsControl(record.Rule) {
			return fmt.Errorf("coverage %q has unsafe canonical text", record.SourceTable)
		}
		if seen[record.SourceTable] {
			return fmt.Errorf("duplicate coverage record %q", record.SourceTable)
		}
		seen[record.SourceTable] = true
		if _, err := parseBoundedCount(record.SourceRowCount, MaxRows); err != nil {
			return fmt.Errorf("coverage %q has invalid row count", record.SourceTable)
		}
		if err := validateLowerSHA256(record.SourceSHA256); err != nil {
			return fmt.Errorf("coverage %q has invalid sha256", record.SourceTable)
		}
		if spec, ok := coverageSpec(record.SourceTable); ok {
			if record.Classification != spec.Classification || record.Rule != spec.Rule || !equalStrings(record.TargetTables, spec.TargetTables) {
				return fmt.Errorf("coverage %q does not match executable matrix", record.SourceTable)
			}
		} else if record.Classification != Blocked || record.SourceRowCount != "0" {
			return fmt.Errorf("unknown coverage %q must be explicitly blocked and empty", record.SourceTable)
		}
	}
	for _, spec := range CoverageMatrix {
		if !seen[spec.SourceTable] {
			return fmt.Errorf("missing coverage record %q", spec.SourceTable)
		}
	}
	return nil
}

func validateSource(source SourceFingerprint) error {
	if source.Engine != "postgresql-offline-export" || source.SnapshotID == "" || source.SchemaName == "" || source.ServerVersion == "" {
		return errors.New("source fingerprint is incomplete or not offline")
	}
	if containsControl(source.SnapshotID) || containsControl(source.SchemaName) || containsControl(source.ServerVersion) {
		return errors.New("source fingerprint contains a control character")
	}
	if !sourceIdentifier(source.SchemaName) || len(source.SnapshotID) > 4<<10 || len(source.ServerVersion) > 64 {
		return errors.New("source fingerprint text is outside canonical bounds")
	}
	if _, err := parseBoundedCount(source.MigrationCount, MaxRows); err != nil {
		return errors.New("source migration summary is invalid")
	}
	if validateLowerSHA256(source.MigrationSHA256) != nil || validateLowerSHA256(source.SnapshotSHA256) != nil {
		return errors.New("source fingerprint sha256 is invalid")
	}
	if !canonicalTimestamp(source.CapturedAt) {
		return errors.New("source captured_at is not canonical UTC RFC3339")
	}
	return nil
}

func DigestRows(rows []json.RawMessage) (string, error) {
	hash := sha256.New()
	var length [8]byte
	for _, row := range rows {
		canonical, err := CanonicalJSON(row)
		if err != nil {
			return "", err
		}
		binary.BigEndian.PutUint64(length[:], uint64(len(canonical)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(canonical)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func CanonicalJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > MaxRowBytes {
		return nil, errors.New("JSON is empty or oversized")
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := ensureEOF(decoder); err != nil {
		return nil, err
	}
	if err := validateJSONValue(value, 0); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	return encoded, err
}

func validateJSONValue(value any, depth int) error {
	if depth > 16 {
		return errors.New("JSON nesting exceeds bound")
	}
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) > 128 {
			return errors.New("JSON object exceeds field bound")
		}
		for key, child := range typed {
			if len(key) > 1<<20 {
				return errors.New("JSON key exceeds bound")
			}
			if containsControl(key) {
				return errors.New("JSON key contains a control character")
			}
			if err := validateJSONValue(child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := validateJSONValue(child, depth+1); err != nil {
				return err
			}
		}
	case string:
		if len(typed) > 1<<20 {
			return errors.New("JSON string exceeds bound")
		}
		if containsControl(typed) {
			return errors.New("JSON string contains a control character")
		}
	case json.Number:
		if strings.ContainsAny(typed.String(), ".eE") {
			return errors.New("JSON numbers must be canonical integers")
		}
		if _, err := strconv.ParseInt(typed.String(), 10, 64); err != nil {
			return errors.New("JSON integer overflows int64")
		}
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("JSON contains a duplicate object key")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON has trailing values")
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("JSON has trailing values")
	}
	return nil
}

func rowIdentity(table string, raw json.RawMessage) (string, error) {
	var row map[string]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil {
		return "", err
	}
	parts := make([]string, 0, len(targetSchemas[table].primaryKey))
	for _, key := range targetSchemas[table].primaryKey {
		parts = append(parts, string(row[key]))
	}
	return strings.Join(parts, "\x1f"), nil
}

func validateE8(value string, signed bool) error {
	if value == "" || value == "-0" || !signed && strings.HasPrefix(value, "-") {
		return errors.New("amount is not canonical E8")
	}
	digits := value
	if signed && strings.HasPrefix(value, "-") {
		digits = value[1:]
	}
	if !canonicalUnsignedAllowZero(digits) {
		return errors.New("amount is not canonical E8")
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok || parsed.Cmp(big.NewInt(math.MaxInt64)) > 0 || parsed.Cmp(big.NewInt(math.MinInt64)) < 0 {
		return errors.New("amount overflows signed 64-bit E8")
	}
	return nil
}

func parseBoundedCount(value string, maximum int) (int, error) {
	if !canonicalUnsignedAllowZero(value) {
		return 0, errors.New("count is not canonical")
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed > maximum {
		return 0, errors.New("count exceeds bound")
	}
	return parsed, nil
}

func canonicalUnsigned(value string) bool {
	return value != "" && value != "0" && canonicalDigits(value)
}

func canonicalUnsignedID(value string) bool {
	if !canonicalUnsigned(value) {
		return false
	}
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}

func canonicalUnsignedAllowZero(value string) bool {
	return value == "0" || canonicalUnsigned(value)
}

func canonicalDigits(value string) bool {
	if value == "" || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func jsonString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func jsonInteger(raw json.RawMessage) int64 {
	value, _ := strconv.ParseInt(string(raw), 10, 64)
	return value
}

func emptyDigest() string {
	digest, _ := DigestRows(nil)
	return digest
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateLowerSHA256(value string) error {
	if len(value) != 64 || strings.ToLower(value) != value {
		return errors.New("not lowercase sha256")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("not lowercase sha256")
	}
	return nil
}

func canonicalTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.UTC().Format(time.RFC3339Nano) == value
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

// The restore-v4 contract is deliberately additive. The v3/0008 API above is
// kept intact so already reviewed bundles and operator procedures remain
// reproducible; new commands opt in to the complete canonical 0001-0017
// target.
const (
	RestoreFormatVersion         = "sub2api-cloudflare-offline-restore/v4"
	RestoreSourceFormatVersion   = "sub2api-postgresql-jsonl/v3"
	RestoreTargetSchemaVersion   = "cloudflare-d1/0001-0017"
	RestoreMappingProfileVersion = "legacy-postgresql-to-d1-0017/v1"

	Restore0018FormatVersion         = "sub2api-cloudflare-offline-restore/v5"
	Restore0018SourceFormatVersion   = "sub2api-postgresql-jsonl/v4"
	Restore0018TargetSchemaVersion   = "cloudflare-d1/0001-0018"
	Restore0018MappingProfileVersion = "legacy-postgresql-to-d1-0018/v1"
)

type MigrationFingerprint struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
}

type OperationalInitialization struct {
	Entity string `json:"entity"`
	Mode   string `json:"mode"`
}

type RestoreManifest struct {
	Format                    string                      `json:"format"`
	TargetSchema              string                      `json:"target_schema"`
	MappingProfile            string                      `json:"mapping_profile"`
	Source                    SourceFingerprint           `json:"source"`
	Coverage                  []CoverageRecord            `json:"coverage"`
	DependencyOrder           []string                    `json:"dependency_order"`
	TargetMigrations          []MigrationFingerprint      `json:"target_migrations"`
	OperationalInitialization []OperationalInitialization `json:"operational_initialization"`
	Warnings                  []string                    `json:"warnings"`
	Blockers                  []string                    `json:"blockers"`
	Tables                    []TableChunk                `json:"tables"`
}

type RestoreBundle struct {
	Manifest RestoreManifest `json:"manifest"`
}

var RestoreTableOrder = []string{
	"groups", "users", "subscription_plans", "user_subscriptions",
	"pricing_versions", "pricing_rules", "pricing_active_version",
	"accounts", "account_groups", "api_keys", "model_aliases", "balance_ledger",
}

var CanonicalTargetMigrations = []MigrationFingerprint{
	{Filename: "0001_initial.sql", SHA256: "7ecbe557b61ba557c0cf8e14caefdf11ce5885548d5f8af80461b4c86f2b94c7"},
	{Filename: "0002_management_control_plane.sql", SHA256: "cd846f4d07dc92db47908d1ca94f577c279fdaa78e238acb793ebf0f86390fe9"},
	{Filename: "0003_group_live_name_unique.sql", SHA256: "d49042eff7ec6dc4fbaf03c7598bb4c0bb9b311e8032082f3c87e6aecc5bfd89"},
	{Filename: "0004_user_live_email_identity.sql", SHA256: "ad5efd4780f3f614bf82e8080ff55b5f809114fc86af1b965c5301567876b744"},
	{Filename: "0005_balance_ledger.sql", SHA256: "60013ff0da8243f6263027e714468b4301fef202bed4577968fd48906f954722"},
	{Filename: "0006_totp_security.sql", SHA256: "1ab45332b377b1dc494529627c12cc81b620a0465d58ab86ece5c3f99d2d79a9"},
	{Filename: "0007_admin_role_management.sql", SHA256: "a146ba486562c64ecb3b5aa920e43a294fcca05ffc6fa5210457f2a927d9e214"},
	{Filename: "0008_e8_money_and_pricing.sql", SHA256: "62c2eb3d734c19cd5e9943f822d0742157a8990dbad4267a967ec663ec26a588"},
	{Filename: "0009_billing_reservations.sql", SHA256: "a8108f2644c1d0ca7e7db5b2b63e34cace0dcad557be69523595c2b6f7855837"},
	{Filename: "0010_scheduler_runtime.sql", SHA256: "89a7f759465a018252d40cc2cfad448687029a9b852999520bf70a8613989dd7"},
	{Filename: "0011_background_job_runtime.sql", SHA256: "9af6d6001510201c9134a9cce634b247153afd2b13b4ad10789cf891781f51c0"},
	{Filename: "0012_subscription_runtime.sql", SHA256: "12dfbabb3c69ae48cc5f419c5212b9d0e311e92a2b3ff35f4ee17d52a27173af"},
	{Filename: "0013_oauth_refresh_runtime.sql", SHA256: "45219392e34cfbdb4e94912e48ee2ce5d9442be07713c3cbc642ba33311af160"},
	{Filename: "0014_auth_cache_runtime.sql", SHA256: "1f5534c55da45fdc930e2a8947064c5363148ed7a4cadcc917c2adadf9452c25"},
	{Filename: "0015_settings_runtime.sql", SHA256: "b28eb57270c6f8dfde12e9091d420553e51a6f3764377ae1da0cf55cc144c96e"},
	{Filename: "0016_payment_runtime.sql", SHA256: "8cf73de4f8834d780895a54338b1881c67599b22854ce69e044b732c8cf8f4b3"},
	{Filename: "0017_email_runtime.sql", SHA256: "480183fbaa08cffba77441b0fc9423d25ff339b47f5c91d4f02f3dcf58555a0b"},
}

var CanonicalTargetMigrations0018 = append(append([]MigrationFingerprint(nil), CanonicalTargetMigrations...),
	MigrationFingerprint{Filename: "0018_auth_sessions.sql", SHA256: "f39e75c2351cb3535e951034d4e85af167b68d33d3f5eabde49c6e78f39168e4"},
)

var CanonicalOperationalInitialization = []OperationalInitialization{
	{Entity: "users.balance_version", Mode: "column-default:0"},
	{Entity: "accounts.credential_version", Mode: "column-default:1"},
	{Entity: "accounts.credential_fingerprint", Mode: "column-default:null"},
	{Entity: "admin_role_change_audit", Mode: "empty-before-import"},
	{Entity: "auth_cache_credential_revisions", Mode: "trigger-managed-from-source-inserts"},
	{Entity: "auth_cache_entity_revisions", Mode: "trigger-managed-from-source-inserts"},
	{Entity: "auth_cache_outbox", Mode: "trigger-managed-from-source-inserts"},
	{Entity: "background_job_outbox", Mode: "empty-before-import"},
	{Entity: "background_job_transitions", Mode: "empty-before-import"},
	{Entity: "background_jobs", Mode: "empty-before-import"},
	{Entity: "billing_cas_guards", Mode: "empty-before-import"},
	{Entity: "billing_monetary_ledger", Mode: "empty-before-import"},
	{Entity: "billing_reservation_events", Mode: "empty-before-import"},
	{Entity: "billing_reservations", Mode: "empty-before-import"},
	{Entity: "email_challenges", Mode: "empty-before-import"},
	{Entity: "email_delivery_jobs", Mode: "empty-before-import"},
	{Entity: "email_delivery_witnesses", Mode: "empty-before-import"},
	{Entity: "email_issue_idempotency", Mode: "empty-before-import"},
	{Entity: "email_issue_witnesses", Mode: "empty-before-import"},
	{Entity: "email_runtime_audit", Mode: "empty-before-import"},
	{Entity: "email_runtime_batch_guards", Mode: "empty-before-import"},
	{Entity: "email_runtime_outbox", Mode: "empty-before-import"},
	{Entity: "gateway_requests", Mode: "empty-before-import"},
	{Entity: "management_operations", Mode: "empty-before-import"},
	{Entity: "oauth_refresh_attempts", Mode: "empty-before-import"},
	{Entity: "oauth_refresh_audit", Mode: "empty-before-import"},
	{Entity: "oauth_refresh_commit_witnesses", Mode: "empty-before-import"},
	{Entity: "oauth_refresh_fingerprint_audit", Mode: "empty-before-import"},
	{Entity: "oauth_refresh_invalidation_outbox", Mode: "empty-before-import"},
	{Entity: "outbox_conflicts", Mode: "empty-before-import"},
	{Entity: "outbox_events", Mode: "empty-before-import"},
	{Entity: "payment_audit_events", Mode: "empty-before-import"},
	{Entity: "payment_batch_guards", Mode: "empty-before-import"},
	{Entity: "payment_idempotency_witnesses", Mode: "empty-before-import"},
	{Entity: "payment_ledger_transactions", Mode: "empty-before-import"},
	{Entity: "payment_outbox_events", Mode: "empty-before-import"},
	{Entity: "payment_provider_event_dedup", Mode: "empty-before-import"},
	{Entity: "payment_records", Mode: "empty-before-import"},
	{Entity: "payment_refund_records", Mode: "empty-before-import"},
	{Entity: "pricing_version_activations", Mode: "trigger-managed-from-source-inserts"},
	{Entity: "scheduler_account_runtime", Mode: "empty-before-import"},
	{Entity: "scheduler_principal_limits", Mode: "empty-before-import"},
	{Entity: "settings_runtime", Mode: "empty-before-import"},
	{Entity: "settings_runtime_audit", Mode: "empty-before-import"},
	{Entity: "settings_runtime_batch_guards", Mode: "empty-before-import"},
	{Entity: "settings_runtime_cas_claims", Mode: "empty-before-import"},
	{Entity: "settings_runtime_idempotency", Mode: "empty-before-import"},
	{Entity: "settings_runtime_outbox", Mode: "empty-before-import"},
	{Entity: "settings_runtime_request_witness", Mode: "empty-before-import"},
	{Entity: "subscription_operation_effects", Mode: "empty-before-import"},
	{Entity: "subscription_operations", Mode: "empty-before-import"},
	{Entity: "subscription_runtime_guards", Mode: "empty-before-import"},
	{Entity: "usage_events", Mode: "empty-before-import"},
}

var CanonicalOperationalInitialization0018 = append(append([]OperationalInitialization(nil), CanonicalOperationalInitialization...),
	OperationalInitialization{Entity: "auth_sessions", Mode: "empty-before-import"},
	OperationalInitialization{Entity: "auth_session_family_revocations", Mode: "empty-before-import"},
	OperationalInitialization{Entity: "auth_session_audit_events", Mode: "empty-before-import"},
	OperationalInitialization{Entity: "auth_session_rotation_witnesses", Mode: "empty-before-import"},
)

var restoreSchemas = buildRestoreSchemas()

func buildRestoreSchemas() map[string]rowSchema {
	result := make(map[string]rowSchema, len(targetSchemas)+2)
	for table, definition := range targetSchemas {
		fields := make(map[string]fieldKind, len(definition.fields)+1)
		for name, kind := range definition.fields {
			fields[name] = kind
		}
		result[table] = schema(append([]string(nil), definition.primaryKey...), fields)
	}
	groups := result["groups"]
	groups.fields["rate_multiplier_bps"] = unsignedE8Field
	result["groups"] = groups
	result["subscription_plans"] = schema([]string{"id"}, map[string]fieldKind{
		"id": unsignedIDField, "group_id": unsignedIDField, "name": textField, "description": textField,
		"price_e8_usd": unsignedE8Field, "original_price_e8_usd": nullableTextField,
		"daily_limit_e8_usd": nullableTextField, "weekly_limit_e8_usd": nullableTextField,
		"monthly_limit_e8_usd": nullableTextField, "currency": textField, "validity_days": integerField,
		"validity_unit": textField, "features": textField, "product_name": textField, "for_sale": boolField,
		"sort_order": integerField, "version": integerField, "created_at": timestampField,
		"updated_at": timestampField, "deleted_at": nullableTimestampField,
	})
	result["user_subscriptions"] = schema([]string{"id"}, map[string]fieldKind{
		"id": unsignedIDField, "user_id": unsignedIDField, "group_id": unsignedIDField,
		"plan_id": nullableTextField, "starts_at": timestampField, "expires_at": timestampField,
		"status": textField, "initial_daily_boundary": nullableTimestampField,
		"daily_window_start": nullableTimestampField, "weekly_window_start": nullableTimestampField,
		"monthly_window_start": nullableTimestampField, "weekly_anchor_kind": nullableTextField,
		"monthly_anchor_kind": nullableTextField, "daily_limit_e8_usd": nullableTextField,
		"weekly_limit_e8_usd": nullableTextField, "monthly_limit_e8_usd": nullableTextField,
		"daily_usage_e8_usd": unsignedE8Field, "weekly_usage_e8_usd": unsignedE8Field,
		"monthly_usage_e8_usd": unsignedE8Field, "assigned_by": nullableTextField,
		"assigned_at": timestampField, "notes": textField, "version": integerField,
		"created_at": timestampField, "updated_at": timestampField, "deleted_at": nullableTimestampField,
	})
	return result
}

func RestoreCoverageMatrix() []CoverageSpec {
	result := make([]CoverageSpec, len(CoverageMatrix))
	copy(result, CoverageMatrix)
	for index := range result {
		spec := &result[index]
		switch spec.SourceTable {
		case "groups":
			spec.Rule = "canonical group fields and exact decimal rate_multiplier are copied; unsupported policy fields must equal declared safe defaults"
		case "subscription_plans":
			spec.Classification = Transformed
			spec.TargetTables = []string{"subscription_plans"}
			spec.Rule = "copy every legacy plan field; convert money exactly to E8 and initialize only canonical version/deletion defaults"
		case "user_subscriptions":
			spec.Classification = Transformed
			spec.TargetTables = []string{"user_subscriptions"}
			spec.Rule = "copy every legacy subscription field; convert usage exactly to E8 and derive only explicit legacy anchor provenance"
		case "settings":
			spec.Rule = "nonempty legacy plaintext settings block: the 0015 target requires purpose-bound encrypted envelopes and cannot be inferred"
		case "payment_orders", "payment_audit_logs":
			spec.Rule = "nonempty legacy payment state blocks: the 0016 authority and immutable witnesses are not equivalent and cannot be invented"
		}
	}
	return result
}

func restoreCoverageSpec(table string) (CoverageSpec, bool) {
	for _, spec := range RestoreCoverageMatrix() {
		if spec.SourceTable == table {
			return spec, true
		}
	}
	return CoverageSpec{}, false
}

func DecodeRestoreBundle(input []byte) (RestoreBundle, error) {
	if len(input) == 0 || len(input) > MaxBundleBytes {
		return RestoreBundle{}, errors.New("restore bundle is empty or exceeds size bound")
	}
	if err := rejectDuplicateKeys(input); err != nil {
		return RestoreBundle{}, err
	}
	var bundle RestoreBundle
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return RestoreBundle{}, fmt.Errorf("decode restore bundle: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return RestoreBundle{}, err
	}
	return bundle, nil
}

func CanonicalizeRestore(manifest RestoreManifest) (RestoreManifest, error) {
	return canonicalizeRestoreWith(manifest, RestoreFormatVersion, RestoreTargetSchemaVersion, RestoreMappingProfileVersion, CanonicalTargetMigrations, CanonicalOperationalInitialization, "0001-0017")
}

func CanonicalizeRestore0018(manifest RestoreManifest) (RestoreManifest, error) {
	return canonicalizeRestoreWith(manifest, Restore0018FormatVersion, Restore0018TargetSchemaVersion, Restore0018MappingProfileVersion, CanonicalTargetMigrations0018, CanonicalOperationalInitialization0018, "0001-0018")
}

func canonicalizeRestoreWith(manifest RestoreManifest, formatVersion, targetSchemaVersion, mappingProfileVersion string, migrations []MigrationFingerprint, operationalInitialization []OperationalInitialization, label string) (RestoreManifest, error) {
	if manifest.Format != formatVersion || manifest.TargetSchema != targetSchemaVersion || manifest.MappingProfile != mappingProfileVersion {
		return RestoreManifest{}, errors.New("unsupported restore format, target schema, or mapping profile")
	}
	if err := validateSource(manifest.Source); err != nil {
		return RestoreManifest{}, err
	}
	if len(manifest.Blockers) != 0 {
		return RestoreManifest{}, fmt.Errorf("restore manifest contains blocking items: %s", strings.Join(manifest.Blockers, "; "))
	}
	if !equalStrings(manifest.DependencyOrder, RestoreTableOrder) {
		return RestoreManifest{}, errors.New("restore dependency_order does not match canonical order")
	}
	if !equalMigrationFingerprints(manifest.TargetMigrations, migrations) {
		return RestoreManifest{}, fmt.Errorf("restore target migration manifest does not match canonical %s", label)
	}
	if !equalOperationalInitialization(manifest.OperationalInitialization, operationalInitialization) {
		return RestoreManifest{}, errors.New("restore operational initialization manifest is incomplete or non-canonical")
	}
	if manifest.Warnings == nil {
		manifest.Warnings = []string{}
	}
	if manifest.Blockers == nil {
		manifest.Blockers = []string{}
	}
	sort.Strings(manifest.Warnings)
	for index, warning := range manifest.Warnings {
		if warning == "" || len(warning) > 4<<10 || containsControl(warning) || index > 0 && warning == manifest.Warnings[index-1] {
			return RestoreManifest{}, errors.New("restore warnings are empty, duplicate, oversized, or unsafe")
		}
	}
	if err := validateRestoreCoverage(manifest.Coverage); err != nil {
		return RestoreManifest{}, err
	}
	sort.Slice(manifest.Coverage, func(i, j int) bool { return manifest.Coverage[i].SourceTable < manifest.Coverage[j].SourceTable })

	byTable := make(map[string][]TableChunk, len(RestoreTableOrder))
	seenChunks := map[string]bool{}
	totalRows := 0
	for _, chunk := range manifest.Tables {
		if _, ok := restoreSchemas[chunk.Table]; !ok {
			return RestoreManifest{}, fmt.Errorf("unknown restore target table %q", chunk.Table)
		}
		if seenChunks[chunk.ID] {
			return RestoreManifest{}, fmt.Errorf("duplicate restore chunk id %q", chunk.ID)
		}
		seenChunks[chunk.ID] = true
		validated, err := validateRestoreChunk(chunk)
		if err != nil {
			return RestoreManifest{}, err
		}
		byTable[chunk.Table] = append(byTable[chunk.Table], validated)
		totalRows += len(validated.Rows)
		if totalRows > MaxRows {
			return RestoreManifest{}, errors.New("restore manifest exceeds total row bound")
		}
	}
	manifest.Tables = nil
	for _, table := range RestoreTableOrder {
		chunks := byTable[table]
		if len(chunks) == 0 {
			return RestoreManifest{}, fmt.Errorf("missing restore target table chunk %q", table)
		}
		sort.Slice(chunks, func(i, j int) bool { return chunks[i].ID < chunks[j].ID })
		previous := ""
		seenRows := map[string]bool{}
		for index, chunk := range chunks {
			if chunk.ID != fmt.Sprintf("%s/%06d", table, index+1) {
				return RestoreManifest{}, fmt.Errorf("restore table %q has non-contiguous chunk ids", table)
			}
			for _, row := range chunk.Rows {
				identity, _ := restoreRowIdentity(table, row)
				if seenRows[identity] || previous != "" && identity <= previous {
					return RestoreManifest{}, fmt.Errorf("restore table %q has duplicate or unordered primary keys", table)
				}
				seenRows[identity] = true
				previous = identity
			}
			manifest.Tables = append(manifest.Tables, chunk)
		}
	}
	if err := validateRestoreRelations(manifest.Tables); err != nil {
		return RestoreManifest{}, err
	}
	if err := validateRestoreCoverageCounts(manifest.Coverage, manifest.Tables); err != nil {
		return RestoreManifest{}, err
	}
	return manifest, nil
}

func equalMigrationFingerprints(left, right []MigrationFingerprint) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] || validateLowerSHA256(left[index].SHA256) != nil {
			return false
		}
	}
	return true
}

func equalOperationalInitialization(left, right []OperationalInitialization) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateRestoreCoverage(records []CoverageRecord) error {
	matrix := RestoreCoverageMatrix()
	seen := map[string]bool{}
	for _, record := range records {
		if !sourceIdentifier(record.SourceTable) || record.Rule == "" || containsControl(record.Rule) || seen[record.SourceTable] {
			return fmt.Errorf("restore coverage %q is duplicate or unsafe", record.SourceTable)
		}
		seen[record.SourceTable] = true
		if _, err := parseBoundedCount(record.SourceRowCount, MaxRows); err != nil || validateLowerSHA256(record.SourceSHA256) != nil {
			return fmt.Errorf("restore coverage %q has invalid count or digest", record.SourceTable)
		}
		if spec, ok := restoreCoverageSpec(record.SourceTable); ok {
			if record.Classification != spec.Classification || record.Rule != spec.Rule || !equalStrings(record.TargetTables, spec.TargetTables) {
				return fmt.Errorf("restore coverage %q does not match executable matrix", record.SourceTable)
			}
		} else if record.Classification != Blocked || record.SourceRowCount != "0" {
			return fmt.Errorf("unknown restore coverage %q must be explicitly blocked and empty", record.SourceTable)
		}
	}
	for _, spec := range matrix {
		if !seen[spec.SourceTable] {
			return fmt.Errorf("missing restore coverage record %q", spec.SourceTable)
		}
	}
	return nil
}

func NewRestoreTableChunks(table string, rows []json.RawMessage) ([]TableChunk, error) {
	if _, ok := restoreSchemas[table]; !ok {
		return nil, fmt.Errorf("unknown restore target table %q", table)
	}
	if len(rows) > MaxRowsPerTable {
		return nil, fmt.Errorf("restore target table %q exceeds row bound", table)
	}
	if rows == nil {
		rows = []json.RawMessage{}
	}
	canonical := make([]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		validated, _, err := validateRestoreRow(table, row)
		if err != nil {
			return nil, err
		}
		canonical = append(canonical, validated)
	}
	sort.Slice(canonical, func(i, j int) bool {
		left, _ := restoreRowIdentity(table, canonical[i])
		right, _ := restoreRowIdentity(table, canonical[j])
		return left < right
	})
	chunks := []TableChunk{}
	for start := 0; start < len(canonical); {
		end, size := start, 0
		for end < len(canonical) && end-start < MaxRowsPerChunk {
			rowSize := len(canonical[end]) + 8
			if rowSize > MaxChunkBytes {
				return nil, fmt.Errorf("restore target table %q contains an oversized row", table)
			}
			if end > start && size+rowSize > MaxChunkBytes {
				break
			}
			size += rowSize
			end++
		}
		rowsCopy := append([]json.RawMessage(nil), canonical[start:end]...)
		digest, _ := DigestRows(rowsCopy)
		chunks = append(chunks, TableChunk{Table: table, ID: fmt.Sprintf("%s/%06d", table, len(chunks)+1), RowCount: strconv.Itoa(len(rowsCopy)), SHA256: digest, Rows: rowsCopy})
		start = end
	}
	if len(chunks) == 0 {
		chunks = append(chunks, TableChunk{Table: table, ID: table + "/000001", RowCount: "0", SHA256: emptyDigest(), Rows: []json.RawMessage{}})
	}
	return chunks, nil
}

func validateRestoreChunk(chunk TableChunk) (TableChunk, error) {
	count, err := parseBoundedCount(chunk.RowCount, MaxRowsPerChunk)
	if err != nil || count != len(chunk.Rows) || len(chunk.Rows) > MaxRowsPerChunk || validateLowerSHA256(chunk.SHA256) != nil {
		return TableChunk{}, fmt.Errorf("restore chunk %q has invalid count or digest", chunk.ID)
	}
	canonical := make([]json.RawMessage, 0, len(chunk.Rows))
	bytesUsed := 0
	for _, row := range chunk.Rows {
		validated, _, err := validateRestoreRow(chunk.Table, row)
		if err != nil {
			return TableChunk{}, err
		}
		bytesUsed += len(validated) + 8
		canonical = append(canonical, validated)
	}
	if bytesUsed > MaxChunkBytes {
		return TableChunk{}, fmt.Errorf("restore chunk %q exceeds byte bound", chunk.ID)
	}
	sort.Slice(canonical, func(i, j int) bool {
		left, _ := restoreRowIdentity(chunk.Table, canonical[i])
		right, _ := restoreRowIdentity(chunk.Table, canonical[j])
		return left < right
	})
	digest, _ := DigestRows(canonical)
	if digest != chunk.SHA256 {
		return TableChunk{}, fmt.Errorf("restore chunk %q sha256 mismatch", chunk.ID)
	}
	return TableChunk{Table: chunk.Table, ID: chunk.ID, RowCount: chunk.RowCount, SHA256: digest, Rows: canonical}, nil
}

func validateRestoreRow(table string, raw json.RawMessage) (json.RawMessage, string, error) {
	definition, ok := restoreSchemas[table]
	if !ok || len(raw) == 0 || len(raw) > MaxRowBytes || rejectDuplicateKeys(raw) != nil {
		return nil, "", fmt.Errorf("restore %s row is invalid", table)
	}
	var row map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&row); err != nil || row == nil || ensureEOF(decoder) != nil || len(row) != len(definition.fields) {
		return nil, "", fmt.Errorf("restore %s row has missing or unknown fields", table)
	}
	for name, value := range row {
		kind, exists := definition.fields[name]
		if !exists {
			return nil, "", fmt.Errorf("restore %s row has unknown field %q", table, name)
		}
		if err := validateField(table, name, kind, value); err != nil {
			return nil, "", err
		}
	}
	if err := validateRestoreSemanticFields(table, row); err != nil {
		return nil, "", err
	}
	canonical, err := CanonicalJSON(raw)
	if err != nil {
		return nil, "", err
	}
	identity, err := restoreRowIdentity(table, canonical)
	return canonical, identity, err
}

func validateRestoreSemanticFields(table string, row map[string]json.RawMessage) error {
	if table == "groups" {
		multiplier := jsonString(row["rate_multiplier_bps"])
		if multiplier == "0" || len(multiplier) > 8 {
			return errors.New("groups.rate_multiplier_bps is outside the canonical positive bound")
		}
		return nil
	}
	if table != "subscription_plans" && table != "user_subscriptions" {
		return nil
	}
	for _, field := range []string{"original_price_e8_usd", "daily_limit_e8_usd", "weekly_limit_e8_usd", "monthly_limit_e8_usd"} {
		raw, ok := row[field]
		if !ok || bytes.Equal(raw, []byte("null")) {
			continue
		}
		if err := validateE8(jsonString(raw), false); err != nil {
			return fmt.Errorf("%s.%s: %w", table, field, err)
		}
	}
	if table == "subscription_plans" {
		currency := jsonString(row["currency"])
		if len(currency) != 3 || strings.ToUpper(currency) != currency || jsonInteger(row["validity_days"]) < 1 || jsonInteger(row["validity_days"]) > 36500 || jsonString(row["validity_unit"]) != "day" || jsonInteger(row["version"]) != 1 {
			return errors.New("subscription_plans contains unsupported currency, validity, or initialized version")
		}
		return nil
	}
	if status := jsonString(row["status"]); status != "active" && status != "expired" && status != "suspended" {
		return errors.New("user_subscriptions.status is unsupported")
	}
	for _, field := range []string{"plan_id", "assigned_by"} {
		if !bytes.Equal(row[field], []byte("null")) && !canonicalUnsignedID(jsonString(row[field])) {
			return fmt.Errorf("user_subscriptions.%s is not a canonical unsigned identifier", field)
		}
	}
	for _, field := range []string{"weekly_anchor_kind", "monthly_anchor_kind"} {
		if bytes.Equal(row[field], []byte("null")) {
			continue
		}
		value := jsonString(row[field])
		if value != "activation" && value != "manual" && value != "legacy_initial" {
			return fmt.Errorf("user_subscriptions.%s is unsupported", field)
		}
	}
	if jsonInteger(row["version"]) != 1 {
		return errors.New("user_subscriptions.version must be initialized to 1")
	}
	return nil
}

func restoreRowIdentity(table string, raw json.RawMessage) (string, error) {
	var row map[string]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil {
		return "", err
	}
	parts := make([]string, 0, len(restoreSchemas[table].primaryKey))
	for _, key := range restoreSchemas[table].primaryKey {
		parts = append(parts, string(row[key]))
	}
	return strings.Join(parts, "\x1f"), nil
}

func validateRestoreRelations(chunks []TableChunk) error {
	rows := map[string][]map[string]json.RawMessage{}
	for _, chunk := range chunks {
		for _, raw := range chunk.Rows {
			var row map[string]json.RawMessage
			_ = json.Unmarshal(raw, &row)
			rows[chunk.Table] = append(rows[chunk.Table], row)
		}
	}
	ids := func(table, field string) map[string]bool {
		result := map[string]bool{}
		for _, row := range rows[table] {
			result[jsonString(row[field])] = true
		}
		return result
	}
	groups, users := ids("groups", "id"), ids("users", "id")
	plans, accounts := ids("subscription_plans", "id"), ids("accounts", "id")
	versions := ids("pricing_versions", "version_id")
	groupTypes := map[string]string{}
	liveGroups := map[string]bool{}
	for _, row := range rows["groups"] {
		id := jsonString(row["id"])
		groupTypes[id] = jsonString(row["subscription_type"])
		liveGroups[id] = bytes.Equal(row["deleted_at"], []byte("null"))
	}
	liveUsers := map[string]bool{}
	adminUsers := map[string]bool{}
	for _, row := range rows["users"] {
		id := jsonString(row["id"])
		liveUsers[id] = bytes.Equal(row["deleted_at"], []byte("null"))
		adminUsers[id] = liveUsers[id] && jsonString(row["role"]) == "admin"
	}
	planGroups := map[string]string{}
	for _, row := range rows["subscription_plans"] {
		groupID := jsonString(row["group_id"])
		if !groups[groupID] || !liveGroups[groupID] || groupTypes[groupID] != "subscription" {
			return errors.New("subscription_plans contains invalid references or initialized fields")
		}
		planGroups[jsonString(row["id"])] = groupID
	}
	liveSubscriptions := map[string]bool{}
	for _, row := range rows["user_subscriptions"] {
		userID, groupID := jsonString(row["user_id"]), jsonString(row["group_id"])
		if !users[userID] || !liveUsers[userID] || !groups[groupID] || !liveGroups[groupID] || groupTypes[groupID] != "subscription" {
			return errors.New("user_subscriptions contains invalid references or version")
		}
		if !bytes.Equal(row["plan_id"], []byte("null")) {
			planID := jsonString(row["plan_id"])
			if !plans[planID] || planGroups[planID] != groupID {
				return errors.New("user_subscriptions contains a missing or mismatched plan")
			}
		}
		if !bytes.Equal(row["assigned_by"], []byte("null")) && !adminUsers[jsonString(row["assigned_by"])] {
			return errors.New("user_subscriptions contains a missing or non-admin assigner")
		}
		startsAt, startsErr := time.Parse(time.RFC3339Nano, jsonString(row["starts_at"]))
		expiresAt, expiresErr := time.Parse(time.RFC3339Nano, jsonString(row["expires_at"]))
		if startsErr != nil || expiresErr != nil || !startsAt.Before(expiresAt) {
			return errors.New("user_subscriptions has an invalid active interval")
		}
		for window, anchor := range map[string]string{"weekly_window_start": "weekly_anchor_kind", "monthly_window_start": "monthly_anchor_kind"} {
			if bytes.Equal(row[window], []byte("null")) != bytes.Equal(row[anchor], []byte("null")) {
				return errors.New("user_subscriptions has inconsistent window anchor provenance")
			}
		}
		if bytes.Equal(row["deleted_at"], []byte("null")) {
			key := userID + "\x00" + groupID
			if liveSubscriptions[key] {
				return errors.New("user_subscriptions contains duplicate live user/group state")
			}
			liveSubscriptions[key] = true
		}
	}
	for _, row := range rows["account_groups"] {
		if !accounts[jsonString(row["account_id"])] || !groups[jsonString(row["group_id"])] {
			return errors.New("account_groups contains a missing reference")
		}
	}
	for _, row := range rows["api_keys"] {
		if !users[jsonString(row["user_id"])] || !groups[jsonString(row["group_id"])] {
			return errors.New("api_keys contains a missing reference")
		}
	}
	for _, row := range rows["pricing_rules"] {
		if !versions[jsonString(row["version_id"])] {
			return errors.New("pricing_rules contains a missing version")
		}
	}
	for _, row := range rows["pricing_active_version"] {
		if !versions[jsonString(row["version_id"])] {
			return errors.New("pricing_active_version contains a missing version")
		}
	}
	return nil
}

func validateRestoreCoverageCounts(coverage []CoverageRecord, chunks []TableChunk) error {
	targetCounts := map[string]int{}
	for _, chunk := range chunks {
		targetCounts[chunk.Table] += len(chunk.Rows)
	}
	sourceCounts := map[string]int{}
	for _, record := range coverage {
		count, _ := parseBoundedCount(record.SourceRowCount, MaxRows)
		sourceCounts[record.SourceTable] = count
	}
	for _, table := range RestoreTableOrder {
		if sourceCounts[table] != targetCounts[table] {
			return fmt.Errorf("restore coverage count for %q does not match target rows", table)
		}
	}
	return nil
}

var restoreLegacySourceColumns = func() map[string][]string {
	result := make(map[string][]string, len(legacySourceColumns)+2)
	for table, columns := range legacySourceColumns {
		result[table] = append([]string(nil), columns...)
	}
	result["subscription_plans"] = []string{
		"id", "group_id", "name", "description", "price", "original_price", "currency",
		"validity_days", "validity_unit", "features", "product_name", "for_sale", "sort_order",
		"created_at", "updated_at",
	}
	result["user_subscriptions"] = []string{
		"id", "created_at", "updated_at", "deleted_at", "starts_at", "expires_at", "status",
		"daily_window_start", "weekly_window_start", "monthly_window_start", "daily_usage_usd",
		"weekly_usage_usd", "monthly_usage_usd", "assigned_at", "notes", "group_id", "user_id", "assigned_by",
	}
	return result
}()

func restoreExpectedPostgreSQLColumns(table string) ([]string, bool) {
	if columns, ok := restoreLegacySourceColumns[table]; ok {
		return append([]string(nil), columns...), true
	}
	if _, ok := restoreSchemas[table]; ok {
		columns := make([]string, 0, len(restoreSchemas[table].fields))
		for column := range restoreSchemas[table].fields {
			columns = append(columns, column)
		}
		return columns, true
	}
	return nil, false
}

func TransformLegacyRow0017(table string, raw json.RawMessage, credentials CredentialTransformer) (json.RawMessage, error) {
	if table != "groups" && table != "subscription_plans" && table != "user_subscriptions" {
		return TransformLegacyRow(table, raw, credentials)
	}
	if len(raw) == 0 || len(raw) > MaxRowBytes || rejectDuplicateKeys(raw) != nil {
		return nil, fmt.Errorf("%s source row is empty, oversized, or invalid", table)
	}
	var row map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&row); err != nil || row == nil || ensureEOF(decoder) != nil {
		return nil, fmt.Errorf("%s source row must be one JSON object", table)
	}
	var transformed map[string]any
	var err error
	switch table {
	case "groups":
		transformed, err = transformLegacyGroup0017(row)
	case "subscription_plans":
		transformed, err = transformLegacySubscriptionPlan(row)
	case "user_subscriptions":
		transformed, err = transformLegacyUserSubscription(row)
	}
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(transformed)
	if err != nil {
		return nil, err
	}
	canonical, _, err := validateRestoreRow(table, encoded)
	return canonical, err
}

func transformLegacyGroup0017(row map[string]json.RawMessage) (map[string]any, error) {
	if err := requireExactColumns("groups", row, restoreLegacySourceColumns["groups"]); err != nil {
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
	for field, expected := range map[string]string{"peak_rate_multiplier": "1", "image_rate_multiplier": "1", "batch_image_discount_multiplier": "0.5", "batch_image_hold_multiplier": "0.6", "video_rate_multiplier": "1", "profit_min_margin": "0", "profit_safety_buffer": "0"} {
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
	rate, err := legacyDecimalText(row["rate_multiplier"])
	if err != nil {
		return nil, errors.New("groups.rate_multiplier is invalid")
	}
	bps, err := decimalToBPS(rate)
	if err != nil {
		return nil, fmt.Errorf("groups.rate_multiplier: %w", err)
	}
	selected, err := normalizeRestoreSelected("groups", row, []string{"id", "name", "platform", "status", "is_exclusive", "subscription_type", "created_at", "updated_at", "deleted_at"})
	if err != nil {
		return nil, err
	}
	selected["rate_multiplier_bps"] = bps
	return selected, nil
}

func decimalToBPS(value string) (string, error) {
	ratio, ok := new(big.Rat).SetString(value)
	if !ok || ratio.Sign() <= 0 {
		return "", errors.New("multiplier must be a positive exact decimal")
	}
	ratio.Mul(ratio, big.NewRat(10_000, 1))
	if ratio.Denom().Cmp(big.NewInt(1)) != 0 || ratio.Num().BitLen() > 63 || len(ratio.Num().String()) > 8 {
		return "", errors.New("multiplier cannot be represented as canonical basis points")
	}
	return ratio.Num().String(), nil
}

func transformLegacySubscriptionPlan(row map[string]json.RawMessage) (map[string]any, error) {
	if err := requireExactColumns("subscription_plans", row, restoreLegacySourceColumns["subscription_plans"]); err != nil {
		return nil, err
	}
	selected, err := normalizeRestoreSelected("subscription_plans", row, []string{"id", "group_id", "name", "description", "currency", "validity_days", "validity_unit", "features", "product_name", "for_sale", "sort_order", "created_at", "updated_at"})
	if err != nil {
		return nil, err
	}
	selected["price_e8_usd"], err = rawDecimalToE8(row["price"])
	if err != nil {
		return nil, fmt.Errorf("subscription_plans.price: %w", err)
	}
	selected["original_price_e8_usd"], err = nullableDecimalToE8(row["original_price"])
	if err != nil {
		return nil, fmt.Errorf("subscription_plans.original_price: %w", err)
	}
	selected["daily_limit_e8_usd"] = nil
	selected["weekly_limit_e8_usd"] = nil
	selected["monthly_limit_e8_usd"] = nil
	selected["version"] = int64(1)
	selected["deleted_at"] = nil
	return selected, nil
}

func transformLegacyUserSubscription(row map[string]json.RawMessage) (map[string]any, error) {
	if err := requireExactColumns("user_subscriptions", row, restoreLegacySourceColumns["user_subscriptions"]); err != nil {
		return nil, err
	}
	selected, err := normalizeRestoreSelected("user_subscriptions", row, []string{"id", "user_id", "group_id", "starts_at", "expires_at", "status", "daily_window_start", "weekly_window_start", "monthly_window_start", "assigned_at", "created_at", "updated_at", "deleted_at"})
	if err != nil {
		return nil, err
	}
	if isNull(row["assigned_by"]) {
		selected["assigned_by"] = nil
	} else {
		selected["assigned_by"], err = normalizeLegacyTargetField(unsignedIDField, row["assigned_by"])
		if err != nil {
			return nil, fmt.Errorf("user_subscriptions.assigned_by: %w", err)
		}
	}
	for source, target := range map[string]string{"daily_usage_usd": "daily_usage_e8_usd", "weekly_usage_usd": "weekly_usage_e8_usd", "monthly_usage_usd": "monthly_usage_e8_usd"} {
		selected[target], err = rawDecimalToE8(row[source])
		if err != nil {
			return nil, fmt.Errorf("user_subscriptions.%s: %w", source, err)
		}
	}
	notes := ""
	if !isNull(row["notes"]) {
		notes, err = legacyString(row["notes"])
		if err != nil {
			return nil, errors.New("user_subscriptions.notes is invalid")
		}
	}
	selected["notes"] = notes
	selected["plan_id"] = nil
	selected["initial_daily_boundary"] = nil
	selected["daily_limit_e8_usd"] = nil
	selected["weekly_limit_e8_usd"] = nil
	selected["monthly_limit_e8_usd"] = nil
	selected["weekly_anchor_kind"] = anchorForLegacyWindow(selected["weekly_window_start"])
	selected["monthly_anchor_kind"] = anchorForLegacyWindow(selected["monthly_window_start"])
	selected["version"] = int64(1)
	return selected, nil
}

func anchorForLegacyWindow(value any) any {
	if value == nil {
		return nil
	}
	return "legacy_initial"
}

func nullableDecimalToE8(raw json.RawMessage) (any, error) {
	if isNull(raw) {
		return nil, nil
	}
	return rawDecimalToE8(raw)
}

func normalizeRestoreSelected(table string, row map[string]json.RawMessage, fields []string) (map[string]any, error) {
	result := make(map[string]any, len(fields))
	for _, field := range fields {
		kind, ok := restoreSchemas[table].fields[field]
		if !ok {
			return nil, fmt.Errorf("%s.%s is not in restore schema", table, field)
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

func ExportPostgreSQLRestoreSnapshot(ctx context.Context, database *sql.DB, output io.Writer, options PostgreSQLSnapshotOptions) error {
	return exportPostgreSQLRestoreSnapshotWith(ctx, database, output, options, RestoreSourceFormatVersion, RestoreMappingProfileVersion)
}

func ExportPostgreSQLRestoreSnapshot0018(ctx context.Context, database *sql.DB, output io.Writer, options PostgreSQLSnapshotOptions) error {
	return exportPostgreSQLRestoreSnapshotWith(ctx, database, output, options, Restore0018SourceFormatVersion, Restore0018MappingProfileVersion)
}

func exportPostgreSQLRestoreSnapshotWith(ctx context.Context, database *sql.DB, output io.Writer, options PostgreSQLSnapshotOptions, sourceFormatVersion, mappingProfileVersion string) error {
	if database == nil || output == nil {
		return errors.New("PostgreSQL database and restore snapshot writer are required")
	}
	schemaName := options.Schema
	if schemaName == "" {
		schemaName = "public"
	}
	if !sourceIdentifier(schemaName) {
		return errors.New("PostgreSQL restore schema name is unsafe")
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return errors.New("begin PostgreSQL restore snapshot failed")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, PostgreSQLReadOnlyTransaction); err != nil {
		return errors.New("enforce PostgreSQL restore read-only transaction failed")
	}
	var isolation, readOnly string
	if err := tx.QueryRowContext(ctx, "SELECT current_setting('transaction_isolation'), current_setting('transaction_read_only')").Scan(&isolation, &readOnly); err != nil || isolation != "repeatable read" || readOnly != "on" {
		return errors.New("PostgreSQL did not confirm restore snapshot isolation")
	}
	var snapshotID, serverVersion string
	var capturedAt time.Time
	if err := tx.QueryRowContext(ctx, "SELECT txid_current_snapshot()::text, current_setting('server_version_num'), transaction_timestamp()").Scan(&snapshotID, &serverVersion, &capturedAt); err != nil {
		return errors.New("read PostgreSQL restore fingerprint failed")
	}
	migrationRows, err := readMigrationFingerprint(ctx, tx, schemaName)
	if err != nil {
		return err
	}
	migrationDigest, err := DigestRows(migrationRows)
	if err != nil {
		return errors.New("compute PostgreSQL restore migration fingerprint failed")
	}
	header := sourceHeader{Type: "source", Format: sourceFormatVersion, MappingProfile: mappingProfileVersion,
		SnapshotID: snapshotID, SchemaName: schemaName, ServerVersion: serverVersion,
		MigrationCount: strconv.Itoa(len(migrationRows)), MigrationSHA256: migrationDigest,
		CapturedAt: capturedAt.UTC().Format(time.RFC3339Nano), Complete: true}
	if err := validateRestoreSourceHeaderWith(header, sourceFormatVersion, mappingProfileVersion); err != nil {
		return err
	}
	inventory, err := readPostgreSQLInventory(ctx, tx, schemaName)
	if err != nil {
		return err
	}
	columns, err := readPostgreSQLColumnInventory(ctx, tx, schemaName, inventory)
	if err != nil {
		return err
	}
	if err := validateRestorePostgreSQLColumns(inventory, columns); err != nil {
		return err
	}
	allTables := map[string]bool{}
	for _, spec := range RestoreCoverageMatrix() {
		allTables[spec.SourceTable] = true
	}
	for table := range inventory {
		allTables[table] = true
	}
	ordered := make([]string, 0, len(allTables))
	for table := range allTables {
		ordered = append(ordered, table)
	}
	sort.Strings(ordered)
	writer := &boundedSnapshotWriter{writer: output, maximum: MaxSnapshotBytes}
	if err := writeJSONLine(writer, header); err != nil {
		return err
	}
	summaries := make([]snapshotTableSummary, 0, len(ordered))
	totalRows := 0
	for _, table := range ordered {
		present := inventory[table]
		presentCopy := present
		if err := writeJSONLine(writer, sourceTableStart{Type: "table", Table: table, Present: &presentCopy}); err != nil {
			return err
		}
		count, digest, err := exportRestorePostgreSQLTable(ctx, tx, schemaName, table, present, options.Credentials, writer)
		if err != nil {
			return err
		}
		totalRows += count
		if totalRows > MaxRows {
			return errors.New("restore snapshot exceeds total row bound")
		}
		summary := snapshotTableSummary{Table: table, Present: present, RowCount: strconv.Itoa(count), SHA256: digest}
		summaries = append(summaries, summary)
		if err := writeJSONLine(writer, sourceTableEnd{Type: "table_end", Table: table, RowCount: summary.RowCount, SHA256: summary.SHA256}); err != nil {
			return err
		}
	}
	snapshotSHA, err := snapshotDigest(header, summaries)
	if err != nil {
		return err
	}
	if err := writeJSONLine(writer, sourceSnapshotEnd{Type: "snapshot_end", TableCount: strconv.Itoa(len(summaries)), RowCount: strconv.Itoa(totalRows), SHA256: snapshotSHA}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("commit PostgreSQL restore read-only snapshot failed")
	}
	return nil
}

func validateRestorePostgreSQLColumns(inventory map[string]bool, columns map[string][]string) error {
	for _, spec := range RestoreCoverageMatrix() {
		if spec.Classification != Transformed || !inventory[spec.SourceTable] {
			continue
		}
		expected, ok := restoreExpectedPostgreSQLColumns(spec.SourceTable)
		if !ok {
			return fmt.Errorf("restore source table %q has no pinned column contract", spec.SourceTable)
		}
		actual := append([]string(nil), columns[spec.SourceTable]...)
		sort.Strings(expected)
		sort.Strings(actual)
		if !equalStrings(expected, actual) {
			return fmt.Errorf("restore source table %q columns differ from %s", spec.SourceTable, RestoreMappingProfileVersion)
		}
	}
	return nil
}

func exportRestorePostgreSQLTable(ctx context.Context, tx *sql.Tx, schemaName, table string, present bool, credentials CredentialTransformer, output io.Writer) (int, string, error) {
	accumulator := newStreamingRowDigest()
	if !present {
		return 0, accumulator.sum(), nil
	}
	spec, known := restoreCoverageSpec(table)
	if !known || spec.Classification != Transformed {
		var count int
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s.%s", quoteIdentifier(schemaName), quoteIdentifier(table))
		if err := tx.QueryRowContext(ctx, query).Scan(&count); err != nil {
			return 0, "", fmt.Errorf("count restore source table %q failed", table)
		}
		if count != 0 {
			if !known {
				return 0, "", fmt.Errorf("unknown restore source table %q is nonempty", table)
			}
			return 0, "", fmt.Errorf("%s restore source table %q is nonempty", spec.Classification, table)
		}
		return 0, accumulator.sum(), nil
	}
	order := postgreSQLRowOrder[table]
	if table == "subscription_plans" || table == "user_subscriptions" {
		order = `"id"`
	}
	if order == "" {
		return 0, "", fmt.Errorf("restore source table %q lacks deterministic row order", table)
	}
	query := fmt.Sprintf("SELECT row_to_json(source_row)::text FROM %s.%s AS source_row ORDER BY %s", quoteIdentifier(schemaName), quoteIdentifier(table), order)
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return 0, "", fmt.Errorf("read restore source table %q failed", table)
	}
	defer func() { _ = rows.Close() }()
	count := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return 0, "", fmt.Errorf("scan restore source table %q failed", table)
		}
		transformed, err := TransformLegacyRow0017(table, raw, credentials)
		if err != nil {
			return 0, "", fmt.Errorf("transform restore source table %q row %d: %w", table, count+1, err)
		}
		accumulator.add(transformed)
		if err := writeJSONLine(output, sourceRow{Type: "row", Table: table, Row: transformed}); err != nil {
			return 0, "", err
		}
		count++
		if count > MaxRowsPerTable {
			return 0, "", fmt.Errorf("restore source table %q exceeds row bound", table)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, "", fmt.Errorf("read restore source table %q failed", table)
	}
	return count, accumulator.sum(), nil
}

func validateRestoreSourceHeader(header sourceHeader) error {
	return validateRestoreSourceHeaderWith(header, RestoreSourceFormatVersion, RestoreMappingProfileVersion)
}

func validateRestoreSourceHeader0018(header sourceHeader) error {
	return validateRestoreSourceHeaderWith(header, Restore0018SourceFormatVersion, Restore0018MappingProfileVersion)
}

func validateRestoreSourceHeaderWith(header sourceHeader, sourceFormatVersion, mappingProfileVersion string) error {
	if header.Type != "source" || header.Format != sourceFormatVersion || header.MappingProfile != mappingProfileVersion || !header.Complete {
		return errors.New("restore source must declare the supported format, mapping profile, and complete_inventory=true")
	}
	if header.SnapshotID == "" || header.SchemaName == "" || header.ServerVersion == "" || containsControl(header.SnapshotID+header.SchemaName+header.ServerVersion) || !sourceIdentifier(header.SchemaName) {
		return errors.New("restore source fingerprint is incomplete or unsafe")
	}
	if _, err := parseBoundedCount(header.MigrationCount, MaxRows); err != nil || validateLowerSHA256(header.MigrationSHA256) != nil || !canonicalTimestamp(header.CapturedAt) {
		return errors.New("restore source migration fingerprint is invalid")
	}
	return nil
}

func ExportRestoreJSONL(reader io.Reader) (RestoreBundle, error) {
	return exportRestoreJSONLWith(reader, RestoreSourceFormatVersion, RestoreMappingProfileVersion, CanonicalizeRestore, CanonicalTargetMigrations, CanonicalOperationalInitialization, RestoreFormatVersion, RestoreTargetSchemaVersion)
}

func ExportRestoreJSONL0018(reader io.Reader) (RestoreBundle, error) {
	return exportRestoreJSONLWith(reader, Restore0018SourceFormatVersion, Restore0018MappingProfileVersion, CanonicalizeRestore0018, CanonicalTargetMigrations0018, CanonicalOperationalInitialization0018, Restore0018FormatVersion, Restore0018TargetSchemaVersion)
}

func exportRestoreJSONLWith(reader io.Reader, sourceFormatVersion, mappingProfileVersion string, canonicalize func(RestoreManifest) (RestoreManifest, error), migrations []MigrationFingerprint, operationalInitialization []OperationalInitialization, formatVersion, targetSchemaVersion string) (RestoreBundle, error) {
	if reader == nil {
		return RestoreBundle{}, errors.New("restore source JSONL reader is nil")
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
		if totalBytes > MaxSnapshotBytes || len(line) == 0 {
			return RestoreBundle{}, fmt.Errorf("restore source JSONL line %d is empty or exceeds bounds", lineNumber)
		}
		if finished {
			return RestoreBundle{}, errors.New("restore source has records after snapshot_end")
		}
		if err := rejectDuplicateKeys(line); err != nil {
			return RestoreBundle{}, fmt.Errorf("restore source line %d: %w", lineNumber, err)
		}
		var envelope struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(line, &envelope) != nil {
			return RestoreBundle{}, fmt.Errorf("restore source line %d is invalid JSON", lineNumber)
		}
		if lineNumber == 1 {
			if decodeStrict(line, &header) != nil || validateRestoreSourceHeaderWith(header, sourceFormatVersion, mappingProfileVersion) != nil {
				return RestoreBundle{}, errors.New("restore source header is unsupported or invalid")
			}
			continue
		}
		switch envelope.Type {
		case "table":
			var start sourceTableStart
			if active != nil || decodeStrict(line, &start) != nil || start.Present == nil || !sourceIdentifier(start.Table) || seen[start.Table] || lastTable != "" && start.Table <= lastTable {
				return RestoreBundle{}, errors.New("restore source table inventory is malformed or unordered")
			}
			seen[start.Table], lastTable, active = true, start.Table, &start
			activeRows = []json.RawMessage{}
		case "row":
			if active == nil || !*active.Present {
				return RestoreBundle{}, errors.New("restore source row occurs outside a present table")
			}
			var record sourceRow
			if decodeStrict(line, &record) != nil || record.Table != active.Table || len(record.Row) == 0 {
				return RestoreBundle{}, fmt.Errorf("restore source row for %q is malformed", active.Table)
			}
			spec, known := restoreCoverageSpec(active.Table)
			if !known || spec.Classification != Transformed {
				return RestoreBundle{}, fmt.Errorf("non-mapped restore source table %q is nonempty", active.Table)
			}
			canonical, err := CanonicalJSON(record.Row)
			if err != nil {
				return RestoreBundle{}, fmt.Errorf("restore source row for %q is invalid: %w", active.Table, err)
			}
			activeRows = append(activeRows, canonical)
			totalRows++
			if len(activeRows) > MaxRowsPerTable || totalRows > MaxRows {
				return RestoreBundle{}, errors.New("restore source row capacity exceeded")
			}
		case "table_end":
			var end sourceTableEnd
			if active == nil || decodeStrict(line, &end) != nil || end.Table != active.Table {
				return RestoreBundle{}, errors.New("restore source table_end is malformed")
			}
			count, err := parseBoundedCount(end.RowCount, MaxRowsPerTable)
			digest, digestErr := DigestRows(activeRows)
			if err != nil || count != len(activeRows) || validateLowerSHA256(end.SHA256) != nil || digestErr != nil || digest != end.SHA256 {
				return RestoreBundle{}, fmt.Errorf("restore source table %q count or digest mismatch", active.Table)
			}
			tables[active.Table] = append([]json.RawMessage(nil), activeRows...)
			present[active.Table] = *active.Present
			summaries = append(summaries, snapshotTableSummary{Table: active.Table, Present: *active.Present, RowCount: end.RowCount, SHA256: end.SHA256})
			active, activeRows = nil, nil
		case "snapshot_end":
			var end sourceSnapshotEnd
			if active != nil || decodeStrict(line, &end) != nil {
				return RestoreBundle{}, errors.New("restore snapshot_end is malformed")
			}
			tableCount, tableErr := parseBoundedCount(end.TableCount, len(RestoreCoverageMatrix())+10_000)
			rowCount, rowErr := parseBoundedCount(end.RowCount, MaxRows)
			digest, digestErr := snapshotDigest(header, summaries)
			if tableErr != nil || rowErr != nil || tableCount != len(summaries) || rowCount != totalRows || validateLowerSHA256(end.SHA256) != nil || digestErr != nil || digest != end.SHA256 {
				return RestoreBundle{}, errors.New("restore snapshot_end count or digest mismatch")
			}
			for _, spec := range RestoreCoverageMatrix() {
				if !seen[spec.SourceTable] {
					return RestoreBundle{}, fmt.Errorf("restore source inventory is incomplete: missing table %q", spec.SourceTable)
				}
			}
			finished, snapshotSHA = true, end.SHA256
		default:
			return RestoreBundle{}, fmt.Errorf("restore source line %d has unknown record type", lineNumber)
		}
	}
	if err := scanner.Err(); err != nil {
		return RestoreBundle{}, errors.New("restore source stream is unreadable or has an oversized line")
	}
	if lineNumber == 0 || !finished {
		return RestoreBundle{}, errors.New("restore source is empty, truncated, or missing snapshot_end")
	}
	return buildRestoreBundleWith(header, snapshotSHA, summaries, present, tables, canonicalize, migrations, operationalInitialization, formatVersion, targetSchemaVersion, mappingProfileVersion)
}

func buildRestoreBundle(header sourceHeader, snapshotSHA string, inventory []snapshotTableSummary, present map[string]bool, sourceRows map[string][]json.RawMessage) (RestoreBundle, error) {
	return buildRestoreBundleWith(header, snapshotSHA, inventory, present, sourceRows, CanonicalizeRestore, CanonicalTargetMigrations, CanonicalOperationalInitialization, RestoreFormatVersion, RestoreTargetSchemaVersion, RestoreMappingProfileVersion)
}

func buildRestoreBundleWith(header sourceHeader, snapshotSHA string, inventory []snapshotTableSummary, present map[string]bool, sourceRows map[string][]json.RawMessage, canonicalize func(RestoreManifest) (RestoreManifest, error), migrations []MigrationFingerprint, operationalInitialization []OperationalInitialization, formatVersion, targetSchemaVersion, mappingProfileVersion string) (RestoreBundle, error) {
	if err := validateSourceMigrationFingerprint(header, present, sourceRows); err != nil {
		return RestoreBundle{}, err
	}
	warnings := []string{}
	for _, item := range inventory {
		spec, known := restoreCoverageSpec(item.Table)
		if !known {
			warnings = append(warnings, "unknown empty source table explicitly blocked: "+item.Table)
			continue
		}
		if !present[item.Table] {
			warnings = append(warnings, "known source table absent and represented as empty: "+item.Table)
		}
		if spec.Classification != Transformed && len(sourceRows[item.Table]) != 0 {
			return RestoreBundle{}, fmt.Errorf("%s restore source table %q is nonempty", spec.Classification, item.Table)
		}
	}
	allowedGroups, err := transformAllowedGroups(sourceRows["user_allowed_groups"])
	if err != nil {
		return RestoreBundle{}, err
	}
	targetRows := make(map[string][]json.RawMessage, len(RestoreTableOrder))
	for _, table := range RestoreTableOrder {
		targetRows[table] = []json.RawMessage{}
	}
	mappings := []struct{ source, target string }{
		{"groups", "groups"}, {"users", "users"}, {"subscription_plans", "subscription_plans"},
		{"user_subscriptions", "user_subscriptions"}, {"pricing_versions", "pricing_versions"},
		{"pricing_rules", "pricing_rules"}, {"pricing_active_version", "pricing_active_version"},
		{"accounts", "accounts"}, {"account_groups", "account_groups"}, {"api_keys", "api_keys"},
		{"model_aliases", "model_aliases"}, {"balance_ledger", "balance_ledger"},
	}
	for _, mapping := range mappings {
		for _, row := range sourceRows[mapping.source] {
			converted, err := transformRestoreSourceRow(mapping.source, row, allowedGroups)
			if err != nil {
				return RestoreBundle{}, fmt.Errorf("transform restore %s row: %w", mapping.source, err)
			}
			targetRows[mapping.target] = append(targetRows[mapping.target], converted)
		}
	}
	coverage := make([]CoverageRecord, 0, len(inventory))
	for _, item := range inventory {
		rows := sourceRows[item.Table]
		digest, err := DigestRows(rows)
		if err != nil {
			return RestoreBundle{}, err
		}
		if spec, known := restoreCoverageSpec(item.Table); known {
			coverage = append(coverage, CoverageRecord{SourceTable: spec.SourceTable, Classification: spec.Classification,
				TargetTables: append([]string(nil), spec.TargetTables...), Rule: spec.Rule,
				SourceRowCount: strconv.Itoa(len(rows)), SourceSHA256: digest})
		} else {
			coverage = append(coverage, CoverageRecord{SourceTable: item.Table, Classification: Blocked,
				TargetTables: []string{}, Rule: "unknown empty table; no mapping", SourceRowCount: "0", SourceSHA256: digest})
		}
	}
	tables := []TableChunk{}
	for _, table := range RestoreTableOrder {
		chunks, err := NewRestoreTableChunks(table, targetRows[table])
		if err != nil {
			return RestoreBundle{}, err
		}
		tables = append(tables, chunks...)
	}
	manifest := RestoreManifest{Format: RestoreFormatVersion, TargetSchema: RestoreTargetSchemaVersion,
		MappingProfile: mappingProfileVersion,
		Source: SourceFingerprint{Engine: "postgresql-offline-export", SnapshotID: header.SnapshotID,
			SchemaName: header.SchemaName, ServerVersion: header.ServerVersion, MigrationCount: header.MigrationCount,
			MigrationSHA256: header.MigrationSHA256, SnapshotSHA256: snapshotSHA, CapturedAt: header.CapturedAt},
		Coverage: coverage, DependencyOrder: append([]string(nil), RestoreTableOrder...),
		TargetMigrations:          append([]MigrationFingerprint(nil), migrations...),
		OperationalInitialization: append([]OperationalInitialization(nil), operationalInitialization...),
		Warnings:                  warnings, Blockers: []string{}, Tables: tables}
	manifest.Format = formatVersion
	manifest.TargetSchema = targetSchemaVersion
	canonical, err := canonicalize(manifest)
	if err != nil {
		return RestoreBundle{}, fmt.Errorf("restore export failed canonical validation: %w", err)
	}
	return RestoreBundle{Manifest: canonical}, nil
}

func transformRestoreSourceRow(table string, raw json.RawMessage, allowedGroups map[string][]string) (json.RawMessage, error) {
	var row map[string]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil || row == nil {
		return nil, errors.New("restore row must be an object")
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
		row["allowed_group_ids_json"], _ = json.Marshal(string(allowed))
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		return nil, err
	}
	canonical, _, err := validateRestoreRow(table, encoded)
	return canonical, err
}

func UpgradeBundleToRestore(bundle Bundle) (RestoreBundle, error) {
	legacy, err := Canonicalize(bundle.Manifest)
	if err != nil {
		return RestoreBundle{}, fmt.Errorf("legacy bundle rejected: %w", err)
	}
	coverage := make([]CoverageRecord, len(legacy.Coverage))
	for index, record := range legacy.Coverage {
		spec, ok := restoreCoverageSpec(record.SourceTable)
		if !ok {
			coverage[index] = record
			continue
		}
		if (record.SourceTable == "subscription_plans" || record.SourceTable == "user_subscriptions") && record.SourceRowCount != "0" {
			return RestoreBundle{}, fmt.Errorf("legacy bundle cannot upgrade nonempty %s without source rows", record.SourceTable)
		}
		record.Classification = spec.Classification
		record.TargetTables = append([]string(nil), spec.TargetTables...)
		record.Rule = spec.Rule
		coverage[index] = record
	}
	tables := []TableChunk{}
	legacyRows := map[string][]json.RawMessage{}
	for _, chunk := range legacy.Tables {
		legacyRows[chunk.Table] = append(legacyRows[chunk.Table], chunk.Rows...)
	}
	for _, table := range RestoreTableOrder {
		rows := legacyRows[table]
		if table == "groups" {
			upgraded := make([]json.RawMessage, 0, len(rows))
			for _, raw := range rows {
				var row map[string]json.RawMessage
				if json.Unmarshal(raw, &row) != nil {
					return RestoreBundle{}, errors.New("legacy group row is invalid")
				}
				row["rate_multiplier_bps"] = json.RawMessage(`"10000"`)
				encoded, _ := json.Marshal(row)
				upgraded = append(upgraded, encoded)
			}
			rows = upgraded
		}
		chunks, err := NewRestoreTableChunks(table, rows)
		if err != nil {
			return RestoreBundle{}, fmt.Errorf("upgrade legacy table %s: %w", table, err)
		}
		tables = append(tables, chunks...)
	}
	warnings := append([]string(nil), legacy.Warnings...)
	warnings = append(warnings, "upgraded from canonical 0001-0008 bundle; subscription source tables were proven empty")
	manifest := RestoreManifest{Format: RestoreFormatVersion, TargetSchema: RestoreTargetSchemaVersion,
		MappingProfile: RestoreMappingProfileVersion, Source: legacy.Source, Coverage: coverage,
		DependencyOrder:           append([]string(nil), RestoreTableOrder...),
		TargetMigrations:          append([]MigrationFingerprint(nil), CanonicalTargetMigrations...),
		OperationalInitialization: append([]OperationalInitialization(nil), CanonicalOperationalInitialization...),
		Warnings:                  warnings, Blockers: []string{}, Tables: tables}
	canonical, err := CanonicalizeRestore(manifest)
	if err != nil {
		return RestoreBundle{}, err
	}
	return RestoreBundle{Manifest: canonical}, nil
}

func UpgradeRestoreBundleTo0018(bundle RestoreBundle) (RestoreBundle, error) {
	legacy, err := CanonicalizeRestore(bundle.Manifest)
	if err != nil {
		return RestoreBundle{}, fmt.Errorf("0017 restore bundle rejected: %w", err)
	}
	manifest := RestoreManifest{
		Format:                    Restore0018FormatVersion,
		TargetSchema:              Restore0018TargetSchemaVersion,
		MappingProfile:            Restore0018MappingProfileVersion,
		Source:                    legacy.Source,
		Coverage:                  append([]CoverageRecord(nil), legacy.Coverage...),
		DependencyOrder:           append([]string(nil), RestoreTableOrder...),
		TargetMigrations:          append([]MigrationFingerprint(nil), CanonicalTargetMigrations0018...),
		OperationalInitialization: append([]OperationalInitialization(nil), CanonicalOperationalInitialization0018...),
		Warnings:                  append([]string(nil), legacy.Warnings...),
		Blockers:                  []string{},
		Tables:                    append([]TableChunk(nil), legacy.Tables...),
	}
	manifest.Warnings = append(manifest.Warnings, "upgraded from canonical 0001-0017 restore bundle; auth session runtime state must start pristine")
	canonical, err := CanonicalizeRestore0018(manifest)
	if err != nil {
		return RestoreBundle{}, err
	}
	return RestoreBundle{Manifest: canonical}, nil
}

var restoreColumnOrder = func() map[string][]string {
	result := make(map[string][]string, len(targetColumnOrder)+2)
	for table, columns := range targetColumnOrder {
		result[table] = append([]string(nil), columns...)
	}
	result["groups"] = append(result["groups"], "rate_multiplier_bps")
	result["subscription_plans"] = []string{
		"id", "group_id", "name", "description", "price_e8_usd", "original_price_e8_usd",
		"daily_limit_e8_usd", "weekly_limit_e8_usd", "monthly_limit_e8_usd", "currency",
		"validity_days", "validity_unit", "features", "product_name", "for_sale", "sort_order",
		"version", "created_at", "updated_at", "deleted_at",
	}
	result["user_subscriptions"] = []string{
		"id", "user_id", "group_id", "plan_id", "starts_at", "expires_at", "status",
		"initial_daily_boundary", "daily_window_start", "weekly_window_start", "monthly_window_start",
		"weekly_anchor_kind", "monthly_anchor_kind", "daily_limit_e8_usd", "weekly_limit_e8_usd",
		"monthly_limit_e8_usd", "daily_usage_e8_usd", "weekly_usage_e8_usd", "monthly_usage_e8_usd",
		"assigned_by", "assigned_at", "notes", "version", "created_at", "updated_at", "deleted_at",
	}
	return result
}()

func BuildRestoreSQLPlan(manifest RestoreManifest) (SQLPlan, error) {
	return buildRestoreSQLPlanWith(manifest, CanonicalizeRestore, "0001-0017", "v4", "offline_migration/v4", []struct{ expression, label string }{
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_bridge_schema_version' AND "value"='2026-09-06.v1')`, "0001 bridge schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_e8_money_scale' AND "value"='8')`, "0008 E8 schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_billing_reservation_schema_version' AND "value"='2026-09-09.v3')`, "0009 billing schema"},
		{`EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='scheduler_account_runtime')`, "0010 scheduler schema"},
		{`EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='background_jobs')`, "0011 job schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_subscription_runtime_schema_version' AND "value"='2026-09-09.v1')`, "0012 subscription schema"},
		{`EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='oauth_refresh_attempts')`, "0013 OAuth schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_auth_cache_schema_version' AND "value"='2026-09-09.v4')`, "0014 auth cache schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_settings_runtime_schema_version' AND "value"='2026-09-10.v1')`, "0015 settings schema"},
		{`EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='payment_records')`, "0016 payment schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_email_runtime_schema_version' AND "value"='2026-09-10.v4')`, "0017 email schema"},
	})
}

func BuildRestoreSQLPlan0018(manifest RestoreManifest) (SQLPlan, error) {
	return buildRestoreSQLPlanWith(manifest, CanonicalizeRestore0018, "0001-0018", "v5", "offline_migration/v5", []struct{ expression, label string }{
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_bridge_schema_version' AND "value"='2026-09-06.v1')`, "0001 bridge schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_e8_money_scale' AND "value"='8')`, "0008 E8 schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_billing_reservation_schema_version' AND "value"='2026-09-09.v3')`, "0009 billing schema"},
		{`EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='scheduler_account_runtime')`, "0010 scheduler schema"},
		{`EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='background_jobs')`, "0011 job schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_subscription_runtime_schema_version' AND "value"='2026-09-09.v1')`, "0012 subscription schema"},
		{`EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='oauth_refresh_attempts')`, "0013 OAuth schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_auth_cache_schema_version' AND "value"='2026-09-09.v4')`, "0014 auth cache schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_settings_runtime_schema_version' AND "value"='2026-09-10.v1')`, "0015 settings schema"},
		{`EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='payment_records')`, "0016 payment schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_email_runtime_schema_version' AND "value"='2026-09-10.v4')`, "0017 email schema"},
		{`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_auth_sessions_schema_version' AND "value"='2026-09-10.v1')`, "0018 auth session schema"},
	})
}

func buildRestoreSQLPlanWith(manifest RestoreManifest, canonicalize func(RestoreManifest) (RestoreManifest, error), label, provenanceVersion, provenancePrefix string, schemaAssertions []struct{ expression, label string }) (SQLPlan, error) {
	canonical, err := canonicalize(manifest)
	if err != nil {
		return SQLPlan{}, err
	}
	bundleBytes, err := json.Marshal(RestoreBundle{Manifest: canonical})
	if err != nil {
		return SQLPlan{}, errors.New("encode canonical restore bundle")
	}
	digestBytes := sha256.Sum256(bundleBytes)
	bundleDigest := hex.EncodeToString(digestBytes[:])
	guardKey := provenancePrefix + "/assert/" + bundleDigest
	bundleKey := provenancePrefix + "/bundle"
	resume := fmt.Sprintf(`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"=%s AND "value"=%s)`, SQLLiteral(bundleKey), SQLLiteral(bundleDigest))
	var plan strings.Builder
	_, _ = fmt.Fprintf(&plan, "-- Generated offline restore plan for canonical D1 migrations %s.\n", label)
	_, _ = plan.WriteString("-- Local execution is transactional; remote whole-file atomicity is not assumed.\n")
	_, _ = plan.WriteString("PRAGMA defer_foreign_keys = ON;\n")
	for _, condition := range schemaAssertions {
		writeAssertion(&plan, guardKey, condition.expression, condition.label+" is installed")
	}
	for _, initialization := range canonical.OperationalInitialization {
		if initialization.Mode == "column-default:0" || initialization.Mode == "column-default:1" || initialization.Mode == "column-default:null" {
			continue
		}
		condition := fmt.Sprintf("(%s) OR NOT EXISTS(SELECT 1 FROM %s)", resume, quoteIdentifier(initialization.Entity))
		writeAssertion(&plan, guardKey, condition, initialization.Entity+" is pristine before first import or this is an identical replay")
	}
	tableCounts := map[string]int{}
	for _, chunk := range canonical.Tables {
		_, _ = fmt.Fprintf(&plan, "\n-- table %s; chunk %s\n", chunk.Table, chunk.ID)
		tableCounts[chunk.Table] += len(chunk.Rows)
		for _, raw := range chunk.Rows {
			rowSQL, identity, rowDigest, err := restoreRowPlanSQL(chunk.Table, raw, guardKey)
			if err != nil {
				return SQLPlan{}, err
			}
			_, _ = plan.WriteString(rowSQL)
			writeProvenance(&plan, guardKey, provenancePrefix+"/row/"+chunk.Table+"/"+identityDigest(identity), rowDigest)
		}
		writeProvenance(&plan, guardKey, provenancePrefix+"/chunk/"+chunk.ID, chunk.SHA256)
	}
	for _, table := range RestoreTableOrder {
		expected := strconv.Itoa(tableCounts[table])
		writeAssertion(&plan, guardKey, fmt.Sprintf("(SELECT COUNT(*) FROM %s)=%s", quoteIdentifier(table), expected), table+" exact row count")
	}
	writeAssertion(&plan, guardKey, "NOT EXISTS(SELECT 1 FROM pragma_foreign_key_check)", "foreign keys are valid")
	writeProvenance(&plan, guardKey, bundleKey, bundleDigest)

	var validation strings.Builder
	_, _ = fmt.Fprintf(&validation, "-- Read-only %s post-restore validation. Success returns no rows.\n", label)
	_, _ = validation.WriteString("SELECT 'foreign_key' AS failure, \"table\" AS subject, CAST(rowid AS TEXT) AS actual, parent AS expected FROM pragma_foreign_key_check;\n")
	_, _ = validation.WriteString("SELECT 'quick_check' AS failure, 'database' AS subject, quick_check AS actual, 'ok' AS expected FROM pragma_quick_check WHERE quick_check <> 'ok';\n")
	for _, table := range RestoreTableOrder {
		expected := strconv.Itoa(tableCounts[table])
		_, _ = fmt.Fprintf(&validation, "SELECT 'row_count' AS failure, %s AS subject, CAST(COUNT(*) AS TEXT) AS actual, %s AS expected FROM %s HAVING COUNT(*) <> %s;\n", SQLLiteral(table), SQLLiteral(expected), quoteIdentifier(table), expected)
	}
	_, _ = fmt.Fprintf(&validation, "SELECT 'bundle_digest' AS failure, %s AS subject, COALESCE((SELECT \"value\" FROM \"schema_metadata\" WHERE \"key\"=%s),'missing') AS actual, %s AS expected WHERE COALESCE((SELECT \"value\" FROM \"schema_metadata\" WHERE \"key\"=%s),'missing') <> %s;\n", SQLLiteral(bundleKey), SQLLiteral(bundleKey), SQLLiteral(bundleDigest), SQLLiteral(bundleKey), SQLLiteral(bundleDigest))
	_, _ = fmt.Fprintf(&validation, "SELECT 'assertion_guard' AS failure, \"key\" AS subject, \"value\" AS actual, 'absent' AS expected FROM \"schema_metadata\" WHERE \"key\" LIKE 'offline_migration/%s/assert/%%';\n", provenanceVersion)
	return SQLPlan{BundleDigest: bundleDigest, SQL: plan.String(), ValidationSQL: validation.String()}, nil
}

func restoreRowPlanSQL(table string, raw json.RawMessage, guardKey string) (string, string, string, error) {
	canonical, identity, err := validateRestoreRow(table, raw)
	if err != nil {
		return "", "", "", err
	}
	var row map[string]json.RawMessage
	if json.Unmarshal(canonical, &row) != nil {
		return "", "", "", errors.New("decode canonical restore row")
	}
	columns := restoreColumnOrder[table]
	values, equality := make([]string, len(columns)), make([]string, len(columns))
	for index, column := range columns {
		value, err := sqlValue(row[column])
		if err != nil {
			return "", "", "", fmt.Errorf("restore %s.%s: %w", table, column, err)
		}
		values[index] = value
		equality[index] = quoteIdentifier(column) + " IS " + value
	}
	primary := make([]string, len(restoreSchemas[table].primaryKey))
	for index, column := range restoreSchemas[table].primaryKey {
		value, err := sqlValue(row[column])
		if err != nil {
			return "", "", "", err
		}
		primary[index] = quoteIdentifier(column) + " IS " + value
	}
	var result strings.Builder
	_, _ = fmt.Fprintf(&result, "INSERT INTO %s(%s) SELECT %s WHERE NOT EXISTS(SELECT 1 FROM %s WHERE %s);\n",
		quoteIdentifier(table), strings.Join(quoteIdentifiers(columns), ","), strings.Join(values, ","),
		quoteIdentifier(table), strings.Join(primary, " AND "))
	writeAssertion(&result, guardKey, "EXISTS(SELECT 1 FROM "+quoteIdentifier(table)+" WHERE "+strings.Join(equality, " AND ")+")", table+" row "+identity+" is identical")
	hash := sha256.Sum256(canonical)
	return result.String(), identity, hex.EncodeToString(hash[:]), nil
}
