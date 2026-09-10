package cloudflaremigration

import (
	"bytes"
	"crypto/sha256"
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
	if name == "status" && text != "active" && text != "disabled" {
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
