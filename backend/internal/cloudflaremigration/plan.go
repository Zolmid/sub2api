package cloudflaremigration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const RemoteAcknowledgement = "I_HAVE_VERIFIED_A_D1_EXPORT_AND_ACCEPT_OPERATOR_OWNED_REMOTE_EXECUTION"

type SQLPlan struct {
	BundleDigest  string `json:"bundle_digest"`
	SQL           string `json:"sql"`
	ValidationSQL string `json:"validation_sql"`
}

type RemotePlan struct {
	WorkingDirectory   string   `json:"working_directory"`
	WranglerVersion    string   `json:"wrangler_version"`
	BackupArgs         []string `json:"backup_args"`
	ImportArgs         []string `json:"import_args"`
	ValidateArgs       []string `json:"validate_args"`
	TimeTravelInfoArgs []string `json:"time_travel_info_args"`
	RestoreArgsPrefix  []string `json:"restore_args_prefix"`
}

var remoteDatabaseName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

var targetColumnOrder = map[string][]string{
	"groups":                 {"id", "name", "platform", "status", "is_exclusive", "subscription_type", "created_at", "updated_at", "deleted_at"},
	"users":                  {"id", "status", "role", "concurrency", "balance_e8_usd", "allowed_group_ids_json", "restrict_public_groups", "created_at", "email", "password_hash", "username", "notes", "rpm_limit", "updated_at", "deleted_at", "totp_secret_envelope", "totp_enabled", "totp_enabled_at", "totp_revision"},
	"pricing_versions":       {"version_id", "digest", "max_reservation_e8_usd", "created_at"},
	"pricing_rules":          {"version_id", "model_pattern", "match_kind", "input_e8_per_million", "output_e8_per_million", "cache_read_e8_per_million", "cache_write_e8_per_million", "cache_write_5m_e8_per_million", "cache_write_1h_e8_per_million", "image_input_e8_per_million", "image_output_e8_per_million", "priority_input_e8_per_million", "priority_output_e8_per_million", "priority_cache_read_e8_per_million", "priority_cache_write_e8_per_million", "fast_multiplier_bps", "flex_multiplier_bps", "max_reasoning_effort_multiplier_bps"},
	"pricing_active_version": {"singleton", "version_id", "activated_at"},
	"accounts":               {"id", "name", "platform", "type", "status", "schedulable", "priority", "max_concurrency", "credential_envelope", "extra_json", "created_at", "updated_at", "deleted_at"},
	"account_groups":         {"account_id", "group_id"},
	"api_keys":               {"id", "user_id", "group_id", "name", "status", "key_hash", "ip_whitelist_json", "ip_blacklist_json", "expires_at", "last_used_at", "created_at", "updated_at", "deleted_at"},
	"model_aliases":          {"alias", "upstream_model", "status", "updated_at"},
	"balance_ledger":         {"id", "operation_id", "actor_user_id", "target_user_id", "adjustment_type", "reason", "delta_e8_usd", "balance_before_e8_usd", "balance_after_e8_usd", "created_at"},
}

// BuildSQLPlan produces a D1 upload file without an unsupported remote
// transaction claim. ExecuteSQLitePlan provides local transaction evidence
// only. Provenance supports verify-first replay after an unknown remote outcome.
func BuildSQLPlan(manifest Manifest) (SQLPlan, error) {
	canonical, err := Canonicalize(manifest)
	if err != nil {
		return SQLPlan{}, err
	}
	bundleBytes, err := json.Marshal(Bundle{Manifest: canonical})
	if err != nil {
		return SQLPlan{}, errors.New("encode canonical bundle")
	}
	bundleHash := sha256.Sum256(bundleBytes)
	bundleDigest := hex.EncodeToString(bundleHash[:])
	guardKey := "offline_migration/v3/assert/" + bundleDigest

	var plan strings.Builder
	plan.WriteString("-- Generated offline migration data plan for canonical D1 migrations 0001-0008.\n")
	plan.WriteString("-- Remote whole-file atomicity is not assumed. Preserve a Time Travel bookmark and verify before replay.\n")
	plan.WriteString("PRAGMA defer_foreign_keys = ON;\n")
	writeAssertion(&plan, guardKey, `EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_bridge_schema_version' AND "value"='2026-09-06.v1')`, "canonical bridge schema is installed")
	writeAssertion(&plan, guardKey, `EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"='cloudflare_e8_money_scale' AND "value"='8')`, "E8 migration is installed")

	tableCounts := map[string]int{}
	for _, chunk := range canonical.Tables {
		fmt.Fprintf(&plan, "\n-- table %s; chunk %s\n", chunk.Table, chunk.ID)
		tableCounts[chunk.Table] += len(chunk.Rows)
		for _, raw := range chunk.Rows {
			rowSQL, identity, rowDigest, rowErr := rowPlanSQL(chunk.Table, raw, guardKey)
			if rowErr != nil {
				return SQLPlan{}, rowErr
			}
			plan.WriteString(rowSQL)
			provenanceKey := "offline_migration/v3/row/" + chunk.Table + "/" + identityDigest(identity)
			writeProvenance(&plan, guardKey, provenanceKey, rowDigest)
		}
		chunkKey := "offline_migration/v3/chunk/" + chunk.ID
		writeProvenance(&plan, guardKey, chunkKey, chunk.SHA256)
	}
	for _, table := range TableOrder {
		expected := strconv.Itoa(tableCounts[table])
		writeAssertion(&plan, guardKey, fmt.Sprintf("(SELECT COUNT(*) FROM %s)=%s", quoteIdentifier(table), expected), table+" exact row count")
	}
	writeAssertion(&plan, guardKey, "NOT EXISTS(SELECT 1 FROM pragma_foreign_key_check)", "foreign keys are valid")
	writeProvenance(&plan, guardKey, "offline_migration/v3/bundle", bundleDigest)

	var validation strings.Builder
	validation.WriteString("-- Read-only post-import validation. Success returns no failure rows.\n")
	validation.WriteString("SELECT 'foreign_key' AS failure, \"table\" AS subject, CAST(rowid AS TEXT) AS actual, parent AS expected FROM pragma_foreign_key_check;\n")
	validation.WriteString("SELECT 'quick_check' AS failure, 'database' AS subject, quick_check AS actual, 'ok' AS expected FROM pragma_quick_check WHERE quick_check <> 'ok';\n")
	for _, table := range TableOrder {
		expected := strconv.Itoa(tableCounts[table])
		fmt.Fprintf(&validation, "SELECT 'row_count' AS failure, %s AS subject, CAST(COUNT(*) AS TEXT) AS actual, %s AS expected FROM %s HAVING COUNT(*) <> %s;\n", SQLLiteral(table), SQLLiteral(expected), quoteIdentifier(table), expected)
	}
	fmt.Fprintf(&validation, "SELECT 'bundle_digest' AS failure, 'offline_migration/v3/bundle' AS subject, COALESCE((SELECT \"value\" FROM \"schema_metadata\" WHERE \"key\"='offline_migration/v3/bundle'),'missing') AS actual, %s AS expected WHERE COALESCE((SELECT \"value\" FROM \"schema_metadata\" WHERE \"key\"='offline_migration/v3/bundle'),'missing') <> %s;\n", SQLLiteral(bundleDigest), SQLLiteral(bundleDigest))
	validation.WriteString("SELECT 'assertion_guard' AS failure, \"key\" AS subject, \"value\" AS actual, 'absent' AS expected FROM \"schema_metadata\" WHERE \"key\" LIKE 'offline_migration/v3/assert/%';\n")
	return SQLPlan{BundleDigest: bundleDigest, SQL: plan.String(), ValidationSQL: validation.String()}, nil
}

func rowPlanSQL(table string, raw json.RawMessage, guardKey string) (string, string, string, error) {
	canonical, identity, err := validateAndCanonicalizeRow(table, raw)
	if err != nil {
		return "", "", "", err
	}
	var row map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &row); err != nil {
		return "", "", "", err
	}
	columns := targetColumnOrder[table]
	values := make([]string, len(columns))
	equality := make([]string, len(columns))
	for index, column := range columns {
		value, valueErr := sqlValue(row[column])
		if valueErr != nil {
			return "", "", "", fmt.Errorf("%s.%s: %w", table, column, valueErr)
		}
		values[index] = value
		equality[index] = quoteIdentifier(column) + " IS " + value
	}
	schema := targetSchemas[table]
	primary := make([]string, len(schema.primaryKey))
	for index, column := range schema.primaryKey {
		value, valueErr := sqlValue(row[column])
		if valueErr != nil {
			return "", "", "", valueErr
		}
		primary[index] = quoteIdentifier(column) + " IS " + value
	}
	var result strings.Builder
	fmt.Fprintf(&result, "INSERT INTO %s(%s) SELECT %s WHERE NOT EXISTS(SELECT 1 FROM %s WHERE %s);\n",
		quoteIdentifier(table), strings.Join(quoteIdentifiers(columns), ","), strings.Join(values, ","),
		quoteIdentifier(table), strings.Join(primary, " AND "))
	writeAssertion(&result, guardKey, "EXISTS(SELECT 1 FROM "+quoteIdentifier(table)+" WHERE "+strings.Join(equality, " AND ")+")", table+" row "+identity+" is identical")
	rowHash := sha256.Sum256(canonical)
	return result.String(), identity, hex.EncodeToString(rowHash[:]), nil
}

func writeProvenance(plan *strings.Builder, guardKey, key, value string) {
	fmt.Fprintf(plan, "INSERT INTO \"schema_metadata\"(\"key\",\"value\") SELECT %s,%s WHERE NOT EXISTS(SELECT 1 FROM \"schema_metadata\" WHERE \"key\"=%s);\n", SQLLiteral(key), SQLLiteral(value), SQLLiteral(key))
	condition := fmt.Sprintf(`EXISTS(SELECT 1 FROM "schema_metadata" WHERE "key"=%s AND "value"=%s)`, SQLLiteral(key), SQLLiteral(value))
	writeAssertion(plan, guardKey, condition, "provenance is identical")
}

func writeAssertion(plan *strings.Builder, guardKey, condition, label string) {
	fmt.Fprintf(plan, "-- assert: %s\n", strings.ReplaceAll(label, "\n", " "))
	fmt.Fprintf(plan, "DELETE FROM \"schema_metadata\" WHERE \"key\"=%s;\n", SQLLiteral(guardKey))
	fmt.Fprintf(plan, "INSERT INTO \"schema_metadata\"(\"key\",\"value\") SELECT %s,'first' WHERE NOT (%s);\n", SQLLiteral(guardKey), condition)
	fmt.Fprintf(plan, "INSERT INTO \"schema_metadata\"(\"key\",\"value\") SELECT %s,'second' WHERE NOT (%s);\n", SQLLiteral(guardKey), condition)
	fmt.Fprintf(plan, "DELETE FROM \"schema_metadata\" WHERE \"key\"=%s;\n", SQLLiteral(guardKey))
}

func identityDigest(identity string) string {
	hash := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(hash[:])
}

func quoteIdentifiers(values []string) []string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = quoteIdentifier(value)
	}
	return quoted
}

func quoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func sqlValue(raw json.RawMessage) (string, error) {
	if bytes.Equal(raw, []byte("null")) {
		return "NULL", nil
	}
	if bytes.Equal(raw, []byte("true")) {
		return "1", nil
	}
	if bytes.Equal(raw, []byte("false")) {
		return "0", nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return SQLLiteral(text), nil
	}
	canonical, err := CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	if bytes.ContainsAny(canonical, ".eE") {
		return "", errors.New("SQL numeric value must be an integer")
	}
	return string(canonical), nil
}

func SQLLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

type NamedPath struct {
	Name string
	Path string
}

// ValidateDistinctPaths resolves aliases before any write. Final symlink paths
// are rejected and every path must identify a distinct filesystem object.
func ValidateDistinctPaths(paths []NamedPath) error {
	resolved := make([]string, len(paths))
	infos := make([]os.FileInfo, len(paths))
	for index, item := range paths {
		if item.Name == "" || item.Path == "" || !filepath.IsAbs(item.Path) {
			return fmt.Errorf("%s path must be absolute", item.Name)
		}
		cleaned := filepath.Clean(item.Path)
		info, err := os.Lstat(cleaned)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%s path may not be a symlink", item.Name)
			}
			if info.IsDir() {
				return fmt.Errorf("%s path may not be a directory", item.Name)
			}
			resolved[index], err = filepath.EvalSymlinks(cleaned)
			if err != nil {
				return fmt.Errorf("%s path could not be resolved", item.Name)
			}
			infos[index] = info
		case os.IsNotExist(err):
			parent, parentErr := filepath.EvalSymlinks(filepath.Dir(cleaned))
			if parentErr != nil {
				return fmt.Errorf("%s parent directory could not be resolved", item.Name)
			}
			resolved[index] = filepath.Join(parent, filepath.Base(cleaned))
		default:
			return fmt.Errorf("%s path could not be inspected", item.Name)
		}
		for prior := 0; prior < index; prior++ {
			same := resolved[index] == resolved[prior]
			if !same && infos[index] != nil && infos[prior] != nil {
				same = os.SameFile(infos[index], infos[prior])
			}
			if same {
				return fmt.Errorf("%s and %s paths alias the same file", item.Name, paths[prior].Name)
			}
		}
	}
	return nil
}

// PlanRemoteImport only returns repository-pinned argv arrays and an explicit
// working directory. It does not invoke pnpm, Wrangler, D1, or Time Travel.
func PlanRemoteImport(acknowledgement, database, backupPath, sqlPath, validationPath, workingDirectory, configPath string) (RemotePlan, error) {
	if acknowledgement != RemoteAcknowledgement {
		return RemotePlan{}, errors.New("exact remote acknowledgement is required")
	}
	if !remoteDatabaseName.MatchString(database) {
		return RemotePlan{}, errors.New("remote database name is invalid")
	}
	if !filepath.IsAbs(workingDirectory) {
		return RemotePlan{}, errors.New("Wrangler working directory must be absolute")
	}
	workInfo, err := os.Lstat(filepath.Clean(workingDirectory))
	if err != nil || !workInfo.IsDir() || workInfo.Mode()&os.ModeSymlink != 0 {
		return RemotePlan{}, errors.New("Wrangler working directory must be a real directory, not a symlink")
	}
	resolvedWork, err := filepath.EvalSymlinks(filepath.Clean(workingDirectory))
	if err != nil {
		return RemotePlan{}, errors.New("Wrangler working directory could not be resolved")
	}
	if err := ValidateDistinctPaths([]NamedPath{
		{Name: "backup", Path: backupPath},
		{Name: "SQL", Path: sqlPath},
		{Name: "validation", Path: validationPath},
		{Name: "Wrangler config", Path: configPath},
	}); err != nil {
		return RemotePlan{}, err
	}
	resolvedConfig, err := filepath.EvalSymlinks(filepath.Clean(configPath))
	if err != nil {
		return RemotePlan{}, errors.New("Wrangler config could not be resolved")
	}
	relativeConfig, err := filepath.Rel(resolvedWork, resolvedConfig)
	if err != nil || relativeConfig == ".." || strings.HasPrefix(relativeConfig, ".."+string(filepath.Separator)) {
		return RemotePlan{}, errors.New("Wrangler config must be inside the working directory")
	}
	for label, path := range map[string]string{"SQL": sqlPath, "validation": validationPath} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return RemotePlan{}, fmt.Errorf("%s plan must be a non-empty regular file", label)
		}
	}
	backupDirectory := filepath.Dir(backupPath)
	if info, err := os.Stat(backupDirectory); err != nil || !info.IsDir() {
		return RemotePlan{}, errors.New("backup parent directory does not exist")
	}
	if _, err := os.Lstat(backupPath); err == nil {
		return RemotePlan{}, errors.New("backup path already exists; use a new path for the pre-import export")
	} else if !os.IsNotExist(err) {
		return RemotePlan{}, errors.New("backup path could not be inspected")
	}
	configInfo, err := os.Stat(configPath)
	if err != nil || !configInfo.Mode().IsRegular() {
		return RemotePlan{}, errors.New("Wrangler config must be a regular file")
	}
	wranglerVersion, err := pinnedWranglerVersion(resolvedWork)
	if err != nil {
		return RemotePlan{}, err
	}
	wrangler := []string{"pnpm", "exec", "wrangler", "--config", filepath.Clean(configPath), "d1"}
	return RemotePlan{
		WorkingDirectory:   resolvedWork,
		WranglerVersion:    wranglerVersion,
		BackupArgs:         append(append([]string{}, wrangler...), "export", database, "--remote", "--output", backupPath),
		ImportArgs:         append(append([]string{}, wrangler...), "execute", database, "--remote", "--file", sqlPath),
		ValidateArgs:       append(append([]string{}, wrangler...), "execute", database, "--remote", "--file", validationPath),
		TimeTravelInfoArgs: append(append([]string{}, wrangler...), "time-travel", "info", database),
		RestoreArgsPrefix:  append(append([]string{}, wrangler...), "time-travel", "restore", database, "--bookmark"),
	}, nil
}

func pinnedWranglerVersion(workingDirectory string) (string, error) {
	packagePath := filepath.Join(workingDirectory, "package.json")
	lockPath := filepath.Join(workingDirectory, "pnpm-lock.yaml")
	for label, path := range map[string]string{"package.json": packagePath, "pnpm-lock.yaml": lockPath} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%s must be a non-symlink regular file in the Wrangler working directory", label)
		}
	}
	contents, err := os.ReadFile(packagePath)
	if err != nil {
		return "", errors.New("read package.json failed")
	}
	var document map[string]any
	if err := json.Unmarshal(contents, &document); err != nil {
		return "", errors.New("package.json is invalid")
	}
	dependencies, ok := document["devDependencies"].(map[string]any)
	if !ok {
		return "", errors.New("package.json has no devDependencies object")
	}
	version, ok := dependencies["wrangler"].(string)
	exactVersion := regexp.MustCompile("^[0-9]+\\.[0-9]+\\.[0-9]+$")
	if !ok || !exactVersion.MatchString(version) {
		return "", errors.New("package.json must pin Wrangler to an exact version")
	}
	lockContents, err := os.ReadFile(lockPath)
	if err != nil {
		return "", errors.New("read pnpm-lock.yaml failed")
	}
	type lockedDependency struct {
		Specifier string `yaml:"specifier"`
		Version   string `yaml:"version"`
	}
	type lockImporter struct {
		DevDependencies map[string]lockedDependency `yaml:"devDependencies"`
	}
	var lockDocument struct {
		Importers map[string]lockImporter `yaml:"importers"`
	}
	if err := yaml.Unmarshal(lockContents, &lockDocument); err != nil {
		return "", errors.New("pnpm-lock.yaml is invalid")
	}
	root, ok := lockDocument.Importers["."]
	if !ok {
		return "", errors.New("pnpm-lock.yaml has no root importer")
	}
	locked, ok := root.DevDependencies["wrangler"]
	if !ok || locked.Specifier != version {
		return "", errors.New("pnpm-lock.yaml root importer does not pin the package.json Wrangler specifier")
	}
	resolvedBase, ok := pnpmResolvedVersionBase(locked.Version)
	if !ok || resolvedBase != version {
		return "", errors.New("pnpm-lock.yaml root importer resolves a different Wrangler version")
	}
	return version, nil
}

func pnpmResolvedVersionBase(resolved string) (string, bool) {
	if resolved == "" || strings.TrimSpace(resolved) != resolved || strings.ContainsAny(resolved, "\x00\r\n\t ") {
		return "", false
	}
	open := strings.IndexByte(resolved, '(')
	if open < 0 {
		return resolved, true
	}
	if open == 0 || resolved[len(resolved)-1] != ')' {
		return "", false
	}
	depth := 0
	for index := open; index < len(resolved); index++ {
		switch resolved[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return "", false
			}
		}
	}
	if depth != 0 {
		return "", false
	}
	return resolved[:open], true
}

func SortedCoverageMatrix() []CoverageSpec {
	result := append([]CoverageSpec(nil), CoverageMatrix...)
	sort.Slice(result, func(left, right int) bool { return result[left].SourceTable < result[right].SourceTable })
	return result
}

// ExecuteSQLitePlan executes a generated plan statement-by-statement inside
// one local transaction. It is intended for offline rehearsal only.
func ExecuteSQLitePlan(ctx context.Context, database *sql.DB, sqlText string) error {
	if database == nil {
		return errors.New("SQLite database is nil")
	}
	statements, err := splitSQLStatements(sqlText)
	if err != nil {
		return err
	}
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, statement := range statements {
		if _, err := transaction.ExecContext(ctx, statement); err != nil {
			_ = transaction.Rollback()
			return err
		}
	}
	return transaction.Commit()
}

func splitSQLStatements(sqlText string) ([]string, error) {
	var statements []string
	start := 0
	inSingle := false
	inDouble := false
	inLineComment := false
	for index := 0; index < len(sqlText); index++ {
		character := sqlText[index]
		if inLineComment {
			if character == '\n' {
				inLineComment = false
			}
			continue
		}
		if !inSingle && !inDouble && character == '-' && index+1 < len(sqlText) && sqlText[index+1] == '-' {
			inLineComment = true
			index++
			continue
		}
		if character == '\'' && !inDouble {
			if inSingle && index+1 < len(sqlText) && sqlText[index+1] == '\'' {
				index++
				continue
			}
			inSingle = !inSingle
			continue
		}
		if character == '"' && !inSingle {
			if inDouble && index+1 < len(sqlText) && sqlText[index+1] == '"' {
				index++
				continue
			}
			inDouble = !inDouble
			continue
		}
		if character == ';' && !inSingle && !inDouble {
			statement := strings.TrimSpace(sqlText[start : index+1])
			if statement != "" {
				statements = append(statements, statement)
			}
			start = index + 1
		}
	}
	if inSingle || inDouble {
		return nil, errors.New("unterminated SQL literal")
	}
	if tail := strings.TrimSpace(sqlText[start:]); tail != "" {
		return nil, errors.New("SQL plan has trailing text without a terminator")
	}
	return statements, nil
}
