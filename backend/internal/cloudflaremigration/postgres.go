package cloudflaremigration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"strconv"
	"time"

	_ "github.com/lib/pq"
)

const PostgreSQLReadOnlyTransaction = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"

type PostgreSQLSnapshotOptions struct {
	Schema      string
	Credentials CredentialTransformer
}

// OpenPostgreSQL opens a driver handle only. The caller supplies the DSN from
// an environment variable or inherited file descriptor and must never log it.
func OpenPostgreSQL(dsn string) (*sql.DB, error) {
	if dsn == "" {
		return nil, errors.New("PostgreSQL DSN is empty")
	}
	return sql.Open("postgres", dsn)
}

// ExportPostgreSQLSnapshot reads one REPEATABLE READ, READ ONLY transaction and
// writes a secret-safe row-streamed snapshot. The caller should write to a
// private temporary file and publish it only after this function commits.
func ExportPostgreSQLSnapshot(ctx context.Context, database *sql.DB, output io.Writer, options PostgreSQLSnapshotOptions) error {
	if database == nil || output == nil {
		return errors.New("PostgreSQL database and snapshot writer are required")
	}
	schema := options.Schema
	if schema == "" {
		schema = "public"
	}
	if !sourceIdentifier(schema) {
		return errors.New("PostgreSQL schema name is unsafe")
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return errors.New("begin PostgreSQL read-only snapshot failed")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, PostgreSQLReadOnlyTransaction); err != nil {
		return errors.New("enforce PostgreSQL REPEATABLE READ READ ONLY failed")
	}
	var isolation, readOnly string
	if err := tx.QueryRowContext(ctx, "SELECT current_setting('transaction_isolation'), current_setting('transaction_read_only')").Scan(&isolation, &readOnly); err != nil || isolation != "repeatable read" || readOnly != "on" {
		return errors.New("PostgreSQL did not confirm repeatable read, read-only mode")
	}

	var snapshotID, serverVersion string
	var capturedAt time.Time
	if err := tx.QueryRowContext(ctx, "SELECT txid_current_snapshot()::text, current_setting('server_version_num'), transaction_timestamp()").Scan(&snapshotID, &serverVersion, &capturedAt); err != nil {
		return errors.New("read PostgreSQL snapshot fingerprint failed")
	}
	migrationRows, err := readMigrationFingerprint(ctx, tx, schema)
	if err != nil {
		return err
	}
	migrationDigest, err := DigestRows(migrationRows)
	if err != nil {
		return errors.New("compute PostgreSQL migration fingerprint failed")
	}
	header := sourceHeader{
		Type: "source", Format: SourceFormatVersion, MappingProfile: MappingProfileVersion,
		SnapshotID: snapshotID, SchemaName: schema, ServerVersion: serverVersion,
		MigrationCount: strconv.Itoa(len(migrationRows)), MigrationSHA256: migrationDigest,
		CapturedAt: capturedAt.UTC().Format(time.RFC3339Nano), Complete: true,
	}
	if err := validateSourceHeader(header); err != nil {
		return err
	}

	inventory, err := readPostgreSQLInventory(ctx, tx, schema)
	if err != nil {
		return err
	}
	columns, err := readPostgreSQLColumnInventory(ctx, tx, schema, inventory)
	if err != nil {
		return err
	}
	if err := validatePostgreSQLColumnInventory(inventory, columns); err != nil {
		return err
	}
	allTables := map[string]bool{}
	for _, spec := range CoverageMatrix {
		allTables[spec.SourceTable] = true
	}
	for table := range inventory {
		allTables[table] = true
	}
	orderedTables := make([]string, 0, len(allTables))
	for table := range allTables {
		orderedTables = append(orderedTables, table)
	}
	sort.Strings(orderedTables)

	writer := &boundedSnapshotWriter{writer: output, maximum: MaxSnapshotBytes}
	if err := writeJSONLine(writer, header); err != nil {
		return err
	}
	summaries := make([]snapshotTableSummary, 0, len(orderedTables))
	totalRows := 0
	for _, table := range orderedTables {
		isPresent := inventory[table]
		presentCopy := isPresent
		if err := writeJSONLine(writer, sourceTableStart{Type: "table", Table: table, Present: &presentCopy}); err != nil {
			return err
		}
		count, digest, err := exportPostgreSQLTable(ctx, tx, schema, table, isPresent, options.Credentials, writer)
		if err != nil {
			return err
		}
		totalRows += count
		if totalRows > MaxRows {
			return fmt.Errorf("snapshot exceeds total row capacity %d", MaxRows)
		}
		summary := snapshotTableSummary{Table: table, Present: isPresent, RowCount: strconv.Itoa(count), SHA256: digest}
		summaries = append(summaries, summary)
		if err := writeJSONLine(writer, sourceTableEnd{Type: "table_end", Table: table, RowCount: summary.RowCount, SHA256: summary.SHA256}); err != nil {
			return err
		}
	}
	snapshotSHA, err := snapshotDigest(header, summaries)
	if err != nil {
		return errors.New("compute snapshot fingerprint failed")
	}
	if err := writeJSONLine(writer, sourceSnapshotEnd{Type: "snapshot_end", TableCount: strconv.Itoa(len(summaries)), RowCount: strconv.Itoa(totalRows), SHA256: snapshotSHA}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("commit PostgreSQL read-only snapshot failed")
	}
	return nil
}

func readMigrationFingerprint(ctx context.Context, tx *sql.Tx, schema string) ([]json.RawMessage, error) {
	query := fmt.Sprintf("SELECT filename, checksum FROM %s.%s ORDER BY filename", quoteIdentifier(schema), quoteIdentifier("schema_migrations"))
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.New("read schema_migrations failed; the repository-owned migration registry is required")
	}
	defer rows.Close()
	result := []json.RawMessage{}
	for rows.Next() {
		var filename, checksum string
		if err := rows.Scan(&filename, &checksum); err != nil || filename == "" || containsControl(filename) || validateLowerSHA256(checksum) != nil {
			return nil, errors.New("schema_migrations contains an invalid filename or checksum")
		}
		encoded, _ := json.Marshal(map[string]string{"filename": filename, "checksum": checksum})
		result = append(result, encoded)
		if len(result) > MaxRowsPerTable {
			return nil, errors.New("schema_migrations exceeds configured capacity")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("read schema_migrations failed")
	}
	return result, nil
}

func readPostgreSQLInventory(ctx context.Context, tx *sql.Tx, schema string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = $1 ORDER BY tablename", schema)
	if err != nil {
		return nil, errors.New("read PostgreSQL table inventory failed")
	}
	defer rows.Close()
	result := map[string]bool{}
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil || !sourceIdentifier(table) {
			return nil, errors.New("PostgreSQL inventory contains an unsafe table name")
		}
		if result[table] {
			return nil, errors.New("PostgreSQL inventory contains a duplicate table")
		}
		result[table] = true
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("read PostgreSQL table inventory failed")
	}
	return result, nil
}

func readPostgreSQLColumnInventory(ctx context.Context, tx *sql.Tx, schema string, inventory map[string]bool) (map[string][]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT table_name, column_name
FROM information_schema.columns
WHERE table_schema = $1
  AND table_name IN (
    SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = $1
  )
ORDER BY table_name, column_name`, schema)
	if err != nil {
		return nil, errors.New("read PostgreSQL column inventory failed")
	}
	defer rows.Close()
	result := make(map[string][]string, len(inventory))
	for table := range inventory {
		result[table] = []string{}
	}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil || !inventory[table] || !sourceIdentifier(table) || !sourceIdentifier(column) {
			return nil, errors.New("PostgreSQL column inventory contains an unsafe or unknown entry")
		}
		columns := result[table]
		if len(columns) != 0 && columns[len(columns)-1] >= column {
			return nil, errors.New("PostgreSQL column inventory is duplicated or not deterministic")
		}
		result[table] = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("read PostgreSQL column inventory failed")
	}
	return result, nil
}

func validatePostgreSQLColumnInventory(inventory map[string]bool, columns map[string][]string) error {
	for _, spec := range CoverageMatrix {
		if spec.Classification != Transformed || !inventory[spec.SourceTable] {
			continue
		}
		expected, ok := expectedPostgreSQLColumns(spec.SourceTable)
		if !ok {
			return fmt.Errorf("transformed source table %q has no pinned column contract", spec.SourceTable)
		}
		actual := append([]string(nil), columns[spec.SourceTable]...)
		sort.Strings(expected)
		sort.Strings(actual)
		if !equalStrings(actual, expected) {
			return fmt.Errorf("source table %q columns differ from mapping profile %s", spec.SourceTable, MappingProfileVersion)
		}
	}
	return nil
}

func exportPostgreSQLTable(ctx context.Context, tx *sql.Tx, schema, table string, present bool, credentials CredentialTransformer, output io.Writer) (int, string, error) {
	accumulator := newStreamingRowDigest()
	if !present {
		return 0, accumulator.sum(), nil
	}
	spec, known := coverageSpec(table)
	if !known || spec.Classification != Transformed {
		var count int
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s.%s", quoteIdentifier(schema), quoteIdentifier(table))
		if err := tx.QueryRowContext(ctx, query).Scan(&count); err != nil {
			return 0, "", fmt.Errorf("count source table %q failed", table)
		}
		if count != 0 {
			if !known {
				return 0, "", fmt.Errorf("unknown source table %q is nonempty", table)
			}
			return 0, "", fmt.Errorf("%s source table %q is nonempty", spec.Classification, table)
		}
		return 0, accumulator.sum(), nil
	}
	order, ok := postgreSQLRowOrder[table]
	if !ok {
		return 0, "", fmt.Errorf("transformed source table %q lacks an explicit deterministic order", table)
	}
	query := fmt.Sprintf("SELECT row_to_json(source_row)::text FROM %s.%s AS source_row ORDER BY %s", quoteIdentifier(schema), quoteIdentifier(table), order)
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return 0, "", fmt.Errorf("read transformed source table %q failed", table)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return 0, "", fmt.Errorf("scan source table %q failed", table)
		}
		transformed, err := TransformLegacyRow(table, raw, credentials)
		if err != nil {
			return 0, "", fmt.Errorf("transform source table %q row %d: %w", table, count+1, err)
		}
		accumulator.add(transformed)
		if err := writeJSONLine(output, sourceRow{Type: "row", Table: table, Row: transformed}); err != nil {
			return 0, "", err
		}
		count++
		if count > MaxRowsPerTable {
			return 0, "", fmt.Errorf("source table %q exceeds row capacity %d", table, MaxRowsPerTable)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, "", fmt.Errorf("read transformed source table %q failed", table)
	}
	return count, accumulator.sum(), nil
}

var postgreSQLRowOrder = map[string]string{
	"account_groups":         "\"account_id\",\"group_id\"",
	"accounts":               "\"id\"",
	"api_keys":               "\"id\"",
	"atlas_schema_revisions": "\"version\"",
	"balance_ledger":         "\"id\"",
	"groups":                 "\"id\"",
	"model_aliases":          "\"alias\"",
	"pricing_active_version": "\"singleton\"",
	"pricing_rules":          "\"version_id\",\"model_pattern\"",
	"pricing_versions":       "\"version_id\"",
	"schema_migrations":      "\"filename\"",
	"user_allowed_groups":    "\"user_id\",\"group_id\"",
	"users":                  "\"id\"",
}

type boundedSnapshotWriter struct {
	writer  io.Writer
	written int
	maximum int
}

func (writer *boundedSnapshotWriter) Write(value []byte) (int, error) {
	if len(value) > writer.maximum-writer.written {
		return 0, fmt.Errorf("snapshot exceeds %d-byte hard limit", writer.maximum)
	}
	written, err := writer.writer.Write(value)
	writer.written += written
	return written, err
}

func writeJSONLine(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return errors.New("encode snapshot record failed")
	}
	if len(encoded) > MaxRowBytes+(64<<10) {
		return errors.New("snapshot record exceeds line capacity")
	}
	encoded = append(encoded, '\n')
	if _, err := writer.Write(encoded); err != nil {
		return errors.New("write private snapshot failed")
	}
	return nil
}

type streamingRowDigest struct {
	hash hash.Hash
}

func newStreamingRowDigest() *streamingRowDigest {
	return &streamingRowDigest{hash: sha256.New()}
}

func (digest *streamingRowDigest) add(row []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(row)))
	_, _ = digest.hash.Write(length[:])
	_, _ = digest.hash.Write(row)
}

func (digest *streamingRowDigest) sum() string {
	return hex.EncodeToString(digest.hash.Sum(nil))
}
