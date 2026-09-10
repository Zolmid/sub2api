package cloudflaremigration

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPostgreSQLSnapshotContractIsReadOnlyOrderedAndBounded(t *testing.T) {
	if PostgreSQLReadOnlyTransaction != "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY" {
		t.Fatal("PostgreSQL transaction contract changed")
	}
	for _, spec := range CoverageMatrix {
		if spec.Classification == Transformed {
			if _, ok := postgreSQLRowOrder[spec.SourceTable]; !ok {
				t.Fatalf("transformed table %q lacks deterministic PostgreSQL ordering", spec.SourceTable)
			}
			if columns, ok := expectedPostgreSQLColumns(spec.SourceTable); !ok || len(columns) == 0 {
				t.Fatalf("transformed table %q lacks a pinned column contract", spec.SourceTable)
			}
		}
	}
	rows := []json.RawMessage{json.RawMessage("{\"id\":\"1\"}"), json.RawMessage("{\"id\":\"2\"}")}
	expected, err := DigestRows(rows)
	if err != nil {
		t.Fatal(err)
	}
	accumulator := newStreamingRowDigest()
	for _, row := range rows {
		accumulator.add(row)
	}
	if accumulator.sum() != expected {
		t.Fatal("streaming and bundle row digests differ")
	}
	var output bytes.Buffer
	writer := &boundedSnapshotWriter{writer: &output, maximum: 3}
	if _, err := writer.Write([]byte("four")); err == nil || !strings.Contains(err.Error(), "hard limit") {
		t.Fatal("snapshot byte hard limit was not enforced")
	}
}

func TestPostgreSQLColumnInventoryFailsClosedForEmptyTableDrift(t *testing.T) {
	expected, ok := expectedPostgreSQLColumns("users")
	if !ok {
		t.Fatal("users column contract is missing")
	}
	inventory := map[string]bool{"users": true}
	if err := validatePostgreSQLColumnInventory(inventory, map[string][]string{"users": expected}); err != nil {
		t.Fatalf("exact users column contract rejected: %v", err)
	}
	extra := append(append([]string(nil), expected...), "unknown_future_column")
	if err := validatePostgreSQLColumnInventory(inventory, map[string][]string{"users": extra}); err == nil {
		t.Fatal("extra column on an empty transformed table was accepted")
	}
	missing := append([]string(nil), expected[1:]...)
	if err := validatePostgreSQLColumnInventory(inventory, map[string][]string{"users": missing}); err == nil {
		t.Fatal("missing column on an empty transformed table was accepted")
	}
}

func TestExportPostgreSQLSnapshotUsesVerifiedReadOnlyTransaction(t *testing.T) {
	state := &snapshotDriverState{}
	snapshotDriverRegistration.Do(func() {
		sql.Register("cloudflaremigration-snapshot-test", snapshotDriver{state: state})
	})
	snapshotDriverCurrent = state
	database, err := sql.Open("cloudflaremigration-snapshot-test", "")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Errorf("close snapshot test database: %v", closeErr)
		}
	})

	var output bytes.Buffer
	if err := ExportPostgreSQLSnapshot(context.Background(), database, &output, PostgreSQLSnapshotOptions{Schema: "public"}); err != nil {
		t.Fatal(err)
	}
	if !state.beganReadOnly || !state.enforcedReadOnly || !state.committed {
		t.Fatalf("read-only snapshot transaction was not fully enforced: %#v", state)
	}
	bundle, err := ExportJSONL(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatalf("repository-owned snapshot was not accepted by strict parser: %v", err)
	}
	if len(bundle.Manifest.Coverage) != len(CoverageMatrix) {
		t.Fatal("repository-owned snapshot omitted known source tables")
	}
}

var (
	snapshotDriverRegistration sync.Once
	snapshotDriverCurrent      *snapshotDriverState
)

type snapshotDriverState struct {
	beganReadOnly    bool
	enforcedReadOnly bool
	committed        bool
}

type snapshotDriver struct {
	state *snapshotDriverState
}

func (driverValue snapshotDriver) Open(string) (driver.Conn, error) {
	if snapshotDriverCurrent != nil {
		driverValue.state = snapshotDriverCurrent
	}
	return &snapshotConnection{state: driverValue.state}, nil
}

type snapshotConnection struct {
	state *snapshotDriverState
}

func (connection *snapshotConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}

func (connection *snapshotConnection) Close() error {
	return nil
}

func (connection *snapshotConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("Begin without transaction options is not accepted")
}

func (connection *snapshotConnection) BeginTx(_ context.Context, options driver.TxOptions) (driver.Tx, error) {
	if !options.ReadOnly || options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("snapshot transaction options are not read-only repeatable-read")
	}
	connection.state.beganReadOnly = true
	return &snapshotTransaction{state: connection.state}, nil
}

func (connection *snapshotConnection) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if query != PostgreSQLReadOnlyTransaction {
		return nil, errors.New("unexpected snapshot exec")
	}
	connection.state.enforcedReadOnly = true
	return driver.RowsAffected(0), nil
}

func (connection *snapshotConnection) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	checksum := strings.Repeat("a", 64)
	switch {
	case strings.Contains(query, "current_setting('transaction_isolation')"):
		return newSnapshotRows([]string{"transaction_isolation", "transaction_read_only"}, [][]driver.Value{{"repeatable read", "on"}}), nil
	case strings.Contains(query, "txid_current_snapshot()"):
		captured := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
		return newSnapshotRows([]string{"snapshot", "server_version", "captured_at"}, [][]driver.Value{{"1:2:", "170000", captured}}), nil
	case strings.Contains(query, "SELECT filename, checksum"):
		return newSnapshotRows([]string{"filename", "checksum"}, [][]driver.Value{{"0001_test.sql", checksum}}), nil
	case strings.Contains(query, "FROM information_schema.columns"):
		return newSnapshotRows([]string{"table_name", "column_name"}, [][]driver.Value{
			{"schema_migrations", "applied_at"},
			{"schema_migrations", "checksum"},
			{"schema_migrations", "filename"},
		}), nil
	case strings.Contains(query, "FROM pg_catalog.pg_tables"):
		return newSnapshotRows([]string{"tablename"}, [][]driver.Value{{"schema_migrations"}}), nil
	case strings.Contains(query, "row_to_json(source_row)") && strings.Contains(query, "schema_migrations"):
		row := `{"filename":"0001_test.sql","checksum":"` + checksum + `","applied_at":"2026-09-09T00:00:00Z"}`
		return newSnapshotRows([]string{"row_to_json"}, [][]driver.Value{{row}}), nil
	default:
		return nil, errors.New("unexpected snapshot query")
	}
}

type snapshotTransaction struct {
	state *snapshotDriverState
}

func (transaction *snapshotTransaction) Commit() error {
	transaction.state.committed = true
	return nil
}

func (*snapshotTransaction) Rollback() error {
	return nil
}

type snapshotRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func newSnapshotRows(columns []string, values [][]driver.Value) *snapshotRows {
	return &snapshotRows{columns: columns, values: values}
}

func (rows *snapshotRows) Columns() []string {
	return rows.columns
}

func (*snapshotRows) Close() error {
	return nil
}

func (rows *snapshotRows) Next(destination []driver.Value) error {
	if rows.index == len(rows.values) {
		return io.EOF
	}
	copy(destination, rows.values[rows.index])
	rows.index++
	return nil
}
