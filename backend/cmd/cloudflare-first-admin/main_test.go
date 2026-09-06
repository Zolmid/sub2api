package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

type fakeTerminal struct {
	tty       bool
	passwords []string
	err       error
}

func (t *fakeTerminal) IsTTY() bool { return t.tty }
func (t *fakeTerminal) ReadPassword(string) (string, error) {
	if t.err != nil {
		return "", t.err
	}
	if len(t.passwords) == 0 {
		return "", io.EOF
	}
	value := t.passwords[0]
	t.passwords = t.passwords[1:]
	return value, nil
}

type fakeRunner struct {
	calls               [][]string
	preflight           []byte
	apply               []byte
	post                []byte
	applyErr            error
	postErr             error
	applyFileContent    string
	readbackFileContent string
	filePaths           []string
	fileModes           []os.FileMode
}

func (r *fakeRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	if file := flagValue(args, "--file"); file != "" {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(file)
		if err != nil {
			return nil, err
		}
		r.filePaths = append(r.filePaths, file)
		r.fileModes = append(r.fileModes, info.Mode().Perm())
		if strings.HasPrefix(strings.TrimSpace(string(content)), "INSERT INTO users") {
			r.applyFileContent = string(content)
			return r.apply, r.applyErr
		}
		r.readbackFileContent = string(content)
		return r.post, r.postErr
	}
	command := flagValue(args, "--command")
	if strings.Contains(command, "metadata_rows") {
		return r.preflight, nil
	}
	return r.post, nil
}

func flagValue(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func statement(row map[string]any) []byte {
	value, _ := json.Marshal([]any{map[string]any{"success": true, "results": []any{row}}})
	return value
}

func mutationStatement(id string) []byte {
	value, _ := json.Marshal([]any{map[string]any{"success": true, "results": []any{map[string]any{"inserted_id": id}}}})
	return value
}

func preflightRow(overrides map[string]any) map[string]any {
	row := map[string]any{
		"metadata_rows": 1, "metadata_matches": 1, "stage_c_columns": 15,
		"email_index_flags": 1,
		"email_index_sql":   "CREATE UNIQUE INDEX users_email_live_idx ON users(email) WHERE email <> '' AND deleted_at IS NULL",
		"users_count":       0,
	}
	for key, value := range overrides {
		row[key] = value
	}
	return row
}

func readbackRow(a firstAdmin, overrides map[string]any) map[string]any {
	row := map[string]any{
		"users_count": 1, "matching_count": 1, "id": a.id(), "email": a.email(),
		"username": a.username, "notes": a.notes, "status": "active", "role": "admin",
		"concurrency": 1, "rpm_limit": 0, "balance_microusd": "0", "allowed_group_ids_json": "[]",
		"restrict_public_groups": 0, "created_at": a.createdAt, "updated_at": a.createdAt,
		"deleted_at": nil, "password_hash_matches": 1,
	}
	for key, value := range overrides {
		row[key] = value
	}
	return row
}

func testDeps(runner *fakeRunner, terminal *fakeTerminal, tempDir string, out io.Writer) dependencies {
	return dependencies{
		repositoryRoot: "/repo", runner: runner, terminal: terminal, stdout: out, stderr: out,
		tempDir: tempDir, now: func() time.Time { return time.Date(2026, 9, 7, 1, 2, 3, 0, time.UTC) },
	}
}

func applyArgs() []string {
	return []string{"-apply-local", "-persist-to", "/state", "-email", "Admin@Example.com", "-id", "9007199254740992"}
}

func TestLocalActionRequiresTTYBeforeD1Access(t *testing.T) {
	runner := &fakeRunner{}
	err := run(applyArgs(), testDeps(runner, &fakeTerminal{}, t.TempDir(), io.Discard))
	if err == nil || !strings.Contains(err.Error(), "real TTY") {
		t.Fatalf("error = %v, want TTY refusal", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("D1 calls = %d, want 0", len(runner.calls))
	}
}

func TestLocalActionRequiresExplicitFlag(t *testing.T) {
	runner := &fakeRunner{}
	err := run([]string{"-email", "admin@example.com"}, testDeps(runner, &fakeTerminal{}, t.TempDir(), io.Discard))
	if err == nil || !strings.Contains(err.Error(), "choose exactly one") {
		t.Fatalf("error = %v, want explicit-action refusal", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("D1 calls = %d, want 0", len(runner.calls))
	}
}

func TestTargetSpecificFlagsCannotBeMixed(t *testing.T) {
	deps := testDeps(&fakeRunner{}, &fakeTerminal{tty: true}, t.TempDir(), io.Discard)
	remoteArgs := []string{
		"-apply-remote", "-email", "admin@example.com", "-persist-to", "/state",
		"-remote-acknowledgement", remoteAcknowledgement,
	}
	if err := run(remoteArgs, deps); err == nil || !strings.Contains(err.Error(), "only valid for local") {
		t.Fatalf("remote mixed-target error = %v", err)
	}
	localArgs := append(applyArgs(), "-remote-acknowledgement", remoteAcknowledgement)
	if err := run(localArgs, deps); err == nil || !strings.Contains(err.Error(), "only valid with -apply-remote") {
		t.Fatalf("local mixed-target error = %v", err)
	}
}

func TestRemoteRequiresExactAcknowledgement(t *testing.T) {
	runner := &fakeRunner{}
	err := run([]string{"-apply-remote", "-email", "admin@example.com", "-remote-acknowledgement", "no"}, testDeps(runner, &fakeTerminal{tty: true}, t.TempDir(), io.Discard))
	if err == nil || !strings.Contains(err.Error(), "remote mutation refused") {
		t.Fatalf("error = %v, want acknowledgement refusal", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("D1 calls = %d, want 0", len(runner.calls))
	}
}

func TestWranglerTargetArgumentsAreExplicit(t *testing.T) {
	remote := strings.Join(wranglerArgs(target{name: remoteDatabaseName, configPath: "/repo/wrangler.jsonc", remote: true}, "SELECT 1", ""), " ")
	if !strings.Contains(remote, "--remote --yes") || strings.Contains(remote, "--local") || strings.Contains(remote, "--persist-to") {
		t.Fatalf("remote arguments = %q", remote)
	}
	local := strings.Join(wranglerArgs(target{name: localDatabaseName, configPath: "/repo/wrangler.local.jsonc", persistTo: "/state"}, "SELECT 1", ""), " ")
	if !strings.Contains(local, "--local --persist-to /state") || strings.Contains(local, "--remote") || strings.Contains(local, "--yes") {
		t.Fatalf("local arguments = %q", local)
	}
}

func TestPasswordMismatchNeverApplies(t *testing.T) {
	runner := &fakeRunner{preflight: statement(preflightRow(nil))}
	err := run(applyArgs(), testDeps(runner, &fakeTerminal{tty: true, passwords: []string{"this-is-a-sufficiently-long-password", "different-sufficiently-long-password"}}, t.TempDir(), io.Discard))
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want mismatch", err)
	}
	for _, call := range runner.calls {
		if flagValue(call, "--file") != "" {
			t.Fatal("mutation ran after password mismatch")
		}
	}
}

func TestOverlongPasswordNeverApplies(t *testing.T) {
	runner := &fakeRunner{preflight: statement(preflightRow(nil))}
	password := strings.Repeat("x", maximumPasswordBytes+1)
	err := run(applyArgs(), testDeps(runner, &fakeTerminal{tty: true, passwords: []string{password, password}}, t.TempDir(), io.Discard))
	if err == nil || !strings.Contains(err.Error(), "20 through 72 bytes") {
		t.Fatalf("error = %v, want bcrypt length refusal", err)
	}
	for _, call := range runner.calls {
		if flagValue(call, "--file") != "" {
			t.Fatal("mutation ran with an overlong password")
		}
	}
}

func TestInputValidationAndTextIDBoundary(t *testing.T) {
	invalid := []options{
		{email: "not-an-email", id: "1", username: "admin"},
		{email: "a@.example", id: "1", username: "admin"},
		{email: "a@example.", id: "1", username: "admin"},
		{email: "a@b@example.com", id: "1", username: "admin"},
		{email: "a@example.com", id: "01", username: "admin"},
		{email: "a@example.com", id: "9223372036854775808", username: "admin"},
	}
	for _, option := range invalid {
		if err := validateBootstrapInput(option); err == nil {
			t.Fatalf("validateBootstrapInput(%+v) succeeded", option)
		}
	}
	for _, id := range []string{"9007199254740992", "9223372036854775807"} {
		if _, err := canonicalPositiveInt64(id); err != nil {
			t.Fatalf("text ID %s rejected: %v", id, err)
		}
	}
}

func TestPreflightFailsClosed(t *testing.T) {
	for name, row := range map[string]map[string]any{
		"schema mismatch": {"metadata_matches": 0},
		"non empty users": {"users_count": 1},
		"missing stage c": {"stage_c_columns": 14},
		"bad index":       {"email_index_flags": 0},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{preflight: statement(preflightRow(row))}
			err := run(applyArgs(), testDeps(runner, &fakeTerminal{tty: true}, t.TempDir(), io.Discard))
			if err == nil || !strings.Contains(err.Error(), "preflight refused") {
				t.Fatalf("error = %v, want preflight refusal", err)
			}
			if len(runner.calls) != 1 {
				t.Fatalf("D1 calls = %d, want preflight only", len(runner.calls))
			}
		})
	}
}

func TestMalformedWranglerJSONFailsClosed(t *testing.T) {
	runner := &fakeRunner{preflight: []byte(`{"success":true}`)}
	err := run(applyArgs(), testDeps(runner, &fakeTerminal{tty: true}, t.TempDir(), io.Discard))
	if err == nil || !strings.Contains(err.Error(), "preflight query failed") {
		t.Fatalf("error = %v, want malformed preflight failure", err)
	}
}

func TestApplyUsesGuardedTempFileAndExactReadback(t *testing.T) {
	password := "this-is-a-sufficiently-long-password"
	// The exact hash is generated inside run, so construct post-readback lazily
	// from the guarded SQL rather than making password/hash test fixtures.
	runner := &fakeRunner{preflight: statement(preflightRow(nil)), apply: mutationStatement("9007199254740992")}
	runner.post = statement(map[string]any{})
	var output strings.Builder
	deps := testDeps(runner, &fakeTerminal{tty: true, passwords: []string{password, password}}, t.TempDir(), &output)
	// The fake fills the post-readback response after seeing the temp SQL.
	hook := &readbackRunner{fakeRunner: runner}
	deps.runner = hook
	err := run(applyArgs(), deps)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if len(runner.fileModes) != 2 {
		t.Fatalf("protected SQL files = %d, want mutation and readback", len(runner.fileModes))
	}
	for _, mode := range runner.fileModes {
		if mode != 0o600 {
			t.Fatalf("temp SQL mode = %#o, want 0600", mode)
		}
	}
	if !strings.Contains(runner.applyFileContent, "WHERE NOT EXISTS (SELECT 1 FROM users)") {
		t.Fatal("mutation SQL lacks race-safe empty-users guard")
	}
	if !strings.Contains(runner.applyFileContent, "RETURNING id AS inserted_id") {
		t.Fatal("mutation SQL does not prove the inserted row")
	}
	for _, call := range runner.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "$2") || strings.Contains(joined, password) {
			t.Fatal("bcrypt hash or password appeared in process argv")
		}
	}
	if !strings.Contains(runner.readbackFileContent, "password_hash_matches") || !strings.Contains(runner.readbackFileContent, "$2") {
		t.Fatal("exact hash comparison did not stay inside the protected readback SQL file")
	}
	for _, file := range runner.filePaths {
		if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temp SQL still exists after command: %v", err)
		}
	}
	allCommandOutput := string(runner.apply) + string(runner.post) + output.String()
	if strings.Contains(allCommandOutput, password) || strings.Contains(allCommandOutput, "$2") {
		t.Fatalf("secret leaked to output: %q", output.String())
	}
}

type readbackRunner struct {
	*fakeRunner
}

func (r *readbackRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if flagValue(args, "--file") != "" {
		content, err := os.ReadFile(flagValue(args, "--file"))
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(strings.TrimSpace(string(content)), "INSERT INTO users") {
			result, runErr := r.fakeRunner.Run(ctx, name, args...)
			id := "9007199254740992"
			email := "admin@example.com"
			stamp := "2026-09-07T01:02:03Z"
			// The generated bcrypt value is only in protected SQL files.
			hash := extractInsertedHash(r.applyFileContent)
			a := firstAdmin{options: options{id: id, email: email, username: "admin"}, passwordHash: hash, createdAt: stamp}
			r.post = statement(readbackRow(a, nil))
			return result, runErr
		}
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func extractInsertedHash(sql string) string {
	const marker = "password_hash,username,notes,rpm_limit,updated_at,deleted_at)\nSELECT "
	start := strings.Index(sql, marker)
	if start < 0 {
		return ""
	}
	values := strings.Split(strings.SplitN(sql[start+len(marker):], "\n", 2)[0], ",")
	if len(values) < 10 {
		return ""
	}
	return strings.Trim(values[9], "'")
}

func TestAmbiguousApplyAlwaysFailsAfterConservativeReadback(t *testing.T) {
	password := "this-is-a-sufficiently-long-password"
	runner := &fakeRunner{preflight: statement(preflightRow(nil)), applyErr: errors.New("transport interrupted")}
	hook := &readbackRunner{fakeRunner: runner}
	deps := testDeps(runner, &fakeTerminal{tty: true, passwords: []string{password, password}}, t.TempDir(), io.Discard)
	deps.runner = hook
	err := run(applyArgs(), deps)
	if err == nil || !strings.Contains(err.Error(), "outcome is uncertain") {
		t.Fatalf("error = %v, want uncertain apply failure", err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("D1 calls = %d, want preflight, apply, readback", len(runner.calls))
	}
}

func TestGuardedInsertMustReturnRequestedID(t *testing.T) {
	password := "this-is-a-sufficiently-long-password"
	runner := &fakeRunner{
		preflight: statement(preflightRow(nil)),
		apply:     statement(map[string]any{"inserted_id": "2"}),
	}
	hook := &readbackRunner{fakeRunner: runner}
	deps := testDeps(runner, &fakeTerminal{tty: true, passwords: []string{password, password}}, t.TempDir(), io.Discard)
	deps.runner = hook
	err := run(applyArgs(), deps)
	if err == nil || !strings.Contains(err.Error(), "outcome is uncertain") {
		t.Fatalf("error = %v, want uncertain result without exact insert proof", err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("D1 calls = %d, want preflight, apply, readback", len(runner.calls))
	}
}

func TestReadbackHashMismatchFailsWithoutHashOutput(t *testing.T) {
	a := firstAdmin{
		options:      options{id: "1", email: "admin@example.com", username: "admin"},
		passwordHash: "$2a$10$not-a-real-test-hash-but-still-secret-material",
		createdAt:    "2026-09-07T01:02:03Z",
	}
	runner := &fakeRunner{post: statement(readbackRow(a, map[string]any{"password_hash_matches": 0}))}
	deps := testDeps(runner, &fakeTerminal{}, t.TempDir(), io.Discard)
	err := readBack(context.Background(), localTarget(options{persistTo: "/state"}, deps), deps, a)
	if err == nil || !strings.Contains(err.Error(), "did not exactly match") {
		t.Fatalf("error = %v, want exact hash mismatch", err)
	}
	if strings.Contains(string(runner.post), a.passwordHash) {
		t.Fatal("bcrypt hash appeared in Wrangler JSON output")
	}
	if len(runner.filePaths) != 1 {
		t.Fatalf("protected SQL files = %d, want 1", len(runner.filePaths))
	}
	if _, statErr := os.Stat(runner.filePaths[0]); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("protected readback SQL still exists: %v", statErr)
	}
}

func TestGuardedInsertSQLExecutesExactlyOnceOnStageCSchema(t *testing.T) {
	db := openBootstrapTestDB(t, "CREATE UNIQUE INDEX users_email_live_idx ON users(email) WHERE email <> '' AND deleted_at IS NULL;")
	a := firstAdmin{
		options:      options{id: "1", email: "admin@example.com", username: "admin"},
		passwordHash: "$2a$10$01234567890123456789012345678901234567890123456789012",
		createdAt:    "2026-09-07T01:02:03Z",
	}
	var insertedID string
	if err := db.QueryRow(guardedInsertSQL(a)).Scan(&insertedID); err != nil {
		t.Fatalf("guarded insert: %v", err)
	}
	if insertedID != a.id() {
		t.Fatalf("inserted ID = %q, want %q", insertedID, a.id())
	}
	if err := db.QueryRow(guardedInsertSQL(a)).Scan(&insertedID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second guarded insert error = %v, want no rows", err)
	}
	var hashMatches int
	if err := db.QueryRow("SELECT password_hash_matches FROM (" + readBackSQL(a) + ")").Scan(&hashMatches); err != nil {
		t.Fatalf("protected readback query: %v", err)
	}
	if hashMatches != 1 {
		t.Fatalf("password hash match = %d, want 1", hashMatches)
	}
}

func TestGuardedInsertSQLRejectsWrongPartialIndexShape(t *testing.T) {
	db := openBootstrapTestDB(t, "CREATE UNIQUE INDEX users_email_live_idx ON users(email) WHERE deleted_at IS NULL;")
	a := firstAdmin{
		options:      options{id: "1", email: "admin@example.com", username: "admin"},
		passwordHash: "$2a$10$01234567890123456789012345678901234567890123456789012",
		createdAt:    "2026-09-07T01:02:03Z",
	}
	var insertedID string
	if err := db.QueryRow(guardedInsertSQL(a)).Scan(&insertedID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("wrong-index guarded insert error = %v, want no rows", err)
	}
}

func openBootstrapTestDB(t *testing.T, indexDDL string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	schema := `CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO schema_metadata(key,value) VALUES ('cloudflare_bridge_schema_version','2026-09-06.v1');
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  role TEXT NOT NULL,
  concurrency INTEGER NOT NULL,
  balance_microusd TEXT NOT NULL,
  allowed_group_ids_json TEXT NOT NULL,
  restrict_public_groups INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  username TEXT NOT NULL,
  notes TEXT NOT NULL,
  rpm_limit INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);` + indexDDL
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create Stage C schema: %v", err)
	}
	return db
}
