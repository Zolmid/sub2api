// cloudflare-first-admin is an out-of-band bootstrap tool for a brand-new
// Sub2API Cloudflare D1 installation. It deliberately has no HTTP surface.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"golang.org/x/term"
)

const (
	bridgeSchemaVersion   = "2026-09-06.v1"
	e8MoneyScale          = "8"
	pricingSchemaVersion  = "2026-09-08.v1"
	remoteAcknowledgement = "I_HAVE_EXPORTED_A_D1_BACKUP_AND_ACCEPT_REMOTE_FIRST_ADMIN_BOOTSTRAP"
	localDatabaseName     = "sub2api-cloudflare-local"
	remoteDatabaseName    = "sub2api-cloudflare"
	stageCEmailIndexSQL   = "createuniqueindexusers_email_live_identity_idxonusers(lower(trim(email)))whereemail<>''anddeleted_atisnull"
	minimumPasswordBytes  = 20
	maximumPasswordBytes  = 72 // bcrypt rejects inputs longer than 72 bytes.
)

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type osCommandRunner struct{}

func (osCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Output deliberately captures stdout and discards stderr. In particular,
	// neither SQL files nor Wrangler diagnostics may reach the terminal because
	// the protected mutation and verification SQL files contain the bcrypt hash.
	return exec.CommandContext(ctx, name, args...).Output()
}

type passwordTerminal interface {
	IsTTY() bool
	ReadPassword(prompt string) (string, error)
}

type realTerminal struct {
	in  *os.File
	out io.Writer
}

func (t realTerminal) IsTTY() bool { return term.IsTerminal(int(t.in.Fd())) }

func (t realTerminal) ReadPassword(prompt string) (string, error) {
	if _, err := fmt.Fprint(t.out, prompt); err != nil {
		return "", err
	}
	password, err := term.ReadPassword(int(t.in.Fd()))
	if _, newlineErr := fmt.Fprintln(t.out); newlineErr != nil && err == nil {
		err = newlineErr
	}
	if err != nil {
		return "", err
	}
	return string(password), nil
}

type target struct {
	name       string
	configPath string
	remote     bool
	persistTo  string
}

type dependencies struct {
	repositoryRoot string
	runner         commandRunner
	terminal       passwordTerminal
	stdout         io.Writer
	stderr         io.Writer
	tempDir        string
	now            func() time.Time
}

type options struct {
	email        string
	id           string
	username     string
	notes        string
	persistTo    string
	applyLocal   bool
	applyRemote  bool
	inspectLocal bool
	remoteAck    string
}

func main() {
	root, err := findRepositoryRoot("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cloudflare-first-admin:", err)
		os.Exit(1)
	}
	deps := dependencies{
		repositoryRoot: root,
		runner:         osCommandRunner{},
		terminal:       realTerminal{in: os.Stdin, out: os.Stderr},
		stdout:         os.Stdout,
		stderr:         os.Stderr,
		now:            time.Now,
	}
	if err := run(os.Args[1:], deps); err != nil {
		fmt.Fprintln(os.Stderr, "cloudflare-first-admin:", err)
		os.Exit(1)
	}
}

func run(args []string, deps dependencies) error {
	if deps.now == nil {
		deps.now = time.Now
	}
	fs := flag.NewFlagSet("cloudflare-first-admin", flag.ContinueOnError)
	fs.SetOutput(deps.stderr)
	opt := options{}
	fs.StringVar(&opt.email, "email", "", "first administrator email (required for apply)")
	fs.StringVar(&opt.id, "id", "1", "positive decimal user ID (default: 1)")
	fs.StringVar(&opt.username, "username", "admin", "administrator username")
	fs.StringVar(&opt.notes, "notes", "", "administrator notes")
	fs.StringVar(&opt.persistTo, "persist-to", "", "isolated local Wrangler persistence directory")
	fs.BoolVar(&opt.inspectLocal, "inspect-local", false, "read-only local schema/users preflight")
	fs.BoolVar(&opt.applyLocal, "apply-local", false, "create the first administrator in local D1")
	fs.BoolVar(&opt.applyRemote, "apply-remote", false, "create the first administrator in remote D1")
	fs.StringVar(&opt.remoteAck, "remote-acknowledgement", "", "required exact acknowledgement for remote mutation")
	fs.Usage = func() {
		fmt.Fprintln(deps.stderr, "Usage: cloudflare-first-admin -inspect-local -persist-to DIR")
		fmt.Fprintln(deps.stderr, "       cloudflare-first-admin -apply-local -persist-to DIR -email ADMIN@example.com [-id 1]")
		fmt.Fprintln(deps.stderr, "       cloudflare-first-admin -apply-remote -email ADMIN@example.com -remote-acknowledgement EXACT_TEXT")
		fmt.Fprintln(deps.stderr, "Passwords are requested twice only from an interactive TTY; no password flag or environment input exists.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	actions := boolCount(opt.inspectLocal, opt.applyLocal, opt.applyRemote)
	if actions == 0 {
		fs.Usage()
		return errors.New("choose exactly one of -inspect-local, -apply-local, or -apply-remote")
	}
	if actions != 1 {
		return errors.New("choose exactly one of -inspect-local, -apply-local, or -apply-remote")
	}

	if opt.inspectLocal {
		if opt.remoteAck != "" {
			return errors.New("-remote-acknowledgement is only valid with -apply-remote")
		}
		if opt.persistTo == "" {
			return errors.New("-inspect-local requires -persist-to")
		}
		if err := inspect(context.Background(), localTarget(opt, deps), deps); err != nil {
			return err
		}
		fmt.Fprintln(deps.stdout, "local preflight passed: compatible Stage C schema and an empty users table")
		return nil
	}

	if err := validateBootstrapInput(opt); err != nil {
		return err
	}
	if opt.applyRemote && opt.remoteAck != remoteAcknowledgement {
		return errors.New("remote mutation refused: -remote-acknowledgement must exactly confirm an exported D1 backup")
	}
	if opt.applyRemote && opt.persistTo != "" {
		return errors.New("-persist-to is only valid for local actions")
	}
	if opt.applyLocal && opt.persistTo == "" {
		return errors.New("-apply-local requires -persist-to")
	}
	if opt.applyLocal && opt.remoteAck != "" {
		return errors.New("-remote-acknowledgement is only valid with -apply-remote")
	}
	if !deps.terminal.IsTTY() {
		return errors.New("refusing mutation: password input requires an interactive real TTY")
	}

	t := remoteTarget(opt, deps)
	if opt.applyLocal {
		t = localTarget(opt, deps)
	}
	if err := inspect(context.Background(), t, deps); err != nil {
		return err
	}

	password, err := deps.terminal.ReadPassword("First administrator password: ")
	if err != nil {
		return errors.New("could not read password from terminal")
	}
	confirmation, err := deps.terminal.ReadPassword("Confirm password: ")
	if err != nil {
		return errors.New("could not read password confirmation from terminal")
	}
	if password != confirmation {
		return errors.New("password confirmation does not match")
	}
	if len(password) < minimumPasswordBytes || len(password) > maximumPasswordBytes {
		return errors.New("password must contain 20 through 72 bytes")
	}

	user := service.User{}
	if err := user.SetPassword(password); err != nil {
		return errors.New("could not create bcrypt password hash")
	}
	stamp := deps.now().UTC().Format(time.RFC3339Nano)
	expected := firstAdmin{options: opt, passwordHash: user.PasswordHash, createdAt: stamp}
	applyErr := apply(context.Background(), t, deps, expected)
	if applyErr != nil {
		// An error after handing the statement to Wrangler is an uncertain state.
		// Read back once, without retrying, then fail even if it happens to match.
		_ = readBack(context.Background(), t, deps, expected)
		return fmt.Errorf("apply outcome is uncertain (%v); no retry was attempted, inspect D1 before taking further action", applyErr)
	}
	if err := readBack(context.Background(), t, deps, expected); err != nil {
		return fmt.Errorf("post-write verification failed (%v); bootstrap state is uncertain and no retry was attempted", err)
	}
	fmt.Fprintf(deps.stdout, "created first administrator %s with ID %s after exact D1 readback\n", expected.email(), expected.id())
	return nil
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func findRepositoryRoot(start string) (string, error) {
	if start == "" {
		var err error
		start, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	for dir := filepath.Clean(start); ; dir = filepath.Dir(dir) {
		if info, err := os.Stat(filepath.Join(dir, "deploy", "cloudflare", "wrangler.local.jsonc")); err == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not locate repository root containing deploy/cloudflare/wrangler.local.jsonc")
		}
	}
}

func localTarget(opt options, deps dependencies) target {
	return target{
		name: localDatabaseName, configPath: filepath.Join(deps.repositoryRoot, "deploy", "cloudflare", "wrangler.local.jsonc"),
		persistTo: opt.persistTo,
	}
}

func remoteTarget(_ options, deps dependencies) target {
	return target{
		name: remoteDatabaseName, configPath: filepath.Join(deps.repositoryRoot, "deploy", "cloudflare", "wrangler.jsonc"),
		remote: true,
	}
}

func validateBootstrapInput(opt options) error {
	if !validBootstrapEmail(opt.email) {
		return errors.New("invalid administrator email")
	}
	if _, err := canonicalPositiveInt64(opt.id); err != nil {
		return fmt.Errorf("invalid administrator ID: %w", err)
	}
	if len(opt.username) > 100 {
		return errors.New("username exceeds the Stage C 100-character limit")
	}
	if len(opt.notes) > 4096 {
		return errors.New("notes exceeds the Stage C 4096-character limit")
	}
	return nil
}

func validBootstrapEmail(value string) bool {
	if value == "" || len(value) > 255 || strings.ContainsAny(value, " \t\r\n") || strings.Count(value, "@") != 1 {
		return false
	}
	at := strings.LastIndexByte(value, '@')
	domain := value[at+1:]
	dot := strings.LastIndexByte(domain, '.')
	return at > 0 && dot > 0 && dot < len(domain)-1
}

func canonicalPositiveInt64(value string) (int64, error) {
	if value == "" || value[0] == '0' {
		return 0, errors.New("must be a canonical positive decimal string")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("must be a canonical positive decimal string")
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, errors.New("must fit positive Go int64")
	}
	// IDs cross the Worker/frontend boundary only as TEXT. This intentionally
	// permits values above Number.MAX_SAFE_INTEGER without a float conversion.
	return parsed, nil
}

type firstAdmin struct {
	options
	passwordHash string
	createdAt    string
}

func (a firstAdmin) email() string { return strings.ToLower(strings.TrimSpace(a.options.email)) }
func (a firstAdmin) id() string    { return a.options.id }

func inspect(ctx context.Context, t target, deps dependencies) error {
	row, err := queryOneWith(ctx, t, preflightSQL(), deps.runner, wranglerPath(deps))
	if err != nil {
		return errors.New("preflight query failed")
	}
	if integer(row, "metadata_rows") != 1 || integer(row, "metadata_matches") != 1 {
		return errors.New("preflight refused: Cloudflare bridge schema metadata is incompatible or ambiguous")
	}
	if integer(row, "e8_metadata_rows") != 1 || integer(row, "e8_metadata_matches") != 1 ||
		integer(row, "pricing_metadata_rows") != 1 || integer(row, "pricing_metadata_matches") != 1 {
		return errors.New("preflight refused: Cloudflare migration 0008 e8 money and pricing metadata is required")
	}
	if integer(row, "stage_c_columns") != 15 {
		return errors.New("preflight refused: required Stage C users columns/shape are incompatible")
	}
	if integer(row, "email_index_flags") != 1 || normalizeIndexSQL(stringField(row, "email_index_sql")) != stageCEmailIndexSQL {
		return errors.New("preflight refused: users_email_live_identity_idx shape is incompatible")
	}
	if integer(row, "users_count") != 0 {
		return errors.New("preflight refused: users table is not empty")
	}
	return nil
}

func preflightSQL() string {
	return fmt.Sprintf(`WITH cols AS (SELECT name, lower(type) AS type, "notnull" AS nn, pk FROM pragma_table_info('users'))
SELECT
	  (SELECT count(*) FROM schema_metadata WHERE key='cloudflare_bridge_schema_version') AS metadata_rows,
	  (SELECT count(*) FROM schema_metadata WHERE key='cloudflare_bridge_schema_version' AND value=%s) AS metadata_matches,
	  (SELECT count(*) FROM schema_metadata WHERE key='cloudflare_e8_money_scale') AS e8_metadata_rows,
	  (SELECT count(*) FROM schema_metadata WHERE key='cloudflare_e8_money_scale' AND value=%s) AS e8_metadata_matches,
	  (SELECT count(*) FROM schema_metadata WHERE key='cloudflare_pricing_schema_version') AS pricing_metadata_rows,
	  (SELECT count(*) FROM schema_metadata WHERE key='cloudflare_pricing_schema_version' AND value=%s) AS pricing_metadata_matches,
  (SELECT count(*) FROM cols WHERE
    (name='id' AND type='text' AND pk=1) OR
    (name IN ('status','role','allowed_group_ids_json','created_at','email','password_hash','username','notes','updated_at') AND type='text' AND nn=1 AND pk=0) OR
    (name='balance_e8_usd' AND type='text' AND nn=1 AND pk=0) OR
    (name IN ('concurrency','restrict_public_groups','rpm_limit') AND type='integer' AND nn=1 AND pk=0) OR
    (name='deleted_at' AND type='text' AND nn=0 AND pk=0)
  ) AS stage_c_columns,
  (SELECT count(*) FROM pragma_index_list('users') WHERE name='users_email_live_identity_idx' AND "unique"=1 AND partial=1) AS email_index_flags,
  (SELECT sql FROM sqlite_master WHERE type='index' AND name='users_email_live_identity_idx') AS email_index_sql,
	  (SELECT count(*) FROM users) AS users_count`, sqlLiteral(bridgeSchemaVersion), sqlLiteral(e8MoneyScale), sqlLiteral(pricingSchemaVersion))
}

func guardedInsertSQL(a firstAdmin) string {
	return fmt.Sprintf(`INSERT INTO users(id,status,role,concurrency,balance_e8_usd,allowed_group_ids_json,restrict_public_groups,created_at,email,password_hash,username,notes,rpm_limit,updated_at,deleted_at)
SELECT %s,'active','admin',1,'0','[]',0,%s,%s,%s,%s,%s,0,%s,NULL
	WHERE NOT EXISTS (SELECT 1 FROM users)
	  AND (SELECT count(*) FROM schema_metadata WHERE key='cloudflare_bridge_schema_version' AND value=%s)=1
	  AND (SELECT count(*) FROM schema_metadata WHERE key='cloudflare_e8_money_scale' AND value=%s)=1
	  AND (SELECT count(*) FROM schema_metadata WHERE key='cloudflare_pricing_schema_version' AND value=%s)=1
  AND (SELECT count(*) FROM pragma_table_info('users') WHERE
    (name='id' AND lower(type)='text' AND pk=1) OR
    (name IN ('status','role','allowed_group_ids_json','created_at','email','password_hash','username','notes','updated_at') AND lower(type)='text' AND "notnull"=1 AND pk=0) OR
    (name='balance_e8_usd' AND lower(type)='text' AND "notnull"=1 AND pk=0) OR
    (name IN ('concurrency','restrict_public_groups','rpm_limit') AND lower(type)='integer' AND "notnull"=1 AND pk=0) OR
    (name='deleted_at' AND lower(type)='text' AND "notnull"=0 AND pk=0)
  )=15
  AND EXISTS (SELECT 1 FROM pragma_index_list('users') WHERE name='users_email_live_identity_idx' AND "unique"=1 AND partial=1)
  AND replace(replace(replace(replace(lower((SELECT sql FROM sqlite_master WHERE type='index' AND name='users_email_live_identity_idx')), ' ', ''), char(9), ''), char(10), ''), char(13), '')=%s
RETURNING id AS inserted_id`,
		sqlLiteral(a.id()), sqlLiteral(a.createdAt), sqlLiteral(a.email()), sqlLiteral(a.passwordHash), sqlLiteral(a.username), sqlLiteral(a.notes), sqlLiteral(a.createdAt), sqlLiteral(bridgeSchemaVersion), sqlLiteral(e8MoneyScale), sqlLiteral(pricingSchemaVersion), sqlLiteral(stageCEmailIndexSQL))
}

func readBackSQL(a firstAdmin) string {
	match := fmt.Sprintf("id=%s OR lower(trim(email))=%s", sqlLiteral(a.id()), sqlLiteral(a.email()))
	parts := []string{
		"(SELECT count(*) FROM users) AS users_count",
		fmt.Sprintf("(SELECT count(*) FROM users WHERE %s) AS matching_count", match),
	}
	for _, column := range []string{"id", "email", "username", "notes", "status", "role", "concurrency", "rpm_limit", "balance_e8_usd", "allowed_group_ids_json", "restrict_public_groups", "created_at", "updated_at", "deleted_at"} {
		parts = append(parts, fmt.Sprintf("(SELECT %s FROM users WHERE %s LIMIT 1) AS %s", column, match, column))
	}
	parts = append(parts, fmt.Sprintf("(SELECT password_hash=%s FROM users WHERE %s LIMIT 1) AS password_hash_matches", sqlLiteral(a.passwordHash), match))
	return "SELECT\n  " + strings.Join(parts, ",\n  ")
}

func sqlLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func apply(ctx context.Context, t target, deps dependencies, a firstAdmin) error {
	output, err := runProtectedSQLFile(ctx, t, deps, guardedInsertSQL(a))
	if err != nil {
		return err
	}
	statement, err := parseStatement(output)
	if err != nil {
		return errors.New("wrangler mutation output was malformed or unsuccessful")
	}
	row, err := exactlyOneRow(statement)
	if err != nil || stringField(row, "inserted_id") != a.id() {
		return errors.New("guarded mutation did not prove exactly one administrator was inserted")
	}
	return nil
}

func runProtectedSQLFile(ctx context.Context, t target, deps dependencies, sql string) (output []byte, resultErr error) {
	if deps.runner == nil {
		return nil, errors.New("missing command runner")
	}
	dir := deps.tempDir
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.CreateTemp(dir, "sub2api-first-admin-*.sql")
	if err != nil {
		return nil, errors.New("could not create protected SQL file")
	}
	path := f.Name()
	defer func() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			output = nil
			resultErr = errors.New("could not remove protected SQL file")
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, errors.New("could not protect SQL file")
	}
	if _, err := f.WriteString(sql); err != nil {
		_ = f.Close()
		return nil, errors.New("could not write protected SQL file")
	}
	if err := f.Close(); err != nil {
		return nil, errors.New("could not close protected SQL file")
	}
	output, err = deps.runner.Run(ctx, wranglerPath(deps), wranglerArgs(t, "", path)...)
	if err != nil {
		return nil, errors.New("wrangler SQL-file command failed")
	}
	return output, nil
}

func readBack(ctx context.Context, t target, deps dependencies, a firstAdmin) error {
	output, err := runProtectedSQLFile(ctx, t, deps, readBackSQL(a))
	if err != nil {
		return err
	}
	statement, err := parseStatement(output)
	if err != nil {
		return errors.New("wrangler readback output was malformed or unsuccessful")
	}
	row, err := exactlyOneRow(statement)
	if err != nil {
		return err
	}
	if integer(row, "users_count") != 1 || integer(row, "matching_count") != 1 ||
		stringField(row, "id") != a.id() || stringField(row, "email") != a.email() ||
		stringField(row, "username") != a.username || stringField(row, "notes") != a.notes ||
		stringField(row, "status") != "active" || stringField(row, "role") != "admin" ||
		integer(row, "concurrency") != 1 || integer(row, "rpm_limit") != 0 ||
		stringField(row, "balance_e8_usd") != "0" || stringField(row, "allowed_group_ids_json") != "[]" ||
		integer(row, "restrict_public_groups") != 0 || stringField(row, "created_at") != a.createdAt ||
		stringField(row, "updated_at") != a.createdAt || !isNull(row["deleted_at"]) ||
		integer(row, "password_hash_matches") != 1 {
		return errors.New("D1 readback did not exactly match the requested first administrator")
	}
	return nil
}

func queryOneWith(ctx context.Context, t target, sql string, runner commandRunner, wrangler string) (map[string]any, error) {
	if runner == nil {
		return nil, errors.New("missing command runner")
	}
	output, err := runner.Run(ctx, wrangler, wranglerArgs(t, sql, "")...)
	if err != nil {
		return nil, errors.New("Wrangler query failed")
	}
	statement, err := parseStatement(output)
	if err != nil {
		return nil, err
	}
	return exactlyOneRow(statement)
}

func exactlyOneRow(statement map[string]any) (map[string]any, error) {
	results, ok := statement["results"].([]any)
	if !ok || len(results) != 1 {
		return nil, errors.New("expected exactly one query result row")
	}
	row, ok := results[0].(map[string]any)
	if !ok {
		return nil, errors.New("query result row is not an object")
	}
	return row, nil
}

func wranglerPath(deps dependencies) string {
	return filepath.Join(deps.repositoryRoot, "deploy", "cloudflare", "node_modules", ".bin", "wrangler")
}

func wranglerArgs(t target, sql, file string) []string {
	args := []string{"d1", "execute", t.name}
	if t.remote {
		// The exact backup acknowledgement is enforced before this point. Keep
		// Wrangler non-interactive so a prompt cannot create an ambiguous hang.
		args = append(args, "--remote", "--yes")
	} else {
		args = append(args, "--local", "--persist-to", t.persistTo)
	}
	args = append(args, "--config", t.configPath, "--json")
	if file != "" {
		return append(args, "--file", file)
	}
	return append(args, "--command", sql)
}

func parseStatement(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return nil, errors.New("invalid Wrangler JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("ambiguous Wrangler JSON")
	}
	return unwrapStatement(root)
}

func unwrapStatement(value any) (map[string]any, error) {
	if entries, ok := value.([]any); ok {
		if len(entries) != 1 {
			return nil, errors.New("expected exactly one Wrangler statement result")
		}
		return unwrapStatement(entries[0])
	}
	statement, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("Wrangler statement is not an object")
	}
	if success, present := statement["success"]; !present || success != true {
		return nil, errors.New("Wrangler reported an unsuccessful statement")
	}
	if nested, ok := statement["result"]; ok && statement["results"] == nil {
		return unwrapStatement(nested)
	}
	if _, ok := statement["results"].([]any); !ok {
		return nil, errors.New("Wrangler statement has no result array")
	}
	return statement, nil
}

func integer(row map[string]any, key string) int64 {
	value, ok := row[key].(json.Number)
	if !ok {
		return -1
	}
	parsed, err := value.Int64()
	if err != nil {
		return -1
	}
	return parsed
}

func stringField(row map[string]any, key string) string {
	value, _ := row[key].(string)
	return value
}

func isNull(value any) bool { return value == nil }

func normalizeIndexSQL(value string) string {
	replacer := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "")
	return replacer.Replace(strings.ToLower(strings.TrimSpace(value)))
}
