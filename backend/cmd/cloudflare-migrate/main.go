// cloudflare-migrate is an offline snapshot, validation, and SQL planning tool.
// Its PostgreSQL access is read-only and it never calls Cloudflare.
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
	"path/filepath"

	"github.com/Wei-Shaw/sub2api/internal/cloudflaremigration"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: cloudflare-migrate <snapshot-postgres|export|plan|remote-plan> [flags]")
		return 2
	}
	switch args[0] {
	case "snapshot-postgres":
		return runSnapshotPostgreSQL(args[1:], stdout, stderr)
	case "export":
		return runExport(args[1:], stdin, stdout, stderr)
	case "plan":
		return runPlan(args[1:], stdout, stderr)
	case "remote-plan":
		return runRemotePlan(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "unknown command; expected snapshot-postgres, export, plan, or remote-plan")
		return 2
	}
}

func runSnapshotPostgreSQL(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("snapshot-postgres", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("out", "", "absolute private secret-safe JSONL snapshot path")
	schema := flags.String("schema", "public", "PostgreSQL schema name")
	dsnFD := flags.Int("dsn-fd", -1, "inherited FD containing DSN; otherwise SUB2API_PG_DSN")
	targetKeyFD := flags.Int("target-key-fd", -1, "inherited FD containing target base64 key; otherwise SUB2API_D1_CREDENTIAL_KEY")
	legacyTOTPKeyFD := flags.Int("legacy-totp-key-fd", -1, "inherited FD containing legacy hex TOTP key; otherwise SUB2API_LEGACY_TOTP_KEY")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *output == "" || !filepath.IsAbs(*output) {
		fmt.Fprintln(stderr, "-out must be absolute; secrets and positional arguments are not accepted")
		return 2
	}
	if err := cloudflaremigration.ValidateDistinctPaths([]cloudflaremigration.NamedPath{{Name: "snapshot output", Path: *output}}); err != nil {
		fmt.Fprintf(stderr, "snapshot paths rejected: %v\n", err)
		return 2
	}
	dsnBytes, _, err := secretFromEnvironmentOrFD("SUB2API_PG_DSN", *dsnFD, true)
	if err != nil {
		fmt.Fprintln(stderr, "PostgreSQL DSN input rejected")
		return 2
	}
	defer wipe(dsnBytes)
	targetEncoded, targetSet, err := secretFromEnvironmentOrFD("SUB2API_D1_CREDENTIAL_KEY", *targetKeyFD, false)
	if err != nil {
		fmt.Fprintln(stderr, "target credential key input rejected")
		return 2
	}
	defer wipe(targetEncoded)
	legacyEncoded, legacySet, err := secretFromEnvironmentOrFD("SUB2API_LEGACY_TOTP_KEY", *legacyTOTPKeyFD, false)
	if err != nil {
		fmt.Fprintln(stderr, "legacy TOTP key input rejected")
		return 2
	}
	defer wipe(legacyEncoded)
	var targetKey, legacyKey []byte
	if targetSet {
		targetKey, err = cloudflaremigration.DecodeTargetCredentialKey(string(targetEncoded))
		if err != nil {
			fmt.Fprintln(stderr, "target credential key input rejected")
			return 2
		}
		defer wipe(targetKey)
	}
	if legacySet {
		legacyKey, err = cloudflaremigration.DecodeLegacyTOTPKey(string(legacyEncoded))
		if err != nil {
			fmt.Fprintln(stderr, "legacy TOTP key input rejected")
			return 2
		}
		defer wipe(legacyKey)
	}
	var allowedHosts []string
	if rawHosts, ok := os.LookupEnv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS"); ok {
		allowedHosts, err = cloudflaremigration.ParseAllowedUpstreamHosts(rawHosts)
		if err != nil {
			fmt.Fprintln(stderr, "upstream host allowlist rejected")
			return 2
		}
	}
	database, err := cloudflaremigration.OpenPostgreSQL(string(dsnBytes))
	if err != nil {
		fmt.Fprintln(stderr, "open PostgreSQL failed")
		return 1
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	options := cloudflaremigration.PostgreSQLSnapshotOptions{Schema: *schema, Credentials: cloudflaremigration.CredentialTransformer{
		TargetKey: targetKey, LegacyTOTPKey: legacyKey, AllowedUpstreamHosts: allowedHosts,
	}}
	if err := writePrivateStream(*output, func(writer io.Writer) error {
		return cloudflaremigration.ExportPostgreSQLSnapshot(context.Background(), database, writer, options)
	}); err != nil {
		fmt.Fprintf(stderr, "PostgreSQL snapshot rejected: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "wrote a secret-safe PostgreSQL snapshot locally; no D1 operation was performed")
	return 0
}

func runExport(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("out", "", "absolute private bundle output path")
	source := flags.String("source-jsonl", "", "absolute path to a complete offline PostgreSQL JSONL export")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *output == "" || !filepath.IsAbs(*output) || *source == "" || !filepath.IsAbs(*source) {
		fmt.Fprintln(stderr, "-source-jsonl and -out must be absolute; positional arguments are not accepted")
		return 2
	}
	if err := cloudflaremigration.ValidateDistinctPaths([]cloudflaremigration.NamedPath{
		{Name: "source JSONL", Path: *source}, {Name: "bundle output", Path: *output},
	}); err != nil {
		fmt.Fprintf(stderr, "export paths rejected: %v\n", err)
		return 2
	}
	input, err := os.Open(*source)
	if err != nil {
		fmt.Fprintln(stderr, "open offline source failed")
		return 1
	}
	defer input.Close()
	bundle, err := cloudflaremigration.ExportJSONL(input)
	if err != nil {
		fmt.Fprintf(stderr, "offline PostgreSQL export rejected: %v\n", err)
		return 1
	}
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "encode private bundle failed")
		return 1
	}
	if len(encoded)+1 > cloudflaremigration.MaxBundleBytes {
		fmt.Fprintln(stderr, "private bundle exceeds size bound")
		return 1
	}
	plan, err := cloudflaremigration.BuildSQLPlan(bundle.Manifest)
	if err != nil {
		fmt.Fprintln(stderr, "exported bundle failed final validation")
		return 1
	}
	if err := writePrivateFile(*output, append(encoded, '\n')); err != nil {
		fmt.Fprintln(stderr, "write private bundle failed")
		return 1
	}
	fmt.Fprintf(stdout, "exported %d classified source tables with %d warning(s); bundle sha256 %s\n", len(bundle.Manifest.Coverage), len(bundle.Manifest.Warnings), plan.BundleDigest)
	return 0
}

func runPlan(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	sourcePath := flags.String("source-jsonl", "", "absolute source snapshot path used to produce the bundle")
	bundlePath := flags.String("bundle", "", "absolute source bundle path")
	canonicalPath := flags.String("canonical-bundle", "", "absolute canonical bundle output path")
	planPath := flags.String("sql-plan", "", "absolute D1 SQL plan output path")
	validationPath := flags.String("validation-sql", "", "absolute read-only validation SQL output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "positional arguments are not accepted")
		return 2
	}
	paths := []struct{ name, value string }{
		{"-source-jsonl", *sourcePath},
		{"-bundle", *bundlePath},
		{"-canonical-bundle", *canonicalPath},
		{"-sql-plan", *planPath},
		{"-validation-sql", *validationPath},
	}
	for _, path := range paths {
		if path.value == "" || !filepath.IsAbs(path.value) {
			fmt.Fprintf(stderr, "%s must be an absolute path\n", path.name)
			return 2
		}
	}
	namedPaths := make([]cloudflaremigration.NamedPath, 0, len(paths))
	for _, path := range paths {
		namedPaths = append(namedPaths, cloudflaremigration.NamedPath{Name: path.name, Path: path.value})
	}
	if err := cloudflaremigration.ValidateDistinctPaths(namedPaths); err != nil {
		fmt.Fprintf(stderr, "plan paths rejected: %v\n", err)
		return 2
	}
	sourceFile, err := os.Open(*sourcePath)
	if err != nil {
		fmt.Fprintln(stderr, "read source snapshot failed")
		return 1
	}
	sourceBundle, err := cloudflaremigration.ExportJSONL(sourceFile)
	closeErr := sourceFile.Close()
	if err != nil || closeErr != nil {
		fmt.Fprintln(stderr, "source snapshot rejected")
		return 1
	}
	input, err := readBoundedFile(*bundlePath, cloudflaremigration.MaxBundleBytes)
	if err != nil {
		fmt.Fprintln(stderr, "read bundle failed")
		return 1
	}
	bundle, err := cloudflaremigration.DecodeBundle(input)
	if err != nil {
		fmt.Fprintf(stderr, "bundle rejected: %v\n", err)
		return 1
	}
	canonical, err := cloudflaremigration.Canonicalize(bundle.Manifest)
	if err != nil {
		fmt.Fprintf(stderr, "bundle rejected: %v\n", err)
		return 1
	}
	sourceCanonical, err := cloudflaremigration.Canonicalize(sourceBundle.Manifest)
	if err != nil {
		fmt.Fprintln(stderr, "source snapshot failed canonical validation")
		return 1
	}
	canonicalComparison, _ := json.Marshal(canonical)
	sourceComparison, _ := json.Marshal(sourceCanonical)
	if !bytes.Equal(canonicalComparison, sourceComparison) {
		fmt.Fprintln(stderr, "bundle does not match the supplied source snapshot")
		return 1
	}
	plan, err := cloudflaremigration.BuildSQLPlan(canonical)
	if err != nil {
		fmt.Fprintf(stderr, "SQL plan rejected: %v\n", err)
		return 1
	}
	canonicalBytes, err := json.MarshalIndent(cloudflaremigration.Bundle{Manifest: canonical}, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "encode canonical bundle failed")
		return 1
	}
	outputs := []struct {
		path string
		data []byte
	}{
		{*canonicalPath, append(canonicalBytes, '\n')},
		{*planPath, []byte(plan.SQL)},
		{*validationPath, []byte(plan.ValidationSQL)},
	}
	for _, output := range outputs {
		if err := writePrivateFile(output.path, output.data); err != nil {
			fmt.Fprintln(stderr, "write private output failed")
			return 1
		}
	}
	fmt.Fprintf(stdout, "validated %d target table chunks; bundle sha256 %s\n", len(canonical.Tables), plan.BundleDigest)
	return 0
}

func runRemotePlan(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("remote-plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	ack := flags.String("ack", "", "exact operator acknowledgement")
	database := flags.String("database", "", "operator-selected D1 database name")
	backup := flags.String("backup", "", "absolute output path for a pre-import D1 export")
	plan := flags.String("sql-plan", "", "absolute reviewed import SQL path")
	validation := flags.String("validation-sql", "", "absolute reviewed validation SQL path")
	workingDirectory := flags.String("deploy-dir", "", "absolute deploy/cloudflare working directory")
	config := flags.String("config", "", "absolute repository-pinned Wrangler config path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "positional arguments are not accepted")
		return 2
	}
	remote, err := cloudflaremigration.PlanRemoteImport(*ack, *database, *backup, *plan, *validation, *workingDirectory, *config)
	if err != nil {
		fmt.Fprintf(stderr, "remote plan rejected: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(remote); err != nil {
		fmt.Fprintln(stderr, "encode remote plan failed")
		return 1
	}
	return 0
}

func readBoundedFile(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(data) > maximum {
		return nil, errors.New("file exceeds size bound")
	}
	return data, nil
}

func writePrivateFile(path string, contents []byte) error {
	return writePrivateStream(path, func(writer io.Writer) error {
		_, err := writer.Write(contents)
		return err
	})
}

func writePrivateStream(path string, write func(io.Writer) error) error {
	if write == nil {
		return errors.New("private writer callback is nil")
	}
	if err := cloudflaremigration.ValidateDistinctPaths([]cloudflaremigration.NamedPath{{Name: "private output", Path: path}}); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".cloudflare-migrate-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := write(temporary); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func secretFromEnvironmentOrFD(environment string, fd int, required bool) ([]byte, bool, error) {
	value, fromEnvironment := os.LookupEnv(environment)
	if fd < -1 || fd >= 0 && fromEnvironment {
		return nil, false, errors.New("secret must have exactly one source")
	}
	if fd >= 0 {
		file := os.NewFile(uintptr(fd), "inherited-secret")
		if file == nil {
			return nil, false, errors.New("secret file descriptor is invalid")
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, 64<<10))
		if err != nil || len(data) == 64<<10 {
			return nil, false, errors.New("secret file descriptor is unreadable or oversized")
		}
		data = bytes.TrimSuffix(data, []byte("\n"))
		data = bytes.TrimSuffix(data, []byte("\r"))
		if len(data) == 0 {
			return nil, false, errors.New("secret is empty")
		}
		return data, true, nil
	}
	if fromEnvironment {
		if value == "" {
			return nil, false, errors.New("secret environment value is empty")
		}
		return []byte(value), true, nil
	}
	if required {
		return nil, false, errors.New("required secret is missing")
	}
	return nil, false, nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
