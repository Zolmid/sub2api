// cloudflare-migrate is an offline snapshot, validation, and SQL planning tool.
// Its PostgreSQL access is read-only and it never calls Cloudflare.
package main

import (
	"bytes"
	"context"
	"database/sql"
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

// Diagnostic output is best effort: the command's exit code describes the
// migration operation, while a broken caller-provided writer must not replace
// or expose the underlying (potentially secret-bearing) failure.
func writeLine(writer io.Writer, values ...any) {
	_, _ = fmt.Fprintln(writer, values...)
}

func writeFormat(writer io.Writer, format string, values ...any) {
	_, _ = fmt.Fprintf(writer, format, values...)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeLine(stderr, "usage: cloudflare-migrate <snapshot-postgres|export|plan|snapshot-postgres-0017|export-0017|plan-0017|upgrade-0017|snapshot-postgres-0018|export-0018|plan-0018|upgrade-0018|remote-plan> [flags]")
		return 2
	}
	switch args[0] {
	case "snapshot-postgres":
		return runSnapshotPostgreSQL(args[1:], stdout, stderr)
	case "snapshot-postgres-0017":
		return runSnapshotPostgreSQL0017(args[1:], stdout, stderr)
	case "snapshot-postgres-0018":
		return runSnapshotPostgreSQL0018(args[1:], stdout, stderr)
	case "export":
		return runExport(args[1:], stdin, stdout, stderr)
	case "export-0017":
		return runExport0017(args[1:], stdout, stderr)
	case "export-0018":
		return runExport0018(args[1:], stdout, stderr)
	case "plan":
		return runPlan(args[1:], stdout, stderr)
	case "plan-0017":
		return runPlan0017(args[1:], stdout, stderr)
	case "plan-0018":
		return runPlan0018(args[1:], stdout, stderr)
	case "upgrade-0017":
		return runUpgrade0017(args[1:], stdout, stderr)
	case "upgrade-0018":
		return runUpgrade0018(args[1:], stdout, stderr)
	case "remote-plan":
		return runRemotePlan(args[1:], stdout, stderr)
	default:
		writeLine(stderr, "unknown command")
		return 2
	}
}

func runSnapshotPostgreSQL(args []string, stdout, stderr io.Writer) int {
	return runSnapshotPostgreSQLWith(args, stdout, stderr, "snapshot-postgres", false, cloudflaremigration.ExportPostgreSQLSnapshot)
}

func runSnapshotPostgreSQL0017(args []string, stdout, stderr io.Writer) int {
	return runSnapshotPostgreSQLWith(args, stdout, stderr, "snapshot-postgres-0017", true, cloudflaremigration.ExportPostgreSQLRestoreSnapshot)
}

func runSnapshotPostgreSQL0018(args []string, stdout, stderr io.Writer) int {
	return runSnapshotPostgreSQLWith(args, stdout, stderr, "snapshot-postgres-0018", true, cloudflaremigration.ExportPostgreSQLRestoreSnapshot0018)
}

func runSnapshotPostgreSQLWith(args []string, stdout, stderr io.Writer, command string, refuseOverwrite bool, exporter func(context.Context, *sql.DB, io.Writer, cloudflaremigration.PostgreSQLSnapshotOptions) error) int {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
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
		writeLine(stderr, "-out must be absolute; secrets and positional arguments are not accepted")
		return 2
	}
	if err := cloudflaremigration.ValidateDistinctPaths([]cloudflaremigration.NamedPath{{Name: "snapshot output", Path: *output}}); err != nil {
		writeFormat(stderr, "snapshot paths rejected: %v\n", err)
		return 2
	}
	if refuseOverwrite {
		if _, err := os.Lstat(*output); err == nil || !errors.Is(err, os.ErrNotExist) {
			writeLine(stderr, "snapshot output already exists or cannot be inspected")
			return 2
		}
	}
	dsnBytes, _, err := secretFromEnvironmentOrFD("SUB2API_PG_DSN", *dsnFD, true)
	if err != nil {
		writeLine(stderr, "PostgreSQL DSN input rejected")
		return 2
	}
	defer wipe(dsnBytes)
	targetEncoded, targetSet, err := secretFromEnvironmentOrFD("SUB2API_D1_CREDENTIAL_KEY", *targetKeyFD, false)
	if err != nil {
		writeLine(stderr, "target credential key input rejected")
		return 2
	}
	defer wipe(targetEncoded)
	legacyEncoded, legacySet, err := secretFromEnvironmentOrFD("SUB2API_LEGACY_TOTP_KEY", *legacyTOTPKeyFD, false)
	if err != nil {
		writeLine(stderr, "legacy TOTP key input rejected")
		return 2
	}
	defer wipe(legacyEncoded)
	var targetKey, legacyKey []byte
	if targetSet {
		targetKey, err = cloudflaremigration.DecodeTargetCredentialKey(string(targetEncoded))
		if err != nil {
			writeLine(stderr, "target credential key input rejected")
			return 2
		}
		defer wipe(targetKey)
	}
	if legacySet {
		legacyKey, err = cloudflaremigration.DecodeLegacyTOTPKey(string(legacyEncoded))
		if err != nil {
			writeLine(stderr, "legacy TOTP key input rejected")
			return 2
		}
		defer wipe(legacyKey)
	}
	var allowedHosts []string
	if rawHosts, ok := os.LookupEnv("SUB2API_CF_UPSTREAM_ALLOWED_HOSTS"); ok {
		allowedHosts, err = cloudflaremigration.ParseAllowedUpstreamHosts(rawHosts)
		if err != nil {
			writeLine(stderr, "upstream host allowlist rejected")
			return 2
		}
	}
	database, err := cloudflaremigration.OpenPostgreSQL(string(dsnBytes))
	if err != nil {
		writeLine(stderr, "open PostgreSQL failed")
		return 1
	}
	defer func() {
		if closeErr := database.Close(); closeErr != nil {
			writeFormat(stderr, "close PostgreSQL failed: %v\n", closeErr)
		}
	}()
	database.SetMaxOpenConns(1)
	options := cloudflaremigration.PostgreSQLSnapshotOptions{Schema: *schema, Credentials: cloudflaremigration.CredentialTransformer{
		TargetKey: targetKey, LegacyTOTPKey: legacyKey, AllowedUpstreamHosts: allowedHosts,
	}}
	if err := writePrivateStream(*output, func(writer io.Writer) error {
		return exporter(context.Background(), database, writer, options)
	}); err != nil {
		writeFormat(stderr, "PostgreSQL snapshot rejected: %v\n", err)
		return 1
	}
	writeLine(stdout, "wrote a secret-safe PostgreSQL snapshot locally; no D1 operation was performed")
	return 0
}

func runExport0017(args []string, stdout, stderr io.Writer) int {
	return runRestoreExportWith(args, stdout, stderr, "export-0017", "0001-0017", cloudflaremigration.ExportRestoreJSONL, cloudflaremigration.BuildRestoreSQLPlan)
}

func runExport0018(args []string, stdout, stderr io.Writer) int {
	return runRestoreExportWith(args, stdout, stderr, "export-0018", "0001-0018", cloudflaremigration.ExportRestoreJSONL0018, cloudflaremigration.BuildRestoreSQLPlan0018)
}

func runRestoreExportWith(args []string, stdout, stderr io.Writer, command, label string, exporter func(io.Reader) (cloudflaremigration.RestoreBundle, error), planner func(cloudflaremigration.RestoreManifest) (cloudflaremigration.SQLPlan, error)) int {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("out", "", "absolute private "+label+" restore bundle output path")
	source := flags.String("source-jsonl", "", "absolute path to a complete "+label+" offline PostgreSQL JSONL export")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *output == "" || !filepath.IsAbs(*output) || *source == "" || !filepath.IsAbs(*source) {
		writeLine(stderr, "-source-jsonl and -out must be absolute; positional arguments are not accepted")
		return 2
	}
	if err := cloudflaremigration.ValidateDistinctPaths([]cloudflaremigration.NamedPath{
		{Name: "source JSONL", Path: *source}, {Name: "restore bundle output", Path: *output},
	}); err != nil {
		writeFormat(stderr, "export paths rejected: %v\n", err)
		return 2
	}
	input, err := os.Open(*source)
	if err != nil {
		writeLine(stderr, "open offline source failed")
		return 1
	}
	bundle, exportErr := exporter(input)
	closeErr := input.Close()
	if exportErr != nil || closeErr != nil {
		writeLine(stderr, "offline PostgreSQL restore export rejected")
		return 1
	}
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil || len(encoded)+1 > cloudflaremigration.MaxBundleBytes {
		writeLine(stderr, "encode private restore bundle failed or exceeded size bound")
		return 1
	}
	plan, err := planner(bundle.Manifest)
	if err != nil {
		writeLine(stderr, "exported restore bundle failed final validation")
		return 1
	}
	if err := writePrivateFilesAtomically([]privateOutput{{path: *output, data: append(encoded, '\n')}}); err != nil {
		writeLine(stderr, "write private restore bundle failed")
		return 1
	}
	writeFormat(stdout, "exported %d classified source tables for canonical %s with %d warning(s); bundle sha256 %s\n", len(bundle.Manifest.Coverage), label, len(bundle.Manifest.Warnings), plan.BundleDigest)
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
		writeLine(stderr, "-source-jsonl and -out must be absolute; positional arguments are not accepted")
		return 2
	}
	if err := cloudflaremigration.ValidateDistinctPaths([]cloudflaremigration.NamedPath{
		{Name: "source JSONL", Path: *source}, {Name: "bundle output", Path: *output},
	}); err != nil {
		writeFormat(stderr, "export paths rejected: %v\n", err)
		return 2
	}
	input, err := os.Open(*source)
	if err != nil {
		writeLine(stderr, "open offline source failed")
		return 1
	}
	defer func() {
		if closeErr := input.Close(); closeErr != nil {
			writeFormat(stderr, "close offline source failed: %v\n", closeErr)
		}
	}()
	bundle, err := cloudflaremigration.ExportJSONL(input)
	if err != nil {
		writeFormat(stderr, "offline PostgreSQL export rejected: %v\n", err)
		return 1
	}
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		writeLine(stderr, "encode private bundle failed")
		return 1
	}
	if len(encoded)+1 > cloudflaremigration.MaxBundleBytes {
		writeLine(stderr, "private bundle exceeds size bound")
		return 1
	}
	plan, err := cloudflaremigration.BuildSQLPlan(bundle.Manifest)
	if err != nil {
		writeLine(stderr, "exported bundle failed final validation")
		return 1
	}
	if err := writePrivateFile(*output, append(encoded, '\n')); err != nil {
		writeLine(stderr, "write private bundle failed")
		return 1
	}
	writeFormat(stdout, "exported %d classified source tables with %d warning(s); bundle sha256 %s\n", len(bundle.Manifest.Coverage), len(bundle.Manifest.Warnings), plan.BundleDigest)
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
		writeLine(stderr, "positional arguments are not accepted")
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
			writeFormat(stderr, "%s must be an absolute path\n", path.name)
			return 2
		}
	}
	namedPaths := make([]cloudflaremigration.NamedPath, 0, len(paths))
	for _, path := range paths {
		namedPaths = append(namedPaths, cloudflaremigration.NamedPath{Name: path.name, Path: path.value})
	}
	if err := cloudflaremigration.ValidateDistinctPaths(namedPaths); err != nil {
		writeFormat(stderr, "plan paths rejected: %v\n", err)
		return 2
	}
	sourceFile, err := os.Open(*sourcePath)
	if err != nil {
		writeLine(stderr, "read source snapshot failed")
		return 1
	}
	sourceBundle, err := cloudflaremigration.ExportJSONL(sourceFile)
	closeErr := sourceFile.Close()
	if err != nil || closeErr != nil {
		writeLine(stderr, "source snapshot rejected")
		return 1
	}
	input, err := readBoundedFile(*bundlePath, cloudflaremigration.MaxBundleBytes)
	if err != nil {
		writeLine(stderr, "read bundle failed")
		return 1
	}
	bundle, err := cloudflaremigration.DecodeBundle(input)
	if err != nil {
		writeFormat(stderr, "bundle rejected: %v\n", err)
		return 1
	}
	canonical, err := cloudflaremigration.Canonicalize(bundle.Manifest)
	if err != nil {
		writeFormat(stderr, "bundle rejected: %v\n", err)
		return 1
	}
	sourceCanonical, err := cloudflaremigration.Canonicalize(sourceBundle.Manifest)
	if err != nil {
		writeLine(stderr, "source snapshot failed canonical validation")
		return 1
	}
	canonicalComparison, _ := json.Marshal(canonical)
	sourceComparison, _ := json.Marshal(sourceCanonical)
	if !bytes.Equal(canonicalComparison, sourceComparison) {
		writeLine(stderr, "bundle does not match the supplied source snapshot")
		return 1
	}
	plan, err := cloudflaremigration.BuildSQLPlan(canonical)
	if err != nil {
		writeFormat(stderr, "SQL plan rejected: %v\n", err)
		return 1
	}
	canonicalBytes, err := json.MarshalIndent(cloudflaremigration.Bundle{Manifest: canonical}, "", "  ")
	if err != nil {
		writeLine(stderr, "encode canonical bundle failed")
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
			writeLine(stderr, "write private output failed")
			return 1
		}
	}
	writeFormat(stdout, "validated %d target table chunks; bundle sha256 %s\n", len(canonical.Tables), plan.BundleDigest)
	return 0
}

func runPlan0017(args []string, stdout, stderr io.Writer) int {
	return runRestorePlanWith(args, stdout, stderr, "plan-0017", "0001-0017", cloudflaremigration.ExportRestoreJSONL, cloudflaremigration.CanonicalizeRestore, cloudflaremigration.BuildRestoreSQLPlan)
}

func runPlan0018(args []string, stdout, stderr io.Writer) int {
	return runRestorePlanWith(args, stdout, stderr, "plan-0018", "0001-0018", cloudflaremigration.ExportRestoreJSONL0018, cloudflaremigration.CanonicalizeRestore0018, cloudflaremigration.BuildRestoreSQLPlan0018)
}

func runRestorePlanWith(args []string, stdout, stderr io.Writer, command, label string, exporter func(io.Reader) (cloudflaremigration.RestoreBundle, error), canonicalize func(cloudflaremigration.RestoreManifest) (cloudflaremigration.RestoreManifest, error), planner func(cloudflaremigration.RestoreManifest) (cloudflaremigration.SQLPlan, error)) int {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	sourcePath := flags.String("source-jsonl", "", "absolute "+label+" source snapshot path")
	bundlePath := flags.String("bundle", "", "absolute "+label+" restore bundle path")
	canonicalPath := flags.String("canonical-bundle", "", "absolute canonical restore bundle output path")
	planPath := flags.String("sql-plan", "", "absolute D1 restore SQL output path")
	validationPath := flags.String("validation-sql", "", "absolute read-only validation SQL output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	paths := []struct{ name, value string }{
		{"-source-jsonl", *sourcePath}, {"-bundle", *bundlePath}, {"-canonical-bundle", *canonicalPath},
		{"-sql-plan", *planPath}, {"-validation-sql", *validationPath},
	}
	if flags.NArg() != 0 {
		writeLine(stderr, "positional arguments are not accepted")
		return 2
	}
	namedPaths := make([]cloudflaremigration.NamedPath, 0, len(paths))
	for _, path := range paths {
		if path.value == "" || !filepath.IsAbs(path.value) {
			writeFormat(stderr, "%s must be an absolute path\n", path.name)
			return 2
		}
		namedPaths = append(namedPaths, cloudflaremigration.NamedPath{Name: path.name, Path: path.value})
	}
	if err := cloudflaremigration.ValidateDistinctPaths(namedPaths); err != nil {
		writeFormat(stderr, "restore plan paths rejected: %v\n", err)
		return 2
	}
	sourceFile, err := os.Open(*sourcePath)
	if err != nil {
		writeLine(stderr, "read restore source snapshot failed")
		return 1
	}
	sourceBundle, sourceErr := exporter(sourceFile)
	closeErr := sourceFile.Close()
	if sourceErr != nil || closeErr != nil {
		writeLine(stderr, "restore source snapshot rejected")
		return 1
	}
	input, err := readBoundedFile(*bundlePath, cloudflaremigration.MaxBundleBytes)
	if err != nil {
		writeLine(stderr, "read restore bundle failed")
		return 1
	}
	bundle, err := cloudflaremigration.DecodeRestoreBundle(input)
	if err != nil {
		writeFormat(stderr, "restore bundle rejected: %v\n", err)
		return 1
	}
	canonical, err := canonicalize(bundle.Manifest)
	if err != nil {
		writeFormat(stderr, "restore bundle rejected: %v\n", err)
		return 1
	}
	sourceCanonical, err := canonicalize(sourceBundle.Manifest)
	if err != nil {
		writeLine(stderr, "restore source failed canonical validation")
		return 1
	}
	canonicalComparison, _ := json.Marshal(canonical)
	sourceComparison, _ := json.Marshal(sourceCanonical)
	if !bytes.Equal(canonicalComparison, sourceComparison) {
		writeLine(stderr, "restore bundle does not match the supplied source snapshot")
		return 1
	}
	plan, err := planner(canonical)
	if err != nil {
		writeFormat(stderr, "restore SQL plan rejected: %v\n", err)
		return 1
	}
	canonicalBytes, err := json.MarshalIndent(cloudflaremigration.RestoreBundle{Manifest: canonical}, "", "  ")
	if err != nil {
		writeLine(stderr, "encode canonical restore bundle failed")
		return 1
	}
	if err := writePrivateFilesAtomically([]privateOutput{
		{path: *canonicalPath, data: append(canonicalBytes, '\n')},
		{path: *planPath, data: []byte(plan.SQL)},
		{path: *validationPath, data: []byte(plan.ValidationSQL)},
	}); err != nil {
		writeLine(stderr, "publish private restore outputs failed; inspect requested paths before retry")
		return 1
	}
	writeFormat(stdout, "validated %d target chunks through canonical %s; bundle sha256 %s\n", len(canonical.Tables), label, plan.BundleDigest)
	return 0
}

func runUpgrade0017(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("upgrade-0017", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundlePath := flags.String("bundle", "", "absolute canonical legacy 0001-0008 bundle path")
	outputPath := flags.String("out", "", "absolute upgraded 0001-0017 restore bundle path")
	planPath := flags.String("sql-plan", "", "absolute upgraded D1 restore SQL output path")
	validationPath := flags.String("validation-sql", "", "absolute upgraded read-only validation SQL output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *bundlePath == "" || *outputPath == "" || *planPath == "" || *validationPath == "" || !filepath.IsAbs(*bundlePath) || !filepath.IsAbs(*outputPath) || !filepath.IsAbs(*planPath) || !filepath.IsAbs(*validationPath) {
		writeLine(stderr, "-bundle, -out, -sql-plan, and -validation-sql must be distinct absolute paths; positional arguments are not accepted")
		return 2
	}
	if err := cloudflaremigration.ValidateDistinctPaths([]cloudflaremigration.NamedPath{
		{Name: "legacy bundle", Path: *bundlePath}, {Name: "restore bundle output", Path: *outputPath},
		{Name: "restore SQL output", Path: *planPath}, {Name: "validation SQL output", Path: *validationPath},
	}); err != nil {
		writeFormat(stderr, "upgrade paths rejected: %v\n", err)
		return 2
	}
	input, err := readBoundedFile(*bundlePath, cloudflaremigration.MaxBundleBytes)
	if err != nil {
		writeLine(stderr, "read legacy bundle failed")
		return 1
	}
	legacy, err := cloudflaremigration.DecodeBundle(input)
	if err != nil {
		writeFormat(stderr, "legacy bundle rejected: %v\n", err)
		return 1
	}
	restore, err := cloudflaremigration.UpgradeBundleToRestore(legacy)
	if err != nil {
		writeFormat(stderr, "legacy bundle cannot be upgraded: %v\n", err)
		return 1
	}
	plan, err := cloudflaremigration.BuildRestoreSQLPlan(restore.Manifest)
	if err != nil {
		writeLine(stderr, "upgraded restore bundle failed final validation")
		return 1
	}
	encoded, err := json.MarshalIndent(restore, "", "  ")
	if err != nil || len(encoded)+1 > cloudflaremigration.MaxBundleBytes {
		writeLine(stderr, "encode upgraded restore bundle failed or exceeded size bound")
		return 1
	}
	if err := writePrivateFilesAtomically([]privateOutput{
		{path: *outputPath, data: append(encoded, '\n')},
		{path: *planPath, data: []byte(plan.SQL)},
		{path: *validationPath, data: []byte(plan.ValidationSQL)},
	}); err != nil {
		writeLine(stderr, "publish upgraded restore outputs failed")
		return 1
	}
	writeFormat(stdout, "upgraded canonical empty-later-state bundle through 0017; bundle sha256 %s\n", plan.BundleDigest)
	return 0
}

func runUpgrade0018(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("upgrade-0018", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundlePath := flags.String("bundle", "", "absolute accepted 0001-0017 restore bundle path")
	outputPath := flags.String("out", "", "absolute upgraded 0001-0018 restore bundle path")
	planPath := flags.String("sql-plan", "", "absolute upgraded D1 0018 restore SQL output path")
	validationPath := flags.String("validation-sql", "", "absolute upgraded 0018 read-only validation SQL output path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *bundlePath == "" || *outputPath == "" || *planPath == "" || *validationPath == "" || !filepath.IsAbs(*bundlePath) || !filepath.IsAbs(*outputPath) || !filepath.IsAbs(*planPath) || !filepath.IsAbs(*validationPath) {
		writeLine(stderr, "-bundle, -out, -sql-plan, and -validation-sql must be distinct absolute paths; positional arguments are not accepted")
		return 2
	}
	if err := cloudflaremigration.ValidateDistinctPaths([]cloudflaremigration.NamedPath{
		{Name: "0017 restore bundle", Path: *bundlePath}, {Name: "0018 restore bundle output", Path: *outputPath},
		{Name: "0018 restore SQL output", Path: *planPath}, {Name: "0018 validation SQL output", Path: *validationPath},
	}); err != nil {
		writeFormat(stderr, "upgrade paths rejected: %v\n", err)
		return 2
	}
	input, err := readBoundedFile(*bundlePath, cloudflaremigration.MaxBundleBytes)
	if err != nil {
		writeLine(stderr, "read 0017 restore bundle failed")
		return 1
	}
	legacy, err := cloudflaremigration.DecodeRestoreBundle(input)
	if err != nil {
		writeFormat(stderr, "0017 restore bundle rejected: %v\n", err)
		return 1
	}
	upgraded, err := cloudflaremigration.UpgradeRestoreBundleTo0018(legacy)
	if err != nil {
		writeFormat(stderr, "0017 restore bundle cannot be upgraded: %v\n", err)
		return 1
	}
	plan, err := cloudflaremigration.BuildRestoreSQLPlan0018(upgraded.Manifest)
	if err != nil {
		writeLine(stderr, "upgraded 0018 restore bundle failed final validation")
		return 1
	}
	encoded, err := json.MarshalIndent(upgraded, "", "  ")
	if err != nil || len(encoded)+1 > cloudflaremigration.MaxBundleBytes {
		writeLine(stderr, "encode upgraded 0018 restore bundle failed or exceeded size bound")
		return 1
	}
	if err := writePrivateFilesAtomically([]privateOutput{
		{path: *outputPath, data: append(encoded, '\n')},
		{path: *planPath, data: []byte(plan.SQL)},
		{path: *validationPath, data: []byte(plan.ValidationSQL)},
	}); err != nil {
		writeLine(stderr, "publish upgraded 0018 restore outputs failed")
		return 1
	}
	writeFormat(stdout, "upgraded canonical pristine-auth-session bundle through 0018; bundle sha256 %s\n", plan.BundleDigest)
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
		writeLine(stderr, "positional arguments are not accepted")
		return 2
	}
	remote, err := cloudflaremigration.PlanRemoteImport(*ack, *database, *backup, *plan, *validation, *workingDirectory, *config)
	if err != nil {
		writeFormat(stderr, "remote plan rejected: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(remote); err != nil {
		writeLine(stderr, "encode remote plan failed")
		return 1
	}
	return 0
}

func readBoundedFile(path string, maximum int) (contents []byte, returnErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && returnErr == nil {
			returnErr = fmt.Errorf("close bounded input file: %w", closeErr)
		}
	}()
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

type privateOutput struct {
	path string
	data []byte
}

var linkPrivateOutput = func(temporaryPath, outputPath string) error {
	// The temporary file is created in the destination directory, so a hard link
	// gives us an atomic no-replace publish on supported local filesystems. Unlike
	// os.Rename, it cannot overwrite a path created after the preflight check.
	return os.Link(temporaryPath, outputPath)
}

func writePrivateFilesAtomically(outputs []privateOutput) (returnErr error) {
	if len(outputs) == 0 {
		return errors.New("no private outputs requested")
	}
	named := make([]cloudflaremigration.NamedPath, 0, len(outputs))
	for index, output := range outputs {
		if !filepath.IsAbs(output.path) {
			return errors.New("private output path must be absolute")
		}
		named = append(named, cloudflaremigration.NamedPath{Name: fmt.Sprintf("private output %d", index+1), Path: output.path})
		if _, err := os.Lstat(output.path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return errors.New("private output already exists or cannot be inspected")
		}
	}
	if err := cloudflaremigration.ValidateDistinctPaths(named); err != nil {
		return err
	}
	temporaryPaths := make([]string, len(outputs))
	published := []string{}
	defer func() {
		cleanupFailures := []string{}
		for _, path := range temporaryPaths {
			if path != "" {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					cleanupFailures = append(cleanupFailures, path)
				}
			}
		}
		if returnErr != nil {
			for _, path := range published {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					cleanupFailures = append(cleanupFailures, path)
				}
			}
		}
		if len(cleanupFailures) != 0 {
			returnErr = fmt.Errorf("%w; cleanup incomplete for %d private path(s)", returnErr, len(cleanupFailures))
		}
	}()
	for index, output := range outputs {
		temporary, err := os.CreateTemp(filepath.Dir(output.path), ".cloudflare-migrate-0017-*")
		if err != nil {
			return err
		}
		temporaryPaths[index] = temporary.Name()
		if err := temporary.Chmod(0o600); err != nil {
			_ = temporary.Close()
			return err
		}
		if _, err := temporary.Write(output.data); err != nil {
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
	}
	for index, output := range outputs {
		if err := linkPrivateOutput(temporaryPaths[index], output.path); err != nil {
			return err
		}
		published = append(published, output.path)
		if err := os.Remove(temporaryPaths[index]); err != nil {
			return err
		}
		temporaryPaths[index] = ""
	}
	return nil
}

func writePrivateStream(path string, write func(io.Writer) error) (returnErr error) {
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
	defer func() {
		if removeErr := os.Remove(temporaryPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			if returnErr == nil {
				returnErr = fmt.Errorf("remove temporary migration file: %w", removeErr)
			}
		}
	}()
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
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				// The descriptor is an input-only secret source; report close failures
				// without exposing the secret or changing an already-determined result.
				writeFormat(os.Stderr, "close inherited secret failed: %v\n", closeErr)
			}
		}()
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
