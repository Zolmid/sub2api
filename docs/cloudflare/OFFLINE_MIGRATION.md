# Historical offline PostgreSQL to D1 0008 migration

This page documents the preserved legacy `snapshot-postgres`, `export`, and `plan` command contract for `legacy-postgresql-to-d1-0008/v1`. For the current canonical restore path through `0018_auth_sessions.sql`, use [MIGRATION.md](MIGRATION.md) and the explicit `snapshot-postgres-0018`, `export-0018`, `plan-0018`, and `upgrade-0018` commands.

cloudflare-migrate is a fail-closed migration preparation tool. It has one narrowly scoped database operation: snapshot-postgres opens the legacy PostgreSQL database and reads one REPEATABLE READ, READ ONLY transaction. It never writes PostgreSQL. The other commands consume local artifacts. No command invokes Wrangler, Cloudflare, D1 import, Time Travel restore, deployment, or traffic cutover.

The bundle format is sub2api-cloudflare-offline-bundle/v3, the row-streamed source format is sub2api-postgresql-jsonl/v2, and the mapping profile is legacy-postgresql-to-d1-0008/v1.

Important: this historical profile targets only canonical D1 migrations 0001 through 0008. It is retained for compatibility and reproducibility of already reviewed legacy artifacts, not for a new canonical Cloudflare restore.

## 1. Secret and path contract

The PostgreSQL DSN and encryption keys are never accepted as positional arguments or flag values. Supply each value by its fixed environment variable or an inherited file descriptor:

- SUB2API_PG_DSN, or -dsn-fd
- SUB2API_D1_CREDENTIAL_KEY, or -target-key-fd; this is the Worker's base64-encoded 32-byte CREDENTIAL_ENCRYPTION_KEY
- SUB2API_LEGACY_TOTP_KEY, or -legacy-totp-key-fd; this is the old 64-hex-character TOTP AES key
- SUB2API_CF_UPSTREAM_ALLOWED_HOSTS; this non-secret allowlist must accept every migrated account base URL

If both the environment variable and FD are supplied for one secret, the command fails. Secret values are not printed. Do not enable shell tracing. Use a secret manager or already-open private descriptors rather than putting assignments in shell history.

Every artifact path must be absolute. Final symlinks, directories, unresolved parents, hard-link aliases, and lexical or resolved aliases are rejected before a write. Keep all of these pairwise distinct: PostgreSQL source JSONL, source bundle, canonical bundle/manifest, import SQL, validation SQL, D1 pre-import export, and any retained validation output.

All local outputs are written through a mode-0600 temporary file, synced, and renamed only after success.

## 2. Repository-owned PostgreSQL snapshot

Run from backend in a clean canonical checkout:

~~~sh
go run ./cmd/cloudflare-migrate snapshot-postgres \
  -schema public \
  -out /absolute/private/postgresql-safe-snapshot.jsonl
~~~

An FD-based invocation is:

~~~sh
go run ./cmd/cloudflare-migrate snapshot-postgres \
  -dsn-fd 3 \
  -target-key-fd 4 \
  -legacy-totp-key-fd 5 \
  -schema public \
  -out /absolute/private/postgresql-safe-snapshot.jsonl \
  3</absolute/private/pg-dsn \
  4</absolute/private/d1-credential-key.base64 \
  5</absolute/private/legacy-totp-key.hex
~~~

The command:

1. begins a PostgreSQL transaction with isolation level REPEATABLE READ and READ ONLY and verifies both settings;
2. records txid_current_snapshot, server version, UTC capture time, schema name, and a deterministic schema_migrations filename/checksum digest;
3. reads pg_catalog.pg_tables in lexical order and checks information_schema.columns against the mapping profile before reading rows, so schema drift is rejected even for an empty transformed table;
4. emits every CoverageMatrix table exactly once, including absent or empty tables, then emits every unknown physical table;
5. orders every transformed table by its explicit primary key;
6. writes one canonical row per JSONL line, followed by row counts and SHA-256 digests for each table and a final whole-snapshot fingerprint;
7. rejects a nonempty unknown, blocked, or rebuild-only table.

The source stream is not raw pg_dump output. Sensitive legacy fields are transformed before a row is written:

- accounts.credentials must be plaintext JSONB for a supported api_key account. The transformer validates api_key and base_url against the canonical Worker URL/allowlist contract, then emits an AES-256-GCM envelope with prefix aes-gcm:v1:. The envelope has a random 12-byte IV and no AAD, matching deploy/cloudflare/src/credentials.ts. An OpenAI API-key account with no base_url uses the audited legacy default https://api.openai.com; other missing platform defaults fail closed.
- Legacy OAuth, cookie, setup-token, service-account, unknown credential fields, and unsupported base URL semantics fail with an account-specific actionable error. No external ETL is treated as a workaround.
- users.totp_secret_encrypted is decrypted as legacy base64(nonce+ciphertext+tag), validated as exactly 32 uppercase base32 characters, and re-encrypted with prefix aes-gcm:v1:totp: and AAD sub2api:totp:v1. Enabled TOTP requires both keys and enabled_at. A disabled user carrying a secret is blocked rather than silently losing it.
- api_keys.key is SHA-256 hashed in memory and only key_hash is emitted.
- Password hashes remain hashes. The command never decrypts or logs passwords.

AES-GCM IVs are intentionally random, so two fresh PostgreSQL snapshots do not have byte-identical ciphertext. Within one completed safe snapshot, ordering, canonical serialization, table hashes, bundle generation, and SQL generation are deterministic. The snapshot footer binds the exact randomized envelopes that were produced.

Legacy rows are checked against the pinned column contract. Unknown columns fail with a mapping-profile extension error. Known source-only fields are accepted only at explicitly coded safe defaults. Examples include zero frozen balance and API-key quota state, empty unsupported scheduling windows, default group policies, and default account rate state. Unknown money is never synthesized as zero.

## 3. Complete inventory and local bundle

The JSONL format is row-streamed:

~~~json
{"type":"source","format":"sub2api-postgresql-jsonl/v2","mapping_profile":"legacy-postgresql-to-d1-0008/v1","snapshot_id":"123:456:","schema_name":"public","server_version":"170000","migration_count":"42","migration_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","captured_at":"2026-09-09T00:00:00Z","complete_inventory":true}
{"type":"table","table":"groups","present":true}
{"type":"row","table":"groups","row":{"created_at":"2026-09-09T00:00:00Z","deleted_at":null,"id":"10","is_exclusive":false,"name":"default","platform":"openai","status":"active","subscription_type":"standard","updated_at":"2026-09-09T00:00:00Z"}}
{"type":"table_end","table":"groups","row_count":"1","sha256":"...64 lowercase hex..."}
{"type":"snapshot_end","table_count":"...","row_count":"...","sha256":"...64 lowercase hex..."}
~~~

A header-only file, missing table section, duplicate table, out-of-order table, missing table_end, missing snapshot_end, count mismatch, or hash mismatch is rejected. Every known CoverageMatrix source table must occur exactly once even when empty. An unknown empty table is retained as an explicit blocked warning; an unknown nonempty table is rejected.

Convert the completed safe snapshot:

~~~sh
go run ./cmd/cloudflare-migrate export \
  -source-jsonl /absolute/private/postgresql-safe-snapshot.jsonl \
  -out /absolute/private/source-bundle.json
~~~

The manifest includes format and mapping versions, PostgreSQL snapshot/migration fingerprints, complete source coverage with row counts and hashes, warnings/blockers, target dependency order, and bounded target chunks.

Hard capacity limits are deliberate:

- safe snapshot: 128 MiB total;
- bundle: 64 MiB total;
- one source/target row: 2 MiB;
- total rows: 1,000,000;
- rows per source table: 250,000;
- rows per target chunk: 2,000;
- approximate canonical data per target chunk: 4 MiB.

Rows are streamed in the source file and target tables are split into deterministic chunks. Bundle validation still holds the bounded bundle in memory. If a real database exceeds a bound, the tool returns an actionable capacity error; do not raise a limit ad hoc or split one snapshot by hand. Extend the format and its tests deliberately.

## 4. Strict validation and SQL generation

Use the same source file when planning. This proves that the supplied bundle was derived from that exact snapshot and lets the command reject source/bundle/output aliasing before any write:

~~~sh
go run ./cmd/cloudflare-migrate plan \
  -source-jsonl /absolute/private/postgresql-safe-snapshot.jsonl \
  -bundle /absolute/private/source-bundle.json \
  -canonical-bundle /absolute/private/canonical-bundle.json \
  -sql-plan /absolute/private/d1-import.sql \
  -validation-sql /absolute/private/d1-validate.sql
~~~

Validation includes exact lowercase SHA-256 syntax, canonical UTC RFC3339 timestamps, control-character rejection, JSON shape/canonicalization, nullability, unique and primary keys, foreign keys, API-key hash uniqueness, group restrictions, pricing references, immutable ledger arithmetic, exact E8 amounts, and decimal ID range 1 through 9223372036854775807. Empty notes is valid.

The import plan uses insert-if-absent plus exact row assertions. It never uses ON CONFLICT DO NOTHING. Row, chunk, and bundle provenance support identical replay. The generated remote file intentionally contains no BEGIN or COMMIT because local SQLite transaction behavior is not evidence of remote whole-file atomicity.

## 5. Local dry-run acceptance

Use explicit canonical files so a workspace containing protected duplicate artifacts is not package-scanned:

~~~sh
cd backend
go test -race \
  internal/cloudflaremigration/coverage.go \
  internal/cloudflaremigration/credentials.go \
  internal/cloudflaremigration/exporter.go \
  internal/cloudflaremigration/plan.go \
  internal/cloudflaremigration/postgres.go \
  internal/cloudflaremigration/toolkit.go \
  internal/cloudflaremigration/transform.go \
  internal/cloudflaremigration/credentials_test.go \
  internal/cloudflaremigration/plan_test.go \
  internal/cloudflaremigration/postgres_test.go \
  internal/cloudflaremigration/toolkit_test.go \
  internal/cloudflaremigration/transform_test.go
~~~

The plan test reads only exact canonical migrations 0001 through 0008, applies them to in-memory SQLite, executes the plan in one local outer transaction, replays it, injects a conflict, and proves local rollback. This is local tool evidence only.

The CLI tests must run in an isolated canonical-only module when duplicate user artifacts exist, because importing a Go package normally scans every Go file in that package directory. Do not run a package glob in such a workspace. A clean canonical checkout can run:

~~~sh
cd backend/cmd/cloudflare-migrate
go test -race main.go main_test.go
go vet main.go main_test.go
~~~

The synthetic tests use fake rows and keys and never require a live PostgreSQL server or real credentials.

## 6. Repository-pinned remote plan

remote-plan only prints JSON argv arrays. It validates that
`deploy/cloudflare/package.json` pins an exact Wrangler version, parses
`pnpm-lock.yaml`, and requires the root importer's Wrangler `specifier` and
resolved-version base (including a resolution with a peer-dependency suffix)
to match that exact package version. Merely having a lockfile is not accepted.
It also requires the explicit config to be inside the explicit working
directory:

~~~sh
go run ./cmd/cloudflare-migrate remote-plan \
  -ack I_HAVE_VERIFIED_A_D1_EXPORT_AND_ACCEPT_OPERATOR_OWNED_REMOTE_EXECUTION \
  -database operator-selected-d1-name \
  -deploy-dir /absolute/repository/deploy/cloudflare \
  -config /absolute/repository/deploy/cloudflare/wrangler.jsonc \
  -backup /absolute/private/d1-before.sql \
  -sql-plan /absolute/private/d1-import.sql \
  -validation-sql /absolute/private/d1-validate.sql
~~~

Printed commands begin with the repository-pinned form:

~~~text
pnpm exec wrangler --config /absolute/repository/deploy/cloudflare/wrangler.jsonc d1 ...
~~~

Run them with cwd set to the emitted working_directory. The tool never uses npx and cannot fetch an unpinned latest Wrangler.
The backup output must not already exist; this prevents a stale file from being mistaken for the pre-import recovery point. package.json, pnpm-lock.yaml, and the Wrangler config must be non-symlink regular files.

Cloudflare documents d1 export, d1 execute --file, d1 time-travel info, and d1 time-travel restore in the [D1 Wrangler command reference](https://developers.cloudflare.com/d1/wrangler-commands/). Cloudflare also states that Time Travel restore overwrites the database in place and is destructive; see [Time Travel and backups](https://developers.cloudflare.com/d1/reference/time-travel/).

## 7. Staging, import, verify, resume, and restore

No production operation is authorized by local tool acceptance.

Staging acceptance is mandatory:

1. Freeze PostgreSQL writes and all writers/background jobs for the snapshot window.
2. Produce the safe snapshot, bundle, SQL, and validation artifacts.
3. Apply only the separately accepted target schema to a staging D1 database.
4. Record a staging D1 export and current Time Travel bookmark.
5. Execute the reviewed import SQL with the emitted repository-pinned command.
6. Execute validation SQL and require zero failure rows.
7. Smoke-test password-hash login, TOTP, API-key lookup, account credential decryption, group restrictions, account scheduling, pricing activation, balances, and immutable ledger behavior without logging secrets.

For an authorized production attempt:

1. Confirm the D1 database identity and config.
2. Export D1 to the distinct pre-import path and hash the export.
3. run time-travel info and retain the exact pre-import bookmark outside transient logs;
4. recheck frozen PostgreSQL, staging evidence, bundle digest, warnings, and blockers;
5. execute the exact reviewed import file once;
6. execute the exact validation file.

Do not assume a whole remote Wrangler --file operation is atomic, and do not claim Cloudflare automatically restored an unknown or failed operation.

If command outcome is unknown, verify first. An exact bundle provenance value, exact counts, clean foreign-key check, and clean quick_check are success evidence. Missing bundle provenance is not proof that no statements ran. Inspect row/chunk provenance and target rows. If all existing rows are byte-equivalent and no divergence exists, an explicitly authorized replay of the exact same reviewed file is the resume path. Never regenerate the source and call that a resume.

If any row or provenance value diverges, stop writers and do not replay. Use the retained pre-import export for investigation and, only with explicit destructive authorization, restore D1 to the retained pre-import Time Travel bookmark. After D1 has accepted authoritative writes, reconcile post-cutover writes before selecting any restore point. An old export or bookmark is not automatically safe.

## 8. Historical scope

This page closes only the offline PostgreSQL path and the 0001–0008 mapping contract. Current canonical restore limitations and commands live in [MIGRATION.md](MIGRATION.md).
