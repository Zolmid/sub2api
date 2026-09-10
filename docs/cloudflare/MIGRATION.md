# PostgreSQL to D1 offline migration and restore

`cloudflare-migrate` prepares a fail-closed, offline legacy PostgreSQL snapshot, a canonical restore bundle, deterministic SQL, and read-only validation SQL. It never creates Cloudflare resources, calls D1, deploys, cuts over traffic, or performs a rollback.

The locked traditional deployment is unchanged. The original `snapshot-postgres`, `export`, and `plan` commands retain their `legacy-postgresql-to-d1-0008/v1` contract. Use the explicit `-0017` commands below for the additive `legacy-postgresql-to-d1-0017/v1` profile and canonical migrations `0001_initial.sql` through `0017_email_runtime.sql`.

## Mapping boundary

The 0017 profile copies or deterministically transforms every legacy field that has an equivalent canonical D1 authority:

- `groups`, `users` plus `user_allowed_groups`, `accounts`, `account_groups`, `api_keys`, and `model_aliases` map to their canonical tables. Decimal group `rate_multiplier` is represented exactly as `rate_multiplier_bps`; an inexact, non-positive, or out-of-range value is rejected.
- `subscription_plans` and `user_subscriptions` copy all legacy persistent fields. Money and usage are converted exactly to E8 text. The legacy source has no plan relation or per-subscription limit fields, so those fields are `NULL`; `version` is initialized to `1`. A present legacy weekly or monthly window gets the explicit `legacy_initial` anchor kind. No plan ID, limit, or anchor date is invented.
- `pricing_versions`, `pricing_rules`, `pricing_active_version`, and `balance_ledger` retain the established exact E8 mapping.
- `schema_migrations` is evidence for the source fingerprint, not target data.
- Non-empty legacy `settings`, `payment_orders`, or `payment_audit_logs` are blocked. Their 0015/0016 D1 authorities require encrypted or immutable runtime evidence that cannot be inferred safely from the legacy rows. Unknown non-empty tables are also blocked.

All target-only runtime/audit/outbox tables introduced through 0017 are declared in the bundle as either `empty-before-import` or `trigger-managed-from-source-inserts`. The planner verifies that declared operational state is pristine before a first import. It explicitly initializes `users.balance_version=0`, `accounts.credential_version=1`, and `accounts.credential_fingerprint=NULL` through canonical column defaults. An identical replay is permitted only after the bundle digest provenance has been accepted.

## Private artifact rules

Use a private directory outside the repository. Every input and output must have a unique absolute path. Do not put the PostgreSQL DSN or encryption keys in positional arguments, filenames, logs, or generated artifacts. New 0017 outputs refuse to overwrite existing paths.

The PostgreSQL snapshot uses one `REPEATABLE READ, READ ONLY` transaction. It inventories tables and exact columns, exports rows in deterministic order, and binds counts and SHA-256 digests to the source migration fingerprint. Credentials and TOTP material require the same secret-source contract as the established exporter: `SUB2API_PG_DSN`, `SUB2API_D1_CREDENTIAL_KEY`, `SUB2API_LEGACY_TOTP_KEY`, optional `SUB2API_CF_UPSTREAM_ALLOWED_HOSTS`, or the corresponding inherited file-descriptor flags.

## 1. Capture and export the 0017 bundle

Run from `backend/` after an approved source-write freeze:

```sh
go run ./cmd/cloudflare-migrate snapshot-postgres-0017 \
  -schema public \
  -out /absolute/private/postgresql-0017.jsonl

go run ./cmd/cloudflare-migrate export-0017 \
  -source-jsonl /absolute/private/postgresql-0017.jsonl \
  -out /absolute/private/source-0017.json
```

`snapshot-postgres-0017` fails if a mapped table's exact canonical legacy column set differs, if a blocked/unknown table is non-empty, or if a source value cannot be represented without loss. `export-0017` rechecks stream ordering, completeness, row/table bounds, source fingerprints, digests, relationships, and the complete 0001–0017 target manifest.

## 2. Bind the reviewed bundle to its source and build the plan

```sh
go run ./cmd/cloudflare-migrate plan-0017 \
  -source-jsonl /absolute/private/postgresql-0017.jsonl \
  -bundle /absolute/private/source-0017.json \
  -canonical-bundle /absolute/private/canonical-0017.json \
  -sql-plan /absolute/private/d1-restore-0017.sql \
  -validation-sql /absolute/private/d1-validate-0017.sql
```

The source is independently re-exported in memory and must byte-match the canonicalized bundle. The three outputs are staged as mode `0600`; if staging or publication fails, this invocation removes every output published by that invocation. If the filesystem refuses cleanup, the command reports cleanup as incomplete and the requested paths must be inspected before retrying. This is artifact-level failure atomicity, not a claim that remote D1 executes an entire SQL file atomically.

The generated SQL verifies the installed 0001–0017 schema, operational-table preconditions, exact source-backed rows, exact table counts, foreign keys, per-row/per-chunk provenance, and the canonical bundle digest. Replaying the identical SQL is idempotent. A different existing row, a non-pristine first-import runtime table, or a mismatched bundle fails closed.

## 3. Upgrade an already canonical 0001–0008 bundle

If the earlier canonical bundle proves that `subscription_plans` and `user_subscriptions` were empty, it can be upgraded without rereading PostgreSQL:

```sh
go run ./cmd/cloudflare-migrate upgrade-0017 \
  -bundle /absolute/private/canonical-0008.json \
  -out /absolute/private/upgraded-0017.json \
  -sql-plan /absolute/private/upgraded-d1-restore-0017.sql \
  -validation-sql /absolute/private/upgraded-d1-validate-0017.sql
```

The upgrade adds the pinned 0009–0017 migration manifest, explicit operational initialization, the canonical group multiplier default equivalent to the old mapping, and empty subscription chunks, then atomically publishes the upgraded bundle and its SQL pair. It refuses a legacy bundle that reports omitted subscription rows. This command cannot recover fields that were absent from an old bundle; use a fresh 0017 snapshot whenever those legacy tables contain data or when current source evidence is required. An upgraded bundle is not accepted by `plan-0017` against a newly generated source snapshot unless the complete canonical manifests match.

## 4. Local acceptance

Run focused tests in a clean checkout or a safe exported tree that cannot contain user duplicate artifacts:

```sh
cd backend
go test -race ./internal/cloudflaremigration ./cmd/cloudflare-migrate
```

The tests fingerprint all 17 canonical migration files, apply them to local SQLite, account for every canonical persistent table, execute and replay a restore transaction, inject schema/version/corruption/operational-state failures, and verify failed multi-output publication leaves no partial accepted result. Local tests are not staging or production verification.

## 5. Operator-owned remote procedure

After a separate staging database has canonical migrations 0001–0017 applied, use `remote-plan` to print repository-pinned Wrangler argv. It still does not execute them:

```sh
go run ./cmd/cloudflare-migrate remote-plan \
  -ack I_HAVE_VERIFIED_A_D1_EXPORT_AND_ACCEPT_OPERATOR_OWNED_REMOTE_EXECUTION \
  -database operator-selected-d1-name \
  -deploy-dir /absolute/repository/deploy/cloudflare \
  -config /absolute/repository/deploy/cloudflare/wrangler.jsonc \
  -backup /absolute/private/d1-before.sql \
  -sql-plan /absolute/private/d1-restore-0017.sql \
  -validation-sql /absolute/private/d1-validate-0017.sql
```

Before any import, an authorized operator must verify the target identity, create and retain a distinct D1 export and Time Travel bookmark, review the exact bundle digest and SQL, and ensure target source-backed tables are empty. Execute the reviewed import and validation files exactly as approved. Validation success returns no failure rows.

## Resumption and recovery

Treat interruption as unknown. Stop writers and inspect D1. Replay only the exact reviewed SQL when the stored bundle digest and all target rows/provenance are identical. If they differ, do not merge, regenerate, or hand-edit the plan; retain the pre-import export and logs and choose an explicitly reviewed recovery.

D1 Time Travel restore is destructive and operator-owned. It is not automatic rollback, and it is unsafe after post-import writes unless those writes are reconciled. Configuration rollback also cannot undo D1 writes. Keep traditional PostgreSQL/Redis authoritative until independent staging acceptance and a separately authorized production cutover are complete.
