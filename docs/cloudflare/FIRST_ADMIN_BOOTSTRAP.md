# Offline first-administrator bootstrap

`backend/cmd/cloudflare-first-admin` is the only supported bootstrap path for a
brand-new Cloudflare D1 installation. It is an operator-run, out-of-band
command ("offline" relative to the application HTTP control plane); it does
not add or enable an HTTP setup endpoint. Remote mode still connects to D1.

It refuses to mutate unless D1 reports the `2026-09-06.v1` bridge metadata,
the complete Stage C `users` shape (including `email`, `password_hash`,
`username`, `notes`, `rpm_limit`, `updated_at`, and `deleted_at`), the partial
unique `users_email_live_idx`, and zero rows in `users`. The insert repeats the
empty-table/schema guards, so a preflight race cannot overwrite or reset an
existing account. It creates one active `admin` with ID `1` unless `-id` is
supplied. IDs and balances are decimal TEXT; IDs must be positive Go `int64`
values and are intentionally never converted to JavaScript numbers.

The password has no default, must contain 20 through 72 bytes (bcrypt's input
limit), and is read twice from a real TTY with echo disabled. The command
accepts no password argument or environment variable. It invokes the
repository's pinned Wrangler executable with an argv array. The bcrypt hash is
supplied only through temporary mode-0600 SQL files for the guarded insert and
exact comparison. Both files are removed after their command; the hash is never
placed in `--command`, process argv, stderr, or Wrangler JSON output. The insert
must return the requested ID, and readback returns only a hash-match boolean. A
temporary-file cleanup failure is fatal and reported without exposing contents.

Install the pinned `deploy/cloudflare` dependencies first. From `backend/`,
perform a read-only local check against an isolated Wrangler state directory:

```sh
go run ./cmd/cloudflare-first-admin -inspect-local \
  -persist-to /private/tmp/sub2api-cf-state
```

Only after the inspection is clean, explicitly create the local first admin:

```sh
go run ./cmd/cloudflare-first-admin -apply-local \
  -persist-to /private/tmp/sub2api-cf-state \
  -email admin@example.com -id 1
```

Remote mutation is deliberately more conspicuous. Before it, export a D1
backup to an operator-controlled secure location and independently verify the
export; `d1 export` requires an explicit `--output` path. Do not put the backup
inside this repository. Example operator command (not run by this task):

```sh
cd deploy/cloudflare
pnpm exec wrangler d1 export sub2api-cloudflare --remote \
  --config wrangler.jsonc --output /secure/operator-path/sub2api-d1.sql
```

Only then may an authorized operator run the guarded remote action from
`backend/` (the acknowledgement is intentionally exact):

```sh
go run ./cmd/cloudflare-first-admin -apply-remote \
  -email admin@example.com -id 1 \
  -remote-acknowledgement I_HAVE_EXPORTED_A_D1_BACKUP_AND_ACCEPT_REMOTE_FIRST_ADMIN_BOOTSTRAP
```

Any preflight mismatch, existing user, malformed Wrangler JSON, command error,
or failed readback is a failure. A command error after apply is reported as
**uncertain** after one conservative readback; the tool never retries or claims
success. Inspect or restore from the verified backup before another operator
action.

No local or remote D1/Wrangler mutation was executed while adding this tool.
