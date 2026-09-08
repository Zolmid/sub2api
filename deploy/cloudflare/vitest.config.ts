import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  cloudflarePool,
  cloudflareTest,
} from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const migrationDirectory = process.env.SUB2API_CF_TEST_MIGRATIONS_DIR ??
  new URL("./migrations", import.meta.url).pathname;
const isolatedDatabaseID = process.env.SUB2API_CF_TEST_DATABASE_ID;

async function readCanonicalD1Migrations(migrationsPath: string) {
  const { unstable_splitSqlQuery } = await import("wrangler");
  const names = readdirSync(migrationsPath, { withFileTypes: true })
    .filter((entry) =>
      entry.isFile() && /^\d{4}_[a-z0-9][a-z0-9_-]*\.sql$/.test(entry.name)
    )
    .map((entry) => entry.name)
    .sort((left, right) => left.localeCompare(right));
  const migrationNumbers = new Set<string>();

  return names.map((name) => {
    const migrationNumber = name.slice(0, 4);
    if (migrationNumbers.has(migrationNumber)) {
      throw new Error(`duplicate canonical D1 migration number: ${migrationNumber}`);
    }
    migrationNumbers.add(migrationNumber);
    return {
      name,
      queries: unstable_splitSqlQuery(
        readFileSync(join(migrationsPath, name), "utf8"),
      ),
    };
  });
}

const workerOptions = async () => ({
  wrangler: { configPath: "./wrangler.test.jsonc" },
  miniflare: {
    ...(isolatedDatabaseID
      ? { d1Databases: { DB: isolatedDatabaseID } }
      : {}),
    bindings: {
      // Explicit local-only value; production receives this binding through
      // Worker secrets and no wrangler vars file contains it.
      SUB2API_CF_JWT_SECRET: "test-only-cloudflare-jwt-secret-32-bytes",
      // A fixed test-only 32-byte base64 key. Production must set its own
      // Worker secret and is never represented in this configuration.
      SUB2API_CF_LOGIN_ADMISSION_KEY: "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
      CREDENTIAL_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      TEST_MIGRATIONS: await readCanonicalD1Migrations(migrationDirectory),
      TEST_FIXTURE_SQL: readFileSync(
        new URL("./fixtures/local.sql", import.meta.url),
        "utf8",
      )
        .split("\n")
        .filter((line) => !line.trimStart().startsWith("--"))
        .join("\n"),
    },
  },
});

export default defineConfig({
  plugins: [cloudflareTest(workerOptions)],
  test: {
    pool: cloudflarePool(workerOptions),
    setupFiles: ["./test/setup.ts"],
    fileParallelism: false,
    testTimeout: 10_000,
  },
});
