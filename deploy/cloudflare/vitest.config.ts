import { readFileSync } from "node:fs";
import {
  cloudflarePool,
  cloudflareTest,
  readD1Migrations,
} from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const migrationDirectory = process.env.SUB2API_CF_TEST_MIGRATIONS_DIR ??
  new URL("./migrations", import.meta.url).pathname;
const isolatedDatabaseID = process.env.SUB2API_CF_TEST_DATABASE_ID;

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
      TEST_MIGRATIONS: await readD1Migrations(
        migrationDirectory,
      ),
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
