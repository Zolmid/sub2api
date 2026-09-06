import { readFileSync } from "node:fs";
import {
  cloudflarePool,
  cloudflareTest,
  readD1Migrations,
} from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const workerOptions = async () => ({
  wrangler: { configPath: "./wrangler.test.jsonc" },
  miniflare: {
    bindings: {
      TEST_MIGRATIONS: await readD1Migrations(
        new URL("./migrations", import.meta.url).pathname,
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
