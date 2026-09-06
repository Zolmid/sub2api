import { env } from "cloudflare:test";
import { applyD1Migrations, type D1Migration } from "cloudflare:test";

type TestEnv = Env & {
  TEST_MIGRATIONS: D1Migration[];
  TEST_FIXTURE_SQL: string;
};

const testEnv = env as TestEnv;
await applyD1Migrations(testEnv.DB, testEnv.TEST_MIGRATIONS);
await testEnv.DB.exec(testEnv.TEST_FIXTURE_SQL);
