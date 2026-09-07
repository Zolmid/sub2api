import { env } from "cloudflare:test";
import { applyD1Migrations, type D1Migration } from "cloudflare:test";
import { beforeEach } from "vitest";

type TestEnv = Env & {
  TEST_MIGRATIONS: D1Migration[];
  TEST_FIXTURE_SQL: string;
};

const testEnv = env as TestEnv;
await applyD1Migrations(testEnv.DB, testEnv.TEST_MIGRATIONS);

async function resetFixture(): Promise<void> {
  await testEnv.DB.exec(`
  DELETE FROM outbox_conflicts;
  DELETE FROM usage_events;
  DELETE FROM outbox_events;
  DELETE FROM gateway_requests;
  DELETE FROM management_operations;
  DELETE FROM account_groups;
  DELETE FROM api_keys;
  DELETE FROM accounts;
  DELETE FROM users;
  DELETE FROM groups;
  DELETE FROM model_aliases;
`);
  await testEnv.DB.exec(testEnv.TEST_FIXTURE_SQL);
}

await resetFixture();
beforeEach(resetFixture);
