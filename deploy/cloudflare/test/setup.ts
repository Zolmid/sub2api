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
  // Full-chain test setup applies 0002 before the fixture import. The CLI
  // upgrade assertion exercises 0001 fixture -> 0002 separately; here we give
  // the fixture rows the post-migration invariant expected by runtime readers.
  await testEnv.DB.exec(`
    UPDATE users SET updated_at=created_at WHERE updated_at='';
    UPDATE groups SET updated_at=created_at WHERE updated_at='';
    UPDATE api_keys SET updated_at=created_at WHERE updated_at='';
    UPDATE accounts SET updated_at=created_at WHERE updated_at='';
  `);
}

await resetFixture();
beforeEach(resetFixture);
