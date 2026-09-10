import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { sha256 } from "../src/contracts";
import {
  AuthCacheRuntime,
  type AuthCacheOutboxEvent,
  safeUtc,
} from "../src/auth-cache-runtime";

const fixtureKey = "fixture-test-key";
const at = "2026-09-09T00:00:00.000Z";
const nowMs = Date.parse("2027-01-15T00:00:00.000Z");

const db = env.DB;

function runtime(database: D1Database = db, initialNow = nowMs) {
  let clock = initialNow;
  return {
    r: new AuthCacheRuntime(database, { now: () => clock, claim_lease_ms: 100 }),
    tick(ms: number) {
      clock += ms;
    },
  };
}

async function digest(value: string) {
  return sha256(value);
}

async function insertUser(id: string) {
  await db.prepare(
    `INSERT INTO users(
       id, status, role, concurrency, balance_e8_usd, allowed_group_ids_json,
       restrict_public_groups, created_at, updated_at, email, username, notes,
       rpm_limit, deleted_at
     )
     VALUES(?, 'active', 'user', 1, '0', '[]', 0, ?, ?, ?, ?, '', 0, NULL)`,
  )
    .bind(id, at, at, `auth-cache-${id}@example.test`, `auth-cache-${id}`)
    .run();
}

async function insertGroup(
  id: string,
  subscriptionType: "standard" | "subscription" = "standard",
) {
  await db.prepare(
    `INSERT INTO groups(
       id, name, platform, status, is_exclusive, subscription_type, created_at, updated_at
     )
     VALUES(?, ?, 'openai', 'active', 0, ?, ?, ?)`,
  )
    .bind(id, `auth-cache-${id}`, subscriptionType, at, at)
    .run();
}

async function insertKey(id: string, userId: string, groupId: string, key: string) {
  await db.prepare(
    `INSERT INTO api_keys(
       id, user_id, group_id, name, status, key_hash, ip_whitelist_json,
       ip_blacklist_json, expires_at, last_used_at, created_at, updated_at, deleted_at
     )
     VALUES(?, ?, ?, ?, 'active', ?, '[]', '[]', NULL, NULL, ?, ?, NULL)`,
  )
    .bind(id, userId, groupId, `auth-cache-${id}`, await digest(key), at, at)
    .run();
}

async function insertSubscription(
  id: string,
  userId = "1001",
  groupId = "2001",
  startsAt = "2026-01-01T00:00:00.000Z",
  expiresAt = "2028-01-01T00:00:00.000Z",
  status = "active",
  deletedAt: string | null = null,
) {
  await db.prepare(
    `INSERT INTO user_subscriptions(
       id, user_id, group_id, starts_at, expires_at, status, assigned_at,
       created_at, updated_at, deleted_at
     )
     VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(id, userId, groupId, startsAt, expiresAt, status, at, at, at, deletedAt)
    .run();
}

async function insertOutboxUser(eventId: string, entityId: string) {
  await db.prepare(
    "INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at) VALUES('user', ?, '1', ?)",
  ).bind(entityId, at).run();
  await db.prepare(
    "INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at) VALUES(?, 'user', ?, '1', ?)",
  ).bind(eventId, entityId, at).run();
}

function rowsOf<T extends Record<string, unknown>>(statement: D1PreparedStatement) {
  return statement.all<T>().then((result) => result.results);
}

describe("auth cache runtime", () => {
  it("applies canonical migration 0014 and keeps probe minimal", async () => {
    const seenSql: string[] = [];
    const wrapped = {
      prepare(sql: string) {
        seenSql.push(sql);
        return db.prepare(sql);
      },
      dump: db.dump?.bind(db),
      batch: db.batch.bind(db),
      exec: db.exec.bind(db),
    } as D1Database;

    const { r } = runtime(wrapped);
    await expect(r.resolve({ credential: fixtureKey })).resolves.toMatchObject({ ok: true });

    const probeSql = seenSql.find((sql) => sql.includes("AS credential_revision"));
    expect(probeSql).toBeDefined();
    expect(probeSql).not.toContain("allowed_group_ids_json");
    expect(probeSql).not.toContain("is_exclusive");
    expect(probeSql).not.toContain("subscription_type");
    expect(probeSql).not.toContain("user_subscriptions AS s");

    const fullSql = seenSql.find((sql) => sql.includes("WITH input(digest, now_utc)"));
    expect(fullSql).toBeDefined();
    expect(fullSql).toContain("allowed_group_ids_json");
    expect(fullSql).toContain("user_subscriptions AS s");
    expect(r.diagnosticMinimalProbeCount).toBe(1);
    expect(r.diagnosticFullLoadCount).toBe(1);

    const table = await db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='auth_cache_outbox'",
    ).first<{ name: string }>();
    expect(table?.name).toBe("auth_cache_outbox");
  });

  it("validates L1 hits against the current probe and retries full-load TOCTOU", async () => {
    const { r } = runtime();
    await expect(r.resolve({ credential: fixtureKey })).resolves.toMatchObject({ ok: true });

    const beforeLoads = r.diagnosticFullLoadCount;
    await expect(r.resolve({ credential: fixtureKey })).resolves.toMatchObject({ ok: true });
    expect(r.diagnosticFullLoadCount).toBe(beforeLoads);
    expect(r.diagnosticMinimalProbeCount).toBeGreaterThan(1);

    await db.prepare("UPDATE groups SET status='disabled', updated_at=? WHERE id='2001'")
      .bind(at)
      .run();
    await expect(r.resolve({ credential: fixtureKey })).resolves.toEqual({
      ok: false,
      code: "AUTH_NOT_FOUND",
    });
    expect(r.diagnosticFullLoadCount).toBeGreaterThan(beforeLoads);

    let mutated = false;
    const wrapped = {
      prepare(sql: string) {
        const statement = db.prepare(sql);
        if (!sql.includes("WITH input(digest, now_utc)")) return statement;
        return {
          bind(...bindings: unknown[]) {
            const bound = statement.bind(...bindings);
            return {
              async first<T = unknown>(column?: string) {
                if (!mutated) {
                  mutated = true;
                  await db.prepare("UPDATE groups SET status='active', updated_at=? WHERE id='2001'")
                    .bind(at)
                    .run();
                }
                return column === undefined ? bound.first<T>() : bound.first<T>(column);
              },
              all: bound.all.bind(bound),
              run: bound.run.bind(bound),
              raw: bound.raw.bind(bound),
            };
          },
          first: statement.first.bind(statement),
          all: statement.all.bind(statement),
          run: statement.run.bind(statement),
          raw: statement.raw.bind(statement),
        } as D1PreparedStatement;
      },
      dump: db.dump?.bind(db),
      batch: db.batch.bind(db),
      exec: db.exec.bind(db),
    } as D1Database;

    const y = runtime(wrapped);
    await expect(y.r.resolve({ credential: fixtureKey })).resolves.toMatchObject({ ok: true });
    expect(y.r.diagnosticFullLoadCount).toBe(2);
    expect(y.r.diagnosticMinimalProbeCount).toBe(2);
  });

  it("keeps independent isolate-local caches subordinate to D1 revisions", async () => {
    const first = runtime();
    const second = runtime();
    await expect(first.r.resolve({ credential: fixtureKey })).resolves.toMatchObject({ ok: true });
    await expect(second.r.resolve({ credential: fixtureKey })).resolves.toMatchObject({ ok: true });

    await db.prepare("UPDATE groups SET status='disabled', updated_at=? WHERE id='2001'")
      .bind(at)
      .run();
    await expect(first.r.resolve({ credential: fixtureKey })).resolves.toEqual({
      ok: false,
      code: "AUTH_NOT_FOUND",
    });
    await expect(second.r.resolve({ credential: fixtureKey })).resolves.toEqual({
      ok: false,
      code: "AUTH_NOT_FOUND",
    });
    expect(first.r.diagnosticMinimalProbeCount).toBeGreaterThan(1);
    expect(second.r.diagnosticMinimalProbeCount).toBeGreaterThan(1);
  });

  it("preserves standard public, restricted, exclusive, and subscription semantics", async () => {
    const { r } = runtime();

    await db.prepare(
      "UPDATE users SET allowed_group_ids_json='[]', restrict_public_groups=0, updated_at=? WHERE id='1001'",
    ).bind(at).run();
    await expect(r.resolve({ credential: fixtureKey })).resolves.toMatchObject({ ok: true });

    await db.prepare(
      "UPDATE users SET restrict_public_groups=1, updated_at=? WHERE id='1001'",
    ).bind(at).run();
    await expect(r.resolve({ credential: fixtureKey })).resolves.toEqual({
      ok: false,
      code: "AUTH_NOT_FOUND",
    });

    await db.prepare(
      "UPDATE users SET allowed_group_ids_json='[\"2001\"]', updated_at=? WHERE id='1001'",
    ).bind(at).run();
    await expect(r.resolve({ credential: fixtureKey })).resolves.toMatchObject({ ok: true });

    await db.prepare("UPDATE groups SET is_exclusive=1, updated_at=? WHERE id='2001'")
      .bind(at)
      .run();
    await db.prepare(
      "UPDATE users SET allowed_group_ids_json='[]', restrict_public_groups=0, updated_at=? WHERE id='1001'",
    ).bind(at).run();
    await expect(r.resolve({ credential: fixtureKey })).resolves.toEqual({
      ok: false,
      code: "AUTH_NOT_FOUND",
    });

    await db.prepare(
      "UPDATE groups SET is_exclusive=0, subscription_type='subscription', updated_at=? WHERE id='2001'",
    ).bind(at).run();
    await expect(r.resolve({ credential: fixtureKey })).resolves.toEqual({
      ok: false,
      code: "AUTH_NOT_FOUND",
    });

    await insertSubscription("9001");
    await expect(r.resolve({ credential: fixtureKey })).resolves.toMatchObject({ ok: true });

    await db.prepare("UPDATE user_subscriptions SET status='suspended', version=version+1 WHERE id='9001'")
      .run();
    await expect(r.resolve({ credential: fixtureKey })).resolves.toEqual({
      ok: false,
      code: "AUTH_NOT_FOUND",
    });
  });

  it("rejects future, expired, and deleted subscription windows", async () => {
    const { r } = runtime();
    await db.prepare(
      "UPDATE groups SET subscription_type='subscription', updated_at=? WHERE id='2001'",
    ).bind(at).run();

    await insertSubscription(
      "9002",
      "1001",
      "2001",
      "2028-01-01T00:00:00.000Z",
      "2029-01-01T00:00:00.000Z",
    );
    await expect(r.resolve({ credential: fixtureKey })).resolves.toEqual({
      ok: false,
      code: "AUTH_NOT_FOUND",
    });

    await db.prepare("UPDATE user_subscriptions SET deleted_at=? WHERE id='9002'")
      .bind(at)
      .run();
    await insertSubscription(
      "9003",
      "1001",
      "2001",
      "2025-01-01T00:00:00.000Z",
      "2026-01-01T00:00:00.000Z",
    );
    await expect(r.resolve({ credential: fixtureKey })).resolves.toEqual({
      ok: false,
      code: "AUTH_NOT_FOUND",
    });

    await db.prepare("UPDATE user_subscriptions SET deleted_at=? WHERE id='9003'")
      .bind(at)
      .run();
    await insertSubscription(
      "9004",
      "1001",
      "2001",
      "2026-01-01T00:00:00.000Z",
      "2028-01-01T00:00:00.000Z",
      "active",
      at,
    );
    await expect(r.resolve({ credential: fixtureKey })).resolves.toEqual({
      ok: false,
      code: "AUTH_NOT_FOUND",
    });
  });

  it("fails closed on hostile input and poisoned rebuild payloads", async () => {
    expect(safeUtc("2026-09-06T00:00:00.000Z")).toBe("2026-09-06T00:00:00.000Z");
    for (const bad of [
      "2026-02-30T00:00:00.000Z",
      "2026-09-06T00:00:00Z",
      "2026-09-06T00:00:00.12Z",
      "2026-09-06T00:00:00.000+00:00",
    ]) {
      expect(safeUtc(bad)).toBe(false);
    }

    const { r } = runtime();
    const hostile = [
      new Proxy({}, { ownKeys: () => { throw new Error("proxy trap"); } }),
      Object.defineProperty({}, "credential", {
        get() {
          throw new Error("getter trap");
        },
        enumerable: true,
      }),
      Object.defineProperty({ credential: fixtureKey }, "hidden", {
        value: true,
        enumerable: false,
      }),
      { credential: fixtureKey, [Symbol("extra")]: true },
      { credential: fixtureKey, requested_group_id: "01" },
      { credential: fixtureKey, requested_group_id: "9223372036854775808" },
      { credential: `ok${String.fromCharCode(0)}` },
    ];
    for (const value of hostile) {
      await expect(r.resolve(value)).resolves.toEqual({
        ok: false,
        code: "AUTH_INVALID_INPUT",
      });
    }

    await expect(r.resolve({ credential: fixtureKey })).resolves.toMatchObject({ ok: true });
    const saved = r.drain();
    const poisoned = saved.map((entry) => ({
      ...entry,
      projection: {
        ...(entry.projection as Record<string, unknown>),
        subscription_type: "standard",
        is_exclusive: false,
        restrict_public_groups: false,
        allowed_group_ids: ["9223372036854775807"],
      },
    }));

    await db.prepare(
      "UPDATE groups SET is_exclusive=1, subscription_type='standard', updated_at=? WHERE id='2001'",
    ).bind(at).run();
    await db.prepare(
      "UPDATE users SET allowed_group_ids_json='[]', updated_at=? WHERE id='1001'",
    ).bind(at).run();
    expect(await r.rebuild(poisoned)).toBe(true);
    await expect(r.resolve({ credential: fixtureKey })).resolves.toEqual({
      ok: false,
      code: "AUTH_NOT_FOUND",
    });
  });

  it("emits one complete digest/id-only outbox event per source mutation", async () => {
    await insertUser("1101");
    await insertUser("1102");
    await insertGroup("2101", "subscription");
    await insertGroup("2102", "subscription");
    await insertKey("3101", "1101", "2101", "source-key");
    await insertSubscription("9101", "1101", "2101");

    await db.prepare("UPDATE users SET notes='changed', updated_at=? WHERE id='1101'")
      .bind(at)
      .run();
    await db.prepare("UPDATE groups SET rate_multiplier_bps='11000', updated_at=? WHERE id='2101'")
      .bind(at)
      .run();
    const oldDigest = await digest("source-key");
    const newDigest = await digest("source-key-rotated");
    const beforeSameHashCredential = await db.prepare(
      "SELECT revision FROM auth_cache_credential_revisions WHERE credential_digest=?",
    ).bind(oldDigest).first<{ revision: string }>();
    await db.prepare("UPDATE api_keys SET name='same hash update', updated_at=? WHERE id='3101'")
      .bind(at)
      .run();
    const afterSameHashCredential = await db.prepare(
      "SELECT revision FROM auth_cache_credential_revisions WHERE credential_digest=?",
    ).bind(oldDigest).first<{ revision: string }>();
    expect(
      BigInt(afterSameHashCredential?.revision ?? "0") -
        BigInt(beforeSameHashCredential?.revision ?? "0"),
    ).toBe(1n);

    await db.prepare("UPDATE api_keys SET key_hash=?, updated_at=? WHERE id='3101'")
      .bind(newDigest, at)
      .run();

    const beforeSubscriptionRevision = await db.prepare(
      "SELECT revision FROM auth_cache_entity_revisions WHERE entity_type='subscription' AND entity_id='1101:2101'",
    ).first<{ revision: string }>();
    await db.prepare("UPDATE user_subscriptions SET notes='same identity', version=version+1 WHERE id='9101'")
      .run();
    const afterSubscriptionRevision = await db.prepare(
      "SELECT revision FROM auth_cache_entity_revisions WHERE entity_type='subscription' AND entity_id='1101:2101'",
    ).first<{ revision: string }>();
    expect(
      BigInt(afterSubscriptionRevision?.revision ?? "0") -
        BigInt(beforeSubscriptionRevision?.revision ?? "0"),
    ).toBe(1n);

    await db.prepare(
      "UPDATE user_subscriptions SET user_id='1102', group_id='2102', version=version+1 WHERE id='9101'",
    ).run();
    await db.prepare("DELETE FROM api_keys WHERE id='3101'").run();
    await db.prepare("DELETE FROM user_subscriptions WHERE id='9101'").run();
    await db.prepare("DELETE FROM groups WHERE id='2101'").run();
    await db.prepare("DELETE FROM groups WHERE id='2102'").run();
    await db.prepare("DELETE FROM users WHERE id='1101'").run();
    await db.prepare("DELETE FROM users WHERE id='1102'").run();

    const events = await rowsOf<{
      event_id: string;
      entity_type: string;
      entity_id: string;
      credential_digest: string | null;
      old_credential_digest: string | null;
      new_credential_digest: string | null;
      revision: string;
    }>(
      db.prepare(
        `SELECT event_id, entity_type, entity_id, credential_digest,
           old_credential_digest, new_credential_digest, revision
         FROM auth_cache_outbox
         WHERE entity_id IN ('1101', '1102', '2101', '2102', '3101', '1101:2101', '1102:2102', ?, ?)
         ORDER BY rowid`,
      ).bind(oldDigest, newDigest),
    );

    const byEntity = (entityType: string, entityId: string) =>
      events.filter((event) => event.entity_type === entityType && event.entity_id === entityId);
    expect(byEntity("user", "1101").map(({ revision }) => revision)).toEqual(["1", "2", "3"]);
    expect(byEntity("user", "1102").map(({ revision }) => revision)).toEqual(["1", "2"]);
    expect(byEntity("group", "2101").map(({ revision }) => revision)).toEqual(["1", "2", "3"]);
    expect(byEntity("group", "2102").map(({ revision }) => revision)).toEqual(["1", "2"]);
    expect(byEntity("subscription", "1101:2101").map(({ revision }) => revision))
      .toEqual(["1", "2", "3"]);
    expect(byEntity("subscription", "1102:2102").map(({ revision }) => revision))
      .toEqual(["1", "2"]);
    expect(byEntity("api_key", "3101")).toEqual([
      expect.objectContaining({
        credential_digest: oldDigest,
        old_credential_digest: null,
        new_credential_digest: oldDigest,
        revision: "1",
      }),
      expect.objectContaining({
        credential_digest: oldDigest,
        old_credential_digest: null,
        new_credential_digest: null,
        revision: "2",
      }),
      expect.objectContaining({
        credential_digest: newDigest,
        old_credential_digest: oldDigest,
        new_credential_digest: newDigest,
        revision: "3",
      }),
      expect.objectContaining({
        credential_digest: newDigest,
        old_credential_digest: newDigest,
        new_credential_digest: null,
        revision: "4",
      }),
    ]);
    expect(byEntity("credential", oldDigest)).toEqual([
      expect.objectContaining({
        credential_digest: oldDigest,
        old_credential_digest: null,
        new_credential_digest: oldDigest,
        revision: "1",
      }),
      expect.objectContaining({
        credential_digest: oldDigest,
        old_credential_digest: null,
        new_credential_digest: oldDigest,
        revision: "2",
      }),
      expect.objectContaining({
        credential_digest: oldDigest,
        old_credential_digest: oldDigest,
        new_credential_digest: null,
        revision: "3",
      }),
    ]);
    expect(byEntity("credential", newDigest)).toEqual([
      expect.objectContaining({
        credential_digest: newDigest,
        old_credential_digest: null,
        new_credential_digest: newDigest,
        revision: "1",
      }),
      expect.objectContaining({
        credential_digest: newDigest,
        old_credential_digest: newDigest,
        new_credential_digest: null,
        revision: "2",
      }),
    ]);
    for (const event of events) {
      expect(event.event_id).toMatch(/^[0-9a-f]{32}$/);
      if (event.entity_type === "credential") {
        expect(event.entity_id).toBe(event.credential_digest);
      }
      if (["user", "group", "subscription"].includes(event.entity_type)) {
        expect(event.credential_digest).toBeNull();
        expect(event.old_credential_digest).toBeNull();
        expect(event.new_credential_digest).toBeNull();
      }
    }
    expect(JSON.stringify(events)).not.toContain("source-key");
  });

  it("strictly rejects malformed numeric text, RFC3339 text, and overflow", async () => {
    await expect(db.prepare(
      "INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at) VALUES(?, 'user', '1', '1x', ?)",
    ).bind("a".repeat(32), at).run()).rejects.toThrow();
    await expect(db.prepare(
      "INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at) VALUES(?, 'user', '1', '9223372036854775808', ?)",
    ).bind("b".repeat(32), at).run()).rejects.toThrow();
    await expect(db.prepare(
      "INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at) VALUES(?, 'user', '1', '01', ?)",
    ).bind("c".repeat(32), at).run()).rejects.toThrow();
    await expect(db.prepare(
      "INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at) VALUES(?, 'user', '1', '1', '2026-09-09T00:00:00Z')",
    ).bind("d".repeat(32)).run()).rejects.toThrow();

    await db.prepare(
      "INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at) VALUES('user', '7000', '9223372036854775807', ?)",
    ).bind(at).run();
    await expect(db.prepare(
      "UPDATE auth_cache_entity_revisions SET revision=CAST(revision + 1 AS TEXT) WHERE entity_type='user' AND entity_id='7000'",
    ).run()).rejects.toThrow();

    await db.prepare(
      "INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at) VALUES('user', '7001', '9', ?)",
    ).bind(at).run();
    await expect(db.prepare(
      "UPDATE auth_cache_entity_revisions SET revision='1', updated_at=? WHERE entity_type='user' AND entity_id='7001'",
    ).bind(at).run()).rejects.toThrow();
    await expect(db.prepare(
      "UPDATE auth_cache_entity_revisions SET revision='11', updated_at=? WHERE entity_type='user' AND entity_id='7001'",
    ).bind(at).run()).rejects.toThrow();
    await expect(db.prepare(
      "UPDATE auth_cache_entity_revisions SET entity_id='7002', revision='10', updated_at=? WHERE entity_type='user' AND entity_id='7001'",
    ).bind(at).run()).rejects.toThrow();
    await expect(db.prepare(
      "DELETE FROM auth_cache_entity_revisions WHERE entity_type='user' AND entity_id='7001'",
    ).run()).rejects.toThrow();

    const guardDigest = "f".repeat(64);
    await db.prepare(
      "INSERT INTO auth_cache_credential_revisions(credential_digest, revision, updated_at) VALUES(?, '9', ?)",
    ).bind(guardDigest, at).run();
    await expect(db.prepare(
      "UPDATE auth_cache_credential_revisions SET revision='1', updated_at=? WHERE credential_digest=?",
    ).bind(at, guardDigest).run()).rejects.toThrow();
    await expect(db.prepare(
      "UPDATE auth_cache_credential_revisions SET revision='11', updated_at=? WHERE credential_digest=?",
    ).bind(at, guardDigest).run()).rejects.toThrow();
    await expect(db.prepare(
      "DELETE FROM auth_cache_credential_revisions WHERE credential_digest=?",
    ).bind(guardDigest).run()).rejects.toThrow();

    await db.prepare(
      "INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at) VALUES('user', '7003', '1', ?)",
    ).bind(at).run();
    await expect(db.prepare(
      `INSERT INTO auth_cache_outbox(
         event_id, entity_type, entity_id, revision, state, claim_version, created_at, published_at
       )
       VALUES(?, 'user', '7003', '1', 'published', '0', ?, ?)`,
    ).bind("9".repeat(32), at, at).run()).rejects.toThrow();
    await db.prepare(
      "INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at) VALUES(?, 'user', '7003', '1', ?)",
    ).bind("9".repeat(32), at).run();
    const sealed = runtime();
    const sealedClaim = await sealed.r.claimOutboxEvent("9".repeat(32));
    expect(sealedClaim).not.toBeNull();
    expect(await sealed.r.markPublished(
      "9".repeat(32),
      sealedClaim!.claim_token,
      sealedClaim!.claim_version,
    )).toBe(true);
    await expect(db.prepare(
      "UPDATE auth_cache_outbox SET state='claimed', claim_token=?, claim_expires_at=? WHERE event_id=?",
    ).bind("8".repeat(32), "2099-01-01T00:00:00.000Z", "9".repeat(32)).run())
      .rejects.toThrow();
    await expect(db.prepare(
      "UPDATE auth_cache_outbox SET entity_id='changed' WHERE event_id=?",
    ).bind("9".repeat(32)).run()).rejects.toThrow();
    await expect(db.prepare(
      "DELETE FROM auth_cache_outbox WHERE event_id=?",
    ).bind("9".repeat(32)).run()).rejects.toThrow();
    await expect(db.prepare(
      "INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, credential_digest, revision, created_at) VALUES(?, 'credential', 'not-a-digest', ?, '1', ?)",
    ).bind("7".repeat(32), "7".repeat(64), at).run()).rejects.toThrow();
    await expect(db.prepare(
      "INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, credential_digest, revision, created_at) VALUES(?, 'user', 'raw-user', ?, '1', ?)",
    ).bind("6".repeat(32), "6".repeat(64), at).run()).rejects.toThrow();
    await expect(db.prepare(
      "INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at) VALUES(?, 'user', '7004', '1', ?)",
    ).bind("5".repeat(32), at).run()).rejects.toThrow();
  });

  it("accepts only bounded, real UTC calendar timestamps in every authority field", async () => {
    await db.prepare(
      "INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at) VALUES('user', '7100', '1', ?)",
    ).bind("0000-02-29T00:00:00.000Z").run();
    await db.prepare(
      "INSERT INTO auth_cache_credential_revisions(credential_digest, revision, updated_at) VALUES(?, '1', ?)",
    ).bind("a".repeat(64), "9999-12-31T23:59:59.999Z").run();

    await expect(db.prepare(
      "INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at) VALUES('user', '7101', '1', '2027-02-29T00:00:00.000Z')",
    ).run()).rejects.toThrow();
    await expect(db.prepare(
      "INSERT INTO auth_cache_credential_revisions(credential_digest, revision, updated_at) VALUES(?, '1', '2027-13-01T00:00:00.000Z')",
    ).bind("b".repeat(64)).run()).rejects.toThrow();
    await expect(db.prepare(
      "INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at) VALUES('user', '7102', '1', '10000-01-01T00:00:00.000Z')",
    ).run()).rejects.toThrow();

    await db.prepare(
      "INSERT INTO auth_cache_entity_revisions(entity_type, entity_id, revision, updated_at) VALUES('user', '7103', '1', ?)",
    ).bind(at).run();
    await expect(db.prepare(
      "INSERT INTO auth_cache_outbox(event_id, entity_type, entity_id, revision, created_at) VALUES(?, 'user', '7103', '1', '2027-04-31T00:00:00.000Z')",
    ).bind("a".repeat(31) + "1").run()).rejects.toThrow();

    await insertOutboxUser("a".repeat(31) + "2", "7104");
    const claim = await runtime().r.claimOutboxEvent("a".repeat(31) + "2");
    expect(claim).not.toBeNull();
    await expect(db.prepare(
      `UPDATE auth_cache_outbox
       SET claim_expires_at = '2027-02-29T00:00:00.000Z',
           claim_version = CAST(claim_version + 1 AS TEXT)
       WHERE event_id = ?`,
    ).bind("a".repeat(31) + "2").run()).rejects.toThrow();
    await expect(db.prepare(
      `UPDATE auth_cache_outbox
       SET state = 'published', claim_token = NULL, claim_expires_at = NULL,
           claim_version = CAST(claim_version + 1 AS TEXT),
           published_at = '2027-02-29T00:00:00.000Z'
       WHERE event_id = ?`,
    ).bind("a".repeat(31) + "2").run()).rejects.toThrow();
    expect(await runtime().r.markPublished(
      "a".repeat(31) + "2",
      claim!.claim_token,
      claim!.claim_version,
    )).toBe(true);
  });

  it("uses leased at-least-once outbox delivery with fencing and crash recovery", async () => {
    const cleanup = runtime();
    for (let pass = 0; pass < 10; pass++) {
      if (await cleanup.r.drainOutbox(async () => {}, 100) === 0) break;
    }
    await insertOutboxUser("1".repeat(32), "9001");

    let blockFirstMark = true;
    const interruptedDb = {
      prepare(sql: string) {
        if (sql.includes("SET state = 'published'")) {
          const statement = db.prepare(sql);
          return {
            bind(...bindings: unknown[]) {
              const bound = statement.bind(...bindings);
              return {
                async run() {
                  if (blockFirstMark) {
                    blockFirstMark = false;
                    throw new Error("simulated D1 interruption before mark");
                  }
                  return bound.run();
                },
                first: bound.first.bind(bound),
                all: bound.all.bind(bound),
                raw: bound.raw.bind(bound),
              };
            },
            first: statement.first.bind(statement),
            all: statement.all.bind(statement),
            run: statement.run.bind(statement),
            raw: statement.raw.bind(statement),
          } as D1PreparedStatement;
        }
        return db.prepare(sql);
      },
      dump: db.dump?.bind(db),
      batch: db.batch.bind(db),
      exec: db.exec.bind(db),
    } as D1Database;

    const x = runtime(interruptedDb);
    const delivered: AuthCacheOutboxEvent[] = [];
    await expect(x.r.drainOutbox(async (event) => { delivered.push(event); }))
      .rejects.toThrow("simulated D1 interruption");
    expect(delivered).toEqual([
      expect.objectContaining({ event_id: "1".repeat(32), revision: "1" }),
    ]);
    const claimed = await db.prepare(
      "SELECT state, attempts, claim_version, published_at FROM auth_cache_outbox WHERE event_id=?",
    ).bind("1".repeat(32)).first<{
      state: string;
      attempts: number;
      claim_version: string;
      published_at: string | null;
    }>();
    expect(claimed).toEqual({
      state: "claimed",
      attempts: 1,
      claim_version: "1",
      published_at: null,
    });

    const y = runtime(db, nowMs + 200);
    expect(await y.r.drainOutbox(async (event) => { delivered.push(event); })).toBe(1);
    expect(delivered).toEqual([
      expect.objectContaining({ event_id: "1".repeat(32), revision: "1" }),
      expect.objectContaining({ event_id: "1".repeat(32), revision: "1" }),
    ]);
    const published = await db.prepare(
      "SELECT state, attempts, claim_version, published_at FROM auth_cache_outbox WHERE event_id=?",
    ).bind("1".repeat(32)).first<{
      state: string;
      attempts: number;
      claim_version: string;
      published_at: string | null;
    }>();
    expect(published?.state).toBe("published");
    expect(published?.attempts).toBe(2);
    expect(published?.claim_version).toBe("3");
    expect(published?.published_at).not.toBeNull();

    await insertOutboxUser("2".repeat(32), "9002");
    await expect(x.r.drainOutbox(async () => { throw new Error("crash-before-deliver"); }))
      .resolves.toBe(0);
    const pending = await db.prepare(
      "SELECT state, attempts FROM auth_cache_outbox WHERE event_id=?",
    ).bind("2".repeat(32)).first<{ state: string; attempts: number }>();
    expect(pending).toEqual({ state: "pending", attempts: 1 });

    const claim = await x.r.claimOutboxEvent("2".repeat(32));
    expect(claim).not.toBeNull();
    const renewed = await x.r.renewOutboxClaim(
      "2".repeat(32),
      claim!.claim_token,
      claim!.claim_version,
    );
    expect(renewed).not.toBeNull();
    expect(BigInt(renewed!.claim_version) - BigInt(claim!.claim_version)).toBe(1n);
    expect(await x.r.markPublished("2".repeat(32), claim!.claim_token, claim!.claim_version))
      .toBe(false);
    expect(await x.r.markPublished("2".repeat(32), renewed!.claim_token, renewed!.claim_version))
      .toBe(true);
    expect(await x.r.markPublished("2".repeat(32), renewed!.claim_token, renewed!.claim_version))
      .toBe(false);

    await insertOutboxUser("3".repeat(32), "9003");
    const firstClaim = await x.r.claimOutboxEvent("3".repeat(32));
    expect(firstClaim).not.toBeNull();
    const takeover = await y.r.claimOutboxEvent("3".repeat(32));
    expect(takeover).not.toBeNull();
    expect(takeover!.claim_token).not.toBe(firstClaim!.claim_token);
    expect(await y.r.markPublished(
      "3".repeat(32),
      firstClaim!.claim_token,
      firstClaim!.claim_version,
    )).toBe(false);
    expect(await y.r.markPublished(
      "3".repeat(32),
      takeover!.claim_token,
      takeover!.claim_version,
    )).toBe(true);

    await insertOutboxUser("5".repeat(32), "9005");
    const expiredClaim = await x.r.claimOutboxEvent("5".repeat(32));
    expect(expiredClaim).not.toBeNull();
    x.tick(200);
    expect(await x.r.markPublished(
      "5".repeat(32),
      expiredClaim!.claim_token,
      expiredClaim!.claim_version,
    )).toBe(false);
    const replayed: AuthCacheOutboxEvent[] = [];
    expect(await y.r.drainOutbox(async (event) => { replayed.push(event); })).toBe(1);
    expect(replayed).toEqual([
      expect.objectContaining({ event_id: "5".repeat(32), revision: "1" }),
    ]);
  });

  it("uses a fresh post-delivery authority time and one clock read per claim helper", async () => {
    await insertOutboxUser("b".repeat(32), "9101");
    let clock = nowMs;
    let reads = 0;
    const narrowedDb = {
      prepare(sql: string) {
        if (sql.includes("ORDER BY created_at, event_id")) {
          return {
            bind() {
              return { all: async <T>() => ({ results: [{ event_id: "b".repeat(32) } as T] }) };
            },
          } as D1PreparedStatement;
        }
        return db.prepare(sql);
      },
      dump: db.dump?.bind(db),
      batch: db.batch.bind(db),
      exec: db.exec.bind(db),
    } as D1Database;
    const r = new AuthCacheRuntime(narrowedDb, {
      now: () => {
        reads += 1;
        return clock;
      },
      claim_lease_ms: 100,
    });

    const beforeDrain = reads;
    expect(await r.drainOutbox(async () => { clock += 50; })).toBe(1);
    expect(reads - beforeDrain).toBe(3);
    const published = await db.prepare(
      "SELECT published_at FROM auth_cache_outbox WHERE event_id=?",
    ).bind("b".repeat(32)).first<{ published_at: string }>();
    expect(published?.published_at).toBe(new Date(nowMs + 50).toISOString());

    await insertOutboxUser("c".repeat(32), "9102");
    const beforeClaim = reads;
    const claim = await r.claimOutboxEvent("c".repeat(32));
    expect(claim).not.toBeNull();
    expect(reads - beforeClaim).toBe(1);
    const beforeRenew = reads;
    const renewed = await r.renewOutboxClaim(
      "c".repeat(32),
      claim!.claim_token,
      claim!.claim_version,
    );
    expect(renewed).not.toBeNull();
    expect(reads - beforeRenew).toBe(1);
    const beforeMark = reads;
    expect(await r.markPublished(
      "c".repeat(32),
      renewed!.claim_token,
      renewed!.claim_version,
    )).toBe(true);
    expect(reads - beforeMark).toBe(1);

    await insertOutboxUser("d".repeat(32), "9103");
    const releasable = await r.claimOutboxEvent("d".repeat(32));
    expect(releasable).not.toBeNull();
    const beforeRelease = reads;
    expect(await r.releaseClaim(
      "d".repeat(32),
      releasable!.claim_token,
      releasable!.claim_version,
    )).toBe(true);
    expect(reads - beforeRelease).toBe(1);
    const cleanup = runtime();
    const cleanupClaim = await cleanup.r.claimOutboxEvent("d".repeat(32));
    expect(cleanupClaim).not.toBeNull();
    expect(await cleanup.r.markPublished(
      "d".repeat(32),
      cleanupClaim!.claim_token,
      cleanupClaim!.claim_version,
    )).toBe(true);
  });

  it("recovers an expired final-attempt crash to dead without stale-token regression", async () => {
    const eventId = "e".repeat(32);
    const x = runtime();
    await insertOutboxUser(eventId, "9201");
    for (let attempt = 0; attempt < 31; attempt += 1) {
      const claim = await x.r.claimOutboxEvent(eventId);
      expect(claim).not.toBeNull();
      expect(await x.r.releaseClaim(eventId, claim!.claim_token, claim!.claim_version)).toBe(true);
    }
    const finalClaim = await x.r.claimOutboxEvent(eventId);
    expect(finalClaim).not.toBeNull();
    const claimed = await db.prepare(
      "SELECT state, attempts FROM auth_cache_outbox WHERE event_id=?",
    ).bind(eventId).first<{ state: string; attempts: number }>();
    expect(claimed).toEqual({ state: "claimed", attempts: 32 });

    x.tick(100);
    const recoveryDb = {
      prepare(sql: string) {
        if (sql.includes("ORDER BY created_at, event_id")) {
          return { bind: () => ({ all: async () => ({ results: [] }) }) } as unknown as D1PreparedStatement;
        }
        return db.prepare(sql);
      },
      dump: db.dump?.bind(db),
      batch: db.batch.bind(db),
      exec: db.exec.bind(db),
    } as D1Database;
    expect(await runtime(recoveryDb, nowMs + 100).r.drainOutbox(async () => {})).toBe(0);
    expect(await x.r.markPublished(
      eventId,
      finalClaim!.claim_token,
      finalClaim!.claim_version,
    )).toBe(false);
    expect(await x.r.releaseClaim(
      eventId,
      finalClaim!.claim_token,
      finalClaim!.claim_version,
    )).toBe(false);
    expect(await x.r.claimOutboxEvent(eventId)).toBeNull();
    const recovered = await db.prepare(
      "SELECT state, attempts, claim_token, claim_expires_at, published_at FROM auth_cache_outbox WHERE event_id=?",
    ).bind(eventId).first<{
      state: string;
      attempts: number;
      claim_token: string | null;
      claim_expires_at: string | null;
      published_at: string | null;
    }>();
    expect(recovered).toEqual({
      state: "dead",
      attempts: 32,
      claim_token: null,
      claim_expires_at: null,
      published_at: null,
    });
  });

  it("does not deliver stale pre-claim payload when live claim reread is corrupt", async () => {
    await insertOutboxUser("4".repeat(32), "9004");

    let corruptRead = true;
    const wrapped = {
      prepare(sql: string) {
        const statement = db.prepare(sql);
        if (sql.includes("ORDER BY created_at, event_id")) {
          return {
            bind() {
              return {
                async all<T = unknown>() {
                  return { results: [{ event_id: "4".repeat(32) } as T] };
                },
              } as D1PreparedStatement;
            },
          } as D1PreparedStatement;
        }
        if (sql.includes("WHERE event_id = ?") && sql.includes("AND state = 'claimed'")) {
          return {
            bind(...bindings: unknown[]) {
              const bound = statement.bind(...bindings);
              return {
                async first<T = unknown>() {
                  if (corruptRead) {
                    corruptRead = false;
                    return {
                      event_id: "4".repeat(32),
                      entity_type: "user",
                      entity_id: "not-a-source-id",
                      credential_digest: null,
                      old_credential_digest: null,
                      new_credential_digest: null,
                      revision: "1",
                      state: "claimed",
                      claim_token: "4".repeat(32),
                      claim_version: "1",
                      claim_expires_at: "2027-01-15T00:00:00.100Z",
                    } as T;
                  }
                  return bound.first<T>();
                },
                all: bound.all.bind(bound),
                run: bound.run.bind(bound),
                raw: bound.raw.bind(bound),
              };
            },
            first: statement.first.bind(statement),
            all: statement.all.bind(statement),
            run: statement.run.bind(statement),
            raw: statement.raw.bind(statement),
          } as D1PreparedStatement;
        }
        return statement;
      },
      dump: db.dump?.bind(db),
      batch: db.batch.bind(db),
      exec: db.exec.bind(db),
    } as D1Database;

    const delivered: AuthCacheOutboxEvent[] = [];
    const { r } = runtime(wrapped);
    expect(await r.drainOutbox(async (event) => { delivered.push(event); })).toBe(0);
    expect(delivered).toEqual([]);
  });

  it("rolls back auth-cache side effects when a source transaction fails", async () => {
    await expect(db.exec(`
      INSERT INTO users(
        id, status, role, concurrency, balance_e8_usd, allowed_group_ids_json,
        restrict_public_groups, created_at, updated_at, email, username, notes,
        rpm_limit, deleted_at
      )
      VALUES(
        '1201', 'active', 'user', 1, '0', '[]', 0,
        '2026-09-09T00:00:00.000Z', '2026-09-09T00:00:00.000Z',
        'rollback@example.test', 'rollback', '', 0, NULL
      );
      INSERT INTO api_keys(
        id, user_id, group_id, name, status, key_hash, ip_whitelist_json,
        ip_blacklist_json, expires_at, last_used_at, created_at, updated_at, deleted_at
      )
      VALUES(
        '3201', '1201', 'missing-group', 'rollback', 'active',
        '${"e".repeat(64)}', '[]', '[]', NULL, NULL,
        '2026-09-09T00:00:00.000Z', '2026-09-09T00:00:00.000Z', NULL
      );
    `)).rejects.toThrow();

    const revisions = await db.prepare(
      "SELECT COUNT(*) AS count FROM auth_cache_entity_revisions WHERE entity_id IN ('1201', '3201')",
    ).first<{ count: number }>();
    const events = await db.prepare(
      "SELECT COUNT(*) AS count FROM auth_cache_outbox WHERE entity_id IN ('1201', '3201')",
    ).first<{ count: number }>();
    expect(revisions?.count).toBe(0);
    expect(events?.count).toBe(0);
  });
});
