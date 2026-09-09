import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  MAX_REFRESH_COUNTER,
  beginRefreshAttempt,
  commitRefreshSuccess,
  expireRefreshAttempt,
  fingerprintCredentialEnvelope,
  initializeCredentialFingerprint,
  markProviderStarted,
  recoverInvalidGrantRace,
  transitionOAuthRefreshLease,
  type OAuthRefreshLeaseState,
} from "../src/oauth-refresh-runtime";

const db = env.DB;
const NOW = 1_700_000_000_000;
let sequence = 0;

type Record = { id: string; envelope: string; fingerprint: string; version: number };

// The shared canonical setup now loads 0013. It owns snapshot/reset lifecycle;
// this file never creates, drops, or weakens migration tables or triggers.
async function account(type = "oauth"): Promise<Record> {
  sequence += 1;
  const id = String(8_000_000_000_000_000 + sequence);
  const envelope = `test-envelope-${sequence}`;
  const fingerprint = await fingerprintCredentialEnvelope(envelope);
  await db.prepare(`INSERT INTO accounts(
    id,name,platform,type,status,schedulable,priority,max_concurrency,
    credential_envelope,extra_json,created_at,credential_version,credential_fingerprint
  ) VALUES(?,?,? ,?,'active',1,0,1,?,'{}','test',1,?)`)
    .bind(id, `account-${sequence}`, "test", type, envelope, fingerprint).run();
  return { id, envelope, fingerprint, version: 1 };
}

function authority(record: Record, operationId: string, options: Partial<{
  owner: string; fence: number; nowMs: number;
}> = {}) {
  return {
    accountId: record.id, expectedCredentialVersion: record.version,
    expectedCredentialFingerprint: record.fingerprint, operationId,
    owner: options.owner ?? "worker-a", fence: options.fence ?? 1, nowMs: options.nowMs ?? NOW,
  };
}

function begin(record: Record, operationId: string, options: Partial<{
  owner: string; fence: number; nowMs: number; leaseExpiresAtMs: number; version: number;
}> = {}) {
  const nowMs = options.nowMs ?? NOW;
  return beginRefreshAttempt(db, {
    ...authority({ ...record, version: options.version ?? record.version }, operationId, options),
    leaseExpiresAtMs: options.leaseExpiresAtMs ?? nowMs + 10_000,
  });
}

function emptyLease(): OAuthRefreshLeaseState {
  return {
    accountId: null, owner: null, operationId: null, credentialVersion: null, fence: 0,
    acquiredAtMs: null, leaseExpiresAtMs: null, lastCompletedCredentialVersion: null,
  };
}

describe("OAuth refresh actual 0013 migration", () => {
  it("enforces canonical identifiers and attempt table constraints", async () => {
    const record = await account();
    await expect(beginRefreshAttempt(db, {
      ...authority(record, "oauth-test-invalid-id"), accountId: "01", leaseExpiresAtMs: NOW + 10_000,
    })).rejects.toThrow("INVALID_ACCOUNT_ID");
    await expect(db.prepare(`INSERT INTO oauth_refresh_attempts(
      operation_id,account_id,expected_credential_version,expected_credential_fingerprint,
      owner,fence,lease_expires_at_ms,request_digest,state,terminal_at_ms,created_at_ms,updated_at_ms
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(" bad", record.id, 1, record.fingerprint, "worker-a", 1, NOW + 10_000,
        "a".repeat(64), "pre_provider", null, NOW, NOW).run()).rejects.toThrow();
    await expect(db.prepare(`INSERT INTO oauth_refresh_attempts(
      operation_id,account_id,expected_credential_version,expected_credential_fingerprint,
      owner,fence,lease_expires_at_ms,request_digest,state,terminal_at_ms,created_at_ms,updated_at_ms
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind("oauth-test-invalid-owner", record.id, 1, record.fingerprint, " bad", 1, NOW + 10_000,
        "a".repeat(64), "pre_provider", null, NOW, NOW).run()).rejects.toThrow();
    await expect(db.prepare(`INSERT INTO oauth_refresh_attempts(
      operation_id,account_id,expected_credential_version,expected_credential_fingerprint,
      owner,fence,lease_expires_at_ms,request_digest,state,terminal_at_ms,created_at_ms,updated_at_ms
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind("oauth-test-invalid-digest", record.id, 1, record.fingerprint, "worker-a", 1, NOW + 10_000,
        "a".repeat(63), "pre_provider", null, NOW, NOW).run()).rejects.toThrow();
    await expect(db.prepare(`INSERT INTO oauth_refresh_attempts(
      operation_id,account_id,expected_credential_version,expected_credential_fingerprint,
      owner,fence,lease_expires_at_ms,request_digest,state,terminal_at_ms,created_at_ms,updated_at_ms
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind("oauth-test-invalid-terminal", record.id, 1, record.fingerprint, "worker-a", 1, NOW + 10_000,
        "b".repeat(64), "pre_provider", NOW, NOW, NOW).run()).rejects.toThrow();
    await expect(db.prepare(`INSERT INTO oauth_refresh_attempts(
      operation_id,account_id,expected_credential_version,expected_credential_fingerprint,
      owner,fence,lease_expires_at_ms,request_digest,state,terminal_at_ms,created_at_ms,updated_at_ms
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind("oauth-test-missing-terminal", record.id, 1, record.fingerprint, "worker-a", 1, NOW + 10_000,
        "d".repeat(64), "failed_retryable", null, NOW, NOW).run()).rejects.toThrow();
    await expect(db.prepare(`INSERT INTO oauth_refresh_attempts(
      operation_id,account_id,expected_credential_version,expected_credential_fingerprint,
      owner,fence,lease_expires_at_ms,request_digest,state,terminal_at_ms,created_at_ms,updated_at_ms
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind("oauth-test-invalid-order", record.id, 1, record.fingerprint, "worker-a", 1, NOW,
        "c".repeat(64), "failed_retryable", NOW, NOW, NOW - 1).run()).rejects.toThrow();
    await expect(db.prepare(`INSERT INTO oauth_refresh_attempts(
      operation_id,account_id,expected_credential_version,expected_credential_fingerprint,
      owner,fence,lease_expires_at_ms,request_digest,state,terminal_at_ms,created_at_ms,updated_at_ms
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind("oauth-test-terminal-before-create", record.id, 1, record.fingerprint, "worker-a", 1, NOW + 10_000,
        "f".repeat(64), "manual_review", NOW - 1, NOW, NOW).run()).rejects.toThrow();
    await begin(record, "oauth-test-constraint-source");
    await expect(db.prepare(`INSERT INTO oauth_refresh_audit(
      audit_id,operation_id,account_id,event,detail_digest,created_at_ms
    ) VALUES(?,?,?,?,?,?)`)
      .bind("audit-invalid-event", "oauth-test-constraint-source", record.id,
        "not-an-oauth-event", "a".repeat(64), NOW).run()).rejects.toThrow();
    await expect(db.prepare(`INSERT INTO oauth_refresh_invalidation_outbox(
      event_id,operation_id,account_id,credential_version,event_type,state,created_at_ms,published_at_ms
    ) VALUES(?,?,?,?,?,?,?,?)`)
      .bind("outbox-invalid-nullability", "oauth-test-constraint-source", record.id, 1,
        "oauth_credentials_invalidated", "published", NOW, null).run()).rejects.toThrow();
  });

  it("has deterministic lease-core account/fence/completion bounds", () => {
    const first = transitionOAuthRefreshLease(emptyLease(), {
      kind: "acquire", input: { accountId: "1", credentialVersion: 4, operationId: "oauth-test-a",
        owner: "owner-a", nowMs: NOW, leaseMs: 1_000 },
    });
    expect(first.result).toMatchObject({ kind: "acquired", fence: 1 });
    expect(transitionOAuthRefreshLease(first.state, {
      kind: "acquire", input: { accountId: "1", credentialVersion: 4, operationId: "oauth-test-b",
        owner: "owner-b", nowMs: NOW + 1, leaseMs: 1_000 },
    }).result).toMatchObject({ kind: "busy" });
    expect(() => transitionOAuthRefreshLease(first.state, {
      kind: "acquire", input: { accountId: "2", credentialVersion: 4, operationId: "oauth-test-b",
        owner: "owner-b", nowMs: NOW + 1, leaseMs: 1_000 },
    })).toThrow("DO_ACCOUNT_MISMATCH");
    expect(() => transitionOAuthRefreshLease(first.state, {
      kind: "acquire", input: { accountId: "1", credentialVersion: 4, operationId: "oauth-test-clock",
        owner: "owner-b", nowMs: NOW - 1, leaseMs: 1_000 },
    })).toThrow("STALE_DO_TIME");
    expect(() => transitionOAuthRefreshLease({
      ...emptyLease(), accountId: "1", fence: MAX_REFRESH_COUNTER,
    }, {
      kind: "acquire", input: { accountId: "1", credentialVersion: 4, operationId: "oauth-test-overflow",
        owner: "owner-a", nowMs: NOW, leaseMs: 1_000 },
    })).toThrow("COUNTER_OVERFLOW");
  });

  it("requires one live attempt, terminalizes takeover, and has stable terminal replays", async () => {
    const record = await account();
    expect(await begin(record, "oauth-test-old")).toEqual({ kind: "ready", state: "pre_provider" });
    expect(await begin(record, "oauth-test-new", { fence: 2 })).toEqual({ kind: "busy" });
    const expired = authority(record, "oauth-test-old", { nowMs: NOW + 10_000 });
    expect(await expireRefreshAttempt(db, expired)).toEqual({ kind: "retry_required", state: "failed_retryable" });
    expect(await expireRefreshAttempt(db, expired)).toEqual({ kind: "retry_required", state: "failed_retryable" });
    expect(await begin(record, "oauth-test-old"))
      .toEqual({ kind: "retry_required", state: "failed_retryable" });
    expect(await markProviderStarted(db, authority(record, "oauth-test-old"))).toEqual({ kind: "busy" });
    expect(await commitRefreshSuccess(db, {
      ...authority(record, "oauth-test-old"), expectedCredentialEnvelope: record.envelope,
      nextCredentialEnvelope: "test-envelope-terminal-retry",
      nextCredentialFingerprint: await fingerprintCredentialEnvelope("test-envelope-terminal-retry"),
    })).toEqual({ kind: "busy" });
    expect(await begin(record, "oauth-test-new", { fence: 2, nowMs: NOW + 10_000 }))
      .toEqual({ kind: "ready", state: "pre_provider" });
  });

  it("enforces the account-wide actual-migration live-attempt invariant across versions", async () => {
    const record = await account();
    expect(await begin(record, "oauth-test-live-v1")).toEqual({ kind: "ready", state: "pre_provider" });
    const envelope2 = "test-envelope-live-v2";
    const fingerprint2 = await fingerprintCredentialEnvelope(envelope2);
    await db.prepare(`UPDATE accounts SET credential_envelope=?,credential_fingerprint=?,credential_version=2
      WHERE id=?`).bind(envelope2, fingerprint2, record.id).run();
    const v2: Record = { id: record.id, envelope: envelope2, fingerprint: fingerprint2, version: 2 };
    expect(await begin(v2, "oauth-test-live-v2", { fence: 2 })).toEqual({ kind: "busy" });
    await expect(db.prepare(`INSERT INTO oauth_refresh_attempts(
      operation_id,account_id,expected_credential_version,expected_credential_fingerprint,
      owner,fence,lease_expires_at_ms,request_digest,state,terminal_at_ms,created_at_ms,updated_at_ms
    ) VALUES(?,?,?,?,?,?,?,?, 'pre_provider',NULL,?,?)`)
      .bind("oauth-test-live-v2-raw", record.id, 2, fingerprint2, "worker-b", 2, NOW + 10_000,
        "e".repeat(64), NOW, NOW).run()).rejects.toThrow();
  });

  it("makes concurrent phase retries deterministic without duplicate audit errors", async () => {
    const started = await account();
    await begin(started, "oauth-test-concurrent-start");
    const startResults = await Promise.all([
      markProviderStarted(db, authority(started, "oauth-test-concurrent-start")),
      markProviderStarted(db, authority(started, "oauth-test-concurrent-start")),
    ]);
    expect(startResults.map((result) => result.kind).sort()).toEqual(["already_started", "ready"]);

    const expired = await account();
    await begin(expired, "oauth-test-concurrent-expire", { leaseExpiresAtMs: NOW + 1_000 });
    const expiry = authority(expired, "oauth-test-concurrent-expire", { nowMs: NOW + 1_000 });
    expect((await Promise.all([
      expireRefreshAttempt(db, expiry), expireRefreshAttempt(db, expiry),
    ])).map((result) => result.kind)).toEqual(["retry_required", "retry_required"]);

    const raced = await account();
    await begin(raced, "oauth-test-phase-race", { leaseExpiresAtMs: NOW + 1_000 });
    await markProviderStarted(db, authority(raced, "oauth-test-phase-race"));
    const raceInput = authority(raced, "oauth-test-phase-race", { nowMs: NOW + 1_000 });
    await Promise.all([expireRefreshAttempt(db, raceInput), recoverInvalidGrantRace(db, raceInput)]);
    expect(await db.prepare(`SELECT count(*) AS count FROM oauth_refresh_audit
      WHERE operation_id=? AND event IN ('provider_result_unknown','invalid_grant_manual_review','invalid_grant_credential_advanced')`)
      .bind("oauth-test-phase-race").first<{ count: number }>()).toEqual({ count: 1 });
  });

  it("replays an identical concurrent commit exactly once", async () => {
    const record = await account();
    await begin(record, "oauth-test-commit-race");
    await markProviderStarted(db, authority(record, "oauth-test-commit-race"));
    const next = "test-envelope-commit-race";
    const input = { ...authority(record, "oauth-test-commit-race"), expectedCredentialEnvelope: record.envelope,
      nextCredentialEnvelope: next, nextCredentialFingerprint: await fingerprintCredentialEnvelope(next) };
    expect((await Promise.all([commitRefreshSuccess(db, input), commitRefreshSuccess(db, input)]))
      .map((result) => result.kind).sort()).toEqual(["already_completed", "committed"]);
    expect(await db.prepare(`SELECT
      (SELECT count(*) FROM oauth_refresh_audit WHERE operation_id=?) AS audits,
      (SELECT count(*) FROM oauth_refresh_invalidation_outbox WHERE operation_id=?) AS outbox,
      (SELECT count(*) FROM oauth_refresh_commit_witnesses WHERE operation_id=?) AS witnesses`)
      .bind("oauth-test-commit-race", "oauth-test-commit-race", "oauth-test-commit-race")
      .first()).toEqual({ audits: 3, outbox: 1, witnesses: 1 });
  });

  it("does not inspect or mutate account B for hostile cross-account calls", async () => {
    const a = await account();
    const b = await account();
    await begin(a, "oauth-test-cross");
    await markProviderStarted(db, authority(a, "oauth-test-cross"));
    const before = await db.prepare("SELECT credential_version,credential_fingerprint FROM accounts WHERE id=?")
      .bind(b.id).first();
    expect(await commitRefreshSuccess(db, {
      ...authority(b, "oauth-test-cross"), expectedCredentialEnvelope: b.envelope,
      nextCredentialEnvelope: "test-envelope-cross", nextCredentialFingerprint: await fingerprintCredentialEnvelope("test-envelope-cross"),
    })).toEqual({ kind: "busy" });
    expect(await recoverInvalidGrantRace(db, authority(b, "oauth-test-cross"))).toEqual({ kind: "busy" });
    expect(await db.prepare("SELECT credential_version,credential_fingerprint FROM accounts WHERE id=?")
      .bind(b.id).first()).toEqual(before);
    expect(await db.prepare("SELECT count(*) AS count FROM oauth_refresh_audit WHERE account_id=?")
      .bind(b.id).first<{ count: number }>()).toEqual({ count: 0 });
    expect(await db.prepare("SELECT count(*) AS count FROM oauth_refresh_invalidation_outbox WHERE account_id=?")
      .bind(b.id).first<{ count: number }>()).toEqual({ count: 0 });
  });

  it("rejects PAT accounts before refresh authority", async () => {
    const pat = await account("pat");
    expect(await begin(pat, "oauth-test-pat")).toEqual({ kind: "non_refreshable" });
  });

  it("keeps an immutable exact witness replay after a later refresh and rejects wrong owner/fence", async () => {
    const first = await account();
    const envelope2 = "test-envelope-v2";
    const fingerprint2 = await fingerprintCredentialEnvelope(envelope2);
    await begin(first, "oauth-test-op1");
    await markProviderStarted(db, authority(first, "oauth-test-op1"));
    const op1 = {
      ...authority(first, "oauth-test-op1"), expectedCredentialEnvelope: first.envelope,
      nextCredentialEnvelope: envelope2, nextCredentialFingerprint: fingerprint2,
    };
    expect(await commitRefreshSuccess(db, op1)).toEqual({ kind: "committed", state: "succeeded" });
    await expect(db.prepare("UPDATE oauth_refresh_commit_witnesses SET created_at_ms=? WHERE operation_id=?")
      .bind(NOW + 1, "oauth-test-op1").run()).rejects.toThrow(/immutable/);
    const second: Record = { id: first.id, envelope: envelope2, fingerprint: fingerprint2, version: 2 };
    const envelope3 = "test-envelope-v3";
    const fingerprint3 = await fingerprintCredentialEnvelope(envelope3);
    await begin(second, "oauth-test-op2", { fence: 2 });
    await markProviderStarted(db, authority(second, "oauth-test-op2", { fence: 2 }));
    expect(await commitRefreshSuccess(db, {
      ...authority(second, "oauth-test-op2", { fence: 2 }), expectedCredentialEnvelope: envelope2,
      nextCredentialEnvelope: envelope3, nextCredentialFingerprint: fingerprint3,
    })).toEqual({ kind: "committed", state: "succeeded" });
    expect(await commitRefreshSuccess(db, op1)).toEqual({ kind: "already_completed", state: "succeeded" });
    expect(await commitRefreshSuccess(db, { ...op1, owner: "worker-b" })).toEqual({ kind: "busy" });
    expect(await commitRefreshSuccess(db, { ...op1, fence: 2 })).toEqual({ kind: "busy" });
    await expect(db.prepare("DELETE FROM oauth_refresh_commit_witnesses WHERE operation_id=?")
      .bind("oauth-test-op1").run()).rejects.toThrow(/immutable/);
    await expect(db.prepare("DELETE FROM oauth_refresh_audit WHERE audit_id=?")
      .bind("success:oauth-test-op1").run()).rejects.toThrow(/immutable/);
    await expect(db.prepare("DELETE FROM oauth_refresh_attempts WHERE operation_id=?")
      .bind("oauth-test-op1").run()).rejects.toThrow(/immutable/);
    await expect(db.prepare(`UPDATE oauth_refresh_invalidation_outbox
      SET state='published',published_at_ms=? WHERE operation_id=?`)
      .bind(NOW + 1, "oauth-test-op1").run()).resolves.toBeDefined();
    await expect(db.prepare(`UPDATE oauth_refresh_invalidation_outbox
      SET state='pending',published_at_ms=? WHERE operation_id=?`)
      .bind(NOW + 2, "oauth-test-op1").run()).rejects.toThrow();
  });

  it("uses actual witness rollback, version limits, invalid_grant proof, and immutable terminal rows", async () => {
    const record = await account();
    await begin(record, "oauth-test-atomic");
    await markProviderStarted(db, authority(record, "oauth-test-atomic"));
    const external = "test-envelope-external";
    await db.prepare("UPDATE accounts SET credential_envelope=?,credential_fingerprint=?,credential_version=2 WHERE id=?")
      .bind(external, await fingerprintCredentialEnvelope(external), record.id).run();
    const before = await db.prepare(`SELECT
      (SELECT credential_version FROM accounts WHERE id=?) AS version,
      (SELECT state FROM oauth_refresh_attempts WHERE operation_id='oauth-test-atomic') AS state,
      (SELECT count(*) FROM oauth_refresh_audit WHERE operation_id='oauth-test-atomic') AS audits,
      (SELECT count(*) FROM oauth_refresh_invalidation_outbox WHERE operation_id='oauth-test-atomic') AS outbox,
      (SELECT count(*) FROM oauth_refresh_commit_witnesses WHERE operation_id='oauth-test-atomic') AS witnesses`)
      .bind(record.id).first();
    const next = "test-envelope-never-committed";
    expect(await commitRefreshSuccess(db, {
      ...authority(record, "oauth-test-atomic"), expectedCredentialEnvelope: record.envelope,
      nextCredentialEnvelope: next, nextCredentialFingerprint: await fingerprintCredentialEnvelope(next),
    })).toEqual({ kind: "already_refreshed" });
    expect(await db.prepare(`SELECT
      (SELECT credential_version FROM accounts WHERE id=?) AS version,
      (SELECT state FROM oauth_refresh_attempts WHERE operation_id='oauth-test-atomic') AS state,
      (SELECT count(*) FROM oauth_refresh_audit WHERE operation_id='oauth-test-atomic') AS audits,
      (SELECT count(*) FROM oauth_refresh_invalidation_outbox WHERE operation_id='oauth-test-atomic') AS outbox,
      (SELECT count(*) FROM oauth_refresh_commit_witnesses WHERE operation_id='oauth-test-atomic') AS witnesses`)
      .bind(record.id).first()).toEqual(before);

    const latest = await account();
    await db.prepare("UPDATE accounts SET credential_version=? WHERE id=?").bind(MAX_REFRESH_COUNTER, latest.id).run();
    const max: Record = { ...latest, version: MAX_REFRESH_COUNTER };
    await expect(begin(max, "oauth-test-max-plus-one", { version: MAX_REFRESH_COUNTER + 1 }))
      .rejects.toThrow("INVALID_VERSION_OR_FENCE");
    expect(await begin(max, "oauth-test-max")).toEqual({ kind: "ready", state: "pre_provider" });
    await markProviderStarted(db, authority(max, "oauth-test-max"));
    await expect(commitRefreshSuccess(db, {
      ...authority(max, "oauth-test-max"), expectedCredentialEnvelope: max.envelope,
      nextCredentialEnvelope: "test-envelope-overflow",
      nextCredentialFingerprint: await fingerprintCredentialEnvelope("test-envelope-overflow"),
    })).rejects.toThrow("COUNTER_OVERFLOW");

    const grant = await account();
    await begin(grant, "oauth-test-grant");
    await markProviderStarted(db, authority(grant, "oauth-test-grant"));
    const advanced = "test-envelope-advanced";
    await db.prepare("UPDATE accounts SET credential_envelope=?,credential_fingerprint=?,credential_version=2 WHERE id=?")
      .bind(advanced, await fingerprintCredentialEnvelope(advanced), grant.id).run();
    expect(await recoverInvalidGrantRace(db, authority(grant, "oauth-test-grant")))
      .toEqual({ kind: "already_refreshed", state: "superseded" });
    expect(await recoverInvalidGrantRace(db, authority(grant, "oauth-test-grant")))
      .toEqual({ kind: "already_refreshed", state: "superseded" });
    await expect(db.prepare("UPDATE oauth_refresh_attempts SET state='succeeded' WHERE operation_id=?")
      .bind("oauth-test-grant").run()).rejects.toThrow(/immutable/);
  });

  it("guards legacy fingerprint initialization without exposing envelope material", async () => {
    const record = await account();
    expect(await initializeCredentialFingerprint(db, {
      accountId: record.id, expectedCredentialVersion: 1, expectedCredentialEnvelope: record.envelope, nowMs: NOW,
    })).toBe("already_initialized");
    expect(await db.prepare("SELECT count(*) AS count FROM oauth_refresh_fingerprint_audit WHERE account_id=? AND credential_version=1")
      .bind(record.id).first<{ count: number }>()).toEqual({ count: 1 });
    const legacy = await account();
    await db.prepare("UPDATE accounts SET credential_fingerprint=NULL WHERE id=?").bind(legacy.id).run();
    expect(await initializeCredentialFingerprint(db, {
      accountId: legacy.id, expectedCredentialVersion: 1, expectedCredentialEnvelope: legacy.envelope, nowMs: NOW,
    })).toBe("initialized");
    expect(await initializeCredentialFingerprint(db, {
      accountId: legacy.id, expectedCredentialVersion: 1, expectedCredentialEnvelope: legacy.envelope, nowMs: NOW,
    })).toBe("already_initialized");
    await expect(db.prepare("DELETE FROM oauth_refresh_fingerprint_audit WHERE account_id=?")
      .bind(legacy.id).run()).rejects.toThrow(/immutable/);

    const conflicted = await account();
    await db.prepare("UPDATE accounts SET credential_fingerprint=NULL WHERE id=?").bind(conflicted.id).run();
    const conflictAuditId = `fingerprint:${conflicted.id}:1:${conflicted.fingerprint}`;
    await db.prepare(`INSERT INTO oauth_refresh_fingerprint_audit(
      audit_id,account_id,credential_version,credential_fingerprint,created_at_ms
    ) VALUES(?,?,?,?,?)`)
      .bind(conflictAuditId, conflicted.id, 1, "f".repeat(64), NOW).run();
    await expect(initializeCredentialFingerprint(db, {
      accountId: conflicted.id, expectedCredentialVersion: 1,
      expectedCredentialEnvelope: conflicted.envelope, nowMs: NOW,
    })).rejects.toThrow("FINGERPRINT_AUDIT_CONFLICT");
    expect(await db.prepare("SELECT credential_fingerprint FROM accounts WHERE id=?")
      .bind(conflicted.id).first<{ credential_fingerprint: string | null }>())
      .toEqual({ credential_fingerprint: null });
    await expect(db.prepare(`INSERT INTO oauth_refresh_fingerprint_audit(
      audit_id,account_id,credential_version,credential_fingerprint,created_at_ms
    ) VALUES(?,?,?,?,?)`).bind("fingerprint-second", conflicted.id, 1, "e".repeat(64), NOW).run()).rejects.toThrow();
  });

  it("keeps derived ids inside real 0013 limits", async () => {
    const record = await account();
    const max = "a".repeat(120);
    expect(await begin(record, max)).toEqual({ kind: "ready", state: "pre_provider" });
    await expect(begin(record, "a".repeat(121))).rejects.toThrow("INVALID_OPERATION_ID");
  });
});
