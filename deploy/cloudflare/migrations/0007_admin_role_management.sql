-- Cloudflare-native administrator role changes are durable, idempotent, and
-- auditable without retaining session or credential material.
CREATE TABLE admin_role_change_audit (
  operation_id TEXT PRIMARY KEY CHECK(length(operation_id) BETWEEN 1 AND 128),
  actor_user_id TEXT NOT NULL CHECK(
    length(actor_user_id) BETWEEN 1 AND 20
    AND actor_user_id NOT GLOB '*[^0-9]*'
    AND substr(actor_user_id, 1, 1) BETWEEN '1' AND '9'
  ),
  target_user_id TEXT NOT NULL CHECK(
    length(target_user_id) BETWEEN 1 AND 20
    AND target_user_id NOT GLOB '*[^0-9]*'
    AND substr(target_user_id, 1, 1) BETWEEN '1' AND '9'
  ),
  old_role TEXT NOT NULL CHECK(old_role IN ('user', 'admin')),
  new_role TEXT NOT NULL CHECK(new_role IN ('user', 'admin')),
  created_at TEXT NOT NULL,
  CHECK(old_role <> new_role)
);

CREATE INDEX admin_role_change_audit_target_created_idx
  ON admin_role_change_audit(target_user_id, created_at, operation_id);

CREATE TRIGGER admin_role_change_audit_no_update
BEFORE UPDATE ON admin_role_change_audit
BEGIN
  SELECT RAISE(ABORT, 'admin role change audit is immutable');
END;

CREATE TRIGGER admin_role_change_audit_no_delete
BEFORE DELETE ON admin_role_change_audit
BEGIN
  SELECT RAISE(ABORT, 'admin role change audit is immutable');
END;
