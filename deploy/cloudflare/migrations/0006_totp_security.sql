-- TOTP is Cloudflare-owned durable security state. Secrets are always stored
-- as purpose-bound AES-GCM envelopes; plaintext is never a D1 value.
ALTER TABLE users ADD COLUMN totp_secret_envelope TEXT
  CHECK(totp_secret_envelope IS NULL OR (
    length(totp_secret_envelope) BETWEEN 32 AND 512
    AND substr(totp_secret_envelope, 1, 16) = 'aes-gcm:v1:totp:'
  ));
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0
  CHECK(totp_enabled IN (0, 1));
ALTER TABLE users ADD COLUMN totp_enabled_at TEXT;
ALTER TABLE users ADD COLUMN totp_revision INTEGER NOT NULL DEFAULT 0
  CHECK(totp_revision BETWEEN 0 AND 9007199254740991);

CREATE TRIGGER users_totp_consistency_insert
BEFORE INSERT ON users
WHEN NOT (
  (NEW.totp_enabled = 0 AND NEW.totp_secret_envelope IS NULL
    AND NEW.totp_enabled_at IS NULL)
  OR
  (NEW.totp_enabled = 1 AND NEW.totp_secret_envelope IS NOT NULL
    AND NEW.totp_enabled_at IS NOT NULL)
)
BEGIN
  SELECT RAISE(ABORT, 'invalid totp state');
END;

CREATE TRIGGER users_totp_consistency_update
BEFORE UPDATE OF totp_secret_envelope, totp_enabled, totp_enabled_at,
  totp_revision ON users
WHEN NOT (
  (NEW.totp_enabled = 0 AND NEW.totp_secret_envelope IS NULL
    AND NEW.totp_enabled_at IS NULL)
  OR
  (NEW.totp_enabled = 1 AND NEW.totp_secret_envelope IS NOT NULL
    AND NEW.totp_enabled_at IS NOT NULL)
)
BEGIN
  SELECT RAISE(ABORT, 'invalid totp state');
END;
