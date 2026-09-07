-- Private login resolves live users by lower(trim(email)). Keep D1's unique
-- identity equal to that lookup key; display casing stays in users.email.
DROP INDEX users_email_live_idx;
CREATE UNIQUE INDEX users_email_live_identity_idx
  ON users(lower(trim(email))) WHERE email <> '' AND deleted_at IS NULL;
