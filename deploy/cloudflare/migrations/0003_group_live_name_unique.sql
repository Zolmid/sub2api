-- Match the traditional repository's live-group name uniqueness while still
-- allowing a name to be reused after its previous group is soft-deleted.
CREATE UNIQUE INDEX groups_name_live_idx
  ON groups(name) WHERE deleted_at IS NULL;
