-- Record whether the captured file existed at all.
--
-- A target with no authorized_keys file is the normal state of a host that has
-- never been managed, and it is distinct from a target with an empty one.
-- Without this column a rollback to "no file" recreates an empty file instead,
-- which is not a faithful restore.
--
-- Existing rows were all captured from files that existed, so the default is
-- true for them and false only for genuinely absent files going forward.
ALTER TABLE snapshots
    ADD COLUMN existed BOOLEAN NOT NULL DEFAULT true;

-- Absent files are stored as empty content rather than NULL, so the column
-- stays NOT NULL and callers never have to handle a nil.
ALTER TABLE snapshots
    ALTER COLUMN raw_content SET DEFAULT ''::bytea;
