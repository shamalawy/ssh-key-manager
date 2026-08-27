-- Allow a consumer to be a file on another machine.
--
-- Until now every sink was somewhere SKM could reach without SSH: its own disk,
-- Vault, Kubernetes, an HTTP endpoint. That left no way to answer the ordinary
-- question "put this private key on that host" — a jump box, a CI runner, or a
-- backup job that rsyncs over SSH all need the private half, and the only route
-- was to reveal the key and copy it by hand.
--
-- The kind list is a CHECK constraint rather than a lookup table, so adding a
-- sink means editing it here as well as registering it in Go. That is the
-- trade: the database refuses a kind the application would not understand.
ALTER TABLE consumers
    DROP CONSTRAINT IF EXISTS consumers_kind_check;

ALTER TABLE consumers
    ADD CONSTRAINT consumers_kind_check
    CHECK (kind IN ('vault_kv','kubernetes_secret','file_drop','webhook','env_export','ssh_file'));
