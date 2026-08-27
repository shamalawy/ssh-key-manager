-- SKM initial schema.
--
-- Conventions used throughout:
--   * UUID primary keys, generated server-side.
--   * Every tenant-owned table carries tenant_id. SKM ships single-tenant, but
--     carrying the column from the start means enabling multi-tenancy later is a
--     configuration change rather than a migration of every table.
--   * Status columns are TEXT with CHECK constraints rather than PostgreSQL
--     ENUMs, because adding a value to an ENUM inside a transaction is awkward
--     and these sets will grow.
--   * Secret material always lives in its own table, so an accidental
--     `SELECT *` on a primary entity can never return plaintext or ciphertext.

-- ---------------------------------------------------------------- tenancy ---

CREATE TABLE tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The single tenant every install starts with. Its fixed UUID lets the
-- single-tenant code path avoid a lookup on every request.
INSERT INTO tenants (id, name, slug)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default');

-- ------------------------------------------------------------------- auth ---

CREATE TABLE users (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username         TEXT NOT NULL,
    email            TEXT NOT NULL DEFAULT '',
    display_name     TEXT NOT NULL DEFAULT '',
    password_hash    TEXT NOT NULL,
    totp_secret      TEXT NOT NULL DEFAULT '',
    totp_enrolled    BOOLEAN NOT NULL DEFAULT false,
    recovery_codes   TEXT[] NOT NULL DEFAULT '{}',
    active           BOOLEAN NOT NULL DEFAULT true,
    must_change_pw   BOOLEAN NOT NULL DEFAULT false,
    failed_logins    INT NOT NULL DEFAULT 0,
    locked_until     TIMESTAMPTZ,
    last_login_at    TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, username)
);

CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    -- System roles cannot be edited or deleted, so an operator cannot lock
    -- everyone out by removing permissions from the admin role.
    is_system   BOOLEAN NOT NULL DEFAULT false,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE user_roles (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

-- Per-user overrides layered on top of role permissions. Deny always wins.
CREATE TABLE user_permission_overrides (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    effect     TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    PRIMARY KEY (user_id, permission)
);

-- Tag-scoped access: a role may be limited to targets carrying these tags.
CREATE TABLE user_scopes (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag     TEXT NOT NULL,
    PRIMARY KEY (user_id, tag)
);

CREATE TABLE sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,
    refresh_hash  TEXT NOT NULL DEFAULT '',
    -- Step-up MFA: some operations require re-authentication within a window.
    mfa_verified_at TIMESTAMPTZ,
    ip_address    INET,
    user_agent    TEXT NOT NULL DEFAULT '',
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expiry_idx ON sessions (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE api_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    -- Only the hash is stored; the plaintext token is shown once at creation.
    token_hash  TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    expires_at  TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX api_tokens_tenant_idx ON api_tokens (tenant_id) WHERE revoked_at IS NULL;

-- ------------------------------------------------------------------- keys ---

CREATE TABLE keys (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    algorithm          TEXT NOT NULL,
    public_key         TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    comment            TEXT NOT NULL DEFAULT '',

    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','staged','active','retiring','retired',
                          'revoked','compromised','destroyed')),

    -- break_glass keys are always deployed and never rotated automatically;
    -- discovered keys were found on a target rather than generated by SKM.
    key_class TEXT NOT NULL DEFAULT 'standard'
        CHECK (key_class IN ('standard','break_glass','discovered','imported')),

    -- Rotation lineage: generation N+1 points back at the key it replaces.
    generation    INT NOT NULL DEFAULT 1,
    parent_key_id UUID REFERENCES keys(id) ON DELETE SET NULL,

    rotation_policy_id UUID,
    owner_id           UUID REFERENCES users(id) ON DELETE SET NULL,
    tags               TEXT[] NOT NULL DEFAULT '{}',

    -- False for keys SKM only knows the public half of (discovered/adopted).
    has_private_key BOOLEAN NOT NULL DEFAULT true,
    -- Set by the compliance checker: weak algorithm, oversized age, etc.
    compliant        BOOLEAN NOT NULL DEFAULT true,
    compliance_notes TEXT NOT NULL DEFAULT '',

    expires_at    TIMESTAMPTZ,
    activated_at  TIMESTAMPTZ,
    retired_at    TIMESTAMPTZ,
    -- After this instant the private key material is shredded.
    destroy_after TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,

    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, fingerprint_sha256)
);
CREATE INDEX keys_tenant_status_idx ON keys (tenant_id, status);
CREATE INDEX keys_expiry_idx ON keys (expires_at)
    WHERE status IN ('active','staged') AND expires_at IS NOT NULL;
CREATE INDEX keys_tags_idx ON keys USING GIN (tags);
CREATE INDEX keys_parent_idx ON keys (parent_key_id);

-- Private key material, isolated so it can never be selected accidentally.
CREATE TABLE key_material (
    key_id      UUID PRIMARY KEY REFERENCES keys(id) ON DELETE CASCADE,
    kek_version INT NOT NULL,
    wrapped_dek BYTEA NOT NULL,
    ciphertext  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX key_material_kek_idx ON key_material (kek_version);

-- ------------------------------------------------------------ credentials ---

-- How SKM authenticates TO a target in order to manage its keys. This is the
-- bootstrap problem: you need some existing access before you can install keys.
CREATE TABLE credentials (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL
        CHECK (kind IN ('ssh_password','ssh_key','api_token','cloud_iam','kubeconfig')),
    username    TEXT NOT NULL DEFAULT '',
    -- References a managed key when SKM authenticates using one of its own.
    key_id      UUID REFERENCES keys(id) ON DELETE SET NULL,
    kek_version INT,
    wrapped_dek BYTEA,
    ciphertext  BYTEA,
    tags        TEXT[] NOT NULL DEFAULT '{}',
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

-- ---------------------------------------------------------------- targets ---

CREATE TABLE targets (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    -- kind is the broad family; connector selects the implementation.
    kind      TEXT NOT NULL,
    connector TEXT NOT NULL,
    address   TEXT NOT NULL DEFAULT '',
    port      INT NOT NULL DEFAULT 22,
    -- Connector-specific settings: vendor profile, API base URL, region, etc.
    config    JSONB NOT NULL DEFAULT '{}'::jsonb,

    credential_id UUID REFERENCES credentials(id) ON DELETE SET NULL,

    -- Trust-on-first-use host key pin. A mismatch aborts every operation.
    host_key_pin         TEXT NOT NULL DEFAULT '',
    host_key_verified_at TIMESTAMPTZ,

    tags    TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,

    -- Canary targets receive changes first during a staged rollout.
    is_canary BOOLEAN NOT NULL DEFAULT false,

    health         TEXT NOT NULL DEFAULT 'unknown'
        CHECK (health IN ('unknown','healthy','degraded','unreachable')),
    health_message TEXT NOT NULL DEFAULT '',

    drift_state TEXT NOT NULL DEFAULT 'unknown'
        CHECK (drift_state IN ('unknown','in_sync','drifted','error')),
    -- Whether the reconciler may fix drift or only report it.
    reconcile_mode TEXT NOT NULL DEFAULT 'report_only'
        CHECK (reconcile_mode IN ('report_only','auto_heal','disabled')),

    last_seen_at       TIMESTAMPTZ,
    last_reconciled_at TIMESTAMPTZ,

    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, name)
);
CREATE INDEX targets_tenant_kind_idx ON targets (tenant_id, kind);
CREATE INDEX targets_tags_idx ON targets USING GIN (tags);
CREATE INDEX targets_drift_idx ON targets (drift_state) WHERE enabled;

-- The account on the target whose authorized_keys SKM manages.
CREATE TABLE principals (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    username  TEXT NOT NULL,
    -- Empty means the connector default (~/.ssh/authorized_keys).
    authorized_keys_path TEXT NOT NULL DEFAULT '',
    use_sudo  BOOLEAN NOT NULL DEFAULT false,
    enabled   BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_id, username)
);

-- ------------------------------------------------------------ assignments ---

-- Desired state: this key should be present on (or absent from) this principal.
CREATE TABLE assignments (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_id       UUID NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    target_id    UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,

    -- authorized_keys options: from="...", command="...", no-pty, permitopen.
    options TEXT[] NOT NULL DEFAULT '{}',

    desired_state TEXT NOT NULL DEFAULT 'present'
        CHECK (desired_state IN ('present','absent')),
    actual_state  TEXT NOT NULL DEFAULT 'unknown'
        CHECK (actual_state IN ('unknown','present','absent','error')),

    deployed_at      TIMESTAMPTZ,
    last_verified_at TIMESTAMPTZ,
    -- Set when SKM proved it can authenticate with this key, not merely that
    -- the line is in the file.
    auth_verified_at TIMESTAMPTZ,
    last_error       TEXT NOT NULL DEFAULT '',

    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (key_id, principal_id)
);
CREATE INDEX assignments_target_idx ON assignments (target_id);
CREATE INDEX assignments_key_idx ON assignments (key_id);
CREATE INDEX assignments_drift_idx ON assignments (desired_state, actual_state)
    WHERE desired_state::text <> actual_state::text;

-- ---------------------------------------------------------------- consumers ---

-- Places the PRIVATE key must be delivered. These must be updated during a
-- rotation before the old key is retired, or automation breaks silently.
CREATE TABLE consumers (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_id    UUID NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    kind      TEXT NOT NULL
        CHECK (kind IN ('vault_kv','kubernetes_secret','file_drop','webhook','env_export')),
    config    JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled   BOOLEAN NOT NULL DEFAULT true,
    last_delivered_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX consumers_key_idx ON consumers (key_id);

-- ----------------------------------------------------------------- rotation ---

CREATE TABLE rotation_policies (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    enabled   BOOLEAN NOT NULL DEFAULT true,

    -- Which keys this policy governs, by tag / key id / target tag.
    selector JSONB NOT NULL DEFAULT '{}'::jsonb,

    cron_expr  TEXT NOT NULL DEFAULT '',
    max_age    INTERVAL,
    algorithm  TEXT NOT NULL DEFAULT 'ed25519',

    -- How long both keys stay live after promotion.
    soak_period INTERVAL NOT NULL DEFAULT '24 hours',
    -- Fraction of targets in the first wave, and the failure rate that aborts.
    canary_percent    INT NOT NULL DEFAULT 10 CHECK (canary_percent BETWEEN 0 AND 100),
    failure_threshold INT NOT NULL DEFAULT 10 CHECK (failure_threshold BETWEEN 0 AND 100),

    approval_required BOOLEAN NOT NULL DEFAULT false,
    notify_webhooks   UUID[] NOT NULL DEFAULT '{}',

    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,

    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX rotation_policies_next_run_idx ON rotation_policies (next_run_at) WHERE enabled;

CREATE TABLE changesets (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind      TEXT NOT NULL
        CHECK (kind IN ('deploy','rotation','rollback','reconcile','adopt','revoke')),
    summary   TEXT NOT NULL DEFAULT '',
    state     TEXT NOT NULL DEFAULT 'open'
        CHECK (state IN ('open','committed','rolled_back','failed')),
    -- Ordered inverse operations, replayed in reverse to undo the change.
    inverse_ops JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at   TIMESTAMPTZ
);
CREATE INDEX changesets_tenant_created_idx ON changesets (tenant_id, created_at DESC);

CREATE TABLE rotations (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES rotation_policies(id) ON DELETE SET NULL,
    old_key_id UUID REFERENCES keys(id) ON DELETE SET NULL,
    new_key_id UUID REFERENCES keys(id) ON DELETE SET NULL,
    changeset_id UUID REFERENCES changesets(id) ON DELETE SET NULL,

    state TEXT NOT NULL DEFAULT 'planned'
        CHECK (state IN ('planned','awaiting_approval','staging','staged','verifying',
                         'verified','promoting','soaking','retiring','completed',
                         'aborted','rolled_back','failed')),

    wave         INT NOT NULL DEFAULT 0,
    trigger      TEXT NOT NULL DEFAULT 'manual'
        CHECK (trigger IN ('manual','schedule','api','compromise','expiry')),
    dry_run      BOOLEAN NOT NULL DEFAULT false,
    soak_until   TIMESTAMPTZ,

    targets_total    INT NOT NULL DEFAULT 0,
    targets_staged   INT NOT NULL DEFAULT 0,
    targets_verified INT NOT NULL DEFAULT 0,
    targets_retired  INT NOT NULL DEFAULT 0,
    targets_failed   INT NOT NULL DEFAULT 0,

    approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMPTZ,
    error       TEXT NOT NULL DEFAULT '',

    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX rotations_state_idx ON rotations (state)
    WHERE state NOT IN ('completed','aborted','rolled_back','failed');
CREATE INDEX rotations_soak_idx ON rotations (soak_until) WHERE state = 'soaking';

-- Per-target progress within a rotation, so a partial failure is legible.
CREATE TABLE rotation_targets (
    rotation_id  UUID NOT NULL REFERENCES rotations(id) ON DELETE CASCADE,
    target_id    UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    wave         INT NOT NULL DEFAULT 0,
    state        TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','staged','verified','retired','failed','skipped')),
    error        TEXT NOT NULL DEFAULT '',
    staged_at    TIMESTAMPTZ,
    verified_at  TIMESTAMPTZ,
    retired_at   TIMESTAMPTZ,
    PRIMARY KEY (rotation_id, target_id, principal_id)
);
CREATE INDEX rotation_targets_state_idx ON rotation_targets (rotation_id, state);

-- ---------------------------------------------------------------- snapshots ---

-- Captured before every mutation so a single deployment can be reverted
-- byte-for-byte.
CREATE TABLE snapshots (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_id    UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    principal_id UUID REFERENCES principals(id) ON DELETE CASCADE,
    changeset_id UUID REFERENCES changesets(id) ON DELETE SET NULL,
    kind         TEXT NOT NULL DEFAULT 'authorized_keys'
        CHECK (kind IN ('authorized_keys','device_config','api_state')),
    raw_content  BYTEA NOT NULL,
    checksum     TEXT NOT NULL,
    key_count    INT NOT NULL DEFAULT 0,
    taken_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX snapshots_target_idx ON snapshots (target_id, taken_at DESC);
CREATE INDEX snapshots_changeset_idx ON snapshots (changeset_id);

-- Keys found on targets that SKM did not deploy. The first genuinely useful
-- inventory for an estate that has never had key management.
CREATE TABLE discovered_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_id    UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    fingerprint_sha256 TEXT NOT NULL,
    public_key   TEXT NOT NULL,
    algorithm    TEXT NOT NULL DEFAULT '',
    comment      TEXT NOT NULL DEFAULT '',
    options      TEXT[] NOT NULL DEFAULT '{}',
    state        TEXT NOT NULL DEFAULT 'unmanaged'
        CHECK (state IN ('unmanaged','adopted','ignored','removed')),
    adopted_key_id UUID REFERENCES keys(id) ON DELETE SET NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_id, principal_id, fingerprint_sha256)
);
CREATE INDEX discovered_keys_state_idx ON discovered_keys (tenant_id, state);

-- --------------------------------------------------------------------- jobs ---

CREATE TABLE jobs (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type      TEXT NOT NULL,
    payload   JSONB NOT NULL DEFAULT '{}'::jsonb,
    state     TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued','running','succeeded','failed','cancelled','dead')),
    priority  INT NOT NULL DEFAULT 100,

    attempts     INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    run_after    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Deduplicates retries and concurrent submissions of the same work.
    idempotency_key TEXT,

    rotation_id  UUID REFERENCES rotations(id) ON DELETE CASCADE,
    changeset_id UUID REFERENCES changesets(id) ON DELETE SET NULL,
    target_id    UUID REFERENCES targets(id) ON DELETE CASCADE,

    -- Identifies the worker holding the lease, for diagnosing stuck jobs.
    locked_by  TEXT NOT NULL DEFAULT '',
    locked_at  TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    result     JSONB,

    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- The dequeue path: cheapest possible index for the SKIP LOCKED query.
CREATE INDEX jobs_dequeue_idx ON jobs (state, priority, run_after) WHERE state = 'queued';
CREATE UNIQUE INDEX jobs_idempotency_idx ON jobs (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND state IN ('queued','running');
CREATE INDEX jobs_rotation_idx ON jobs (rotation_id);

-- Streamed to the GUI so an operator can watch a deployment happen.
CREATE TABLE job_logs (
    id        BIGSERIAL PRIMARY KEY,
    job_id    UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    level     TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('debug','info','warn','error')),
    message   TEXT NOT NULL,
    fields    JSONB,
    logged_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX job_logs_job_idx ON job_logs (job_id, id);

-- -------------------------------------------------------------------- audit ---

-- Append-only and hash-chained: each row commits to its predecessor, so any
-- deletion or edit breaks the chain and is detectable.
CREATE TABLE audit_events (
    seq        BIGSERIAL PRIMARY KEY,
    id         UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    actor_type TEXT NOT NULL DEFAULT 'user'
        CHECK (actor_type IN ('user','api_token','system','scheduler')),
    actor_id   UUID,
    actor_name TEXT NOT NULL DEFAULT '',

    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id   UUID,
    resource_name TEXT NOT NULL DEFAULT '',

    outcome TEXT NOT NULL DEFAULT 'success'
        CHECK (outcome IN ('success','failure','denied')),
    detail  JSONB NOT NULL DEFAULT '{}'::jsonb,

    ip_address INET,
    user_agent TEXT NOT NULL DEFAULT '',
    session_id UUID,

    prev_hash TEXT NOT NULL DEFAULT '',
    hash      TEXT NOT NULL,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_tenant_time_idx ON audit_events (tenant_id, occurred_at DESC);
CREATE INDEX audit_actor_idx ON audit_events (actor_id, occurred_at DESC);
CREATE INDEX audit_resource_idx ON audit_events (resource_type, resource_id);
CREATE INDEX audit_action_idx ON audit_events (action);

-- Enforce append-only at the database level, so a bug in application code
-- cannot quietly rewrite history.
CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (attempted %)', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

-- ----------------------------------------------------------------- webhooks ---

CREATE TABLE webhooks (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    url       TEXT NOT NULL,
    -- HMAC signing secret, encrypted with the vault like any other secret.
    kek_version INT,
    wrapped_dek BYTEA,
    ciphertext  BYTEA,
    events    TEXT[] NOT NULL DEFAULT '{}',
    enabled   BOOLEAN NOT NULL DEFAULT true,
    headers   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE webhook_deliveries (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id  UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event       TEXT NOT NULL,
    payload     JSONB NOT NULL,
    state       TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','delivered','failed','dead')),
    attempts    INT NOT NULL DEFAULT 0,
    status_code INT,
    response    TEXT NOT NULL DEFAULT '',
    next_retry_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ
);
CREATE INDEX webhook_deliveries_retry_idx ON webhook_deliveries (next_retry_at)
    WHERE state = 'pending';

-- ----------------------------------------------------------------- backups ---

CREATE TABLE backups (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    kind      TEXT NOT NULL DEFAULT 'full' CHECK (kind IN ('full','keys_only','metadata')),
    location  TEXT NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    checksum  TEXT NOT NULL DEFAULT '',
    key_count INT NOT NULL DEFAULT 0,
    state     TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','running','completed','failed','verified')),
    error     TEXT NOT NULL DEFAULT '',
    verified_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX backups_tenant_idx ON backups (tenant_id, created_at DESC);

-- ---------------------------------------------------------------- settings ---

-- Cluster-wide runtime state: current KEK version, seal status, schema notes.
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO settings (key, value) VALUES
    ('kek_version', '1'::jsonb),
    ('schema_version', '1'::jsonb);
