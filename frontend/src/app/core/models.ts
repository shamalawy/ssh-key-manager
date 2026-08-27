/** Types mirroring the SKM REST API. */

export type KeyStatus =
  | 'pending' | 'staged' | 'active' | 'retiring'
  | 'retired' | 'revoked' | 'compromised' | 'destroyed';

export type KeyClass = 'standard' | 'break_glass' | 'discovered' | 'imported';

export interface ManagedKey {
  id: string;
  name: string;
  description: string;
  algorithm: string;
  public_key: string;
  fingerprint_sha256: string;
  comment: string;
  status: KeyStatus;
  key_class: KeyClass;
  generation: number;
  parent_key_id?: string;
  tags: string[];
  has_private_key: boolean;
  compliant: boolean;
  compliance_notes: string;
  expires_at?: string;
  activated_at?: string;
  retired_at?: string;
  destroy_after?: string;
  last_used_at?: string;
  rotation_policy_id?: string;
  owner_id?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export type Health = 'unknown' | 'healthy' | 'degraded' | 'unreachable';
export type DriftState = 'unknown' | 'in_sync' | 'drifted' | 'error';

export interface Target {
  id: string;
  name: string;
  kind: string;
  connector: string;
  address: string;
  port: number;
  config: Record<string, unknown>;
  credential_id?: string;
  host_key_pin: string;
  host_key_verified_at?: string;
  tags: string[];
  enabled: boolean;
  is_canary: boolean;
  health: Health;
  health_message: string;
  drift_state: DriftState;
  reconcile_mode: string;
  last_seen_at?: string;
  last_reconciled_at?: string;
  created_by?: string;
  created_at: string;
  updated_at?: string;
}

export interface Principal {
  id: string;
  target_id: string;
  username: string;
  authorized_keys_path: string;
  use_sudo: boolean;
  enabled: boolean;
}

export interface Assignment {
  id: string;
  key_id: string;
  target_id: string;
  principal_id: string;
  options: string[];
  desired_state: 'present' | 'absent';
  actual_state: 'unknown' | 'present' | 'absent' | 'error';
  deployed_at?: string;
  auth_verified_at?: string;
  last_error: string;
  key_name: string;
  key_fingerprint: string;
  key_status: KeyStatus;
  target_name: string;
  target_address: string;
  username: string;
  last_verified_at?: string;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
}

export interface Credential {
  id: string;
  name: string;
  kind: string;
  username: string;
  key_id?: string;
  has_secret: boolean;
  tags: string[];
  created_by?: string;
  created_at: string;
  updated_at?: string;
}

export interface DeployResult {
  target_id: string;
  target_name: string;
  principal_id: string;
  username: string;
  changed: boolean;
  dry_run: boolean;
  added: string[];
  removed: string[];
  diff: string;
  key_count: number;
  warnings?: string[];
  snapshot_id?: string;
  verified_keys?: string[];
  failed_keys?: string[];
}

export interface Snapshot {
  id: string;
  target_id: string;
  principal_id?: string;
  kind: string;
  checksum: string;
  key_count: number;
  taken_at: string;
}

export interface AuditEvent {
  seq: number;
  id: string;
  actor_type: string;
  actor_name: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  resource_name: string;
  outcome: 'success' | 'failure' | 'denied';
  detail: Record<string, unknown>;
  ip_address?: string;
  prev_hash: string;
  hash: string;
  occurred_at: string;
}

export interface ChainVerification {
  valid: boolean;
  checked: number;
  broken_at_seq?: number;
  reason?: string;
  first_event_at?: string;
  last_event_at?: string;
}

export interface Dashboard {
  active_keys: number;
  expiring_soon: number;
  targets: number;
  unreachable_targets: number;
  drifted_assignments: number;
  non_compliant_keys: number;
  vault_sealed: boolean;

  /** These arrive only when the corresponding subsystem answers, so each tile
   *  can dim on its own rather than blanking the whole dashboard. */
  active_rotations?: number;
  rotations_awaiting_approval?: number;
  unmanaged_keys?: number;
  jobs_queued?: number;
  jobs_running?: number;
  jobs_dead?: number;
  last_backup_at?: string;
  last_backup_state?: string;
  scheduler_leader?: boolean;
}

/**
 * User is an account as every endpoint returns it. role_names is present on
 * the users listing and absent from /auth/me, where roles sit beside the user.
 */
export interface User {
  id: string;
  username: string;
  email: string;
  display_name: string;
  totp_enrolled: boolean;
  active: boolean;
  must_change_password: boolean;
  locked_until?: string;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
  role_names?: string[];
}

export interface Identity {
  user: User;
  roles: string[];
  permissions: string[];
  /** null from /auth/me when unrestricted; Auth normalises it to []. */
  scopes: string[] | null;
  mfa_verified: boolean;
  is_admin: boolean;
}

export interface LoginResponse {
  token: string;
  expires_at: string;
  user: User;
  roles: string[];
  permissions: string[];
  scopes?: string[];
  mfa_verified: boolean;
}

export interface ProbeResult {
  reachable: boolean;
  host_key_pin?: string;
  host_key_is_new: boolean;
  message?: string;
  detail?: Record<string, string>;
}

export interface ConnectorInfo {
  kind: string;
  capabilities: {
    can_list: boolean;
    can_snapshot: boolean;
    can_restore: boolean;
    can_verify: boolean;
    supports_options: boolean;
    single_key: boolean;
  };
  /** Present when the connector documents its configuration keys. */
  settings?: ConnectorSetting[];
}

/** One connector-specific configuration key, described by the server. */
export interface ConnectorSetting {
  key: string;
  label: string;
  type: 'string' | 'secret' | 'bool' | 'int' | 'choice';
  choices?: string[];
  default?: string;
  required?: boolean;
  description: string;
}

export interface VaultStatus {
  sealed: boolean;
  current_version: number;
  known_versions: number[];
}

export interface ListResponse<T> {
  items: T[];
  total: number;
}

// --------------------------------------------------------------- rotation ---

export type RotationState =
  | 'planned' | 'awaiting_approval' | 'staging' | 'staged' | 'verifying'
  | 'verified' | 'promoting' | 'soaking' | 'retiring' | 'completed'
  | 'aborted' | 'rolled_back' | 'failed';

export interface Rotation {
  id: string;
  policy_id?: string;
  old_key_id?: string;
  new_key_id?: string;
  changeset_id?: string;
  state: RotationState;
  wave: number;
  trigger: string;
  dry_run: boolean;
  soak_until?: string;
  targets_total: number;
  targets_staged: number;
  targets_verified: number;
  targets_retired: number;
  targets_failed: number;
  approved_by?: string;
  approved_at?: string;
  error?: string;
  created_at: string;
  updated_at: string;
  completed_at?: string;
}

export type RotationTargetState =
  | 'pending' | 'staged' | 'verified' | 'retired' | 'failed' | 'skipped';

export interface RotationTarget {
  rotation_id: string;
  target_id: string;
  principal_id: string;
  wave: number;
  state: RotationTargetState;
  error?: string;
  staged_at?: string;
  verified_at?: string;
  retired_at?: string;
  target_name?: string;
  username?: string;
}

export interface RotationPlan {
  rotation: Rotation;
  old_key: ManagedKey;
  targets: RotationTarget[];
  waves: Record<string, number>;
  consumers: Consumer[];
  warnings?: string[];
}

export interface RotationPolicy {
  id: string;
  name: string;
  enabled: boolean;
  selector: {
    key_tags?: string[];
    target_tags?: string[];
    key_ids?: string[];
    key_class?: string;
  };
  cron_expr: string;
  max_age_seconds: number;
  algorithm: string;
  soak_period_seconds: number;
  canary_percent: number;
  failure_threshold: number;
  approval_required: boolean;
  notify_webhooks: string[];
  last_run_at?: string;
  next_run_at?: string;
  created_at: string;
  updated_at: string;
}

// ------------------------------------------------------------------- jobs ---

export type JobState = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled' | 'dead';

export interface Job {
  id: string;
  type: string;
  payload: unknown;
  state: JobState;
  priority: number;
  attempts: number;
  max_attempts: number;
  run_after: string;
  rotation_id?: string;
  target_id?: string;
  locked_by?: string;
  started_at?: string;
  finished_at?: string;
  last_error?: string;
  result?: unknown;
  created_at: string;
  updated_at: string;
}

export interface JobLog {
  id: number;
  job_id: string;
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  fields?: Record<string, unknown>;
  logged_at: string;
}

// -------------------------------------------------------- drift discovery ---

export type DiscoveredState = 'unmanaged' | 'adopted' | 'ignored' | 'removed';

export interface DiscoveredKey {
  id: string;
  target_id: string;
  principal_id: string;
  fingerprint_sha256: string;
  public_key: string;
  algorithm: string;
  comment: string;
  options: string[];
  state: DiscoveredState;
  adopted_key_id?: string;
  first_seen_at: string;
  last_seen_at: string;
  target_name?: string;
  username?: string;
}

export interface PrincipalReport {
  principal_id: string;
  username: string;
  missing?: string[];
  unexpected?: string[];
  unmanaged?: string[];
  healed: boolean;
  error?: string;
}

export interface ReconcileResult {
  target_id: string;
  target_name: string;
  drift_state: DriftState;
  reconcile_mode: string;
  principals: PrincipalReport[];
  checked_at: string;
}

// ---------------------------------------------------------------- backups ---

export type BackupState = 'pending' | 'running' | 'completed' | 'failed' | 'verified';

export interface Backup {
  id: string;
  name: string;
  kind: 'full' | 'keys_only' | 'metadata';
  location: string;
  size_bytes: number;
  checksum: string;
  key_count: number;
  state: BackupState;
  error?: string;
  verified_at?: string;
  expires_at?: string;
  created_at: string;
  completed_at?: string;
}

export interface BackupVerification {
  location: string;
  kind: string;
  created_at: string;
  key_count: number;
  target_count: number;
  keys_decrypted: number;
  problems?: string[];
  valid: boolean;
}

export interface RestoreResult {
  keys_restored: number;
  keys_skipped: number;
  problems?: string[];
}

// -------------------------------------------------------------- consumers ---

export interface Consumer {
  id: string;
  key_id: string;
  name: string;
  kind: string;
  config: Record<string, unknown>;
  enabled: boolean;
  last_delivered_at?: string;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

// --------------------------------------------------------------- webhooks ---

export interface Webhook {
  id: string;
  name: string;
  url: string;
  events: string[];
  enabled: boolean;
  headers: Record<string, string>;
  has_secret: boolean;
  created_at: string;
  updated_at: string;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event: string;
  payload: unknown;
  state: 'pending' | 'delivered' | 'failed' | 'dead';
  attempts: number;
  status_code?: number;
  response?: string;
  next_retry_at?: string;
  created_at: string;
  delivered_at?: string;
  webhook_name?: string;
}

/** A live event, as delivered over the SSE stream. */
export interface LiveEvent {
  id: string;
  type: string;
  resource_type?: string;
  resource_id?: string;
  resource_name?: string;
  data?: Record<string, unknown>;
  occurred_at: string;
}

export interface SystemStatus {
  scheduler_enabled: boolean;
  is_leader: boolean;
  vault_sealed: boolean;
  kek_version: number;
  connectors: string[];
  event_subscribers?: number;
  jobs?: Record<string, number>;
}

// ------------------------------------------------------------------ users ---

/** A local account, as the administration screen sees it. */
/** A named set of permissions. */
export interface Role {
  id: string;
  name: string;
  description: string;
  is_system: boolean;
  permissions: string[];
}

/** One entry in the permission vocabulary the server publishes. */
export interface PermissionInfo {
  name: string;
  group: string;
}

/**
 * An API token as listed. The secret is absent by design — it exists exactly
 * once, in the response to the call that created it.
 */
export interface ApiToken {
  id: string;
  name: string;
  prefix: string;
  username: string;
  permissions: string[];
  scopes: string[];
  status: 'active' | 'revoked' | 'expired';
  expires_at?: string;
  last_used_at?: string;
  revoked_at?: string;
  created_at: string;
}

/** The one-time response to minting a token. */
export interface NewToken {
  token: ApiToken;
  secret: string;
  notice: string;
}

/** Second-factor enrolment material, shown once. */
export interface TotpEnrolment {
  secret: string;
  uri: string;
  qr_code: string;
  recovery_codes: string[];
}

// --------------------------------------------------------- api reference ---

/** The parts of an OpenAPI document the reference screen renders. */
export interface OpenApiDoc {
  info: { title: string; version: string; description: string };
  tags: { name: string }[];
  paths: Record<string, Record<string, OpenApiOperation>>;
}

export interface OpenApiOperation {
  tags: string[];
  summary: string;
  description: string;
  operationId: string;
  parameters?: OpenApiParam[];
  requestBody?: {
    required: boolean;
    content: { 'application/json': { schema: OpenApiSchema } };
  };
}

export interface OpenApiParam {
  name: string;
  in: 'path' | 'query';
  required: boolean;
  description: string;
  schema: { type: string };
}

export interface OpenApiSchema {
  type: string;
  required?: string[];
  properties?: Record<string, { type: string; description: string }>;
}
