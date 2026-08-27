import { HttpClient, HttpErrorResponse, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

import type {
  ApiToken, Assignment, AuditEvent, Backup, BackupVerification, ChainVerification,
  ConnectorInfo, Consumer, Credential, Dashboard, DeployResult, DiscoveredKey,
  Identity, Job, JobLog, ListResponse, LoginResponse, ManagedKey, NewToken,
  OpenApiDoc, PermissionInfo, Principal, ProbeResult, ReconcileResult,
  RestoreResult, Role, Rotation, RotationPlan, RotationPolicy, RotationTarget,
  Snapshot, SystemStatus, Target, TotpEnrolment, User, VaultStatus,
  Webhook, WebhookDelivery,
} from './models';

/** The server mounts the API under this prefix. */
const BASE = '/api/v1';

/**
 * Api is the single place that talks HTTP.
 *
 * Errors are normalised here so every caller can render `err.message` directly
 * instead of unpacking HttpErrorResponse shapes.
 */
@Injectable({ providedIn: 'root' })
export class Api {
  private readonly http = inject(HttpClient);

  // ---------------------------------------------------------------- auth ---

  login(username: string, password: string, totpCode?: string): Observable<LoginResponse> {
    return this.post<LoginResponse>('/auth/login', { username, password, totp_code: totpCode ?? '' });
  }

  logout(): Observable<unknown> {
    return this.post('/auth/logout', {});
  }

  me(): Observable<Identity> {
    return this.get<Identity>('/auth/me');
  }

  stepUp(totpCode: string): Observable<{ status: string; valid_until: string }> {
    return this.post('/auth/step-up', { totp_code: totpCode });
  }

  enrolTotp(): Observable<TotpEnrolment> {
    return this.post('/auth/totp/enrol', {});
  }

  regenerateRecoveryCodes(totpCode: string): Observable<{ recovery_codes: string[] }> {
    return this.post('/auth/totp/recovery-codes', { totp_code: totpCode });
  }

  disableTotp(totpCode: string): Observable<{ status: string }> {
    return this.deleteWith('/auth/totp', { totp_code: totpCode });
  }

  changeOwnPassword(currentPassword: string, password: string): Observable<{ status: string }> {
    return this.post('/auth/password', { current_password: currentPassword, password });
  }

  // --------------------------------------------------------------- users ---

  listUsers(): Observable<ListResponse<User>> {
    return this.get<ListResponse<User>>('/users');
  }

  createUser(body: {
    username: string; password: string; email?: string; display_name?: string;
    roles?: string[]; must_change_password?: boolean; active?: boolean;
  }): Observable<User> {
    return this.post<User>('/users', body);
  }

  updateUser(id: string, body: {
    email?: string; display_name?: string; active?: boolean;
    must_change_password?: boolean; roles?: string[]; unlock?: boolean;
  }): Observable<User> {
    return this.patch<User>(`/users/${id}`, body);
  }

  deleteUser(id: string): Observable<unknown> {
    return this.delete(`/users/${id}`);
  }

  setUserPassword(id: string, password: string, mustChange = true): Observable<{ status: string }> {
    return this.post(`/users/${id}/password`, { password, must_change_password: mustChange });
  }

  resetUserTotp(id: string): Observable<{ status: string }> {
    return this.post(`/users/${id}/reset-totp`, {});
  }

  listRoles(): Observable<ListResponse<Role>> {
    return this.get<ListResponse<Role>>('/roles');
  }

  listPermissions(): Observable<ListResponse<PermissionInfo>> {
    return this.get<ListResponse<PermissionInfo>>('/permissions');
  }

  // ---------------------------------------------------------- api tokens ---

  listTokens(): Observable<ListResponse<ApiToken>> {
    return this.get<ListResponse<ApiToken>>('/api-tokens');
  }

  createToken(body: {
    name: string; permissions?: string[]; scopes?: string[]; expires_in?: string;
  }): Observable<NewToken> {
    return this.post<NewToken>('/api-tokens', body);
  }

  revokeToken(id: string): Observable<{ status: string }> {
    return this.post(`/api-tokens/${id}/revoke`, {});
  }

  deleteToken(id: string): Observable<unknown> {
    return this.delete(`/api-tokens/${id}`);
  }

  // ------------------------------------------------------- api reference ---

  openApi(): Observable<OpenApiDoc> {
    return this.get<OpenApiDoc>('/openapi.json');
  }

  confirmTotp(totpCode: string): Observable<{ status: string }> {
    return this.post('/auth/totp/confirm', { totp_code: totpCode });
  }

  // ---------------------------------------------------------------- keys ---

  listKeys(filter: { status?: string[]; tag?: string[]; q?: string } = {}): Observable<ListResponse<ManagedKey>> {
    let params = new HttpParams().set('limit', '200');
    filter.status?.forEach((s) => (params = params.append('status', s)));
    filter.tag?.forEach((t) => (params = params.append('tag', t)));
    if (filter.q) params = params.set('q', filter.q);
    return this.get<ListResponse<ManagedKey>>('/keys', params);
  }

  getKey(id: string): Observable<ManagedKey> {
    return this.get<ManagedKey>(`/keys/${id}`);
  }

  createKey(body: {
    name: string; algorithm: string; comment?: string;
    description?: string; tags?: string[]; valid_days?: number;
    /** "standard" (default) or "break_glass". */
    key_class?: string;
  }): Observable<ManagedKey> {
    return this.post<ManagedKey>('/keys', body);
  }

  importKey(body: { name: string; private_key: string; passphrase?: string; tags?: string[] }): Observable<ManagedKey> {
    return this.post<ManagedKey>('/keys/import', body);
  }

  /** Reveal requires a reason; it is recorded on the audit trail. */
  revealKey(id: string, reason: string): Observable<{ key: ManagedKey; private_key: string }> {
    return this.post(`/keys/${id}/reveal`, { reason });
  }

  revokeKey(id: string, compromised: boolean, reason: string): Observable<ManagedKey> {
    return this.post<ManagedKey>(`/keys/${id}/revoke`, { compromised, reason });
  }

  setKeyStatus(id: string, status: string): Observable<ManagedKey> {
    return this.post<ManagedKey>(`/keys/${id}/status`, { status });
  }

  // ------------------------------------------------------------- targets ---

  listTargets(filter: { kind?: string[]; tag?: string[]; q?: string } = {}): Observable<ListResponse<Target>> {
    let params = new HttpParams().set('limit', '500');
    filter.kind?.forEach((k) => (params = params.append('kind', k)));
    filter.tag?.forEach((t) => (params = params.append('tag', t)));
    if (filter.q) params = params.set('q', filter.q);
    return this.get<ListResponse<Target>>('/targets', params);
  }

  getTarget(id: string): Observable<Target> {
    return this.get<Target>(`/targets/${id}`);
  }

  createTarget(body: {
    name: string; kind: string; connector: string; address: string;
    port: number; credential_id?: string; tags?: string[]; config?: Record<string, unknown>;
    is_canary?: boolean;
  }): Observable<Target> {
    return this.post<Target>('/targets', body);
  }

  updateTarget(id: string, body: {
    name?: string; address?: string; port?: number; connector?: string; kind?: string;
    config?: Record<string, unknown>; credential_id?: string | null;
    clear_credential?: boolean; tags?: string[]; enabled?: boolean;
    is_canary?: boolean; reconcile_mode?: string; clear_host_key_pin?: boolean;
  }): Observable<Target> {
    return this.patch<Target>(`/targets/${id}`, body);
  }

  updatePrincipal(targetId: string, principalId: string, body: {
    username?: string; authorized_keys_path?: string; use_sudo?: boolean; enabled?: boolean;
  }): Observable<Principal> {
    return this.patch<Principal>(`/targets/${targetId}/principals/${principalId}`, body);
  }

  deletePrincipal(targetId: string, principalId: string): Observable<{ status: string; notice: string }> {
    return this.delete(`/targets/${targetId}/principals/${principalId}`);
  }

  deleteKey(id: string): Observable<unknown> {
    return this.delete(`/keys/${id}`);
  }

  deleteCredential(id: string): Observable<unknown> {
    return this.delete(`/credentials/${id}`);
  }

  setWebhookEnabled(id: string, enabled: boolean): Observable<Webhook> {
    return this.patch<Webhook>(`/webhooks/${id}`, { enabled });
  }

  deleteTarget(id: string): Observable<unknown> {
    return this.delete(`/targets/${id}`);
  }

  probeTarget(id: string): Observable<ProbeResult> {
    return this.post<ProbeResult>(`/targets/${id}/probe`, {});
  }

  listPrincipals(targetId: string): Observable<ListResponse<Principal>> {
    return this.get<ListResponse<Principal>>(`/targets/${targetId}/principals`);
  }

  createPrincipal(targetId: string, body: {
    username: string; authorized_keys_path?: string; use_sudo?: boolean;
  }): Observable<Principal> {
    return this.post<Principal>(`/targets/${targetId}/principals`, body);
  }

  listSnapshots(targetId: string): Observable<ListResponse<Snapshot>> {
    return this.get<ListResponse<Snapshot>>(`/targets/${targetId}/snapshots`);
  }

  /**
   * authorizedKeys renders the file SKM intends for a login.
   *
   * The server answers in text/plain — it is a file, not a record — so this is
   * the one call that bypasses the JSON helpers.
   */
  authorizedKeys(targetId: string, username: string): Observable<string> {
    return this.http.get(
      `${BASE}/targets/${targetId}/authorized-keys/${encodeURIComponent(username)}`,
      { responseType: 'text', withCredentials: true },
    ).pipe(catchError(normalise));
  }

  // ----------------------------------------------------------- inventory ---

  /** Dynamic inventory for Ansible, in its expected JSON shape. */
  ansibleInventory(tags: string[] = []): Observable<unknown> {
    return this.get<unknown>('/inventory/ansible', tagParams(tags));
  }

  /** Dynamic inventory for Nornir. */
  nornirInventory(tags: string[] = []): Observable<unknown> {
    return this.get<unknown>('/inventory/nornir', tagParams(tags));
  }

  /** The absolute URL of an inventory endpoint, for pasting into a config. */
  inventoryUrl(kind: 'ansible' | 'nornir'): string {
    return `${location.origin}${BASE}/inventory/${kind}`;
  }

  // --------------------------------------------------------- assignments ---

  listAssignments(filter: { key_id?: string; target_id?: string; drifted?: boolean } = {}): Observable<ListResponse<Assignment>> {
    let params = new HttpParams().set('limit', '1000');
    if (filter.key_id) params = params.set('key_id', filter.key_id);
    if (filter.target_id) params = params.set('target_id', filter.target_id);
    if (filter.drifted) params = params.set('drifted', 'true');
    return this.get<ListResponse<Assignment>>('/assignments', params);
  }

  createAssignment(body: {
    key_id: string; target_id: string; principal_id: string; options?: string[];
  }): Observable<Assignment> {
    return this.post<Assignment>('/assignments', body);
  }

  deleteAssignment(id: string): Observable<unknown> {
    return this.delete(`/assignments/${id}`);
  }

  // -------------------------------------------------------------- deploy ---

  deploy(body: {
    target_id: string; principal_id: string;
    dry_run?: boolean; prune?: boolean; verify_auth?: boolean;
  }): Observable<DeployResult> {
    return this.post<DeployResult>('/deploy', body);
  }

  rollback(snapshotId: string): Observable<DeployResult> {
    return this.post<DeployResult>(`/rollback/${snapshotId}`, {});
  }

  // --------------------------------------------------------- credentials ---

  listCredentials(): Observable<ListResponse<Credential>> {
    return this.get<ListResponse<Credential>>('/credentials');
  }

  createCredential(body: {
    name: string; kind: string; username?: string; secret?: string; key_id?: string;
  }): Observable<Credential> {
    return this.post<Credential>('/credentials', body);
  }

  // --------------------------------------------------------------- audit ---

  listAudit(filter: { action?: string[]; outcome?: string; limit?: number } = {}): Observable<ListResponse<AuditEvent>> {
    let params = new HttpParams().set('limit', String(filter.limit ?? 100));
    filter.action?.forEach((a) => (params = params.append('action', a)));
    if (filter.outcome) params = params.set('outcome', filter.outcome);
    return this.get<ListResponse<AuditEvent>>('/audit', params);
  }

  verifyAudit(): Observable<ChainVerification> {
    return this.get<ChainVerification>('/audit/verify');
  }

  // -------------------------------------------------------------- system ---

  dashboard(): Observable<Dashboard> {
    return this.get<Dashboard>('/dashboard');
  }

  vaultStatus(): Observable<VaultStatus> {
    return this.get<VaultStatus>('/vault/status');
  }

  rotateKek(): Observable<{ keys_rewrapped: number; kek_version: number }> {
    return this.post('/vault/rotate-kek', {});
  }

  connectors(): Observable<{ connectors: ConnectorInfo[]; algorithms: string[] }> {
    return this.get('/connectors');
  }

  status(): Observable<SystemStatus> {
    return this.get<SystemStatus>('/status');
  }

  // ------------------------------------------------------------ rotation ---

  listRotations(states: string[] = []): Observable<ListResponse<Rotation>> {
    let params = new HttpParams().set('limit', '100');
    states.forEach((s) => (params = params.append('state', s)));
    return this.get<ListResponse<Rotation>>('/rotations', params);
  }

  getRotation(id: string): Observable<{ rotation: Rotation; targets: RotationTarget[] }> {
    return this.get(`/rotations/${id}`);
  }

  /** Plans a rotation and, unless held for approval, starts it. */
  /** soak_hours is sent explicitly, including zero: the server treats an
   *  omitted field as "use the default" and a literal 0 as "no soak". */
  planRotation(body: {
    key_id: string; algorithm?: string; soak_hours?: number;
    canary_percent?: number; failure_threshold?: number;
    approval_required?: boolean; dry_run?: boolean; start?: boolean;
  }): Observable<RotationPlan> {
    return this.post<RotationPlan>('/rotations', body);
  }

  startRotation(id: string): Observable<Rotation> {
    return this.post<Rotation>(`/rotations/${id}/start`, {});
  }

  approveRotation(id: string): Observable<Rotation> {
    return this.post<Rotation>(`/rotations/${id}/approve`, {});
  }

  abortRotation(id: string, reason: string): Observable<Rotation> {
    return this.post<Rotation>(`/rotations/${id}/abort`, { reason });
  }

  listPolicies(): Observable<ListResponse<RotationPolicy>> {
    return this.get<ListResponse<RotationPolicy>>('/rotation-policies');
  }

  createPolicy(body: {
    name: string; enabled: boolean; cron_expr?: string; max_age_days?: number;
    algorithm?: string; soak_hours?: number; canary_percent?: number;
    failure_threshold?: number; approval_required?: boolean;
    key_tags?: string[]; target_tags?: string[]; key_class?: string;
  }): Observable<RotationPolicy> {
    return this.post<RotationPolicy>('/rotation-policies', body);
  }

  deletePolicy(id: string): Observable<unknown> {
    return this.delete(`/rotation-policies/${id}`);
  }

  /** Answers "when would this fire?" before a policy is saved. */
  previewSchedule(expr: string): Observable<{ expr: string; next_runs: string[] }> {
    return this.get('/rotation-policies/preview', new HttpParams().set('expr', expr));
  }

  // ---------------------------------------------------------------- jobs ---

  listJobs(filter: { state?: string[]; type?: string[]; rotation_id?: string } = {}): Observable<ListResponse<Job>> {
    let params = new HttpParams().set('limit', '100');
    filter.state?.forEach((s) => (params = params.append('state', s)));
    filter.type?.forEach((t) => (params = params.append('type', t)));
    if (filter.rotation_id) params = params.set('rotation_id', filter.rotation_id);
    return this.get<ListResponse<Job>>('/jobs', params);
  }

  getJob(id: string): Observable<Job> {
    return this.get<Job>(`/jobs/${id}`);
  }

  /** Reads a job's log forward from a cursor, so polling never re-reads. */
  jobLogs(id: string, after = 0): Observable<{ items: JobLog[]; cursor: number }> {
    return this.get(`/jobs/${id}/logs`, new HttpParams().set('after', String(after)));
  }

  cancelJob(id: string): Observable<unknown> {
    return this.post(`/jobs/${id}/cancel`, {});
  }

  // ----------------------------------------------------------- reconcile ---

  reconcile(targetId?: string, async = false): Observable<ReconcileResult | Job> {
    return this.post('/reconcile', { target_id: targetId ?? '', async });
  }

  listDiscovered(filter: { state?: string[]; target_id?: string } = {}): Observable<ListResponse<DiscoveredKey>> {
    let params = new HttpParams().set('limit', '300');
    filter.state?.forEach((s) => (params = params.append('state', s)));
    if (filter.target_id) params = params.set('target_id', filter.target_id);
    return this.get<ListResponse<DiscoveredKey>>('/discovered-keys', params);
  }

  adoptKey(id: string, name?: string): Observable<ManagedKey> {
    return this.post<ManagedKey>(`/discovered-keys/${id}/adopt`, { name: name ?? '' });
  }

  ignoreDiscovered(id: string): Observable<DiscoveredKey> {
    return this.post<DiscoveredKey>(`/discovered-keys/${id}/ignore`, {});
  }

  // ------------------------------------------------------------- backups ---

  listBackups(): Observable<ListResponse<Backup>> {
    return this.get<ListResponse<Backup>>('/backups');
  }

  createBackup(body: { name?: string; kind?: string; passphrase: string; retain_days?: number }): Observable<Backup> {
    return this.post<Backup>('/backups', body);
  }

  verifyBackup(id: string, passphrase: string): Observable<BackupVerification> {
    return this.post<BackupVerification>(`/backups/${id}/verify`, { passphrase });
  }

  restoreBackup(body: { backup_id?: string; path?: string; passphrase: string }): Observable<RestoreResult> {
    return this.post<RestoreResult>('/restore', body);
  }

  deleteBackup(id: string): Observable<unknown> {
    return this.delete(`/backups/${id}`);
  }

  // ----------------------------------------------------------- consumers ---

  listConsumers(keyId?: string): Observable<ListResponse<Consumer>> {
    const params = keyId ? new HttpParams().set('key_id', keyId) : undefined;
    return this.get<ListResponse<Consumer>>('/consumers', params);
  }

  createConsumer(body: {
    name: string; kind: string; key_id: string;
    config: Record<string, unknown>; enabled: boolean;
  }): Observable<Consumer> {
    return this.post<Consumer>('/consumers', body);
  }

  deliverConsumer(id: string): Observable<unknown> {
    return this.post(`/consumers/${id}/deliver`, {});
  }

  deleteConsumer(id: string): Observable<unknown> {
    return this.delete(`/consumers/${id}`);
  }

  // ------------------------------------------------------------ webhooks ---

  listWebhooks(): Observable<ListResponse<Webhook>> {
    return this.get<ListResponse<Webhook>>('/webhooks');
  }

  createWebhook(body: {
    name: string; url: string; events: string[];
    headers?: Record<string, string>; enabled: boolean; secret?: string;
  }): Observable<{ webhook: Webhook; secret?: string; note?: string }> {
    return this.post('/webhooks', body);
  }

  deleteWebhook(id: string): Observable<unknown> {
    return this.delete(`/webhooks/${id}`);
  }

  listDeliveries(webhookId?: string): Observable<ListResponse<WebhookDelivery>> {
    const params = webhookId ? new HttpParams().set('webhook_id', webhookId) : undefined;
    return this.get<ListResponse<WebhookDelivery>>('/webhooks/deliveries', params);
  }

  replayDelivery(id: string): Observable<unknown> {
    return this.post(`/webhooks/deliveries/${id}/replay`, {});
  }

  eventTypes(): Observable<{ events: string[] }> {
    return this.get('/events/types');
  }

  // ------------------------------------------------------------ plumbing ---

  private get<T>(path: string, params?: HttpParams): Observable<T> {
    return this.http.get<T>(BASE + path, { params, withCredentials: true }).pipe(catchError(normalise));
  }

  private post<T>(path: string, body: unknown): Observable<T> {
    return this.http.post<T>(BASE + path, body, { withCredentials: true }).pipe(catchError(normalise));
  }

  private patch<T>(path: string, body: unknown): Observable<T> {
    return this.http.patch<T>(BASE + path, body, { withCredentials: true }).pipe(catchError(normalise));
  }

  private delete<T>(path: string): Observable<T> {
    return this.http.delete<T>(BASE + path, { withCredentials: true }).pipe(catchError(normalise));
  }

  /** DELETE with a body, which Angular's HttpClient only exposes via request(). */
  private deleteWith<T>(path: string, body: unknown): Observable<T> {
    return this.http.request<T>('DELETE', BASE + path, { body, withCredentials: true })
      .pipe(catchError(normalise));
  }
}

/** tagParams renders repeated ?tag= filters, which both inventories accept. */
function tagParams(tags: string[]): HttpParams {
  let params = new HttpParams();
  for (const t of tags) params = params.append('tag', t);
  return params;
}

/** ApiError carries the server's own error code alongside the message. */
export interface ApiError extends Error {
  code?: string;
  status?: number;
}

/** mfaRequired reports whether a failure wants a fresh second-factor code. */
export function mfaRequired(err: unknown): boolean {
  return (err as ApiError | null)?.code === 'mfa_required';
}

/**
 * normalise turns an HttpErrorResponse into an Error carrying the server's
 * message, so components render it without special-casing transport failures
 * against API errors.
 */
function normalise(err: HttpErrorResponse) {
  if (err.status === 0) {
    return throwError(() => new Error('Cannot reach the SKM server. Is it running?'));
  }
  const body = err.error as { error?: string; code?: string } | null;
  const wrapped = new Error(body?.error ?? err.message ?? 'Request failed') as ApiError;
  wrapped.code = body?.code;
  wrapped.status = err.status;
  return throwError(() => wrapped);
}
