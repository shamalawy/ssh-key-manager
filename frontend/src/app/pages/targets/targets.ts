import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import { Auth } from '../../core/auth';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import { Modal } from '../../shared/modal';
import type { ConnectorInfo, ConnectorSetting, Credential, Principal, Snapshot, Target } from '../../core/models';

@Component({
  selector: 'skm-targets',
  imports: [FormsModule, DatePipe, Alerts, Modal],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .toolbar { display: flex; gap: 0.6rem; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; }
    .toolbar input[type=search] { max-width: 260px; }
    .pin { font-family: var(--mono); font-size: 0.74rem; color: var(--text-muted); word-break: break-all; }
    .principal-row {
      display: flex; align-items: center; gap: 0.6rem;
      padding: 0.45rem 0; border-bottom: 1px solid var(--border-soft);
    }
    .principal-row:last-child { border-bottom: none; }
    .keys-preview {
      font-family: var(--mono); font-size: 0.74rem; margin: 0 0 0.4rem;
      background: var(--bg-input); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 0.6rem;
      white-space: pre-wrap; word-break: break-all;
      max-height: 220px; overflow-y: auto;
    }
    .req { color: var(--danger); }
    .spacer { flex: 1; }
  `],
  template: `
    <div class="card-header">
      <h1>Targets</h1>
      @if (auth.can('target.write')) {
        <button class="primary" type="button" (click)="openCreate()">Add target</button>
      }
    </div>

    <skm-alerts [error]="error" [notice]="notice" />

    <div class="toolbar">
      <input type="search" placeholder="Search name or address…"
             [(ngModel)]="search" (ngModelChange)="reload()" />
      <span class="spacer"></span>
      <span class="muted small">{{ targets().length }} target(s)</span>
    </div>

    <div class="card">
      @if (loading()) {
        <div class="empty"><span class="spinner"></span> Loading…</div>
      } @else if (targets().length === 0) {
        <div class="empty">
          No targets yet. First add a credential on the <strong>Credentials</strong>
          tab so SKM has a way to sign in, then add a target here and pick it.
        </div>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th><th>Kind</th><th>Address</th><th>Health</th>
                <th>Drift</th><th>Tags</th><th>Last seen</th><th></th>
              </tr>
            </thead>
            <tbody>
              @for (t of targets(); track t.id) {
                <tr>
                  <td>
                    <strong>{{ t.name }}</strong>
                    @if (t.is_canary) { <span class="badge info">canary</span> }
                    @if (!t.enabled) { <span class="badge neutral">disabled</span> }
                  </td>
                  <td class="mono small">{{ t.kind }}</td>
                  <td class="mono small">{{ t.address }}:{{ t.port }}</td>
                  <td><span class="badge" [class]="healthClass(t)">{{ t.health }}</span></td>
                  <td><span class="badge" [class]="driftClass(t)">{{ t.drift_state }}</span></td>
                  <td>@for (tag of t.tags; track tag) { <span class="tag">{{ tag }}</span> }</td>
                  <td class="small faint">{{ t.last_seen_at ? (t.last_seen_at | date:'MMM d, HH:mm') : '—' }}</td>
                  <td>
                    <div class="row">
                      <button class="ghost sm" type="button" (click)="select(t)">Details</button>
                      <button class="ghost sm" type="button" [disabled]="probing() === t.id" (click)="probe(t)">
                        @if (probing() === t.id) { <span class="spinner"></span> } Probe
                      </button>
                      @if (auth.can('target.write')) {
                        <button class="ghost sm" type="button" (click)="openEdit(t)">Edit</button>
                      }
                      @if (auth.can('target.delete')) {
                        <button class="ghost sm" type="button" [disabled]="busyId() === t.id" (click)="remove(t)">
                          @if (busyId() === t.id) { <span class="spinner"></span> } Delete
                        </button>
                      }
                    </div>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </div>


    <!-- Inventory export ----------------------------------------------- -->
    <div class="card" style="margin-top: 1.4rem;">
      <div class="card-header">
        <h2>Use these machines from Ansible or Nornir</h2>
      </div>
      <p class="small faint" style="padding: 0 1rem;">
        SKM can hand its list of machines straight to your automation tool, so
        you keep one list instead of two. Point the tool at the address below and
        it picks up every machine here, with its tags as groups. Add
        <code>?tag=prod</code> to narrow it down. You will need an API token —
        make one under Users and access.
      </p>
      <div style="padding: 0 1rem 1rem;">
        <div class="row" style="margin-bottom: 0.5rem;">
          <strong style="min-width: 5rem;">Ansible</strong>
          <code class="mono small">{{ ansibleUrl }}</code>
          <button class="ghost sm" type="button" (click)="copyText(ansibleUrl)">Copy</button>
          <button class="ghost sm" type="button" (click)="previewInventory('ansible')">Preview</button>
        </div>
        <div class="row">
          <strong style="min-width: 5rem;">Nornir</strong>
          <code class="mono small">{{ nornirUrl }}</code>
          <button class="ghost sm" type="button" (click)="copyText(nornirUrl)">Copy</button>
          <button class="ghost sm" type="button" (click)="previewInventory('nornir')">Preview</button>
        </div>

        @if (inventoryPreview(); as text) {
          <p class="small faint" style="margin: 0.9rem 0 0.4rem;">
            Exactly what your automation tool will receive:
          </p>
          <pre class="keys-preview">{{ text }}</pre>
          <button class="ghost sm" type="button" (click)="inventoryPreview.set(null)">Hide</button>
        }
      </div>
    </div>

    <!-- Add target ----------------------------------------------------- -->
    @if (creating()) {
      <skm-modal title="Add a target" (close)="creating.set(false)">
        @if (formError(); as message) { <div class="notice error">{{ message }}</div> }

          <label>
            <span class="label">Name</span>
            <input [(ngModel)]="draft.name" placeholder="web-01" />
          </label>

          <label>
            <span class="label">Connector</span>
            <select [(ngModel)]="draft.connector">
              @for (c of connectors(); track c) { <option [value]="c">{{ c }}</option> }
            </select>
          </label>

          <div class="grid cols-2">
            <label>
              <span class="label">Address</span>
              <input [(ngModel)]="draft.address" placeholder="10.0.0.10" />
            </label>
            <label>
              <span class="label">Port</span>
              <input type="number" [(ngModel)]="draft.port" />
            </label>
          </div>

          <label>
            <span class="label">Credential</span>
            <select [(ngModel)]="draft.credentialId">
              <option [ngValue]="null">— none —</option>
              @for (c of credentials(); track c.id) {
                <option [ngValue]="c.id">{{ c.name }} ({{ c.kind }}, {{ c.username }})</option>
              }
            </select>
            <span class="hint">
              Optional here; without one, SKM cannot connect until you set it in Edit. How SKM signs in to manage this host. For an EC2 instance this is
              the <code>.pem</code> AWS gave you plus the image's login name
              (<code>ec2-user</code>, <code>ubuntu</code>). If the list is empty,
              add one on the <strong>Credentials</strong> tab first.
            </span>
          </label>

          <label>
            <span class="label">Tags</span>
            <input [(ngModel)]="draft.tags" placeholder="prod, web" />
          </label>

          <label class="checkbox" style="margin: 0;">
            <input type="checkbox" [(ngModel)]="draft.isCanary" />
            <span>Is a canary (rotations reach it first)</span>
          </label>

          @for (setting of settingsFor(draft.connector); track setting.key) {
            <label>
              <span class="label">{{ setting.label }}@if (setting.required) { <span class="req">*</span> }</span>
              @if (setting.type === 'choice') {
                <select [ngModel]="draft.config[setting.key] ?? setting.default ?? ''"
                        (ngModelChange)="draft.config[setting.key] = $event"
                        [name]="'new-' + setting.key">
                  @for (choice of setting.choices ?? []; track choice) {
                    <option [value]="choice">{{ choice || '— default —' }}</option>
                  }
                </select>
              } @else if (setting.type === 'bool') {
                <label class="checkbox" style="margin: 0;">
                  <input type="checkbox" [ngModel]="!!draft.config[setting.key]"
                         (ngModelChange)="draft.config[setting.key] = $event"
                         [name]="'new-' + setting.key" />
                  <span>enabled</span>
                </label>
              } @else {
                <input [ngModel]="draft.config[setting.key] ?? ''"
                       (ngModelChange)="draft.config[setting.key] = $event"
                       [name]="'new-' + setting.key" [placeholder]="setting.default ?? ''" />
              }
              <span class="hint">{{ setting.description }}</span>
            </label>
          }

        <div class="row end">
          <button type="button" (click)="creating.set(false)">Cancel</button>
          <button class="primary" type="button"
                  [disabled]="busy() || !draft.name || !draft.address" (click)="create()">
            @if (busy()) { <span class="spinner"></span> } Add
          </button>
        </div>

        <hr style="border: none; border-top: 1px solid var(--border-soft); margin: 1.3rem 0 1rem;" />

        <p class="small faint">
          Credentials live on their own tab now, where a private key gets a
          proper box to paste into. Open <strong>Credentials</strong> in the
          sidebar, add one, then come back and pick it here.
        </p>
      </skm-modal>
    }


    <!-- Edit target ---------------------------------------------------- -->
    @if (editing(); as t) {
      <skm-modal [title]="'Edit ' + t.name" [wide]="true" (close)="editing.set(null)">
        @if (formError(); as message) { <div class="notice error">{{ message }}</div> }

          <div class="grid cols-2">
            <label>
              <span class="label">Name</span>
              <input [(ngModel)]="edit.name" name="edit-name" />
            </label>
            <label>
              <span class="label">Connector</span>
              <select [(ngModel)]="edit.connector" name="edit-connector">
                @for (c of connectors(); track c) { <option [value]="c">{{ c }}</option> }
              </select>
            </label>
            <label>
              <span class="label">Address</span>
              <input [(ngModel)]="edit.address" name="edit-address" />
            </label>
            <label>
              <span class="label">Port</span>
              <input type="number" [(ngModel)]="edit.port" name="edit-port" />
            </label>
          </div>

          <label>
            <span class="label">Credential</span>
            <select [(ngModel)]="edit.credentialId" name="edit-credential">
              <option [ngValue]="null">— none —</option>
              @for (c of credentials(); track c.id) {
                <option [ngValue]="c.id">{{ c.name }} ({{ c.kind }}, {{ c.username }})</option>
              }
            </select>
          </label>

          <label>
            <span class="label">Tags</span>
            <input [(ngModel)]="edit.tags" name="edit-tags" placeholder="prod, web" />
          </label>

          <label>
            <span class="label">Drift handling</span>
            <select [(ngModel)]="edit.reconcileMode" name="edit-reconcile">
              <option value="report_only">Report only — tell me, change nothing</option>
              <option value="auto_heal">Auto heal — put back what should be there</option>
              <option value="disabled">Disabled — do not scan this target</option>
            </select>
            <span class="hint">
              Auto heal reapplies desired state on every sweep. Report only is the
              honest default until you trust what the scan is finding.
            </span>
          </label>

          @for (setting of settingsFor(edit.connector); track setting.key) {
            <label>
              <span class="label">{{ setting.label }}@if (setting.required) { <span class="req">*</span> }</span>
              @if (setting.type === 'choice') {
                <select [ngModel]="edit.config[setting.key] ?? setting.default ?? ''"
                        (ngModelChange)="edit.config[setting.key] = $event"
                        [name]="'edit-' + setting.key">
                  @for (choice of setting.choices ?? []; track choice) {
                    <option [value]="choice">{{ choice || '— default —' }}</option>
                  }
                </select>
              } @else if (setting.type === 'bool') {
                <label class="checkbox" style="margin: 0;">
                  <input type="checkbox" [ngModel]="!!edit.config[setting.key]"
                         (ngModelChange)="edit.config[setting.key] = $event"
                         [name]="'edit-' + setting.key" />
                  <span>enabled</span>
                </label>
              } @else {
                <input [ngModel]="edit.config[setting.key] ?? ''"
                       (ngModelChange)="edit.config[setting.key] = $event"
                       [name]="'edit-' + setting.key" [placeholder]="setting.default ?? ''" />
              }
              <span class="hint">{{ setting.description }}</span>
            </label>
          }

          <div class="row" style="gap: 1.2rem; margin: 0.8rem 0;">
            <label class="checkbox" style="margin: 0;">
              <input type="checkbox" [(ngModel)]="edit.enabled" name="edit-enabled" />
              <span>Enabled</span>
            </label>
            <label class="checkbox" style="margin: 0;">
              <input type="checkbox" [(ngModel)]="edit.isCanary" name="edit-canary" />
              <span>Canary — reached first in a rotation</span>
            </label>
          </div>

          @if (t.host_key_pin) {
            <label class="checkbox">
              <input type="checkbox" [(ngModel)]="edit.clearHostKeyPin" name="edit-clearpin" />
              <span>Forget the pinned host key</span>
            </label>
            <p class="hint" style="margin-top: -0.3rem;">
              Only after the host has genuinely been rebuilt. Clearing the pin
              means the next connection trusts whatever answers, which is the
              one thing pinning exists to prevent.
            </p>
          }

        <div class="row end" style="margin-top: 1rem;">
          <button type="button" (click)="editing.set(null)">Cancel</button>
          <button class="primary" type="button" [disabled]="busy() || !edit.name || !edit.address"
                  (click)="saveEdit(t)">
            @if (busy()) { <span class="spinner"></span> } Save
          </button>
        </div>
      </skm-modal>
    }

    <!-- Target details ------------------------------------------------- -->
    @if (selected(); as t) {
      <skm-modal [title]="t.name" [wide]="true" (close)="selected.set(null)">

          <div class="grid cols-2" style="margin-bottom: 1rem;">
            <div><span class="label small faint">Address</span><div class="mono">{{ t.address }}:{{ t.port }}</div></div>
            <div><span class="label small faint">Connector</span><div class="mono">{{ t.connector }}</div></div>
            <div><span class="label small faint">Health</span>
                 <div><span class="badge" [class]="healthClass(t)">{{ t.health }}</span>
                      <span class="small muted"> {{ t.health_message }}</span></div></div>
            <div><span class="label small faint">Drift</span>
                 <div><span class="badge" [class]="driftClass(t)">{{ t.drift_state }}</span></div></div>
          </div>

          <span class="label small faint">Pinned host key</span>
          <div class="pin" style="margin-bottom: 1.2rem;">
            {{ t.host_key_pin || 'not yet pinned — run a probe' }}
          </div>

          <h3>Managed accounts</h3>
          @if (principals().length === 0) {
            <p class="muted small">No accounts are managed on this target yet.</p>
          } @else {
            @for (p of principals(); track p.id) {
              <div class="principal-row">
                @if (editingPrincipal() === p.id) {
                  <input [(ngModel)]="principalEdit.username" [name]="'pu-' + p.id"
                         style="max-width: 140px;" />
                  <input [(ngModel)]="principalEdit.path" [name]="'pp-' + p.id"
                         placeholder="~/.ssh/authorized_keys" style="max-width: 220px;" />
                  <label class="checkbox" style="margin: 0;">
                    <input type="checkbox" [(ngModel)]="principalEdit.useSudo" [name]="'ps-' + p.id" />
                    <span>sudo</span>
                  </label>
                  <label class="checkbox" style="margin: 0;">
                    <input type="checkbox" [(ngModel)]="principalEdit.enabled" [name]="'pe-' + p.id" />
                    <span>enabled</span>
                  </label>
                  <span class="spacer"></span>
                  <button class="ghost sm" type="button" [disabled]="busyId() === p.id" (click)="editingPrincipal.set(null)">Cancel</button>
                  <button class="sm" type="button" [disabled]="busyId() === p.id" (click)="savePrincipal(t, p)">
                    @if (busyId() === p.id) { <span class="spinner"></span> } Save
                  </button>
                } @else {
                  <strong class="mono">{{ p.username }}</strong>
                  @if (p.use_sudo) { <span class="badge neutral">sudo</span> }
                  @if (!p.enabled) { <span class="badge neutral">disabled</span> }
                  <span class="small faint">{{ p.authorized_keys_path || '~/.ssh/authorized_keys' }}</span>
                  <span class="spacer"></span>
                  <button class="ghost sm" type="button" [disabled]="busyId() === p.id" (click)="showKeys(t, p)"
                          title="See the authorized_keys file SKM intends for this login">
                    @if (busyId() === p.id) { <span class="spinner"></span> } View keys
                  </button>
                  @if (auth.can('target.write')) {
                    <button class="ghost sm" type="button" (click)="startEditPrincipal(p)">Edit</button>
                    <button class="ghost sm" type="button" [disabled]="busyId() === p.id" (click)="removePrincipal(t, p)">
                      @if (busyId() === p.id) { <span class="spinner"></span> } Remove
                    </button>
                  }
                }
              </div>

              @if (keysFor() === p.id) {
                <div style="margin: 0 0 0.9rem 0.4rem;">
                  <p class="small faint" style="margin: 0 0 0.4rem;">
                    What SKM wants <code class="mono">{{ p.username }}</code>'s
                    <code>authorized_keys</code> to contain. This is the intended
                    file, not a read of the machine — deploy to make the machine
                    match it.
                  </p>
                  <pre class="keys-preview">{{ keysText() || '(loading…)' }}</pre>
                  <button class="ghost sm" type="button" (click)="copyKeys()">Copy</button>
                </div>
              }
            }
          }

          @if (auth.can('target.write')) {
            <div class="row" style="margin-top: 0.8rem;">
              <input [(ngModel)]="newPrincipal" placeholder="username" style="max-width: 200px;" />
              <label class="checkbox" style="margin: 0;">
                <input type="checkbox" [(ngModel)]="newPrincipalSudo" /> <span>use sudo</span>
              </label>
              <button type="button" [disabled]="busy() || !newPrincipal" (click)="addPrincipal(t)">
                @if (busy()) { <span class="spinner"></span> } Add account
              </button>
            </div>
          }

          <h3 style="margin-top: 1.4rem;">Snapshots</h3>
          @if (snapshots().length === 0) {
            <p class="muted small">No snapshots yet. One is taken before every change.</p>
          } @else {
            <div class="table-wrap">
              <table>
                <thead><tr><th>Taken</th><th>Login</th><th>Keys</th><th>Checksum</th><th></th></tr></thead>
                <tbody>
                  @for (s of snapshots(); track s.id) {
                    <tr>
                      <td class="small">{{ s.taken_at | date:'MMM d, HH:mm:ss' }}</td>
                      <td class="mono small">{{ principalName(s.principal_id) }}</td>
                      <td>{{ s.key_count }}</td>
                      <td class="mono small truncate" style="max-width: 200px;">{{ s.checksum }}</td>
                      <td>
                        @if (auth.can('changeset.rollback')) {
                          <button class="danger sm" type="button" [disabled]="busyId() === s.id" (click)="rollback(s)">
                            @if (busyId() === s.id) { <span class="spinner"></span> } Roll back
                          </button>
                        }
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }

        <div class="row end" style="margin-top: 1.2rem;">
          @if (auth.can('target.write')) {
            <button type="button" (click)="selected.set(null); openEdit(t)">Edit target</button>
          }
          <button type="button" (click)="selected.set(null)">Close</button>
        </div>
      </skm-modal>
    }
  `,
})
export class TargetsPage implements OnInit {
  private readonly api = inject(Api);
  protected readonly auth = inject(Auth);
  private readonly confirm = inject(Confirm);

  protected readonly targets = signal<Target[]>([]);
  protected readonly credentials = signal<Credential[]>([]);
  protected readonly connectors = signal<string[]>(['linux']);
  protected readonly principals = signal<Principal[]>([]);
  protected readonly snapshots = signal<Snapshot[]>([]);

  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  protected readonly busyId = signal<string | null>(null);
  protected readonly probing = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly formError = signal<string | null>(null);

  protected readonly creating = signal(false);
  protected readonly editing = signal<Target | null>(null);
  protected readonly selected = signal<Target | null>(null);
  protected readonly editingPrincipal = signal<string | null>(null);
  /** Which login's rendered authorized_keys is expanded, and its content. */
  protected readonly keysFor = signal<string | null>(null);
  protected readonly keysText = signal<string>('');

  /** Connector settings, indexed by kind, as published by the server. */
  protected readonly connectorSettings = signal<Record<string, ConnectorSetting[]>>({});

  protected search = '';
  protected newPrincipal = '';
  protected newPrincipalSudo = false;

  protected draft = {
    name: '', connector: 'linux', address: '', port: 22,
    credentialId: null as string | null, tags: '', isCanary: false,
    config: {} as Record<string, unknown>,
  };

  protected edit = {
    name: '', connector: 'linux', address: '', port: 22,
    credentialId: null as string | null, tags: '',
    enabled: true, isCanary: false, reconcileMode: 'report_only',
    clearHostKeyPin: false, config: {} as Record<string, unknown>,
  };

  protected principalEdit = { username: '', path: '', useSudo: false, enabled: true };

  ngOnInit(): void {
    this.reload();
    this.loadCredentials();
    this.api.connectors().subscribe({
      next: (r) => {
        this.connectors.set(r.connectors.map((c: ConnectorInfo) => c.kind));
        const settings: Record<string, ConnectorSetting[]> = {};
        for (const c of r.connectors as ConnectorInfo[]) {
          if (c.settings?.length) settings[c.kind] = c.settings;
        }
        this.connectorSettings.set(settings);
      },
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected reload(): void {
    this.loading.set(true);
    this.api.listTargets({ q: this.search || undefined }).subscribe({
      next: (r) => {
        this.targets.set(r.items);
        this.loading.set(false);
      },
      error: (err: Error) => {
        this.error.set(err.message);
        this.loading.set(false);
      },
    });
  }

  private loadCredentials(): void {
    this.api.listCredentials().subscribe({
      next: (r) => this.credentials.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  /** settingsFor is what turns a connector's declared config into a form. */
  protected settingsFor(connector: string): ConnectorSetting[] {
    return this.connectorSettings()[connector] ?? [];
  }

  protected openCreate(): void {
    this.draft = {
      name: '', connector: 'linux', address: '', port: 22,
      credentialId: null, tags: '', isCanary: false, config: {},
    };
    this.formError.set(null);
    this.creating.set(true);
  }

  protected openEdit(t: Target): void {
    this.edit = {
      name: t.name,
      connector: t.connector,
      address: t.address,
      port: t.port,
      credentialId: t.credential_id ?? null,
      tags: (t.tags ?? []).join(', '),
      enabled: t.enabled,
      isCanary: t.is_canary,
      reconcileMode: t.reconcile_mode || 'report_only',
      clearHostKeyPin: false,
      config: { ...(t.config ?? {}) },
    };
    this.formError.set(null);
    this.editing.set(t);
  }

  protected saveEdit(t: Target): void {
    this.busy.set(true);
    this.formError.set(null);

    this.api.updateTarget(t.id, {
      name: this.edit.name,
      connector: this.edit.connector,
      kind: this.edit.connector,
      address: this.edit.address,
      port: Number(this.edit.port) || 22,
      // A null credential means "unbind"; the API needs that said explicitly,
      // because an absent field means "leave it alone".
      credential_id: this.edit.credentialId ?? undefined,
      clear_credential: this.edit.credentialId === null,
      tags: this.edit.tags.split(',').map((tag) => tag.trim()).filter(Boolean),
      enabled: this.edit.enabled,
      is_canary: this.edit.isCanary,
      reconcile_mode: this.edit.reconcileMode,
      config: this.prune(this.edit.config),
      clear_host_key_pin: this.edit.clearHostKeyPin,
    }).subscribe({
      next: (updated) => {
        this.busy.set(false);
        this.editing.set(null);
        this.notice.set(`Saved ${updated.name}.`);
        this.reload();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.formError.set(err.message);
      },
    });
  }

  /**
   * prune drops empty settings so an untouched optional field is stored as
   * absent rather than as an empty string. The connectors treat "" as unset
   * anyway, but a config object full of empty keys is unreadable in the audit
   * log and in a backup.
   */
  private prune(config: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(config)) {
      if (value === '' || value === null || value === undefined || value === false) continue;
      out[key] = value;
    }
    return out;
  }

  protected async remove(t: Target): Promise<void> {
    if (!(await this.confirm.ask({
      title: `Delete ${t.name}?`,
      message: 'This removes SKM\'s record of the target, along with its assignments and snapshots. Keys already installed on the host are NOT removed — if you meant to withdraw access, remove the assignments and deploy first.',
      action: 'Delete',
      danger: true,
    }))) return;

    this.busyId.set(t.id);
    this.api.deleteTarget(t.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.notice.set(`Deleted ${t.name}. Any keys on the host were left in place.`);
        this.reload();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  /**
   * showKeys renders the authorized_keys SKM intends for one login.
   *
   * It is desired state rather than a read of the host, which is the point: it
   * is the thing a deployment would write, so it can be checked before one runs
   * or handed to a configuration management tool that writes the file itself.
   */
  protected showKeys(t: Target, p: Principal): void {
    if (this.keysFor() === p.id) {
      this.keysFor.set(null);
      this.busyId.set(null);
      return;
    }

    this.keysText.set('');
    this.keysFor.set(p.id);
    this.busyId.set(p.id);
    this.api.authorizedKeys(t.id, p.username).subscribe({
      next: (text) => {
        this.busyId.set(null);
        this.keysText.set(text.trim() || '# nothing assigned to this login yet');
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.keysText.set(`# could not render: ${err.message}`);
      },
    });
  }

  protected copyKeys(): void {
    navigator.clipboard?.writeText(this.keysText()).catch(() => {
      this.error.set('Could not copy to the clipboard.');
    });
  }

  protected copyText(text: string): void {
    navigator.clipboard?.writeText(text).catch(() => {
      this.error.set('Could not copy to the clipboard.');
    });
  }

  protected readonly ansibleUrl = this.api.inventoryUrl('ansible');
  protected readonly nornirUrl = this.api.inventoryUrl('nornir');
  protected readonly inventoryPreview = signal<string | null>(null);

  /** previewInventory shows the document the automation tool would fetch. */
  protected previewInventory(kind: 'ansible' | 'nornir'): void {
    this.inventoryPreview.set('loading…');
    const call = kind === 'ansible' ? this.api.ansibleInventory() : this.api.nornirInventory();
    call.subscribe({
      next: (doc) => this.inventoryPreview.set(JSON.stringify(doc, null, 2)),
      error: (err: Error) => this.inventoryPreview.set(`could not load: ${err.message}`),
    });
  }

  protected startEditPrincipal(p: Principal): void {
    this.principalEdit = {
      username: p.username,
      path: p.authorized_keys_path ?? '',
      useSudo: p.use_sudo,
      enabled: p.enabled,
    };
    this.editingPrincipal.set(p.id);
  }

  protected savePrincipal(t: Target, p: Principal): void {
    this.busyId.set(p.id);
    this.api.updatePrincipal(t.id, p.id, {
      username: this.principalEdit.username,
      authorized_keys_path: this.principalEdit.path,
      use_sudo: this.principalEdit.useSudo,
      enabled: this.principalEdit.enabled,
    }).subscribe({
      next: () => {
        this.busyId.set(null);
        this.notice.set('Login updated.');
        this.editingPrincipal.set(null);
        this.select(t);
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected async removePrincipal(t: Target, p: Principal): Promise<void> {
    if (!(await this.confirm.ask({
      title: `Stop managing ${p.username} on ${t.name}?`,
      message: 'Keys already in that account\'s authorized_keys stay where they are.',
      action: 'Remove',
      danger: true,
    }))) return;

    this.busyId.set(p.id);
    this.api.deletePrincipal(t.id, p.id).subscribe({
      next: (r) => {
        this.busyId.set(null);
        this.notice.set(r.notice);
        this.select(t);
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected create(): void {
    this.busy.set(true);
    this.formError.set(null);

    this.api.createTarget({
      name: this.draft.name,
      kind: this.draft.connector,
      connector: this.draft.connector,
      address: this.draft.address,
      port: Number(this.draft.port) || 22,
      credential_id: this.draft.credentialId ?? undefined,
      tags: this.draft.tags.split(',').map((t) => t.trim()).filter(Boolean),
      is_canary: this.draft.isCanary,
      config: this.prune(this.draft.config),
    }).subscribe({
      next: (t) => {
        this.busy.set(false);
        this.creating.set(false);
        this.notice.set(`Added ${t.name}. Probe it to pin its host key.`);
        this.reload();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.formError.set(err.message);
      },
    });
  }

  protected probe(t: Target): void {
    this.probing.set(t.id);
    this.api.probeTarget(t.id).subscribe({
      next: (r) => {
        this.probing.set(null);
        this.notice.set(r.reachable
          ? `${t.name} is reachable.`
          : `${t.name} is unreachable: ${r.message ?? 'no detail'}`);
        this.reload();
      },
      error: (err: Error) => {
        this.probing.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected select(t: Target): void {
    this.selected.set(t);
    this.principals.set([]);
    this.snapshots.set([]);

    this.api.listPrincipals(t.id).subscribe({
      next: (r) => this.principals.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
    this.api.listSnapshots(t.id).subscribe({
      next: (r) => this.snapshots.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected addPrincipal(t: Target): void {
    this.busy.set(true);
    this.api.createPrincipal(t.id, {
      username: this.newPrincipal,
      use_sudo: this.newPrincipalSudo,
    }).subscribe({
      next: () => {
        this.busy.set(false);
        this.notice.set('Login added.');
        this.newPrincipal = '';
        this.newPrincipalSudo = false;
        this.select(t);
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected async rollback(s: Snapshot): Promise<void> {
    if (!(await this.confirm.ask({
      title: 'Restore this target?',
      message: `Restore to its state at ${new Date(s.taken_at).toLocaleString()}?`,
      action: 'Roll back',
      danger: true,
    }))) return;

    this.busyId.set(s.id);
    this.api.rollback(s.id).subscribe({
      next: (r) => {
        this.busyId.set(null);
        this.notice.set(`Rolled ${r.target_name}/${r.username} back to ${r.key_count} key(s).`);
        this.selected.set(null);
        this.reload();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected healthClass(t: Target): string {
    switch (t.health) {
      case 'healthy': return 'ok';
      case 'degraded': return 'warn';
      case 'unreachable': return 'danger';
      default: return 'neutral';
    }
  }

  protected driftClass(t: Target): string {
    switch (t.drift_state) {
      case 'in_sync': return 'ok';
      case 'drifted': return 'warn';
      case 'error': return 'danger';
      default: return 'neutral';
    }
  }

  protected principalName(principalId?: string): string {
    if (!principalId) return '—';
    const principal = this.principals().find((p) => p.id === principalId);
    return principal?.username || principalId.substring(0, 8);
  }

}
