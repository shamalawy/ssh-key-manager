import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import { Auth } from '../../core/auth';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import { Modal } from '../../shared/modal';
import type { Consumer, ManagedKey, Principal, Target } from '../../core/models';

@Component({
  selector: 'skm-clients',
  imports: [FormsModule, DatePipe, Alerts, Modal],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .toolbar { display: flex; gap: 1rem; margin-bottom: 1.2rem; align-items: center; }
    .toolbar input { flex: 1; max-width: 300px; }
    .choices { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
    .choice { cursor: pointer; border: 2px solid var(--border); border-radius: 0.4rem; padding: 1rem; text-align: center; transition: all 0.15s; }
    .choice input { display: none; }
    .choice.chosen { border-color: var(--accent); background: rgba(var(--accent-rgb), 0.08); }
    .choice span { display: block; }
    .choice strong { display: block; margin-bottom: 0.4rem; }
    .choice .blurb { font-size: 0.85rem; color: var(--text-muted); }
    .modal-step { margin-bottom: 1.2rem; }
    .modal-step h3 { margin: 0 0 0.6rem; font-size: 0.9rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
  `],
  template: `
    <h1>Clients</h1>
    <p class="muted" style="margin-top: -0.4rem;">
      A client is anything that needs the private key: a CI secret store, a Vault path, a Kubernetes Secret, a file on a server. Register them here; Deploy pushes a key to the clients you tick.
    </p>

    <skm-alerts [error]="error" [notice]="notice" />

    <div class="toolbar">
      <input type="text" placeholder="Filter by name…"
             [ngModel]="filterText()" (ngModelChange)="filterText.set($event)"
             class="filter-box" />
      @if (auth.can('key.write')) {
        <button class="primary" type="button" (click)="showAddModal.set(true)">
          + Add client
        </button>
      }
    </div>

    @if (filteredClients().length === 0) {
      <div class="card">
        <div class="empty">
          @if (clients().length === 0) {
            No clients yet.
          } @else {
            No clients match the filter.
          }
        </div>
      </div>
    } @else {
      <div class="card table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Kind</th>
              <th>Where</th>
              <th>Holds key</th>
              <th>Last delivered</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            @for (c of filteredClients(); track c.id) {
              <tr>
                <td><strong>{{ c.name }}</strong></td>
                <td class="small">{{ consumerKindLabel(c.kind) }}</td>
                <td class="small">{{ consumerWhere(c) }}</td>
                <td class="small">
                  @if (c.key_id) {
                    {{ keyName(c.key_id) }}
                  } @else {
                    <span class="muted">—</span>
                  }
                </td>
                <td class="small faint">
                  @if (c.last_delivered_at) {
                    {{ c.last_delivered_at | date:'MMM d, HH:mm' }}
                  } @else {
                    never
                  }
                </td>
                <td>
                  @if (c.last_error) {
                    <span class="badge danger" [title]="c.last_error">error</span>
                    <div class="small danger-text faint truncate" style="max-width: 240px; margin-top: 0.2rem;" [title]="c.last_error">
                      {{ c.last_error }}
                    </div>
                  } @else {
                    <span class="badge ok">ok</span>
                  }
                </td>
                <td style="text-align: right; white-space: nowrap;">
                  @if (auth.can('key.write')) {
                    <button class="ghost sm" type="button" [disabled]="busyId() === c.id" (click)="deliver(c)"
                            title="Copy the private key to the client right now.">
                      @if (busyId() === c.id) { <span class="spinner"></span> }
                      Deliver now
                    </button>
                    <button class="ghost sm" type="button" [disabled]="busyId() === c.id" (click)="showChangeKeyModal.set(true); changeKeyForConsumerId.set(c.id)">
                      @if (busyId() === c.id) { <span class="spinner"></span> }
                      Change key
                    </button>
                    <button class="ghost sm" type="button" [disabled]="busyId() === c.id" (click)="removeConsumer(c)">
                      @if (busyId() === c.id) { <span class="spinner"></span> }
                      Delete
                    </button>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      </div>
    }

    <!-- Add client modal -->
    @if (showAddModal()) {
    <skm-modal title="Add client" (close)="showAddModal.set(false); consumerDraft.set({name: '', kind: 'ssh_file', keyId: '', config: '', targetId: '', username: '', path: '', writePublic: true, useSudo: false}); consumerPrincipals.set([])">
      <div style="padding: 1.2rem;">
        <!-- Step 1: Basic info -->
        <div class="modal-step">
          <h3>Basic info</h3>
          <label>
            <span class="label">Name</span>
            <input [ngModel]="consumerDraft().name" (ngModelChange)="consumerDraft.update(d => ({...d, name: $event}))" name="c-name" placeholder="ci-deploy-key" />
            <span class="hint">Any label that tells you what this is.</span>
          </label>
        </div>

        <!-- Step 2: Where? -->
        <div class="modal-step">
          <h3>Where should it go?</h3>
          <div class="choices">
            @for (k of consumerKinds(); track k.id) {
              <label class="choice" [class.chosen]="consumerDraft().kind === k.id">
                <input type="radio" [value]="k.id" [ngModel]="consumerDraft().kind" (ngModelChange)="consumerDraft.update(d => ({...d, kind: $event}))" name="c-kind" />
                <span>
                  <strong>{{ k.label }}</strong>
                  <div class="blurb">{{ k.blurb }}</div>
                </span>
              </label>
            }
          </div>
        </div>

        <!-- Step 3: Which key? -->
        <div class="modal-step">
          <h3>Which key?</h3>
          <label>
            <span class="label">Key</span>
            <select [ngModel]="consumerDraft().keyId" (ngModelChange)="consumerDraft.update(d => ({...d, keyId: $event}))" name="c-key">
              <option value="">— choose a key —</option>
              @for (k of keys(); track k.id) {
                <option [value]="k.id">{{ k.name }} ({{ k.algorithm }})</option>
              }
            </select>
            <span class="hint">Its private half is what gets sent.</span>
          </label>
        </div>

        <!-- Step 4: Config -->
        <div class="modal-step">
          <h3>Configuration</h3>
          @if (consumerDraft().kind === 'ssh_file') {
            <div class="grid cols-3">
              <label>
                <span class="label">Which server?</span>
                <select [ngModel]="consumerDraft().targetId" (ngModelChange)="consumerDraft.update(d => ({...d, targetId: $event})); onConsumerTargetChange()" name="c-target">
                  <option value="">— choose a server —</option>
                  @for (t of targets(); track t.id) {
                    <option [value]="t.id">{{ t.name }} ({{ t.address }})</option>
                  }
                </select>
                @if (targets().length === 0) {
                  <span class="hint">No servers yet. Add one under Servers.</span>
                }
              </label>
              <label>
                <span class="label">Login to write as</span>
                <input [ngModel]="consumerDraft().username" (ngModelChange)="consumerDraft.update(d => ({...d, username: $event}))" name="c-user"
                       placeholder="ec2-user" list="consumer-logins" />
                <datalist id="consumer-logins">
                  @for (p of consumerPrincipals(); track p.id) {
                    <option [value]="p.username"></option>
                  }
                </datalist>
                <span class="hint">The account that will own the file.</span>
              </label>
              <label>
                <span class="label">File to write</span>
                <input [ngModel]="consumerDraft().path" (ngModelChange)="consumerDraft.update(d => ({...d, path: $event}))" name="c-path"
                       placeholder="/home/ec2-user/.ssh/id_ed25519" />
                <span class="hint">Full path, including the file name.</span>
              </label>
            </div>
            <div class="row">
              <label class="checkbox" style="margin: 0;">
                <input type="checkbox" [ngModel]="consumerDraft().writePublic" (ngModelChange)="consumerDraft.update(d => ({...d, writePublic: $event}))" name="c-pub" />
                <span>Also write the matching <code>.pub</code> beside it</span>
              </label>
              <label class="checkbox" style="margin: 0;">
                <input type="checkbox" [ngModel]="consumerDraft().useSudo" (ngModelChange)="consumerDraft.update(d => ({...d, useSudo: $event}))" name="c-sudo" />
                <span>Use sudo (needed if the path is outside that login's home)</span>
              </label>
            </div>
          } @else {
            <label>
              <span class="label">Configuration (JSON)</span>
              <textarea rows="6" [ngModel]="consumerDraft().config" (ngModelChange)="consumerDraft.update(d => ({...d, config: $event}))" name="c-config"
                        [placeholder]="configExample()"></textarea>
              <span class="hint">{{ configHelp() }}</span>
            </label>
          }
        </div>

        <div class="row" style="margin-top: 1.2rem;">
          <button class="primary" type="button"
                  [disabled]="!consumerReady() || busy()"
                  (click)="createConsumer()">
            @if (busy()) { <span class="spinner"></span> }
            Create client
          </button>
          <button class="ghost" type="button" (click)="consumerDraft.set({name: '', kind: 'ssh_file', keyId: '', config: '', targetId: '', username: '', path: '', writePublic: true, useSudo: false}); showAddModal.set(false)">Cancel</button>
        </div>
      </div>
    </skm-modal>
    }

    <!-- Change key modal -->
    @if (showChangeKeyModal()) {
    <skm-modal title="Change key" (close)="showChangeKeyModal.set(false); changeKeyDraftKeyId.set(''); changeKeyForConsumerId.set('')">
      <div style="padding: 1.2rem;">
        <p class="small muted" style="margin-bottom: 0.8rem;">
          Select a new key. It will be delivered to the client immediately.
        </p>
        <label>
          <span class="label">Key</span>
          <select [ngModel]="changeKeyDraftKeyId()" (ngModelChange)="changeKeyDraftKeyId.set($event)" name="change-key">
            <option value="">— choose a key —</option>
            @for (k of keys(); track k.id) {
              <option [value]="k.id">{{ k.name }} ({{ k.algorithm }})</option>
            }
          </select>
        </label>
        <div class="row" style="margin-top: 1.2rem;">
          <button class="primary" type="button"
                  [disabled]="!changeKeyDraftKeyId() || busy()"
                  (click)="applyChangeKey()">
            @if (busy()) { <span class="spinner"></span> }
            Change and deliver
          </button>
          <button class="ghost" type="button" (click)="changeKeyDraftKeyId.set(''); showChangeKeyModal.set(false)">Cancel</button>
        </div>
      </div>
    </skm-modal>
    }
  `,
})
export class ClientsPage implements OnInit {
  private readonly api = inject(Api);
  protected readonly auth = inject(Auth);
  private readonly confirm = inject(Confirm);

  // Data
  protected readonly clients = signal<Consumer[]>([]);
  protected readonly keys = signal<ManagedKey[]>([]);
  protected readonly targets = signal<Target[]>([]);
  protected readonly consumerPrincipals = signal<Principal[]>([]);

  // Filter
  protected readonly filterText = signal('');
  protected readonly filteredClients = computed(() => {
    const filter = this.filterText().toLowerCase();
    if (!filter) return this.clients();
    return this.clients().filter(c => c.name.toLowerCase().includes(filter));
  });

  // Add modal
  protected readonly showAddModal = signal(false);
  protected readonly consumerDraft = signal({
    name: '', kind: 'ssh_file', keyId: '', config: '',
    targetId: '', username: '', path: '', writePublic: true, useSudo: false,
  });

  // Change key modal
  protected readonly showChangeKeyModal = signal(false);
  protected readonly changeKeyForConsumerId = signal<string>('');
  protected readonly changeKeyDraftKeyId = signal<string>('');

  // Loading states
  protected readonly busy = signal(false);
  protected readonly busyId = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);

  protected readonly consumerKinds = signal([
    { id: 'ssh_file', label: 'A file on a server', blurb: 'Over SSH to a login you specify' },
    { id: 'file_drop', label: 'A file on the SKM server', blurb: 'Stored on this machine' },
    { id: 'vault_kv', label: 'HashiCorp Vault', blurb: 'Written to a KV store' },
    { id: 'kubernetes_secret', label: 'A Kubernetes secret', blurb: 'In a namespace and secret name' },
    { id: 'webhook', label: 'POSTed to a URL', blurb: 'Sent to your webhook endpoint' },
    { id: 'env_export', label: 'A shell-sourceable file', blurb: 'Wrapped for shell sourcing' },
  ]);

  ngOnInit(): void {
    this.loadClients();
    this.api.listKeys().subscribe({
      next: (r) => this.keys.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
    this.api.listTargets().subscribe({
      next: (r) => this.targets.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  private loadClients(): void {
    this.api.listConsumers().subscribe({
      next: (r) => this.clients.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected consumerReady(): boolean {
    const d = this.consumerDraft();
    if (!d.name || !d.keyId) return false;
    if (d.kind === 'ssh_file') return !!d.targetId && !!d.username && !!d.path;
    if (!d.config || !d.config.trim()) return false;
    try {
      JSON.parse(d.config);
      return true;
    } catch {
      return false;
    }
  }

  protected consumerKindLabel(kind: string): string {
    const k = this.consumerKinds().find(x => x.id === kind);
    return k?.label ?? kind;
  }

  protected consumerWhere(c: Consumer): string {
    const config = c.config as Record<string, unknown> | undefined;
    if (!config) return '—';

    switch (c.kind) {
      case 'ssh_file':
        return config['path'] as string ?? '—';
      case 'vault_kv':
        return config['path'] as string ?? '—';
      case 'kubernetes_secret':
        return `${config['namespace'] ?? 'default'}/${config['name'] ?? '?'}`;
      case 'webhook':
        return (config['url'] as string ?? '—').replace(/^https?:\/\//, '');
      case 'env_export':
      case 'file_drop':
        return config['path'] as string ?? '—';
      default:
        return JSON.stringify(config).substring(0, 60);
    }
  }

  protected configExample(): string {
    const draft = this.consumerDraft();
    switch (draft.kind) {
      case 'ssh_file':
        return '{"target_id": "' + (this.targets()[0]?.id ?? '…') +
          '", "username": "ec2-user", "path": "/home/ec2-user/.ssh/id_ed25519", "write_public": true}';
      case 'vault_kv':
        return '{"address": "https://vault:8200", "token": "…", "path": "secret/ci/deploy-key"}';
      case 'kubernetes_secret':
        return '{"namespace": "default", "name": "deploy-key", "key": "id_ed25519"}';
      case 'webhook':
        return '{"url": "https://ci.example.com/hooks/rotate-key"}';
      default:
        return '{"path": "/var/lib/skm/consumers/ci.pem"}';
    }
  }

  protected configHelp(): string {
    const draft = this.consumerDraft();
    switch (draft.kind) {
      case 'ssh_file':
        return 'target_id is the server from the Servers page — copy its id from the URL or the list. ' +
          'username is the login to write as; path is where the private key file goes. ' +
          'Add "write_public": true to drop the matching .pub beside it, and "use_sudo": true if the path needs root.';
      case 'vault_kv':
        return 'The Vault address, a token that may write, and the KV v2 path to write to.';
      case 'kubernetes_secret':
        return 'The namespace and secret name, plus the field inside it to hold the key.';
      case 'webhook':
        return 'The URL to POST to. The request is signed so the receiver can check it came from SKM.';
      case 'env_export':
        return 'The path of the file to write. It is written so a shell can source it.';
      default:
        return 'The full path of the file to write on the SKM server.';
    }
  }

  protected onConsumerTargetChange(): void {
    this.consumerPrincipals.set([]);
    const draft = this.consumerDraft();
    if (!draft.targetId) return;

    this.api.listPrincipals(draft.targetId).subscribe({
      next: (r) => {
        this.consumerPrincipals.set(r.items);
        if (!this.consumerDraft().username && r.items.length) {
          this.consumerDraft.update(d => ({ ...d, username: r.items[0].username }));
        }
      },
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected createConsumer(): void {
    const draft = this.consumerDraft();
    let config: Record<string, unknown> = {};

    if (draft.kind === 'ssh_file') {
      config = {
        target_id: draft.targetId,
        username: draft.username,
        path: draft.path,
      };
      if (draft.writePublic) config['write_public'] = true;
      if (draft.useSudo) config['use_sudo'] = true;
      this.saveConsumer(config);
      return;
    }

    if (draft.config.trim()) {
      try {
        config = JSON.parse(draft.config) as Record<string, unknown>;
      } catch {
        this.error.set('The settings are not valid JSON.');
        return;
      }
    }

    this.saveConsumer(config);
  }

  private saveConsumer(config: Record<string, unknown>): void {
    const draft = this.consumerDraft();
    this.busy.set(true);
    this.api.createConsumer({
      name: draft.name,
      kind: draft.kind,
      key_id: draft.keyId,
      config,
      enabled: true,
    }).subscribe({
      next: () => {
        this.busy.set(false);
        this.error.set(null);
        this.consumerDraft.set({
          name: '', kind: 'ssh_file', keyId: '', config: '',
          targetId: '', username: '', path: '', writePublic: true, useSudo: false,
        });
        this.consumerPrincipals.set([]);
        this.showAddModal.set(false);
        this.notice.set('Client created.');
        setTimeout(() => this.notice.set(null), 3000);
        this.loadClients();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected deliver(c: Consumer): void {
    this.busyId.set(c.id);
    this.api.deliverConsumer(c.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.error.set(null);
        this.notice.set('Delivered.');
        setTimeout(() => this.notice.set(null), 3000);
        this.loadClients();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected applyChangeKey(): void {
    const consumerId = this.changeKeyForConsumerId();
    if (!consumerId || !this.changeKeyDraftKeyId()) return;

    this.busy.set(true);
    this.api.rebindConsumer(consumerId, this.changeKeyDraftKeyId()).subscribe({
      next: () => {
        this.busy.set(false);
        this.error.set(null);
        this.showChangeKeyModal.set(false);
        this.changeKeyDraftKeyId.set('');
        this.notice.set('Key changed and delivered.');
        setTimeout(() => this.notice.set(null), 3000);
        this.loadClients();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected async removeConsumer(c: Consumer): Promise<void> {
    if (!(await this.confirm.ask({
      title: `Delete the client "${c.name}"?`,
      message: 'Whatever it already received stays where it was sent. Rotations will simply stop updating it.',
      action: 'Delete',
      danger: true,
    }))) return;

    this.busyId.set(c.id);
    this.api.deleteConsumer(c.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.error.set(null);
        this.notice.set('Client deleted.');
        setTimeout(() => this.notice.set(null), 3000);
        this.loadClients();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected keyName(id: string): string {
    return this.keys().find((k) => k.id === id)?.name ?? id.slice(0, 8);
  }
}
