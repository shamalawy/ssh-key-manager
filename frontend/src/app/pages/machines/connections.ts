import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import { Auth } from '../../core/auth';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import { Modal } from '../../shared/modal';
import type { Credential, ManagedKey, Target } from '../../core/models';

/**
 * One credential kind, with the wording an operator needs to pick correctly.
 *
 * The kinds themselves are the server's (store.Cred*). What is added here is
 * the explanation: "ssh_key" is obvious to whoever wrote it and useless to
 * whoever is staring at an EC2 instance wondering where the .pem goes.
 */
interface KindInfo {
  value: string;
  label: string;
  blurb: string;
  /** Placeholder for the username field, which differs sharply by platform. */
  userHint: string;
}

const KINDS: KindInfo[] = [
  {
    value: 'ssh_key',
    label: 'SSH private key',
    blurb: 'A username and a private key file. This is what AWS EC2, and most ' +
      'cloud Linux images, give you — there is no password to type.',
    userHint: 'ec2-user, ubuntu, root…',
  },
  {
    value: 'ssh_password',
    label: 'SSH password',
    blurb: 'A username and a password. Common on network switches and older ' +
      'hosts; rare on anything cloud-provisioned.',
    userHint: 'admin, root…',
  },
  {
    value: 'api_token',
    label: 'API token',
    blurb: 'A token rather than an SSH login — for connectors that talk to a ' +
      'web API, such as a git provider holding deploy keys.',
    userHint: 'optional',
  },
];

@Component({
  selector: 'skm-connections',
  imports: [FormsModule, DatePipe, Modal, Alerts],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .kind-picker { display: grid; gap: 0.5rem; margin-bottom: 1rem; }
    .kind-option {
      display: flex; gap: 0.6rem; align-items: flex-start;
      padding: 0.7rem; border: 1px solid var(--border);
      border-radius: var(--radius); cursor: pointer;
    }
    .kind-option:hover { border-color: var(--accent); }
    .kind-option.chosen { border-color: var(--accent); background: var(--bg-input); }
    .kind-option input { margin-top: 0.2rem; }
    .kind-option .blurb { color: var(--text-muted); font-size: 0.8rem; margin-top: 0.15rem; }
    textarea.pem {
      font-family: var(--mono); font-size: 0.74rem; min-height: 150px;
      white-space: pre; overflow-wrap: normal; overflow-x: auto;
    }
    .used-by { display: flex; flex-wrap: wrap; gap: 0.3rem; }
  `],
  template: `
    <div class="card-header">
      @if (auth.can('credential.write')) {
        <button class="primary" type="button" (click)="openCreate()">Add connection</button>
      }
    </div>

    <p class="intro">
      How SKM signs in to machines. A connection is a username plus a password
      or private key; pick it when you add a machine. Most people never need
      this tab — the Add machine form creates one for you.
    </p>

    <skm-alerts [error]="error" [notice]="notice" />

    <div class="card">
      @if (loading()) {
        <div class="empty"><span class="spinner"></span> Loading…</div>
      } @else if (credentials().length === 0) {
        <div class="empty">
          No connections yet. Add one — for an EC2 instance, choose
          <strong>Private key</strong> and paste the <code>.pem</code> AWS gave you.
        </div>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th><th>Type</th><th>Signs in as</th>
                <th>Holds</th><th>Used by</th><th>Added</th><th></th>
              </tr>
            </thead>
            <tbody>
              @for (c of credentials(); track c.id) {
                <tr>
                  <td><strong>{{ c.name }}</strong></td>
                  <td>{{ kindLabel(c.kind) }}</td>
                  <td class="mono small">{{ c.username || '—' }}</td>
                  <td class="small">
                    @if (c.key_id) {
                      <span class="badge info">a key from the Keys page</span>
                      <div class="faint">{{ keyName(c.key_id) }}</div>
                    } @else if (c.has_secret) {
                      <span class="badge neutral">a stored secret</span>
                    } @else {
                      <span class="badge warn">nothing — it will not work</span>
                    }
                  </td>
                  <td class="small">
                    @if (usedBy(c).length === 0) {
                      <span class="faint">not used yet</span>
                    } @else {
                      <div class="used-by">
                        @for (t of usedBy(c); track t.id) { <span class="tag">{{ t.name }} (machine)</span> }
                      </div>
                    }
                  </td>
                  <td class="small faint">{{ c.created_at | date:'MMM d, y' }}</td>
                  <td style="text-align: right;">
                    @if (auth.can('credential.write')) {
                      <button class="ghost sm" type="button" [disabled]="busy()" (click)="remove(c)">
                        @if (busy()) { <span class="spinner"></span> } Delete
                      </button>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </div>

    <!-- Create --------------------------------------------------------- -->
    @if (creating()) {
      <skm-modal title="Add a connection" [wide]="true" (close)="creating.set(false)">
        @if (formError(); as message) { <div class="notice error">{{ message }}</div> }

          <label>
            <span class="label">Name</span>
            <input [(ngModel)]="draft.name" placeholder="aws-ec2-prod" />
            <span class="hint">Just a label so you can pick it out on a machine.</span>
          </label>

          <span class="label">What kind of sign-in is it?</span>
          <div class="kind-picker">
            @for (k of kinds; track k.value) {
              <label class="kind-option" [class.chosen]="draft.kind === k.value">
                <input type="radio" name="kind" [value]="k.value" [(ngModel)]="draft.kind" />
                <span>
                  <strong>{{ k.label }}</strong>
                  <div class="blurb">{{ k.blurb }}</div>
                </span>
              </label>
            }
          </div>

          <label>
            <span class="label">Username</span>
            <input [(ngModel)]="draft.username" [placeholder]="currentKind().userHint" />
            <span class="hint">
              The account SKM logs in as. On EC2 this is set by the image —
              <code>ec2-user</code> on Amazon Linux, <code>ubuntu</code> on
              Ubuntu, <code>admin</code> on Debian. Getting it wrong looks
              exactly like a rejected key.
            </span>
          </label>

          @if (draft.kind === 'ssh_key') {
            <span class="label">Where is the private key?</span>
            <div class="kind-picker">
              <label class="kind-option" [class.chosen]="draft.source === 'paste'">
                <input type="radio" name="source" value="paste" [(ngModel)]="draft.source" />
                <span>
                  <strong>Paste or upload a key file</strong>
                  <div class="blurb">
                    The <code>.pem</code> AWS handed you, or any private key file.
                  </div>
                </span>
              </label>
              <label class="kind-option" [class.chosen]="draft.source === 'managed'" [title]="keys().length === 0 ? 'Add a key under the Keys page first' : ''">
                <input type="radio" name="source" value="managed" [(ngModel)]="draft.source" [disabled]="keys().length === 0" />
                <span>
                  <strong>Use a key SKM already manages</strong>
                  <div class="blurb">
                    Pick one from the Keys page. Do this if the key is encrypted
                    with a passphrase — import it under Keys first, where you can
                    enter the passphrase, then choose it here.
                  </div>
                </span>
              </label>
            </div>

            @if (draft.source === 'paste') {
              <label>
                <span class="label">Key file</span>
                <input type="file" accept=".pem,.key,.txt" (change)="pickFile($event)" />
                <span class="hint">Or paste it below instead.</span>
              </label>
              <label>
                <span class="label">Private key</span>
                <textarea class="pem" [(ngModel)]="draft.secret"
                          placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;…&#10;-----END RSA PRIVATE KEY-----"></textarea>
                <span class="hint">
                  The whole file, BEGIN and END lines included. It is encrypted
                  before it is stored and is never shown again. A key protected
                  by a passphrase will not work here — use the option above for
                  those.
                </span>
              </label>
            } @else {
              <label>
                <span class="label">Key</span>
                <select [(ngModel)]="draft.keyId">
                  <option value="">— choose a key —</option>
                  @for (k of keys(); track k.id) {
                    <option [value]="k.id">{{ k.name }} ({{ k.algorithm }})</option>
                  }
                </select>
                <span class="hint">
                  SKM will sign in with this key's private half. The matching
                  public key has to already be on the machine — on a fresh EC2
                  instance that means the key AWS installed at launch.
                </span>
              </label>
            }
          } @else {
            <label>
              <span class="label">
                {{ draft.kind === 'api_token' ? 'Token' : 'Password' }}
              </span>
              <input type="password" [(ngModel)]="draft.secret" />
              <span class="hint">Encrypted before storage and never shown again.</span>
            </label>
          }

        <div class="row end">
          <button type="button" (click)="creating.set(false)">Cancel</button>
          <button class="primary" type="button" [disabled]="busy() || !valid()" (click)="create()">
            @if (busy()) { <span class="spinner"></span> } Save connection
          </button>
        </div>
      </skm-modal>
    }
  `,
})
export class ConnectionsPage implements OnInit {
  private readonly api = inject(Api);
  private readonly confirm = inject(Confirm);
  protected readonly auth = inject(Auth);

  protected readonly credentials = signal<Credential[]>([]);
  protected readonly targets = signal<Target[]>([]);
  protected readonly keys = signal<ManagedKey[]>([]);

  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  protected readonly creating = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly formError = signal<string | null>(null);

  protected readonly kinds = KINDS;

  protected draft = {
    name: '', kind: 'ssh_key', username: '', secret: '',
    source: 'paste' as 'paste' | 'managed', keyId: '',
  };

  /**
   * currentKind drives the username placeholder.
   *
   * A plain method rather than a computed: draft.kind is an ngModel field, not
   * a signal, and a computed over a plain field never recalculates.
   */
  protected currentKind(): KindInfo {
    return KINDS.find((k) => k.value === this.draft.kind) ?? KINDS[0];
  }

  ngOnInit(): void {
    this.reload();
    this.api.listTargets().subscribe({ next: (r) => this.targets.set(r.items), error: (err: Error) => this.error.set(err.message) });
    this.api.listKeys().subscribe({ next: (r) => this.keys.set(r.items), error: (err: Error) => this.error.set(err.message) });
  }

  protected reload(): void {
    this.loading.set(true);
    this.api.listCredentials().subscribe({
      next: (r) => {
        this.credentials.set(r.items);
        this.loading.set(false);
      },
      error: (err: Error) => {
        this.error.set(err.message);
        this.loading.set(false);
      },
    });
  }

  protected openCreate(): void {
    this.draft = {
      name: '', kind: 'ssh_key', username: '', secret: '',
      source: 'paste', keyId: '',
    };
    this.formError.set(null);
    this.creating.set(true);
  }

  /**
   * valid mirrors the server's requirements so the button explains itself by
   * being disabled, rather than by a round trip that returns "secret required".
   */
  protected valid(): boolean {
    if (!this.draft.name) return false;
    if (this.draft.kind === 'ssh_key' && this.draft.source === 'managed') {
      return !!this.draft.keyId;
    }
    return !!this.draft.secret;
  }

  protected pickFile(ev: Event): void {
    const file = (ev.target as HTMLInputElement).files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      this.draft.secret = String(reader.result ?? '');
      if (!this.draft.name) this.draft.name = file.name.replace(/\.(pem|key|txt)$/i, '');
    };
    reader.onerror = () => this.formError.set(`Could not read ${file.name}.`);
    reader.readAsText(file);
  }

  protected create(): void {
    this.busy.set(true);
    this.formError.set(null);

    // A credential either carries its own secret or points at a managed key.
    // Sending both would leave the server to guess which one was meant.
    const usesManagedKey = this.draft.kind === 'ssh_key' && this.draft.source === 'managed';

    this.api.createCredential({
      name: this.draft.name,
      kind: this.draft.kind,
      username: this.draft.username || undefined,
      secret: usesManagedKey ? undefined : this.draft.secret,
      key_id: usesManagedKey ? this.draft.keyId : undefined,
    }).subscribe({
      next: (c) => {
        this.busy.set(false);
        this.creating.set(false);
        this.notice.set(
          `Saved ${c.name}. Pick it when you add a machine.`);
        this.reload();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.formError.set(err.message);
      },
    });
  }

  /**
   * remove deletes a credential.
   *
   * The server refuses while a target still refers to it and names the targets,
   * so the useful failure is the server's, not a local guard.
   */
  protected async remove(c: Credential): Promise<void> {
    const users = this.usedBy(c);
    const message = users.length
      ? `It is in use by: ${users.map((t) => t.name).join(', ')}. SKM will refuse until those machines point somewhere else.`
      : `The stored secret is destroyed. If you need it again you will have to paste it in afresh.`;

    if (!(await this.confirm.ask({ title: `Delete ${c.name}?`, message, action: 'Delete', danger: true }))) {
      return;
    }

    this.busy.set(true);
    this.api.deleteCredential(c.id).subscribe({
      next: () => {
        this.busy.set(false);
        this.notice.set(`Deleted ${c.name}.`);
        this.reload();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected usedBy(c: Credential): Target[] {
    return this.targets().filter((t) => t.credential_id === c.id);
  }

  protected kindLabel(kind: string): string {
    return KINDS.find((k) => k.value === kind)?.label ?? kind;
  }

  protected keyName(id: string): string {
    return this.keys().find((k) => k.id === id)?.name ?? id.slice(0, 8);
  }
}
