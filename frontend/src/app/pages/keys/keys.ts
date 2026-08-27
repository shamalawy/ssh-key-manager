import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { Api, mfaRequired } from '../../core/api';
import { Auth } from '../../core/auth';
import { Confirm } from '../../shared/confirm';
import { Modal } from '../../shared/modal';
import { Alerts } from '../../shared/alerts';
import { StepUp } from '../../shared/stepup';
import type { ApiError } from '../../core/api';
import type { Assignment, ManagedKey, Principal, Target } from '../../core/models';

@Component({
  selector: 'skm-keys',
  imports: [FormsModule, DatePipe, Modal, Alerts, StepUp],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .fingerprint { font-family: var(--mono); font-size: 0.78rem; color: var(--text-muted); }
    .toolbar { display: flex; gap: 0.6rem; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; }
    .toolbar input[type=search] { max-width: 260px; }
    .reveal-box {
      font-family: var(--mono); font-size: 0.75rem;
      background: var(--bg-input); border: 1px solid var(--danger);
      border-radius: var(--radius); padding: 0.7rem; white-space: pre-wrap;
      word-break: break-all; max-height: 260px; overflow-y: auto;
    }
    .pubkey {
      font-family: var(--mono); font-size: 0.74rem; color: var(--text-muted);
      word-break: break-all; background: var(--bg-input);
      border: 1px solid var(--border); border-radius: var(--radius); padding: 0.5rem;
    }
  `],
  template: `
    <div class="card-header">
      <h1>Keys</h1>
      <div class="row">
        @if (auth.can('key.import')) {
          <button type="button" (click)="openImport()">Import key</button>
        }
        @if (auth.can('key.write')) {
          <button class="primary" type="button" (click)="openCreate()">Generate key</button>
        }
      </div>
    </div>

    <p class="muted" style="margin-top: -0.4rem;">
      Every SSH key SKM looks after. <strong>Generate</strong> makes a brand new
      pair here. <strong>Import</strong> takes a private key you already have —
      one AWS handed you, or an old key off a laptop — and brings it under
      management. Once a key is here, use <strong>Assign</strong> to say which
      machines and logins should have it, then go to Deploy to actually put it
      there.
    </p>

    <skm-alerts [error]="error" [notice]="notice" />

    <div class="toolbar">
      <input type="search" placeholder="Search name or fingerprint…"
             [(ngModel)]="search" (ngModelChange)="reload()" />
      <select [(ngModel)]="statusFilter" (ngModelChange)="reload()" style="max-width: 170px;">
        <option value="">All statuses</option>
        @for (s of statuses; track s) { <option [value]="s">{{ s }}</option> }
      </select>
      <span class="spacer"></span>
      <span class="muted small">{{ keys().length }} key(s)</span>
    </div>

    <div class="card">
      @if (loading()) {
        <div class="empty"><span class="spinner"></span> Loading…</div>
      } @else if (keys().length === 0) {
        <div class="empty">No keys yet. Generate one to get started.</div>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th><th>Algorithm</th><th>Status</th><th>Gen</th>
                <th>Fingerprint</th><th>Tags</th><th>Expires</th><th></th>
              </tr>
            </thead>
            <tbody>
              @for (k of keys(); track k.id) {
                <tr>
                  <td>
                    <strong>{{ k.name }}</strong>
                    @if (!k.compliant) {
                      <span class="badge warn" [title]="k.compliance_notes">non-compliant</span>
                    }
                    @if (k.key_class === 'break_glass') { <span class="badge danger">break-glass</span> }
                  </td>
                  <td class="mono small">{{ k.algorithm }}</td>
                  <td><span class="badge" [class]="statusClass(k)">{{ k.status }}</span></td>
                  <td class="faint">{{ k.generation }}</td>
                  <td class="fingerprint truncate" style="max-width: 260px;"
                      [title]="k.fingerprint_sha256">{{ k.fingerprint_sha256 }}</td>
                  <td>@for (t of k.tags; track t) { <span class="tag">{{ t }}</span> }</td>
                  <td class="small" [class.warn-text]="expiringSoon(k)">
                    {{ k.expires_at ? (k.expires_at | date:'MMM d, y') : '—' }}
                  </td>
                  <td>
                    <div class="row">
                      <button class="ghost sm" type="button" (click)="select(k)">Details</button>
                      @if (auth.can('key.write')) {
                        <button class="ghost sm" type="button" (click)="openAssign(k)"
                                title="Choose which machines and logins should have this key">Assign</button>
                      }
                      @if (auth.can('key.reveal') && k.has_private_key) {
                        <button class="ghost sm" type="button" (click)="openReveal(k)">Reveal</button>
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

    <!-- Generate ------------------------------------------------------- -->
    @if (creating()) {
      <skm-modal title="Generate a key" (close)="creating.set(false)">
        @if (formError(); as message) { <div class="notice error">{{ message }}</div> }

        <label>
          <span class="label">Name</span>
          <input [(ngModel)]="draft.name" placeholder="web-fleet-2026" />
        </label>

        <label>
          <span class="label">Algorithm</span>
          <select [(ngModel)]="draft.algorithm">
            @for (a of algorithms(); track a) { <option [value]="a">{{ a }}</option> }
          </select>
          <span class="hint">Ed25519 unless something on the fleet cannot accept it.</span>
        </label>

        <label>
          <span class="label">Comment</span>
          <input [(ngModel)]="draft.comment" placeholder="skm:web-fleet" />
          <span class="hint">Appears at the end of the authorized_keys entry.</span>
        </label>

        <label>
          <span class="label">Tags</span>
          <input [(ngModel)]="draft.tags" placeholder="prod, web" />
        </label>

        <label>
          <span class="label">Rotate after (days)</span>
          <input type="number" min="0" [(ngModel)]="draft.validDays" placeholder="90" />
          <span class="hint">Leave empty for no expiry.</span>
        </label>

        <label>
          <input type="checkbox" [(ngModel)]="draft.breakGlass" />
          <span class="label">Break-glass key (emergency access; gated and alerted on separately)</span>
        </label>

        <div class="row end">
          <button type="button" (click)="creating.set(false)">Cancel</button>
          <button class="primary" type="button" [disabled]="busy() || !draft.name" (click)="create()">
            @if (busy()) { <span class="spinner"></span> } Generate
          </button>
        </div>
      </skm-modal>
    }

    <!-- Import --------------------------------------------------------- -->
    @if (importing()) {
      <skm-modal title="Import a key you already have" [wide]="true" (close)="importing.set(false)">
        @if (formError(); as message) { <div class="notice error">{{ message }}</div> }

        <div class="notice info">
          Paste the <strong>private</strong> key. SKM works out the public half
          by itself, so you do not need a <code>.pub</code> file. This is how
          you bring in a <code>.pem</code> that AWS generated for you, or any
          existing key you want SKM to rotate from now on.
        </div>

        <label>
          <span class="label">Name</span>
          <input [(ngModel)]="importDraft.name" placeholder="aws-ec2-prod" />
          <span class="hint">What you will call it in SKM. Must be unique.</span>
        </label>

        <label>
          <span class="label">Private key file</span>
          <input type="file" accept=".pem,.key,.txt" (change)="pickFile($event)" />
          <span class="hint">Or paste the text below instead.</span>
        </label>

        <label>
          <span class="label">Private key</span>
          <textarea rows="8" class="mono" [(ngModel)]="importDraft.privateKey"
                    placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;…&#10;-----END RSA PRIVATE KEY-----"></textarea>
          <span class="hint">
            The whole file, including the BEGIN and END lines.
          </span>
        </label>

        <label>
          <span class="label">Passphrase</span>
          <input type="password" [(ngModel)]="importDraft.passphrase"
                 placeholder="leave empty if the key has none" />
          <span class="hint">
            Only if the key is encrypted. SKM stores it decrypted under its own
            encryption, so you will not need this passphrase again.
          </span>
        </label>

        <label>
          <span class="label">Tags</span>
          <input [(ngModel)]="importDraft.tags" placeholder="aws, prod" />
          <span class="hint">Optional labels used for grouping and access scoping.</span>
        </label>

        <div class="row end">
          <button type="button" (click)="importing.set(false)">Cancel</button>
          <button class="primary" type="button"
                  [disabled]="busy() || !importDraft.name || !importDraft.privateKey"
                  (click)="importKey()">
            @if (busy()) { <span class="spinner"></span> } Import
          </button>
        </div>
      </skm-modal>
    }

    <!-- Assign --------------------------------------------------------- -->
    @if (assigning(); as k) {
      <skm-modal [title]="'Where should ' + k.name + ' be installed?'" [wide]="true" (close)="assigning.set(null)">
        @if (formError(); as message) { <div class="notice error">{{ message }}</div> }

        <div class="notice info">
          This only records the intention. Nothing is written to the machine
          until you run a deployment, which shows you the exact change first.
        </div>

        <div class="grid cols-2">
          <label>
            <span class="label">Machine</span>
            <select [(ngModel)]="assignDraft.targetId" (ngModelChange)="onAssignTargetChange()">
              <option value="">— choose a machine —</option>
              @for (t of targets(); track t.id) {
                <option [value]="t.id">{{ t.name }} ({{ t.address }})</option>
              }
            </select>
            @if (targets().length === 0) {
              <span class="hint">No machines yet. Add one on the Targets page first.</span>
            }
          </label>

          <label>
            <span class="label">Login</span>
            <select [(ngModel)]="assignDraft.principalId"
                    [disabled]="assignPrincipals().length === 0">
              <option value="">— choose a login —</option>
              @for (p of assignPrincipals(); track p.id) {
                <option [value]="p.id">{{ p.username }}{{ p.use_sudo ? ' (sudo)' : '' }}</option>
              }
            </select>
            <span class="hint">
              The user account on that machine, e.g. <code>root</code> or
              <code>ubuntu</code>.
            </span>
            @if (assignDraft.targetId && assignPrincipals().length === 0) {
              <span class="hint warn-text">
                That machine has no logins set up. Add one under Targets.
              </span>
            }
          </label>
        </div>

        <label>
          <span class="label">Restrictions (optional)</span>
          <input [(ngModel)]="assignDraft.options"
                 placeholder="from=&quot;10.0.0.0/8&quot;, no-pty" />
          <span class="hint">
            Standard <code>authorized_keys</code> options, comma separated.
            <code>from="…"</code> limits which addresses may use the key;
            <code>no-pty</code> blocks interactive shells;
            <code>command="…"</code> forces one command. Leave empty for no
            restrictions.
          </span>
        </label>

        <div class="row end">
          <button type="button" (click)="assigning.set(null)">Cancel</button>
          <button class="primary" type="button"
                  [disabled]="busy() || !assignDraft.targetId || !assignDraft.principalId"
                  (click)="assign(k)">
            @if (busy()) { <span class="spinner"></span> } Assign
          </button>
        </div>
      </skm-modal>
    }

    <!-- Details -------------------------------------------------------- -->
    @if (selected(); as k) {
      <skm-modal [title]="k.name" [wide]="true" (close)="selected.set(null)">

          <div class="grid cols-2" style="margin-bottom: 1rem;">
            <div><span class="label small faint">Algorithm</span><div class="mono">{{ k.algorithm }}</div></div>
            <div><span class="label small faint">Status</span>
                 <div><span class="badge" [class]="statusClass(k)">{{ k.status }}</span></div></div>
            <div><span class="label small faint">Generation</span><div>{{ k.generation }}</div></div>
            <div><span class="label small faint">Class</span><div>{{ k.key_class }}</div></div>
            <div><span class="label small faint">Created</span><div>{{ k.created_at | date:'medium' }}</div></div>
            <div><span class="label small faint">Expires</span>
                 <div>{{ k.expires_at ? (k.expires_at | date:'medium') : 'never' }}</div></div>
          </div>

          <span class="label small faint">Fingerprint</span>
          <div class="pubkey" style="margin-bottom: 0.9rem;">{{ k.fingerprint_sha256 }}</div>

          <span class="label small faint">Public key</span>
          <div class="pubkey">{{ k.public_key }}</div>

          @if (!k.compliant) {
            <div class="notice warn" style="margin-top: 1rem;">{{ k.compliance_notes }}</div>
          }

          <!-- Where it is installed -->
          <h3 style="margin-top: 1.4rem;">Installed on</h3>
          @if (keyAssignments().length === 0) {
            <p class="small faint">
              Not assigned anywhere yet. Close this and press <strong>Assign</strong>
              to pick a machine.
            </p>
          } @else {
            <div class="table-wrap">
              <table>
                <thead><tr><th>Machine</th><th>Login</th><th>On the machine?</th><th>Options</th></tr></thead>
                <tbody>
                  @for (a of keyAssignments(); track a.id) {
                    <tr>
                      <td>{{ a.target_name }}</td>
                      <td class="mono small">{{ a.username }}</td>
                      <td>
                        <span class="badge"
                              [class.ok]="a.actual_state === 'present'"
                              [class.danger]="a.actual_state === 'error'"
                              [class.neutral]="a.actual_state !== 'present' && a.actual_state !== 'error'">
                          {{ actualLabel(a) }}
                        </span>
                      </td>
                      <td>@for (o of a.options; track o) { <span class="tag">{{ o }}</span> }</td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }

          <!-- Lifecycle -->
          @if (auth.can('key.write')) {
            <h3 style="margin-top: 1.4rem;">Change stage</h3>
            <p class="small faint" style="margin-top: -0.4rem;">
              Where the key sits in its life. <code>staged</code> means it is on
              the machines but not relied on yet; <code>active</code> is in
              normal use; <code>retiring</code> means it is on its way out and
              the next deployment with pruning will remove it. Most of the time
              a rotation moves these for you — set it by hand only when you are
              fixing something up.
            </p>
            <div class="row">
              <select [(ngModel)]="statusDraft" style="max-width: 200px;">
                @for (s of statuses; track s) { <option [value]="s">{{ s }}</option> }
              </select>
              <button type="button" [disabled]="busy() || statusDraft === k.status"
                      (click)="changeStatus(k)">@if (busy()) { <span class="spinner"></span> } Set stage</button>
            </div>
          }

          <div class="row end" style="margin-top: 1.2rem;">
            @if (auth.can('key.revoke') && k.status !== 'revoked' && k.status !== 'compromised') {
              <button class="danger" type="button" [disabled]="busy()" (click)="revoke(k)">@if (busy()) { <span class="spinner"></span> } Revoke</button>
            }
            @if (auth.can('key.delete')) {
              <button class="danger" type="button" [disabled]="busy()" (click)="remove(k)">@if (busy()) { <span class="spinner"></span> } Delete</button>
            }
            <button type="button" (click)="selected.set(null)">Close</button>
          </div>
      </skm-modal>
    }

    <!-- Reveal --------------------------------------------------------- -->
    @if (revealing(); as k) {
      <skm-modal [title]="'Reveal the private key for ' + k.name" [wide]="true" (close)="closeReveal()">
        @if (revealed()) {
          <div class="notice warn">
            This is secret material. It has been recorded on the audit trail.
          </div>
          <div class="reveal-box">{{ revealed() }}</div>
          <div class="row end" style="margin-top: 1rem;">
            <button type="button" (click)="copy(revealed()!)">Copy</button>
            <button class="primary" type="button" (click)="closeReveal()">Done</button>
          </div>
        } @else if (needsStepUp()) {
          <skm-stepup message="Revealing a private key needs a second-factor code verified in the last few minutes."
                      (verified)="needsStepUp.set(false); reveal(k)"
                      (cancelled)="needsStepUp.set(false)" />
        } @else {
          @if (formError(); as message) { <div class="notice error">{{ message }}</div> }
          <div class="notice info">
            Revealing a private key requires a reason and a second factor verified
            within the last five minutes. Both are recorded.
          </div>

          <label>
            <span class="label">Reason</span>
            <input [(ngModel)]="revealReason" placeholder="Break-glass access to web-01" />
          </label>

          <div class="row end">
            <button type="button" (click)="closeReveal()">Cancel</button>
            <button class="danger" type="button" [disabled]="busy() || !revealReason" (click)="reveal(k)">
              @if (busy()) { <span class="spinner"></span> } Reveal
            </button>
          </div>
        }
      </skm-modal>
    }
  `,
})
export class KeysPage implements OnInit {
  private readonly api = inject(Api);
  protected readonly auth = inject(Auth);
  private readonly confirm = inject(Confirm);

  protected readonly keys = signal<ManagedKey[]>([]);
  protected readonly algorithms = signal<string[]>(['ed25519']);
  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly formError = signal<string | null>(null);

  protected readonly creating = signal(false);
  protected readonly importing = signal(false);
  protected readonly assigning = signal<ManagedKey | null>(null);
  protected readonly selected = signal<ManagedKey | null>(null);
  protected readonly revealing = signal<ManagedKey | null>(null);
  protected readonly revealed = signal<string | null>(null);
  protected readonly needsStepUp = signal(false);

  /** Machines and their logins, loaded so a key can be assigned from here. */
  protected readonly targets = signal<Target[]>([]);
  protected readonly assignPrincipals = signal<Principal[]>([]);
  protected readonly assignments = signal<Assignment[]>([]);

  protected search = '';
  protected statusFilter = '';
  protected revealReason = '';
  protected statusDraft = '';
  protected readonly statuses = ['pending', 'staged', 'active', 'retiring', 'retired', 'revoked', 'compromised'];

  protected draft = { name: '', algorithm: 'ed25519', comment: '', tags: '', validDays: null as number | null, breakGlass: false };
  protected importDraft = { name: '', privateKey: '', passphrase: '', tags: '' };
  protected assignDraft = { targetId: '', principalId: '', options: '' };

  /** The deployments of whichever key the details dialog is showing. */
  protected readonly keyAssignments = computed(() => {
    const k = this.selected();
    return k ? this.assignments().filter((a) => a.key_id === k.id) : [];
  });

  ngOnInit(): void {
    this.reload();
    this.api.connectors().subscribe({
      next: (r) => this.algorithms.set(r.algorithms),
      error: (err: Error) => this.error.set(err.message),
    });
    this.api.listTargets().subscribe({
      next: (r) => this.targets.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
    this.loadAssignments();
  }

  private loadAssignments(): void {
    this.api.listAssignments().subscribe({
      next: (r) => this.assignments.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected reload(): void {
    this.loading.set(true);
    this.api.listKeys({
      q: this.search || undefined,
      status: this.statusFilter ? [this.statusFilter] : undefined,
    }).subscribe({
      next: (r) => {
        this.keys.set(r.items);
        this.loading.set(false);
      },
      error: (err: Error) => {
        this.error.set(err.message);
        this.loading.set(false);
      },
    });
  }

  protected openCreate(): void {
    this.draft = { name: '', algorithm: 'ed25519', comment: '', tags: '', validDays: null, breakGlass: false };
    this.formError.set(null);
    this.creating.set(true);
  }

  protected create(): void {
    this.busy.set(true);
    this.formError.set(null);

    this.api.createKey({
      name: this.draft.name,
      algorithm: this.draft.algorithm,
      comment: this.draft.comment || undefined,
      tags: splitTags(this.draft.tags),
      valid_days: this.draft.validDays ?? undefined,
      key_class: this.draft.breakGlass ? 'break_glass' : undefined,
    }).subscribe({
      next: (k) => {
        this.busy.set(false);
        this.creating.set(false);
        this.notice.set(`Generated ${k.name} (${k.fingerprint_sha256}).`);
        this.reload();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.formError.set(err.message);
      },
    });
  }

  protected select(k: ManagedKey): void {
    this.statusDraft = k.status;
    this.formError.set(null);
    this.selected.set(k);
    // The list endpoint does not carry deployments, so refresh them alongside.
    this.loadAssignments();
  }

  // ------------------------------------------------------------- import ---

  protected openImport(): void {
    this.importDraft = { name: '', privateKey: '', passphrase: '', tags: '' };
    this.formError.set(null);
    this.importing.set(true);
  }

  /**
   * pickFile reads a chosen private key into the textarea.
   *
   * Reading it in the browser rather than uploading it means the same request
   * carries the key whether it was pasted or picked, so there is one code path
   * on the server and one place where key material is handled.
   */
  protected pickFile(ev: Event): void {
    const file = (ev.target as HTMLInputElement).files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      this.importDraft.privateKey = String(reader.result ?? '');
      if (!this.importDraft.name) {
        this.importDraft.name = file.name.replace(/\.(pem|key|txt)$/i, '');
      }
    };
    reader.onerror = () => this.formError.set(`Could not read ${file.name}.`);
    reader.readAsText(file);
  }

  protected importKey(): void {
    this.busy.set(true);
    this.formError.set(null);

    this.api.importKey({
      name: this.importDraft.name,
      private_key: this.importDraft.privateKey,
      passphrase: this.importDraft.passphrase || undefined,
      tags: splitTags(this.importDraft.tags),
    }).subscribe({
      next: (k) => {
        this.busy.set(false);
        this.importing.set(false);
        this.notice.set(
          `Imported ${k.name} (${k.algorithm}). SKM worked out the public key ` +
          `from the private one — assign it to a machine to install it.`);
        this.reload();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.formError.set(err.message);
      },
    });
  }

  // ------------------------------------------------------------- assign ---

  protected openAssign(k: ManagedKey): void {
    this.assignDraft = { targetId: '', principalId: '', options: '' };
    this.assignPrincipals.set([]);
    this.formError.set(null);
    this.assigning.set(k);
  }

  protected onAssignTargetChange(): void {
    this.assignDraft.principalId = '';
    this.assignPrincipals.set([]);
    if (!this.assignDraft.targetId) return;

    this.api.listPrincipals(this.assignDraft.targetId).subscribe({
      next: (r) => {
        this.assignPrincipals.set(r.items);
        // One login is not a choice worth making.
        if (r.items.length === 1) this.assignDraft.principalId = r.items[0].id;
      },
      error: (err: Error) => this.formError.set(err.message),
    });
  }

  protected assign(k: ManagedKey): void {
    this.busy.set(true);
    this.formError.set(null);

    const target = this.targets().find((t) => t.id === this.assignDraft.targetId);
    const login = this.assignPrincipals().find((p) => p.id === this.assignDraft.principalId);

    this.api.createAssignment({
      key_id: k.id,
      target_id: this.assignDraft.targetId,
      principal_id: this.assignDraft.principalId,
      options: splitTags(this.assignDraft.options),
    }).subscribe({
      next: () => {
        this.busy.set(false);
        this.assigning.set(null);
        this.notice.set(
          `${k.name} is now meant to be on ${target?.name ?? 'the machine'}/${login?.username ?? ''}. ` +
          `Nothing has been written yet — go to Deploy to apply it.`);
        this.loadAssignments();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.formError.set(err.message);
      },
    });
  }

  // ---------------------------------------------------------- lifecycle ---

  /**
   * changeStatus moves the key between lifecycle stages by hand.
   *
   * Rotation normally owns these transitions. This exists for the case rotation
   * cannot cover: a half-finished run, or a key adopted from the fleet that is
   * already in use and should say so.
   */
  protected changeStatus(k: ManagedKey): void {
    this.busy.set(true);
    this.formError.set(null);

    this.api.setKeyStatus(k.id, this.statusDraft).subscribe({
      next: (updated) => {
        this.busy.set(false);
        this.selected.set(updated);
        this.notice.set(`${k.name} is now ${updated.status}.`);
        this.reload();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.formError.set(err.message);
      },
    });
  }

  /** actualLabel says what the machine really has, in words rather than jargon. */
  protected actualLabel(a: Assignment): string {
    switch (a.actual_state) {
      case 'present': return a.auth_verified_at ? 'yes, verified' : 'yes';
      case 'absent': return 'not yet';
      case 'error': return 'failed';
      default: return 'not checked';
    }
  }

  protected openReveal(k: ManagedKey): void {
    this.revealReason = '';
    this.revealed.set(null);
    this.formError.set(null);
    this.needsStepUp.set(false);
    this.revealing.set(k);
  }

  protected closeReveal(): void {
    // Drop the material from memory as soon as the dialog closes.
    this.revealed.set(null);
    this.revealing.set(null);
    this.revealReason = '';
  }

  protected reveal(k: ManagedKey): void {
    this.busy.set(true);
    this.formError.set(null);

    this.api.revealKey(k.id, this.revealReason).subscribe({
      next: (r) => {
        this.busy.set(false);
        this.revealed.set(r.private_key);
      },
      error: (err: ApiError) => {
        this.busy.set(false);
        if (mfaRequired(err)) {
          this.needsStepUp.set(true);
          return;
        }
        this.formError.set(err.message);
      },
    });
  }

  protected async revoke(k: ManagedKey): Promise<void> {
    const reason = await this.confirm.prompt({
      title: `Revoke "${k.name}"?`,
      label: 'Reason (recorded on the audit trail)',
      action: 'Revoke',
      danger: true,
    });
    if (!reason) return;

    this.busy.set(true);
    this.api.revokeKey(k.id, false, reason).subscribe({
      next: () => {
        this.busy.set(false);
        this.selected.set(null);
        this.notice.set(`Revoked ${k.name}. It will be removed from targets on the next deployment.`);
        this.reload();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected copy(text: string): void {
    void navigator.clipboard?.writeText(text);
  }

  protected statusClass(k: ManagedKey): string {
    switch (k.status) {
      case 'active': return 'ok';
      case 'staged': case 'pending': return 'info';
      case 'retiring': return 'warn';
      case 'revoked': case 'compromised': return 'danger';
      default: return 'neutral';
    }
  }

  protected expiringSoon(k: ManagedKey): boolean {
    if (!k.expires_at) return false;
    const days = (new Date(k.expires_at).getTime() - Date.now()) / 86_400_000;
    return days < 30;
  }

  /**
   * remove destroys the key and its private half.
   *
   * The server refuses while the key is still assigned anywhere, and names the
   * places. That refusal is the useful part of this button: it turns "delete
   * removed my access" into "you have three deployments to retire first".
   */
  protected async remove(k: ManagedKey): Promise<void> {
    if (!(await this.confirm.ask({
      title: `Delete "${k.name}"?`,
      message: `This shreds the private key. It cannot be redeployed, rotated, or used to authenticate anywhere it is still installed, and there is no undo short of restoring a backup.`,
      action: 'Delete',
      danger: true,
    }))) {
      return;
    }

    this.busy.set(true);
    this.api.deleteKey(k.id).subscribe({
      next: () => {
        this.busy.set(false);
        this.notice.set(`Deleted ${k.name} and shredded its private key.`);
        this.selected.set(null);
        this.reload();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }
}

function splitTags(raw: string): string[] {
  return raw.split(',').map((t) => t.trim()).filter(Boolean);
}
