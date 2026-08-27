import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';

import { Api } from '../../core/api';
import { Auth } from '../../core/auth';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import type { Assignment, Consumer, DeployResult, ManagedKey, Principal, Target } from '../../core/models';

/** One rendered line of a unified diff. */
interface DiffLine {
  text: string;
  kind: 'add' | 'remove' | 'meta' | 'hunk' | 'context';
}

@Component({
  selector: 'skm-install',
  imports: [FormsModule, DatePipe, RouterLink, Alerts],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .picker { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
    .matrix td.state { text-align: center; }
    .dot {
      display: inline-block; width: 0.6rem; height: 0.6rem; border-radius: 50%;
    }
    .dot.ok { background: var(--ok); }
    .dot.pending { background: var(--warn); }
    .dot.bad { background: var(--danger); }
    .dot.unknown { background: var(--text-faint); }
    .verified { color: var(--ok); }
    .legend { display: flex; gap: 1rem; font-size: 0.8rem; color: var(--text-muted); }
    .legend span { display: flex; align-items: center; gap: 0.35rem; }
    .step { margin-bottom: 1rem; transition: opacity 0.15s; }
    .step.dim { opacity: 0.55; }
    .step h2 { display: flex; align-items: center; gap: 0.55rem; }
    .num {
      display: inline-flex; align-items: center; justify-content: center;
      width: 1.5rem; height: 1.5rem; border-radius: 50%; flex: none;
      background: var(--accent); color: var(--bg); font-size: 0.8rem; font-weight: 600;
    }
    .step .checkbox { align-items: flex-start; }
    .step .checkbox input { margin-top: 0.2rem; }
  `],
  template: `
    <h1>Install</h1>
    <p class="muted" style="margin-top: -0.4rem;">
      Copy the keys you have planned onto a machine. Pick a machine below and
      SKM shows you the exact change first — nothing is written until you press
      <strong>Apply</strong>.
    </p>

    <skm-alerts [error]="error" />

    <!-- Step 1 --------------------------------------------------------- -->
    <div class="card step">
      <div class="card-header">
        <h2><span class="num">1</span> Pick a machine and login</h2>
      </div>

      <div class="picker">
        <label>
          <span class="label">Machine</span>
          <select [ngModel]="targetId()" (ngModelChange)="chooseTarget($event)">
            <option [ngValue]="null">— choose a machine —</option>
            @for (t of targets(); track t.id) {
              <option [ngValue]="t.id">{{ t.name }} ({{ t.address }})</option>
            }
          </select>
        </label>

        <label>
          <span class="label">Login</span>
          <select [ngModel]="principalId()" (ngModelChange)="choosePrincipal($event)"
                  [disabled]="principals().length === 0">
            <option [ngValue]="null">— choose a login —</option>
            @for (p of principals(); track p.id) {
              <option [ngValue]="p.id">{{ p.username }}{{ p.use_sudo ? ' (sudo)' : '' }}</option>
            }
          </select>
          @if (targetId() && principals().length === 0) {
            <span class="hint">
              This machine has no logins set up. Add one under Machines.
            </span>
          }
        </label>
      </div>
    </div>

    <!-- Step 2 --------------------------------------------------------- -->
    <div class="card step" [class.dim]="!ready()">
      <div class="card-header">
        <h2><span class="num">2</span> Check what will change</h2>
        @if (ready() && !busy()) {
          <button class="ghost sm" type="button" (click)="preview()">Refresh</button>
        }
      </div>

      @if (!ready()) {
        <div class="empty">Pick a machine and login above.</div>
      } @else if (busy() && lastWasDryRun()) {
        <div class="empty"><span class="spinner"></span> Working out the change…</div>
      } @else if (result(); as r) {
        @if (!r.changed) {
          <div class="notice ok">
            This machine already has exactly the right keys. There is nothing to do.
          </div>
        } @else {
          <div class="row small" style="margin-bottom: 0.8rem;">
            <span class="badge ok">{{ r.added.length }} to add</span>
            <span class="badge danger">{{ r.removed.length }} to remove</span>
            <span class="muted">{{ r.key_count }} key(s) afterwards</span>
          </div>

          <p class="small faint" style="margin-bottom: 0.5rem;">
            Green lines are keys that will be added, red ones removed. This is
            <code>{{ r.username }}</code>'s <code>authorized_keys</code> on
            <strong>{{ r.target_name }}</strong>.
          </p>

          @if (r.diff) {
            <div class="diff">
              @for (line of diffLines(); track $index) {
                <div class="line" [class]="line.kind">{{ line.text }}</div>
              }
            </div>
          }

          @if (r.dry_run) {
            <p class="small faint" style="margin-top: 0.7rem;">
              Nothing has been written. This is a preview.
            </p>
          }

          @if (r.verified_keys?.length) {
            <p class="verified small" style="margin-top: 0.9rem;">
              ✓ {{ r.verified_keys!.length }} key(s) were tested by logging in with them.
            </p>
          }
          @if (r.failed_keys?.length) {
            <div class="notice error" style="margin-top: 0.9rem;">
              {{ r.failed_keys!.length }} key(s) were written but could not log in.
              The old keys were left in place, so you are not locked out.
              @if (r.snapshot_id && !r.dry_run) {
                <div style="margin-top: 0.5rem; font-size: 0.85rem;">
                  To undo, <a routerLink="/machines">open the machine's Details on the Machines page and roll back the snapshot this run took</a>.
                </div>
              }
            </div>
          }
          @if (r.snapshot_id && !r.dry_run && !r.failed_keys?.length) {
            <p class="small faint" style="margin-top: 0.7rem;">
              A copy of the old file was saved first. Undo it from this machine's
              Details on the Machines page.
            </p>
          }
        }
      } @else {
        <div class="empty">Nothing to preview.</div>
      }
    </div>

    <!-- Step 3 --------------------------------------------------------- -->
    <div class="card step" [class.dim]="!ready()">
      <div class="card-header">
        <h2><span class="num">3</span> Apply it</h2>
      </div>

      <div style="padding: 0 1rem 1rem;">
        <label class="checkbox">
          <input type="checkbox" [ngModel]="verifyAuth()" (ngModelChange)="verifyAuth.set($event)" />
          <span>
            <strong>Test each key by logging in with it</strong>
            <div class="small faint">
              Recommended. Proves the key really works rather than assuming the
              file was written correctly.
            </div>
          </span>
        </label>

        <label class="checkbox" style="margin-top: 0.6rem;">
          <input type="checkbox" [ngModel]="prune()" (ngModelChange)="setPrune($event)" />
          <span>
            <strong>Also remove keys that are no longer assigned</strong>
            <div class="small faint">
              Only touches keys SKM put there. Leave this off and old keys stay
              on the machine until you turn it on.
            </div>
          </span>
        </label>

        @if (auth.can('deploy.execute')) {
          <div class="row" style="margin-top: 1rem;">
            <button class="primary" type="button"
                    [disabled]="!ready() || busy()"
                    (click)="run(false)">
              @if (busy() && !lastWasDryRun()) { <span class="spinner"></span> }
              Apply this change
            </button>
            @if (!ready()) {
              <span class="hint" style="margin: 0;">Pick a machine and login first.</span>
            } @else if (!hasChanges()) {
              <span class="hint" style="margin: 0;">
                Nothing to apply right now — the preview shows no change. Pressing
                it anyway is safe and simply re-checks the machine.
              </span>
            }
          </div>
        } @else {
          <p class="small faint" style="margin-top: 1rem;">
            You can preview changes but not apply them. That needs the
            <code>deploy.execute</code> permission.
          </p>
        }
      </div>
    </div>

    <div class="card matrix">
      <div class="card-header">
        <h2>Coverage</h2>
        <div class="row">
          <div class="legend">
            <span><i class="dot ok"></i> installed &amp; verified</span>
            <span><i class="dot pending"></i> installed</span>
            <span><i class="dot bad"></i> failed</span>
            <span><i class="dot unknown"></i> not applied</span>
          </div>
          @if (auth.can('key.write')) {
            <button class="ghost sm" type="button" (click)="assignForm.set(!assignForm())">
              {{ assignForm() ? 'Cancel' : 'Add a key' }}
            </button>
          }
        </div>
      </div>

      <p class="small faint" style="padding: 0 1rem;">
        Which keys are <em>meant</em> to be on which machines, and whether they
        actually are. A row appears here as soon as you add a key; the dot
        turns green once an install has put it there and proved it can log in.
      </p>

      @if (assignForm()) {
        <div style="padding: 0 1rem 1rem;">
          <div class="grid cols-3">
            <label>
              <span class="label">Key</span>
              <select [(ngModel)]="assignDraft.keyId" name="a-key">
                <option value="">— choose a key —</option>
                @for (k of keys(); track k.id) {
                  <option [value]="k.id">{{ k.name }} ({{ k.algorithm }})</option>
                }
              </select>
            </label>
            <label>
              <span class="label">Machine</span>
              <select [(ngModel)]="assignDraft.targetId" name="a-target"
                      (ngModelChange)="onAssignTargetChange()">
                <option value="">— choose a machine —</option>
                @for (t of targets(); track t.id) {
                  <option [value]="t.id">{{ t.name }} ({{ t.address }})</option>
                }
              </select>
            </label>
            <label>
              <span class="label">Login</span>
              <select [(ngModel)]="assignDraft.principalId" name="a-principal"
                      [disabled]="assignPrincipals().length === 0">
                <option value="">— choose a login —</option>
                @for (p of assignPrincipals(); track p.id) {
                  <option [value]="p.id">{{ p.username }}{{ p.use_sudo ? ' (sudo)' : '' }}</option>
                }
              </select>
            </label>
          </div>
          <label>
            <span class="label">Restrictions (optional)</span>
            <input [(ngModel)]="assignDraft.options" name="a-options"
                   placeholder="from=&quot;10.0.0.0/8&quot;, no-pty" />
            <span class="hint">
              <code>authorized_keys</code> options, comma separated. Leave empty
              for an unrestricted key.
            </span>
          </label>
          <button class="primary" type="button"
                  [disabled]="!assignDraft.keyId || !assignDraft.targetId || !assignDraft.principalId || busy()"
                  (click)="createAssignment()">
            @if (busy()) { <span class="spinner"></span> }
            Add
          </button>
          <span class="hint">
            This records the planned install only. Use the panel above to actually write it
            to the machine.
          </span>
        </div>
      }

      @if (assignments().length === 0) {
        <div class="empty">
          Nothing is planned yet. Press <strong>Add a key</strong> above, or
          use the <strong>Add</strong> button next to any key on the Keys page.
        </div>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th></th><th>Key</th><th>Machine</th><th>Login</th>
                  <th>Desired</th><th>Actual</th><th>Verified</th><th>Options</th><th></th></tr>
            </thead>
            <tbody>
              @for (a of assignments(); track a.id) {
                <tr>
                  <td class="state"><i class="dot" [class]="dotClass(a)"></i></td>
                  <td><strong>{{ a.key_name }}</strong></td>
                  <td>{{ a.target_name }}</td>
                  <td class="mono small">{{ a.username }}</td>
                  <td><span class="badge neutral">{{ a.desired_state }}</span></td>
                  <td>
                    <span class="badge" [class.ok]="a.actual_state === 'present'"
                          [class.danger]="a.actual_state === 'error'"
                          [class.neutral]="a.actual_state === 'unknown'">{{ a.actual_state }}</span>
                    @if (a.last_error) {
                      <div class="small danger-text faint truncate" style="max-width: 240px;"
                           [title]="a.last_error">{{ a.last_error }}</div>
                    }
                  </td>
                  <td class="small faint">
                    {{ a.auth_verified_at ? (a.auth_verified_at | date:'MMM d, HH:mm') : '—' }}
                  </td>
                  <td>@for (o of a.options; track o) { <span class="tag">{{ o }}</span> }</td>
                  <td style="text-align: right;">
                    @if (auth.can('key.write')) {
                      <button class="ghost sm" type="button" [disabled]="busyId() !== null" (click)="unassign(a)">
                        @if (busyId() === a.id) { <span class="spinner"></span> }
                        Remove
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

    <!-- Consumers ------------------------------------------------------ -->
    <div class="card" style="margin-top: 1.4rem;">
      <div class="card-header">
        <h2>
          Private-key deliveries
          <span class="badge neutral">optional</span>
        </h2>
        <div class="row">
          <button class="ghost sm" type="button" (click)="showConsumers.set(!showConsumers())">
            {{ showConsumers() ? 'Hide' : (consumers().length ? 'Show (' + consumers().length + ')' : 'Show') }}
          </button>
          @if (showConsumers() && auth.can('key.write')) {
            <button class="ghost sm" type="button" (click)="consumerForm.set(!consumerForm())">
              {{ consumerForm() ? 'Cancel' : 'Add delivery' }}
            </button>
          }
        </div>
      </div>

      @if (showConsumers()) {
        <div class="notice info" style="margin: 0 1rem 1rem;">
          <p style="margin: 0;">
            Some systems need the private key too — a CI secret, a Vault path, a file on a host.
            Register them here so a rotation updates them before the old key is retired.
          </p>
        </div>
      }

      @if (showConsumers() && consumerForm()) {
        <div style="padding: 0 1rem 1rem;">
          <div class="grid cols-3">
            <label>
              <span class="label">Name</span>
              <input [(ngModel)]="consumerDraft.name" name="c-name" placeholder="ci-deploy-key" />
              <span class="hint">Any label that tells you what this is.</span>
            </label>
            <label>
              <span class="label">Where should it go?</span>
              <select [(ngModel)]="consumerDraft.kind" name="c-kind">
                <option value="ssh_file">A file on another machine (over SSH)</option>
                <option value="file_drop">A file on the SKM server</option>
                <option value="vault_kv">HashiCorp Vault</option>
                <option value="kubernetes_secret">A Kubernetes secret</option>
                <option value="webhook">POSTed to a URL you choose</option>
                <option value="env_export">A file you can source in a shell</option>
              </select>
            </label>
            <label>
              <span class="label">Which key?</span>
              <select [(ngModel)]="consumerDraft.keyId" name="c-key">
                <option value="">— choose a key —</option>
                @for (k of keys(); track k.id) { <option [value]="k.id">{{ k.name }}</option> }
              </select>
              <span class="hint">Its private half is what gets sent.</span>
            </label>
          </div>
          @if (consumerDraft.kind === 'ssh_file') {
            <div class="grid cols-3">
              <label>
                <span class="label">Which machine?</span>
                <select [(ngModel)]="consumerDraft.targetId" name="c-target"
                        (ngModelChange)="onConsumerTargetChange()">
                  <option value="">— choose a machine —</option>
                  @for (t of targets(); track t.id) {
                    <option [value]="t.id">{{ t.name }} ({{ t.address }})</option>
                  }
                </select>
                @if (targets().length === 0) {
                  <span class="hint">No machines yet. Add one under Machines.</span>
                }
              </label>
              <label>
                <span class="label">Login to write as</span>
                <input [(ngModel)]="consumerDraft.username" name="c-user"
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
                <input [(ngModel)]="consumerDraft.path" name="c-path"
                       placeholder="/home/ec2-user/.ssh/id_ed25519" />
                <span class="hint">Full path, including the file name.</span>
              </label>
            </div>
            <div class="row">
              <label class="checkbox" style="margin: 0;">
                <input type="checkbox" [(ngModel)]="consumerDraft.writePublic" name="c-pub" />
                <span>Also write the matching <code>.pub</code> beside it</span>
              </label>
              <label class="checkbox" style="margin: 0;">
                <input type="checkbox" [(ngModel)]="consumerDraft.useSudo" name="c-sudo" />
                <span>Use sudo (needed if the path is outside that login's home)</span>
              </label>
            </div>
          } @else {
            <label>
              <span class="label">Where exactly? (JSON)</span>
              <textarea rows="3" [(ngModel)]="consumerDraft.config" name="c-config"
                        [placeholder]="configExample()"></textarea>
              <span class="hint">{{ configHelp() }}</span>
            </label>
          }

          <button class="primary" type="button"
                  [disabled]="!consumerReady() || busy()"
                  (click)="createConsumer()">
            @if (busy()) { <span class="spinner"></span> }
            Create delivery
          </button>
        </div>
      }

      @if (showConsumers()) {
        @if (consumers().length === 0) {
          <div class="empty">
            Nothing set up. That is the normal case — add one only if some other
            system needs the private key.
          </div>
        } @else {
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th><th>Goes to</th><th>Which key</th>
                  <th>Last sent</th><th></th>
                </tr>
              </thead>
              <tbody>
                @for (c of consumers(); track c.id) {
                  <tr>
                    <td><strong>{{ c.name }}</strong>
                        @if (!c.enabled) { <span class="badge neutral">off</span> }</td>
                    <td class="small">{{ consumerKindLabel(c.kind) }}</td>
                    <td class="small">{{ keyName(c.key_id) }}</td>
                    <td class="small faint">
                      {{ c.last_delivered_at ? (c.last_delivered_at | date:'MMM d, HH:mm') : 'never' }}
                      @if (c.last_error) {
                        <div class="small danger-text truncate" style="max-width: 240px;"
                             [title]="c.last_error">{{ c.last_error }}</div>
                      }
                    </td>
                    <td style="text-align: right; white-space: nowrap;">
                      @if (auth.can('key.write')) {
                        <button class="ghost sm" type="button" [disabled]="busyId() !== null" (click)="deliver(c)"
                                title="Copy the private key there right now. Normally SKM does this by itself during a rotation.">
                          @if (busyId() === c.id) { <span class="spinner"></span> }
                          Send now
                        </button>
                        <button class="ghost sm" type="button" [disabled]="busyId() !== null" (click)="removeConsumer(c)">
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
          <p class="small faint" style="padding: 0 1rem 0.8rem;">
            <strong>Send now</strong> writes the key to its destination
            immediately. You rarely need it — SKM does this on its own whenever
            the key is rotated. It is there for when a destination was broken at
            the time and you want to retry.
          </p>
        }
      }
    </div>
  `,
})
export class InstallPage implements OnInit {
  private readonly api = inject(Api);
  protected readonly auth = inject(Auth);
  private readonly confirm = inject(Confirm);
  private readonly route = inject(ActivatedRoute);

  protected readonly targets = signal<Target[]>([]);
  protected readonly principals = signal<Principal[]>([]);
  protected readonly assignments = signal<Assignment[]>([]);
  protected readonly consumers = signal<Consumer[]>([]);
  protected readonly keys = signal<ManagedKey[]>([]);
  protected readonly consumerForm = signal(false);
  /** Collapsed by default: an optional feature should not look like a step. */
  protected readonly showConsumers = signal(false);
  protected readonly assignForm = signal(false);
  /** Logins on whichever machine the assign form has selected. */
  protected readonly assignPrincipals = signal<Principal[]>([]);
  protected readonly result = signal<DeployResult | null>(null);

  protected readonly busy = signal(false);
  protected readonly busyId = signal<string | null>(null);
  protected readonly lastWasDryRun = signal(true);
  protected readonly error = signal<string | null>(null);

  // These are signals, not plain fields, because `ready` below is a computed:
  // a computed only recalculates when a signal it read changes, so plain fields
  // left it stuck on its first value — which disabled both buttons forever.
  protected readonly targetId = signal<string | null>(null);
  protected readonly principalId = signal<string | null>(null);
  protected readonly prune = signal(false);
  protected readonly verifyAuth = signal(true);

  protected readonly ready = computed(() => !!this.targetId() && !!this.principalId());

  /**
   * hasChanges keeps Apply disabled unless an un-applied preview says there is
   * work to do — so it is also off immediately after applying, rather than
   * inviting the same change twice.
   */
  protected readonly hasChanges = computed(() => {
    const r = this.result();
    return !!r && r.changed && r.dry_run;
  });

  /** diffLines classifies each line of the unified diff for colouring. */
  protected readonly diffLines = computed<DiffLine[]>(() => {
    const diff = this.result()?.diff;
    if (!diff) return [];

    return diff.replace(/\n$/, '').split('\n').map((text): DiffLine => {
      if (text.startsWith('+++') || text.startsWith('---')) return { text, kind: 'meta' };
      if (text.startsWith('@@')) return { text, kind: 'hunk' };
      if (text.startsWith('+')) return { text, kind: 'add' };
      if (text.startsWith('-')) return { text, kind: 'remove' };
      return { text, kind: 'context' };
    });
  });

  ngOnInit(): void {
    this.api.listTargets().subscribe({
      next: (r) => {
        this.targets.set(r.items);
        // Handle ?target=<id>&principal=<id> query params
        this.route.queryParamMap.subscribe((params) => {
          const targetId = params.get('target');
          const principalId = params.get('principal');
          if (targetId) {
            this.chooseTarget(targetId);
            if (principalId) {
              // Set principal after target is chosen
              setTimeout(() => this.choosePrincipal(principalId), 0);
            }
          }
        });
      },
      error: (err: Error) => this.error.set(err.message),
    });
    this.loadAssignments();
    this.loadConsumers();
    this.api.listKeys().subscribe({
      next: (r) => {
        this.keys.set(r.items);
        // Handle ?key=<id> query param
        this.route.queryParamMap.subscribe((params) => {
          const keyId = params.get('key');
          if (keyId) {
            this.assignDraft.keyId = keyId;
            this.assignForm.set(true);
          }
        });
      },
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected chooseTarget(id: string | null): void {
    this.targetId.set(id);
    this.principalId.set(null);
    this.principals.set([]);
    this.result.set(null);
    if (!id) return;

    this.api.listPrincipals(id).subscribe({
      next: (r) => {
        this.principals.set(r.items);
        // With exactly one login there is nothing to choose.
        if (r.items.length === 1) this.choosePrincipal(r.items[0].id);
      },
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected choosePrincipal(id: string | null): void {
    this.principalId.set(id);
    this.result.set(null);
    if (id) this.preview();
  }

  /** Pruning changes the diff, so the preview has to be redrawn when it moves. */
  protected setPrune(on: boolean): void {
    this.prune.set(on);
    if (this.ready()) this.preview();
  }

  /**
   * preview is the dry run.
   *
   * It runs on its own whenever the selection changes rather than waiting for a
   * button, because a preview you have to remember to ask for is a preview
   * people skip.
   */
  protected preview(): void {
    this.run(true);
  }

  protected run(dryRun: boolean): void {
    const target = this.targetId();
    const principal = this.principalId();
    if (!target || !principal) return;

    this.busy.set(true);
    this.lastWasDryRun.set(dryRun);
    this.error.set(null);

    this.api.deploy({
      target_id: target,
      principal_id: principal,
      dry_run: dryRun,
      prune: this.prune(),
      verify_auth: this.verifyAuth() && !dryRun,
    }).subscribe({
      next: (r) => {
        this.busy.set(false);
        this.result.set(r);
        // The applied result carries the verification outcome, so it stays on
        // screen rather than being replaced by a fresh preview. Apply disables
        // itself because hasChanges only counts an un-applied dry run.
        if (!dryRun) this.loadAssignments();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  private loadAssignments(): void {
    this.api.listAssignments().subscribe({
      next: (r) => this.assignments.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected dotClass(a: Assignment): string {
    if (a.actual_state === 'error') return 'bad';
    if (a.actual_state !== 'present') return 'unknown';
    return a.auth_verified_at ? 'ok' : 'pending';
  }

  /**
   * unassign drops the desired-state row.
   *
   * It does not touch the host. Removing a key from a machine is an install,
   * not a database edit, and the two being different is the whole reason
   * desired state exists — so the confirmation says which one this is.
   */
  protected async unassign(a: Assignment): Promise<void> {
    if (!(await this.confirm.ask({
      title: `Remove ${a.key_name} from ${a.target_name}/${a.username}?`,
      message: 'SKM stops intending the key to be there. The key stays on the host until an install with pruning removes it.',
      action: 'Remove',
    }))) return;

    this.busyId.set(a.id);
    this.api.deleteAssignment(a.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.error.set(null);
        this.loadAssignments();
        this.refreshPreview();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  /**
   * refreshPreview re-runs the dry run after the desired state changes.
   *
   * Editing an assignment changes what the next install would do, so a
   * preview taken before the edit is wrong. Leaving it on screen is worse than
   * showing nothing: it looks like the change had no effect.
   */
  private refreshPreview(): void {
    if (this.ready()) this.preview();
  }


  // ------------------------------------------------------------- assign ---

  protected assignDraft = { keyId: '', targetId: '', principalId: '', options: '' };

  protected onAssignTargetChange(): void {
    this.assignDraft.principalId = '';
    this.assignPrincipals.set([]);
    if (!this.assignDraft.targetId) return;

    this.api.listPrincipals(this.assignDraft.targetId).subscribe({
      next: (r) => {
        this.assignPrincipals.set(r.items);
        if (r.items.length === 1) this.assignDraft.principalId = r.items[0].id;
      },
      error: (err: Error) => this.error.set(err.message),
    });
  }

  /**
   * createAssignment records that a key belongs on a login.
   *
   * Nothing is written to the host here. Keeping the two apart is what makes
   * the dry-run diff above meaningful: intent is edited in the database,
   * reality is changed by an install, and the gap between them is visible.
   */
  protected createAssignment(): void {
    this.error.set(null);
    this.busy.set(true);

    this.api.createAssignment({
      key_id: this.assignDraft.keyId,
      target_id: this.assignDraft.targetId,
      principal_id: this.assignDraft.principalId,
      options: this.assignDraft.options.split(',').map((o) => o.trim()).filter(Boolean),
    }).subscribe({
      next: () => {
        this.busy.set(false);
        const keyName = this.keys().find((k) => k.id === this.assignDraft.keyId)?.name || 'Key';
        this.assignDraft = { keyId: '', targetId: '', principalId: '', options: '' };
        this.assignPrincipals.set([]);
        this.assignForm.set(false);
        this.loadAssignments();
        this.refreshPreview();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected consumerDraft = {
    name: '', kind: 'ssh_file', keyId: '', config: '',
    targetId: '', username: '', path: '', writePublic: true, useSudo: false,
  };

  /** Logins on the machine the destination form has selected, for the datalist. */
  protected readonly consumerPrincipals = signal<Principal[]>([]);

  protected onConsumerTargetChange(): void {
    this.consumerPrincipals.set([]);
    if (!this.consumerDraft.targetId) return;

    this.api.listPrincipals(this.consumerDraft.targetId).subscribe({
      next: (r) => {
        this.consumerPrincipals.set(r.items);
        // Prefill the obvious answer; the field stays editable because the file
        // does not have to be owned by a login SKM manages keys for.
        if (!this.consumerDraft.username && r.items.length) {
          this.consumerDraft.username = r.items[0].username;
        }
      },
      error: (err: Error) => this.error.set(err.message),
    });
  }

  /** consumerReady mirrors what the chosen destination actually needs. */
  protected consumerReady(): boolean {
    const d = this.consumerDraft;
    if (!d.name || !d.keyId) return false;
    if (d.kind === 'ssh_file') return !!d.targetId && !!d.username && !!d.path;
    // For non-ssh_file kinds, require non-empty, parseable JSON config.
    if (!d.config.trim()) return false;
    try {
      JSON.parse(d.config);
      return true;
    } catch {
      return false;
    }
  }

  /** Plain-English names for the destination kinds the server accepts. */
  private static readonly CONSUMER_KINDS: Record<string, string> = {
    ssh_file: 'A file on another machine',
    file_drop: 'A file on the SKM server',
    vault_kv: 'HashiCorp Vault',
    kubernetes_secret: 'A Kubernetes secret',
    webhook: 'POSTed to a URL',
    env_export: 'A shell-sourceable file',
  };

  protected consumerKindLabel(kind: string): string {
    return InstallPage.CONSUMER_KINDS[kind] ?? kind;
  }

  /** A worked example for the chosen destination, rather than one generic blob. */
  protected configExample(): string {
    switch (this.consumerDraft.kind) {
      case 'ssh_file':
        return '{"target_id": "' + (this.targets()[0]?.id ?? '…') +
          '", "username": "ec2-user", "path": "/home/ec2-user/.ssh/id_ed25519", "write_public": "true"}';
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
    switch (this.consumerDraft.kind) {
      case 'ssh_file':
        return 'target_id is the machine from the Machines page — copy its id from the URL or the list. ' +
          'username is the login to write as; path is where the private key file goes. ' +
          'Add "write_public": "true" to drop the matching .pub beside it, and "use_sudo": true if the path needs root.';
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

  private loadConsumers(): void {
    this.api.listConsumers().subscribe({
      next: (r) => this.consumers.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected keyName(id: string): string {
    return this.keys().find((k) => k.id === id)?.name ?? id.slice(0, 8);
  }

  protected createConsumer(): void {
    let config: Record<string, unknown> = {};

    if (this.consumerDraft.kind === 'ssh_file') {
      // Built from the form rather than typed as JSON: making someone paste a
      // UUID into a text box is how this screen earned its reputation.
      config = {
        target_id: this.consumerDraft.targetId,
        username: this.consumerDraft.username,
        path: this.consumerDraft.path,
      };
      if (this.consumerDraft.writePublic) config['write_public'] = true;
      if (this.consumerDraft.useSudo) config['use_sudo'] = true;
      this.saveConsumer(config);
      return;
    }

    if (this.consumerDraft.config.trim()) {
      try {
        config = JSON.parse(this.consumerDraft.config) as Record<string, unknown>;
      } catch {
        this.error.set('The settings are not valid JSON.');
        return;
      }
    }

    this.saveConsumer(config);
  }

  private saveConsumer(config: Record<string, unknown>): void {
    this.busy.set(true);
    this.api.createConsumer({
      name: this.consumerDraft.name,
      kind: this.consumerDraft.kind,
      key_id: this.consumerDraft.keyId,
      config,
      enabled: true,
    }).subscribe({
      next: () => {
        this.busy.set(false);
        this.error.set(null);
        this.consumerDraft = {
          name: '', kind: 'ssh_file', keyId: '', config: '',
          targetId: '', username: '', path: '', writePublic: true, useSudo: false,
        };
        this.consumerPrincipals.set([]);
        this.consumerForm.set(false);
        this.loadConsumers();
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
        this.loadConsumers();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected async removeConsumer(c: Consumer): Promise<void> {
    if (!(await this.confirm.ask({
      title: `Delete the delivery "${c.name}"?`,
      message: 'Whatever it already delivered stays where it was sent. Rotations will simply stop updating it, which is worth being sure about.',
      action: 'Delete',
      danger: true,
    }))) return;

    this.busyId.set(c.id);
    this.api.deleteConsumer(c.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.error.set(null);
        this.loadConsumers();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

}
