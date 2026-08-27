import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { forkJoin, combineLatest } from 'rxjs';

import { Api } from '../../core/api';
import { Auth } from '../../core/auth';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import type { Assignment, Consumer, DeployResult, ManagedKey, Principal, Target } from '../../core/models';

/**
 * Outcome is what one login's preview or apply produced: a deploy result, or
 * the error that stopped it. Either way the template can ask for .error.
 */
type Outcome = (DeployResult & { error?: undefined }) | (Partial<DeployResult> & { error: string });

/** One rendered line of a unified diff. */
interface DiffLine {
  text: string;
  kind: 'add' | 'remove' | 'meta' | 'hunk' | 'context';
}

/** A row in the logins table. */
interface TableRow {
  target: Target;
  principal: Principal;
  key: string; // "target.id:principal.id"
  checked: boolean;
  assignment: Assignment | null;
}

@Component({
  selector: 'skm-install',
  imports: [FormsModule, DatePipe, Alerts],
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
    .filter-box { margin-bottom: 0.8rem; }
    .results-grid { display: grid; gap: 1rem; }
    .result-block { border: 1px solid var(--border); border-radius: 0.4rem; padding: 0.8rem; }
    .result-block.error { border-color: var(--danger); background: rgba(var(--danger-rgb), 0.05); }
    .result-block.ok { border-color: var(--ok); background: rgba(var(--ok-rgb), 0.05); }
  `],
  template: `
    <h1>Install</h1>
    <p class="muted" style="margin-top: -0.4rem;">
      Put a key on the logins that should have it. Pick the key, tick the logins, check the diff, apply. Nothing is removed unless you ask, and every change takes a snapshot you can roll back.
    </p>

    <skm-alerts [error]="error" [notice]="notice" />

    <!-- Card 1: Which key? ============================================== -->
    <div class="card step">
      <div class="card-header">
        <h2><span class="num">1</span> Which key?</h2>
      </div>

      <div style="padding: 0 1rem 1rem;">
        <label>
          <span class="label">Key</span>
          <select [ngModel]="selectedKeyId()" (ngModelChange)="selectKey($event)">
            <option [ngValue]="null">— choose a key —</option>
            @for (k of availableKeys(); track k.id) {
              <option [ngValue]="k.id">{{ k.name }} ({{ k.algorithm }})</option>
            }
          </select>
        </label>

        @if (selectedKey(); as key) {
          <p class="small faint" style="margin-top: 0.5rem;">
            {{ key.name }} · {{ key.algorithm }} · installed on {{ assignmentCountForKey() }} logins
          </p>
        }
      </div>
    </div>

    <!-- Card 2: Where should it go? ==================================== -->
    <div class="card step" [class.dim]="!selectedKey()">
      <div class="card-header">
        <h2><span class="num">2</span> Where should it go?</h2>
      </div>

      @if (!selectedKey()) {
        <div class="empty">Pick a key above.</div>
      } @else {
        <div style="padding: 0 1rem 1rem;">
          <input type="text" placeholder="Filter by machine or login name…"
                 [ngModel]="filterText()" (ngModelChange)="filterText.set($event)"
                 class="filter-box" />

          @if (filteredRows().length === 0) {
            <div class="empty">No logins match the filter.</div>
          } @else {
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th></th>
                    <th>Machine</th>
                    <th>Login</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody>
                  @for (row of filteredRows(); track row.key) {
                    <tr>
                      <td>
                        <label class="checkbox" style="margin: 0;">
                          <input type="checkbox" [checked]="row.checked" [disabled]="applyBusy()"
                                 (change)="toggleRow(row.key, $any($event).target.checked)" />
                        </label>
                      </td>
                      <td><strong>{{ row.target.name }}</strong></td>
                      <td class="mono small">{{ row.principal.username }}{{ row.principal.use_sudo ? ' (sudo)' : '' }}</td>
                      <td class="state">
                        @if (row.assignment) {
                          <i class="dot" [class]="dotClass(row.assignment)"></i>
                          <span class="small faint">{{ row.assignment.actual_state }}</span>
                        } @else {
                          <span class="badge neutral">not planned</span>
                        }
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>

            <p class="small faint" style="margin-top: 0.6rem;">
              Unticking only removes the plan. The key stays on that login until you apply with "Remove keys that are not planned" ticked for it.
            </p>
          }
        </div>
      }
    </div>

    <!-- Card 3: Check what will change ================================ -->
    <div class="card step" [class.dim]="!canPreview()">
      <div class="card-header">
        <h2><span class="num">3</span> Check what will change</h2>
        @if (canPreview() && !previewBusy()) {
          <button class="ghost sm" type="button" (click)="runPreviews()">Refresh preview</button>
        }
      </div>

      @if (!canPreview()) {
        <div class="empty">Pick a key and select at least one login above.</div>
      } @else if (previewBusy()) {
        <div class="empty"><span class="spinner"></span> Working out the changes…</div>
      } @else {
        <div style="padding: 0 1rem 1rem;">
          <label class="checkbox">
            <input type="checkbox" [ngModel]="verifyAuth()" (ngModelChange)="verifyAuth.set($event)" />
            <span>
              <strong>Verify the new key can log in</strong>
              <div class="small faint">
                Recommended. Proves the key really works rather than assuming the file was written correctly.
              </div>
            </span>
          </label>

          <label class="checkbox" style="margin-top: 0.6rem;">
            <input type="checkbox" [ngModel]="prune()" (ngModelChange)="setPrune($event)" />
            <span>
              <strong>Remove keys that are not planned</strong>
              <div class="small faint">
                Only touches keys SKM put there. Leave this off and old keys stay on the machine until you turn it on.
              </div>
            </span>
          </label>
        </div>

        <div class="results-grid" style="padding: 0 1rem;">
          @for (row of previewRows(); track row.key) {
            @if (previewResults()[row.key]; as result) {
              <div [class.result-block]="true" [class.ok]="!result.error && result.changed" [class.error]="result.error">
                <div style="margin-bottom: 0.6rem;">
                  <strong>{{ row.target.name }} / {{ row.principal.username }}</strong>
                </div>

                @if (result.error) {
                  <div class="notice error" style="margin: 0;">{{ result.error }}</div>
                } @else if (!result.changed) {
                  <div class="notice ok" style="margin: 0;">No change</div>
                } @else {
                  <div class="row small" style="margin-bottom: 0.6rem;">
                    <span class="badge ok">{{ result.added?.length ?? 0 }} to add</span>
                    <span class="badge danger">{{ result.removed?.length ?? 0 }} to remove</span>
                    <span class="muted">{{ result.key_count }} key(s) afterwards</span>
                  </div>

                  @if (result.diff) {
                    <div class="diff" style="max-height: 300px; overflow-y: auto;">
                      @for (line of parseDiff(result.diff); track $index) {
                        <div class="line" [class]="line.kind">{{ line.text }}</div>
                      }
                    </div>
                  }

                  @if (result.verified_keys?.length) {
                    <p class="verified small" style="margin-top: 0.6rem; margin-bottom: 0;">
                      ✓ {{ result.verified_keys!.length }} key(s) were tested by logging in with them.
                    </p>
                  }
                  @if (result.failed_keys?.length) {
                    <div class="notice error" style="margin-top: 0.6rem; margin-bottom: 0;">
                      {{ result.failed_keys!.length }} key(s) were written but could not log in.
                      The old keys were left in place.
                    </div>
                  }
                }
              </div>
            }
          }
        </div>
      }
    </div>

    <!-- Card 4: Apply ================================================= -->
    <div class="card step" [class.dim]="!canApply()">
      <div class="card-header">
        <h2><span class="num">4</span> Apply</h2>
      </div>

      @if (!canApply()) {
        <div class="empty">
          @if (!selectedKey()) {
            Pick a key first.
          } @else if (checkedCount() === 0) {
            Select at least one login to install on.
          } @else {
            Preview the changes first.
          }
        </div>
      } @else {
        <div style="padding: 0 1rem 1rem;">
          @if (auth.can('deploy.execute')) {
            <button class="primary" type="button"
                    [disabled]="applyBusy()"
                    (click)="apply()">
              @if (applyBusy()) { <span class="spinner"></span> }
              Install on {{ checkedCount() }} logins
            </button>
          } @else {
            <p class="small faint">
              You can preview changes but not apply them. That needs the
              <code>deploy.execute</code> permission.
            </p>
          }

          @if (hasApplyResults()) {
            <div class="results-grid" style="margin-top: 1rem;">
              @for (row of applyRows(); track row.key) {
                @if (applyResults()[row.key]; as result) {
                  <div [class.result-block]="true" [class.ok]="!result.error" [class.error]="result.error">
                    <div style="margin-bottom: 0.6rem;">
                      <strong>{{ row.target.name }} / {{ row.principal.username }}</strong>
                    </div>

                    @if (result.error) {
                      <div class="notice error" style="margin: 0;">{{ result.error }}</div>
                    } @else if (result.result?.changed === false) {
                      <div class="notice ok" style="margin: 0;">No change</div>
                    } @else {
                      @if (result.result?.verified_keys?.length) {
                        <p class="verified small" style="margin: 0;">
                          ✓ Installed. Logged in with the new key.
                        </p>
                      } @else if (!result.result?.failed_keys?.length) {
                        <p class="small faint" style="margin: 0;">
                          Installed successfully.
                        </p>
                      }

                      @if (result.result?.failed_keys?.length) {
                        <div class="notice error" style="margin: 0;">
                          {{ result.result!.failed_keys!.length }} key(s) failed verification.
                        </div>
                      }

                      @if (result.result?.snapshot_id) {
                        <button class="ghost sm" type="button"
                                [disabled]="busyId() === row.key"
                                (click)="doRollback(row, result.result?.snapshot_id ?? '')"
                                style="margin-top: 0.6rem;">
                          @if (busyId() === row.key) { <span class="spinner"></span> }
                          Roll back
                        </button>
                      }
                    }
                  </div>
                }
              }
            </div>
          }
        </div>
      }
    </div>

    <!-- Coverage matrix ================================================ -->
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
              <select [ngModel]="assignDraft().keyId" (ngModelChange)="assignDraft.update(d => ({...d, keyId: $event}))" name="a-key">
                <option value="">— choose a key —</option>
                @for (k of keys(); track k.id) {
                  <option [value]="k.id">{{ k.name }} ({{ k.algorithm }})</option>
                }
              </select>
            </label>
            <label>
              <span class="label">Machine</span>
              <select [ngModel]="assignDraft().targetId" (ngModelChange)="assignDraft.update(d => ({...d, targetId: $event})); onAssignTargetChange()" name="a-target">
                <option value="">— choose a machine —</option>
                @for (t of targets(); track t.id) {
                  <option [value]="t.id">{{ t.name }} ({{ t.address }})</option>
                }
              </select>
            </label>
            <label>
              <span class="label">Login</span>
              <select [ngModel]="assignDraft().principalId" (ngModelChange)="assignDraft.update(d => ({...d, principalId: $event}))" name="a-principal"
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
            <input [ngModel]="assignDraft().options" (ngModelChange)="assignDraft.update(d => ({...d, options: $event}))" name="a-options"
                   placeholder="from=&quot;10.0.0.0/8&quot;, no-pty" />
            <span class="hint">
              <code>authorized_keys</code> options, comma separated. Leave empty
              for an unrestricted key.
            </span>
          </label>
          <button class="primary" type="button"
                  [disabled]="!assignDraft().keyId || !assignDraft().targetId || !assignDraft().principalId || busy()"
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

    <!-- Private-key deliveries ========================================== -->
    <details class="card" style="margin-top: 1.4rem;">
      <summary style="cursor: pointer; padding: 1rem; display: flex; justify-content: space-between; align-items: center;">
        <h2 style="margin: 0;">
          Also deliver the private key to…
          <span class="badge neutral">{{ filteredConsumers().length }}</span>
        </h2>
      </summary>

      <div>
        <div class="notice info" style="margin: 1rem;">
          <p style="margin: 0;">
            Some systems need the private key too — a CI secret, a Vault path, a file on a host.
            Register them here so a rotation updates them before the old key is retired.
          </p>
        </div>

        @if (auth.can('key.write')) {
          <div style="padding: 0 1rem 1rem;">
            <button class="ghost sm" type="button" (click)="consumerForm.set(!consumerForm())"
                    style="margin-bottom: 0.8rem;">
              {{ consumerForm() ? 'Cancel' : 'Add delivery' }}
            </button>
          </div>
        }

        @if (consumerForm()) {
          <div style="padding: 0 1rem 1rem;">
            <div class="grid cols-3">
              <label>
                <span class="label">Name</span>
                <input [ngModel]="consumerDraft().name" (ngModelChange)="consumerDraft.update(d => ({...d, name: $event}))" name="c-name" placeholder="ci-deploy-key" />
                <span class="hint">Any label that tells you what this is.</span>
              </label>
              <label>
                <span class="label">Where should it go?</span>
                <select [ngModel]="consumerDraft().kind" (ngModelChange)="consumerDraft.update(d => ({...d, kind: $event}))" name="c-kind">
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
                <select [ngModel]="consumerDraft().keyId" (ngModelChange)="consumerDraft.update(d => ({...d, keyId: $event}))" name="c-key">
                  <option value="">— choose a key —</option>
                  @for (k of keys(); track k.id) { <option [value]="k.id">{{ k.name }}</option> }
                </select>
                <span class="hint">Its private half is what gets sent.</span>
              </label>
            </div>
            @if (consumerDraft().kind === 'ssh_file') {
              <div class="grid cols-3">
                <label>
                  <span class="label">Which machine?</span>
                  <select [ngModel]="consumerDraft().targetId" (ngModelChange)="consumerDraft.update(d => ({...d, targetId: $event})); onConsumerTargetChange()" name="c-target">
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
                <span class="label">Where exactly? (JSON)</span>
                <textarea rows="3" [ngModel]="consumerDraft().config" (ngModelChange)="consumerDraft.update(d => ({...d, config: $event}))" name="c-config"
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

        @if (filteredConsumers().length === 0) {
          <div class="empty" style="margin: 1rem;">
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
                @for (c of filteredConsumers(); track c.id) {
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
      </div>
    </details>
  `,
})
export class InstallPage implements OnInit {
  private readonly api = inject(Api);
  protected readonly auth = inject(Auth);
  private readonly confirm = inject(Confirm);
  private readonly route = inject(ActivatedRoute);

  // Data
  protected readonly targets = signal<Target[]>([]);
  protected readonly assignments = signal<Assignment[]>([]);
  protected readonly consumers = signal<Consumer[]>([]);
  protected readonly keys = signal<ManagedKey[]>([]);
  protected readonly targetPrincipalsMap = signal<Record<string, Principal[]>>({});

  // Card 1: Key selection
  protected readonly selectedKeyId = signal<string | null>(null);
  protected readonly selectedKey = computed(() => {
    const id = this.selectedKeyId();
    if (!id) return null;
    return this.keys().find(k => k.id === id) ?? null;
  });

  // Available keys: exclude revoked, compromised, retired
  protected readonly availableKeys = computed(() => {
    return this.keys().filter(k =>
      k.status !== 'revoked' && k.status !== 'compromised' && k.status !== 'retired'
    );
  });

  // Count assignments for selected key
  protected readonly assignmentCountForKey = computed(() => {
    const keyId = this.selectedKeyId();
    if (!keyId) return 0;
    return this.assignments().filter(a => a.key_id === keyId).length;
  });

  // Card 2: Row selection
  protected readonly allRows = computed(() => {
    const rows: TableRow[] = [];
    const principalsMap = this.targetPrincipalsMap();
    for (const target of this.targets()) {
      const principals = principalsMap[target.id] ?? [];
      for (const principal of principals) {
        const key = `${target.id}:${principal.id}`;
        const keyId = this.selectedKeyId();
        const assignment = keyId ?
          this.assignments().find(a => a.key_id === keyId && a.target_id === target.id && a.principal_id === principal.id) ?? null
          : null;
        rows.push({
          target,
          principal,
          key,
          checked: this.rowChecked()[key] ?? !!assignment,
          assignment,
        });
      }
    }
    return rows;
  });

  protected readonly filterText = signal('');
  protected readonly filteredRows = computed(() => {
    const filter = this.filterText().toLowerCase();
    if (!filter) return this.allRows();
    return this.allRows().filter(r =>
      r.target.name.toLowerCase().includes(filter) ||
      r.principal.username.toLowerCase().includes(filter)
    );
  });

  protected readonly rowChecked = signal<Record<string, boolean>>({});

  protected readonly checkedCount = computed(() => {
    return Object.values(this.rowChecked()).filter(Boolean).length;
  });

  protected readonly previewRows = computed(() => {
    return this.allRows().filter(r => this.rowChecked()[r.key]);
  });

  protected readonly canPreview = computed(() => {
    return !!this.selectedKey() && this.checkedCount() > 0;
  });

  // Card 3: Previews
  protected readonly verifyAuth = signal(true);
  protected readonly prune = signal(false);
  protected readonly previewResults = signal<Record<string, Outcome>>({});
  protected readonly previewBusy = signal(false);

  protected readonly canApply = computed(() => {
    if (!this.canPreview()) return false;
    const results = this.previewResults();
    // Can apply if we have previews for all checked rows
    return this.previewRows().every(r => !!results[r.key]);
  });

  // Card 4: Apply
  protected readonly applyResults = signal<Record<string, {result?: DeployResult, error?: string}>>({});
  protected readonly applyBusy = signal(false);
  protected readonly applyRows = computed(() => {
    return this.allRows().filter(r => !!this.applyResults()[r.key]);
  });

  protected readonly hasApplyResults = computed(() => {
    return Object.keys(this.applyResults()).length > 0;
  });

  // Loading states
  protected readonly busy = signal(false);
  protected readonly busyId = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);

  // Consumers
  protected readonly consumerForm = signal(false);
  protected readonly consumerPrincipals = signal<Principal[]>([]);
  protected readonly consumerDraft = signal({
    name: '', kind: 'ssh_file', keyId: '', config: '',
    targetId: '', username: '', path: '', writePublic: true, useSudo: false,
  });

  protected readonly filteredConsumers = computed(() => {
    const keyId = this.selectedKeyId();
    if (!keyId) return this.consumers();
    return this.consumers().filter(c => c.key_id === keyId);
  });

  // Assignments form
  protected readonly assignForm = signal(false);
  protected readonly assignPrincipals = signal<Principal[]>([]);
  protected readonly assignDraft = signal({ keyId: '', targetId: '', principalId: '', options: '' });


  ngOnInit(): void {
    // Load targets first
    this.api.listTargets().subscribe({
      next: (r) => {
        this.targets.set(r.items);
        // Load principals for each target in parallel
        const requests = r.items.map(t => this.api.listPrincipals(t.id));
        forkJoin(requests).subscribe({
          next: (results) => {
            const map: Record<string, Principal[]> = {};
            for (let i = 0; i < r.items.length; i++) {
              map[r.items[i].id] = results[i].items ?? [];
            }
            // Rebuild all rows with principals
            this.rebuildTargetPrincipals(map);
          },
          error: (err: Error) => this.error.set(err.message),
        });
      },
      error: (err: Error) => this.error.set(err.message),
    });

    // Load assignments
    this.loadAssignments();

    // Load consumers
    this.loadConsumers();

    // Load keys and handle combined query params
    this.api.listKeys().subscribe({
      next: (r) => {
        this.keys.set(r.items);
        // Handle all query params together to avoid race condition
        this.route.queryParamMap.subscribe((params) => {
          const keyId = params.get('key');
          const targetId = params.get('target');
          const principalId = params.get('principal');

          // If key param exists, select it first (clears rowChecked)
          if (keyId) {
            this.selectKey(keyId);
          }

          // Then apply target/principal pre-checks if present
          if (targetId && principalId) {
            const key = `${targetId}:${principalId}`;
            this.rowChecked.update(v => ({ ...v, [key]: true }));
          }
        });
      },
      error: (err: Error) => this.error.set(err.message),
    });
  }

  private rebuildTargetPrincipals(map: Record<string, Principal[]>): void {
    this.targetPrincipalsMap.set(map);
  }

  protected selectKey(id: string | null): void {
    this.selectedKeyId.set(id);
    this.rowChecked.set({});
    this.previewResults.set({});
    this.applyResults.set({});
    this.filterText.set('');
  }

  protected toggleRow(key: string, checked: boolean): void {
    this.rowChecked.update(v => ({ ...v, [key]: checked }));
    this.previewResults.set({});
    this.applyResults.set({});
  }

  protected setPrune(on: boolean): void {
    this.prune.set(on);
    if (this.canPreview()) {
      this.runPreviews();
    }
  }

  protected parseDiff(diff: string): DiffLine[] {
    return diff.replace(/\n$/, '').split('\n').map((text): DiffLine => {
      if (text.startsWith('+++') || text.startsWith('---')) return { text, kind: 'meta' };
      if (text.startsWith('@@')) return { text, kind: 'hunk' };
      if (text.startsWith('+')) return { text, kind: 'add' };
      if (text.startsWith('-')) return { text, kind: 'remove' };
      return { text, kind: 'context' };
    });
  }

  protected dotClass(a: Assignment): string {
    if (a.actual_state === 'error') return 'bad';
    if (a.actual_state !== 'present') return 'unknown';
    return a.auth_verified_at ? 'ok' : 'pending';
  }

  protected runPreviews(): void {
    if (!this.canPreview()) return;

    this.previewBusy.set(true);
    this.error.set(null);
    const rows = this.previewRows();
    const results: Record<string, Outcome> = {};
    let completed = 0;

    // Run deploys sequentially with a simple loop and subscriptions
    const runNext = (index: number) => {
      if (index >= rows.length) {
        this.previewBusy.set(false);
        this.previewResults.set(results);
        return;
      }

      const row = rows[index];
      this.api.deploy({
        target_id: row.target.id,
        principal_id: row.principal.id,
        dry_run: true,
        prune: this.prune(),
        verify_auth: this.verifyAuth(),
      }).subscribe({
        next: (result) => {
          results[row.key] = result;
          runNext(index + 1);
        },
        error: (err: Error) => {
          results[row.key] = { error: err.message };
          runNext(index + 1);
        },
      });
    };

    runNext(0);
  }

  protected apply(): void {
    if (!this.canApply()) return;

    const rows = this.previewRows();
    this.applyBusy.set(true);
    this.error.set(null);
    const results: Record<string, {result?: DeployResult, error?: string}> = {};

    // Step 1: Sync assignments (create missing, delete unchecked)
    const toCreate: Promise<void>[] = [];
    const toDelete: Promise<void>[] = [];

    for (const row of this.allRows()) {
      const isChecked = this.rowChecked()[row.key];
      const hasAssignment = !!row.assignment;

      if (isChecked && !hasAssignment) {
        // Create assignment
        toCreate.push(
          new Promise(resolve => {
            this.api.createAssignment({
              key_id: this.selectedKeyId()!,
              target_id: row.target.id,
              principal_id: row.principal.id,
              options: [],
            }).subscribe({
              next: () => resolve(),
              error: () => resolve(), // swallow errors, proceed
            });
          })
        );
      } else if (!isChecked && hasAssignment) {
        // Delete assignment
        toDelete.push(
          new Promise(resolve => {
            this.api.deleteAssignment(row.assignment!.id).subscribe({
              next: () => resolve(),
              error: () => resolve(), // swallow errors, proceed
            });
          })
        );
      }
    }

    Promise.all([...toCreate, ...toDelete]).then(() => {
      // Step 2: Run deploys sequentially
      const runDeploy = (index: number) => {
        if (index >= rows.length) {
          this.applyBusy.set(false);
          this.applyResults.set(results);
          this.loadAssignments();
          this.notice.set('Installations complete.');
          setTimeout(() => this.notice.set(null), 3000);
          return;
        }

        const row = rows[index];
        this.api.deploy({
          target_id: row.target.id,
          principal_id: row.principal.id,
          dry_run: false,
          prune: this.prune(),
          verify_auth: this.verifyAuth(),
        }).subscribe({
          next: (result) => {
            results[row.key] = { result };
            runDeploy(index + 1);
          },
          error: (err: Error) => {
            results[row.key] = { error: err.message };
            runDeploy(index + 1);
          },
        });
      };

      runDeploy(0);
    });
  }

  protected doRollback(row: TableRow, snapshotId: string): void {
    this.confirm.ask({
      title: 'Roll back this installation?',
      message: 'The key file will be restored to its previous state.',
      action: 'Roll back',
      danger: true,
    }).then(ok => {
      if (!ok) return;

      this.busyId.set(row.key);
      this.api.rollback(snapshotId).subscribe({
        next: () => {
          this.busyId.set(null);
          this.error.set(null);
          this.notice.set('Rolled back successfully.');
          this.loadAssignments();
          setTimeout(() => this.notice.set(null), 3000);
        },
        error: (err: Error) => {
          this.busyId.set(null);
          this.error.set(err.message);
        },
      });
    });
  }

  private loadAssignments(): void {
    this.api.listAssignments().subscribe({
      next: (r) => this.assignments.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

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
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected onAssignTargetChange(): void {
    const draft = this.assignDraft();
    this.assignDraft.update(d => ({ ...d, principalId: '' }));
    this.assignPrincipals.set([]);
    if (!draft.targetId) return;

    this.api.listPrincipals(draft.targetId).subscribe({
      next: (r) => {
        this.assignPrincipals.set(r.items);
        if (r.items.length === 1) this.assignDraft.update(d => ({ ...d, principalId: r.items[0].id }));
      },
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected createAssignment(): void {
    const draft = this.assignDraft();
    this.error.set(null);
    this.busy.set(true);

    this.api.createAssignment({
      key_id: draft.keyId,
      target_id: draft.targetId,
      principal_id: draft.principalId,
      options: draft.options.split(',').map((o) => o.trim()).filter(Boolean),
    }).subscribe({
      next: () => {
        this.busy.set(false);
        this.assignDraft.set({ keyId: '', targetId: '', principalId: '', options: '' });
        this.assignPrincipals.set([]);
        this.assignForm.set(false);
        this.loadAssignments();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected onConsumerTargetChange(): void {
    this.consumerPrincipals.set([]);
    const draft = this.consumerDraft();
    if (!draft.targetId) return;

    this.api.listPrincipals(draft.targetId).subscribe({
      next: (r) => {
        this.consumerPrincipals.set(r.items);
        if (!draft.username && r.items.length) {
          this.consumerDraft.update(d => ({ ...d, username: r.items[0].username }));
        }
      },
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

  protected configExample(): string {
    const draft = this.consumerDraft();
    switch (draft.kind) {
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
    const draft = this.consumerDraft();
    switch (draft.kind) {
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
