import { ChangeDetectionStrategy, Component, OnDestroy, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import { Live } from '../../core/live';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import type { ManagedKey, Rotation, RotationPolicy, RotationTarget } from '../../core/models';

/** States in which a rotation is still doing something. */
const IN_FLIGHT = new Set([
  'planned', 'awaiting_approval', 'staging', 'staged',
  'verifying', 'verified', 'promoting', 'soaking', 'retiring',
]);

@Component({
  selector: 'skm-rotation',
  imports: [Alerts, DatePipe, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .state { font-size: 0.75rem; padding: 0.1rem 0.45rem; border-radius: 999px;
             border: 1px solid var(--border-soft); white-space: nowrap; }
    .state.running { color: var(--accent); border-color: var(--accent-dim); }
    .state.done { color: var(--ok); border-color: var(--ok); }
    .state.bad { color: var(--danger); border-color: var(--danger); }
    .state.wait { color: var(--warn); border-color: var(--warn); }

    .progress { display: flex; gap: 2px; margin-top: 0.35rem; }
    .progress i { height: 4px; flex: 1; background: var(--border-soft); border-radius: 2px; }
    .progress i.on { background: var(--accent); }
    .progress i.fail { background: var(--danger); }

    .machine { display: flex; flex-wrap: wrap; gap: 0.35rem; margin: 0.6rem 0 1rem; }
    .machine span { font-size: 0.72rem; padding: 0.15rem 0.5rem; border-radius: 999px;
                    border: 1px solid var(--border-soft); color: var(--text-muted); }
    .machine span.at { border-color: var(--accent); color: var(--accent); font-weight: 600; }
    .machine span.past { color: var(--text-dim); }

    .wave-tag { font-variant-numeric: tabular-nums; color: var(--text-muted); font-size: 0.78rem; }
    .warn-list li { margin-bottom: 0.25rem; }
  `],
  template: `
    <h1>Rotation</h1>

    <skm-alerts [error]="error" [notice]="notice" />

    <div class="tabs" style="margin-bottom: 1.4rem;">
      <button [class.on]="tab() === 'rotations'" (click)="tab.set('rotations')">Rotations</button>
      <button [class.on]="tab() === 'schedules'" (click)="tab.set('schedules')">Schedules</button>
    </div>

    @if (tab() === 'rotations') {
      <div class="card" style="margin-bottom: 1.4rem;">
        <div class="card-header"><h2>Rotate a key</h2></div>
        <div class="card-body">
          <p class="small faint">
            Replace a key everywhere it is installed, safely: the new key goes on
            first, is proved to work, and only then is the old one removed.
          </p>

        <div class="grid cols-3">
          <label>
            Key
            <select [(ngModel)]="selectedKeyId">
              <option value="">Choose a key…</option>
              @for (k of rotatableKeys(); track k.id) {
                <option [value]="k.id">{{ k.name }} · gen {{ k.generation }} · {{ k.algorithm }}</option>
              }
            </select>
          </label>
          <label>
            Soak window (hours)
            <input type="number" min="0" [(ngModel)]="soakHours" />
          </label>
          <label>
            Canary (% of machines first)
            <input type="number" min="0" max="100" [(ngModel)]="canaryPercent" />
          </label>
          <label>
            Failure tolerance (%)
            <input type="number" min="0" max="100" [(ngModel)]="failureThreshold" />
          </label>
          <label class="checkbox">
            <input type="checkbox" [(ngModel)]="approvalRequired" />
            Hold for approval before staging
          </label>
          <label class="checkbox">
            <input type="checkbox" [(ngModel)]="dryRun" />
            Dry run (plan only, change nothing)
          </label>
        </div>

        <div class="actions">
          <button type="button" (click)="plan()" [disabled]="!selectedKeyId || busy()">
            @if (busy()) { <span class="spinner"></span> }
            {{ dryRun ? 'Plan a dry run' : (approvalRequired ? 'Plan and hold for approval' : 'Plan and start') }}
          </button>
        </div>

        @if (planWarnings().length) {
          <div class="notice warn">
            <strong>Before you proceed:</strong>
            <ul class="warn-list">
              @for (w of planWarnings(); track w) { <li>{{ w }}</li> }
            </ul>
          </div>
        }
      </div>
    </div>

    <div class="card" style="margin-bottom: 1.4rem;">
      <div class="card-header">
        <h2>Rotations</h2>
        <div class="small faint">
          @if (live.connected()) { <span class="dot on"></span> live } @else { <span class="dot"></span> reconnecting… }
        </div>
      </div>

      @if (rotations().length) {
        <table>
          <thead>
            <tr>
              <th>State</th><th>Key</th><th>Trigger</th>
              <th>Progress</th><th>Started</th><th></th>
            </tr>
          </thead>
          <tbody>
            @for (r of rotations(); track r.id) {
              <tr (click)="select(r)" style="cursor: pointer;">
                <td><span class="state" [class]="stateClass(r.state)">{{ r.state }}</span></td>
                <td>
                  {{ keyName(r.old_key_id) }}
                  @if (r.dry_run) { <span class="small faint"> · dry run</span> }
                </td>
                <td class="small">{{ r.trigger }}</td>
                <td>
                  <span class="wave-tag">
                    {{ r.targets_retired }}/{{ r.targets_total }} retired
                    @if (r.targets_failed) { <span style="color: var(--danger);"> · {{ r.targets_failed }} failed</span> }
                  </span>
                  <div class="progress">
                    @for (i of bar(r); track $index) { <i [class]="i"></i> }
                  </div>
                </td>
                <td class="small faint">{{ r.created_at | date: 'short' }}</td>
                <td style="text-align: right;">
                  @if (r.state === 'planned') {
                    <button class="sm" type="button" (click)="start(r, $event)"
                            [disabled]="busyId() !== null"
                            title="Begin adding the new key to every machine">
                      @if (busyId() === r.id) { <span class="spinner"></span> } Start
                    </button>
                  }
                  @if (r.state === 'awaiting_approval') {
                    <button class="sm" type="button" (click)="approve(r, $event)" [disabled]="busyId() !== null">
                      @if (busyId() === r.id) { <span class="spinner"></span> } Approve
                    </button>
                  }
                  @if (inFlight(r)) {
                    <button class="ghost sm" type="button" (click)="abort(r, $event)" [disabled]="busyId() !== null">
                      @if (busyId() === r.id) { <span class="spinner"></span> } Abort
                    </button>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      } @else {
        <div class="empty">No rotations yet.</div>
      }
    </div>

    @if (selected(); as r) {
      <div class="card" style="margin-bottom: 1.4rem;">
        <div class="card-header">
          <h2>{{ keyName(r.old_key_id) }} → generation {{ (keyById(r.new_key_id)?.generation) ?? '…' }}</h2>
          <span class="state" [class]="stateClass(r.state)">{{ r.state }}</span>
        </div>
        <div class="card-body">
          <div class="machine">
            @for (step of machine; track step) {
              <span [class.at]="step === r.state" [class.past]="isPast(step, r.state)">{{ step }}</span>
            }
          </div>

          @if (r.error) { <div class="notice warn">{{ r.error }}</div> }
          @if (r.soak_until && r.state === 'soaking') {
            <p class="small">
              Both keys remain valid until <strong>{{ r.soak_until | date: 'medium' }}</strong>.
            </p>
          }

          @if (targets().length) {
            <table>
              <thead><tr><th>Wave</th><th>Machine</th><th>Login</th><th>State</th><th>Detail</th></tr></thead>
              <tbody>
                @for (t of targets(); track t.target_id + t.principal_id) {
                  <tr>
                    <td class="wave-tag">{{ t.wave }}</td>
                    <td>{{ t.target_name }}</td>
                    <td class="small">{{ t.username }}</td>
                    <td><span class="state" [class]="targetClass(t.state)">{{ t.state }}</span></td>
                    <td class="small faint">{{ t.error || (t.retired_at ? 'old key removed' : t.verified_at ? 'new key authenticated' : '') }}</td>
                  </tr>
                }
              </tbody>
            </table>
          }
        </div>
      </div>
    }
    }

    @if (tab() === 'schedules') {
    <div class="card">
      <div class="card-header"><h2>Schedules</h2></div>
      <div class="card-body">
        <p class="small faint">
          A schedule rotates every key carrying the given tags once it reaches the
          maximum age, on the schedule below. Age is checked as well as the
          schedule, so a daily cron does not rotate everything daily.
        </p>

        <div class="grid cols-3">
          <label>Name <input [(ngModel)]="policyName" placeholder="production-quarterly" /></label>
          <label>
            Schedule (cron)
            <input [(ngModel)]="policyCron" (blur)="previewCron()" placeholder="0 3 * * 0" />
          </label>
          <label>Maximum key age (days) <input type="number" min="0" [(ngModel)]="policyMaxAgeDays" /></label>
          <label>Key tags (comma separated) <input [(ngModel)]="policyTags" placeholder="production" /></label>
          <label>Soak window (hours) <input type="number" min="0" [(ngModel)]="policySoak" /></label>
          <label>Canary (%) <input type="number" min="0" max="100" [(ngModel)]="policyCanary" /></label>
          <label class="checkbox">
            <input type="checkbox" [(ngModel)]="policyApproval" /> Require approval
          </label>
          <label class="checkbox">
            <input type="checkbox" [(ngModel)]="policyEnabled" /> Enabled
          </label>
        </div>

        @if (cronPreview().length) {
          <p class="small">Next runs: {{ cronPreview().join(' · ') }}</p>
        }
        @if (cronError(); as ce) { <div class="notice error">{{ ce }}</div> }

        <div class="actions">
          <button type="button" (click)="createPolicy()" [disabled]="!policyName || busy()">Create schedule</button>
        </div>

        @if (policies().length) {
          <table>
            <thead><tr><th>Name</th><th>Schedule</th><th>Selector</th><th>Settings</th><th>Next run</th><th></th></tr></thead>
            <tbody>
              @for (p of policies(); track p.id) {
                <tr>
                  <td>
                    {{ p.name }}
                    @if (!p.enabled) { <span class="small faint"> · disabled</span> }
                  </td>
                  <td class="small"><code>{{ p.cron_expr || 'age only' }}</code></td>
                  <td class="small faint">
                    {{ p.selector.key_tags?.join(', ') || 'any tag' }}
                    @if (p.max_age_seconds) { · older than {{ days(p.max_age_seconds) }}d }
                  </td>
                  <td class="small faint">
                    soak {{ hours(p.soak_period_seconds) }}h · canary {{ p.canary_percent }}%
                    @if (p.failure_threshold) { · tolerate {{ p.failure_threshold }}% }
                    @if (p.approval_required) { · needs approval }
                  </td>
                  <td class="small faint">{{ p.next_run_at ? (p.next_run_at | date: 'short') : '—' }}</td>
                  <td style="text-align: right;">
                    <button class="ghost sm" type="button" (click)="removePolicy(p)" [disabled]="policyBusyId() !== null">
                      @if (policyBusyId() === p.id) { <span class="spinner"></span> } Delete
                    </button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        } @else {
          <div class="empty">No schedules. Rotations run on demand until one is created.</div>
        }
      </div>
    </div>
    }
  `,
})
export class RotationPage implements OnInit, OnDestroy {
  private readonly api = inject(Api);
  protected readonly live = inject(Live);
  private readonly confirm = inject(Confirm);

  protected readonly tab = signal<'rotations' | 'schedules'>('rotations');
  protected readonly rotations = signal<Rotation[]>([]);
  protected readonly policies = signal<RotationPolicy[]>([]);
  protected readonly keys = signal<ManagedKey[]>([]);
  protected readonly targets = signal<RotationTarget[]>([]);
  protected readonly selected = signal<Rotation | null>(null);
  protected readonly planWarnings = signal<string[]>([]);
  protected readonly cronPreview = signal<string[]>([]);
  protected readonly cronError = signal('');
  protected readonly error = signal('');
  protected readonly notice = signal('');
  protected readonly busy = signal(false);
  protected readonly busyId = signal<string | null>(null);
  protected readonly policyBusyId = signal<string | null>(null);

  protected selectedKeyId = '';
  protected soakHours = 24;
  protected canaryPercent = 10;
  protected failureThreshold = 10;
  protected approvalRequired = false;
  protected dryRun = false;

  protected policyName = '';
  protected policyCron = '0 3 * * 0';
  protected policyMaxAgeDays = 90;
  protected policyTags = '';
  protected policySoak = 24;
  protected policyCanary = 10;
  protected policyApproval = false;
  protected policyEnabled = true;

  protected readonly machine = [
    'planned', 'staging', 'verifying', 'verified',
    'promoting', 'soaking', 'retiring', 'completed',
  ];

  /** Keys SKM can actually rotate: it must hold the private half, and
   *  break-glass keys are excluded by design. */
  protected readonly rotatableKeys = computed(() =>
    this.keys().filter((k) =>
      k.has_private_key &&
      k.key_class !== 'break_glass' &&
      !['retired', 'destroyed', 'revoked'].includes(k.status)));

  private detach?: () => void;
  private poller?: ReturnType<typeof setInterval>;

  ngOnInit(): void {
    this.detach = this.live.attach();
    this.refresh();

    // The stream tells us something changed; the poll is the safety net for a
    // dropped connection, which is why it is slow rather than absent.
    this.poller = setInterval(() => this.refresh(), 5000);
  }

  ngOnDestroy(): void {
    this.detach?.();
    if (this.poller) clearInterval(this.poller);
  }

  protected refresh(): void {
    this.api.listRotations().subscribe({
      next: (res) => {
        this.rotations.set(res.items);
        const current = this.selected();
        if (current) {
          const updated = res.items.find((r) => r.id === current.id);
          if (updated) this.selected.set(updated);
        }
      },
      error: (err: Error) => this.error.set(err.message),
    });
    this.api.listKeys().subscribe({ next: (res) => this.keys.set(res.items) });
    this.api.listPolicies().subscribe({ next: (res) => this.policies.set(res.items) });

    const current = this.selected();
    if (current) this.loadTargets(current.id);
  }

  protected select(r: Rotation): void {
    this.selected.set(r);
    this.loadTargets(r.id);
  }

  private loadTargets(id: string): void {
    this.api.getRotation(id).subscribe({
      next: (res) => {
        this.targets.set(res.targets);
        this.selected.set(res.rotation);
      },
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected plan(): void {
    this.busy.set(true);
    this.error.set('');
    this.notice.set('');
    this.planWarnings.set([]);

    this.api.planRotation({
      key_id: this.selectedKeyId,
      soak_hours: this.soakHours,
      canary_percent: this.canaryPercent,
      failure_threshold: this.failureThreshold,
      approval_required: this.approvalRequired,
      dry_run: this.dryRun,
      start: !this.approvalRequired,
    }).subscribe({
      next: (plan) => {
        this.busy.set(false);
        this.planWarnings.set(plan.warnings ?? []);
        this.notice.set(
          this.approvalRequired
            ? `Planned across ${plan.targets.length} machine(s); waiting for approval.`
            : `Rotating across ${plan.targets.length} machine(s).`);
        this.selected.set(plan.rotation);
        this.targets.set(plan.targets);
        this.selectedKeyId = '';
        this.soakHours = 24;
        this.canaryPercent = 10;
        this.failureThreshold = 10;
        this.approvalRequired = false;
        this.dryRun = false;
        this.refresh();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  /**
   * start runs a rotation that was planned but never begun.
   *
   * Planning and starting are separate so a plan can be read before it moves:
   * "plan and start" covers the common case, and this covers the plan you
   * looked at yesterday and decided to go ahead with today.
   */
  protected async start(r: Rotation, ev: Event): Promise<void> {
    ev.stopPropagation();
    if (!(await this.confirm.ask({
      title: 'Start this rotation?',
      message: 'The new key is added alongside the old one on every machine and each is tested by logging in with it. Nothing is removed until the new key has proved it works.',
      action: 'Start',
    }))) {
      return;
    }

    this.busyId.set(r.id);
    this.error.set('');
    this.api.startRotation(r.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.notice.set('Rotation started. Watch the progress bar, or the Jobs page for detail.');
        this.refresh();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected approve(r: Rotation, ev: Event): void {
    ev.stopPropagation();
    this.busyId.set(r.id);
    this.error.set('');
    this.api.approveRotation(r.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.notice.set('Approved; the rotation is now running.');
        this.refresh();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected async abort(r: Rotation, ev: Event): Promise<void> {
    ev.stopPropagation();
    const reason = await this.confirm.prompt({
      title: 'Abort this rotation',
      label: 'Reason (recorded on the audit trail)',
      action: 'Abort',
      danger: true,
    });
    if (!reason) return;

    this.busyId.set(r.id);
    this.error.set('');
    this.api.abortRotation(r.id, reason).subscribe({
      next: () => {
        this.busyId.set(null);
        this.notice.set('Aborted. Nothing already installed was removed — both keys remain in place.');
        this.refresh();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected previewCron(): void {
    this.cronError.set('');
    this.cronPreview.set([]);
    if (!this.policyCron) return;

    this.api.previewSchedule(this.policyCron).subscribe({
      next: (res) => this.cronPreview.set(
        res.next_runs.slice(0, 3).map((t) => new Date(t).toLocaleString())),
      error: (err: Error) => this.cronError.set(err.message),
    });
  }

  protected createPolicy(): void {
    this.busy.set(true);
    this.error.set('');

    this.api.createPolicy({
      name: this.policyName,
      enabled: this.policyEnabled,
      cron_expr: this.policyCron,
      max_age_days: this.policyMaxAgeDays,
      soak_hours: this.policySoak,
      canary_percent: this.policyCanary,
      approval_required: this.policyApproval,
      key_tags: this.policyTags.split(',').map((t) => t.trim()).filter(Boolean),
    }).subscribe({
      next: () => {
        this.busy.set(false);
        this.notice.set(`Schedule "${this.policyName}" created.`);
        this.policyName = '';
        this.policyCron = '0 3 * * 0';
        this.policyMaxAgeDays = 90;
        this.policyTags = '';
        this.policySoak = 24;
        this.policyCanary = 10;
        this.policyApproval = false;
        this.policyEnabled = true;
        this.cronPreview.set([]);
        this.cronError.set('');
        this.refresh();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected async removePolicy(p: RotationPolicy): Promise<void> {
    if (!(await this.confirm.ask({
      title: `Delete the schedule "${p.name}"?`,
      message: 'Rotations it already produced are kept.',
      action: 'Delete',
      danger: true,
    }))) return;

    this.policyBusyId.set(p.id);
    this.error.set('');
    this.api.deletePolicy(p.id).subscribe({
      next: () => {
        this.policyBusyId.set(null);
        this.notice.set(`Schedule "${p.name}" deleted.`);
        this.refresh();
      },
      error: (err: Error) => {
        this.policyBusyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected keyById(id?: string): ManagedKey | undefined {
    return id ? this.keys().find((k) => k.id === id) : undefined;
  }

  protected keyName(id?: string): string {
    return this.keyById(id)?.name ?? '—';
  }

  protected inFlight(r: Rotation): boolean {
    return IN_FLIGHT.has(r.state);
  }

  protected isPast(step: string, state: string): boolean {
    return this.machine.indexOf(step) < this.machine.indexOf(state);
  }

  protected stateClass(state: string): string {
    if (state === 'completed') return 'done';
    if (['aborted', 'failed', 'rolled_back'].includes(state)) return 'bad';
    if (state === 'awaiting_approval') return 'wait';
    return 'running';
  }

  protected targetClass(state: string): string {
    if (state === 'retired' || state === 'verified') return 'done';
    if (state === 'failed') return 'bad';
    if (state === 'pending') return '';
    return 'running';
  }

  /** bar renders per-target progress as one segment per target. */
  protected bar(r: Rotation): string[] {
    const out: string[] = [];
    for (let i = 0; i < r.targets_total; i++) {
      if (i < r.targets_failed) out.push('fail');
      else if (i < r.targets_failed + r.targets_verified) out.push('on');
      else out.push('');
    }
    return out;
  }

  protected hours(seconds: number): number {

    return Math.round(seconds / 3600);

  }


  protected days(seconds: number): number {
    return Math.round(seconds / 86400);
  }
}
