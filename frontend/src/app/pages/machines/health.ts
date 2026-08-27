import { ChangeDetectionStrategy, Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import type { DiscoveredKey, ReconcileResult, Target } from '../../core/models';

@Component({
  selector: 'skm-fleet-health',
  imports: [Alerts, DatePipe, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .fp { font-family: var(--mono); font-size: 0.78rem; }
    .state { font-size: 0.75rem; padding: 0.1rem 0.45rem; border-radius: 999px;
             border: 1px solid var(--border-soft); }
    .state.unmanaged { color: var(--warn); border-color: var(--warn); }
    .state.adopted { color: var(--ok); border-color: var(--ok); }
    .state.ignored { color: var(--text-dim); }
    .filters { display: flex; gap: 0.4rem; flex-wrap: wrap; margin-bottom: 0.8rem; align-items: center; }
    .filters button.on { border-color: var(--accent); color: var(--accent); }
    .report { font-size: 0.85rem; }
    .report li { margin-bottom: 0.2rem; }
  `],
  template: `
    <skm-alerts [error]="error" [notice]="notice" />

    <div class="card" style="margin-bottom: 1.4rem;">
      <div class="card-header">
        <h2>Machines</h2>
        <button type="button" (click)="scan()" [disabled]="busy()">
          @if (busy()) { <span class="spinner"></span> } {{ busy() ? 'Scanning…' : 'Check the fleet' }}
        </button>
      </div>
      @if (targets().length) {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th><th>Address</th><th>Health</th>
                <th>Sync state</th><th>Last checked</th><th>Fix automatically</th><th></th>
              </tr>
            </thead>
            <tbody>
              @for (t of targets(); track t.id) {
                <tr>
                  <td><strong>{{ t.name }}</strong></td>
                  <td class="mono small">{{ t.address }}:{{ t.port }}</td>
                  <td><span class="badge" [class]="healthClass(t)">{{ t.health }}</span></td>
                  <td><span class="badge" [class]="driftClass(t)">{{ syncStateLabel(t.drift_state) }}</span></td>
                  <td class="small faint">{{ t.last_reconciled_at ? (t.last_reconciled_at | date:'MMM d, HH:mm') : '—' }}</td>
                  <td class="small">{{ reconcileLabel(t.reconcile_mode) }}</td>
                  <td>
                    <button class="ghost sm" type="button" [disabled]="busyId() === t.id" (click)="checkMachine(t)">
                      @if (busyId() === t.id) { <span class="spinner"></span> } Check now
                    </button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      } @else {
        <div class="empty">Loading machines…</div>
      }
    </div>

    <div class="card">
      <div class="card-header">
        <h2>Keys SKM did not install</h2>
      </div>

      <div class="filters" style="margin-bottom: 0.8rem;">
        @for (f of stateFilters; track f.value) {
          <button class="ghost sm" type="button" [class.on]="filter() === f.value"
                  (click)="setFilter(f.value)">{{ f.label }}</button>
        }
      </div>

      @if (discovered().length) {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Fingerprint</th><th>Machine</th><th>Login</th>
                <th>First seen</th><th></th>
              </tr>
            </thead>
            <tbody>
              @for (d of discovered(); track d.id) {
                <tr>
                  <td class="fp">{{ short(d.fingerprint_sha256) }}</td>
                  <td class="small">{{ d.target_name }}</td>
                  <td class="mono small">{{ d.username }}</td>
                  <td class="small faint">{{ d.first_seen_at | date: 'short' }}</td>
                  <td style="text-align: right; white-space: nowrap;">
                    @if (d.state === 'unmanaged') {
                      <button class="sm" type="button" (click)="adopt(d)" [disabled]="busyId() !== null">
                        @if (busyId() === d.id) { <span class="spinner"></span> } Adopt
                      </button>
                      <button class="ghost sm" type="button" (click)="ignore(d)" [disabled]="busyId() !== null">
                        @if (busyId() === d.id) { <span class="spinner"></span> } Ignore
                      </button>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      } @else {
        <div class="empty">
          Nothing found. Check the fleet to read the machines' keys back.
        </div>
      }
    </div>
  `,
})
export class FleetHealthPage implements OnInit, OnDestroy {
  private readonly api = inject(Api);
  private readonly confirm = inject(Confirm);

  protected readonly discovered = signal<DiscoveredKey[]>([]);
  protected readonly targets = signal<Target[]>([]);
  protected readonly lastScan = signal<ReconcileResult | null>(null);
  protected readonly filter = signal('unmanaged');
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly busyId = signal<string | null>(null);

  protected scanTargetId = '';

  private fleetScanPoller?: ReturnType<typeof setInterval>;

  protected readonly stateFilters = [
    { label: 'Unmanaged', value: 'unmanaged' },
    { label: 'Adopted', value: 'adopted' },
    { label: 'Ignored', value: 'ignored' },
    { label: 'All', value: '' },
  ];

  ngOnInit(): void {
    this.refresh();
    this.api.listTargets().subscribe({
      next: (res) => this.targets.set(res.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  ngOnDestroy(): void {
    if (this.fleetScanPoller) clearInterval(this.fleetScanPoller);
  }

  protected setFilter(value: string): void {
    this.filter.set(value);
    this.refresh();
  }

  protected refresh(): void {
    const state = this.filter();
    this.api.listDiscovered(state ? { state: [state] } : {}).subscribe({
      next: (res) => this.discovered.set(res.items),
      error: (err: Error) => this.error.set(err.message),
    });
    this.api.listTargets().subscribe({
      next: (res) => this.targets.set(res.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected scan(): void {
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);
    this.lastScan.set(null);

    // A fleet-wide sweep is queued rather than run inline: it is slow enough
    // to time out a request, and the Jobs screen shows its progress.
    this.api.reconcile(this.scanTargetId || undefined, !this.scanTargetId).subscribe({
      next: (res) => {
        if ('principals' in res) {
          this.busy.set(false);
          this.lastScan.set(res);
          this.notice.set('Check finished.');
          this.scanTargetId = '';
          this.refresh();
        } else {
          // Fleet-wide scan returned a Job; poll it
          const jobId = res.id;
          const shortId = jobId.slice(0, 8);
          this.notice.set(`Checking the fleet… (job ${shortId})`);
          this.pollFleetScan(jobId);
        }
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  private pollFleetScan(jobId: string): void {
    if (this.fleetScanPoller) clearInterval(this.fleetScanPoller);

    this.fleetScanPoller = setInterval(() => {
      this.api.getJob(jobId).subscribe({
        next: (job) => {
          if (job.state === 'succeeded' || job.state === 'failed' || job.state === 'dead' || job.state === 'cancelled') {
            clearInterval(this.fleetScanPoller);
            this.fleetScanPoller = undefined;
            this.busy.set(false);

            if (job.state === 'succeeded') {
              this.notice.set('Check finished.');
            } else {
              this.error.set(`Check ${job.state}.`);
            }
            this.refresh();
          }
        },
        error: (err: Error) => {
          clearInterval(this.fleetScanPoller);
          this.fleetScanPoller = undefined;
          this.busy.set(false);
          this.error.set(err.message);
        },
      });
    }, 2000);
  }

  protected adopt(d: DiscoveredKey): void {
    this.confirm.prompt({
      title: 'Adopt this key',
      label: 'Name',
      initial: `adopted-${this.short(d.fingerprint_sha256)}`,
      action: 'Adopt',
    }).then((name) => {
      if (name === null) return;

      this.busyId.set(d.id);
      this.api.adoptKey(d.id, name || undefined).subscribe({
        next: (key) => {
          this.busyId.set(null);
          this.notice.set(
            `Adopted as "${key.name}". SKM does not hold its private half, so it can be ` +
            `tracked and removed but not rotated.`);
          this.refresh();
        },
        error: (err: Error) => {
          this.busyId.set(null);
          this.error.set(err.message);
        },
      });
    });
  }

  protected ignore(d: DiscoveredKey): void {
    this.busyId.set(d.id);
    this.api.ignoreDiscovered(d.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.notice.set('Marked as known.');
        this.refresh();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected short(fingerprint: string): string {
    return fingerprint.replace(/^SHA256:/, '').slice(0, 16);
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

  protected syncStateLabel(state: string): string {
    switch (state) {
      case 'in_sync': return 'in sync';
      case 'drifted': return 'out of sync';
      case 'error': return 'error';
      default: return 'unknown';
    }
  }

  protected reconcileLabel(mode: string): string {
    switch (mode) {
      case 'report_only': return 'Report only';
      case 'auto_heal': return 'Fix automatically';
      case 'disabled': return 'Disabled';
      default: return mode;
    }
  }

  protected checkMachine(t: Target): void {
    this.busyId.set(t.id);
    this.api.reconcile(t.id).subscribe({
      next: (res) => {
        this.busyId.set(null);
        if ('principals' in res) {
          this.notice.set('Check finished.');
          this.refresh();
        } else {
          this.notice.set('Check queued.');
        }
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }
}
