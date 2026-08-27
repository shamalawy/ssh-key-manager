import { ChangeDetectionStrategy, Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import type { DiscoveredKey, ReconcileResult, Target } from '../../core/models';

@Component({
  selector: 'skm-inventory',
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
    <h1>Key inventory</h1>

    <skm-alerts [error]="error" [notice]="notice" />

    <p class="small faint">
      Every key found on a managed target that SKM did not put there. For an
      estate that has never had key management, this is usually the first
      genuinely useful thing to look at: it answers who can already log in.
      Adopt a key to track it, or ignore one you have accounted for.
    </p>

    <div class="filters">
      @for (f of stateFilters; track f.value) {
        <button class="ghost sm" type="button" [class.on]="filter() === f.value"
                (click)="setFilter(f.value)">{{ f.label }}</button>
      }

      <span style="flex: 1;"></span>

      <select [(ngModel)]="scanTargetId" style="max-width: 16rem;" [disabled]="busy()">
        <option value="">The whole fleet</option>
        @for (t of targets(); track t.id) { <option [value]="t.id">{{ t.name }}</option> }
      </select>
      <button type="button" (click)="scan()" [disabled]="busy()">
        @if (busy()) { <span class="spinner"></span> } {{ busy() ? 'Scanning…' : 'Scan for drift' }}
      </button>
    </div>

    @if (lastScan(); as scan) {
      <div class="card" style="margin-bottom: 1.4rem;">
        <div class="card-header">
          <h2>{{ scan.target_name }}</h2>
          <span class="small faint">checked {{ scan.checked_at | date: 'short' }}</span>
        </div>
        <div class="card-body report">
          @for (p of scan.principals; track p.principal_id) {
            <div style="margin-bottom: 0.6rem;">
              <strong>{{ p.username }}</strong>
              @if (p.error) { <span style="color: var(--danger);"> — {{ p.error }}</span> }
              @else if (!p.missing?.length && !p.unexpected?.length && !p.unmanaged?.length) {
                <span class="small faint"> — in sync</span>
              }
              <ul>
                @if (p.missing?.length) { <li>{{ p.missing?.length }} assigned key(s) not present on the host</li> }
                @if (p.unexpected?.length) { <li>{{ p.unexpected?.length }} managed key(s) present that should not be</li> }
                @if (p.unmanaged?.length) { <li>{{ p.unmanaged?.length }} key(s) SKM did not deploy</li> }
                @if (p.healed) { <li style="color: var(--ok);">auto-healed</li> }
              </ul>
            </div>
          }
        </div>
      </div>
    }

    <div class="card">
      @if (discovered().length) {
        <table>
          <thead>
            <tr>
              <th>State</th><th>Fingerprint</th><th>Comment</th>
              <th>Where</th><th>Last seen</th><th></th>
            </tr>
          </thead>
          <tbody>
            @for (d of discovered(); track d.id) {
              <tr>
                <td><span class="state" [class]="d.state">{{ d.state }}</span></td>
                <td class="fp">{{ short(d.fingerprint_sha256) }}</td>
                <td class="small">{{ d.comment || '—' }}</td>
                <td class="small faint">{{ d.target_name }} · {{ d.username }}</td>
                <td class="small faint">{{ d.last_seen_at | date: 'short' }}</td>
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
      } @else {
        <div class="empty">
          Nothing found. Run a scan to read the fleet's actual keys back.
        </div>
      }
    </div>
  `,
})
export class InventoryPage implements OnInit, OnDestroy {
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
          this.notice.set('Scan finished.');
          this.scanTargetId = '';
          this.refresh();
        } else {
          // Fleet-wide scan returned a Job; poll it
          const jobId = res.id;
          const shortId = jobId.slice(0, 8);
          this.notice.set(`Scanning the fleet… (job ${shortId})`);
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
              this.notice.set('Scan finished.');
            } else {
              this.error.set(`Scan ${job.state}.`);
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
}
