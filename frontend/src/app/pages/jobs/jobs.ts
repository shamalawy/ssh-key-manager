import { ChangeDetectionStrategy, Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';

import { Api } from '../../core/api';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import type { Job, JobLog } from '../../core/models';

@Component({
  selector: 'skm-jobs',
  imports: [Alerts, DatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .state { font-size: 0.75rem; padding: 0.1rem 0.45rem; border-radius: 999px;
             border: 1px solid var(--border-soft); white-space: nowrap; }
    .state.running { color: var(--accent); border-color: var(--accent-dim); }
    .state.ok { color: var(--ok); border-color: var(--ok); }
    .state.bad { color: var(--danger); border-color: var(--danger); }

    .log { font-family: var(--mono); font-size: 0.8rem; background: var(--bg-sunken);
           border: 1px solid var(--border-soft); border-radius: var(--radius-md);
           padding: 0.6rem 0.8rem; max-height: 22rem; overflow-y: auto; }
    .log .line { display: flex; gap: 0.7rem; padding: 0.1rem 0; }
    .log .at { color: var(--text-dim); flex-shrink: 0; }
    .log .warn { color: var(--warn); }
    .log .error { color: var(--danger); }
    .filters { display: flex; gap: 0.4rem; flex-wrap: wrap; margin-bottom: 0.8rem; }
    .filters button.on { border-color: var(--accent); color: var(--accent); }
  `],
  template: `
    <h1>Jobs</h1>

    <skm-alerts [error]="error" />

    <p class="small faint">
      Every rotation step, deployment, and drift sweep runs as a durable job.
      A job that gave up stays here rather than disappearing — that is exactly
      what you need to see when something stopped working.
    </p>

    <div class="filters">
      @for (f of stateFilters; track f.value) {
        <button class="ghost sm" type="button" [class.on]="filter() === f.value"
                (click)="setFilter(f.value)">{{ f.label }}</button>
      }
    </div>

    <div class="card" style="margin-bottom: 1.4rem;">
      @if (jobs().length) {
        <table>
          <thead>
            <tr><th>State</th><th>Type</th><th>Attempts</th><th>Started</th><th>Detail</th><th></th></tr>
          </thead>
          <tbody>
            @for (j of jobs(); track j.id) {
              <tr (click)="open(j)" style="cursor: pointer;"
                  [style.background]="selected()?.id === j.id ? 'var(--bg-sunken)' : ''">
                <td><span class="state" [class]="stateClass(j.state)">{{ j.state }}</span></td>
                <td><code class="small">{{ j.type }}</code></td>
                <td class="small">{{ j.attempts }}/{{ j.max_attempts }}</td>
                <td class="small faint">{{ j.started_at ? (j.started_at | date: 'short') : '—' }}</td>
                <td class="small faint" style="max-width: 28rem; overflow: hidden; text-overflow: ellipsis;">
                  {{ j.last_error || '' }}
                </td>
                <td style="text-align: right;">
                  @if (j.state === 'queued' || j.state === 'running') {
                    <button class="ghost sm" type="button" (click)="cancel(j, $event)" [disabled]="busyId() !== null">
                      @if (busyId() === j.id) { <span class="spinner"></span> } Cancel
                    </button>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      } @else {
        <div class="empty">No jobs match this filter.</div>
      }
    </div>

    @if (selected(); as j) {
      <div class="card">
        <div class="card-header">
          <h2><code>{{ j.type }}</code></h2>
          <span class="state" [class]="stateClass(j.state)">{{ j.state }}</span>
        </div>
        <div class="card-body">
          @if (j.last_error) { <div class="notice error">{{ j.last_error }}</div> }

          @if (logs().length) {
            <div class="log">
              @for (l of logs(); track l.id) {
                <div class="line">
                  <span class="at">{{ l.logged_at | date: 'HH:mm:ss' }}</span>
                  <span [class]="l.level">{{ l.message }}</span>
                </div>
              }
            </div>
          } @else {
            <div class="empty">This job has written no progress lines.</div>
          }
        </div>
      </div>
    }
  `,
})
export class JobsPage implements OnInit, OnDestroy {
  private readonly api = inject(Api);
  private readonly confirm = inject(Confirm);

  protected readonly jobs = signal<Job[]>([]);
  protected readonly logs = signal<JobLog[]>([]);
  protected readonly selected = signal<Job | null>(null);
  protected readonly filter = signal<string>('');
  protected readonly error = signal<string | null>(null);
  protected readonly busyId = signal<string | null>(null);

  protected readonly stateFilters = [
    { label: 'All', value: '' },
    { label: 'Running', value: 'running' },
    { label: 'Queued', value: 'queued' },
    { label: 'Dead', value: 'dead' },
    { label: 'Succeeded', value: 'succeeded' },
  ];

  private cursor = 0;
  private poller?: ReturnType<typeof setInterval>;

  ngOnInit(): void {
    this.refresh();
    this.poller = setInterval(() => this.refresh(), 3000);
  }

  ngOnDestroy(): void {
    if (this.poller) clearInterval(this.poller);
  }

  protected setFilter(value: string): void {
    this.filter.set(value);
    this.refresh();
  }

  protected refresh(): void {
    const state = this.filter();
    this.api.listJobs(state ? { state: [state] } : {}).subscribe({
      next: (res) => {
        this.jobs.set(res.items);
        // Update the selected job's state from the list
        const current = this.selected();
        if (current) {
          const updated = res.items.find((j) => j.id === current.id);
          if (updated) this.selected.set(updated);
        }
      },
      error: (err: Error) => this.error.set(err.message),
    });

    const current = this.selected();
    if (current) this.pollLogs(current.id);
  }

  protected open(j: Job): void {
    if (this.selected()?.id === j.id) return;

    this.selected.set(j);
    this.logs.set([]);
    this.cursor = 0;
    this.pollLogs(j.id);
  }

  /** Reads forward from the cursor so a long-running job's log is not
   *  re-fetched in full on every poll. */
  private pollLogs(id: string): void {
    this.api.jobLogs(id, this.cursor).subscribe({
      next: (res) => {
        if (res.items.length) {
          this.logs.update((existing) => [...existing, ...res.items]);
        }
        this.cursor = res.cursor;
      },
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected async cancel(j: Job, ev: Event): Promise<void> {
    ev.stopPropagation();
    if (!(await this.confirm.ask({
      title: 'Cancel this job?',
      message: 'A rotation step that is cancelled part-way is retried by the engine, not lost.',
      action: 'Cancel job',
      danger: true,
    }))) return;

    this.busyId.set(j.id);
    this.api.cancelJob(j.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.refresh();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected stateClass(state: string): string {
    if (state === 'succeeded') return 'ok';
    if (state === 'dead' || state === 'failed') return 'bad';
    if (state === 'running') return 'running';
    return '';
  }
}
