import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe, JsonPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import { Auth } from '../../core/auth';
import { Alerts } from '../../shared/alerts';
import type { AuditEvent, ChainVerification } from '../../core/models';

@Component({
  selector: 'skm-audit',
  imports: [Alerts, DatePipe, FormsModule, JsonPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .toolbar { display: flex; gap: 0.6rem; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; }
    .detail { font-family: var(--mono); font-size: 0.76rem; color: var(--text-muted); }
    .hash { font-family: var(--mono); font-size: 0.7rem; color: var(--text-faint); }
    tr.expandable { cursor: pointer; }
  `],
  template: `
    <h1>Audit trail</h1>
    <p class="muted" style="margin-top: -0.4rem;">
      Every entry commits to its predecessor by hash. Altering or removing one
      invalidates every entry after it, and verification detects that.
    </p>

    <skm-alerts [error]="error" />

    @if (chain(); as c) {
      @if (c.valid) {
        <div class="notice ok">
          <strong>Chain intact.</strong> {{ c.checked }} events verified.
        </div>
      } @else {
        <div class="notice error">
          <strong>Chain broken at event {{ c.broken_at_seq }}.</strong> {{ c.reason }}
        </div>
      }
    }

    <div class="toolbar">
      <select [(ngModel)]="outcomeFilter" (ngModelChange)="reload()" style="max-width: 160px;">
        <option value="">All outcomes</option>
        <option value="success">success</option>
        <option value="failure">failure</option>
        <option value="denied">denied</option>
      </select>
      <span class="spacer"></span>
      @if (auth.can('audit.verify')) {
        <button type="button" [disabled]="verifying()" (click)="verify()">
          @if (verifying()) { <span class="spinner"></span> } Verify chain integrity
        </button>
      }
    </div>

    <div class="card">
      @if (loading()) {
        <div class="empty"><span class="spinner"></span> Loading…</div>
      } @else if (events().length === 0) {
        <div class="empty">No audit events match.</div>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>#</th><th>When</th><th>Actor</th><th>Action</th>
                  <th>Resource</th><th>Outcome</th><th>From</th></tr>
            </thead>
            <tbody>
              @for (e of events(); track e.seq) {
                <tr class="expandable" (click)="toggle(e.seq)">
                  <td class="faint small">{{ e.seq }}</td>
                  <td class="small">{{ e.occurred_at | date:'MMM d, HH:mm:ss' }}</td>
                  <td>{{ e.actor_name || e.actor_type }}</td>
                  <td class="mono small">{{ e.action }}</td>
                  <td class="muted truncate" style="max-width: 200px;">{{ e.resource_name || '—' }}</td>
                  <td>
                    <span class="badge" [class.ok]="e.outcome === 'success'"
                          [class.warn]="e.outcome === 'denied'"
                          [class.danger]="e.outcome === 'failure'">{{ e.outcome }}</span>
                  </td>
                  <td class="small faint">{{ e.ip_address || '—' }}</td>
                </tr>
                @if (expanded() === e.seq) {
                  <tr>
                    <td colspan="7" style="background: var(--bg-input);">
                      <div class="detail">{{ e.detail | json }}</div>
                      <div class="hash" style="margin-top: 0.5rem;">
                        hash {{ e.hash }}<br />prev {{ e.prev_hash || '(genesis)' }}
                      </div>
                    </td>
                  </tr>
                }
              }
            </tbody>
          </table>
        </div>
      }
    </div>
  `,
})
export class AuditPage implements OnInit {
  private readonly api = inject(Api);
  protected readonly auth = inject(Auth);

  protected readonly events = signal<AuditEvent[]>([]);
  protected readonly chain = signal<ChainVerification | null>(null);
  protected readonly expanded = signal<number | null>(null);
  protected readonly loading = signal(true);
  protected readonly verifying = signal(false);
  protected readonly error = signal<string | null>(null);

  protected outcomeFilter = '';

  ngOnInit(): void {
    this.reload();
  }

  protected reload(): void {
    this.loading.set(true);
    this.api.listAudit({
      outcome: this.outcomeFilter || undefined,
      limit: 200,
    }).subscribe({
      next: (r) => {
        this.events.set(r.items);
        this.loading.set(false);
      },
      error: (err: Error) => {
        this.error.set(err.message);
        this.loading.set(false);
      },
    });
  }

  protected verify(): void {
    this.verifying.set(true);
    this.api.verifyAudit().subscribe({
      next: (c) => {
        this.chain.set(c);
        this.verifying.set(false);
      },
      error: (err: Error) => {
        this.error.set(err.message);
        this.verifying.set(false);
      },
    });
  }

  protected toggle(seq: number): void {
    this.expanded.set(this.expanded() === seq ? null : seq);
  }
}
