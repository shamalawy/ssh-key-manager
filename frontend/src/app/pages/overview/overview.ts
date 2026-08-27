import { ChangeDetectionStrategy, Component, inject, signal, OnInit } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';

import { Api } from '../../core/api';
import { Alerts } from '../../shared/alerts';
import type { AuditEvent, Dashboard as Stats, VaultStatus } from '../../core/models';

@Component({
  selector: 'skm-overview',
  imports: [RouterLink, DatePipe, Alerts],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .stat {
      display: block;
      text-decoration: none;
      color: inherit;
      background: var(--bg-raised);
      border: 1px solid var(--border-soft);
      border-radius: var(--radius-lg);
      padding: 1rem 1.1rem;
      transition: border-color 0.12s;
    }
    .stat:hover { border-color: var(--accent-dim); text-decoration: none; }
    .stat .value { font-size: 1.9rem; font-weight: 650; line-height: 1.1; font-variant-numeric: tabular-nums; }
    .stat .label { font-size: 0.8rem; color: var(--text-muted); margin-top: 0.15rem; }
    .stat.attention .value { color: var(--warn); }
    .stat.bad .value { color: var(--danger); }
    .feed td { font-size: 0.87rem; }
  `],
  template: `
    <h1>Overview</h1>

    <skm-alerts [error]="error" />

    @if (vault(); as v) {
      @if (v.sealed) {
        <div class="notice error">
          <strong>The vault is sealed.</strong>
          Key operations are refused until it is unsealed. Set
          <code>SKM_MASTER_KEY</code> and restart the server.
        </div>
      }
    }

    @if (stats(); as s) {
      <div class="grid cols-3" style="margin-bottom: 1.4rem;">
        <a class="stat" routerLink="/keys">
          <div class="value">{{ s.active_keys }}</div>
          <div class="label">Active keys</div>
        </a>
        <a class="stat" routerLink="/machines">
          <div class="value">{{ s.targets }}</div>
          <div class="label">Machines</div>
        </a>
        <a class="stat" [class.attention]="s.expiring_soon > 0" routerLink="/keys">
          <div class="value">{{ s.expiring_soon }}</div>
          <div class="label">Expiring within 30 days</div>
        </a>
        <a class="stat" [class.attention]="s.drifted_assignments > 0" routerLink="/install">
          <div class="value">{{ s.drifted_assignments }}</div>
          <div class="label">Installs out of sync</div>
        </a>
        <a class="stat" [class.bad]="s.unreachable_targets > 0" routerLink="/machines">
          <div class="value">{{ s.unreachable_targets }}</div>
          <div class="label">Unreachable machines</div>
        </a>
        <a class="stat" [class.attention]="s.non_compliant_keys > 0" routerLink="/keys">
          <div class="value">{{ s.non_compliant_keys }}</div>
          <div class="label">Non-compliant keys</div>
        </a>

        @if (s.active_rotations !== undefined) {
          <a class="stat" [class.attention]="(s.rotations_awaiting_approval ?? 0) > 0" routerLink="/rotation">
            <div class="value">{{ s.active_rotations }}</div>
            <div class="label">
              Rotations in flight
              @if (s.rotations_awaiting_approval) { · {{ s.rotations_awaiting_approval }} awaiting approval }
            </div>
          </a>
        }
        @if (s.unmanaged_keys !== undefined) {
          <a class="stat" [class.attention]="s.unmanaged_keys > 0" routerLink="/machines/health">
            <div class="value">{{ s.unmanaged_keys }}</div>
            <div class="label">Keys SKM did not install</div>
          </a>
        }
        @if (s.jobs_dead !== undefined) {
          <a class="stat" [class.bad]="s.jobs_dead > 0" routerLink="/settings/jobs">
            <div class="value">{{ s.jobs_dead }}</div>
            <div class="label">
              Jobs that gave up
              @if (s.jobs_running) { · {{ s.jobs_running }} running }
            </div>
          </a>
        }
      </div>

      @if (s.scheduler_leader === false) {
        <div class="notice">
          Scheduled work is running on another instance. This one serves requests
          and processes jobs, but does not fire rotation policies.
        </div>
      }
      @if (!s.last_backup_at) {
        <div class="notice warn">
          <strong>No vault backup has been taken.</strong>
          A lost master key with no archive means every private key is
          unrecoverable. <a routerLink="/settings/backups">Create one</a>.
        </div>
      }
    } @else if (!error()) {
      <div class="empty"><span class="spinner"></span> Loading…</div>
    }

    <div class="card feed">
      <div class="card-header">
        <h2>Recent activity</h2>
        <a routerLink="/settings/audit" class="small">View the full trail →</a>
      </div>

      @if (recent().length === 0) {
        <div class="empty">Nothing has happened yet.</div>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>When</th><th>Actor</th><th>Action</th><th>Resource</th><th>Outcome</th></tr>
            </thead>
            <tbody>
              @for (e of recent(); track e.seq) {
                <tr>
                  <td class="faint small">{{ e.occurred_at | date:'MMM d, HH:mm:ss' }}</td>
                  <td>{{ e.actor_name }}</td>
                  <td class="mono">{{ e.action }}</td>
                  <td class="muted truncate">{{ e.resource_name || '—' }}</td>
                  <td>
                    <span class="badge" [class.ok]="e.outcome === 'success'"
                          [class.danger]="e.outcome !== 'success'">{{ e.outcome }}</span>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </div>
  `,
})
export class OverviewPage implements OnInit {
  private readonly api = inject(Api);

  protected readonly stats = signal<Stats | null>(null);
  protected readonly vault = signal<VaultStatus | null>(null);
  protected readonly recent = signal<AuditEvent[]>([]);
  protected readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.api.dashboard().subscribe({
      next: (s) => this.stats.set(s),
      error: (err: Error) => this.error.set(err.message),
    });
    // A sealed vault or a missing permission should not blank the page, so
    // these are best-effort.
    this.api.vaultStatus().subscribe({ next: (v) => this.vault.set(v), error: (err: Error) => this.error.set(err.message) });
    this.api.listAudit({ limit: 12 }).subscribe({
      next: (r) => this.recent.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }
}
