import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';

import { Api, mfaRequired } from '../../core/api';
import { Auth } from '../../core/auth';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import { StepUp } from '../../shared/stepup';
import type { SystemStatus, VaultStatus } from '../../core/models';

@Component({
  selector: 'skm-vault-settings',
  imports: [Alerts, StepUp],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p class="muted" style="margin-bottom: 1.2rem;">Manage encryption and system status.</p>

    <skm-alerts [error]="error" [notice]="notice" />

    <div class="card">
      <div class="card-header"><h2>Vault</h2></div>

      @if (vault(); as v) {
        <div class="row" style="margin-bottom: 0.8rem;">
          <span class="badge" [class.ok]="!v.sealed" [class.danger]="v.sealed">
            {{ v.sealed ? 'sealed' : 'unsealed' }}
          </span>
          <span class="muted small">
            key-encryption key version {{ v.current_version }}
            @if (v.known_versions.length > 1) {
              (also holds {{ v.known_versions.join(', ') }})
            }
          </span>
        </div>

        @if (needsStepUp()) {
          <skm-stepup message="Rotating the key-encryption key needs a second-factor code verified in the last few minutes."
                      (verified)="needsStepUp.set(false); runPending()"
                      (cancelled)="needsStepUp.set(false); pending = null" />
        }

        @if (auth.can('vault.rotate_kek')) {
          <p class="muted small">
            Rotating the key-encryption key rewraps every stored key without
            re-encrypting the key material itself. It is safe to re-run.
          </p>
          <button type="button" [disabled]="busy() || v.sealed" (click)="rotateKek()">
            @if (busy()) { <span class="spinner"></span> } Rotate the key-encryption key
          </button>
        }
      } @else {
        <div class="empty"><span class="spinner"></span> Loading…</div>
      }
    </div>

    <div class="card" style="margin-bottom: 1.4rem;">
      <div class="card-header"><h2>System status</h2></div>
      <div class="card-body">
        @if (status(); as st) {
          <div class="grid cols-3">
            <div>
              <span class="label small faint">Scheduled work</span>
              <div>{{ st.scheduler_enabled ? 'enabled' : 'disabled' }}</div>
            </div>
            <div>
              <span class="label small faint">This instance</span>
              <div>{{ st.is_leader ? 'holds the scheduler lock' : 'standby' }}</div>
            </div>
            <div>
              <span class="label small faint">Connectors</span>
              <div class="small">{{ st.connectors.join(', ') }}</div>
            </div>
          </div>
          <p class="small faint" style="margin-top: 0.7rem;">
            Only one instance runs scheduled work, chosen by a PostgreSQL advisory
            lock. Scaling out multiplies throughput without running every schedule twice.
          </p>
        } @else {
          <div class="empty"><span class="spinner"></span> Loading…</div>
        }
      </div>
    </div>
  `,
})
export class VaultSettings implements OnInit {
  private readonly api = inject(Api);
  private readonly confirmDialog = inject(Confirm);
  protected readonly auth = inject(Auth);

  protected readonly vault = signal<VaultStatus | null>(null);
  protected readonly status = signal<SystemStatus | null>(null);

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);

  protected readonly needsStepUp = signal(false);
  protected pending: (() => void) | null = null;

  ngOnInit(): void {
    this.loadVault();
    this.api.status().subscribe({ next: (st) => this.status.set(st) });
  }

  protected runPending(): void {
    if (this.pending) {
      this.pending();
      this.pending = null;
    }
  }

  private loadVault(): void {
    this.api.vaultStatus().subscribe({
      next: (v) => this.vault.set(v),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected async rotateKek(): Promise<void> {
    if (!(await this.confirmDialog.ask({
      title: 'Rotate the key-encryption key?',
      message: 'Rewrap every stored key under the current key-encryption key.',
      action: 'Rotate',
    }))) return;

    this.pending = () => this.doRotateKek();
    this.doRotateKek();
  }

  private doRotateKek(): void {
    this.busy.set(true);
    this.api.rotateKek().subscribe({
      next: (r) => {
        this.busy.set(false);
        this.notice.set(`Rewrapped ${r.keys_rewrapped} key(s) under version ${r.kek_version}.`);
        this.loadVault();
      },
      error: (err: Error) => {
        this.busy.set(false);
        if (mfaRequired(err)) {
          this.pending = () => this.doRotateKek();
          this.needsStepUp.set(true);
          return;
        }
        this.error.set(err.message);
      },
    });
  }
}
