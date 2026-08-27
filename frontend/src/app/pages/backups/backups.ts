import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { Api, mfaRequired } from '../../core/api';
import { Auth } from '../../core/auth';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import { StepUp } from '../../shared/stepup';
import type { Backup, BackupVerification } from '../../core/models';

@Component({
  selector: 'skm-backups',
  imports: [Alerts, DatePipe, FormsModule, StepUp],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .state { font-size: 0.75rem; padding: 0.1rem 0.45rem; border-radius: 999px;
             border: 1px solid var(--border-soft); }
    .state.completed { color: var(--accent); border-color: var(--accent-dim); }
    .state.verified { color: var(--ok); border-color: var(--ok); }
    .state.failed { color: var(--danger); border-color: var(--danger); }
    .path { font-family: var(--mono); font-size: 0.76rem; color: var(--text-muted); }
    .problems li { color: var(--danger); font-size: 0.85rem; }
    .stepup { border: 1px solid var(--warn); border-radius: var(--radius-md);
              padding: 0.8rem 1rem; margin: 0.9rem 0; }
  `],
  template: `
    <h1>Backup and restore</h1>

    <skm-alerts [error]="error" [notice]="notice" />

    <div class="notice warn">
      <strong>An archive holds every private key SKM manages.</strong>
      It is encrypted under a passphrase of its own — not the server's master
      key — so it can be restored into a fresh install. That passphrase is never
      stored and cannot be recovered. Losing it means losing the archive.
    </div>

    <div class="card" style="margin-bottom: 1.4rem;">
      <div class="card-header"><h2>Create an archive</h2></div>
      <div class="card-body">
        <div class="grid cols-3">
          <label>Name <input [(ngModel)]="name" placeholder="before-the-migration" /></label>
          <label>
            Contents
            <select [(ngModel)]="kind">
              <option value="full">Everything (keys, targets, policies) — needs a second factor</option>
              <option value="keys_only">Keys only</option>
              <option value="metadata">Metadata only — no private keys</option>
            </select>
          </label>
          <label>Keep for (days, 0 = forever) <input type="number" min="0" [(ngModel)]="retainDays" /></label>
          <label>
            Passphrase (at least 12 characters)
            <input type="password" [(ngModel)]="passphrase" autocomplete="new-password" />
          </label>
          <label>
            Confirm passphrase
            <input type="password" [(ngModel)]="passphraseConfirm" autocomplete="new-password" />
          </label>
        </div>

        @if (passphrase && passphraseConfirm && passphrase !== passphraseConfirm) {
          <p class="small" style="color: var(--danger);">The passphrases do not match.</p>
        }
        @if (passphrase && passphrase.length < 12) {
          <p class="small" style="color: var(--danger);">Passphrase must be at least 12 characters.</p>
        }

        @if (needsStepUp()) {
          <skm-stepup message="This archive will contain every private key SKM holds, so it requires a second factor verified in the last few minutes. Enter a current code and the archive continues."
                      (verified)="needsStepUp.set(false); runPending()" (cancelled)="needsStepUp.set(false); pending = null; busy.set(false)" />
        }

        <div class="actions">
          <button type="button" (click)="create()" [disabled]="!canCreate() || busy() || needsStepUp()">
            @if (busy()) { <span class="spinner"></span> } {{ busy() ? 'Working…' : 'Create archive' }}
          </button>
        </div>

        <p class="small faint">
          A full archive requires a recent second factor: exporting every private
          key is a reveal of every private key, and is gated the same way.
          "Metadata only" does not, because it contains no key material.
        </p>
      </div>
    </div>

    <div class="card" style="margin-bottom: 1.4rem;">
      <div class="card-header"><h2>Archives</h2></div>

      @if (backups().length) {
        <table>
          <thead>
            <tr><th>State</th><th>Name</th><th>Keys</th><th>Size</th><th>Created</th><th></th></tr>
          </thead>
          <tbody>
            @for (b of backups(); track b.id) {
              <tr>
                <td><span class="state" [class]="b.state">{{ b.state }}</span></td>
                <td>
                  {{ b.name }}
                  <div class="path">{{ b.location }}</div>
                  @if (b.error) { <div class="small" style="color: var(--danger);">{{ b.error }}</div> }
                </td>
                <td class="small">{{ b.key_count }}</td>
                <td class="small faint">{{ size(b.size_bytes) }}</td>
                <td class="small faint">{{ b.created_at | date: 'short' }}</td>
                <td style="text-align: right; white-space: nowrap;">
                  <button class="ghost sm" type="button" (click)="verify(b)" [disabled]="busyId() !== null">
                    @if (busyId() === b.id) { <span class="spinner"></span> } Verify
                  </button>
                  <button class="ghost sm" type="button" (click)="restore(b)" [disabled]="busyId() !== null">
                    @if (busyId() === b.id) { <span class="spinner"></span> } Restore
                  </button>
                  <button class="ghost sm" type="button" (click)="remove(b)" [disabled]="busyId() !== null">
                    @if (busyId() === b.id) { <span class="spinner"></span> } Delete
                  </button>
                </td>
              </tr>
            }
          </tbody>
        </table>
      } @else {
        <div class="empty">No archives yet.</div>
      }
    </div>

    @if (verification(); as v) {
      <div class="card">
        <div class="card-header">
          <h2>Verification</h2>
          <span class="state" [class]="v.valid ? 'verified' : 'failed'">
            {{ v.valid ? 'restorable' : 'problems found' }}
          </span>
        </div>
        <div class="card-body">
          <p class="small">
            {{ v.keys_decrypted }} of {{ v.key_count }} private keys decrypted and matched
            their recorded fingerprints. {{ v.target_count }} target(s) in the archive.
          </p>
          <p class="small faint">
            "The backup ran" and "the backup can be restored" are different
            claims. This checked the second one, then discarded what it read.
          </p>
          @if (v.problems?.length) {
            <ul class="problems">
              @for (p of v.problems ?? []; track p) { <li>{{ p }}</li> }
            </ul>
          }
        </div>
      </div>
    }

    @if (restoreResult(); as r) {
      <div class="card">
        <div class="card-header"><h2>Restore</h2></div>
        <div class="card-body">
          <p>
            Restored {{ r.keys_restored }} key(s); skipped {{ r.keys_skipped }} already present.
          </p>
          <p class="small faint">
            Existing keys are never overwritten — a restore that replaced a live
            key with an older copy would be a way to reintroduce a revoked one.
          </p>
          @if (r.problems?.length) {
            <ul class="problems">
              @for (p of r.problems ?? []; track p) { <li>{{ p }}</li> }
            </ul>
          }
        </div>
      </div>
    }
  `,
})
export class BackupsPage implements OnInit {
  private readonly api = inject(Api);
  private readonly auth = inject(Auth);
  private readonly confirm = inject(Confirm);

  protected readonly backups = signal<Backup[]>([]);
  protected readonly verification = signal<BackupVerification | null>(null);
  protected readonly restoreResult = signal<{ keys_restored: number; keys_skipped: number; problems?: string[] } | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly busyId = signal<string | null>(null);
  protected readonly needsStepUp = signal(false);

  /** What to re-run once the second factor is verified. */
  protected pending: (() => void) | null = null;

  protected name = '';
  protected kind = 'full';
  protected retainDays = 0;
  protected passphrase = '';
  protected passphraseConfirm = '';

  ngOnInit(): void {
    this.refresh();
  }

  protected refresh(): void {
    this.api.listBackups().subscribe({
      next: (res) => this.backups.set(res.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected canCreate(): boolean {
    return this.passphrase.length >= 12 && this.passphrase === this.passphraseConfirm;
  }

  protected create(): void {
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);

    this.api.createBackup({
      name: this.name || undefined,
      kind: this.kind,
      passphrase: this.passphrase,
      retain_days: this.retainDays,
    }).subscribe({
      next: (b) => {
        this.busy.set(false);
        this.notice.set(`Wrote ${b.key_count} key(s) to ${b.location}.`);
        // The passphrase must not linger in the page after it has been used.
        this.passphrase = '';
        this.passphraseConfirm = '';
        this.refresh();
      },
      error: (err: Error) => this.failed(err, () => this.create()),
    });
  }

  /**
   * failed routes a step-up refusal into the inline prompt instead of showing
   * it as an error.
   *
   * Being told to go to another screen, verify, come back, and re-enter a
   * passphrase you have already typed twice is the kind of friction that ends
   * with people not taking backups.
   */
  private failed(err: Error, retry: () => void): void {
    this.busy.set(false);

    if (mfaRequired(err)) {
      this.pending = retry;
      this.needsStepUp.set(true);
      return;
    }
    this.error.set(err.message);
  }

  protected runPending(): void {
    const retry = this.pending;
    this.pending = null;
    if (retry) retry();
    else this.busy.set(false);
  }

  protected async verify(b: Backup): Promise<void> {
    const pass = await this.confirm.prompt({
      title: `Verify "${b.name}"`,
      label: 'Passphrase',
      type: 'password',
      action: 'Verify'
    });
    if (pass === null) return;

    this.verifyWith(b, pass);
  }

  private verifyWith(b: Backup, pass: string): void {
    this.busyId.set(b.id);
    this.error.set(null);
    this.restoreResult.set(null);

    this.api.verifyBackup(b.id, pass).subscribe({
      next: (v) => {
        this.busyId.set(null);
        this.verification.set(v);
        this.refresh();
      },
      error: (err: Error) => { this.busyId.set(null); this.failed(err, () => this.verifyWith(b, pass)); },
    });
  }

  protected async restore(b: Backup): Promise<void> {
    const pass = await this.confirm.prompt({
      title: `Restore "${b.name}" into this instance?`,
      message: 'Keys already present are skipped, not overwritten.',
      label: 'Passphrase',
      type: 'password',
      action: 'Restore',
      danger: true
    });
    if (pass === null) return;

    this.restoreWith(b, pass);
  }

  /** Split out so a step-up retry does not ask for the passphrase again. */
  private restoreWith(b: Backup, passphrase: string): void {
    this.busyId.set(b.id);
    this.error.set(null);
    this.verification.set(null);

    this.api.restoreBackup({ backup_id: b.id, passphrase }).subscribe({
      next: (r) => {
        this.busyId.set(null);
        this.restoreResult.set(r);
        this.notice.set('Restore complete.');
      },
      error: (err: Error) => { this.busyId.set(null); this.failed(err, () => this.restoreWith(b, passphrase)); },
    });
  }

  protected async remove(b: Backup): Promise<void> {
    if (!(await this.confirm.ask({
      title: `Delete "${b.name}"?`,
      message: 'This removes the archive file. This cannot be undone.',
      action: 'Delete',
      danger: true
    }))) return;

    this.busyId.set(b.id);
    this.error.set(null);

    this.api.deleteBackup(b.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.notice.set(`Deleted ${b.name}.`);
        this.refresh();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected size(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }
}
