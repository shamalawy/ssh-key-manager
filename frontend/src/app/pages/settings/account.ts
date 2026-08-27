import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import { Auth } from '../../core/auth';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import type { TotpEnrolment } from '../../core/models';

@Component({
  selector: 'skm-account-settings',
  imports: [Alerts, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .secret {
      font-family: var(--mono); font-size: 0.85rem; letter-spacing: 0.05em;
      background: var(--bg-input); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 0.6rem; word-break: break-all;
    }
    .codes {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 0.35rem; font-family: var(--mono); font-size: 0.82rem;
    }
    .codes span {
      background: var(--bg-input); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 0.3rem 0.5rem; text-align: center;
    }
    .enrol { display: flex; gap: 1.5rem; align-items: flex-start; flex-wrap: wrap; }
    .enrol-text { flex: 1; min-width: 16rem; }
    /* The code is rendered as black modules on white and must stay that way in
       a dark theme: inverting it is the one styling choice that stops a camera
       reading it. */
    .qr {
      background: #fff; padding: 0.6rem; border-radius: var(--radius);
      border: 1px solid var(--border);
    }
    .qr img { display: block; image-rendering: pixelated; }
    .rule { border: none; border-top: 1px solid var(--border-soft); margin: 1.3rem 0 1rem; }
  `],
  template: `
    <p class="muted" style="margin-bottom: 1.2rem;">Your own sign-in: second factor and password.</p>

    <skm-alerts [error]="error" [notice]="notice" />

    <div class="card">
      <div class="card-header"><h2>Second factor</h2></div>

      @if (auth.totpEnrolled()) {
        <p class="muted">
          A second factor is enrolled.
          @if (auth.mfaVerified()) {
            You verified it this session, so sensitive operations are available.
          } @else {
            Verify it below to unlock revealing private keys, full backups and restores, rotating the key-encryption key, and rolling back.
          }
        </p>

        <label style="max-width: 220px;">
          <span class="label">Current code</span>
          <input inputmode="numeric" maxlength="6" placeholder="000000" [(ngModel)]="stepUpCode" />
        </label>
        <button class="primary" type="button" [disabled]="busy() || stepUpCode.length !== 6" (click)="stepUp()">
          @if (busy()) { <span class="spinner"></span> } Verify
        </button>

        @if (freshCodes(); as codes) {
          <div class="notice warn" style="margin-top: 1.2rem;">
            New recovery codes. The previous set no longer works. Save these now —
            they are shown once.
          </div>
          <div class="codes">@for (c of codes; track c) { <span>{{ c }}</span> }</div>
          <div class="row" style="margin-top: 0.7rem;">
            <button type="button" (click)="copyCodes(codes)">Copy all</button>
            <button type="button" (click)="downloadCodes(codes)">Download</button>
            <button class="ghost" type="button" (click)="freshCodes.set(null)">Done</button>
          </div>
        }

        <hr class="rule" />

        <h3>Managing your second factor</h3>
        <p class="muted small">
          Both of these need a current code, because a live session on its own is
          not proof of possession — and if it were, anyone who walked up to an
          unlocked screen could mint themselves a permanent way around the
          second factor.
        </p>
        <label style="max-width: 220px;">
          <span class="label">Current code</span>
          <input inputmode="numeric" maxlength="6" placeholder="000000"
                 [(ngModel)]="manageCode" name="manage-code" />
        </label>
        <div class="row">
          <button type="button" [disabled]="busy() || manageCode.length !== 6"
                  (click)="regenerateCodes()">New recovery codes</button>
          <button class="danger" type="button" [disabled]="busy() || manageCode.length !== 6"
                  (click)="disableTotp()">Remove the second factor</button>
        </div>

      } @else if (enrolment(); as e) {
        <div class="notice warn">
          Save the recovery codes now. They are shown once and cannot be retrieved again.
        </div>

        <div class="enrol">
          @if (e.qr_code) {
            <div class="qr">
              <img [src]="e.qr_code" alt="Scan this with your authenticator app"
                   width="240" height="240" />
              <p class="muted small" style="text-align: center; margin: 0.4rem 0 0;">
                Scan with your authenticator app
              </p>
            </div>
          }

          <div class="enrol-text">
            <p class="muted small" style="margin-top: 0;">
              @if (e.qr_code) { Or type the secret in by hand: }
              @else { Add this secret to your authenticator app: }
            </p>
            <div class="secret">{{ e.secret }}</div>
            <div class="row" style="margin-top: 0.5rem;">
              <button class="ghost sm" type="button" (click)="copyText(e.secret, 'Secret copied.')">
                Copy secret
              </button>
            </div>
          </div>
        </div>

        <p class="muted small" style="margin-top: 1.2rem;">
          Recovery codes — each works once, and only if you have lost the
          authenticator. Keep them somewhere other than the device generating
          your codes, or they protect against nothing.
        </p>
        <div class="codes">
          @for (code of e.recovery_codes; track code) { <span>{{ code }}</span> }
        </div>
        <div class="row" style="margin: 0.7rem 0 1.2rem;">
          <button type="button" (click)="copyCodes(e.recovery_codes)">Copy all</button>
          <button type="button" (click)="downloadCodes(e.recovery_codes)">Download</button>
        </div>

        <label style="max-width: 220px;">
          <span class="label">Confirm with a generated code</span>
          <input inputmode="numeric" maxlength="6" placeholder="000000" [(ngModel)]="confirmCode" />
        </label>
        <button class="primary" type="button" [disabled]="busy() || confirmCode.length !== 6" (click)="confirm()">
          @if (busy()) { <span class="spinner"></span> } Confirm enrolment
        </button>

      } @else {
        <p class="muted">
          No second factor is enrolled. Revealing private keys, full backups and restores,
          rotating the key-encryption key, and rolling back all require one.
        </p>
        <button class="primary" type="button" [disabled]="busy()" (click)="enrol()">
          @if (busy()) { <span class="spinner"></span> } Enrol a second factor
        </button>
      }
    </div>

    <div class="card">
      <div class="card-header"><h2>Password</h2></div>

      <div class="grid cols-3">
        <label>
          <span class="label">Current password</span>
          <input type="password" [(ngModel)]="passwords.current" name="pw-current"
                 autocomplete="current-password" />
        </label>
        <label>
          <span class="label">New password</span>
          <input type="password" [(ngModel)]="passwords.next" name="pw-next"
                 autocomplete="new-password" />
        </label>
        <label>
          <span class="label">Confirm</span>
          <input type="password" [(ngModel)]="passwords.confirm" name="pw-confirm"
                 autocomplete="new-password" />
        </label>
      </div>

      @if (passwords.next && passwords.confirm && passwords.next !== passwords.confirm) {
        <p class="small" style="color: var(--danger);">The new passwords do not match.</p>
      }

      <button class="primary" type="button" [disabled]="busy() || !canChangePassword()"
              (click)="changePassword()">
        @if (busy()) { <span class="spinner"></span> } Change password
      </button>
      <p class="muted small">
        At least 12 characters, and that is the only rule. Length is what costs
        an attacker something; composition rules mostly produce Password1!.
      </p>
    </div>

    <div class="card">
      <div class="card-header"><h2>Your access</h2></div>

      @if (auth.identity(); as identity) {
        <p><strong>Username:</strong> {{ identity.user.username }}</p>
        @if (identity.roles && identity.roles.length > 0) {
          <p><strong>Roles:</strong> {{ identity.roles.join(', ') }}</p>
        }
        @if (identity.permissions && identity.permissions.length > 0) {
          <p><strong>Permissions:</strong> {{ identity.permissions.join(', ') }}</p>
        }
      } @else {
        <p class="muted">Could not load access information.</p>
      }
    </div>
  `,
})
export class AccountSettings implements OnInit {
  private readonly api = inject(Api);
  private readonly confirmDialog = inject(Confirm);
  protected readonly auth = inject(Auth);

  protected readonly enrolment = signal<TotpEnrolment | null>(null);
  protected readonly freshCodes = signal<string[] | null>(null);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);

  protected stepUpCode = '';
  protected confirmCode = '';
  protected manageCode = '';
  protected passwords = { current: '', next: '', confirm: '' };

  ngOnInit(): void {
    // No initialization needed - MFA status loaded by Auth service
  }

  protected enrol(): void {
    this.busy.set(true);
    this.api.enrolTotp().subscribe({
      next: (e) => {
        this.busy.set(false);
        this.enrolment.set(e);
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected confirm(): void {
    this.busy.set(true);
    this.api.confirmTotp(this.confirmCode).subscribe({
      next: () => {
        this.busy.set(false);
        this.enrolment.set(null);
        this.confirmCode = '';
        this.notice.set('Second factor enrolled.');
        this.auth.refresh();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected stepUp(): void {
    this.busy.set(true);
    this.api.stepUp(this.stepUpCode).subscribe({
      next: (r) => {
        this.busy.set(false);
        this.stepUpCode = '';
        this.notice.set(`Verified. Sensitive operations are available until ${new Date(r.valid_until).toLocaleTimeString()}.`);
        this.auth.refresh();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected canChangePassword(): boolean {
    return this.passwords.current.length > 0
      && this.passwords.next.length >= 12
      && this.passwords.next === this.passwords.confirm;
  }

  protected changePassword(): void {
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);

    this.api.changeOwnPassword(this.passwords.current, this.passwords.next).subscribe({
      next: () => {
        this.busy.set(false);
        this.passwords = { current: '', next: '', confirm: '' };
        this.notice.set('Password changed. Other sessions keep working until they expire.');
      },
      error: (err: Error) => { this.busy.set(false); this.error.set(err.message); },
    });
  }

  protected async regenerateCodes(): Promise<void> {
    if (!(await this.confirmDialog.ask({
      title: 'Issue new recovery codes?',
      message: 'The codes you have now stop working the moment the new ones appear.',
      action: 'Generate',
    }))) return;

    this.busy.set(true);
    this.error.set(null);

    this.api.regenerateRecoveryCodes(this.manageCode).subscribe({
      next: (r) => {
        this.busy.set(false);
        this.manageCode = '';
        this.freshCodes.set(r.recovery_codes);
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected async disableTotp(): Promise<void> {
    if (!(await this.confirmDialog.ask({
      title: 'Remove the second factor?',
      message: 'Revealing private keys, full backups and restores, rotating the key-encryption key, and rolling back will no longer be available until you enrol again.',
      action: 'Remove',
      danger: true,
    }))) return;

    this.busy.set(true);
    this.error.set(null);

    this.api.disableTotp(this.manageCode).subscribe({
      next: () => {
        this.busy.set(false);
        this.manageCode = '';
        this.freshCodes.set(null);
        this.notice.set('The second factor has been removed. Enrol again when you can.');
        this.auth.refresh();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }

  protected copyText(text: string, message: string): void {
    navigator.clipboard.writeText(text).then(
      () => this.notice.set(message),
      () => this.error.set('The browser refused clipboard access; select and copy by hand.'),
    );
  }

  protected copyCodes(codes: string[]): void {
    this.copyText(codes.join('\n'), 'All recovery codes copied.');
  }

  /**
   * downloadCodes writes the codes to a file the browser saves locally.
   *
   * A blob URL rather than a request to the server: the codes are already in
   * the page, and sending them back so they can be sent forward again would
   * put them through one more system for no reason.
   */
  protected downloadCodes(codes: string[]): void {
    const who = this.auth.identity()?.user.username ?? 'account';
    const body = [
      'SKM recovery codes',
      `Account: ${who}`,
      `Issued:  ${new Date().toISOString()}`,
      '',
      'Each code works once, and only in place of your authenticator app.',
      'Store these somewhere other than the device that generates your codes.',
      '',
      ...codes,
      '',
    ].join('\n');

    const url = URL.createObjectURL(new Blob([body], { type: 'text/plain' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `skm-recovery-codes-${who}.txt`;
    link.click();
    URL.revokeObjectURL(url);

    this.notice.set('Recovery codes downloaded.');
  }
}
