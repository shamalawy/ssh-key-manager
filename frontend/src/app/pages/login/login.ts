import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';

import { Auth } from '../../core/auth';
import type { ApiError } from '../../core/api';

@Component({
  selector: 'skm-login',
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .wrap {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 2rem;
    }
    .panel { width: 100%; max-width: 370px; }
    .brand { text-align: center; margin-bottom: 1.6rem; }
    .brand .mark {
      font-size: 1.6rem; font-weight: 700; letter-spacing: 0.12em; color: var(--accent);
    }
    .brand p { margin: 0.15rem 0 0; color: var(--text-faint); font-size: 0.85rem; }
    button { width: 100%; margin-top: 0.4rem; }
  `],
  template: `
    <div class="wrap">
      <div class="panel">
        <div class="brand">
          <div class="mark">SKM</div>
          <p>SSH Key Manager</p>
        </div>

        <form class="card" (ngSubmit)="submit()">
          @if (error(); as message) {
            <div class="notice error">{{ message }}</div>
          }
          @if (needsTotp()) {
            <div class="notice info">Enter the current code from your authenticator app.</div>
          }

          <label>
            <span class="label">Username</span>
            <input name="username" autocomplete="username" autofocus
                   [(ngModel)]="username" [disabled]="busy()" />
          </label>

          <label>
            <span class="label">Password</span>
            <input name="password" type="password" autocomplete="current-password"
                   [(ngModel)]="password" [disabled]="busy()" />
          </label>

          @if (needsTotp()) {
            <label>
              <span class="label">Authentication code</span>
              <input name="totp" inputmode="numeric" autocomplete="one-time-code"
                     maxlength="6" placeholder="000000"
                     [(ngModel)]="totpCode" [disabled]="busy()" />
              <div class="help" style="margin-top: 0.4rem; font-size: 0.8rem; color: var(--text-muted);">
                Enter the 6-digit code from your authenticator, or a recovery code.
              </div>
            </label>
          }

          <button class="primary" type="submit" [disabled]="busy() || !username || !password || (needsTotp() && totpCode.length !== 6)">
            @if (busy()) { <span class="spinner"></span> Signing in… } @else { Sign in }
          </button>
        </form>
      </div>
    </div>
  `,
})
export class Login {
  private readonly auth = inject(Auth);
  private readonly router = inject(Router);

  protected username = '';
  protected password = '';
  protected totpCode = '';

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly needsTotp = signal(false);

  protected submit(): void {
    if (this.busy()) return;

    this.busy.set(true);
    this.error.set(null);

    this.auth.login(this.username, this.password, this.totpCode || undefined).subscribe({
      next: () => {
        this.busy.set(false);
        void this.router.navigate(['/overview']);
      },
      error: (err: ApiError) => {
        this.busy.set(false);
        // A second factor is a prompt, not a failure: reveal the field and let
        // the user continue rather than making them start over.
        if (err.code === 'mfa_required') {
          this.needsTotp.set(true);
          // Only clear error if no code was entered yet; if code is present but wrong,
          // show the server's message.
          if (!this.totpCode) {
            this.error.set(null);
          } else {
            this.error.set(err.message);
          }
          return;
        }
        this.error.set(err.message);
      },
    });
  }
}
