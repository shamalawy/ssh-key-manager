import { ChangeDetectionStrategy, Component, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';

import { Api, ApiError } from '../../core/api';
import { Auth } from '../../core/auth';

/**
 * ChangePasswordPage is where an account with must_change_password lands.
 *
 * It is outside the shell on purpose: there is no navigation to wander off
 * into, and the route guard sends every other page back here until the
 * password has been changed.
 */
@Component({
  selector: 'skm-change-password',
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: `
    :host { display: grid; place-items: center; min-height: 100vh; padding: 1.5rem; }
    .card { width: 100%; max-width: 420px; }
    form { display: flex; flex-direction: column; gap: 0.9rem; }
  `,
  template: `
    <div class="card">
      <h1 style="margin-bottom: 0.3rem;">Choose a new password</h1>
      <p class="muted" style="margin-bottom: 1.2rem;">
        The password you signed in with was set by someone else. Pick your own
        before going any further. At least 12 characters.
      </p>

      @if (error(); as message) { <div class="notice error">{{ message }}</div> }

      <form (ngSubmit)="submit()">
        <label>
          <span class="label">Current password</span>
          <input type="password" name="current" autocomplete="current-password"
                 [(ngModel)]="current" [disabled]="busy()" required />
        </label>
        <label>
          <span class="label">New password</span>
          <input type="password" name="password" autocomplete="new-password"
                 [(ngModel)]="password" [disabled]="busy()" required minlength="12" />
        </label>
        <label>
          <span class="label">New password again</span>
          <input type="password" name="confirm" autocomplete="new-password"
                 [(ngModel)]="confirm" [disabled]="busy()" required />
        </label>
        @if (password && confirm && password !== confirm) {
          <p class="small" style="color: var(--danger); margin: 0;">The passwords do not match.</p>
        }
        @if (password && password.length < 12) {
          <p class="small faint" style="margin: 0;">{{ 12 - password.length }} more characters needed.</p>
        }

        <div class="row end">
          <button class="ghost" type="button" [disabled]="busy()" (click)="auth.logout()">Sign out</button>
          <button class="primary" type="submit" [disabled]="busy() || !canSubmit()">
            @if (busy()) { <span class="spinner"></span> } Save and continue
          </button>
        </div>
      </form>
    </div>
  `,
})
export class ChangePasswordPage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);
  protected readonly auth = inject(Auth);

  protected current = '';
  protected password = '';
  protected confirm = '';
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected canSubmit(): boolean {
    return !!this.current && this.password.length >= 12 && this.password === this.confirm;
  }

  protected submit(): void {
    if (!this.canSubmit() || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);

    this.api.changeOwnPassword(this.current, this.password).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: async () => {
        await this.auth.reload();
        this.busy.set(false);
        void this.router.navigate(['/dashboard']);
      },
      error: (err: ApiError) => {
        this.busy.set(false);
        this.error.set(err.code === 'invalid_credentials' ? 'The current password is wrong.' : err.message);
      },
    });
  }
}
