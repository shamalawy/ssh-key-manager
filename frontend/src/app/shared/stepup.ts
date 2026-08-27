import { ChangeDetectionStrategy, Component, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';

import { Api, ApiError } from '../core/api';
import { Auth } from '../core/auth';

/**
 * StepUp collects a second-factor code right where it is needed, instead of
 * sending the user to Settings and back.
 *
 * Drop it into the modal that hit `mfa_required`:
 *
 *   @if (needsStepUp()) {
 *     <skm-stepup message="Revealing a private key needs a fresh code."
 *                 (verified)="needsStepUp.set(false); reveal(k)"
 *                 (cancelled)="needsStepUp.set(false)" />
 *   }
 *
 * If no second factor is enrolled it says so and points at enrolment, which
 * is the case the old "verify under Settings" message got wrong.
 */
@Component({
  selector: 'skm-stepup',
  imports: [FormsModule, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (!auth.totpEnrolled()) {
      <div class="notice warn">
        This needs a second factor, and your account has none enrolled.
        <a routerLink="/settings">Enrol one under Settings</a>, then come back here.
      </div>
      <div class="row end">
        <button type="button" (click)="cancelled.emit()">Close</button>
      </div>
    } @else {
      <div class="notice info">{{ message() }}</div>
      @if (error(); as e) { <div class="notice error">{{ e }}</div> }
      <div class="row">
        <input inputmode="numeric" maxlength="6" placeholder="000000" autocomplete="one-time-code"
               [(ngModel)]="code" name="stepup-code" style="max-width: 8rem;"
               (keydown.enter)="verify()" [disabled]="busy()" />
        <button class="primary" type="button" [disabled]="busy() || code.length !== 6" (click)="verify()">
          @if (busy()) { <span class="spinner"></span> } Verify and continue
        </button>
        <button class="ghost" type="button" [disabled]="busy()" (click)="cancelled.emit()">Cancel</button>
      </div>
    }
  `,
})
export class StepUp {
  private readonly api = inject(Api);
  protected readonly auth = inject(Auth);

  readonly message = input('This action needs a second-factor code verified in the last few minutes.');
  readonly verified = output<void>();
  readonly cancelled = output<void>();

  protected code = '';
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected verify(): void {
    if (this.code.length !== 6 || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.stepUp(this.code).subscribe({
      next: () => {
        this.code = '';
        this.busy.set(false);
        this.auth.refresh();
        this.verified.emit();
      },
      error: (err: ApiError) => {
        this.busy.set(false);
        this.error.set(err.message);
      },
    });
  }
}
