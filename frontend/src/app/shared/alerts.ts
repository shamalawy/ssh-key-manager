import { ChangeDetectionStrategy, Component, WritableSignal, computed, input } from '@angular/core';

/**
 * Alerts shows a page's error and success notices, each dismissible.
 *
 *   <skm-alerts [error]="error" [notice]="notice" />
 *
 * The page hands over its signals so a dismiss clears the page's own state.
 */
@Component({
  selector: 'skm-alerts',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (errorText(); as message) {
      <div class="notice error row" role="alert">
        <span class="spacer">{{ message }}</span>
        <button class="ghost sm" type="button" aria-label="Dismiss" (click)="error()?.set(null)">✕</button>
      </div>
    }
    @if (noticeText(); as message) {
      <div class="notice ok row" role="status">
        <span class="spacer">{{ message }}</span>
        <button class="ghost sm" type="button" aria-label="Dismiss" (click)="notice()?.set(null)">✕</button>
      </div>
    }
  `,
})
export class Alerts {
  readonly error = input<WritableSignal<string | null>>();
  readonly notice = input<WritableSignal<string | null>>();

  protected readonly errorText = computed(() => this.error()?.() || null);
  protected readonly noticeText = computed(() => this.notice()?.() || null);
}
