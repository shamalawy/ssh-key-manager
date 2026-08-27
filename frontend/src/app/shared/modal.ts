import { ChangeDetectionStrategy, Component, HostListener, OnDestroy, OnInit, input, output } from '@angular/core';

/**
 * open is the stack of modals currently on screen, newest last. Escape closes
 * only the top one, so a confirm dialog over an edit form takes the key and
 * the form underneath stays put.
 */
const open: Modal[] = [];

/**
 * Modal is the one dialog frame every page uses.
 *
 * It owns the backdrop, the Escape key, and the click-outside-to-close
 * behaviour, so a page only says what goes inside:
 *
 *   @if (editing()) {
 *     <skm-modal title="Edit target" (close)="editing.set(false)">
 *       …form…
 *     </skm-modal>
 *   }
 */
@Component({
  selector: 'skm-modal',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="modal-backdrop" (click)="close.emit()">
      <div class="modal" [class.wide]="wide()" role="dialog" aria-modal="true"
           [attr.aria-label]="title() || null" (click)="$event.stopPropagation()">
        @if (title()) { <h2>{{ title() }}</h2> }
        <ng-content />
      </div>
    </div>
  `,
})
export class Modal implements OnInit, OnDestroy {
  readonly title = input('');
  readonly wide = input(false);
  readonly close = output<void>();

  ngOnInit(): void {
    open.push(this);
  }

  ngOnDestroy(): void {
    const i = open.lastIndexOf(this);
    if (i >= 0) open.splice(i, 1);
  }

  @HostListener('document:keydown.escape')
  protected onEscape(): void {
    if (open[open.length - 1] === this) {
      this.close.emit();
    }
  }
}
