import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  Injectable,
  computed,
  effect,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';

import { Modal } from './modal';

export interface ConfirmOptions {
  /** The question, as a short sentence: "Delete web-01?" */
  title: string;
  /** What happens if they say yes. Plain words, no jargon. */
  message?: string;
  /** The verb on the button. Defaults to "Confirm". */
  action?: string;
  /** Styles the action button as destructive. */
  danger?: boolean;
}

export interface PromptOptions extends ConfirmOptions {
  /** Label above the input. */
  label?: string;
  placeholder?: string;
  /** Pre-filled value. */
  initial?: string;
  /** "password" hides the characters. */
  type?: 'text' | 'password';
  /** The action button stays disabled until the value is at least this long. */
  minLength?: number;
}

interface Pending {
  opts: PromptOptions;
  withInput: boolean;
  resolve: (value: string | null) => void;
}

/**
 * Confirm replaces the browser's confirm() and prompt().
 *
 *   if (!(await this.confirm.ask({ title: 'Delete web-01?', action: 'Delete', danger: true }))) return;
 *   const reason = await this.confirm.prompt({ title: 'Abort the rotation', label: 'Reason' });
 *
 * Both resolve when the user answers; ask() with false and prompt() with null
 * on cancel. One dialog is open at a time — a second call while one is open
 * answers the first with "no".
 */
@Injectable({ providedIn: 'root' })
export class Confirm {
  readonly current = signal<Pending | null>(null);

  ask(opts: ConfirmOptions): Promise<boolean> {
    return this.open(opts, false).then((v) => v !== null);
  }

  prompt(opts: PromptOptions): Promise<string | null> {
    return this.open(opts, true);
  }

  /** Called by the host component with the answer. */
  answer(value: string | null): void {
    const pending = this.current();
    this.current.set(null);
    pending?.resolve(value);
  }

  private open(opts: PromptOptions, withInput: boolean): Promise<string | null> {
    this.current()?.resolve(null);
    return new Promise((resolve) => this.current.set({ opts, withInput, resolve }));
  }
}

/** ConfirmHost renders the pending question. Mounted once, in the shell. */
@Component({
  selector: 'skm-confirm-host',
  imports: [FormsModule, Modal],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (confirm.current(); as p) {
      <skm-modal [title]="p.opts.title" (close)="confirm.answer(null)">
        @if (p.opts.message) { <p class="muted" style="white-space: pre-line;">{{ p.opts.message }}</p> }

        @if (p.withInput) {
          <label>
            @if (p.opts.label) { <span class="label">{{ p.opts.label }}</span> }
            <input #field [type]="p.opts.type ?? 'text'" [placeholder]="p.opts.placeholder ?? ''"
                   [(ngModel)]="value" name="confirm-value" (keydown.enter)="submit()"
                   [attr.autocomplete]="p.opts.type === 'password' ? 'off' : null" />
          </label>
        }

        <div class="row end" style="margin-top: 1rem;">
          <button type="button" (click)="confirm.answer(null)">Cancel</button>
          <button #primary type="button" [class.danger]="p.opts.danger" [class.primary]="!p.opts.danger"
                  [disabled]="!ready()" (click)="submit()">
            {{ p.opts.action ?? 'Confirm' }}
          </button>
        </div>
      </skm-modal>
    }
  `,
})
export class ConfirmHost {
  protected readonly confirm = inject(Confirm);
  protected value = '';

  private readonly field = viewChild<ElementRef<HTMLInputElement>>('field');
  private readonly primary = viewChild<ElementRef<HTMLButtonElement>>('primary');

  protected readonly ready = computed(() => {
    const p = this.confirm.current();
    if (!p || !p.withInput) return true;
    return this.value.length >= (p.opts.minLength ?? 1);
  });

  constructor() {
    effect(() => {
      const p = this.confirm.current();
      if (!p) return;
      this.value = p.opts.initial ?? '';
      // The dialog is inserted this frame; focus it on the next one.
      setTimeout(() => (this.field()?.nativeElement ?? this.primary()?.nativeElement)?.focus());
    });
  }

  protected submit(): void {
    const p = this.confirm.current();
    if (!p) return;
    if (p.withInput) {
      if (this.value.length < (p.opts.minLength ?? 1)) return;
      this.confirm.answer(this.value);
    } else {
      this.confirm.answer('');
    }
  }
}
