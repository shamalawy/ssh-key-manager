import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import type { Webhook, WebhookDelivery } from '../../core/models';

/**
 * Shared utility for clipboard operations.
 * Encapsulates the common logic for copying text to clipboard with callbacks.
 * Can be extracted to a shared service if needed by multiple components.
 */
function writeToClipboard(
  text: string,
  message: string,
  onSuccess: (msg: string) => void,
  onError: (msg: string) => void
): void {
  navigator.clipboard.writeText(text).then(
    () => onSuccess(message),
    () => onError('The browser refused clipboard access; select and copy by hand.'),
  );
}

@Component({
  selector: 'skm-notification-settings',
  imports: [Alerts, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .secret {
      font-family: var(--mono); font-size: 0.85rem; letter-spacing: 0.05em;
      background: var(--bg-input); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 0.6rem; word-break: break-all;
    }
  `],
  template: `
    <p class="muted" style="margin-bottom: 1.2rem;">Send events to a URL.</p>

    <skm-alerts [error]="error" [notice]="notice" />

    <div class="card" style="margin-bottom: 1.4rem;">
      <div class="card-header"><h2>Notifications</h2></div>
      <div class="card-body">
        <p class="small faint">
          Signed notifications for key, rotation, drift, and installation events.
          Each request carries an <code>X-SKM-Signature</code> header: an HMAC over
          <code>timestamp.body</code>, so a captured request cannot be replayed
          indefinitely. Verify it before trusting the payload.
        </p>

        <div class="grid cols-2">
          <label>Name <input [(ngModel)]="hookName" placeholder="ops-slack-bridge" /></label>
          <label>URL <input [(ngModel)]="hookUrl" placeholder="https://hooks.example.com/skm" /></label>
        </div>

        <div style="margin: 0.6rem 0;">
          <span class="label small faint">Events (none selected means every event)</span>
          <div>
            @for (e of eventTypes(); track e) {
              <span class="tag" style="cursor: pointer;"
                    [style.border-color]="hookEvents.has(e) ? 'var(--accent)' : ''"
                    [style.color]="hookEvents.has(e) ? 'var(--accent)' : ''"
                    (click)="toggleEvent(e)">{{ e }}</span>
            }
          </div>
        </div>

        <div class="actions">
          <button type="button" (click)="createWebhook()" [disabled]="!hookName || !hookUrl || busy()">
            @if (busy()) { <span class="spinner"></span> } Add notification
          </button>
        </div>

        @if (newSecret(); as secret) {
          <div class="notice warn">
            <strong>Signing secret — shown once.</strong>
            <div class="secret">{{ secret }}</div>
            It cannot be retrieved afterwards. Store it where the receiver will read it.
          </div>
          <div class="row" style="margin-top: 0.7rem;">
            <button type="button" (click)="copyText(secret, 'Signing secret copied.')">Copy secret</button>
            <button class="ghost" type="button" (click)="newSecret.set(null)">Done</button>
          </div>
        }

        @if (webhooks().length) {
          <table>
            <thead><tr><th>Name</th><th>URL</th><th>Events</th><th></th></tr></thead>
            <tbody>
              @for (w of webhooks(); track w.id) {
                <tr>
                  <td>
                    {{ w.name }}
                    @if (!w.enabled) { <span class="small faint"> · disabled</span> }
                    @if (!w.has_secret) { <span class="small" style="color: var(--warn);"> · unsigned</span> }
                  </td>
                  <td class="small faint" style="max-width: 20rem; overflow: hidden; text-overflow: ellipsis;">{{ w.url }}</td>
                  <td class="small faint">{{ w.events.length ? w.events.length + ' selected' : 'all' }}</td>
                  <td style="text-align: right; white-space: nowrap;">
                    <button class="ghost sm" type="button" [disabled]="busyId() !== null" (click)="toggleWebhook(w)">
                      {{ w.enabled ? 'Disable' : 'Enable' }}
                    </button>
                    <button class="ghost sm" type="button" [disabled]="busyId() !== null" (click)="deleteWebhook(w)">Delete</button>
                  </td>
                </tr>
              }
            </tbody>
          </table>

          @if (deliveries().length) {
            <h3 class="small" style="margin-top: 1rem;">Recent deliveries</h3>
            <table>
              <thead><tr><th>Event</th><th>Endpoint</th><th>Status</th><th>Attempts</th><th></th></tr></thead>
              <tbody>
                @for (d of deliveries(); track d.id) {
                  <tr>
                    <td class="small"><code>{{ d.event }}</code></td>
                    <td class="small faint">{{ d.webhook_name }}</td>
                    <td class="small" [style.color]="d.state === 'delivered' ? 'var(--ok)' : d.state === 'dead' ? 'var(--danger)' : ''">
                      {{ d.state }}@if (d.status_code) { · {{ d.status_code }} }
                    </td>
                    <td class="small faint">{{ d.attempts }}</td>
                    <td style="text-align: right;">
                      @if (d.state !== 'delivered') {
                        <button class="ghost sm" type="button" [disabled]="busyId() !== null" (click)="replay(d)">
                          @if (busyId() === d.id) { <span class="spinner"></span> } Replay
                        </button>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          }
        } @else {
          <div class="empty">No notifications configured.</div>
        }
      </div>
    </div>
  `,
})
export class NotificationSettings implements OnInit {
  private readonly api = inject(Api);
  private readonly confirmDialog = inject(Confirm);

  protected readonly webhooks = signal<Webhook[]>([]);
  protected readonly deliveries = signal<WebhookDelivery[]>([]);
  protected readonly eventTypes = signal<string[]>([]);
  protected readonly newSecret = signal<string | null>(null);

  protected readonly busy = signal(false);
  protected readonly busyId = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);

  protected hookName = '';
  protected hookUrl = '';
  protected readonly hookEvents = new Set<string>();

  ngOnInit(): void {
    this.api.eventTypes().subscribe({ next: (res) => this.eventTypes.set(res.events) });
    this.loadWebhooks();
  }

  private loadWebhooks(): void {
    this.api.listWebhooks().subscribe({
      next: (res) => this.webhooks.set(res.items),
      error: () => { /* a missing permission should not blank the page */ },
    });
    this.api.listDeliveries().subscribe({
      next: (res) => this.deliveries.set(res.items),
      error: () => { /* likewise */ },
    });
  }

  protected toggleEvent(e: string): void {
    if (this.hookEvents.has(e)) this.hookEvents.delete(e);
    else this.hookEvents.add(e);
  }

  protected createWebhook(): void {
    this.busy.set(true);
    this.error.set(null);
    this.newSecret.set(null);

    this.api.createWebhook({
      name: this.hookName,
      url: this.hookUrl,
      events: [...this.hookEvents],
      enabled: true,
    }).subscribe({
      next: (res) => {
        this.busy.set(false);
        if (res.secret) this.newSecret.set(res.secret);
        this.hookName = '';
        this.hookUrl = '';
        this.hookEvents.clear();
        this.loadWebhooks();
      },
      error: (err: Error) => { this.busy.set(false); this.error.set(err.message); },
    });
  }

  protected async deleteWebhook(w: Webhook): Promise<void> {
    if (!(await this.confirmDialog.ask({
      title: `Delete the notification "${w.name}"?`,
      message: 'This removes the notification endpoint and its delivery history.',
      action: 'Delete',
      danger: true,
    }))) return;

    this.busyId.set(w.id);
    this.api.deleteWebhook(w.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.notice.set(`Deleted the notification "${w.name}".`);
        this.loadWebhooks();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected replay(d: WebhookDelivery): void {
    this.busyId.set(d.id);
    this.api.replayDelivery(d.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.notice.set('Queued for redelivery.');
        this.loadWebhooks();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  /**
   * toggleWebhook pauses deliveries without discarding the subscription.
   *
   * Deleting a webhook to stop a noisy endpoint loses its URL, its event
   * selection, and its signing secret, all of which have to be set up again
   * afterwards — so people leave the noise on instead.
   */
  protected toggleWebhook(w: Webhook): void {
    this.busyId.set(w.id);
    this.api.setWebhookEnabled(w.id, !w.enabled).subscribe({
      next: () => {
        this.busyId.set(null);
        this.notice.set(w.enabled
          ? `Paused deliveries to ${w.name}.`
          : `Deliveries to ${w.name} resumed.`);
        this.loadWebhooks();
      },
      error: (err: Error) => {
        this.busyId.set(null);
        this.error.set(err.message);
      },
    });
  }

  protected copyText(text: string, message: string): void {
    writeToClipboard(text, message, (msg) => this.notice.set(msg), (msg) => this.error.set(msg));
  }
}
