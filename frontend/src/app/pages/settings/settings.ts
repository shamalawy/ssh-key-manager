import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { Api, mfaRequired } from '../../core/api';
import { Auth } from '../../core/auth';
import { Alerts } from '../../shared/alerts';
import { Confirm } from '../../shared/confirm';
import { StepUp } from '../../shared/stepup';
import type { SystemStatus, TotpEnrolment, VaultStatus, Webhook, WebhookDelivery } from '../../core/models';

@Component({
  selector: 'skm-settings',
  imports: [Alerts, FormsModule, StepUp],
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
    <h1>Settings</h1>

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
      <div class="card-header"><h2>Webhooks</h2></div>
      <div class="card-body">
        <p class="small faint">
          Signed notifications for key, rotation, drift, and deployment events.
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
            @if (busy()) { <span class="spinner"></span> } Add webhook
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
          <div class="empty">No webhooks configured.</div>
        }
      </div>
    </div>

    <div class="card" style="margin-bottom: 1.4rem;">
      <div class="card-header"><h2>Scheduler</h2></div>
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
            lock. Scaling out multiplies throughput without running every policy twice.
          </p>
        } @else {
          <div class="empty"><span class="spinner"></span> Loading…</div>
        }
      </div>
    </div>

    <div class="card">
      <div class="card-header"><h2>Your access</h2></div>
      @if (auth.identity(); as me) {
        <div class="grid cols-2">
          <div><span class="label small faint">Username</span><div>{{ me.user.username }}</div></div>
          <div><span class="label small faint">Roles</span><div>{{ me.roles.join(', ') || '—' }}</div></div>
        </div>
        <div style="margin-top: 0.9rem;">
          <span class="label small faint">Permissions ({{ me.permissions.length }})</span>
          <div>@for (p of me.permissions; track p) { <span class="tag">{{ p }}</span> }</div>
        </div>
      }
    </div>
  `,
})
export class SettingsPage implements OnInit {
  private readonly api = inject(Api);
  private readonly confirmDialog = inject(Confirm);
  protected readonly auth = inject(Auth);

  protected readonly vault = signal<VaultStatus | null>(null);
  protected readonly enrolment = signal<TotpEnrolment | null>(null);
  protected readonly freshCodes = signal<string[] | null>(null);
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);

  protected readonly status = signal<SystemStatus | null>(null);
  protected readonly webhooks = signal<Webhook[]>([]);
  protected readonly deliveries = signal<WebhookDelivery[]>([]);
  protected readonly eventTypes = signal<string[]>([]);
  protected readonly newSecret = signal<string | null>(null);

  protected readonly needsStepUp = signal(false);
  protected readonly busyId = signal<string | null>(null);
  protected pending: (() => void) | null = null;

  protected stepUpCode = '';
  protected confirmCode = '';
  protected manageCode = '';
  protected passwords = { current: '', next: '', confirm: '' };
  protected hookName = '';
  protected hookUrl = '';
  protected readonly hookEvents = new Set<string>();

  ngOnInit(): void {
    this.loadVault();
    this.api.status().subscribe({ next: (st) => this.status.set(st) });
    this.api.eventTypes().subscribe({ next: (res) => this.eventTypes.set(res.events) });
    this.loadWebhooks();
  }

  protected runPending(): void {
    if (this.pending) {
      this.pending();
      this.pending = null;
    }
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
      title: `Delete the webhook "${w.name}"?`,
      message: 'This removes the webhook and its delivery history.',
      action: 'Delete',
      danger: true,
    }))) return;

    this.busyId.set(w.id);
    this.api.deleteWebhook(w.id).subscribe({
      next: () => {
        this.busyId.set(null);
        this.notice.set(`Deleted the webhook "${w.name}".`);
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

  private loadVault(): void {
    this.api.vaultStatus().subscribe({
      next: (v) => this.vault.set(v),
      error: (err: Error) => this.error.set(err.message),
    });
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

}
