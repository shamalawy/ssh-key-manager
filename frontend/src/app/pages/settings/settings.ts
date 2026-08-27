import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { Auth } from '../../core/auth';

/**
 * SettingsPage frames everything that is not day-to-day key work: your own
 * account, other people's, backups, the job queue, the audit trail,
 * notifications, the API reference and the vault. Tabs the account cannot
 * use are not shown rather than shown disabled.
 */
@Component({
  selector: 'skm-settings',
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1>Settings</h1>
    <nav class="tabs" aria-label="Settings sections">
      @for (tab of tabs; track tab.path) {
        @if (!tab.permission || auth.can(tab.permission)) {
          <a [routerLink]="tab.path" routerLinkActive="active">{{ tab.label }}</a>
        }
      }
    </nav>
    <router-outlet />
  `,
})
export class SettingsPage {
  protected readonly auth = inject(Auth);

  protected readonly tabs = [
    { path: '/settings/account', label: 'Account' },
    { path: '/settings/users', label: 'Users & tokens', permission: 'user.read' },
    { path: '/settings/backups', label: 'Backups', permission: 'backup.read' },
    { path: '/settings/jobs', label: 'Jobs', permission: 'job.read' },
    { path: '/settings/audit', label: 'Audit trail', permission: 'audit.read' },
    { path: '/settings/notifications', label: 'Notifications', permission: 'webhook.read' },
    { path: '/settings/api', label: 'API' },
    { path: '/settings/vault', label: 'Vault', permission: 'vault.status' },
  ];
}
