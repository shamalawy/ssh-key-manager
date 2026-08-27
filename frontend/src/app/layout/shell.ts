import { Component, ChangeDetectionStrategy, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { Auth } from '../core/auth';
import { ConfirmHost } from '../shared/confirm';

/** Shell is the signed-in frame: navigation, identity, and the routed page. */
@Component({
  selector: 'skm-shell',
  imports: [RouterLink, RouterLinkActive, RouterOutlet, ConfirmHost],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrl: './shell.scss',
  template: `
    <div class="shell">
      <nav class="sidebar">
        <div class="brand">
          <span class="mark">SKM</span>
          <span class="brand-sub">SSH Key Manager</span>
        </div>

        <ul class="nav">
          @for (item of navigation; track item.path) {
            <li>
              <a [routerLink]="item.path" routerLinkActive="active"
                 [routerLinkActiveOptions]="{ exact: item.exact ?? false }">
                <span class="glyph" aria-hidden="true">{{ item.glyph }}</span>
                {{ item.label }}
              </a>
            </li>
          }
        </ul>

        <div class="identity">
          @if (auth.identity(); as me) {
            <div class="who">
              <div class="name">{{ me.user.username }}</div>
              <div class="roles small faint">{{ me.roles.join(', ') || 'no roles' }}</div>
            </div>
            @if (!me.user.totp_enrolled) {
              <a class="mfa-warn small" routerLink="/settings">Second factor not enrolled</a>
            }
            <button class="ghost sm" type="button" (click)="auth.logout()">Sign out</button>
          }
        </div>
      </nav>

      <main class="content">
        <router-outlet />
      </main>
      <skm-confirm-host />
    </div>
  `,
})
export class Shell {
  protected readonly auth = inject(Auth);

  protected readonly navigation = [
    { path: '/dashboard', label: 'Dashboard', glyph: '▤', exact: true },
    { path: '/keys', label: 'Keys', glyph: '⚿' },
    { path: '/targets', label: 'Targets', glyph: '⬢' },
    { path: '/credentials', label: 'Credentials', glyph: '⚷' },
    { path: '/deploy', label: 'Deploy', glyph: '↗' },
    { path: '/rotations', label: 'Rotation', glyph: '⟳' },
    { path: '/inventory', label: 'Inventory', glyph: '◈' },
    { path: '/jobs', label: 'Jobs', glyph: '⚙' },
    { path: '/backups', label: 'Backups', glyph: '⬇' },
    { path: '/audit', label: 'Audit', glyph: '☰' },
    { path: '/users', label: 'Users', glyph: '☺' },
    { path: '/api', label: 'API', glyph: '⌘' },
    { path: '/settings', label: 'Settings', glyph: '⚒' },
  ];
}
