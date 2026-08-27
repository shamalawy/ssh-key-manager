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
              <a [routerLink]="item.path" routerLinkActive="active">
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
              <a class="mfa-warn small" routerLink="/settings/account">Second factor not enrolled</a>
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
    { path: '/overview', label: 'Overview', glyph: '▤' },
    { path: '/machines', label: 'Machines', glyph: '⬢' },
    { path: '/keys', label: 'Keys', glyph: '⚿' },
    { path: '/install', label: 'Install', glyph: '↗' },
    { path: '/rotation', label: 'Rotation', glyph: '⟳' },
    { path: '/settings', label: 'Settings', glyph: '⚒' },
  ];
}
