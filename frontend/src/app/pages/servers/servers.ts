import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

/**
 * ServersPage frames everything about the fleet: the machines themselves,
 * the saved connections SKM uses to reach them, and how healthy they are.
 * Each tab is its own routed component so a link can land on one directly.
 */
@Component({
  selector: 'skm-servers',
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1>Servers</h1>
    <nav class="tabs" aria-label="Servers sections">
      <a routerLink="/servers" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: true }">Servers</a>
      <a routerLink="/servers/connections" routerLinkActive="active">Connections</a>
      <a routerLink="/servers/health" routerLinkActive="active">Fleet health</a>
    </nav>
    <router-outlet />
  `,
})
export class ServersPage {}
