import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

/**
 * MachinesPage frames everything about the fleet: the machines themselves,
 * the saved connections SKM uses to reach them, and how healthy they are.
 * Each tab is its own routed component so a link can land on one directly.
 */
@Component({
  selector: 'skm-machines',
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1>Machines</h1>
    <nav class="tabs" aria-label="Machines sections">
      <a routerLink="/machines" routerLinkActive="active" [routerLinkActiveOptions]="{ exact: true }">Machines</a>
      <a routerLink="/machines/connections" routerLinkActive="active">Connections</a>
      <a routerLink="/machines/health" routerLinkActive="active">Fleet health</a>
    </nav>
    <router-outlet />
  `,
})
export class MachinesPage {}
