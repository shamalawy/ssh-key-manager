import { Routes } from '@angular/router';

import { authGuard, passwordGuard } from './core/auth';
import { Shell } from './layout/shell';

/**
 * Seven places to be: Overview, Servers, Clients, Keys, Deploy, Rotation, Settings.
 * Servers get the public key; clients get the private key; Deploy does both.
 * Everything else lives as a tab inside one of those. The old one-page-per-
 * concept paths redirect so bookmarks and the CLI's printed links keep working.
 *
 * Pages are lazily loaded so the sign-in screen does not carry the weight of
 * the whole application.
 */
export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () => import('./pages/login/login').then((m) => m.Login),
    title: 'Sign in · SKM',
  },
  {
    path: 'change-password',
    loadComponent: () => import('./pages/change-password/change-password').then((m) => m.ChangePasswordPage),
    canActivate: [authGuard],
    title: 'Choose a new password · SKM',
  },
  {
    path: '',
    component: Shell,
    canActivate: [authGuard, passwordGuard],
    canActivateChild: [passwordGuard],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'overview' },
      {
        path: 'overview',
        loadComponent: () => import('./pages/overview/overview').then((m) => m.OverviewPage),
        title: 'Overview · SKM',
      },
      {
        path: 'servers',
        loadComponent: () => import('./pages/servers/servers').then((m) => m.ServersPage),
        children: [
          {
            path: '',
            loadComponent: () => import('./pages/servers/list').then((m) => m.ServerListPage),
            title: 'Servers · SKM',
          },
          {
            path: 'connections',
            loadComponent: () => import('./pages/servers/connections').then((m) => m.ConnectionsPage),
            title: 'Connections · SKM',
          },
          {
            path: 'health',
            loadComponent: () => import('./pages/servers/health').then((m) => m.FleetHealthPage),
            title: 'Fleet health · SKM',
          },
        ],
      },
      {
        path: 'clients',
        loadComponent: () => import('./pages/clients/clients').then((m) => m.ClientsPage),
        title: 'Clients · SKM',
      },
      {
        path: 'keys',
        loadComponent: () => import('./pages/keys/keys').then((m) => m.KeysPage),
        title: 'Keys · SKM',
      },
      {
        path: 'deploy',
        loadComponent: () => import('./pages/deploy/deploy').then((m) => m.DeployPage),
        title: 'Deploy · SKM',
      },
      {
        path: 'rotation',
        loadComponent: () => import('./pages/rotation/rotation').then((m) => m.RotationPage),
        title: 'Rotation · SKM',
      },
      {
        path: 'settings',
        loadComponent: () => import('./pages/settings/settings').then((m) => m.SettingsPage),
        children: [
          { path: '', pathMatch: 'full', redirectTo: 'account' },
          {
            path: 'account',
            loadComponent: () => import('./pages/settings/account').then((m) => m.AccountSettings),
            title: 'Account · SKM',
          },
          {
            path: 'users',
            loadComponent: () => import('./pages/settings/users').then((m) => m.UsersPage),
            title: 'Users and tokens · SKM',
          },
          {
            path: 'backups',
            loadComponent: () => import('./pages/settings/backups').then((m) => m.BackupsPage),
            title: 'Backups · SKM',
          },
          {
            path: 'jobs',
            loadComponent: () => import('./pages/settings/jobs').then((m) => m.JobsPage),
            title: 'Jobs · SKM',
          },
          {
            path: 'audit',
            loadComponent: () => import('./pages/settings/audit').then((m) => m.AuditPage),
            title: 'Audit trail · SKM',
          },
          {
            path: 'notifications',
            loadComponent: () => import('./pages/settings/notifications').then((m) => m.NotificationSettings),
            title: 'Notifications · SKM',
          },
          {
            path: 'api',
            loadComponent: () => import('./pages/settings/api').then((m) => m.ApiDocsPage),
            title: 'API reference · SKM',
          },
          {
            path: 'vault',
            loadComponent: () => import('./pages/settings/vault').then((m) => m.VaultSettings),
            title: 'Vault · SKM',
          },
        ],
      },

      // Paths from before the six-item navigation.
      { path: 'dashboard', redirectTo: 'overview' },
      { path: 'targets', redirectTo: 'servers' },
      { path: 'machines', redirectTo: 'servers' },
      { path: 'machines/connections', redirectTo: 'servers/connections' },
      { path: 'machines/health', redirectTo: 'servers/health' },
      { path: 'credentials', redirectTo: 'servers/connections' },
      { path: 'inventory', redirectTo: 'servers/health' },
      { path: 'install', redirectTo: 'deploy' },
      { path: 'rotations', redirectTo: 'rotation' },
      { path: 'users', redirectTo: 'settings/users' },
      { path: 'backups', redirectTo: 'settings/backups' },
      { path: 'jobs', redirectTo: 'settings/jobs' },
      { path: 'audit', redirectTo: 'settings/audit' },
      { path: 'api', redirectTo: 'settings/api' },
    ],
  },
  { path: '**', redirectTo: '' },
];
