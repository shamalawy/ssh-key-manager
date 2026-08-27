import { Routes } from '@angular/router';

import { authGuard, passwordGuard } from './core/auth';
import { Shell } from './layout/shell';

/**
 * Six places to be: Overview, Machines, Keys, Install, Rotation, Settings.
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
        path: 'machines',
        loadComponent: () => import('./pages/machines/machines').then((m) => m.MachinesPage),
        children: [
          {
            path: '',
            loadComponent: () => import('./pages/machines/list').then((m) => m.MachineListPage),
            title: 'Machines · SKM',
          },
          {
            path: 'connections',
            loadComponent: () => import('./pages/machines/connections').then((m) => m.ConnectionsPage),
            title: 'Connections · SKM',
          },
          {
            path: 'health',
            loadComponent: () => import('./pages/machines/health').then((m) => m.FleetHealthPage),
            title: 'Fleet health · SKM',
          },
        ],
      },
      {
        path: 'keys',
        loadComponent: () => import('./pages/keys/keys').then((m) => m.KeysPage),
        title: 'Keys · SKM',
      },
      {
        path: 'install',
        loadComponent: () => import('./pages/install/install').then((m) => m.InstallPage),
        title: 'Install · SKM',
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
      { path: 'targets', redirectTo: 'machines' },
      { path: 'credentials', redirectTo: 'machines/connections' },
      { path: 'inventory', redirectTo: 'machines/health' },
      { path: 'deploy', redirectTo: 'install' },
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
