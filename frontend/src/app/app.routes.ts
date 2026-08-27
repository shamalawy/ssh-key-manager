import { Routes } from '@angular/router';

import { authGuard, passwordGuard } from './core/auth';
import { Shell } from './layout/shell';

/**
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
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      {
        path: 'dashboard',
        loadComponent: () => import('./pages/dashboard/dashboard').then((m) => m.DashboardPage),
        title: 'Dashboard · SKM',
      },
      {
        path: 'keys',
        loadComponent: () => import('./pages/keys/keys').then((m) => m.KeysPage),
        title: 'Keys · SKM',
      },
      {
        path: 'targets',
        loadComponent: () => import('./pages/targets/targets').then((m) => m.TargetsPage),
        title: 'Targets · SKM',
      },
      {
        path: 'credentials',
        loadComponent: () => import('./pages/credentials/credentials').then((m) => m.CredentialsPage),
        title: 'Credentials · SKM',
      },
      {
        path: 'deploy',
        loadComponent: () => import('./pages/deploy/deploy').then((m) => m.DeployPage),
        title: 'Deploy · SKM',
      },
      {
        path: 'rotations',
        loadComponent: () => import('./pages/rotations/rotations').then((m) => m.RotationsPage),
        title: 'Rotation · SKM',
      },
      {
        path: 'inventory',
        loadComponent: () => import('./pages/inventory/inventory').then((m) => m.InventoryPage),
        title: 'Key inventory · SKM',
      },
      {
        path: 'jobs',
        loadComponent: () => import('./pages/jobs/jobs').then((m) => m.JobsPage),
        title: 'Jobs · SKM',
      },
      {
        path: 'backups',
        loadComponent: () => import('./pages/backups/backups').then((m) => m.BackupsPage),
        title: 'Backups · SKM',
      },
      {
        path: 'audit',
        loadComponent: () => import('./pages/audit/audit').then((m) => m.AuditPage),
        title: 'Audit · SKM',
      },
      {
        path: 'users',
        loadComponent: () => import('./pages/users/users').then((m) => m.UsersPage),
        title: 'Users and access · SKM',
      },
      {
        path: 'api',
        loadComponent: () => import('./pages/apidocs/apidocs').then((m) => m.ApiDocsPage),
        title: 'API reference · SKM',
      },
      {
        path: 'settings',
        loadComponent: () => import('./pages/settings/settings').then((m) => m.SettingsPage),
        title: 'Settings · SKM',
      },
    ],
  },
  { path: '**', redirectTo: '' },
];
