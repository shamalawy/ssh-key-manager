import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import { Auth } from '../../core/auth';
import { Confirm } from '../../shared/confirm';
import { Modal } from '../../shared/modal';
import { Alerts } from '../../shared/alerts';
import type { ApiToken, NewToken, PermissionInfo, Role, User } from '../../core/models';

/**
 * Accounts, roles, and API tokens on one screen.
 *
 * They belong together because they answer one question — who can do what —
 * and separating them means an administrator granting someone access has to
 * visit three places and hold the third in their head while looking at the
 * first.
 */
@Component({
  selector: 'skm-users',
  imports: [DatePipe, FormsModule, Modal, Alerts],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .tabs { display: flex; gap: 0.4rem; margin-bottom: 1.2rem; }
    .tabs button.on { border-color: var(--accent); color: var(--accent); }
    .roles { display: flex; gap: 0.3rem; flex-wrap: wrap; }
    .mono-sm { font-family: var(--mono); font-size: 0.78rem; }
    .secret { font-family: var(--mono); font-size: 0.82rem; word-break: break-all;
              background: var(--bg-sunken); border: 1px solid var(--border-soft);
              border-radius: var(--radius-md); padding: 0.7rem 0.9rem; }
    .permgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr));
                gap: 0.15rem 1rem; max-height: 20rem; overflow-y: auto;
                border: 1px solid var(--border-soft); border-radius: var(--radius-md);
                padding: 0.7rem 0.9rem; }
    .permgroup { grid-column: 1 / -1; font-size: 0.74rem; text-transform: uppercase;
                 letter-spacing: 0.06em; color: var(--text-dim); margin-top: 0.6rem; }
    .permgroup:first-child { margin-top: 0; }
    .req { color: var(--danger); }
    .spacer { flex: 1; }
  `],
  template: `
    <p class="muted" style="margin-bottom: 1.2rem;">Manage user accounts, roles, and API tokens.</p>

    <div class="card-header">
      <div class="row">
        @if (tab() === 'users' && auth.can('user.write')) {
          <button class="primary" type="button" (click)="openCreateUser()">Add user</button>
        }
        @if (tab() === 'tokens' && auth.can('api_token.write')) {
          <button class="primary" type="button" (click)="openCreateToken()">New API token</button>
        }
      </div>
    </div>

    <skm-alerts [error]="error" [notice]="notice" />

    <div class="tabs">
      <button class="ghost sm" type="button" [class.on]="tab() === 'users'"
              (click)="tab.set('users')">Users</button>
      <button class="ghost sm" type="button" [class.on]="tab() === 'roles'"
              (click)="tab.set('roles')">Roles</button>
      <button class="ghost sm" type="button" [class.on]="tab() === 'tokens'"
              (click)="tab.set('tokens')">API tokens</button>
    </div>

    <!-- Users ---------------------------------------------------------- -->
    @if (tab() === 'users') {
      <div class="card">
        @if (users().length === 0) {
          <div class="empty">No accounts to show.</div>
        } @else {
          <div class="table-wrap">
            <table>
              <thead>
                <tr><th>Username</th><th>Name</th><th>Roles</th><th>Second factor</th>
                    <th>State</th><th>Last sign-in</th><th></th></tr>
              </thead>
              <tbody>
                @for (u of users(); track u.id) {
                  <tr>
                    <td><strong class="mono-sm">{{ u.username }}</strong></td>
                    <td class="small">{{ u.display_name || '—' }}
                        @if (u.email) { <div class="small faint">{{ u.email }}</div> }</td>
                    <td><div class="roles">
                      @for (r of u.role_names ?? []; track r) { <span class="tag">{{ r }}</span> }
                      @if (!u.role_names?.length) { <span class="small faint">none</span> }
                    </div></td>
                    <td>
                      @if (u.totp_enrolled) { <span class="badge ok">enrolled</span> }
                      @else { <span class="badge warn">not enrolled</span> }
                    </td>
                    <td>
                      @if (!u.active) { <span class="badge neutral">disabled</span> }
                      @else if (locked(u)) { <span class="badge danger">locked</span> }
                      @else if (u.must_change_password) { <span class="badge warn">must change password</span> }
                      @else { <span class="badge ok">active</span> }
                    </td>
                    <td class="small faint">
                      {{ u.last_login_at ? (u.last_login_at | date:'MMM d, HH:mm') : 'never' }}
                    </td>
                    <td>
                      @if (auth.can('user.write')) {
                        <div class="row">
                          <button class="ghost sm" type="button" (click)="openEditUser(u)"
                                  [disabled]="busyId() !== null">Edit</button>
                          <button class="ghost sm" type="button" (click)="resetPassword(u)"
                                  [disabled]="busyId() !== null">
                            @if (busyId() === u.id) { <span class="spinner"></span> } Password
                          </button>
                          @if (u.id !== me() && u.totp_enrolled) {
                            <button class="ghost sm" type="button" (click)="resetTotp(u)"
                                    [disabled]="busyId() !== null">
                              @if (busyId() === u.id) { <span class="spinner"></span> } Reset 2FA
                            </button>
                          }
                          @if (u.id !== me()) {
                            <button class="ghost sm" type="button" (click)="removeUser(u)"
                                    [disabled]="busyId() !== null">
                              @if (busyId() === u.id) { <span class="spinner"></span> } Delete
                            </button>
                          }
                        </div>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </div>
    }

    <!-- Roles ---------------------------------------------------------- -->
    @if (tab() === 'roles') {
      <p class="small faint">
        Roles are fixed sets, seeded on first boot. The split that matters is
        operator against engineer: an operator runs rotations and installs
        that already exist, but cannot reveal a private key or restore a backup.
      </p>
      @for (r of roles(); track r.id) {
        <div class="card" style="margin-bottom: 0.9rem;">
          <div class="card-header">
            <h2>{{ r.name }}</h2>
            <span class="small faint">{{ r.permissions.length }} permission(s)</span>
          </div>
          <div class="card-body">
            <p class="small">{{ r.description }}</p>
            <div class="roles">
              @for (p of r.permissions; track p) { <span class="tag mono-sm">{{ p }}</span> }
            </div>
          </div>
        </div>
      }
    }

    <!-- Tokens --------------------------------------------------------- -->
    @if (tab() === 'tokens') {
      <p class="small faint">
        A token authenticates as the account behind it and can be narrowed below
        that account's rights, never above them. Tokens carry no second factor,
        so revealing a private key and restoring a backup stay closed to them.
      </p>

      @if (freshToken(); as t) {
        <div class="card" style="margin-bottom: 1.2rem; border-color: var(--accent);">
          <div class="card-header"><h2>{{ t.token.name }}</h2></div>
          <div class="card-body">
            <div class="notice warn">{{ t.notice }}</div>
            <div class="secret">{{ t.secret }}</div>
            <div class="row" style="margin-top: 0.7rem;">
              <button type="button" (click)="copy(t.secret, 'Token copied.')">Copy</button>
              <button class="ghost" type="button" (click)="freshToken.set(null)">Done</button>
            </div>
          </div>
        </div>
      }

      <div class="card">
        @if (tokens().length === 0) {
          <div class="empty">No API tokens yet.</div>
        } @else {
          <div class="table-wrap">
            <table>
              <thead>
                <tr><th>Name</th><th>Prefix</th><th>Owner</th><th>Permissions</th>
                    <th>State</th><th>Last used</th><th></th></tr>
              </thead>
              <tbody>
                @for (t of tokens(); track t.id) {
                  <tr>
                    <td><strong>{{ t.name }}</strong></td>
                    <td class="mono-sm">{{ t.prefix }}…</td>
                    <td class="small">{{ t.username || '—' }}</td>
                    <td class="small">
                      @if (t.permissions.length) { limited to {{ t.permissions.length }} permission(s) }
                      @else { <span class="faint">all of the account's permissions</span> }
                    </td>
                    <td>
                      <span class="badge" [class]="tokenClass(t)">{{ t.status }}</span>
                      @if (t.expires_at) {
                        <div class="small faint">expires {{ t.expires_at | date:'MMM d, y' }}</div>
                      }
                    </td>
                    <td class="small faint">
                      {{ t.last_used_at ? (t.last_used_at | date:'MMM d, HH:mm') : 'never' }}
                    </td>
                    <td>
                      @if (auth.can('api_token.write')) {
                        <div class="row">
                          @if (t.status === 'active') {
                            <button class="ghost sm" type="button" (click)="revoke(t)"
                                    [disabled]="busyId() !== null">
                              @if (busyId() === t.id) { <span class="spinner"></span> } Revoke
                            </button>
                          }
                          <button class="ghost sm" type="button" (click)="removeToken(t)"
                                  [disabled]="busyId() !== null">
                            @if (busyId() === t.id) { <span class="spinner"></span> } Delete
                          </button>
                        </div>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </div>
    }

    <!-- Create / edit user --------------------------------------------- -->
    @if (userForm(); as mode) {
      <skm-modal [title]="mode === 'create' ? 'Add a user' : 'Edit ' + draft.username"
                 (close)="userForm.set(null)">
        @if (formError(); as message) { <div class="notice error">{{ message }}</div> }

        @if (mode === 'create') {
          <label>
            <span class="label">Username <span class="req">*</span></span>
            <input [(ngModel)]="draft.username" name="u-username" placeholder="jordan" />
          </label>
          <label>
            <span class="label">Password <span class="req">*</span></span>
            <input type="password" [(ngModel)]="draft.password" name="u-password"
                   autocomplete="new-password" />
            <span class="hint">
              At least 12 characters. Length is the property that costs an
              attacker something; composition rules mostly produce Password1!.
            </span>
          </label>
        }

        <div class="grid cols-2">
          <label>
            <span class="label">Display name</span>
            <input [(ngModel)]="draft.displayName" name="u-display" />
          </label>
          <label>
            <span class="label">Email</span>
            <input [(ngModel)]="draft.email" name="u-email" />
          </label>
        </div>

        <span class="label">Roles</span>
        <div class="permgrid" style="max-height: 12rem;">
          @for (r of roles(); track r.id) {
            <label class="checkbox" style="margin: 0;">
              <input type="checkbox" [checked]="draft.roles.includes(r.name)"
                     (change)="toggleRole(r.name)" [name]="'role-' + r.name" />
              <span>{{ r.name }} <span class="small faint">— {{ r.description }}</span></span>
            </label>
          }
        </div>

        <div class="row" style="gap: 1.2rem; margin: 0.9rem 0;">
          <label class="checkbox" style="margin: 0;">
            <input type="checkbox" [(ngModel)]="draft.active" name="u-active" />
            <span>Active</span>
          </label>
          <label class="checkbox" style="margin: 0;">
            <input type="checkbox" [(ngModel)]="draft.mustChange" name="u-mustchange" />
            <span>Must change password at next sign-in</span>
          </label>
          @if (mode === 'edit') {
            <label class="checkbox" style="margin: 0;">
              <input type="checkbox" [(ngModel)]="draft.unlock" name="u-unlock" />
              <span>Clear failed-login lockout</span>
            </label>
          }
        </div>

        <div class="row end">
          <button type="button" (click)="userForm.set(null)">Cancel</button>
          <button class="primary" type="button" [disabled]="busy() || !canSaveUser()"
                  (click)="saveUser()">
            @if (busy()) { <span class="spinner"></span> }
            {{ mode === 'create' ? 'Add' : 'Save' }}
          </button>
        </div>
      </skm-modal>
    }

    <!-- Create token --------------------------------------------------- -->
    @if (tokenForm()) {
      <skm-modal title="New API token" [wide]="true" (close)="tokenForm.set(false)">
        @if (formError(); as message) { <div class="notice error">{{ message }}</div> }

        <div class="grid cols-2">
          <label>
            <span class="label">Name <span class="req">*</span></span>
            <input [(ngModel)]="tokenDraft.name" name="t-name" placeholder="ci-rotate-nightly" />
          </label>
          <label>
            <span class="label">Expires after</span>
            <select [(ngModel)]="tokenDraft.expiresIn" name="t-expires">
              <option value="">never</option>
              <option value="24h">a day</option>
              <option value="720h">30 days</option>
              <option value="2160h">90 days</option>
              <option value="8760h">a year</option>
            </select>
          </label>
        </div>

        <label>
          <span class="label">Restrict to tags</span>
          <input [(ngModel)]="tokenDraft.scopes" name="t-scopes" placeholder="staging, lab" />
          <span class="hint">Leave empty for every resource the account can reach.</span>
        </label>

        <div class="row" style="align-items: baseline;">
          <span class="label">Permissions</span>
          <span class="spacer"></span>
          <span class="small faint">
            {{ tokenDraft.permissions.length || 'none selected — the token inherits the account\\'s rights' }}
          </span>
          @if (tokenDraft.permissions.length) {
            <button class="ghost sm" type="button" (click)="tokenDraft.permissions = []">Clear</button>
          }
        </div>
        <div class="permgrid">
          @for (group of permissionGroups(); track group.name) {
            <div class="permgroup">{{ group.name }}</div>
            @for (p of group.items; track p.name) {
              <label class="checkbox" style="margin: 0;">
                <input type="checkbox" [checked]="tokenDraft.permissions.includes(p.name)"
                       (change)="togglePermission(p.name)" [name]="'perm-' + p.name" />
                <span class="mono-sm">{{ p.name }}</span>
              </label>
            }
          }
        </div>

        <div class="row end" style="margin-top: 1rem;">
          <button type="button" (click)="tokenForm.set(false)">Cancel</button>
          <button class="primary" type="button" [disabled]="busy() || !tokenDraft.name"
                  (click)="createToken()">
            @if (busy()) { <span class="spinner"></span> } Create
          </button>
        </div>
      </skm-modal>
    }
  `,
})
export class UsersPage implements OnInit {
  private readonly api = inject(Api);
  protected readonly auth = inject(Auth);
  private readonly confirm = inject(Confirm);

  protected readonly tab = signal<'users' | 'roles' | 'tokens'>('users');
  protected readonly users = signal<User[]>([]);
  protected readonly roles = signal<Role[]>([]);
  protected readonly tokens = signal<ApiToken[]>([]);
  protected readonly permissions = signal<PermissionInfo[]>([]);
  protected readonly freshToken = signal<NewToken | null>(null);

  protected readonly userForm = signal<'create' | 'edit' | null>(null);
  protected readonly tokenForm = signal(false);
  protected readonly busy = signal(false);
  protected readonly busyId = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly formError = signal<string | null>(null);

  protected readonly me = computed(() => this.auth.identity()?.user.id ?? '');

  /** Permissions grouped by resource, so the list reads as sections. */
  protected readonly permissionGroups = computed(() => {
    const groups = new Map<string, PermissionInfo[]>();
    for (const p of this.permissions()) {
      const existing = groups.get(p.group);
      if (existing) existing.push(p);
      else groups.set(p.group, [p]);
    }
    return [...groups.entries()].map(([name, items]) => ({ name, items }));
  });

  private editingId = '';

  protected draft = {
    username: '', password: '', email: '', displayName: '',
    roles: [] as string[], active: true, mustChange: true, unlock: false,
  };

  protected tokenDraft = { name: '', expiresIn: '720h', scopes: '', permissions: [] as string[] };

  ngOnInit(): void {
    this.reload();
  }

  protected reload(): void {
    this.api.listUsers().subscribe({
      next: (r) => this.users.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
    this.api.listRoles().subscribe({
      next: (r) => this.roles.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
    this.api.listPermissions().subscribe({
      next: (r) => this.permissions.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
    this.api.listTokens().subscribe({
      next: (r) => this.tokens.set(r.items),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected locked(u: User): boolean {
    return !!u.locked_until && new Date(u.locked_until) > new Date();
  }

  protected tokenClass(t: ApiToken): string {
    switch (t.status) {
      case 'active': return 'ok';
      case 'expired': return 'warn';
      default: return 'neutral';
    }
  }

  protected toggleRole(name: string): void {
    const roles = this.draft.roles;
    this.draft.roles = roles.includes(name) ? roles.filter((r) => r !== name) : [...roles, name];
  }

  protected togglePermission(name: string): void {
    const perms = this.tokenDraft.permissions;
    this.tokenDraft.permissions = perms.includes(name)
      ? perms.filter((p) => p !== name)
      : [...perms, name];
  }

  protected canSaveUser(): boolean {
    if (this.userForm() === 'edit') return true;
    return this.draft.username.trim().length > 0 && this.draft.password.length >= 12;
  }

  protected openCreateUser(): void {
    this.draft = {
      username: '', password: '', email: '', displayName: '',
      roles: ['viewer'], active: true, mustChange: true, unlock: false,
    };
    this.formError.set(null);
    this.userForm.set('create');
  }

  protected openEditUser(u: User): void {
    this.editingId = u.id;
    this.draft = {
      username: u.username, password: '', email: u.email, displayName: u.display_name,
      roles: [...(u.role_names ?? [])], active: u.active, mustChange: u.must_change_password,
      unlock: false,
    };
    this.formError.set(null);
    this.userForm.set('edit');
  }

  protected saveUser(): void {
    this.busy.set(true);
    this.formError.set(null);

    const done = (message: string) => {
      this.busy.set(false);
      this.userForm.set(null);
      this.notice.set(message);
      this.reload();
    };
    const failed = (err: Error) => {
      this.busy.set(false);
      this.formError.set(err.message);
    };

    if (this.userForm() === 'create') {
      this.api.createUser({
        username: this.draft.username,
        password: this.draft.password,
        email: this.draft.email,
        display_name: this.draft.displayName,
        roles: this.draft.roles,
        must_change_password: this.draft.mustChange,
        active: this.draft.active,
      }).subscribe({
        next: (u) => done(`Added ${u.username}.`),
        error: failed,
      });
      return;
    }

    this.api.updateUser(this.editingId, {
      email: this.draft.email,
      display_name: this.draft.displayName,
      roles: this.draft.roles,
      active: this.draft.active,
      must_change_password: this.draft.mustChange,
      unlock: this.draft.unlock,
    }).subscribe({
      next: (u) => done(`Saved ${u.username}.`),
      error: failed,
    });
  }

  protected resetPassword(u: User): void {
    this.busyId.set(u.id);
    this.confirm.prompt({
      title: `New password for ${u.username}`,
      message: 'At least 12 characters. They will be asked to change it at next sign-in.',
      label: 'New password',
      type: 'password',
      minLength: 12,
      action: 'Set password',
    }).then((password) => {
      this.busyId.set(null);
      if (!password) return;

      this.busyId.set(u.id);
      this.api.setUserPassword(u.id, password, true).subscribe({
        next: () => {
          this.busyId.set(null);
          this.notice.set(`Password reset for ${u.username}.`);
          this.reload();
        },
        error: (err: Error) => {
          this.busyId.set(null);
          this.error.set(err.message);
        },
      });
    });
  }

  protected resetTotp(u: User): void {
    this.busyId.set(u.id);
    this.confirm.ask({
      title: `Clear the second factor on ${u.username}?`,
      message: 'This turns a two-factor account into a one-factor one until they enrol again. Do it only when you have confirmed who you are talking to.',
      action: 'Clear',
      danger: true,
    }).then((ok) => {
      this.busyId.set(null);
      if (!ok) return;

      this.busyId.set(u.id);
      this.api.resetUserTotp(u.id).subscribe({
        next: () => {
          this.busyId.set(null);
          this.notice.set(`${u.username} can now enrol a second factor again.`);
          this.reload();
        },
        error: (err: Error) => {
          this.busyId.set(null);
          this.error.set(err.message);
        },
      });
    });
  }

  protected removeUser(u: User): void {
    this.busyId.set(u.id);
    this.confirm.ask({
      title: `Delete ${u.username}?`,
      message: 'Their sessions, role grants, and API tokens go with the account. Their entries in the audit log stay.',
      action: 'Delete',
      danger: true,
    }).then((ok) => {
      this.busyId.set(null);
      if (!ok) return;

      this.busyId.set(u.id);
      this.api.deleteUser(u.id).subscribe({
        next: () => {
          this.busyId.set(null);
          this.notice.set(`Deleted ${u.username}.`);
          this.reload();
        },
        error: (err: Error) => {
          this.busyId.set(null);
          this.error.set(err.message);
        },
      });
    });
  }

  protected openCreateToken(): void {
    this.tokenDraft = { name: '', expiresIn: '720h', scopes: '', permissions: [] };
    this.formError.set(null);
    this.freshToken.set(null);
    this.tokenForm.set(true);
  }

  protected createToken(): void {
    this.busy.set(true);
    this.formError.set(null);

    this.api.createToken({
      name: this.tokenDraft.name,
      permissions: this.tokenDraft.permissions,
      scopes: this.tokenDraft.scopes.split(',').map((s) => s.trim()).filter(Boolean),
      expires_in: this.tokenDraft.expiresIn || undefined,
    }).subscribe({
      next: (t) => {
        this.busy.set(false);
        this.tokenForm.set(false);
        this.freshToken.set(t);
        this.tab.set('tokens');
        this.reload();
      },
      error: (err: Error) => {
        this.busy.set(false);
        this.formError.set(err.message);
      },
    });
  }

  protected revoke(t: ApiToken): void {
    this.busyId.set(t.id);
    this.confirm.ask({
      title: `Revoke "${t.name}"?`,
      message: 'Anything using it stops working immediately.',
      action: 'Revoke',
      danger: true,
    }).then((ok) => {
      this.busyId.set(null);
      if (!ok) return;

      this.busyId.set(t.id);
      this.api.revokeToken(t.id).subscribe({
        next: () => {
          this.busyId.set(null);
          this.notice.set(`Revoked ${t.name}.`);
          this.reload();
        },
        error: (err: Error) => {
          this.busyId.set(null);
          this.error.set(err.message);
        },
      });
    });
  }

  protected removeToken(t: ApiToken): void {
    this.busyId.set(t.id);
    this.confirm.ask({
      title: `Delete the record of "${t.name}"?`,
      action: 'Delete',
      danger: true,
    }).then((ok) => {
      this.busyId.set(null);
      if (!ok) return;

      this.busyId.set(t.id);
      this.api.deleteToken(t.id).subscribe({
        next: () => {
          this.busyId.set(null);
          this.notice.set(`Deleted the record of ${t.name}.`);
          this.reload();
        },
        error: (err: Error) => {
          this.busyId.set(null);
          this.error.set(err.message);
        },
      });
    });
  }

  protected copy(text: string, message: string): void {
    navigator.clipboard.writeText(text).then(
      () => this.notice.set(message),
      () => this.error.set('The browser refused clipboard access; select and copy by hand.'),
    );
  }
}
