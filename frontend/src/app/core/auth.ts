import { Injectable, computed, inject, signal } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { HttpInterceptorFn } from '@angular/common/http';
import { tap } from 'rxjs/operators';
import { Observable } from 'rxjs';

import { Api } from './api';
import type { Identity, LoginResponse } from './models';

/** Where the bearer token is kept between reloads. */
const TOKEN_KEY = 'skm.token';

/**
 * Auth holds the signed-in identity.
 *
 * The token is mirrored into localStorage so a reload does not sign the user
 * out; the server also sets an HttpOnly cookie, and either is accepted. The
 * cookie is the safer of the two and is what the browser actually uses.
 */
@Injectable({ providedIn: 'root' })
export class Auth {
  private readonly api = inject(Api);
  private readonly router = inject(Router);

  readonly identity = signal<Identity | null>(null);
  readonly loading = signal(false);

  readonly isAuthenticated = computed(() => this.identity() !== null);
  readonly username = computed(() => this.identity()?.user.username ?? '');
  readonly roles = computed(() => this.identity()?.roles ?? []);
  readonly mfaVerified = computed(() => this.identity()?.mfa_verified ?? false);
  readonly totpEnrolled = computed(() => this.identity()?.user.totp_enrolled ?? false);

  /** can reports whether the signed-in user holds a permission. */
  can(permission: string): boolean {
    return this.identity()?.permissions.includes(permission) ?? false;
  }

  get token(): string | null {
    return localStorage.getItem(TOKEN_KEY);
  }

  login(username: string, password: string, totpCode?: string): Observable<LoginResponse> {
    return this.api.login(username, password, totpCode).pipe(
      tap((res) => {
        localStorage.setItem(TOKEN_KEY, res.token);
        this.identity.set({
          user: res.user,
          roles: res.roles,
          permissions: res.permissions,
          scopes: res.scopes ?? [],
          mfa_verified: res.mfa_verified,
          is_admin: res.permissions.length > 40,
        });
      }),
    );
  }

  logout(): void {
    this.api.logout().subscribe({
      complete: () => this.clear(),
      error: () => this.clear(),
    });
  }

  /**
   * restore re-establishes the session on page load.
   *
   * It resolves rather than rejects on failure: a stale token should land the
   * user on the sign-in page, not on an error.
   */
  restore(): Promise<void> {
    if (!this.token) {
      return Promise.resolve();
    }
    this.loading.set(true);
    return this.reload().finally(() => this.loading.set(false));
  }

  /**
   * reload re-reads the identity and resolves when it is in place — after a
   * password change, the guard must see the cleared flag before navigating.
   * A failed read clears the session rather than rejecting.
   */
  reload(): Promise<void> {
    if (!this.token) {
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      this.api.me().subscribe({
        next: (identity) => {
          this.identity.set(normalise(identity));
          resolve();
        },
        error: () => {
          this.clear();
          resolve();
        },
      });
    });
  }

  /** refresh re-reads the identity, picking up a step-up or a new enrolment. */
  refresh(): void {
    if (!this.token) return;
    this.api.me().subscribe({ next: (identity) => this.identity.set(normalise(identity)) });
  }

  private clear(): void {
    localStorage.removeItem(TOKEN_KEY);
    this.identity.set(null);
    void this.router.navigate(['/login']);
  }
}

/** normalise smooths over the one shape difference between /auth/me and login. */
function normalise(identity: Identity): Identity {
  return { ...identity, scopes: identity.scopes ?? [] };
}

/** authGuard keeps unauthenticated visitors on the sign-in page. */
export const authGuard: CanActivateFn = () => {
  const auth = inject(Auth);
  const router = inject(Router);

  if (auth.isAuthenticated()) {
    return true;
  }
  return router.createUrlTree(['/login']);
};

/**
 * passwordGuard sends an account that must change its password to the page
 * that does that, and nowhere else. The server enforces the same rule on the
 * API, so this is about not showing a wall of 403s rather than about security.
 */
export const passwordGuard: CanActivateFn = () => {
  const auth = inject(Auth);
  const router = inject(Router);

  if (auth.identity()?.user.must_change_password) {
    return router.createUrlTree(['/change-password']);
  }
  return true;
};

/** authInterceptor attaches the bearer token to every API request. */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token || !req.url.startsWith('/api/')) {
    return next(req);
  }
  return next(req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }));
};
