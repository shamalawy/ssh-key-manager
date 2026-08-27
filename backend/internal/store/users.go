package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/db"
)

// User is a local account.
type User struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"-"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"display_name"`
	PasswordHash string    `json:"-"`

	TOTPSecret    string   `json:"-"`
	TOTPEnrolled  bool     `json:"totp_enrolled"`
	RecoveryCodes []string `json:"-"`

	Active       bool       `json:"active"`
	MustChangePW bool       `json:"must_change_password"`
	FailedLogins int        `json:"-"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Roles and Permissions are populated by LoadSubject, not by a plain Get.
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// Locked reports whether the account is currently barred from signing in.
func (u *User) Locked() bool {
	return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}

// Role is a named set of permissions.
type Role struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"-"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Users is the repository for accounts, roles, and their bindings.
type Users struct{ pool *db.Pool }

// NewUsers returns a Users repository.
func NewUsers(pool *db.Pool) *Users { return &Users{pool: pool} }

const userColumns = `id, tenant_id, username, email, display_name, password_hash,
	totp_secret, totp_enrolled, recovery_codes, active, must_change_pw,
	failed_logins, locked_until, last_login_at, created_at, updated_at`

// Create inserts a user.
func (s *Users) Create(ctx context.Context, u *User) (*User, error) {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.TenantID == uuid.Nil {
		u.TenantID = DefaultTenantID
	}
	if u.RecoveryCodes == nil {
		u.RecoveryCodes = []string{}
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO users (id, tenant_id, username, email, display_name,
			password_hash, totp_secret, totp_enrolled, recovery_codes,
			active, must_change_pw)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING `+userColumns,
		u.ID, u.TenantID, u.Username, u.Email, u.DisplayName,
		u.PasswordHash, u.TOTPSecret, u.TOTPEnrolled, u.RecoveryCodes,
		u.Active, u.MustChangePW)

	created, err := scanUser(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: a user named %q already exists", ErrConflict, u.Username)
		}
		return nil, fmt.Errorf("store: inserting user: %w", err)
	}
	return created, nil
}

// Get returns a user by ID.
func (s *Users) Get(ctx context.Context, tenantID, id uuid.UUID) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: user %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading user: %w", err)
	}
	return u, nil
}

// GetByUsername returns a user by login name.
func (s *Users) GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE tenant_id = $1 AND username = $2`, tenantID, username)

	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: user %q", ErrNotFound, username)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading user: %w", err)
	}
	return u, nil
}

// List returns every user in the tenant.
func (s *Users) List(ctx context.Context, tenantID uuid.UUID) ([]User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+userColumns+` FROM users WHERE tenant_id = $1 ORDER BY username`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: listing users: %w", err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning user: %w", err)
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// RecordLogin resets the failure counter and stamps the login time.
func (s *Users) RecordLogin(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET last_login_at = now(), failed_logins = 0, locked_until = NULL,
		 updated_at = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: recording login: %w", err)
	}
	return nil
}

// RecordFailedLogin increments the failure counter and locks the account once
// it crosses the threshold.
//
// Locking is time-boxed rather than permanent: a permanent lock turns a failed
// password guess into a denial of service against a legitimate user.
func (s *Users) RecordFailedLogin(ctx context.Context, id uuid.UUID, threshold int, lockFor time.Duration) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users
		SET failed_logins = failed_logins + 1,
		    locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + $3::interval ELSE locked_until END,
		    updated_at = now()
		WHERE id = $1`, id, threshold, lockFor.String())
	if err != nil {
		return fmt.Errorf("store: recording failed login: %w", err)
	}
	return nil
}

// SetPassword replaces a user's password hash.
func (s *Users) SetPassword(ctx context.Context, id uuid.UUID, hash string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, must_change_pw = false, updated_at = now() WHERE id = $1`,
		id, hash)
	if err != nil {
		return fmt.Errorf("store: setting password: %w", err)
	}
	return nil
}

// SetTOTP enrols or clears a user's second factor.
func (s *Users) SetTOTP(ctx context.Context, id uuid.UUID, secret string, enrolled bool, recoveryCodes []string) error {
	if recoveryCodes == nil {
		recoveryCodes = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET totp_secret = $2, totp_enrolled = $3, recovery_codes = $4, updated_at = now()
		WHERE id = $1`, id, secret, enrolled, recoveryCodes)
	if err != nil {
		return fmt.Errorf("store: setting TOTP: %w", err)
	}
	return nil
}

// SetActive enables or disables an account.
func (s *Users) SetActive(ctx context.Context, tenantID, id uuid.UUID, active bool) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET active = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, active)
	if err != nil {
		return fmt.Errorf("store: setting user active state: %w", err)
	}
	return nil
}

// ------------------------------------------------------------------- roles ---

// EnsureSystemRoles seeds the built-in roles, updating their permission sets if
// the definitions in code have changed.
//
// System roles are reconciled from code on every boot rather than edited in the
// database: it means an upgrade that adds a permission grants it to the right
// roles automatically, and it means nobody can lock everyone out by editing the
// admin role.
func (s *Users) EnsureSystemRoles(ctx context.Context, tenantID uuid.UUID) error {
	for _, role := range authz.SystemRoles {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO roles (tenant_id, name, description, is_system, permissions)
			VALUES ($1,$2,$3,true,$4)
			ON CONFLICT (tenant_id, name) DO UPDATE
			SET description = EXCLUDED.description,
			    permissions = EXCLUDED.permissions,
			    updated_at = now()`,
			tenantID, role.Name, role.Description,
			authz.PermissionStrings(role.Permissions)); err != nil {
			return fmt.Errorf("store: seeding role %q: %w", role.Name, err)
		}
	}
	return nil
}

// GetRoleByName returns a role.
func (s *Users) GetRoleByName(ctx context.Context, tenantID uuid.UUID, name string) (*Role, error) {
	var r Role
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, description, is_system, permissions, created_at, updated_at
		FROM roles WHERE tenant_id = $1 AND name = $2`, tenantID, name).
		Scan(&r.ID, &r.TenantID, &r.Name, &r.Description, &r.IsSystem, &r.Permissions,
			&r.CreatedAt, &r.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: role %q", ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading role: %w", err)
	}
	return &r, nil
}

// ListRoles returns every role in the tenant.
func (s *Users) ListRoles(ctx context.Context, tenantID uuid.UUID) ([]Role, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, description, is_system, permissions, created_at, updated_at
		FROM roles WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: listing roles: %w", err)
	}
	defer rows.Close()

	var out []Role
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Description, &r.IsSystem,
			&r.Permissions, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning role: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GrantRole binds a role to a user.
func (s *Users) GrantRole(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		userID, roleID)
	if err != nil {
		return fmt.Errorf("store: granting role: %w", err)
	}
	return nil
}

// RevokeRole unbinds a role from a user.
func (s *Users) RevokeRole(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`, userID, roleID)
	if err != nil {
		return fmt.Errorf("store: revoking role: %w", err)
	}
	return nil
}

// LoadSubject resolves a user's effective permissions for request-time checks.
//
// One query per source, flattened once. Everything after this is a map lookup,
// so permission checks never touch the database.
func (s *Users) LoadSubject(ctx context.Context, tenantID, userID uuid.UUID) (*authz.Subject, error) {
	u, err := s.Get(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT r.name, r.permissions
		FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: reading user roles: %w", err)
	}

	var roleNames []string
	var granted []authz.Permission
	for rows.Next() {
		var name string
		var perms []string
		if err := rows.Scan(&name, &perms); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: scanning user role: %w", err)
		}
		roleNames = append(roleNames, name)
		for _, p := range perms {
			granted = append(granted, authz.Permission(p))
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating user roles: %w", err)
	}

	allow, deny, err := s.overrides(ctx, userID)
	if err != nil {
		return nil, err
	}

	subject := authz.NewSubject(u.ID, u.TenantID, u.Username, granted, allow, deny)
	subject.MustChangePassword = u.MustChangePW

	scopes, err := s.scopes(ctx, userID)
	if err != nil {
		return nil, err
	}
	subject.Scopes = scopes

	_ = roleNames
	return subject, nil
}

func (s *Users) overrides(ctx context.Context, userID uuid.UUID) (allow, deny []authz.Permission, err error) {
	rows, err := s.pool.Query(ctx,
		`SELECT permission, effect FROM user_permission_overrides WHERE user_id = $1`, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("store: reading permission overrides: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var permission, effect string
		if err := rows.Scan(&permission, &effect); err != nil {
			return nil, nil, fmt.Errorf("store: scanning permission override: %w", err)
		}
		if effect == "deny" {
			deny = append(deny, authz.Permission(permission))
		} else {
			allow = append(allow, authz.Permission(permission))
		}
	}
	return allow, deny, rows.Err()
}

func (s *Users) scopes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT tag FROM user_scopes WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: reading user scopes: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, fmt.Errorf("store: scanning user scope: %w", err)
		}
		out = append(out, tag)
	}
	return out, rows.Err()
}

// RoleNamesFor returns the role names bound to a user, for display.
func (s *Users) RoleNamesFor(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 ORDER BY r.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: reading role names: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: scanning role name: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.Username, &u.Email, &u.DisplayName,
		&u.PasswordHash, &u.TOTPSecret, &u.TOTPEnrolled, &u.RecoveryCodes,
		&u.Active, &u.MustChangePW, &u.FailedLogins, &u.LockedUntil,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateProfile changes the mutable, non-secret fields of an account.
//
// Password, TOTP secret, and recovery codes each have their own setter: those
// are the fields where an accidental overwrite is a lockout, and a wide
// "update everything" call is exactly how that accident happens.
func (s *Users) UpdateProfile(ctx context.Context, tenantID, id uuid.UUID,
	email, displayName string, active, mustChangePW, unlock bool) error {

	tag, err := s.pool.Exec(ctx, `
		UPDATE users
		SET email = $3, display_name = $4, active = $5, must_change_pw = $6,
		    failed_logins = CASE WHEN $7 THEN 0 ELSE failed_logins END,
		    locked_until  = CASE WHEN $7 THEN NULL ELSE locked_until END,
		    updated_at = now()
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, email, displayName, active, mustChangePW, unlock)
	if err != nil {
		return fmt.Errorf("store: updating user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: user %s", ErrNotFound, id)
	}
	return nil
}

// Delete removes an account. Sessions, role bindings, and API tokens go with
// it through the schema's cascades; audit rows deliberately do not, because an
// audit trail that disappears when the actor is deleted is not an audit trail.
func (s *Users) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: deleting user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: user %s", ErrNotFound, id)
	}
	return nil
}
