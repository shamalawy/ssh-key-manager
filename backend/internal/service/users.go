package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/hamalawy/ssh-key-manager/backend/internal/auth"
	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
)

// ErrBadUser marks a request an administrator can fix by changing the input.
var ErrBadUser = errors.New("service: invalid user request")

// MinPasswordLength is deliberately a length floor and nothing else.
//
// Composition rules — a digit, a symbol, mixed case — reliably produce
// "Password1!" and reliably annoy everyone. Length is the property that
// actually costs an attacker something.
const MinPasswordLength = 12

// TokenPrefix marks a string as an SKM API token. It exists so that a token
// pasted into a commit can be recognised by a secret scanner, and so the
// authenticator can tell a token from a session cookie without a database
// round trip.
const TokenPrefix = "skmt_"

// UserService administers accounts, role bindings, and API tokens.
type UserService struct {
	users    *store.Users
	tokens   *store.Tokens
	auditLog *audit.Logger
}

// NewUserService returns a UserService.
func NewUserService(users *store.Users, tokens *store.Tokens, auditLog *audit.Logger) *UserService {
	return &UserService{users: users, tokens: tokens, auditLog: auditLog}
}

// UserDetail is a user with their role names attached, which is what every
// screen showing a user actually needs.
type UserDetail struct {
	*store.User
	RoleNames []string `json:"role_names"`
}

// List returns every account with its roles.
func (s *UserService) List(ctx context.Context, subject *authz.Subject) ([]UserDetail, error) {
	if err := subject.Require(authz.PermUserRead); err != nil {
		return nil, err
	}

	users, err := s.users.List(ctx, subject.TenantID)
	if err != nil {
		return nil, err
	}

	out := make([]UserDetail, 0, len(users))
	for i := range users {
		u := users[i]
		redact(&u)
		roles, err := s.users.RoleNamesFor(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, UserDetail{User: &u, RoleNames: roles})
	}
	return out, nil
}

// Get returns one account.
func (s *UserService) Get(ctx context.Context, subject *authz.Subject, id uuid.UUID) (*UserDetail, error) {
	if err := subject.Require(authz.PermUserRead); err != nil {
		return nil, err
	}

	u, err := s.users.Get(ctx, subject.TenantID, id)
	if err != nil {
		return nil, err
	}
	redact(u)

	roles, err := s.users.RoleNamesFor(ctx, id)
	if err != nil {
		return nil, err
	}
	return &UserDetail{User: u, RoleNames: roles}, nil
}

// CreateUserRequest is the input to Create.
type CreateUserRequest struct {
	Username     string   `json:"username"`
	Email        string   `json:"email"`
	DisplayName  string   `json:"display_name"`
	Password     string   `json:"password"`
	Roles        []string `json:"roles"`
	MustChangePW bool     `json:"must_change_password"`
	Active       *bool    `json:"active"`
}

// Create adds an account and binds its roles.
func (s *UserService) Create(ctx context.Context, subject *authz.Subject, req CreateUserRequest) (*UserDetail, error) {
	if err := subject.Require(authz.PermUserWrite); err != nil {
		return nil, err
	}

	username := strings.TrimSpace(strings.ToLower(req.Username))
	if username == "" {
		return nil, fmt.Errorf("%w: a username is required", ErrBadUser)
	}
	if err := checkPassword(req.Password); err != nil {
		return nil, err
	}

	// Roles are resolved before the account exists.
	//
	// Doing it afterwards leaves a half-made account behind when a role name is
	// wrong: the insert succeeds, the grant fails, the caller sees an error, and
	// a user with no roles and no password anybody knows is sitting in the
	// table. Found by listing accounts after a rejected create and finding one.
	roleIDs, err := s.resolveRoles(ctx, subject.TenantID, req.Roles)
	if err != nil {
		return nil, err
	}

	hash, err := auth.HashPassword(req.Password, auth.DefaultParams())
	if err != nil {
		return nil, fmt.Errorf("service: hashing password: %w", err)
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	user, err := s.users.Create(ctx, &store.User{
		TenantID:     subject.TenantID,
		Username:     username,
		Email:        strings.TrimSpace(req.Email),
		DisplayName:  strings.TrimSpace(req.DisplayName),
		PasswordHash: hash,
		Active:       active,
		MustChangePW: req.MustChangePW,
	})
	if err != nil {
		return nil, err
	}

	for _, id := range roleIDs {
		if err := s.users.GrantRole(ctx, user.ID, id); err != nil {
			return nil, err
		}
	}

	s.log(ctx, subject, audit.ActionUserCreate, user.ID, map[string]any{
		"username": username, "roles": req.Roles,
	})
	return s.Get(ctx, subject, user.ID)
}

// UpdateUserRequest carries only the fields an administrator changed. A nil
// pointer means "leave this alone", which is what lets one endpoint serve both
// a rename and a deactivation without either clobbering the other.
type UpdateUserRequest struct {
	Email        *string   `json:"email"`
	DisplayName  *string   `json:"display_name"`
	Active       *bool     `json:"active"`
	MustChangePW *bool     `json:"must_change_password"`
	Roles        *[]string `json:"roles"`
	Unlock       bool      `json:"unlock"`
}

// Update changes an account's profile, roles, and active state.
func (s *UserService) Update(ctx context.Context, subject *authz.Subject, id uuid.UUID, req UpdateUserRequest) (*UserDetail, error) {
	if err := subject.Require(authz.PermUserWrite); err != nil {
		return nil, err
	}

	user, err := s.users.Get(ctx, subject.TenantID, id)
	if err != nil {
		return nil, err
	}

	// Deactivating yourself ends your own session on the next request and
	// leaves nobody holding the door. Refuse it rather than explain it later.
	if req.Active != nil && !*req.Active && id == subject.UserID {
		return nil, fmt.Errorf("%w: you cannot deactivate your own account", ErrBadUser)
	}
	if req.Active != nil && !*req.Active && user.Active {
		if err := s.assertNotLastAdmin(ctx, subject.TenantID, id); err != nil {
			return nil, err
		}
	}

	if req.Email != nil {
		user.Email = strings.TrimSpace(*req.Email)
	}
	if req.DisplayName != nil {
		user.DisplayName = strings.TrimSpace(*req.DisplayName)
	}
	if req.Active != nil {
		user.Active = *req.Active
	}
	if req.MustChangePW != nil {
		user.MustChangePW = *req.MustChangePW
	}

	if err := s.users.UpdateProfile(ctx, subject.TenantID, id, user.Email,
		user.DisplayName, user.Active, user.MustChangePW, req.Unlock); err != nil {
		return nil, err
	}

	if req.Roles != nil {
		if err := s.assertRoleChangeIsSafe(ctx, subject, id, *req.Roles); err != nil {
			return nil, err
		}
		if err := s.setRoles(ctx, subject.TenantID, id, *req.Roles); err != nil {
			return nil, err
		}
	}

	s.log(ctx, subject, audit.ActionUserUpdate, id, map[string]any{
		"username": user.Username, "roles": req.Roles, "active": req.Active,
	})
	return s.Get(ctx, subject, id)
}

// SetPassword resets an account's password.
//
// Administrators do not need the old password — that is the point of an
// administrative reset — but the account is flagged to change it at next
// sign-in so the administrator's chosen value does not become the permanent
// one. Changing your own password does require the current one.
func (s *UserService) SetPassword(ctx context.Context, subject *authz.Subject, id uuid.UUID, current, password string, mustChange bool) error {
	self := id == subject.UserID
	if !self {
		if err := subject.Require(authz.PermUserWrite); err != nil {
			return err
		}
	}

	user, err := s.users.Get(ctx, subject.TenantID, id)
	if err != nil {
		return err
	}

	if self {
		ok, _, err := auth.VerifyPassword(current, user.PasswordHash, auth.DefaultParams())
		if err != nil || !ok {
			return ErrInvalidCredentials
		}
		// You chose it, so you are not made to choose it again.
		mustChange = false
	}

	if err := checkPassword(password); err != nil {
		return err
	}
	hash, err := auth.HashPassword(password, auth.DefaultParams())
	if err != nil {
		return fmt.Errorf("service: hashing password: %w", err)
	}
	if err := s.users.SetPassword(ctx, id, hash); err != nil {
		return err
	}
	if err := s.users.UpdateProfile(ctx, subject.TenantID, id, user.Email,
		user.DisplayName, user.Active, mustChange, true); err != nil {
		return err
	}

	s.log(ctx, subject, audit.ActionUserUpdate, id, map[string]any{
		"event": "password_reset", "username": user.Username, "self": self,
	})
	return nil
}

// ResetTOTP clears a user's second factor so they can enrol again.
//
// This is the "I lost my phone" path, and it is the most dangerous button in
// the product's administration screen: it turns an account with two factors
// into an account with one. It is audited loudly and refuses to act on your own
// account, so it always leaves a second person in the story.
func (s *UserService) ResetTOTP(ctx context.Context, subject *authz.Subject, id uuid.UUID) error {
	if err := subject.Require(authz.PermUserWrite); err != nil {
		return err
	}
	if id == subject.UserID {
		return fmt.Errorf("%w: use the second-factor section to change your own enrolment", ErrBadUser)
	}

	user, err := s.users.Get(ctx, subject.TenantID, id)
	if err != nil {
		return err
	}
	if err := s.users.SetTOTP(ctx, id, "", false, nil); err != nil {
		return err
	}

	s.log(ctx, subject, audit.ActionUserUpdate, id, map[string]any{
		"event": "totp_reset", "username": user.Username,
	})
	return nil
}

// Delete removes an account.
func (s *UserService) Delete(ctx context.Context, subject *authz.Subject, id uuid.UUID) error {
	if err := subject.Require(authz.PermUserWrite); err != nil {
		return err
	}
	if id == subject.UserID {
		return fmt.Errorf("%w: you cannot delete your own account", ErrBadUser)
	}

	user, err := s.users.Get(ctx, subject.TenantID, id)
	if err != nil {
		return err
	}
	if err := s.assertNotLastAdmin(ctx, subject.TenantID, id); err != nil {
		return err
	}
	if err := s.users.Delete(ctx, subject.TenantID, id); err != nil {
		return err
	}

	s.log(ctx, subject, audit.ActionUserUpdate, id, map[string]any{
		"event": "deleted", "username": user.Username,
	})
	return nil
}

// ListRoles returns the tenant's roles and their permissions.
func (s *UserService) ListRoles(ctx context.Context, subject *authz.Subject) ([]store.Role, error) {
	if err := subject.Require(authz.PermRoleRead); err != nil {
		return nil, err
	}
	return s.users.ListRoles(ctx, subject.TenantID)
}

// ------------------------------------------------------------ api tokens ---

// CreateTokenRequest is the input to CreateToken.
type CreateTokenRequest struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	Scopes      []string `json:"scopes"`
	ExpiresIn   string   `json:"expires_in"`
	UserID      string   `json:"user_id"`
}

// ListTokens returns the tenant's API tokens.
func (s *UserService) ListTokens(ctx context.Context, subject *authz.Subject) ([]store.APIToken, error) {
	if err := subject.Require(authz.PermTokenRead); err != nil {
		return nil, err
	}
	return s.tokens.List(ctx, subject.TenantID, nil)
}

// CreateToken mints a token and returns the plaintext exactly once.
func (s *UserService) CreateToken(ctx context.Context, subject *authz.Subject, req CreateTokenRequest) (*store.APIToken, string, error) {
	if err := subject.Require(authz.PermTokenWrite); err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, "", fmt.Errorf("%w: a token needs a name", ErrBadUser)
	}

	owner := subject.UserID
	if req.UserID != "" {
		parsed, err := uuid.Parse(req.UserID)
		if err != nil {
			return nil, "", fmt.Errorf("%w: user_id is not a uuid", ErrBadUser)
		}
		if parsed != subject.UserID {
			// Minting a token for someone else is minting their authority.
			if err := subject.Require(authz.PermUserWrite); err != nil {
				return nil, "", err
			}
		}
		owner = parsed
	}

	// A token can never exceed the rights of the account behind it. Asking for
	// more is a mistake worth reporting rather than silently trimming: the
	// caller would otherwise deploy a token that quietly does less than they
	// designed their automation around.
	ownerSubject, err := s.users.LoadSubject(ctx, subject.TenantID, owner)
	if err != nil {
		return nil, "", err
	}
	for _, p := range req.Permissions {
		if !ownerSubject.Can(authz.Permission(p)) {
			return nil, "", fmt.Errorf("%w: %s does not hold %q, so a token cannot carry it",
				ErrBadUser, ownerSubject.Username, p)
		}
	}

	var expiresAt *time.Time
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil || d <= 0 {
			return nil, "", fmt.Errorf("%w: expires_in must be a positive duration such as 720h", ErrBadUser)
		}
		t := time.Now().Add(d)
		expiresAt = &t
	}

	plaintext, prefix, hash, err := newAPIToken()
	if err != nil {
		return nil, "", err
	}

	token, err := s.tokens.Create(ctx, &store.APIToken{
		TenantID:    subject.TenantID,
		UserID:      &owner,
		Name:        strings.TrimSpace(req.Name),
		Prefix:      prefix,
		Permissions: req.Permissions,
		Scopes:      req.Scopes,
		ExpiresAt:   expiresAt,
		CreatedBy:   &subject.UserID,
	}, hash)
	if err != nil {
		return nil, "", err
	}

	s.log(ctx, subject, audit.ActionTokenCreate, token.ID, map[string]any{
		"name": token.Name, "prefix": prefix, "permissions": req.Permissions,
	})
	return token, plaintext, nil
}

// RevokeToken makes a token stop working without removing its history.
func (s *UserService) RevokeToken(ctx context.Context, subject *authz.Subject, id uuid.UUID) error {
	if err := subject.Require(authz.PermTokenWrite); err != nil {
		return err
	}
	token, err := s.tokens.Get(ctx, subject.TenantID, id)
	if err != nil {
		return err
	}
	if err := s.tokens.Revoke(ctx, subject.TenantID, id); err != nil {
		return err
	}

	s.log(ctx, subject, audit.ActionTokenRevoke, id, map[string]any{
		"name": token.Name, "prefix": token.Prefix,
	})
	return nil
}

// DeleteToken removes a token record entirely.
func (s *UserService) DeleteToken(ctx context.Context, subject *authz.Subject, id uuid.UUID) error {
	if err := subject.Require(authz.PermTokenWrite); err != nil {
		return err
	}
	token, err := s.tokens.Get(ctx, subject.TenantID, id)
	if err != nil {
		return err
	}
	if err := s.tokens.Delete(ctx, subject.TenantID, id); err != nil {
		return err
	}

	s.log(ctx, subject, audit.ActionTokenRevoke, id, map[string]any{
		"event": "deleted", "name": token.Name,
	})
	return nil
}

// ------------------------------------------------------------- internals ---

// newAPIToken returns the plaintext, the display prefix, and the stored hash.
func newAPIToken() (plaintext, prefix, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", "", fmt.Errorf("service: generating token: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	plaintext = TokenPrefix + body

	sum := sha256.Sum256([]byte(plaintext))
	return plaintext, TokenPrefix + body[:8], hex.EncodeToString(sum[:]), nil
}

func checkPassword(password string) error {
	if len([]rune(password)) < MinPasswordLength {
		return fmt.Errorf("%w: passwords must be at least %d characters",
			ErrBadUser, MinPasswordLength)
	}
	return nil
}

func redact(u *store.User) {
	u.PasswordHash = ""
	u.TOTPSecret = ""
	u.RecoveryCodes = nil
}

// resolveRoles turns role names into ids, failing on the first unknown one.
func (s *UserService) resolveRoles(ctx context.Context, tenantID uuid.UUID, names []string) ([]uuid.UUID, error) {
	if len(names) == 0 {
		return nil, nil
	}

	existing, err := s.users.ListRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]uuid.UUID, len(existing))
	for _, r := range existing {
		byName[r.Name] = r.ID
	}

	out := make([]uuid.UUID, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		id, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("%w: no such role %q", ErrBadUser, name)
		}
		out = append(out, id)
	}
	return out, nil
}

// setRoles replaces a user's role bindings with exactly the named set.
func (s *UserService) setRoles(ctx context.Context, tenantID, userID uuid.UUID, names []string) error {
	existing, err := s.users.ListRoles(ctx, tenantID)
	if err != nil {
		return err
	}
	byName := make(map[string]uuid.UUID, len(existing))
	for _, r := range existing {
		byName[r.Name] = r.ID
	}

	wanted := make(map[string]bool, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, ok := byName[n]; !ok {
			return fmt.Errorf("%w: no such role %q", ErrBadUser, n)
		}
		wanted[n] = true
	}

	current, err := s.users.RoleNamesFor(ctx, userID)
	if err != nil {
		return err
	}
	held := make(map[string]bool, len(current))
	for _, n := range current {
		held[n] = true
	}

	for name := range wanted {
		if !held[name] {
			if err := s.users.GrantRole(ctx, userID, byName[name]); err != nil {
				return err
			}
		}
	}
	for name := range held {
		if !wanted[name] {
			if err := s.users.RevokeRole(ctx, userID, byName[name]); err != nil {
				return err
			}
		}
	}
	return nil
}

// assertRoleChangeIsSafe refuses a change that would leave the install with no
// administrator, and refuses to let an administrator demote themselves — the
// second is not paranoia but the same lockout risk the rest of the product is
// built around, applied to the console instead of to a host.
func (s *UserService) assertRoleChangeIsSafe(ctx context.Context, subject *authz.Subject, id uuid.UUID, roles []string) error {
	keepsAdmin := false
	for _, r := range roles {
		if r == authz.RoleAdmin {
			keepsAdmin = true
		}
	}
	if keepsAdmin {
		return nil
	}

	if id == subject.UserID {
		return fmt.Errorf("%w: you cannot remove your own administrator role", ErrBadUser)
	}
	return s.assertNotLastAdmin(ctx, subject.TenantID, id)
}

// assertNotLastAdmin refuses to remove the final active administrator. It is
// the console's version of "never remove the last working key".
func (s *UserService) assertNotLastAdmin(ctx context.Context, tenantID, id uuid.UUID) error {
	users, err := s.users.List(ctx, tenantID)
	if err != nil {
		return err
	}

	others := 0
	for _, u := range users {
		if u.ID == id || !u.Active {
			continue
		}
		roles, err := s.users.RoleNamesFor(ctx, u.ID)
		if err != nil {
			return err
		}
		for _, r := range roles {
			if r == authz.RoleAdmin {
				others++
				break
			}
		}
	}
	if others == 0 {
		return fmt.Errorf("%w: this is the only active administrator; promote someone else first", ErrBadUser)
	}
	return nil
}

func (s *UserService) log(ctx context.Context, subject *authz.Subject, action string, resource uuid.UUID, detail map[string]any) {
	if s.auditLog == nil {
		return
	}
	_, _ = s.auditLog.Log(ctx, audit.Event{
		TenantID:     subject.TenantID,
		ActorID:      &subject.UserID,
		ActorName:    subject.Username,
		Action:       action,
		ResourceType: "user",
		ResourceID:   &resource,
		Outcome:      audit.OutcomeSuccess,
		Detail:       detail,
	})
}
