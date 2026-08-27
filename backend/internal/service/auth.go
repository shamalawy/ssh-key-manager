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
	"github.com/jackc/pgx/v5"

	"github.com/shamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/shamalawy/ssh-key-manager/backend/internal/auth"
	"github.com/shamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/shamalawy/ssh-key-manager/backend/internal/db"
	"github.com/shamalawy/ssh-key-manager/backend/internal/qr"
	"github.com/shamalawy/ssh-key-manager/backend/internal/store"
)

// Login failure handling. Locking is time-boxed so a password-guessing attempt
// against a known username cannot permanently deny service to its owner.
const (
	MaxFailedLogins = 5
	LockoutDuration = 15 * time.Minute
)

var (
	// ErrInvalidCredentials is returned for every authentication failure.
	// It is deliberately uniform: distinguishing "no such user" from "wrong
	// password" tells an attacker which usernames are worth attacking.
	ErrInvalidCredentials = errors.New("invalid username or password")
	// ErrAccountLocked means too many failures have occurred recently.
	ErrAccountLocked = errors.New("account is temporarily locked")
	// ErrMFARequired means the account has a second factor and none was given.
	ErrMFARequired = errors.New("a second factor is required")
	// ErrSessionInvalid means the presented token is unknown, expired, or revoked.
	ErrSessionInvalid = errors.New("session is invalid or expired")
	// ErrPasswordChangeRequired is returned for every call except changing the
	// password while an account is flagged must_change_password.
	ErrPasswordChangeRequired = errors.New("the password must be changed before doing anything else")
)

// AuthService handles sign-in, sessions, and second factors.
type AuthService struct {
	pool   *db.Pool
	users  *store.Users
	tokens *store.Tokens
	audit  *audit.Logger
	ttl    time.Duration
}

// NewAuthService wires an AuthService.
func NewAuthService(pool *db.Pool, users *store.Users, auditLog *audit.Logger, sessionTTL time.Duration) *AuthService {
	if sessionTTL <= 0 {
		sessionTTL = 12 * time.Hour
	}
	return &AuthService{pool: pool, users: users, audit: auditLog, ttl: sessionTTL}
}

// Session is an authenticated session as returned to the client.
type Session struct {
	Token       string      `json:"token"`
	ExpiresAt   time.Time   `json:"expires_at"`
	User        *store.User `json:"user"`
	Roles       []string    `json:"roles"`
	Permissions []string    `json:"permissions"`
	MFAVerified bool        `json:"mfa_verified"`
}

// LoginRequest carries sign-in input.
type LoginRequest struct {
	Username  string
	Password  string
	TOTPCode  string
	IPAddress string
	UserAgent string
}

// Login authenticates a user and opens a session.
//
// The uniform failure path matters as much as the success path: unknown users
// still cost a full Argon2 verification, so response timing does not reveal
// which usernames exist.
func (s *AuthService) Login(ctx context.Context, tenantID uuid.UUID, req LoginRequest) (*Session, error) {
	if tenantID == uuid.Nil {
		tenantID = store.DefaultTenantID
	}

	user, err := s.users.GetByUsername(ctx, tenantID, req.Username)
	if err != nil {
		// Spend the same time as a real verification before failing.
		auth.DummyVerify(req.Password)
		s.auditLogin(ctx, tenantID, nil, req, audit.OutcomeFailure, "unknown user")
		return nil, ErrInvalidCredentials
	}

	if !user.Active {
		s.auditLogin(ctx, tenantID, &user.ID, req, audit.OutcomeDenied, "account disabled")
		return nil, ErrInvalidCredentials
	}
	if user.Locked() {
		s.auditLogin(ctx, tenantID, &user.ID, req, audit.OutcomeDenied, "account locked")
		return nil, fmt.Errorf("%w until %s", ErrAccountLocked, user.LockedUntil.Format(time.RFC3339))
	}

	ok, needsRehash, err := auth.VerifyPassword(req.Password, user.PasswordHash, auth.DefaultParams())
	if err != nil || !ok {
		if err := s.users.RecordFailedLogin(ctx, user.ID, MaxFailedLogins, LockoutDuration); err != nil {
			return nil, fmt.Errorf("service: recording failed login: %w", err)
		}
		s.auditLogin(ctx, tenantID, &user.ID, req, audit.OutcomeFailure, "wrong password")
		return nil, ErrInvalidCredentials
	}

	// A correct password against a hash from weaker parameters is the moment to
	// silently upgrade it.
	if needsRehash {
		if fresh, err := auth.HashPassword(req.Password, auth.DefaultParams()); err == nil {
			_ = s.users.SetPassword(ctx, user.ID, fresh)
		}
	}

	mfaVerified := false
	if user.TOTPEnrolled {
		if req.TOTPCode == "" {
			return nil, ErrMFARequired
		}
		if !auth.VerifyTOTP(user.TOTPSecret, req.TOTPCode, time.Now()) {
			if err := s.users.RecordFailedLogin(ctx, user.ID, MaxFailedLogins, LockoutDuration); err != nil {
				return nil, fmt.Errorf("service: recording failed login: %w", err)
			}
			s.auditLogin(ctx, tenantID, &user.ID, req, audit.OutcomeFailure, "wrong TOTP code")
			return nil, ErrInvalidCredentials
		}
		mfaVerified = true
	}

	token, session, err := s.createSession(ctx, user, mfaVerified, req.IPAddress, req.UserAgent)
	if err != nil {
		return nil, err
	}

	if err := s.users.RecordLogin(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("service: recording login: %w", err)
	}

	subject, err := s.users.LoadSubject(ctx, tenantID, user.ID)
	if err != nil {
		return nil, err
	}
	roles, err := s.users.RoleNamesFor(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	s.auditLogin(ctx, tenantID, &user.ID, req, audit.OutcomeSuccess, "")

	user.PasswordHash = ""
	user.TOTPSecret = ""
	user.RecoveryCodes = nil

	return &Session{
		Token:       token,
		ExpiresAt:   session,
		User:        user,
		Roles:       roles,
		Permissions: subject.Permissions(),
		MFAVerified: mfaVerified,
	}, nil
}

// createSession issues an opaque bearer token.
//
// Only the token's hash is stored, so a database leak does not yield usable
// sessions. Opaque tokens are used rather than JWTs because sessions must be
// revocable the instant an account is disabled, and a self-contained token
// cannot be.
func (s *AuthService) createSession(ctx context.Context, user *store.User, mfaVerified bool, ip, userAgent string) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, fmt.Errorf("service: generating session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expiresAt := time.Now().Add(s.ttl)

	var mfaAt *time.Time
	if mfaVerified {
		now := time.Now()
		mfaAt = &now
	}

	var ipVal any
	if ip != "" {
		ipVal = ip
	}

	if _, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (user_id, token_hash, mfa_verified_at, ip_address, user_agent, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		user.ID, hashToken(token), mfaAt, ipVal, userAgent, expiresAt); err != nil {
		return "", time.Time{}, fmt.Errorf("service: storing session: %w", err)
	}

	return token, expiresAt, nil
}

// Authenticate resolves a bearer token into an authorised subject.
//
// This runs on every request, so it is one query joined against the user, and
// the permission flattening it triggers is the only other database work a
// request does for authorisation.
func (s *AuthService) Authenticate(ctx context.Context, token string) (*authz.Subject, error) {
	if token == "" {
		return nil, ErrSessionInvalid
	}
	if strings.HasPrefix(token, TokenPrefix) {
		return s.authenticateAPIToken(ctx, token)
	}

	var (
		sessionID   uuid.UUID
		userID      uuid.UUID
		tenantID    uuid.UUID
		active      bool
		mfaVerified *time.Time
	)

	err := s.pool.QueryRow(ctx, `
		SELECT s.id, s.user_id, u.tenant_id, u.active, s.mfa_verified_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1
		  AND s.revoked_at IS NULL
		  AND s.expires_at > now()`,
		hashToken(token)).Scan(&sessionID, &userID, &tenantID, &active, &mfaVerified)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("service: reading session: %w", err)
	}
	if !active {
		return nil, ErrSessionInvalid
	}

	subject, err := s.users.LoadSubject(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	if mfaVerified != nil {
		subject.MFAVerifiedAt = *mfaVerified
	}
	return subject, nil
}

// VerifyStepUp re-checks a second factor mid-session, refreshing the window
// that sensitive operations require.
func (s *AuthService) VerifyStepUp(ctx context.Context, subject *authz.Subject, token, code string) error {
	user, err := s.users.Get(ctx, subject.TenantID, subject.UserID)
	if err != nil {
		return err
	}
	if !user.TOTPEnrolled {
		return fmt.Errorf("service: no second factor is enrolled for %s", user.Username)
	}
	if !auth.VerifyTOTP(user.TOTPSecret, code, time.Now()) {
		s.logEvent(ctx, subject, audit.ActionMFAVerify, audit.OutcomeFailure, nil)
		return ErrInvalidCredentials
	}

	if _, err := s.pool.Exec(ctx,
		`UPDATE sessions SET mfa_verified_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`,
		hashToken(token)); err != nil {
		return fmt.Errorf("service: recording step-up: %w", err)
	}

	s.logEvent(ctx, subject, audit.ActionMFAVerify, audit.OutcomeSuccess, nil)
	return nil
}

// Logout revokes a session.
func (s *AuthService) Logout(ctx context.Context, subject *authz.Subject, token string) error {
	if _, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE token_hash = $1`, hashToken(token)); err != nil {
		return fmt.Errorf("service: revoking session: %w", err)
	}
	if subject != nil {
		s.logEvent(ctx, subject, audit.ActionLogout, audit.OutcomeSuccess, nil)
	}
	return nil
}

// EnrolTOTP generates a secret and recovery codes for a user.
//
// The secret is stored but not marked enrolled until the user proves they can
// generate a code from it, so a failed enrolment cannot lock them out.
func (s *AuthService) EnrolTOTP(ctx context.Context, subject *authz.Subject, issuer string) (secret, uri string, recoveryCodes []string, err error) {
	user, err := s.users.Get(ctx, subject.TenantID, subject.UserID)
	if err != nil {
		return "", "", nil, err
	}

	secret, err = auth.GenerateTOTPSecret()
	if err != nil {
		return "", "", nil, err
	}
	recoveryCodes, err = auth.GenerateRecoveryCodes(10)
	if err != nil {
		return "", "", nil, err
	}

	if err := s.users.SetTOTP(ctx, user.ID, secret, false, hashRecoveryCodes(recoveryCodes)); err != nil {
		return "", "", nil, err
	}

	return secret, auth.TOTPURI(issuer, user.Username, secret), recoveryCodes, nil
}

// ConfirmTOTP completes enrolment once the user proves possession.
func (s *AuthService) ConfirmTOTP(ctx context.Context, subject *authz.Subject, code string) error {
	user, err := s.users.Get(ctx, subject.TenantID, subject.UserID)
	if err != nil {
		return err
	}
	if user.TOTPSecret == "" {
		return fmt.Errorf("service: no enrolment is in progress")
	}
	if !auth.VerifyTOTP(user.TOTPSecret, code, time.Now()) {
		return ErrInvalidCredentials
	}
	if err := s.users.SetTOTP(ctx, user.ID, user.TOTPSecret, true, user.RecoveryCodes); err != nil {
		return err
	}

	s.logEvent(ctx, subject, audit.ActionMFAVerify, audit.OutcomeSuccess,
		map[string]any{"event": "totp_enrolled"})
	return nil
}

// PurgeExpiredSessions removes sessions that can no longer be used.
func (s *AuthService) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM sessions WHERE expires_at < now() - interval '7 days' OR revoked_at < now() - interval '7 days'`)
	if err != nil {
		return 0, fmt.Errorf("service: purging sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Bootstrap creates the first administrator when no users exist.
//
// It is a no-op once any account exists, so leaving the bootstrap variables set
// cannot silently re-create or reset an admin account later.
func (s *AuthService) Bootstrap(ctx context.Context, tenantID uuid.UUID, username, password string) (*store.User, error) {
	if username == "" || password == "" {
		return nil, nil
	}
	if tenantID == uuid.Nil {
		tenantID = store.DefaultTenantID
	}

	existing, err := s.users.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		return nil, nil
	}

	if err := s.users.EnsureSystemRoles(ctx, tenantID); err != nil {
		return nil, err
	}

	hash, err := auth.HashPassword(password, auth.DefaultParams())
	if err != nil {
		return nil, err
	}

	user, err := s.users.Create(ctx, &store.User{
		TenantID:     tenantID,
		Username:     username,
		DisplayName:  username,
		PasswordHash: hash,
		Active:       true,
		// The bootstrap password arrives through the environment, so it should
		// not remain the long-term credential.
		MustChangePW: true,
	})
	if err != nil {
		return nil, err
	}

	adminRole, err := s.users.GetRoleByName(ctx, tenantID, "admin")
	if err != nil {
		return nil, err
	}
	if err := s.users.GrantRole(ctx, user.ID, adminRole.ID); err != nil {
		return nil, err
	}

	if _, err := s.audit.Log(ctx, audit.Event{
		TenantID:     tenantID,
		ActorType:    audit.ActorSystem,
		ActorName:    "bootstrap",
		Action:       audit.ActionUserCreate,
		ResourceType: "user",
		ResourceID:   &user.ID,
		ResourceName: user.Username,
		Detail:       map[string]any{"role": "admin", "source": "bootstrap"},
	}); err != nil {
		return nil, fmt.Errorf("service: recording bootstrap: %w", err)
	}

	return user, nil
}

func (s *AuthService) auditLogin(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID, req LoginRequest, outcome audit.Outcome, reason string) {
	action := audit.ActionLogin
	if outcome != audit.OutcomeSuccess {
		action = audit.ActionLoginFailed
	}

	detail := map[string]any{"username": req.Username}
	if reason != "" {
		detail["reason"] = reason
	}

	_, _ = s.audit.Log(ctx, audit.Event{
		TenantID:     tenantID,
		ActorType:    audit.ActorUser,
		ActorID:      userID,
		ActorName:    req.Username,
		Action:       action,
		ResourceType: "user",
		ResourceID:   userID,
		ResourceName: req.Username,
		Outcome:      outcome,
		Detail:       detail,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
	})
}

func (s *AuthService) logEvent(ctx context.Context, subject *authz.Subject, action string, outcome audit.Outcome, detail map[string]any) {
	_, _ = s.audit.Log(ctx, audit.Event{
		TenantID:  subject.TenantID,
		ActorType: audit.ActorUser,
		ActorID:   &subject.UserID,
		ActorName: subject.Username,
		Action:    action,
		Outcome:   outcome,
		Detail:    detail,
	})
}

// hashToken derives the stored form of a session token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// hashRecoveryCodes stores recovery codes hashed, like passwords.
func hashRecoveryCodes(codes []string) []string {
	out := make([]string, len(codes))
	for i, c := range codes {
		sum := sha256.Sum256([]byte(c))
		out[i] = hex.EncodeToString(sum[:])
	}
	return out
}

// SetTokens enables API token authentication.
//
// It is a setter rather than a constructor argument because token
// authentication is an addition to sessions, not a replacement: an AuthService
// without it still works, and every existing caller keeps compiling.
func (s *AuthService) SetTokens(tokens *store.Tokens) { s.tokens = tokens }

// authenticateAPIToken resolves a token credential into a subject.
//
// A token subject never carries a second factor. That is deliberate rather
// than an omission: step-up exists so that a human confirms a dangerous action
// in the moment, and a token sitting in a CI variable cannot confirm anything.
// Revealing a private key through a token is therefore refused, which is the
// correct answer even though it will occasionally be an inconvenient one.
func (s *AuthService) authenticateAPIToken(ctx context.Context, plaintext string) (*authz.Subject, error) {
	if s.tokens == nil {
		return nil, ErrSessionInvalid
	}

	token, err := s.tokens.ByHash(ctx, hashToken(plaintext))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, err
	}
	if !token.Active() || token.UserID == nil {
		return nil, ErrSessionInvalid
	}

	user, err := s.users.Get(ctx, token.TenantID, *token.UserID)
	if err != nil || !user.Active {
		return nil, ErrSessionInvalid
	}

	subject, err := s.users.LoadSubject(ctx, token.TenantID, *token.UserID)
	if err != nil {
		return nil, err
	}
	subject.TokenID = &token.ID
	subject.Restrict(authz.Permissions(token.Permissions))
	if len(token.Scopes) > 0 {
		subject.Scopes = token.Scopes
	}

	// Best effort: a failure to record use must not fail the request.
	_ = s.tokens.TouchUsed(ctx, token.ID)

	return subject, nil
}

// TOTPEnrolment is everything a user needs to add a second factor.
type TOTPEnrolment struct {
	Secret        string   `json:"secret"`
	URI           string   `json:"uri"`
	QRCode        string   `json:"qr_code"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// EnrolTOTPWithQR is EnrolTOTP plus a scannable image of the URI.
//
// A failure to render the image is not a failure to enrol: the secret is still
// returned and can still be typed in. Losing the ability to add a second factor
// because a PNG encoder had a bad day would be a poor trade.
func (s *AuthService) EnrolTOTPWithQR(ctx context.Context, subject *authz.Subject, issuer string) (*TOTPEnrolment, error) {
	secret, uri, codes, err := s.EnrolTOTP(ctx, subject, issuer)
	if err != nil {
		return nil, err
	}

	image, err := qr.DataURI(uri, 6)
	if err != nil {
		image = ""
	}
	return &TOTPEnrolment{Secret: secret, URI: uri, QRCode: image, RecoveryCodes: codes}, nil
}

// RegenerateRecoveryCodes issues a fresh set and invalidates the old one.
//
// Proof of the current second factor is required. Without it, anyone holding a
// live session could mint themselves a permanent bypass of the second factor,
// which is the opposite of what recovery codes are for.
func (s *AuthService) RegenerateRecoveryCodes(ctx context.Context, subject *authz.Subject, code string) ([]string, error) {
	user, err := s.users.Get(ctx, subject.TenantID, subject.UserID)
	if err != nil {
		return nil, err
	}
	if !user.TOTPEnrolled {
		return nil, fmt.Errorf("service: no second factor is enrolled")
	}
	if !auth.VerifyTOTP(user.TOTPSecret, code, time.Now()) {
		s.logEvent(ctx, subject, audit.ActionMFAVerify, audit.OutcomeFailure,
			map[string]any{"event": "recovery_codes_regenerate"})
		return nil, ErrInvalidCredentials
	}

	codes, err := auth.GenerateRecoveryCodes(10)
	if err != nil {
		return nil, err
	}
	if err := s.users.SetTOTP(ctx, user.ID, user.TOTPSecret, true, hashRecoveryCodes(codes)); err != nil {
		return nil, err
	}

	s.logEvent(ctx, subject, audit.ActionMFAVerify, audit.OutcomeSuccess,
		map[string]any{"event": "recovery_codes_regenerated"})
	return codes, nil
}

// DisableTOTP removes a user's own second factor, on proof of possession.
func (s *AuthService) DisableTOTP(ctx context.Context, subject *authz.Subject, code string) error {
	user, err := s.users.Get(ctx, subject.TenantID, subject.UserID)
	if err != nil {
		return err
	}
	if !user.TOTPEnrolled {
		return nil
	}
	if !auth.VerifyTOTP(user.TOTPSecret, code, time.Now()) {
		s.logEvent(ctx, subject, audit.ActionMFAVerify, audit.OutcomeFailure,
			map[string]any{"event": "totp_disable"})
		return ErrInvalidCredentials
	}
	if err := s.users.SetTOTP(ctx, user.ID, "", false, nil); err != nil {
		return err
	}

	s.logEvent(ctx, subject, audit.ActionMFAVerify, audit.OutcomeSuccess,
		map[string]any{"event": "totp_disabled"})
	return nil
}
