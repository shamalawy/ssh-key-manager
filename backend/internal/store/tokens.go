package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shamalawy/ssh-key-manager/backend/internal/db"
)

// APIToken is a non-interactive credential for the REST API.
//
// Only the hash is stored. The plaintext is shown once at creation and cannot
// be recovered, which is the same bargain the product makes with backup
// passphrases and for the same reason: a value that can be read back is a value
// that can be read back by the wrong person.
type APIToken struct {
	ID       uuid.UUID  `json:"id"`
	TenantID uuid.UUID  `json:"-"`
	UserID   *uuid.UUID `json:"user_id,omitempty"`
	Username string     `json:"username,omitempty"`
	Name     string     `json:"name"`

	// Prefix is the leading, non-secret part of the token, kept so a listing
	// can say which token is which without holding the secret.
	Prefix string `json:"prefix"`

	// Permissions narrows the token below its owner's rights. Empty means the
	// token inherits everything the owner holds — convenient, and the reason
	// the UI nudges towards naming permissions explicitly.
	Permissions []string `json:"permissions"`
	Scopes      []string `json:"scopes"`

	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Active reports whether the token can still authenticate.
func (t *APIToken) Active() bool {
	if t.RevokedAt != nil {
		return false
	}
	return t.ExpiresAt == nil || t.ExpiresAt.After(time.Now())
}

// Status renders the token's state for a listing, so the UI does not have to
// re-derive it from three nullable timestamps.
func (t *APIToken) Status() string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case t.ExpiresAt != nil && !t.ExpiresAt.After(time.Now()):
		return "expired"
	default:
		return "active"
	}
}

// Tokens is the repository for API tokens.
type Tokens struct{ pool *db.Pool }

// NewTokens returns a Tokens repository.
func NewTokens(pool *db.Pool) *Tokens { return &Tokens{pool: pool} }

const tokenColumns = `t.id, t.tenant_id, t.user_id, t.name, t.token_prefix,
	t.permissions, t.scopes, t.expires_at, t.last_used_at, t.revoked_at,
	t.created_by, t.created_at`

// Create stores a token. hash is the caller's digest of the plaintext.
func (s *Tokens) Create(ctx context.Context, t *APIToken, hash string) (*APIToken, error) {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO api_tokens (tenant_id, user_id, name, token_hash, token_prefix,
		                        permissions, scopes, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, created_at`,
		t.TenantID, t.UserID, t.Name, hash, t.Prefix,
		orEmpty(t.Permissions), orEmpty(t.Scopes), t.ExpiresAt, t.CreatedBy).
		Scan(&t.ID, &t.CreatedAt)

	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: that token already exists", ErrConflict)
		}
		return nil, fmt.Errorf("store: creating api token: %w", err)
	}
	return t, nil
}

// ByHash resolves a presented token. Revoked and expired tokens are returned
// too, so the caller can tell "no such token" from "that token is finished" —
// the audit trail is more useful when it can say which.
func (s *Tokens) ByHash(ctx context.Context, hash string) (*APIToken, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+tokenColumns+` FROM api_tokens t WHERE t.token_hash = $1`, hash)

	t, err := scanToken(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// List returns the tenant's tokens, newest first, with the owner's username
// joined in.
func (s *Tokens) List(ctx context.Context, tenantID uuid.UUID, userID *uuid.UUID) ([]APIToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+tokenColumns+`, COALESCE(u.username, '')
		FROM api_tokens t
		LEFT JOIN users u ON u.id = t.user_id
		WHERE t.tenant_id = $1 AND ($2::uuid IS NULL OR t.user_id = $2)
		ORDER BY t.created_at DESC`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("store: listing api tokens: %w", err)
	}
	defer rows.Close()

	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.TenantID, &t.UserID, &t.Name, &t.Prefix,
			&t.Permissions, &t.Scopes, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt,
			&t.CreatedBy, &t.CreatedAt, &t.Username); err != nil {
			return nil, fmt.Errorf("store: scanning api token: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Get returns one token by id.
func (s *Tokens) Get(ctx context.Context, tenantID, id uuid.UUID) (*APIToken, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+tokenColumns+` FROM api_tokens t WHERE t.tenant_id = $1 AND t.id = $2`,
		tenantID, id)

	t, err := scanToken(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: api token %s", ErrNotFound, id)
	}
	return t, err
}

// Revoke marks a token unusable. Revoking is preferred to deleting so the
// audit log keeps something to point at.
func (s *Tokens) Revoke(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE api_tokens SET revoked_at = now()
		 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: revoking api token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: api token %s", ErrNotFound, id)
	}
	return nil
}

// Delete removes a token outright.
func (s *Tokens) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM api_tokens WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: deleting api token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: api token %s", ErrNotFound, id)
	}
	return nil
}

// TouchUsed records that a token authenticated a request.
//
// The write is skipped when the timestamp is under a minute old. Without that
// guard every API request would carry a row update, which turns a read-heavy
// integration into a write-heavy one for no operational gain: nobody needs
// last-used accurate to the second.
func (s *Tokens) TouchUsed(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE api_tokens SET last_used_at = now()
		WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, id)
	if err != nil {
		return fmt.Errorf("store: recording token use: %w", err)
	}
	return nil
}

func scanToken(row interface{ Scan(...any) error }) (*APIToken, error) {
	var t APIToken
	if err := row.Scan(&t.ID, &t.TenantID, &t.UserID, &t.Name, &t.Prefix,
		&t.Permissions, &t.Scopes, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt,
		&t.CreatedBy, &t.CreatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

// orEmpty turns a nil slice into an empty one, because a NOT NULL TEXT[]
// column rejects nil but accepts {}.
func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
