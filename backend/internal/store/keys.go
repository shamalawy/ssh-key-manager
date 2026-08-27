// Package store holds the SQL repositories. Queries are written directly rather
// than generated, so what runs against the database is what is on the page.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hamalawy/ssh-key-manager/backend/internal/db"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a uniqueness constraint would be violated.
var ErrConflict = errors.New("store: already exists")

// Key mirrors a row of the keys table. Private key material is deliberately
// absent: it lives in key_material and is only reachable through the vault.
type Key struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         uuid.UUID  `json:"-"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Algorithm        string     `json:"algorithm"`
	PublicKey        string     `json:"public_key"`
	Fingerprint      string     `json:"fingerprint_sha256"`
	Comment          string     `json:"comment"`
	Status           string     `json:"status"`
	KeyClass         string     `json:"key_class"`
	Generation       int        `json:"generation"`
	ParentKeyID      *uuid.UUID `json:"parent_key_id,omitempty"`
	RotationPolicyID *uuid.UUID `json:"rotation_policy_id,omitempty"`
	OwnerID          *uuid.UUID `json:"owner_id,omitempty"`
	Tags             []string   `json:"tags"`
	HasPrivateKey    bool       `json:"has_private_key"`
	Compliant        bool       `json:"compliant"`
	ComplianceNotes  string     `json:"compliance_notes"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	ActivatedAt      *time.Time `json:"activated_at,omitempty"`
	RetiredAt        *time.Time `json:"retired_at,omitempty"`
	DestroyAfter     *time.Time `json:"destroy_after,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	CreatedBy        *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Key lifecycle states.
const (
	KeyStatusPending     = "pending"
	KeyStatusStaged      = "staged"
	KeyStatusActive      = "active"
	KeyStatusRetiring    = "retiring"
	KeyStatusRetired     = "retired"
	KeyStatusRevoked     = "revoked"
	KeyStatusCompromised = "compromised"
	KeyStatusDestroyed   = "destroyed"
)

// Key classes.
const (
	KeyClassStandard   = "standard"
	KeyClassBreakGlass = "break_glass"
	KeyClassDiscovered = "discovered"
	KeyClassImported   = "imported"
)

// Keys is the repository for managed keypairs.
type Keys struct{ pool *db.Pool }

// NewKeys returns a Keys repository.
func NewKeys(pool *db.Pool) *Keys { return &Keys{pool: pool} }

const keyColumns = `id, tenant_id, name, description, algorithm, public_key,
	fingerprint_sha256, comment, status, key_class, generation, parent_key_id,
	rotation_policy_id, owner_id, tags, has_private_key, compliant, compliance_notes,
	expires_at, activated_at, retired_at, destroy_after, last_used_at,
	created_by, created_at, updated_at`

// Create inserts a key and, when material is supplied, its encrypted private
// half in the same transaction.
//
// Both land together or neither does: a key row without its material is a key
// that looks usable in the UI but cannot actually authenticate, and that
// discrepancy is far worse than a failed creation.
func (s *Keys) Create(ctx context.Context, k *Key, material *vault.Sealed) (*Key, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: beginning key creation: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	if k.TenantID == uuid.Nil {
		k.TenantID = DefaultTenantID
	}
	if k.Status == "" {
		k.Status = KeyStatusPending
	}
	if k.KeyClass == "" {
		k.KeyClass = KeyClassStandard
	}
	if k.Generation == 0 {
		k.Generation = 1
	}
	if k.Tags == nil {
		k.Tags = []string{}
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO keys (
			id, tenant_id, name, description, algorithm, public_key,
			fingerprint_sha256, comment, status, key_class, generation,
			parent_key_id, rotation_policy_id, owner_id, tags,
			has_private_key, compliant, compliance_notes,
			expires_at, destroy_after, created_by
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
		RETURNING `+keyColumns,
		k.ID, k.TenantID, k.Name, k.Description, k.Algorithm, k.PublicKey,
		k.Fingerprint, k.Comment, k.Status, k.KeyClass, k.Generation,
		k.ParentKeyID, k.RotationPolicyID, k.OwnerID, k.Tags,
		k.HasPrivateKey, k.Compliant, k.ComplianceNotes,
		k.ExpiresAt, k.DestroyAfter, k.CreatedBy)

	created, err := scanKey(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: a key with fingerprint %s is already registered", ErrConflict, k.Fingerprint)
		}
		return nil, fmt.Errorf("store: inserting key: %w", err)
	}

	if material != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO key_material (key_id, kek_version, wrapped_dek, ciphertext)
			VALUES ($1,$2,$3,$4)`,
			created.ID, material.KEKVersion, material.WrappedDEK, material.Ciphertext); err != nil {
			return nil, fmt.Errorf("store: storing key material: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("store: committing key creation: %w", err)
	}
	return created, nil
}

// Get returns a key by ID.
func (s *Keys) Get(ctx context.Context, tenantID, id uuid.UUID) (*Key, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+keyColumns+` FROM keys WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	k, err := scanKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: key %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading key: %w", err)
	}
	return k, nil
}

// GetByFingerprint returns a key by its SHA256 fingerprint.
func (s *Keys) GetByFingerprint(ctx context.Context, tenantID uuid.UUID, fingerprint string) (*Key, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+keyColumns+` FROM keys WHERE tenant_id = $1 AND fingerprint_sha256 = $2`,
		tenantID, fingerprint)

	k, err := scanKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: no key with fingerprint %s", ErrNotFound, fingerprint)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading key by fingerprint: %w", err)
	}
	return k, nil
}

// KeyFilter narrows a key listing.
type KeyFilter struct {
	TenantID   uuid.UUID
	Statuses   []string
	Classes    []string
	Tags       []string
	Search     string
	OwnerID    *uuid.UUID
	ParentID   *uuid.UUID
	Compliant  *bool
	ExpiringIn time.Duration
	Limit      int
	Offset     int
}

// List returns keys matching the filter, newest first.
func (s *Keys) List(ctx context.Context, f KeyFilter) ([]Key, error) {
	if f.TenantID == uuid.Nil {
		f.TenantID = DefaultTenantID
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}

	q := `SELECT ` + keyColumns + ` FROM keys WHERE tenant_id = $1`
	args := []any{f.TenantID}

	add := func(clause string, val any) {
		args = append(args, val)
		q += fmt.Sprintf(clause, len(args))
	}

	if len(f.Statuses) > 0 {
		add(" AND status = ANY($%d)", f.Statuses)
	}
	if len(f.Classes) > 0 {
		add(" AND key_class = ANY($%d)", f.Classes)
	}
	if len(f.Tags) > 0 {
		// && is array overlap: the key carries at least one requested tag.
		add(" AND tags && $%d", f.Tags)
	}
	if f.OwnerID != nil {
		add(" AND owner_id = $%d", *f.OwnerID)
	}
	if f.ParentID != nil {
		add(" AND parent_key_id = $%d", *f.ParentID)
	}
	if f.Compliant != nil {
		add(" AND compliant = $%d", *f.Compliant)
	}
	if f.ExpiringIn > 0 {
		add(" AND expires_at IS NOT NULL AND expires_at <= $%d", time.Now().Add(f.ExpiringIn))
	}
	if s := strings.TrimSpace(f.Search); s != "" {
		args = append(args, "%"+strings.ToLower(s)+"%")
		q += fmt.Sprintf(
			" AND (lower(name) LIKE $%d OR lower(comment) LIKE $%d OR lower(fingerprint_sha256) LIKE $%d)",
			len(args), len(args), len(args))
	}

	args = append(args, f.Limit)
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args))
	args = append(args, f.Offset)
	q += fmt.Sprintf(" OFFSET $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing keys: %w", err)
	}
	defer rows.Close()

	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning key: %w", err)
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// Count returns how many keys match a filter, for pagination totals.
func (s *Keys) Count(ctx context.Context, tenantID uuid.UUID, statuses []string) (int, error) {
	q := `SELECT count(*) FROM keys WHERE tenant_id = $1`
	args := []any{tenantID}
	if len(statuses) > 0 {
		q += ` AND status = ANY($2)`
		args = append(args, statuses)
	}

	var n int
	if err := s.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: counting keys: %w", err)
	}
	return n, nil
}

// SetStatus moves a key to a new lifecycle state, stamping the matching
// timestamp column so the history is legible without consulting the audit log.
func (s *Keys) SetStatus(ctx context.Context, tenantID, id uuid.UUID, status string) (*Key, error) {
	var timestampCol string
	switch status {
	case KeyStatusActive:
		timestampCol = ", activated_at = COALESCE(activated_at, now())"
	case KeyStatusRetired:
		timestampCol = ", retired_at = now()"
	}

	row := s.pool.QueryRow(ctx,
		`UPDATE keys SET status = $3, updated_at = now()`+timestampCol+`
		 WHERE tenant_id = $1 AND id = $2 RETURNING `+keyColumns,
		tenantID, id, status)

	k, err := scanKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: key %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: updating key status: %w", err)
	}
	return k, nil
}

// Update changes the mutable metadata of a key. Cryptographic fields are
// immutable by design: changing a key's material makes it a different key, and
// that is what rotation is for.
func (s *Keys) Update(ctx context.Context, tenantID, id uuid.UUID, name, description string, tags []string, expiresAt *time.Time) (*Key, error) {
	if tags == nil {
		tags = []string{}
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE keys
		SET name = $3, description = $4, tags = $5, expires_at = $6, updated_at = now()
		WHERE tenant_id = $1 AND id = $2
		RETURNING `+keyColumns,
		tenantID, id, name, description, tags, expiresAt)

	k, err := scanKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: key %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: updating key: %w", err)
	}
	return k, nil
}

// LoadMaterial fetches the encrypted private key for decryption by the vault.
func (s *Keys) LoadMaterial(ctx context.Context, keyID uuid.UUID) (*vault.Sealed, error) {
	var sealed vault.Sealed
	err := s.pool.QueryRow(ctx,
		`SELECT kek_version, wrapped_dek, ciphertext FROM key_material WHERE key_id = $1`,
		keyID).Scan(&sealed.KEKVersion, &sealed.WrappedDEK, &sealed.Ciphertext)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: no private key material for key %s", ErrNotFound, keyID)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading key material: %w", err)
	}
	return &sealed, nil
}

// StoreMaterial writes or replaces encrypted private key material.
func (s *Keys) StoreMaterial(ctx context.Context, keyID uuid.UUID, sealed *vault.Sealed) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO key_material (key_id, kek_version, wrapped_dek, ciphertext)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (key_id) DO UPDATE
		SET kek_version = EXCLUDED.kek_version,
		    wrapped_dek = EXCLUDED.wrapped_dek,
		    ciphertext  = EXCLUDED.ciphertext,
		    updated_at  = now()`,
		keyID, sealed.KEKVersion, sealed.WrappedDEK, sealed.Ciphertext)
	if err != nil {
		return fmt.Errorf("store: writing key material: %w", err)
	}
	return nil
}

// DestroyMaterial removes the private key permanently, leaving the key row so
// the audit history and deployment record survive.
//
// This is the irreversible step at the end of a key's life. It happens only
// after the retention window, so a rotation that turns out to have been a
// mistake can still be undone right up until this point.
func (s *Keys) DestroyMaterial(ctx context.Context, tenantID, keyID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: beginning material destruction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	if _, err := tx.Exec(ctx, `DELETE FROM key_material WHERE key_id = $1`, keyID); err != nil {
		return fmt.Errorf("store: deleting key material: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE keys SET status = $3, has_private_key = false, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, keyID, KeyStatusDestroyed); err != nil {
		return fmt.Errorf("store: marking key destroyed: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: committing material destruction: %w", err)
	}
	return nil
}

// MaterialNeedingRewrap lists keys whose material is wrapped under an older KEK.
// Used by the KEK rotation job.
func (s *Keys) MaterialNeedingRewrap(ctx context.Context, currentVersion, limit int) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key_id FROM key_material WHERE kek_version < $1 ORDER BY key_id LIMIT $2`,
		currentVersion, limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing material needing rewrap: %w", err)
	}
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scanning key id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Delete removes a key entirely. Callers should prefer revoking: deleting
// discards the deployment history along with the key.
func (s *Keys) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM keys WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: deleting key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: key %s", ErrNotFound, id)
	}
	return nil
}

// scanKey reads a key row from either a QueryRow or a Rows cursor.
func scanKey(row interface{ Scan(...any) error }) (*Key, error) {
	var k Key
	err := row.Scan(
		&k.ID, &k.TenantID, &k.Name, &k.Description, &k.Algorithm, &k.PublicKey,
		&k.Fingerprint, &k.Comment, &k.Status, &k.KeyClass, &k.Generation,
		&k.ParentKeyID, &k.RotationPolicyID, &k.OwnerID, &k.Tags,
		&k.HasPrivateKey, &k.Compliant, &k.ComplianceNotes,
		&k.ExpiresAt, &k.ActivatedAt, &k.RetiredAt, &k.DestroyAfter, &k.LastUsedAt,
		&k.CreatedBy, &k.CreatedAt, &k.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &k, nil
}
