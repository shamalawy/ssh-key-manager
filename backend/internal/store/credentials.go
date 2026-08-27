package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shamalawy/ssh-key-manager/backend/internal/db"
	"github.com/shamalawy/ssh-key-manager/backend/internal/vault"
)

// Credential is how SKM authenticates to a target in order to manage it.
//
// This is the bootstrap problem: installing a key requires access that predates
// the key. Most installs start with a password or an existing administrative
// key, then switch the credential to a managed key once one is deployed.
type Credential struct {
	ID       uuid.UUID  `json:"id"`
	TenantID uuid.UUID  `json:"-"`
	Name     string     `json:"name"`
	Kind     string     `json:"kind"`
	Username string     `json:"username"`
	KeyID    *uuid.UUID `json:"key_id,omitempty"`
	Tags     []string   `json:"tags"`

	// HasSecret reports whether encrypted material is stored, without
	// revealing it. Listings return this; never the secret itself.
	HasSecret bool `json:"has_secret"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Credential kinds.
const (
	CredSSHPassword = "ssh_password"
	CredSSHKey      = "ssh_key"
	CredAPIToken    = "api_token"
	CredCloudIAM    = "cloud_iam"
	CredKubeconfig  = "kubeconfig"
)

// Credentials is the repository for target access credentials.
type Credentials struct{ pool *db.Pool }

// NewCredentials returns a Credentials repository.
func NewCredentials(pool *db.Pool) *Credentials { return &Credentials{pool: pool} }

const credentialColumns = `id, tenant_id, name, kind, username, key_id, tags,
	(ciphertext IS NOT NULL) AS has_secret, created_by, created_at, updated_at`

// Create stores a credential, sealing any secret material.
func (s *Credentials) Create(ctx context.Context, c *Credential, secret *vault.Sealed) (*Credential, error) {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.TenantID == uuid.Nil {
		c.TenantID = DefaultTenantID
	}
	if c.Tags == nil {
		c.Tags = []string{}
	}

	var kekVersion *int
	var wrappedDEK, ciphertext []byte
	if secret != nil {
		kekVersion = &secret.KEKVersion
		wrappedDEK = secret.WrappedDEK
		ciphertext = secret.Ciphertext
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO credentials (id, tenant_id, name, kind, username, key_id,
			kek_version, wrapped_dek, ciphertext, tags, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING `+credentialColumns,
		c.ID, c.TenantID, c.Name, c.Kind, c.Username, c.KeyID,
		kekVersion, wrappedDEK, ciphertext, c.Tags, c.CreatedBy)

	created, err := scanCredential(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: a credential named %q already exists", ErrConflict, c.Name)
		}
		return nil, fmt.Errorf("store: inserting credential: %w", err)
	}
	return created, nil
}

// Get returns a credential's metadata, never its secret.
func (s *Credentials) Get(ctx context.Context, tenantID, id uuid.UUID) (*Credential, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+credentialColumns+` FROM credentials WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)

	c, err := scanCredential(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: credential %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading credential: %w", err)
	}
	return c, nil
}

// List returns credential metadata for the tenant.
func (s *Credentials) List(ctx context.Context, tenantID uuid.UUID) ([]Credential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+credentialColumns+` FROM credentials WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: listing credentials: %w", err)
	}
	defer rows.Close()

	var out []Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning credential: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// LoadSecret fetches sealed credential material for decryption.
func (s *Credentials) LoadSecret(ctx context.Context, tenantID, id uuid.UUID) (*vault.Sealed, error) {
	var (
		kekVersion *int
		sealed     vault.Sealed
	)
	err := s.pool.QueryRow(ctx,
		`SELECT kek_version, wrapped_dek, ciphertext FROM credentials WHERE tenant_id = $1 AND id = $2`,
		tenantID, id).Scan(&kekVersion, &sealed.WrappedDEK, &sealed.Ciphertext)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: credential %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading credential secret: %w", err)
	}
	if kekVersion == nil || len(sealed.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: credential %s holds no secret", ErrNotFound, id)
	}

	sealed.KEKVersion = *kekVersion
	return &sealed, nil
}

// Delete removes a credential. Targets referencing it keep working until their
// next operation, which then fails with a clear message.
func (s *Credentials) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM credentials WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: deleting credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: credential %s", ErrNotFound, id)
	}
	return nil
}

func scanCredential(row interface{ Scan(...any) error }) (*Credential, error) {
	var c Credential
	err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.Kind, &c.Username, &c.KeyID,
		&c.Tags, &c.HasSecret, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
