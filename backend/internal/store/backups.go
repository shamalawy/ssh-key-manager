package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hamalawy/ssh-key-manager/backend/internal/db"
)

// Backup is one encrypted export of the vault.
//
// The row is metadata only; the archive itself lives on disk or in object
// storage. Keeping them apart means a database restore does not silently
// resurrect a backup whose bytes are gone, and the state column says which of
// those two situations you are in.
type Backup struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"-"`
	Name     string    `json:"name"`
	Kind     string    `json:"kind"`
	Location string    `json:"location"`

	SizeBytes int64  `json:"size_bytes"`
	Checksum  string `json:"checksum"`
	KeyCount  int    `json:"key_count"`

	State string `json:"state"`
	Error string `json:"error,omitempty"`

	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`

	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Backup kinds and states.
const (
	BackupFull     = "full"
	BackupKeysOnly = "keys_only"
	BackupMetadata = "metadata"

	BackupPending   = "pending"
	BackupRunning   = "running"
	BackupCompleted = "completed"
	BackupFailed    = "failed"
	BackupVerified  = "verified"
)

// Backups is the repository for backup metadata.
type Backups struct{ pool *db.Pool }

// NewBackups returns a Backups repository.
func NewBackups(pool *db.Pool) *Backups { return &Backups{pool: pool} }

const backupColumns = `id, tenant_id, name, kind, location, size_bytes, checksum,
	key_count, state, error, verified_at, expires_at, created_by, created_at, completed_at`

// Create opens a backup record before the export starts, so a crashed export
// leaves visible evidence rather than nothing at all.
func (s *Backups) Create(ctx context.Context, b *Backup) (*Backup, error) {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	if b.TenantID == uuid.Nil {
		b.TenantID = DefaultTenantID
	}
	if b.Kind == "" {
		b.Kind = BackupFull
	}
	if b.State == "" {
		b.State = BackupPending
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO backups (id, tenant_id, name, kind, location, state, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+backupColumns,
		b.ID, b.TenantID, b.Name, b.Kind, b.Location, b.State, b.ExpiresAt, b.CreatedBy)

	created, err := scanBackup(row)
	if err != nil {
		return nil, fmt.Errorf("store: inserting backup: %w", err)
	}
	return created, nil
}

// Complete records a finished export.
func (s *Backups) Complete(ctx context.Context, id uuid.UUID, size int64, checksum string, keyCount int) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE backups SET state = 'completed', size_bytes = $2, checksum = $3,
			key_count = $4, completed_at = now(), error = '' WHERE id = $1`,
		id, size, checksum, keyCount)
	if err != nil {
		return fmt.Errorf("store: completing backup: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Fail records a failed export.
func (s *Backups) Fail(ctx context.Context, id uuid.UUID, cause error) error {
	msg := ""
	if cause != nil {
		msg = truncate(cause.Error(), 4000)
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE backups SET state = 'failed', error = $2, completed_at = now() WHERE id = $1`,
		id, msg)
	if err != nil {
		return fmt.Errorf("store: failing backup: %w", err)
	}
	return nil
}

// MarkVerified records that the archive was proven restorable.
func (s *Backups) MarkVerified(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE backups SET state = 'verified', verified_at = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: marking backup verified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Get returns one backup record.
func (s *Backups) Get(ctx context.Context, tenantID, id uuid.UUID) (*Backup, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+backupColumns+` FROM backups WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	b, err := scanBackup(row)
	if err != nil {
		return nil, fmt.Errorf("store: loading backup %s: %w", id, err)
	}
	return b, nil
}

// List returns backups newest first.
func (s *Backups) List(ctx context.Context, tenantID uuid.UUID, limit int) ([]Backup, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx,
		`SELECT `+backupColumns+` FROM backups WHERE tenant_id = $1
		 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing backups: %w", err)
	}
	defer rows.Close()

	out := []Backup{}
	for rows.Next() {
		b, err := scanBackup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// Expired returns backups past their retention date, for the pruning job.
func (s *Backups) Expired(ctx context.Context, now time.Time) ([]Backup, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+backupColumns+` FROM backups
		 WHERE expires_at IS NOT NULL AND expires_at <= $1 AND state <> 'failed'`, now)
	if err != nil {
		return nil, fmt.Errorf("store: listing expired backups: %w", err)
	}
	defer rows.Close()

	out := []Backup{}
	for rows.Next() {
		b, err := scanBackup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// Delete removes a backup record.
func (s *Backups) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM backups WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: deleting backup: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanBackup(row interface{ Scan(...any) error }) (*Backup, error) {
	var b Backup
	err := row.Scan(&b.ID, &b.TenantID, &b.Name, &b.Kind, &b.Location, &b.SizeBytes,
		&b.Checksum, &b.KeyCount, &b.State, &b.Error, &b.VerifiedAt, &b.ExpiresAt,
		&b.CreatedBy, &b.CreatedAt, &b.CompletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &b, nil
}
