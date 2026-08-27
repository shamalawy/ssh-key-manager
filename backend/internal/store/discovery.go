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

// DiscoveredKey is a key found on a target that SKM did not put there.
//
// For an estate that has never had key management, this inventory is the first
// genuinely useful thing the product produces: it answers "who can already log
// into these machines?", a question most operators cannot answer at all.
type DiscoveredKey struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"-"`
	TargetID    uuid.UUID `json:"target_id"`
	PrincipalID uuid.UUID `json:"principal_id"`

	Fingerprint string   `json:"fingerprint_sha256"`
	PublicKey   string   `json:"public_key"`
	Algorithm   string   `json:"algorithm"`
	Comment     string   `json:"comment"`
	Options     []string `json:"options"`

	State        string     `json:"state"`
	AdoptedKeyID *uuid.UUID `json:"adopted_key_id,omitempty"`

	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`

	// Joined for display.
	TargetName string `json:"target_name,omitempty"`
	Username   string `json:"username,omitempty"`
}

// Discovered-key states.
const (
	DiscoveredUnmanaged = "unmanaged"
	DiscoveredAdopted   = "adopted"
	DiscoveredIgnored   = "ignored"
	DiscoveredRemoved   = "removed"
)

// Discovery is the repository for the unmanaged-key inventory.
type Discovery struct{ pool *db.Pool }

// NewDiscovery returns a Discovery repository.
func NewDiscovery(pool *db.Pool) *Discovery { return &Discovery{pool: pool} }

// Observe records a key seen on a target.
//
// Re-observing an existing row refreshes last_seen_at and resurrects a row
// previously marked removed, because a key reappearing after being deleted is
// a materially different event from one that was simply never removed.
func (s *Discovery) Observe(ctx context.Context, d *DiscoveredKey) (*DiscoveredKey, error) {
	if d.TenantID == uuid.Nil {
		d.TenantID = DefaultTenantID
	}
	if d.Options == nil {
		d.Options = []string{}
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO discovered_keys (tenant_id, target_id, principal_id,
			fingerprint_sha256, public_key, algorithm, comment, options)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (target_id, principal_id, fingerprint_sha256) DO UPDATE SET
			last_seen_at = now(),
			public_key = EXCLUDED.public_key,
			comment = EXCLUDED.comment,
			options = EXCLUDED.options,
			state = CASE WHEN discovered_keys.state = 'removed'
				THEN 'unmanaged' ELSE discovered_keys.state END
		RETURNING id, tenant_id, target_id, principal_id, fingerprint_sha256,
			public_key, algorithm, comment, options, state, adopted_key_id,
			first_seen_at, last_seen_at`,
		d.TenantID, d.TargetID, d.PrincipalID, d.Fingerprint, d.PublicKey,
		d.Algorithm, d.Comment, d.Options)

	out, err := scanDiscovered(row)
	if err != nil {
		return nil, fmt.Errorf("store: recording discovered key: %w", err)
	}
	return out, nil
}

// MarkAbsent flags keys previously seen on a principal that are no longer
// present, so the inventory reflects removals as well as additions.
func (s *Discovery) MarkAbsent(ctx context.Context, targetID, principalID uuid.UUID, seen []string, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE discovered_keys SET state = 'removed', last_seen_at = last_seen_at
		WHERE target_id = $1 AND principal_id = $2 AND state = 'unmanaged'
			AND last_seen_at < $3
			AND ($4::text[] IS NULL OR NOT (fingerprint_sha256 = ANY($4)))`,
		targetID, principalID, before, nullableStrings(seen))
	if err != nil {
		return 0, fmt.Errorf("store: marking discovered keys absent: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DiscoveryFilter narrows the inventory listing.
type DiscoveryFilter struct {
	TenantID uuid.UUID
	States   []string
	TargetID *uuid.UUID
	Limit    int
}

// List returns the inventory, most recently seen first.
func (s *Discovery) List(ctx context.Context, f DiscoveryFilter) ([]DiscoveredKey, error) {
	if f.TenantID == uuid.Nil {
		f.TenantID = DefaultTenantID
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}

	args := []any{f.TenantID, nullableStrings(f.States), f.TargetID, f.Limit}
	rows, err := s.pool.Query(ctx, `
		SELECT d.id, d.tenant_id, d.target_id, d.principal_id, d.fingerprint_sha256,
			d.public_key, d.algorithm, d.comment, d.options, d.state, d.adopted_key_id,
			d.first_seen_at, d.last_seen_at, t.name, p.username
		FROM discovered_keys d
		JOIN targets t ON t.id = d.target_id
		JOIN principals p ON p.id = d.principal_id
		WHERE d.tenant_id = $1
			AND ($2::text[] IS NULL OR d.state = ANY($2))
			AND ($3::uuid IS NULL OR d.target_id = $3)
		ORDER BY d.last_seen_at DESC LIMIT $4`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing discovered keys: %w", err)
	}
	defer rows.Close()

	out := []DiscoveredKey{}
	for rows.Next() {
		var d DiscoveredKey
		if err := rows.Scan(&d.ID, &d.TenantID, &d.TargetID, &d.PrincipalID,
			&d.Fingerprint, &d.PublicKey, &d.Algorithm, &d.Comment, &d.Options,
			&d.State, &d.AdoptedKeyID, &d.FirstSeenAt, &d.LastSeenAt,
			&d.TargetName, &d.Username); err != nil {
			return nil, fmt.Errorf("store: scanning discovered key: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Get returns one discovered key.
func (s *Discovery) Get(ctx context.Context, tenantID, id uuid.UUID) (*DiscoveredKey, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, target_id, principal_id, fingerprint_sha256,
			public_key, algorithm, comment, options, state, adopted_key_id,
			first_seen_at, last_seen_at
		FROM discovered_keys WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	d, err := scanDiscovered(row)
	if err != nil {
		return nil, fmt.Errorf("store: loading discovered key %s: %w", id, err)
	}
	return d, nil
}

// SetState changes a discovered key's disposition, optionally linking the
// managed key it was adopted into.
func (s *Discovery) SetState(ctx context.Context, tenantID, id uuid.UUID, state string, adoptedKeyID *uuid.UUID) (*DiscoveredKey, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE discovered_keys SET state = $3, adopted_key_id = COALESCE($4, adopted_key_id)
		WHERE tenant_id = $1 AND id = $2
		RETURNING id, tenant_id, target_id, principal_id, fingerprint_sha256,
			public_key, algorithm, comment, options, state, adopted_key_id,
			first_seen_at, last_seen_at`, tenantID, id, state, adoptedKeyID)

	d, err := scanDiscovered(row)
	if err != nil {
		return nil, fmt.Errorf("store: updating discovered key: %w", err)
	}
	return d, nil
}

// CountByState summarises the inventory for the dashboard.
func (s *Discovery) CountByState(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT state, count(*) FROM discovered_keys WHERE tenant_id = $1 GROUP BY state`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: counting discovered keys: %w", err)
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var state string
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			return nil, err
		}
		out[state] = n
	}
	return out, rows.Err()
}

func scanDiscovered(row interface{ Scan(...any) error }) (*DiscoveredKey, error) {
	var d DiscoveredKey
	err := row.Scan(&d.ID, &d.TenantID, &d.TargetID, &d.PrincipalID, &d.Fingerprint,
		&d.PublicKey, &d.Algorithm, &d.Comment, &d.Options, &d.State,
		&d.AdoptedKeyID, &d.FirstSeenAt, &d.LastSeenAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}
