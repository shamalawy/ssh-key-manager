package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hamalawy/ssh-key-manager/backend/internal/db"
)

// Target is a place public keys are authorized.
type Target struct {
	ID           uuid.UUID      `json:"id"`
	TenantID     uuid.UUID      `json:"-"`
	Name         string         `json:"name"`
	Kind         string         `json:"kind"`
	Connector    string         `json:"connector"`
	Address      string         `json:"address"`
	Port         int            `json:"port"`
	Config       map[string]any `json:"config"`
	CredentialID *uuid.UUID     `json:"credential_id,omitempty"`

	HostKeyPin        string     `json:"host_key_pin"`
	HostKeyVerifiedAt *time.Time `json:"host_key_verified_at,omitempty"`

	Tags     []string `json:"tags"`
	Enabled  bool     `json:"enabled"`
	IsCanary bool     `json:"is_canary"`

	Health        string `json:"health"`
	HealthMessage string `json:"health_message"`
	DriftState    string `json:"drift_state"`
	ReconcileMode string `json:"reconcile_mode"`

	LastSeenAt       *time.Time `json:"last_seen_at,omitempty"`
	LastReconciledAt *time.Time `json:"last_reconciled_at,omitempty"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Target health and drift states.
const (
	HealthUnknown     = "unknown"
	HealthHealthy     = "healthy"
	HealthDegraded    = "degraded"
	HealthUnreachable = "unreachable"

	DriftUnknown = "unknown"
	DriftInSync  = "in_sync"
	DriftDrifted = "drifted"
	DriftError   = "error"

	ReconcileReportOnly = "report_only"
	ReconcileAutoHeal   = "auto_heal"
	ReconcileDisabled   = "disabled"
)

// Principal is the account on a target whose keys are managed.
type Principal struct {
	ID                 uuid.UUID `json:"id"`
	TargetID           uuid.UUID `json:"target_id"`
	Username           string    `json:"username"`
	AuthorizedKeysPath string    `json:"authorized_keys_path"`
	UseSudo            bool      `json:"use_sudo"`
	Enabled            bool      `json:"enabled"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// Targets is the repository for targets and their principals.
type Targets struct{ pool *db.Pool }

// NewTargets returns a Targets repository.
func NewTargets(pool *db.Pool) *Targets { return &Targets{pool: pool} }

const targetColumns = `id, tenant_id, name, kind, connector, address, port, config,
	credential_id, host_key_pin, host_key_verified_at, tags, enabled, is_canary,
	health, health_message, drift_state, reconcile_mode,
	last_seen_at, last_reconciled_at, created_by, created_at, updated_at`

// Create inserts a target.
func (s *Targets) Create(ctx context.Context, t *Target) (*Target, error) {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.TenantID == uuid.Nil {
		t.TenantID = DefaultTenantID
	}
	if t.Port == 0 {
		t.Port = 22
	}
	if t.Tags == nil {
		t.Tags = []string{}
	}
	if t.Config == nil {
		t.Config = map[string]any{}
	}
	if t.ReconcileMode == "" {
		t.ReconcileMode = ReconcileReportOnly
	}

	cfg, err := json.Marshal(t.Config)
	if err != nil {
		return nil, fmt.Errorf("store: encoding target config: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO targets (
			id, tenant_id, name, kind, connector, address, port, config,
			credential_id, host_key_pin, tags, enabled, is_canary,
			reconcile_mode, created_by
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		RETURNING `+targetColumns,
		t.ID, t.TenantID, t.Name, t.Kind, t.Connector, t.Address, t.Port, cfg,
		t.CredentialID, t.HostKeyPin, t.Tags, t.Enabled, t.IsCanary,
		t.ReconcileMode, t.CreatedBy)

	created, err := scanTarget(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: a target named %q already exists", ErrConflict, t.Name)
		}
		return nil, fmt.Errorf("store: inserting target: %w", err)
	}
	return created, nil
}

// Get returns a target by ID.
func (s *Targets) Get(ctx context.Context, tenantID, id uuid.UUID) (*Target, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+targetColumns+` FROM targets WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	t, err := scanTarget(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: target %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading target: %w", err)
	}
	return t, nil
}

// TargetFilter narrows a target listing.
type TargetFilter struct {
	TenantID   uuid.UUID
	Kinds      []string
	Tags       []string
	Health     []string
	DriftState []string
	Enabled    *bool
	IsCanary   *bool
	Search     string
	Limit      int
	Offset     int
}

// List returns targets matching the filter, by name.
func (s *Targets) List(ctx context.Context, f TargetFilter) ([]Target, error) {
	if f.TenantID == uuid.Nil {
		f.TenantID = DefaultTenantID
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}

	q := `SELECT ` + targetColumns + ` FROM targets WHERE tenant_id = $1`
	args := []any{f.TenantID}

	add := func(clause string, val any) {
		args = append(args, val)
		q += fmt.Sprintf(clause, len(args))
	}

	if len(f.Kinds) > 0 {
		add(" AND kind = ANY($%d)", f.Kinds)
	}
	if len(f.Tags) > 0 {
		add(" AND tags && $%d", f.Tags)
	}
	if len(f.Health) > 0 {
		add(" AND health = ANY($%d)", f.Health)
	}
	if len(f.DriftState) > 0 {
		add(" AND drift_state = ANY($%d)", f.DriftState)
	}
	if f.Enabled != nil {
		add(" AND enabled = $%d", *f.Enabled)
	}
	if f.IsCanary != nil {
		add(" AND is_canary = $%d", *f.IsCanary)
	}
	if search := strings.TrimSpace(f.Search); search != "" {
		args = append(args, "%"+strings.ToLower(search)+"%")
		q += fmt.Sprintf(" AND (lower(name) LIKE $%d OR lower(address) LIKE $%d)", len(args), len(args))
	}

	args = append(args, f.Limit)
	q += fmt.Sprintf(" ORDER BY name ASC LIMIT $%d", len(args))
	args = append(args, f.Offset)
	q += fmt.Sprintf(" OFFSET $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing targets: %w", err)
	}
	defer rows.Close()

	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning target: %w", err)
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// Update changes a target's mutable fields.
func (s *Targets) Update(ctx context.Context, t *Target) (*Target, error) {
	if t.Config == nil {
		t.Config = map[string]any{}
	}
	if t.Tags == nil {
		t.Tags = []string{}
	}

	cfg, err := json.Marshal(t.Config)
	if err != nil {
		return nil, fmt.Errorf("store: encoding target config: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE targets SET
			name = $3, kind = $4, connector = $5, address = $6, port = $7,
			config = $8, credential_id = $9, tags = $10, enabled = $11,
			is_canary = $12, reconcile_mode = $13, updated_at = now()
		WHERE tenant_id = $1 AND id = $2
		RETURNING `+targetColumns,
		t.TenantID, t.ID, t.Name, t.Kind, t.Connector, t.Address, t.Port,
		cfg, t.CredentialID, t.Tags, t.Enabled, t.IsCanary, t.ReconcileMode)

	updated, err := scanTarget(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: target %s", ErrNotFound, t.ID)
	}
	if err != nil {
		return nil, fmt.Errorf("store: updating target: %w", err)
	}
	return updated, nil
}

// SetHostKeyPin records the host key observed on first contact.
func (s *Targets) SetHostKeyPin(ctx context.Context, tenantID, id uuid.UUID, pin string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE targets SET host_key_pin = $3, host_key_verified_at = now(), updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, pin)
	if err != nil {
		return fmt.Errorf("store: recording host key pin: %w", err)
	}
	return nil
}

// SetHealth records reachability after a probe.
func (s *Targets) SetHealth(ctx context.Context, tenantID, id uuid.UUID, health, message string) error {
	seen := "last_seen_at = last_seen_at"
	if health == HealthHealthy {
		seen = "last_seen_at = now()"
	}

	_, err := s.pool.Exec(ctx, `
		UPDATE targets SET health = $3, health_message = $4, `+seen+`, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, health, message)
	if err != nil {
		return fmt.Errorf("store: recording target health: %w", err)
	}
	return nil
}

// SetDrift records the outcome of a reconcile pass.
func (s *Targets) SetDrift(ctx context.Context, tenantID, id uuid.UUID, state string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE targets SET drift_state = $3, last_reconciled_at = now(), updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, state)
	if err != nil {
		return fmt.Errorf("store: recording drift state: %w", err)
	}
	return nil
}

// Delete removes a target and, by cascade, its principals and assignments.
func (s *Targets) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM targets WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: deleting target: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: target %s", ErrNotFound, id)
	}
	return nil
}

// --------------------------------------------------------------- principals ---

// CreatePrincipal adds a managed account to a target.
func (s *Targets) CreatePrincipal(ctx context.Context, p *Principal) (*Principal, error) {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO principals (id, target_id, username, authorized_keys_path, use_sudo, enabled)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, target_id, username, authorized_keys_path, use_sudo, enabled, created_at, updated_at`,
		p.ID, p.TargetID, p.Username, p.AuthorizedKeysPath, p.UseSudo, p.Enabled)

	created, err := scanPrincipal(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: %s is already managed on this target", ErrConflict, p.Username)
		}
		if isForeignKeyViolation(err) {
			return nil, fmt.Errorf("%w: target %s", ErrNotFound, p.TargetID)
		}
		return nil, fmt.Errorf("store: inserting principal: %w", err)
	}
	return created, nil
}

// GetPrincipal returns a principal by ID.
func (s *Targets) GetPrincipal(ctx context.Context, id uuid.UUID) (*Principal, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, target_id, username, authorized_keys_path, use_sudo, enabled, created_at, updated_at
		FROM principals WHERE id = $1`, id)

	p, err := scanPrincipal(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: principal %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading principal: %w", err)
	}
	return p, nil
}

// ListPrincipals returns the managed accounts on a target.
func (s *Targets) ListPrincipals(ctx context.Context, targetID uuid.UUID) ([]Principal, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, target_id, username, authorized_keys_path, use_sudo, enabled, created_at, updated_at
		FROM principals WHERE target_id = $1 ORDER BY username`, targetID)
	if err != nil {
		return nil, fmt.Errorf("store: listing principals: %w", err)
	}
	defer rows.Close()

	var out []Principal
	for rows.Next() {
		p, err := scanPrincipal(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning principal: %w", err)
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// DeletePrincipal removes a managed account.
func (s *Targets) DeletePrincipal(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM principals WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: deleting principal: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: principal %s", ErrNotFound, id)
	}
	return nil
}

func scanTarget(row interface{ Scan(...any) error }) (*Target, error) {
	var (
		t   Target
		cfg []byte
	)
	err := row.Scan(
		&t.ID, &t.TenantID, &t.Name, &t.Kind, &t.Connector, &t.Address, &t.Port, &cfg,
		&t.CredentialID, &t.HostKeyPin, &t.HostKeyVerifiedAt, &t.Tags, &t.Enabled, &t.IsCanary,
		&t.Health, &t.HealthMessage, &t.DriftState, &t.ReconcileMode,
		&t.LastSeenAt, &t.LastReconciledAt, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	t.Config = map[string]any{}
	if len(cfg) > 0 {
		if err := json.Unmarshal(cfg, &t.Config); err != nil {
			return nil, fmt.Errorf("store: decoding target config: %w", err)
		}
	}
	return &t, nil
}

func scanPrincipal(row interface{ Scan(...any) error }) (*Principal, error) {
	var p Principal
	err := row.Scan(&p.ID, &p.TargetID, &p.Username, &p.AuthorizedKeysPath,
		&p.UseSudo, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdatePrincipal changes a managed login's settings.
func (s *Targets) UpdatePrincipal(ctx context.Context, p *Principal) (*Principal, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE principals
		SET username = $2, authorized_keys_path = $3, use_sudo = $4, enabled = $5,
		    updated_at = now()
		WHERE id = $1
		RETURNING id, target_id, username, authorized_keys_path, use_sudo, enabled,
		          created_at, updated_at`,
		p.ID, p.Username, p.AuthorizedKeysPath, p.UseSudo, p.Enabled)

	updated, err := scanPrincipal(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: principal %s", ErrNotFound, p.ID)
	}
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: %s is already managed on this target", ErrConflict, p.Username)
		}
		return nil, fmt.Errorf("store: updating principal: %w", err)
	}
	return updated, nil
}
