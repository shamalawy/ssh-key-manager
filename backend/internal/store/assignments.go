package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shamalawy/ssh-key-manager/backend/internal/db"
)

// Assignment is the desired state for one key on one principal.
type Assignment struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"-"`
	KeyID       uuid.UUID `json:"key_id"`
	TargetID    uuid.UUID `json:"target_id"`
	PrincipalID uuid.UUID `json:"principal_id"`

	Options      []string `json:"options"`
	DesiredState string   `json:"desired_state"`
	ActualState  string   `json:"actual_state"`

	DeployedAt     *time.Time `json:"deployed_at,omitempty"`
	LastVerifiedAt *time.Time `json:"last_verified_at,omitempty"`
	AuthVerifiedAt *time.Time `json:"auth_verified_at,omitempty"`
	LastError      string     `json:"last_error"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Desired and actual assignment states.
const (
	StatePresent = "present"
	StateAbsent  = "absent"
	StateUnknown = "unknown"
	StateError   = "error"
)

// InSync reports whether the observed state matches the desired one.
func (a *Assignment) InSync() bool { return a.DesiredState == a.ActualState }

// AssignmentDetail joins an assignment with the names needed to render it,
// avoiding an N+1 query from the coverage matrix.
type AssignmentDetail struct {
	Assignment
	KeyName        string `json:"key_name"`
	KeyFingerprint string `json:"key_fingerprint"`
	KeyStatus      string `json:"key_status"`
	TargetName     string `json:"target_name"`
	TargetAddress  string `json:"target_address"`
	Username       string `json:"username"`
}

// Assignments is the repository for desired-state bindings.
type Assignments struct{ pool *db.Pool }

// NewAssignments returns an Assignments repository.
func NewAssignments(pool *db.Pool) *Assignments { return &Assignments{pool: pool} }

const assignmentColumns = `id, tenant_id, key_id, target_id, principal_id, options,
	desired_state, actual_state, deployed_at, last_verified_at, auth_verified_at,
	last_error, created_by, created_at, updated_at`

// Upsert creates or updates the binding of a key to a principal.
func (s *Assignments) Upsert(ctx context.Context, a *Assignment) (*Assignment, error) {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.TenantID == uuid.Nil {
		a.TenantID = DefaultTenantID
	}
	if a.DesiredState == "" {
		a.DesiredState = StatePresent
	}
	if a.Options == nil {
		a.Options = []string{}
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO assignments (
			id, tenant_id, key_id, target_id, principal_id, options, desired_state, created_by
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (key_id, principal_id) DO UPDATE
		SET options = EXCLUDED.options,
		    desired_state = EXCLUDED.desired_state,
		    updated_at = now()
		RETURNING `+assignmentColumns,
		a.ID, a.TenantID, a.KeyID, a.TargetID, a.PrincipalID,
		a.Options, a.DesiredState, a.CreatedBy)

	created, err := scanAssignment(row)
	if err != nil {
		if isForeignKeyViolation(err) {
			return nil, fmt.Errorf("%w: the key, target, or principal does not exist", ErrNotFound)
		}
		return nil, fmt.Errorf("store: upserting assignment: %w", err)
	}
	return created, nil
}

// Get returns an assignment by ID.
func (s *Assignments) Get(ctx context.Context, tenantID, id uuid.UUID) (*Assignment, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+assignmentColumns+` FROM assignments WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)

	a, err := scanAssignment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: assignment %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading assignment: %w", err)
	}
	return a, nil
}

// AssignmentFilter narrows an assignment listing.
type AssignmentFilter struct {
	TenantID     uuid.UUID
	KeyID        *uuid.UUID
	TargetID     *uuid.UUID
	PrincipalID  *uuid.UUID
	DesiredState string
	ActualState  string
	// OnlyDrifted returns bindings whose observed state differs from the
	// desired one — the reconciler's work list.
	OnlyDrifted bool
	Limit       int
	Offset      int
}

// List returns assignments joined with display names.
func (s *Assignments) List(ctx context.Context, f AssignmentFilter) ([]AssignmentDetail, error) {
	if f.TenantID == uuid.Nil {
		f.TenantID = DefaultTenantID
	}
	if f.Limit <= 0 || f.Limit > 2000 {
		f.Limit = 500
	}

	q := `
		SELECT a.id, a.tenant_id, a.key_id, a.target_id, a.principal_id, a.options,
		       a.desired_state, a.actual_state, a.deployed_at, a.last_verified_at,
		       a.auth_verified_at, a.last_error, a.created_by, a.created_at, a.updated_at,
		       k.name, k.fingerprint_sha256, k.status,
		       t.name, t.address, p.username
		FROM assignments a
		JOIN keys k ON k.id = a.key_id
		JOIN targets t ON t.id = a.target_id
		JOIN principals p ON p.id = a.principal_id
		WHERE a.tenant_id = $1`
	args := []any{f.TenantID}

	add := func(clause string, val any) {
		args = append(args, val)
		q += fmt.Sprintf(clause, len(args))
	}

	if f.KeyID != nil {
		add(" AND a.key_id = $%d", *f.KeyID)
	}
	if f.TargetID != nil {
		add(" AND a.target_id = $%d", *f.TargetID)
	}
	if f.PrincipalID != nil {
		add(" AND a.principal_id = $%d", *f.PrincipalID)
	}
	if f.DesiredState != "" {
		add(" AND a.desired_state = $%d", f.DesiredState)
	}
	if f.ActualState != "" {
		add(" AND a.actual_state = $%d", f.ActualState)
	}
	if f.OnlyDrifted {
		q += " AND a.desired_state <> a.actual_state"
	}

	args = append(args, f.Limit)
	q += fmt.Sprintf(" ORDER BY t.name, p.username, k.name LIMIT $%d", len(args))
	args = append(args, f.Offset)
	q += fmt.Sprintf(" OFFSET $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing assignments: %w", err)
	}
	defer rows.Close()

	var out []AssignmentDetail
	for rows.Next() {
		var d AssignmentDetail
		if err := rows.Scan(
			&d.ID, &d.TenantID, &d.KeyID, &d.TargetID, &d.PrincipalID, &d.Options,
			&d.DesiredState, &d.ActualState, &d.DeployedAt, &d.LastVerifiedAt,
			&d.AuthVerifiedAt, &d.LastError, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
			&d.KeyName, &d.KeyFingerprint, &d.KeyStatus,
			&d.TargetName, &d.TargetAddress, &d.Username,
		); err != nil {
			return nil, fmt.Errorf("store: scanning assignment: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ForPrincipal returns every assignment on one principal, which is what the
// connector needs to compute a full desired file.
func (s *Assignments) ForPrincipal(ctx context.Context, tenantID, principalID uuid.UUID) ([]Assignment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+assignmentColumns+` FROM assignments
		 WHERE tenant_id = $1 AND principal_id = $2 ORDER BY created_at`,
		tenantID, principalID)
	if err != nil {
		return nil, fmt.Errorf("store: listing assignments for principal: %w", err)
	}
	defer rows.Close()

	var out []Assignment
	for rows.Next() {
		a, err := scanAssignment(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning assignment: %w", err)
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// RecordDeployment marks an assignment as applied.
func (s *Assignments) RecordDeployment(ctx context.Context, id uuid.UUID, state string, errMsg string) error {
	deployedAt := "deployed_at"
	if state == StatePresent && errMsg == "" {
		deployedAt = "now()"
	}

	_, err := s.pool.Exec(ctx, `
		UPDATE assignments
		SET actual_state = $2, last_error = $3, deployed_at = `+deployedAt+`,
		    last_verified_at = now(), updated_at = now()
		WHERE id = $1`, id, state, errMsg)
	if err != nil {
		return fmt.Errorf("store: recording deployment: %w", err)
	}
	return nil
}

// RecordAuthVerified stamps the moment SKM proved the key can actually
// authenticate — distinct from merely observing the line in a file.
func (s *Assignments) RecordAuthVerified(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE assignments SET auth_verified_at = now(), updated_at = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: recording auth verification: %w", err)
	}
	return nil
}

// Delete removes an assignment. This changes desired state only; the key is
// removed from the target on the next apply.
func (s *Assignments) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM assignments WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: deleting assignment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: assignment %s", ErrNotFound, id)
	}
	return nil
}

// --------------------------------------------------------------- snapshots ---

// Snapshot is a pre-mutation capture of a target's key state.
type Snapshot struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"-"`
	TargetID    uuid.UUID  `json:"target_id"`
	PrincipalID *uuid.UUID `json:"principal_id,omitempty"`
	ChangesetID *uuid.UUID `json:"changeset_id,omitempty"`
	Kind        string     `json:"kind"`
	RawContent  []byte     `json:"-"`
	Checksum    string     `json:"checksum"`
	KeyCount    int        `json:"key_count"`
	// Existed records whether the target had this file at all. Restoring a
	// snapshot with Existed false removes the file rather than writing an
	// empty one.
	Existed bool      `json:"existed"`
	TakenAt time.Time `json:"taken_at"`
}

// Snapshots is the repository for rollback captures.
type Snapshots struct{ pool *db.Pool }

// NewSnapshots returns a Snapshots repository.
func NewSnapshots(pool *db.Pool) *Snapshots { return &Snapshots{pool: pool} }

// Create stores a snapshot taken before a mutation.
func (s *Snapshots) Create(ctx context.Context, snap *Snapshot) (*Snapshot, error) {
	if snap.ID == uuid.Nil {
		snap.ID = uuid.New()
	}
	if snap.TenantID == uuid.Nil {
		snap.TenantID = DefaultTenantID
	}
	if snap.Kind == "" {
		snap.Kind = "authorized_keys"
	}
	// A target with no authorized_keys file yields nil content. That is the
	// normal state of a host that has never been managed, so it is stored as
	// empty bytes with Existed false rather than rejected as NULL.
	if snap.RawContent == nil {
		snap.RawContent = []byte{}
	}

	err := s.pool.QueryRow(ctx, `
		INSERT INTO snapshots (id, tenant_id, target_id, principal_id, changeset_id,
			kind, raw_content, checksum, key_count, existed)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING taken_at`,
		snap.ID, snap.TenantID, snap.TargetID, snap.PrincipalID, snap.ChangesetID,
		snap.Kind, snap.RawContent, snap.Checksum, snap.KeyCount, snap.Existed).Scan(&snap.TakenAt)
	if err != nil {
		return nil, fmt.Errorf("store: storing snapshot: %w", err)
	}
	return snap, nil
}

// Get returns a snapshot including its content.
func (s *Snapshots) Get(ctx context.Context, tenantID, id uuid.UUID) (*Snapshot, error) {
	var snap Snapshot
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, target_id, principal_id, changeset_id, kind,
		       raw_content, checksum, key_count, existed, taken_at
		FROM snapshots WHERE tenant_id = $1 AND id = $2`, tenantID, id).
		Scan(&snap.ID, &snap.TenantID, &snap.TargetID, &snap.PrincipalID, &snap.ChangesetID,
			&snap.Kind, &snap.RawContent, &snap.Checksum, &snap.KeyCount, &snap.Existed, &snap.TakenAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: snapshot %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading snapshot: %w", err)
	}
	return &snap, nil
}

// ListForTarget returns a target's snapshots newest-first, without content so
// the listing stays cheap.
func (s *Snapshots) ListForTarget(ctx context.Context, tenantID, targetID uuid.UUID, limit int) ([]Snapshot, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, target_id, principal_id, changeset_id, kind,
		       checksum, key_count, existed, taken_at
		FROM snapshots WHERE tenant_id = $1 AND target_id = $2
		ORDER BY taken_at DESC LIMIT $3`, tenantID, targetID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing snapshots: %w", err)
	}
	defer rows.Close()

	var out []Snapshot
	for rows.Next() {
		var snap Snapshot
		if err := rows.Scan(&snap.ID, &snap.TenantID, &snap.TargetID, &snap.PrincipalID,
			&snap.ChangesetID, &snap.Kind, &snap.Checksum, &snap.KeyCount,
			&snap.Existed, &snap.TakenAt); err != nil {
			return nil, fmt.Errorf("store: scanning snapshot: %w", err)
		}
		out = append(out, snap)
	}
	return out, rows.Err()
}

// -------------------------------------------------------------- changesets ---

// Changeset groups a set of mutations so they can be rolled back together.
type Changeset struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"-"`
	Kind       string     `json:"kind"`
	Summary    string     `json:"summary"`
	State      string     `json:"state"`
	InverseOps []any      `json:"inverse_ops"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
}

// Changeset kinds and states.
const (
	ChangesetDeploy    = "deploy"
	ChangesetRotation  = "rotation"
	ChangesetRollback  = "rollback"
	ChangesetReconcile = "reconcile"

	ChangesetOpen       = "open"
	ChangesetCommitted  = "committed"
	ChangesetRolledBack = "rolled_back"
	ChangesetFailed     = "failed"
)

// Changesets is the repository for rollback units.
type Changesets struct{ pool *db.Pool }

// NewChangesets returns a Changesets repository.
func NewChangesets(pool *db.Pool) *Changesets { return &Changesets{pool: pool} }

// Create opens a changeset.
func (s *Changesets) Create(ctx context.Context, cs *Changeset) (*Changeset, error) {
	if cs.ID == uuid.Nil {
		cs.ID = uuid.New()
	}
	if cs.TenantID == uuid.Nil {
		cs.TenantID = DefaultTenantID
	}
	if cs.State == "" {
		cs.State = ChangesetOpen
	}
	if cs.InverseOps == nil {
		cs.InverseOps = []any{}
	}

	ops, err := json.Marshal(cs.InverseOps)
	if err != nil {
		return nil, fmt.Errorf("store: encoding inverse operations: %w", err)
	}

	if err := s.pool.QueryRow(ctx, `
		INSERT INTO changesets (id, tenant_id, kind, summary, state, inverse_ops, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
		cs.ID, cs.TenantID, cs.Kind, cs.Summary, cs.State, ops, cs.CreatedBy).
		Scan(&cs.CreatedAt); err != nil {
		return nil, fmt.Errorf("store: creating changeset: %w", err)
	}
	return cs, nil
}

// AppendInverse records an operation that would undo part of this changeset.
//
// Appending in the database rather than in memory means a crash mid-change
// still leaves a rollback path for whatever had already been applied.
func (s *Changesets) AppendInverse(ctx context.Context, id uuid.UUID, op any) error {
	encoded, err := json.Marshal(op)
	if err != nil {
		return fmt.Errorf("store: encoding inverse operation: %w", err)
	}

	if _, err := s.pool.Exec(ctx,
		`UPDATE changesets SET inverse_ops = inverse_ops || $2::jsonb WHERE id = $1`,
		id, encoded); err != nil {
		return fmt.Errorf("store: appending inverse operation: %w", err)
	}
	return nil
}

// SetState closes a changeset.
func (s *Changesets) SetState(ctx context.Context, id uuid.UUID, state string) error {
	closed := "closed_at"
	if state != ChangesetOpen {
		closed = "now()"
	}

	if _, err := s.pool.Exec(ctx,
		`UPDATE changesets SET state = $2, closed_at = `+closed+` WHERE id = $1`,
		id, state); err != nil {
		return fmt.Errorf("store: updating changeset state: %w", err)
	}
	return nil
}

// Get returns a changeset.
func (s *Changesets) Get(ctx context.Context, tenantID, id uuid.UUID) (*Changeset, error) {
	var (
		cs  Changeset
		ops []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, kind, summary, state, inverse_ops, created_by, created_at, closed_at
		FROM changesets WHERE tenant_id = $1 AND id = $2`, tenantID, id).
		Scan(&cs.ID, &cs.TenantID, &cs.Kind, &cs.Summary, &cs.State, &ops,
			&cs.CreatedBy, &cs.CreatedAt, &cs.ClosedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: changeset %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading changeset: %w", err)
	}

	if len(ops) > 0 {
		if err := json.Unmarshal(ops, &cs.InverseOps); err != nil {
			return nil, fmt.Errorf("store: decoding inverse operations: %w", err)
		}
	}
	return &cs, nil
}

// List returns changesets newest-first.
func (s *Changesets) List(ctx context.Context, tenantID uuid.UUID, limit int) ([]Changeset, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, kind, summary, state, created_by, created_at, closed_at
		FROM changesets WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2`,
		tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing changesets: %w", err)
	}
	defer rows.Close()

	var out []Changeset
	for rows.Next() {
		var cs Changeset
		if err := rows.Scan(&cs.ID, &cs.TenantID, &cs.Kind, &cs.Summary, &cs.State,
			&cs.CreatedBy, &cs.CreatedAt, &cs.ClosedAt); err != nil {
			return nil, fmt.Errorf("store: scanning changeset: %w", err)
		}
		out = append(out, cs)
	}
	return out, rows.Err()
}

func scanAssignment(row interface{ Scan(...any) error }) (*Assignment, error) {
	var a Assignment
	err := row.Scan(&a.ID, &a.TenantID, &a.KeyID, &a.TargetID, &a.PrincipalID, &a.Options,
		&a.DesiredState, &a.ActualState, &a.DeployedAt, &a.LastVerifiedAt,
		&a.AuthVerifiedAt, &a.LastError, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}
