package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hamalawy/ssh-key-manager/backend/internal/db"
)

// Selector chooses which keys and targets a rotation policy governs.
//
// Selection is by tag rather than by explicit list because a fleet changes
// faster than a policy does: a host that gains the "production" tag should be
// covered by the production rotation policy without anyone remembering to edit
// it.
type Selector struct {
	KeyTags    []string    `json:"key_tags,omitempty"`
	TargetTags []string    `json:"target_tags,omitempty"`
	KeyIDs     []uuid.UUID `json:"key_ids,omitempty"`
	KeyClass   string      `json:"key_class,omitempty"`
}

// Empty reports whether the selector would match nothing at all. A policy with
// an empty selector is refused rather than being interpreted as "everything".
func (s Selector) Empty() bool {
	return len(s.KeyTags) == 0 && len(s.TargetTags) == 0 && len(s.KeyIDs) == 0 && s.KeyClass == ""
}

// RotationPolicy schedules unattended rotation.
type RotationPolicy struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"-"`
	Name     string    `json:"name"`
	Enabled  bool      `json:"enabled"`

	Selector Selector `json:"selector"`

	CronExpr  string `json:"cron_expr"`
	MaxAgeSec int64  `json:"max_age_seconds"`
	Algorithm string `json:"algorithm"`

	SoakPeriodSec    int64 `json:"soak_period_seconds"`
	CanaryPercent    int   `json:"canary_percent"`
	FailureThreshold int   `json:"failure_threshold"`

	ApprovalRequired bool        `json:"approval_required"`
	NotifyWebhooks   []uuid.UUID `json:"notify_webhooks"`

	LastRunAt *time.Time `json:"last_run_at,omitempty"`
	NextRunAt *time.Time `json:"next_run_at,omitempty"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// SoakPeriod returns the configured soak window.
func (p *RotationPolicy) SoakPeriod() time.Duration {
	return time.Duration(p.SoakPeriodSec) * time.Second
}

// MaxAge returns the age at which a key becomes due for rotation, or zero when
// age is not a trigger for this policy.
func (p *RotationPolicy) MaxAge() time.Duration {
	return time.Duration(p.MaxAgeSec) * time.Second
}

// Rotation is one execution of the add-before-remove state machine.
type Rotation struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"-"`
	PolicyID    *uuid.UUID `json:"policy_id,omitempty"`
	OldKeyID    *uuid.UUID `json:"old_key_id,omitempty"`
	NewKeyID    *uuid.UUID `json:"new_key_id,omitempty"`
	ChangesetID *uuid.UUID `json:"changeset_id,omitempty"`

	State   string `json:"state"`
	Wave    int    `json:"wave"`
	Trigger string `json:"trigger"`
	DryRun  bool   `json:"dry_run"`

	SoakUntil *time.Time `json:"soak_until,omitempty"`

	TargetsTotal    int `json:"targets_total"`
	TargetsStaged   int `json:"targets_staged"`
	TargetsVerified int `json:"targets_verified"`
	TargetsRetired  int `json:"targets_retired"`
	TargetsFailed   int `json:"targets_failed"`

	ApprovedBy *uuid.UUID `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	Error      string     `json:"error,omitempty"`

	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Rotation states, in the order the machine walks them.
const (
	RotationPlanned    = "planned"
	RotationAwaiting   = "awaiting_approval"
	RotationStaging    = "staging"
	RotationStaged     = "staged"
	RotationVerifying  = "verifying"
	RotationVerified   = "verified"
	RotationPromoting  = "promoting"
	RotationSoaking    = "soaking"
	RotationRetiring   = "retiring"
	RotationCompleted  = "completed"
	RotationAborted    = "aborted"
	RotationRolledBack = "rolled_back"
	RotationFailed     = "failed"
)

// Rotation triggers.
const (
	TriggerManual     = "manual"
	TriggerSchedule   = "schedule"
	TriggerAPI        = "api"
	TriggerCompromise = "compromise"
	TriggerExpiry     = "expiry"
)

// RotationFinished reports whether a rotation will make no further progress.
func RotationFinished(state string) bool {
	switch state {
	case RotationCompleted, RotationAborted, RotationRolledBack, RotationFailed:
		return true
	}
	return false
}

// RotationTarget is one target's progress within a rotation, so a partial
// failure names the hosts it happened on instead of just a count.
type RotationTarget struct {
	RotationID  uuid.UUID `json:"rotation_id"`
	TargetID    uuid.UUID `json:"target_id"`
	PrincipalID uuid.UUID `json:"principal_id"`
	Wave        int       `json:"wave"`
	State       string    `json:"state"`
	Error       string    `json:"error,omitempty"`

	StagedAt   *time.Time `json:"staged_at,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	RetiredAt  *time.Time `json:"retired_at,omitempty"`

	// TargetName and Username are joined in for display.
	TargetName string `json:"target_name,omitempty"`
	Username   string `json:"username,omitempty"`
}

// Per-target rotation states.
const (
	RTPending  = "pending"
	RTStaged   = "staged"
	RTVerified = "verified"
	RTRetired  = "retired"
	RTFailed   = "failed"
	RTSkipped  = "skipped"
)

// Rotations is the repository for policies, runs, and per-target progress.
type Rotations struct{ pool *db.Pool }

// NewRotations returns a Rotations repository.
func NewRotations(pool *db.Pool) *Rotations { return &Rotations{pool: pool} }

// Interval columns are read as seconds rather than as pgtype.Interval: the
// application only ever needs a duration, and an integer round-trips through
// JSON to the interface without a custom encoder.
const policyColumns = `id, tenant_id, name, enabled, selector, cron_expr,
	COALESCE(EXTRACT(EPOCH FROM max_age)::bigint, 0),
	algorithm,
	EXTRACT(EPOCH FROM soak_period)::bigint,
	canary_percent, failure_threshold, approval_required, notify_webhooks,
	last_run_at, next_run_at, created_by, created_at, updated_at`

// CreatePolicy stores a rotation policy.
func (s *Rotations) CreatePolicy(ctx context.Context, p *RotationPolicy) (*RotationPolicy, error) {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if p.TenantID == uuid.Nil {
		p.TenantID = DefaultTenantID
	}
	if p.Algorithm == "" {
		p.Algorithm = "ed25519"
	}
	if p.SoakPeriodSec == 0 {
		p.SoakPeriodSec = int64((24 * time.Hour).Seconds())
	}
	if p.NotifyWebhooks == nil {
		p.NotifyWebhooks = []uuid.UUID{}
	}
	if p.Selector.Empty() {
		return nil, fmt.Errorf("%w: a rotation policy needs a selector; an empty one would match every key", ErrConflict)
	}

	selector, err := json.Marshal(p.Selector)
	if err != nil {
		return nil, fmt.Errorf("store: encoding selector: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO rotation_policies (id, tenant_id, name, enabled, selector,
			cron_expr, max_age, algorithm, soak_period, canary_percent,
			failure_threshold, approval_required, notify_webhooks, next_run_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,
			CASE WHEN $7::bigint = 0 THEN NULL ELSE make_interval(secs => $7::bigint) END,
			$8, make_interval(secs => $9::bigint), $10,$11,$12,$13,$14,$15)
		RETURNING `+policyColumns,
		p.ID, p.TenantID, p.Name, p.Enabled, selector, p.CronExpr, p.MaxAgeSec,
		p.Algorithm, p.SoakPeriodSec, p.CanaryPercent, p.FailureThreshold,
		p.ApprovalRequired, p.NotifyWebhooks, p.NextRunAt, p.CreatedBy)

	created, err := scanPolicy(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: a policy named %q already exists", ErrConflict, p.Name)
		}
		return nil, fmt.Errorf("store: inserting rotation policy: %w", err)
	}
	return created, nil
}

// GetPolicy returns one policy.
func (s *Rotations) GetPolicy(ctx context.Context, tenantID, id uuid.UUID) (*RotationPolicy, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+policyColumns+` FROM rotation_policies WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)

	p, err := scanPolicy(row)
	if err != nil {
		return nil, fmt.Errorf("store: loading rotation policy %s: %w", id, err)
	}
	return p, nil
}

// ListPolicies returns every policy for a tenant.
func (s *Rotations) ListPolicies(ctx context.Context, tenantID uuid.UUID) ([]RotationPolicy, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+policyColumns+` FROM rotation_policies WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: listing rotation policies: %w", err)
	}
	defer rows.Close()

	out := []RotationPolicy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// UpdatePolicy rewrites a policy's mutable fields.
func (s *Rotations) UpdatePolicy(ctx context.Context, p *RotationPolicy) (*RotationPolicy, error) {
	if p.Selector.Empty() {
		return nil, fmt.Errorf("%w: a rotation policy needs a selector", ErrConflict)
	}

	selector, err := json.Marshal(p.Selector)
	if err != nil {
		return nil, fmt.Errorf("store: encoding selector: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE rotation_policies SET name = $3, enabled = $4, selector = $5,
			cron_expr = $6,
			max_age = CASE WHEN $7::bigint = 0 THEN NULL ELSE make_interval(secs => $7::bigint) END,
			algorithm = $8, soak_period = make_interval(secs => $9::bigint),
			canary_percent = $10, failure_threshold = $11, approval_required = $12,
			notify_webhooks = $13, next_run_at = $14, updated_at = now()
		WHERE tenant_id = $1 AND id = $2
		RETURNING `+policyColumns,
		p.TenantID, p.ID, p.Name, p.Enabled, selector, p.CronExpr, p.MaxAgeSec,
		p.Algorithm, p.SoakPeriodSec, p.CanaryPercent, p.FailureThreshold,
		p.ApprovalRequired, p.NotifyWebhooks, p.NextRunAt)

	updated, err := scanPolicy(row)
	if err != nil {
		return nil, fmt.Errorf("store: updating rotation policy: %w", err)
	}
	return updated, nil
}

// DeletePolicy removes a policy. Rotations it produced are kept, with their
// policy reference nulled, because deleting the schedule should not erase the
// history of what it did.
func (s *Rotations) DeletePolicy(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM rotation_policies WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: deleting rotation policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DuePolicies returns enabled policies whose next run has arrived.
func (s *Rotations) DuePolicies(ctx context.Context, now time.Time) ([]RotationPolicy, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+policyColumns+` FROM rotation_policies
		WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= $1
		ORDER BY next_run_at ASC`, now)
	if err != nil {
		return nil, fmt.Errorf("store: listing due policies: %w", err)
	}
	defer rows.Close()

	out := []RotationPolicy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// MarkPolicyRun records that a policy fired and schedules its next run.
func (s *Rotations) MarkPolicyRun(ctx context.Context, id uuid.UUID, next *time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE rotation_policies SET last_run_at = now(), next_run_at = $2, updated_at = now()
		 WHERE id = $1`, id, next)
	if err != nil {
		return fmt.Errorf("store: recording policy run: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- rotations ---

const rotationColumns = `id, tenant_id, policy_id, old_key_id, new_key_id,
	changeset_id, state, wave, trigger, dry_run, soak_until, targets_total,
	targets_staged, targets_verified, targets_retired, targets_failed,
	approved_by, approved_at, error, created_by, created_at, updated_at, completed_at`

// CreateRotation opens a new rotation run.
func (s *Rotations) CreateRotation(ctx context.Context, r *Rotation) (*Rotation, error) {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	if r.TenantID == uuid.Nil {
		r.TenantID = DefaultTenantID
	}
	if r.State == "" {
		r.State = RotationPlanned
	}
	if r.Trigger == "" {
		r.Trigger = TriggerManual
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO rotations (id, tenant_id, policy_id, old_key_id, new_key_id,
			changeset_id, state, trigger, dry_run, targets_total, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING `+rotationColumns,
		r.ID, r.TenantID, r.PolicyID, r.OldKeyID, r.NewKeyID, r.ChangesetID,
		r.State, r.Trigger, r.DryRun, r.TargetsTotal, r.CreatedBy)

	created, err := scanRotation(row)
	if err != nil {
		return nil, fmt.Errorf("store: inserting rotation: %w", err)
	}
	return created, nil
}

// GetRotation returns one rotation.
func (s *Rotations) GetRotation(ctx context.Context, tenantID, id uuid.UUID) (*Rotation, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+rotationColumns+` FROM rotations WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	r, err := scanRotation(row)
	if err != nil {
		return nil, fmt.Errorf("store: loading rotation %s: %w", id, err)
	}
	return r, nil
}

// ListRotations returns rotations newest first.
func (s *Rotations) ListRotations(ctx context.Context, tenantID uuid.UUID, states []string, limit int) ([]Rotation, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	query := `SELECT ` + rotationColumns + ` FROM rotations WHERE tenant_id = $1`
	args := []any{tenantID}
	if len(states) > 0 {
		args = append(args, states)
		query += fmt.Sprintf(" AND state = ANY($%d)", len(args))
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing rotations: %w", err)
	}
	defer rows.Close()

	out := []Rotation{}
	for rows.Next() {
		r, err := scanRotation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// SetRotationState advances a rotation, refusing a transition the machine does
// not define. The guard lives here rather than only in the engine so that a
// concurrent worker cannot drive a rotation backwards.
func (s *Rotations) SetRotationState(ctx context.Context, id uuid.UUID, from []string, to string, errMsg string) (*Rotation, error) {
	completed := RotationFinished(to)

	row := s.pool.QueryRow(ctx, `
		UPDATE rotations SET state = $3, error = $4,
			completed_at = CASE WHEN $5 THEN now() ELSE completed_at END,
			updated_at = now()
		WHERE id = $1 AND ($2::text[] IS NULL OR state = ANY($2))
		RETURNING `+rotationColumns,
		id, nullableStrings(from), to, truncate(errMsg, 4000), completed)

	r, err := scanRotation(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("%w: rotation %s is not in a state that allows %q", ErrConflict, id, to)
		}
		return nil, fmt.Errorf("store: advancing rotation: %w", err)
	}
	return r, nil
}

// SetRotationKeys records the generated key and the changeset grouping the run.
func (s *Rotations) SetRotationKeys(ctx context.Context, id uuid.UUID, newKeyID, changesetID *uuid.UUID, total int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE rotations SET new_key_id = COALESCE($2, new_key_id),
			changeset_id = COALESCE($3, changeset_id),
			targets_total = $4, updated_at = now() WHERE id = $1`,
		id, newKeyID, changesetID, total)
	if err != nil {
		return fmt.Errorf("store: recording rotation keys: %w", err)
	}
	return nil
}

// SetSoakUntil records when the soak window closes.
func (s *Rotations) SetSoakUntil(ctx context.Context, id uuid.UUID, until time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE rotations SET soak_until = $2, updated_at = now() WHERE id = $1`, id, until)
	if err != nil {
		return fmt.Errorf("store: setting soak window: %w", err)
	}
	return nil
}

// Approve records an approval, unblocking a policy that requires one.
func (s *Rotations) Approve(ctx context.Context, tenantID, id, userID uuid.UUID) (*Rotation, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE rotations SET approved_by = $3, approved_at = now(),
			state = 'planned', updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND state = 'awaiting_approval'
		RETURNING `+rotationColumns, tenantID, id, userID)

	r, err := scanRotation(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("%w: rotation %s is not awaiting approval", ErrConflict, id)
		}
		return nil, fmt.Errorf("store: approving rotation: %w", err)
	}
	return r, nil
}

// SoakExpired returns soaking rotations whose window has closed and which are
// therefore ready to retire the old key.
func (s *Rotations) SoakExpired(ctx context.Context, now time.Time) ([]Rotation, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+rotationColumns+` FROM rotations
		WHERE state = 'soaking' AND soak_until IS NOT NULL AND soak_until <= $1`, now)
	if err != nil {
		return nil, fmt.Errorf("store: listing expired soaks: %w", err)
	}
	defer rows.Close()

	out := []Rotation{}
	for rows.Next() {
		r, err := scanRotation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// ----------------------------------------------------- per-target progress ---

// AddRotationTarget records a target as part of a rotation's wave plan.
func (s *Rotations) AddRotationTarget(ctx context.Context, rt *RotationTarget) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rotation_targets (rotation_id, target_id, principal_id, wave, state)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (rotation_id, target_id, principal_id) DO UPDATE SET wave = EXCLUDED.wave`,
		rt.RotationID, rt.TargetID, rt.PrincipalID, rt.Wave, orDefault(rt.State, RTPending))
	if err != nil {
		return fmt.Errorf("store: adding rotation target: %w", err)
	}
	return nil
}

// SetRotationTargetState records one target's outcome and keeps the rotation's
// aggregate counters in step, so the interface never shows a total that
// disagrees with the rows behind it.
func (s *Rotations) SetRotationTargetState(ctx context.Context, rotationID, targetID, principalID uuid.UUID, state, errMsg string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: beginning rotation target update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var stamp string
	switch state {
	case RTStaged:
		stamp = ", staged_at = now()"
	case RTVerified:
		stamp = ", verified_at = now()"
	case RTRetired:
		stamp = ", retired_at = now()"
	}

	if _, err := tx.Exec(ctx, `
		UPDATE rotation_targets SET state = $4, error = $5`+stamp+`
		WHERE rotation_id = $1 AND target_id = $2 AND principal_id = $3`,
		rotationID, targetID, principalID, state, truncate(errMsg, 2000)); err != nil {
		return fmt.Errorf("store: updating rotation target: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE rotations SET
			targets_staged = (SELECT count(*) FROM rotation_targets
				WHERE rotation_id = $1 AND state IN ('staged','verified','retired')),
			targets_verified = (SELECT count(*) FROM rotation_targets
				WHERE rotation_id = $1 AND state IN ('verified','retired')),
			targets_retired = (SELECT count(*) FROM rotation_targets
				WHERE rotation_id = $1 AND state = 'retired'),
			targets_failed = (SELECT count(*) FROM rotation_targets
				WHERE rotation_id = $1 AND state = 'failed'),
			updated_at = now()
		WHERE id = $1`, rotationID); err != nil {
		return fmt.Errorf("store: refreshing rotation counters: %w", err)
	}

	return tx.Commit(ctx)
}

// ListRotationTargets returns per-target progress, joined with display names.
func (s *Rotations) ListRotationTargets(ctx context.Context, rotationID uuid.UUID) ([]RotationTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT rt.rotation_id, rt.target_id, rt.principal_id, rt.wave, rt.state,
			rt.error, rt.staged_at, rt.verified_at, rt.retired_at,
			t.name, p.username
		FROM rotation_targets rt
		JOIN targets t ON t.id = rt.target_id
		JOIN principals p ON p.id = rt.principal_id
		WHERE rt.rotation_id = $1
		ORDER BY rt.wave, t.name, p.username`, rotationID)
	if err != nil {
		return nil, fmt.Errorf("store: listing rotation targets: %w", err)
	}
	defer rows.Close()

	out := []RotationTarget{}
	for rows.Next() {
		var rt RotationTarget
		if err := rows.Scan(&rt.RotationID, &rt.TargetID, &rt.PrincipalID, &rt.Wave,
			&rt.State, &rt.Error, &rt.StagedAt, &rt.VerifiedAt, &rt.RetiredAt,
			&rt.TargetName, &rt.Username); err != nil {
			return nil, fmt.Errorf("store: scanning rotation target: %w", err)
		}
		out = append(out, rt)
	}
	return out, rows.Err()
}

// WaveTargets returns the members of one wave in a given state.
func (s *Rotations) WaveTargets(ctx context.Context, rotationID uuid.UUID, wave int, states []string) ([]RotationTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT rt.rotation_id, rt.target_id, rt.principal_id, rt.wave, rt.state,
			rt.error, rt.staged_at, rt.verified_at, rt.retired_at, t.name, p.username
		FROM rotation_targets rt
		JOIN targets t ON t.id = rt.target_id
		JOIN principals p ON p.id = rt.principal_id
		WHERE rt.rotation_id = $1 AND rt.wave = $2
			AND ($3::text[] IS NULL OR rt.state = ANY($3))
		ORDER BY t.name, p.username`, rotationID, wave, nullableStrings(states))
	if err != nil {
		return nil, fmt.Errorf("store: listing wave targets: %w", err)
	}
	defer rows.Close()

	out := []RotationTarget{}
	for rows.Next() {
		var rt RotationTarget
		if err := rows.Scan(&rt.RotationID, &rt.TargetID, &rt.PrincipalID, &rt.Wave,
			&rt.State, &rt.Error, &rt.StagedAt, &rt.VerifiedAt, &rt.RetiredAt,
			&rt.TargetName, &rt.Username); err != nil {
			return nil, err
		}
		out = append(out, rt)
	}
	return out, rows.Err()
}

// MaxWave returns the highest wave number planned for a rotation.
func (s *Rotations) MaxWave(ctx context.Context, rotationID uuid.UUID) (int, error) {
	var max int
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(wave), 0) FROM rotation_targets WHERE rotation_id = $1`,
		rotationID).Scan(&max)
	if err != nil {
		return 0, fmt.Errorf("store: reading wave count: %w", err)
	}
	return max, nil
}

// SetWave records which wave a rotation is currently working.
func (s *Rotations) SetWave(ctx context.Context, id uuid.UUID, wave int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE rotations SET wave = $2, updated_at = now() WHERE id = $1`, id, wave)
	if err != nil {
		return fmt.Errorf("store: setting rotation wave: %w", err)
	}
	return nil
}

func scanPolicy(row interface{ Scan(...any) error }) (*RotationPolicy, error) {
	var p RotationPolicy
	var selector []byte
	err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Enabled, &selector, &p.CronExpr,
		&p.MaxAgeSec, &p.Algorithm, &p.SoakPeriodSec, &p.CanaryPercent,
		&p.FailureThreshold, &p.ApprovalRequired, &p.NotifyWebhooks,
		&p.LastRunAt, &p.NextRunAt, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(selector) > 0 {
		if err := json.Unmarshal(selector, &p.Selector); err != nil {
			return nil, fmt.Errorf("store: decoding selector: %w", err)
		}
	}
	return &p, nil
}

func scanRotation(row interface{ Scan(...any) error }) (*Rotation, error) {
	var r Rotation
	err := row.Scan(&r.ID, &r.TenantID, &r.PolicyID, &r.OldKeyID, &r.NewKeyID,
		&r.ChangesetID, &r.State, &r.Wave, &r.Trigger, &r.DryRun, &r.SoakUntil,
		&r.TargetsTotal, &r.TargetsStaged, &r.TargetsVerified, &r.TargetsRetired,
		&r.TargetsFailed, &r.ApprovedBy, &r.ApprovedAt, &r.Error, &r.CreatedBy,
		&r.CreatedAt, &r.UpdatedAt, &r.CompletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}

// nullableStrings turns an empty slice into a SQL NULL, so "no filter" and
// "filter on nothing" stay distinguishable in a query.
func nullableStrings(v []string) any {
	if len(v) == 0 {
		return nil
	}
	return v
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
