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

// Job is one unit of background work.
//
// The queue lives in PostgreSQL rather than a broker because SKM already
// depends on PostgreSQL for correctness-critical state, and a second stateful
// system would mean a second way to lose it. FOR UPDATE SKIP LOCKED gives
// competing workers exactly-once-at-a-time delivery without polling contention.
type Job struct {
	ID       uuid.UUID       `json:"id"`
	TenantID uuid.UUID       `json:"-"`
	Type     string          `json:"type"`
	Payload  json.RawMessage `json:"payload"`
	State    string          `json:"state"`
	Priority int             `json:"priority"`

	Attempts    int       `json:"attempts"`
	MaxAttempts int       `json:"max_attempts"`
	RunAfter    time.Time `json:"run_after"`

	IdempotencyKey *string `json:"idempotency_key,omitempty"`

	RotationID  *uuid.UUID `json:"rotation_id,omitempty"`
	ChangesetID *uuid.UUID `json:"changeset_id,omitempty"`
	TargetID    *uuid.UUID `json:"target_id,omitempty"`

	LockedBy   string     `json:"locked_by,omitempty"`
	LockedAt   *time.Time `json:"locked_at,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	Result     []byte     `json:"result,omitempty"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Job states.
const (
	JobQueued    = "queued"
	JobRunning   = "running"
	JobSucceeded = "succeeded"
	JobFailed    = "failed"
	JobCancelled = "cancelled"
	// JobDead means the job exhausted its attempts. It stays in the table for
	// inspection rather than disappearing, because a job that gave up is
	// exactly the thing an operator needs to see.
	JobDead = "dead"
)

// Job types dispatched by the worker pool.
const (
	JobTypeDeploy         = "deploy"
	JobTypeRotationStage  = "rotation.stage"
	JobTypeRotationVerify = "rotation.verify"
	JobTypeRotationRetire = "rotation.retire"
	JobTypeRotationStep   = "rotation.step"
	JobTypeReconcile      = "reconcile"
	JobTypeWebhook        = "webhook.deliver"
	JobTypeConsumer       = "consumer.deliver"
	JobTypeBackup         = "backup.create"
)

// Terminal reports whether a state means the job will not run again.
func JobTerminal(state string) bool {
	switch state {
	case JobSucceeded, JobCancelled, JobDead:
		return true
	}
	return false
}

// Jobs is the work-queue repository.
type Jobs struct{ pool *db.Pool }

// NewJobs returns a Jobs repository.
func NewJobs(pool *db.Pool) *Jobs { return &Jobs{pool: pool} }

const jobColumns = `id, tenant_id, type, payload, state, priority, attempts,
	max_attempts, run_after, idempotency_key, rotation_id, changeset_id,
	target_id, locked_by, locked_at, started_at, finished_at, last_error,
	result, created_by, created_at, updated_at`

// Enqueue adds a job.
//
// When an idempotency key is set and an equivalent job is already queued or
// running, the existing job is returned instead of a duplicate being created.
// This is what makes a retried API call, a re-fired cron tick, and a restarted
// worker all safe.
func (s *Jobs) Enqueue(ctx context.Context, j *Job) (*Job, error) {
	if j.ID == uuid.Nil {
		j.ID = uuid.New()
	}
	if j.TenantID == uuid.Nil {
		j.TenantID = DefaultTenantID
	}
	if j.Priority == 0 {
		j.Priority = 100
	}
	if j.MaxAttempts == 0 {
		j.MaxAttempts = 5
	}
	if j.RunAfter.IsZero() {
		j.RunAfter = time.Now()
	}
	if len(j.Payload) == 0 {
		j.Payload = json.RawMessage(`{}`)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO jobs (id, tenant_id, type, payload, priority, max_attempts,
			run_after, idempotency_key, rotation_id, changeset_id, target_id, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING `+jobColumns,
		j.ID, j.TenantID, j.Type, []byte(j.Payload), j.Priority, j.MaxAttempts,
		j.RunAfter, j.IdempotencyKey, j.RotationID, j.ChangesetID, j.TargetID, j.CreatedBy)

	created, err := scanJob(row)
	if err != nil {
		if isUniqueViolation(err) && j.IdempotencyKey != nil {
			return s.byIdempotencyKey(ctx, j.TenantID, *j.IdempotencyKey)
		}
		return nil, fmt.Errorf("store: enqueueing job: %w", err)
	}
	return created, nil
}

func (s *Jobs) byIdempotencyKey(ctx context.Context, tenantID uuid.UUID, key string) (*Job, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+jobColumns+` FROM jobs
		WHERE tenant_id = $1 AND idempotency_key = $2 AND state IN ('queued','running')
		ORDER BY created_at DESC LIMIT 1`, tenantID, key)

	j, err := scanJob(row)
	if err != nil {
		return nil, fmt.Errorf("store: locating the existing job for idempotency key %q: %w", key, err)
	}
	return j, nil
}

// Dequeue leases up to limit runnable jobs for a worker.
//
// SKIP LOCKED is the whole trick: a worker takes rows no other worker holds and
// never blocks waiting for one, so throughput scales with worker count instead
// of collapsing into lock contention.
func (s *Jobs) Dequeue(ctx context.Context, workerID string, types []string, limit int) ([]Job, error) {
	if limit <= 0 {
		limit = 1
	}

	typeFilter := ""
	args := []any{workerID, limit}
	if len(types) > 0 {
		typeFilter = " AND type = ANY($3)"
		args = append(args, types)
	}

	rows, err := s.pool.Query(ctx, `
		UPDATE jobs SET
			state = 'running',
			attempts = attempts + 1,
			locked_by = $1,
			locked_at = now(),
			started_at = COALESCE(started_at, now()),
			updated_at = now()
		WHERE id IN (
			SELECT id FROM jobs
			WHERE state = 'queued' AND run_after <= now()`+typeFilter+`
			ORDER BY priority ASC, run_after ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		RETURNING `+jobColumns, args...)
	if err != nil {
		return nil, fmt.Errorf("store: dequeueing jobs: %w", err)
	}
	defer rows.Close()

	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

// Succeed marks a job complete, storing its result.
func (s *Jobs) Succeed(ctx context.Context, id uuid.UUID, result any) error {
	var payload []byte
	if result != nil {
		encoded, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("store: encoding job result: %w", err)
		}
		payload = encoded
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE jobs SET state = 'succeeded', result = $2, finished_at = now(),
			last_error = '', locked_by = '', locked_at = NULL, updated_at = now()
		WHERE id = $1`, id, payload)
	if err != nil {
		return fmt.Errorf("store: completing job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Fail records an attempt failure, requeueing with backoff until the attempt
// budget runs out, at which point the job is dead rather than silently retried
// forever.
func (s *Jobs) Fail(ctx context.Context, id uuid.UUID, cause error, backoff time.Duration) (dead bool, err error) {
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE jobs SET
			state = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
			run_after = now() + $3::interval,
			last_error = $2,
			locked_by = '', locked_at = NULL,
			finished_at = CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END,
			updated_at = now()
		WHERE id = $1
		RETURNING state = 'dead'`, id, truncate(msg, 4000), backoff.String())

	if err := row.Scan(&dead); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("store: failing job: %w", err)
	}
	return dead, nil
}

// Kill marks a job dead immediately, without spending its remaining attempts.
//
// It exists for failures retrying cannot fix — a malformed payload, a deleted
// target, a refused permission. Attempting those five times only delays the
// operator finding out.
func (s *Jobs) Kill(ctx context.Context, id uuid.UUID, cause error) error {
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE jobs SET state = 'dead', last_error = $2, finished_at = now(),
			locked_by = '', locked_at = NULL, run_after = now(), updated_at = now()
		WHERE id = $1 AND state NOT IN ('succeeded','cancelled')`,
		id, truncate(msg, 4000))
	if err != nil {
		return fmt.Errorf("store: killing job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Cancel stops a job that has not yet finished.
func (s *Jobs) Cancel(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE jobs SET state = 'cancelled', finished_at = now(), updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND state IN ('queued','running')`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: cancelling job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Heartbeat refreshes a lease so a long-running job is not reaped as stalled.
func (s *Jobs) Heartbeat(ctx context.Context, id uuid.UUID, workerID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE jobs SET locked_at = now() WHERE id = $1 AND locked_by = $2 AND state = 'running'`,
		id, workerID)
	if err != nil {
		return fmt.Errorf("store: refreshing job lease: %w", err)
	}
	return nil
}

// ReapStalled requeues jobs whose worker died holding the lease.
//
// Without this a killed process leaves work permanently "running". The chaos
// test relies on it: kill the server mid-rotation and the rotation resumes.
func (s *Jobs) ReapStalled(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE jobs SET
			state = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
			locked_by = '', locked_at = NULL,
			last_error = 'worker lease expired; the job was requeued',
			updated_at = now()
		WHERE state = 'running' AND locked_at < now() - $1::interval`, olderThan.String())
	if err != nil {
		return 0, fmt.Errorf("store: reaping stalled jobs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Get returns one job.
func (s *Jobs) Get(ctx context.Context, tenantID, id uuid.UUID) (*Job, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+jobColumns+` FROM jobs WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	j, err := scanJob(row)
	if err != nil {
		return nil, fmt.Errorf("store: loading job %s: %w", id, err)
	}
	return j, nil
}

// JobFilter narrows a job listing.
type JobFilter struct {
	TenantID   uuid.UUID
	States     []string
	Types      []string
	RotationID *uuid.UUID
	TargetID   *uuid.UUID
	Limit      int
}

// List returns jobs newest first.
func (s *Jobs) List(ctx context.Context, f JobFilter) ([]Job, error) {
	if f.TenantID == uuid.Nil {
		f.TenantID = DefaultTenantID
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}

	var conds []string
	args := []any{f.TenantID}
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}

	if len(f.States) > 0 {
		add("state = ANY($%d)", f.States)
	}
	if len(f.Types) > 0 {
		add("type = ANY($%d)", f.Types)
	}
	if f.RotationID != nil {
		add("rotation_id = $%d", *f.RotationID)
	}
	if f.TargetID != nil {
		add("target_id = $%d", *f.TargetID)
	}

	query := `SELECT ` + jobColumns + ` FROM jobs WHERE tenant_id = $1`
	if len(conds) > 0 {
		query += " AND " + strings.Join(conds, " AND ")
	}
	args = append(args, f.Limit)
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing jobs: %w", err)
	}
	defer rows.Close()

	out := []Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

// JobLog is one line of a job's progress, streamed to the interface.
type JobLog struct {
	ID       int64           `json:"id"`
	JobID    uuid.UUID       `json:"job_id"`
	Level    string          `json:"level"`
	Message  string          `json:"message"`
	Fields   json.RawMessage `json:"fields,omitempty"`
	LoggedAt time.Time       `json:"logged_at"`
}

// AppendLog records a progress line against a job.
func (s *Jobs) AppendLog(ctx context.Context, jobID uuid.UUID, level, message string, fields map[string]any) error {
	var encoded []byte
	if len(fields) > 0 {
		b, err := json.Marshal(fields)
		if err != nil {
			return fmt.Errorf("store: encoding job log fields: %w", err)
		}
		encoded = b
	}

	_, err := s.pool.Exec(ctx,
		`INSERT INTO job_logs (job_id, level, message, fields) VALUES ($1,$2,$3,$4)`,
		jobID, level, truncate(message, 8000), encoded)
	if err != nil {
		return fmt.Errorf("store: appending job log: %w", err)
	}
	return nil
}

// Logs returns a job's log lines after a cursor, oldest first, so the interface
// can poll or stream forward without re-reading history.
func (s *Jobs) Logs(ctx context.Context, jobID uuid.UUID, afterID int64, limit int) ([]JobLog, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, job_id, level, message, fields, logged_at FROM job_logs
		WHERE job_id = $1 AND id > $2 ORDER BY id ASC LIMIT $3`, jobID, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: reading job logs: %w", err)
	}
	defer rows.Close()

	out := []JobLog{}
	for rows.Next() {
		var l JobLog
		var fields []byte
		if err := rows.Scan(&l.ID, &l.JobID, &l.Level, &l.Message, &fields, &l.LoggedAt); err != nil {
			return nil, fmt.Errorf("store: scanning job log: %w", err)
		}
		l.Fields = fields
		out = append(out, l)
	}
	return out, rows.Err()
}

// Stats counts jobs by state, for the dashboard.
func (s *Jobs) Stats(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT state, count(*) FROM jobs WHERE tenant_id = $1 GROUP BY state`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: counting jobs: %w", err)
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

// PurgeFinished deletes terminal jobs older than a retention window.
func (s *Jobs) PurgeFinished(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM jobs
		WHERE state IN ('succeeded','cancelled') AND finished_at < now() - $1::interval`,
		olderThan.String())
	if err != nil {
		return 0, fmt.Errorf("store: purging finished jobs: %w", err)
	}
	return tag.RowsAffected(), nil
}

func scanJob(row interface{ Scan(...any) error }) (*Job, error) {
	var j Job
	var payload, result []byte
	err := row.Scan(&j.ID, &j.TenantID, &j.Type, &payload, &j.State, &j.Priority,
		&j.Attempts, &j.MaxAttempts, &j.RunAfter, &j.IdempotencyKey, &j.RotationID,
		&j.ChangesetID, &j.TargetID, &j.LockedBy, &j.LockedAt, &j.StartedAt,
		&j.FinishedAt, &j.LastError, &result, &j.CreatedBy, &j.CreatedAt, &j.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	j.Payload = payload
	j.Result = result
	return &j, nil
}

// truncate bounds a string stored in a diagnostic column. An error message from
// a misbehaving device can be arbitrarily long, and one of those should not be
// able to bloat the jobs table.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "… (truncated)"
}
