// Package jobs runs background work: a PostgreSQL-backed queue, a worker pool,
// and a leader-elected scheduler.
//
// The design constraint is that a rotation must survive the process dying
// halfway through it. That rules out in-memory queues and goroutine-per-task
// fire-and-forget: every step has to be a durable row that another worker can
// pick up. It also means jobs must be idempotent, since "did it finish before
// the crash?" is not always answerable.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/shamalawy/ssh-key-manager/backend/internal/store"
)

// Handler executes one job. The returned value is stored as the job's result.
type Handler func(ctx context.Context, j *store.Job, log *JobLogger) (any, error)

// permanentError marks a failure that retrying cannot fix — a malformed
// payload, a deleted target, a refused permission. Retrying those five times
// just delays the operator finding out.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// Permanent wraps an error so the runner marks the job dead immediately.
func Permanent(err error) error { return permanentError{err: err} }

// IsPermanent reports whether an error should skip the retry budget.
func IsPermanent(err error) bool {
	var p permanentError
	return errors.As(err, &p)
}

// JobLogger writes progress lines for one job, so an operator can watch a
// deployment happen instead of waiting for a final verdict.
type JobLogger struct {
	jobs  *store.Jobs
	jobID uuid.UUID
	log   *slog.Logger
}

// Info records an informational progress line.
func (l *JobLogger) Info(ctx context.Context, msg string, fields map[string]any) {
	l.write(ctx, "info", msg, fields)
}

// Warn records a non-fatal problem.
func (l *JobLogger) Warn(ctx context.Context, msg string, fields map[string]any) {
	l.write(ctx, "warn", msg, fields)
}

// Error records a fatal problem.
func (l *JobLogger) Error(ctx context.Context, msg string, fields map[string]any) {
	l.write(ctx, "error", msg, fields)
}

func (l *JobLogger) write(ctx context.Context, level, msg string, fields map[string]any) {
	// A job log line is diagnostic; failing to store one must never fail the
	// job it describes.
	if err := l.jobs.AppendLog(ctx, l.jobID, level, msg, fields); err != nil {
		l.log.Warn("appending job log", "job", l.jobID, "error", err)
	}
}

// Options tune a Runner.
type Options struct {
	// Workers is the number of jobs processed concurrently.
	Workers int
	// PollInterval is how often an idle worker looks for work. Jobs are also
	// picked up immediately after one completes, so this only bounds latency
	// on a quiet queue.
	PollInterval time.Duration
	// JobTimeout bounds a single execution.
	JobTimeout time.Duration
	// LeaseTTL is how long a lease survives without a heartbeat before the
	// reaper requeues the job.
	LeaseTTL time.Duration
	// BaseBackoff is the first retry delay; it doubles per attempt.
	BaseBackoff time.Duration
	// MaxBackoff caps the doubling.
	MaxBackoff time.Duration
}

// DefaultOptions returns settings suitable for a single-node install.
func DefaultOptions() Options {
	return Options{
		Workers:      4,
		PollInterval: 2 * time.Second,
		JobTimeout:   15 * time.Minute,
		LeaseTTL:     5 * time.Minute,
		BaseBackoff:  10 * time.Second,
		MaxBackoff:   30 * time.Minute,
	}
}

// Runner is the worker pool.
type Runner struct {
	jobs  *store.Jobs
	opts  Options
	log   *slog.Logger
	id    string
	mu    sync.RWMutex
	table map[string]Handler
	wg    sync.WaitGroup

	// stop cancels the workers' context. The runner owns it rather than
	// relying on the caller cancelling first, because Stop() would otherwise
	// block forever on any shutdown path that did not — including a server
	// exiting because ListenAndServe failed.
	stop context.CancelFunc
}

// NewRunner builds a worker pool. The worker identity includes the hostname so
// a stuck job names the machine holding it.
func NewRunner(jobStore *store.Jobs, opts Options, log *slog.Logger) *Runner {
	if opts.Workers <= 0 {
		opts = DefaultOptions()
	}

	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}

	return &Runner{
		jobs:  jobStore,
		opts:  opts,
		log:   log,
		id:    fmt.Sprintf("%s/%s", host, uuid.New().String()[:8]),
		table: make(map[string]Handler),
	}
}

// ID returns this runner's worker identity.
func (r *Runner) ID() string { return r.id }

// Register binds a handler to a job type. Registering twice panics, because a
// silently shadowed handler is a bug that only shows up in production.
func (r *Runner) Register(jobType string, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.table[jobType]; exists {
		panic(fmt.Sprintf("jobs: duplicate handler registration for %q", jobType))
	}
	r.table[jobType] = h
}

// Types lists the registered job types, which is also the dequeue filter: a
// worker never leases work it cannot run.
func (r *Runner) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]string, 0, len(r.table))
	for t := range r.table {
		out = append(out, t)
	}
	return out
}

func (r *Runner) handler(jobType string) (Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.table[jobType]
	return h, ok
}

// Start launches the worker pool and the stalled-job reaper. It returns
// immediately; Stop cancels the workers and waits for in-flight work.
func (r *Runner) Start(ctx context.Context) {
	r.log.Info("starting job workers",
		"workers", r.opts.Workers, "worker_id", r.id, "types", r.Types())

	ctx, r.stop = context.WithCancel(ctx)

	for i := 0; i < r.opts.Workers; i++ {
		r.wg.Add(1)
		go func(n int) {
			defer r.wg.Done()
			r.worker(ctx, n)
		}(i)
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.reaper(ctx)
	}()
}

// Stop signals the workers to finish and waits for them. It is safe to call
// without having cancelled the context Start was given, and safe to call twice.
func (r *Runner) Stop() {
	if r.stop != nil {
		r.stop()
	}
	r.wg.Wait()
}

func (r *Runner) worker(ctx context.Context, n int) {
	// Stagger the pollers so four workers do not hit the queue in lockstep.
	jitter := time.Duration(rand.Int64N(int64(r.opts.PollInterval)))
	timer := time.NewTimer(jitter)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		worked, err := r.step(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			r.log.Warn("job worker step", "worker", n, "error", err)
		}

		// Having just done work, look again immediately: a rotation enqueues
		// its next step as it finishes the previous one.
		next := r.opts.PollInterval
		if worked {
			next = time.Millisecond
		}
		timer.Reset(next)
	}
}

// step leases one job and runs it, reporting whether anything was found.
func (r *Runner) step(ctx context.Context) (bool, error) {
	leased, err := r.jobs.Dequeue(ctx, r.id, r.Types(), 1)
	if err != nil {
		return false, err
	}
	if len(leased) == 0 {
		return false, nil
	}

	job := leased[0]
	r.execute(ctx, &job)
	return true, nil
}

func (r *Runner) execute(ctx context.Context, job *store.Job) {
	handler, ok := r.handler(job.Type)
	if !ok {
		// Dequeue filters by type, so this means the table changed underneath
		// us. Requeue rather than kill the job.
		if _, err := r.jobs.Fail(ctx, job.ID, fmt.Errorf("jobs: no handler for type %q", job.Type), time.Minute); err != nil {
			r.log.Error("failing unhandled job", "job", job.ID, "error", err)
		}
		return
	}

	jobCtx, cancel := context.WithTimeout(ctx, r.opts.JobTimeout)
	defer cancel()

	logger := &JobLogger{jobs: r.jobs, jobID: job.ID, log: r.log}

	// Refresh the lease while the job runs so a slow but healthy deployment is
	// not mistaken for a dead worker.
	heartbeatDone := make(chan struct{})
	go r.heartbeat(jobCtx, job.ID, heartbeatDone)

	started := time.Now()
	result, err := r.safely(jobCtx, handler, job, logger)
	close(heartbeatDone)

	elapsed := time.Since(started).Round(time.Millisecond)

	if err == nil {
		if err := r.jobs.Succeed(context.WithoutCancel(ctx), job.ID, result); err != nil {
			r.log.Error("recording job success", "job", job.ID, "error", err)
		}
		r.log.Info("job completed", "job", job.ID, "type", job.Type, "duration", elapsed)
		return
	}

	recordCtx := context.WithoutCancel(ctx)

	dead := true
	if IsPermanent(err) {
		if killErr := r.jobs.Kill(recordCtx, job.ID, err); killErr != nil {
			r.log.Error("marking a permanently failed job dead", "job", job.ID, "error", killErr)
			return
		}
	} else {
		var failErr error
		dead, failErr = r.jobs.Fail(recordCtx, job.ID, err, r.backoff(job.Attempts))
		if failErr != nil {
			r.log.Error("recording job failure", "job", job.ID, "error", failErr)
			return
		}
	}

	logger.Error(recordCtx, err.Error(), map[string]any{
		"attempt": job.Attempts, "dead": dead,
	})

	level := r.log.Warn
	if dead {
		level = r.log.Error
	}
	level("job failed", "job", job.ID, "type", job.Type, "attempt", job.Attempts,
		"dead", dead, "duration", elapsed, "error", err)
}

// safely runs a handler with panic recovery, so one bad job cannot take the
// worker pool down with it.
func (r *Runner) safely(ctx context.Context, h Handler, job *store.Job, logger *JobLogger) (result any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			r.log.Error("panic in job handler", "job", job.ID, "type", job.Type,
				"panic", rec, "stack", string(debug.Stack()))
			err = Permanent(fmt.Errorf("jobs: handler for %q panicked: %v", job.Type, rec))
		}
	}()
	return h(ctx, job, logger)
}

func (r *Runner) heartbeat(ctx context.Context, jobID uuid.UUID, done <-chan struct{}) {
	interval := r.opts.LeaseTTL / 3
	if interval < time.Second {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			if err := r.jobs.Heartbeat(context.WithoutCancel(ctx), jobID, r.id); err != nil {
				r.log.Warn("refreshing job lease", "job", jobID, "error", err)
			}
		}
	}
}

// backoff returns an exponentially increasing delay with jitter, so a fleet-wide
// outage does not produce a synchronised retry stampede when it clears.
func (r *Runner) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}

	delay := r.opts.BaseBackoff
	for i := 1; i < attempt && delay < r.opts.MaxBackoff; i++ {
		delay *= 2
	}
	if delay > r.opts.MaxBackoff {
		delay = r.opts.MaxBackoff
	}

	jitter := time.Duration(rand.Int64N(int64(delay/4) + 1))
	return delay + jitter
}

// reaper requeues jobs whose worker died holding the lease.
func (r *Runner) reaper(ctx context.Context) {
	interval := r.opts.LeaseTTL / 2
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := r.jobs.ReapStalled(ctx, r.opts.LeaseTTL)
			if err != nil {
				r.log.Warn("reaping stalled jobs", "error", err)
				continue
			}
			if n > 0 {
				r.log.Warn("requeued stalled jobs", "count", n,
					"note", "a worker died holding these leases")
			}
		}
	}
}
