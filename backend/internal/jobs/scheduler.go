package jobs

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SchedulerLockID is the advisory lock every SKM instance contends for.
//
// Only the holder runs periodic work. Without this, scaling to two replicas
// would double every scheduled rotation — the failure mode being two rotations
// racing to retire the same key.
const SchedulerLockID int64 = 0x534B4D5343 // "SKMSC"

// Task is one periodic unit of scheduled work.
type Task struct {
	Name     string
	Interval time.Duration
	Run      func(ctx context.Context) error

	lastRun time.Time
}

// Scheduler runs periodic tasks on whichever instance holds the leader lock.
type Scheduler struct {
	pool  *pgxpool.Pool
	log   *slog.Logger
	tick  time.Duration
	mu    sync.Mutex
	tasks []*Task

	leaderMu sync.RWMutex
	leader   bool
}

// NewScheduler builds a scheduler. The tick is how often it evaluates which
// tasks are due; individual tasks set their own intervals.
func NewScheduler(pool *pgxpool.Pool, tick time.Duration, log *slog.Logger) *Scheduler {
	if tick <= 0 {
		tick = 30 * time.Second
	}
	return &Scheduler{pool: pool, log: log, tick: tick}
}

// Add registers a periodic task.
func (s *Scheduler) Add(name string, interval time.Duration, run func(ctx context.Context) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks = append(s.tasks, &Task{Name: name, Interval: interval, Run: run})
}

// IsLeader reports whether this instance currently holds the lock, so the API
// can show which node is scheduling.
func (s *Scheduler) IsLeader() bool {
	s.leaderMu.RLock()
	defer s.leaderMu.RUnlock()
	return s.leader
}

// Run blocks until ctx is cancelled, contending for leadership and running due
// tasks while it holds it.
//
// The advisory lock is session-scoped and held on a dedicated connection: if
// this process dies, PostgreSQL drops the session and another instance takes
// over without any lease-expiry bookkeeping of our own.
func (s *Scheduler) Run(ctx context.Context) {
	names := make([]string, 0, len(s.tasks))
	for _, t := range s.tasks {
		names = append(names, t.Name)
	}
	s.log.Info("starting scheduler", "tick", s.tick, "tasks", names)

	ticker := time.NewTicker(s.tick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.setLeader(false)
			return
		default:
		}

		if err := s.holdLeadership(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Warn("scheduler leadership attempt", "error", err)
		}

		select {
		case <-ctx.Done():
			s.setLeader(false)
			return
		case <-ticker.C:
		}
	}
}

// holdLeadership acquires the lock and runs the task loop until it loses the
// connection or ctx ends. Returning releases the connection, and with it the
// lock.
func (s *Scheduler) holdLeadership(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, SchedulerLockID).Scan(&acquired); err != nil {
		return err
	}
	if !acquired {
		s.setLeader(false)
		return nil
	}

	s.setLeader(true)
	s.log.Info("acquired scheduler leadership")

	defer func() {
		// Release explicitly rather than relying on the connection being
		// closed: pooled connections are reused, and a lock left behind on a
		// recycled connection would stall every other instance.
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(releaseCtx, `SELECT pg_advisory_unlock($1)`, SchedulerLockID); err != nil {
			s.log.Warn("releasing scheduler lock", "error", err)
		}
		s.setLeader(false)
		s.log.Info("released scheduler leadership")
	}()

	ticker := time.NewTicker(s.tick)
	defer ticker.Stop()

	for {
		s.runDue(ctx)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		// Confirm the connection is still alive; a dropped one means the lock
		// is gone and another instance may already have taken over.
		if err := conn.Ping(ctx); err != nil {
			return err
		}
	}
}

func (s *Scheduler) runDue(ctx context.Context) {
	s.mu.Lock()
	tasks := make([]*Task, len(s.tasks))
	copy(tasks, s.tasks)
	s.mu.Unlock()

	now := time.Now()
	for _, task := range tasks {
		if !task.lastRun.IsZero() && now.Sub(task.lastRun) < task.Interval {
			continue
		}
		task.lastRun = now

		started := time.Now()
		if err := task.Run(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			s.log.Warn("scheduled task failed", "task", task.Name, "error", err)
			continue
		}

		if elapsed := time.Since(started); elapsed > time.Second {
			s.log.Info("scheduled task completed", "task", task.Name,
				"duration", elapsed.Round(time.Millisecond))
		}
	}
}

func (s *Scheduler) setLeader(v bool) {
	s.leaderMu.Lock()
	s.leader = v
	s.leaderMu.Unlock()
}
