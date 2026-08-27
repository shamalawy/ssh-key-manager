package store

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hamalawy/ssh-key-manager/backend/internal/db"
	"github.com/hamalawy/ssh-key-manager/backend/internal/dbtest"
)

func jobRepo(t *testing.T) (*Jobs, *db.Pool) {
	t.Helper()
	pool := dbtest.New(t)
	return NewJobs(pool), pool
}

func TestEnqueueAndDequeue(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	queued, err := jobs.Enqueue(ctx, &Job{
		Type:    JobTypeDeploy,
		Payload: json.RawMessage(`{"target":"web-01"}`),
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if queued.State != JobQueued {
		t.Errorf("State = %q, want queued", queued.State)
	}
	if queued.MaxAttempts == 0 || queued.Priority == 0 {
		t.Errorf("defaults were not applied: %+v", queued)
	}

	leased, err := jobs.Dequeue(ctx, "worker-1", []string{JobTypeDeploy}, 10)
	if err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	if len(leased) != 1 {
		t.Fatalf("leased %d jobs, want 1", len(leased))
	}

	got := leased[0]
	if got.State != JobRunning {
		t.Errorf("State = %q, want running", got.State)
	}
	if got.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1", got.Attempts)
	}
	if got.LockedBy != "worker-1" {
		t.Errorf("LockedBy = %q, want worker-1", got.LockedBy)
	}
}

// A worker must never lease work it has no handler for; the dequeue filter is
// what makes registering handlers per instance safe.
func TestDequeueFiltersByType(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	if _, err := jobs.Enqueue(ctx, &Job{Type: JobTypeBackup}); err != nil {
		t.Fatal(err)
	}

	leased, err := jobs.Dequeue(ctx, "worker-1", []string{JobTypeDeploy}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 0 {
		t.Fatalf("leased %d jobs of the wrong type", len(leased))
	}
}

func TestDequeueRespectsRunAfter(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	if _, err := jobs.Enqueue(ctx, &Job{
		Type:     JobTypeDeploy,
		RunAfter: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	leased, err := jobs.Dequeue(ctx, "worker-1", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 0 {
		t.Fatalf("leased %d jobs scheduled for the future", len(leased))
	}
}

func TestDequeueHonoursPriority(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	if _, err := jobs.Enqueue(ctx, &Job{Type: JobTypeReconcile, Priority: 200}); err != nil {
		t.Fatal(err)
	}
	urgent, err := jobs.Enqueue(ctx, &Job{Type: JobTypeRotationStep, Priority: 10})
	if err != nil {
		t.Fatal(err)
	}

	leased, err := jobs.Dequeue(ctx, "worker-1", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 || leased[0].ID != urgent.ID {
		t.Error("the lower-priority job was leased first")
	}
}

// SKIP LOCKED is the whole reason the queue lives in PostgreSQL. Two workers
// pulling at once must never both get the same job.
func TestConcurrentWorkersNeverShareAJob(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	const total = 20
	for i := 0; i < total; i++ {
		if _, err := jobs.Enqueue(ctx, &Job{Type: JobTypeDeploy}); err != nil {
			t.Fatal(err)
		}
	}

	var (
		mu     sync.Mutex
		seen   = map[string]string{}
		wg     sync.WaitGroup
		errsMu sync.Mutex
		errs   []error
	)

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(worker string) {
			defer wg.Done()
			for {
				leased, err := jobs.Dequeue(ctx, worker, nil, 3)
				if err != nil {
					errsMu.Lock()
					errs = append(errs, err)
					errsMu.Unlock()
					return
				}
				if len(leased) == 0 {
					return
				}
				mu.Lock()
				for _, j := range leased {
					if other, taken := seen[j.ID.String()]; taken {
						t.Errorf("job %s leased by both %s and %s", j.ID, other, worker)
					}
					seen[j.ID.String()] = worker
				}
				mu.Unlock()
			}
		}("worker-" + string(rune('a'+w)))
	}
	wg.Wait()

	for _, err := range errs {
		t.Errorf("dequeue: %v", err)
	}
	if len(seen) != total {
		t.Errorf("leased %d distinct jobs, want %d", len(seen), total)
	}
}

// A retried API call and a re-fired cron tick both have to collapse into one
// job, or a rotation gets started twice.
func TestIdempotencyKeyCollapsesDuplicates(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	key := "rotation:abc:staging:0"
	first, err := jobs.Enqueue(ctx, &Job{Type: JobTypeRotationStep, IdempotencyKey: &key})
	if err != nil {
		t.Fatal(err)
	}

	second, err := jobs.Enqueue(ctx, &Job{Type: JobTypeRotationStep, IdempotencyKey: &key})
	if err != nil {
		t.Fatalf("the duplicate enqueue failed instead of collapsing: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("got two jobs (%s and %s) for one idempotency key", first.ID, second.ID)
	}
}

// The uniqueness index is partial: once a job finishes, the same key must be
// usable again, or a rotation could never run a second time.
func TestIdempotencyKeyIsReusableAfterCompletion(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	key := "reconcile:sweep"
	first, err := jobs.Enqueue(ctx, &Job{Type: JobTypeReconcile, IdempotencyKey: &key})
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.Succeed(ctx, first.ID, map[string]any{"targets": 3}); err != nil {
		t.Fatal(err)
	}

	second, err := jobs.Enqueue(ctx, &Job{Type: JobTypeReconcile, IdempotencyKey: &key})
	if err != nil {
		t.Fatalf("Enqueue after completion: %v", err)
	}
	if second.ID == first.ID {
		t.Error("the finished job was returned instead of a new one")
	}
}

func TestSucceedStoresTheResult(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	job, err := jobs.Enqueue(ctx, &Job{Type: JobTypeDeploy})
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.Succeed(ctx, job.ID, map[string]any{"added": 2}); err != nil {
		t.Fatal(err)
	}

	got, err := jobs.Get(ctx, DefaultTenantID, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != JobSucceeded {
		t.Errorf("State = %q, want succeeded", got.State)
	}
	if got.FinishedAt == nil {
		t.Error("FinishedAt was not set")
	}

	var result map[string]any
	if err := json.Unmarshal(got.Result, &result); err != nil {
		t.Fatalf("the result did not round-trip: %v", err)
	}
	if result["added"] != float64(2) {
		t.Errorf("result = %v", result)
	}
}

func TestFailRequeuesUntilTheBudgetRunsOut(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	job, err := jobs.Enqueue(ctx, &Job{Type: JobTypeDeploy, MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}

	// First attempt.
	if _, err := jobs.Dequeue(ctx, "worker-1", nil, 1); err != nil {
		t.Fatal(err)
	}
	dead, err := jobs.Fail(ctx, job.ID, errors.New("host unreachable"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if dead {
		t.Fatal("the job died on its first attempt despite a budget of two")
	}

	// Second attempt exhausts the budget.
	if _, err := jobs.Dequeue(ctx, "worker-1", nil, 1); err != nil {
		t.Fatal(err)
	}
	dead, err = jobs.Fail(ctx, job.ID, errors.New("host unreachable"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !dead {
		t.Error("the job was requeued past its attempt budget")
	}

	got, err := jobs.Get(ctx, DefaultTenantID, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != JobDead {
		t.Errorf("State = %q, want dead", got.State)
	}
	// A job that gave up must stay visible: it is exactly what an operator
	// needs to see.
	if got.LastError == "" {
		t.Error("the failure reason was not retained")
	}
}

func TestFailAppliesBackoff(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	job, err := jobs.Enqueue(ctx, &Job{Type: JobTypeDeploy, MaxAttempts: 5})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Dequeue(ctx, "worker-1", nil, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Fail(ctx, job.ID, errors.New("transient"), time.Hour); err != nil {
		t.Fatal(err)
	}

	leased, err := jobs.Dequeue(ctx, "worker-1", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 0 {
		t.Error("a backed-off job was leased immediately")
	}
}

// Killing the server mid-rotation must not strand work. The reaper is what
// makes that true.
func TestReapStalledRequeuesAbandonedWork(t *testing.T) {
	ctx := context.Background()
	jobs, pool := jobRepo(t)

	job, err := jobs.Enqueue(ctx, &Job{Type: JobTypeRotationStep, MaxAttempts: 5})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Dequeue(ctx, "worker-that-died", nil, 1); err != nil {
		t.Fatal(err)
	}

	// Age the lease rather than sleeping through a real TTL.
	if _, err := pool.Exec(ctx,
		`UPDATE jobs SET locked_at = now() - interval '20 minutes' WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}

	n, err := jobs.ReapStalled(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("reaped %d jobs, want 1", n)
	}

	leased, err := jobs.Dequeue(ctx, "worker-that-lives", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 || leased[0].ID != job.ID {
		t.Error("the reaped job was not picked up by another worker")
	}
}

func TestHeartbeatKeepsALeaseAlive(t *testing.T) {
	ctx := context.Background()
	jobs, pool := jobRepo(t)

	job, err := jobs.Enqueue(ctx, &Job{Type: JobTypeRotationStep})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Dequeue(ctx, "worker-1", nil, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE jobs SET locked_at = now() - interval '20 minutes' WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}

	// A slow but healthy job refreshes its lease and survives the reaper.
	if err := jobs.Heartbeat(ctx, job.ID, "worker-1"); err != nil {
		t.Fatal(err)
	}

	n, err := jobs.ReapStalled(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("reaped %d jobs that were heartbeating", n)
	}
}

func TestCancelStopsAQueuedJob(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	job, err := jobs.Enqueue(ctx, &Job{Type: JobTypeDeploy})
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.Cancel(ctx, DefaultTenantID, job.ID); err != nil {
		t.Fatal(err)
	}

	leased, err := jobs.Dequeue(ctx, "worker-1", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 0 {
		t.Error("a cancelled job was leased")
	}

	// Cancelling a finished job is a conflict, not a silent success.
	if err := jobs.Cancel(ctx, DefaultTenantID, job.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Cancel = %v, want ErrNotFound", err)
	}
}

func TestJobLogsStreamForward(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	job, err := jobs.Enqueue(ctx, &Job{Type: JobTypeRotationStep})
	if err != nil {
		t.Fatal(err)
	}

	for _, msg := range []string{"staged on web-01", "verified on web-01", "retired on web-01"} {
		if err := jobs.AppendLog(ctx, job.ID, "info", msg, map[string]any{"host": "web-01"}); err != nil {
			t.Fatal(err)
		}
	}

	first, err := jobs.Logs(ctx, job.ID, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].Message != "staged on web-01" {
		t.Fatalf("first page = %+v", first)
	}

	// The cursor is what makes the interface able to poll without re-reading
	// everything it has already shown.
	rest, err := jobs.Logs(ctx, job.ID, first[len(first)-1].ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 1 || rest[0].Message != "retired on web-01" {
		t.Errorf("second page = %+v", rest)
	}
}

func TestStatsCountByState(t *testing.T) {
	ctx := context.Background()
	jobs, _ := jobRepo(t)

	for i := 0; i < 3; i++ {
		if _, err := jobs.Enqueue(ctx, &Job{Type: JobTypeDeploy}); err != nil {
			t.Fatal(err)
		}
	}
	leased, err := jobs.Dequeue(ctx, "worker-1", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.Succeed(ctx, leased[0].ID, nil); err != nil {
		t.Fatal(err)
	}

	stats, err := jobs.Stats(ctx, DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	if stats[JobQueued] != 2 {
		t.Errorf("queued = %d, want 2", stats[JobQueued])
	}
	if stats[JobSucceeded] != 1 {
		t.Errorf("succeeded = %d, want 1", stats[JobSucceeded])
	}
}

func TestPurgeKeepsFailuresAndDropsSuccesses(t *testing.T) {
	ctx := context.Background()
	jobs, pool := jobRepo(t)

	done, err := jobs.Enqueue(ctx, &Job{Type: JobTypeDeploy})
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.Succeed(ctx, done.ID, nil); err != nil {
		t.Fatal(err)
	}

	failed, err := jobs.Enqueue(ctx, &Job{Type: JobTypeDeploy, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Dequeue(ctx, "worker-1", nil, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Fail(ctx, failed.ID, errors.New("nope"), 0); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `UPDATE jobs SET finished_at = now() - interval '30 days'`); err != nil {
		t.Fatal(err)
	}

	if _, err := jobs.PurgeFinished(ctx, 14*24*time.Hour); err != nil {
		t.Fatal(err)
	}

	if _, err := jobs.Get(ctx, DefaultTenantID, done.ID); !errors.Is(err, ErrNotFound) {
		t.Error("an old successful job was not purged")
	}
	// A dead job is evidence. It stays.
	if _, err := jobs.Get(ctx, DefaultTenantID, failed.ID); err != nil {
		t.Errorf("a dead job was purged: %v", err)
	}
}
