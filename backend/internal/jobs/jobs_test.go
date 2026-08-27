package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shamalawy/ssh-key-manager/backend/internal/dbtest"
	"github.com/shamalawy/ssh-key-manager/backend/internal/store"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func fastOptions() Options {
	return Options{
		Workers:      2,
		PollInterval: 20 * time.Millisecond,
		JobTimeout:   10 * time.Second,
		LeaseTTL:     30 * time.Second,
		BaseBackoff:  10 * time.Millisecond,
		MaxBackoff:   50 * time.Millisecond,
	}
}

// waitFor polls a condition rather than sleeping a fixed interval, so the test
// is neither flaky on a loaded machine nor slower than it has to be.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRunnerExecutesAQueuedJob(t *testing.T) {
	pool := dbtest.New(t)
	jobStore := store.NewJobs(pool)

	ctx := context.Background()

	var ran atomic.Int64
	runner := NewRunner(jobStore, fastOptions(), quiet())
	runner.Register("test.work", func(ctx context.Context, j *store.Job, log *JobLogger) (any, error) {
		log.Info(ctx, "doing the work", map[string]any{"job": j.ID.String()})
		ran.Add(1)
		return map[string]any{"done": true}, nil
	})

	runner.Start(ctx)
	defer runner.Stop()

	job, err := jobStore.Enqueue(ctx, &store.Job{Type: "test.work"})
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, "the job to run", func() bool { return ran.Load() == 1 })

	waitFor(t, "the job to be recorded as succeeded", func() bool {
		got, err := jobStore.Get(context.Background(), store.DefaultTenantID, job.ID)
		return err == nil && got.State == store.JobSucceeded
	})

	got, err := jobStore.Get(context.Background(), store.DefaultTenantID, job.ID)
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(got.Result, &result); err != nil {
		t.Fatalf("the handler's result was not stored: %v", err)
	}
	if result["done"] != true {
		t.Errorf("result = %v", result)
	}

	// The progress line the handler wrote is what an operator watches.
	logs, err := jobStore.Logs(context.Background(), job.ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 || logs[0].Message != "doing the work" {
		t.Errorf("job logs = %+v", logs)
	}
}

// A worker must not lease work it cannot run. Without the type filter, an
// instance with a partial handler table would swallow jobs and requeue them
// forever.
func TestRunnerOnlyLeasesRegisteredTypes(t *testing.T) {
	pool := dbtest.New(t)
	jobStore := store.NewJobs(pool)

	ctx := context.Background()

	runner := NewRunner(jobStore, fastOptions(), quiet())
	runner.Register("test.handled", func(context.Context, *store.Job, *JobLogger) (any, error) {
		return nil, nil
	})
	runner.Start(ctx)
	defer runner.Stop()

	handled, err := jobStore.Enqueue(ctx, &store.Job{Type: "test.handled"})
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := jobStore.Enqueue(ctx, &store.Job{Type: "test.nobody-handles-this"})
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, "the handled job to finish", func() bool {
		got, err := jobStore.Get(context.Background(), store.DefaultTenantID, handled.ID)
		return err == nil && got.State == store.JobSucceeded
	})

	got, err := jobStore.Get(context.Background(), store.DefaultTenantID, orphan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != store.JobQueued {
		t.Errorf("the unhandled job is in state %q, want it left queued", got.State)
	}
	if got.Attempts != 0 {
		t.Errorf("the unhandled job was attempted %d times", got.Attempts)
	}
}

func TestRunnerRetriesAndEventuallyGivesUp(t *testing.T) {
	pool := dbtest.New(t)
	jobStore := store.NewJobs(pool)

	ctx := context.Background()

	var attempts atomic.Int64
	runner := NewRunner(jobStore, fastOptions(), quiet())
	runner.Register("test.always-fails", func(context.Context, *store.Job, *JobLogger) (any, error) {
		attempts.Add(1)
		return nil, errors.New("the host is unreachable")
	})
	runner.Start(ctx)
	defer runner.Stop()

	job, err := jobStore.Enqueue(ctx, &store.Job{Type: "test.always-fails", MaxAttempts: 3})
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, "the job to exhaust its attempts", func() bool {
		got, err := jobStore.Get(context.Background(), store.DefaultTenantID, job.ID)
		return err == nil && got.State == store.JobDead
	})

	if n := attempts.Load(); n != 3 {
		t.Errorf("the handler ran %d times, want 3", n)
	}

	got, err := jobStore.Get(context.Background(), store.DefaultTenantID, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastError == "" {
		t.Error("the failure reason was not retained on the dead job")
	}
}

// A malformed payload or a deleted target will not fix itself. Burning five
// attempts on it only delays the operator finding out.
func TestPermanentFailureSkipsTheRetryBudget(t *testing.T) {
	pool := dbtest.New(t)
	jobStore := store.NewJobs(pool)

	ctx := context.Background()

	var attempts atomic.Int64
	runner := NewRunner(jobStore, fastOptions(), quiet())
	runner.Register("test.hopeless", func(context.Context, *store.Job, *JobLogger) (any, error) {
		attempts.Add(1)
		return nil, Permanent(errors.New("the payload is malformed"))
	})
	runner.Start(ctx)
	defer runner.Stop()

	job, err := jobStore.Enqueue(ctx, &store.Job{Type: "test.hopeless", MaxAttempts: 5})
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, "the job to be marked dead", func() bool {
		got, err := jobStore.Get(context.Background(), store.DefaultTenantID, job.ID)
		return err == nil && got.State == store.JobDead
	})

	if n := attempts.Load(); n != 1 {
		t.Errorf("the handler ran %d times, want 1; a permanent failure must not be retried", n)
	}
}

// One bad job must not take the worker pool down with it.
func TestPanicInAHandlerDoesNotKillTheWorker(t *testing.T) {
	pool := dbtest.New(t)
	jobStore := store.NewJobs(pool)

	ctx := context.Background()

	var good atomic.Int64
	runner := NewRunner(jobStore, fastOptions(), quiet())
	runner.Register("test.panics", func(context.Context, *store.Job, *JobLogger) (any, error) {
		panic("something went very wrong")
	})
	runner.Register("test.fine", func(context.Context, *store.Job, *JobLogger) (any, error) {
		good.Add(1)
		return nil, nil
	})
	runner.Start(ctx)
	defer runner.Stop()

	bad, err := jobStore.Enqueue(ctx, &store.Job{Type: "test.panics", MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobStore.Enqueue(ctx, &store.Job{Type: "test.fine"}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "the healthy job to run despite the panic", func() bool { return good.Load() == 1 })

	waitFor(t, "the panicking job to be marked dead", func() bool {
		got, err := jobStore.Get(context.Background(), store.DefaultTenantID, bad.ID)
		return err == nil && got.State == store.JobDead
	})
}

// Two workers on one queue must never run the same job twice; a rotation step
// executed twice could stage two successor keys.
func TestNoJobRunsTwice(t *testing.T) {
	pool := dbtest.New(t)
	jobStore := store.NewJobs(pool)

	ctx := context.Background()

	var (
		mu   sync.Mutex
		seen = map[string]int{}
	)

	opts := fastOptions()
	opts.Workers = 4

	runner := NewRunner(jobStore, opts, quiet())
	runner.Register("test.count", func(_ context.Context, j *store.Job, _ *JobLogger) (any, error) {
		mu.Lock()
		seen[j.ID.String()]++
		mu.Unlock()
		return nil, nil
	})
	runner.Start(ctx)
	defer runner.Stop()

	const total = 25
	for i := 0; i < total; i++ {
		if _, err := jobStore.Enqueue(ctx, &store.Job{Type: "test.count"}); err != nil {
			t.Fatal(err)
		}
	}

	waitFor(t, "every job to run", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(seen) == total
	})

	mu.Lock()
	defer mu.Unlock()
	for id, count := range seen {
		if count != 1 {
			t.Errorf("job %s ran %d times", id, count)
		}
	}
}

func TestBackoffGrowsAndIsBounded(t *testing.T) {
	runner := NewRunner(nil, Options{
		Workers: 1, BaseBackoff: time.Second, MaxBackoff: 10 * time.Second,
		PollInterval: time.Second, JobTimeout: time.Minute, LeaseTTL: time.Minute,
	}, quiet())

	first := runner.backoff(1)
	second := runner.backoff(2)
	far := runner.backoff(20)

	if first < time.Second {
		t.Errorf("the first retry waits %s, want at least the base delay", first)
	}
	if second <= first {
		t.Errorf("the delay did not grow: %s then %s", first, second)
	}
	// The jitter is a quarter of the delay, so the ceiling plus jitter is the
	// real bound.
	if far > 10*time.Second+10*time.Second/4 {
		t.Errorf("the delay grew past its ceiling: %s", far)
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("registering two handlers for one type did not panic; " +
				"a silently shadowed handler is a bug that only shows up in production")
		}
	}()

	runner := NewRunner(nil, fastOptions(), quiet())
	noop := func(context.Context, *store.Job, *JobLogger) (any, error) { return nil, nil }
	runner.Register("test.duplicate", noop)
	runner.Register("test.duplicate", noop)
}

// Only one instance may run scheduled work, or scaling out would double every
// rotation the schedule fires.
func TestOnlyOneSchedulerHoldsLeadership(t *testing.T) {
	pool := dbtest.New(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var firstRuns, secondRuns atomic.Int64

	first := NewScheduler(pool, 20*time.Millisecond, quiet())
	first.Add("tick", time.Millisecond, func(context.Context) error {
		firstRuns.Add(1)
		return nil
	})

	second := NewScheduler(pool, 20*time.Millisecond, quiet())
	second.Add("tick", time.Millisecond, func(context.Context) error {
		secondRuns.Add(1)
		return nil
	})

	go first.Run(ctx)
	go second.Run(ctx)

	waitFor(t, "one scheduler to take leadership", func() bool {
		return first.IsLeader() || second.IsLeader()
	})

	// Give both a while to run their loops.
	time.Sleep(300 * time.Millisecond)

	if first.IsLeader() && second.IsLeader() {
		t.Fatal("both schedulers believe they are the leader")
	}

	leaderRuns, followerRuns := firstRuns.Load(), secondRuns.Load()
	if second.IsLeader() {
		leaderRuns, followerRuns = followerRuns, leaderRuns
	}

	if leaderRuns == 0 {
		t.Error("the leader never ran its task")
	}
	if followerRuns != 0 {
		t.Errorf("the follower ran its task %d times", followerRuns)
	}
}

// Losing the leader must not stop scheduled work; the next instance takes over.
func TestLeadershipPassesOnWhenTheLeaderStops(t *testing.T) {
	pool := dbtest.New(t)

	firstCtx, stopFirst := context.WithCancel(context.Background())
	secondCtx, stopSecond := context.WithCancel(context.Background())
	defer stopSecond()

	first := NewScheduler(pool, 20*time.Millisecond, quiet())
	first.Add("noop", time.Hour, func(context.Context) error { return nil })

	var secondRuns atomic.Int64
	second := NewScheduler(pool, 20*time.Millisecond, quiet())
	second.Add("tick", time.Millisecond, func(context.Context) error {
		secondRuns.Add(1)
		return nil
	})

	go first.Run(firstCtx)
	waitFor(t, "the first scheduler to take leadership", first.IsLeader)

	go second.Run(secondCtx)
	time.Sleep(100 * time.Millisecond)
	if second.IsLeader() {
		t.Fatal("the second scheduler took leadership while the first still held it")
	}

	stopFirst()

	waitFor(t, "the second scheduler to take over", second.IsLeader)
	waitFor(t, "the new leader to run its task", func() bool { return secondRuns.Load() > 0 })
}

// A task that fails must not stop the ones after it, or one broken integration
// would silently halt rotation scheduling.
func TestAFailingTaskDoesNotBlockTheRest(t *testing.T) {
	pool := dbtest.New(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var laterRuns atomic.Int64

	sched := NewScheduler(pool, 20*time.Millisecond, quiet())
	sched.Add("broken", time.Millisecond, func(context.Context) error {
		return errors.New("this integration is down")
	})
	sched.Add("healthy", time.Millisecond, func(context.Context) error {
		laterRuns.Add(1)
		return nil
	})

	go sched.Run(ctx)

	waitFor(t, "the task after the failing one to run", func() bool { return laterRuns.Load() > 0 })
}
