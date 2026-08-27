package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hamalawy/ssh-key-manager/backend/internal/dbtest"
)

// testLogger returns a Logger backed by a database private to this test, so
// concurrent test packages cannot interfere with one another.
func testLogger(t *testing.T) (*Logger, *pgxpool.Pool) {
	t.Helper()
	pool := dbtest.New(t)
	return New(pool), pool
}

// tamper runs fn with the append-only triggers disabled, simulating an attacker
// with direct database access. The application can never do this; the test does
// it precisely to prove the chain still catches the result.
func tamper(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `ALTER TABLE audit_events DISABLE TRIGGER USER`); err != nil {
		t.Fatalf("disabling triggers: %v", err)
	}
	defer func() {
		if _, err := pool.Exec(ctx, `ALTER TABLE audit_events ENABLE TRIGGER USER`); err != nil {
			t.Fatalf("re-enabling triggers: %v", err)
		}
	}()

	if _, err := pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("tampering: %v", err)
	}
}

func TestLogChainsEvents(t *testing.T) {
	logger, _ := testLogger(t)
	ctx := context.Background()

	first, err := logger.Log(ctx, Event{Action: ActionKeyCreate, ResourceName: "web-fleet"})
	if err != nil {
		t.Fatalf("first Log: %v", err)
	}
	if first.PrevHash != "" {
		t.Errorf("first event PrevHash = %q, want empty", first.PrevHash)
	}
	if first.Hash == "" {
		t.Error("first event has an empty hash")
	}

	second, err := logger.Log(ctx, Event{Action: ActionKeyDeploy, ResourceName: "web-01"})
	if err != nil {
		t.Fatalf("second Log: %v", err)
	}
	if second.PrevHash != first.Hash {
		t.Errorf("second event PrevHash = %q, want %q", second.PrevHash, first.Hash)
	}
	if second.Seq <= first.Seq {
		t.Errorf("seq did not advance: %d then %d", first.Seq, second.Seq)
	}
}

func TestLogRequiresAction(t *testing.T) {
	logger, _ := testLogger(t)
	if _, err := logger.Log(context.Background(), Event{}); err == nil {
		t.Error("Log with no Action succeeded; want an error")
	}
}

func TestVerifyAcceptsCleanChain(t *testing.T) {
	logger, _ := testLogger(t)
	ctx := context.Background()

	for i := 0; i < 25; i++ {
		if _, err := logger.Log(ctx, Event{
			Action:       ActionKeyDeploy,
			ResourceName: "host",
			Detail:       map[string]any{"index": i, "nested": map[string]any{"b": 2, "a": 1}},
		}); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	res, err := logger.Verify(ctx, DefaultTenantID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid {
		t.Errorf("clean chain reported invalid at seq %d: %s", res.BrokenAtSeq, res.Reason)
	}
	if res.Checked != 25 {
		t.Errorf("Checked = %d, want 25", res.Checked)
	}
}

func TestVerifyDetectsModifiedEvent(t *testing.T) {
	logger, pool := testLogger(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := logger.Log(ctx, Event{Action: ActionKeyDeploy, ResourceName: "host"}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// Rewrite history: change an action without recomputing the hash.
	tamper(t, pool, `UPDATE audit_events SET action = 'key.definitely_not_this' WHERE seq = 3`)

	res, err := logger.Verify(ctx, DefaultTenantID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid {
		t.Fatal("Verify accepted a chain containing a modified event")
	}
	if res.BrokenAtSeq != 3 {
		t.Errorf("BrokenAtSeq = %d, want 3", res.BrokenAtSeq)
	}
	if res.Reason == "" {
		t.Error("Verify reported no reason for the failure")
	}
	t.Logf("detected: %s", res.Reason)
}

func TestVerifyDetectsDeletedEvent(t *testing.T) {
	logger, pool := testLogger(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := logger.Log(ctx, Event{Action: ActionKeyDeploy, ResourceName: "host"}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// Excise an event entirely — the classic "remove the incriminating line".
	tamper(t, pool, `DELETE FROM audit_events WHERE seq = 3`)

	res, err := logger.Verify(ctx, DefaultTenantID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid {
		t.Fatal("Verify accepted a chain with a deleted event")
	}
	// Seq 4 is now the first event whose prev_hash has no matching predecessor.
	if res.BrokenAtSeq != 4 {
		t.Errorf("BrokenAtSeq = %d, want 4", res.BrokenAtSeq)
	}
	t.Logf("detected: %s", res.Reason)
}

func TestVerifyDetectsTruncatedStart(t *testing.T) {
	logger, pool := testLogger(t)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		if _, err := logger.Log(ctx, Event{Action: ActionKeyDeploy}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// Remove the genesis event, so the chain no longer starts from "".
	tamper(t, pool, `DELETE FROM audit_events WHERE seq = 1`)

	res, err := logger.Verify(ctx, DefaultTenantID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid {
		t.Fatal("Verify accepted a chain whose beginning was truncated")
	}
	t.Logf("detected: %s", res.Reason)
}

// The advisory lock is what stops two concurrent appends from chaining off the
// same predecessor. Without it the chain forks and Verify fails.
func TestConcurrentAppendsProduceValidChain(t *testing.T) {
	logger, _ := testLogger(t)
	ctx := context.Background()

	const writers, each = 8, 6

	var wg sync.WaitGroup
	errs := make(chan error, writers*each)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				_, err := logger.Log(ctx, Event{
					Action:       ActionKeyDeploy,
					ResourceName: "host",
					Detail:       map[string]any{"writer": w, "i": i},
				})
				if err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent Log: %v", err)
	}

	res, err := logger.Verify(ctx, DefaultTenantID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid {
		t.Errorf("concurrent appends forked the chain at seq %d: %s", res.BrokenAtSeq, res.Reason)
	}
	if want := int64(writers * each); res.Checked != want {
		t.Errorf("Checked = %d, want %d", res.Checked, want)
	}
}

func TestQueryFilters(t *testing.T) {
	logger, _ := testLogger(t)
	ctx := context.Background()

	actor := uuid.New()
	if _, err := logger.Log(ctx, Event{Action: ActionKeyCreate, ActorID: &actor, ActorType: ActorUser}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if _, err := logger.Log(ctx, Event{Action: ActionKeyReveal, Outcome: OutcomeDenied}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if _, err := logger.Log(ctx, Event{Action: ActionKeyDeploy, ResourceType: "target"}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	tests := []struct {
		name   string
		filter Filter
		want   int
	}{
		{"no filter", Filter{}, 3},
		{"by action", Filter{Actions: []string{ActionKeyReveal}}, 1},
		{"by two actions", Filter{Actions: []string{ActionKeyReveal, ActionKeyDeploy}}, 2},
		{"by actor", Filter{ActorID: &actor}, 1},
		{"by outcome", Filter{Outcome: OutcomeDenied}, 1},
		{"by resource type", Filter{ResourceType: "target"}, 1},
		{"limit", Filter{Limit: 2}, 2},
		{"future window", Filter{Since: time.Now().Add(time.Hour)}, 0},
		{"no match", Filter{Actions: []string{"nope.nothing"}}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := logger.Query(ctx, tc.filter)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("Query returned %d records, want %d", len(got), tc.want)
			}
		})
	}
}

// Records must come back newest-first so the GUI can page backwards through
// history with the keyset cursor.
func TestQueryOrderingAndPagination(t *testing.T) {
	logger, _ := testLogger(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		if _, err := logger.Log(ctx, Event{Action: ActionKeyDeploy}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	page1, err := logger.Query(ctx, Filter{Limit: 4})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(page1) != 4 {
		t.Fatalf("page 1 has %d records, want 4", len(page1))
	}
	for i := 1; i < len(page1); i++ {
		if page1[i].Seq >= page1[i-1].Seq {
			t.Fatalf("records are not newest-first: seq %d then %d", page1[i-1].Seq, page1[i].Seq)
		}
	}

	page2, err := logger.Query(ctx, Filter{Limit: 4, BeforeSeq: page1[len(page1)-1].Seq})
	if err != nil {
		t.Fatalf("Query page 2: %v", err)
	}
	if len(page2) != 4 {
		t.Fatalf("page 2 has %d records, want 4", len(page2))
	}
	if page2[0].Seq >= page1[len(page1)-1].Seq {
		t.Error("page 2 overlaps page 1")
	}
}

// Detail round-trips through JSONB, which does not preserve key order. If
// canonicalisation were wrong, Verify would fail on any event with a
// multi-key detail object.
func TestDetailSurvivesJSONBRoundTrip(t *testing.T) {
	logger, _ := testLogger(t)
	ctx := context.Background()

	detail := map[string]any{
		"zebra":  "last",
		"alpha":  "first",
		"count":  float64(42),
		"nested": map[string]any{"z": true, "a": false},
		"list":   []any{"one", "two"},
	}

	if _, err := logger.Log(ctx, Event{Action: ActionKeyDeploy, Detail: detail}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	res, err := logger.Verify(ctx, DefaultTenantID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid {
		t.Errorf("detail round trip broke the hash: %s", res.Reason)
	}

	got, err := logger.Query(ctx, Filter{Limit: 1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].Detail["alpha"] != "first" {
		t.Errorf("detail[alpha] = %v, want %q", got[0].Detail["alpha"], "first")
	}
}

// Events carrying an IP address exercise the inet column, which needs explicit
// handling on the way back out. Without this the whole listing fails as soon as
// a single login is recorded.
func TestEventsWithIPAddressRoundTrip(t *testing.T) {
	logger, _ := testLogger(t)
	ctx := context.Background()

	addresses := []string{"192.0.2.10", "::1", "2001:db8::8a2e:370:7334", ""}
	for _, addr := range addresses {
		if _, err := logger.Log(ctx, Event{
			Action:    ActionLogin,
			ActorName: "alice",
			IPAddress: addr,
			UserAgent: "skmctl/1.0",
		}); err != nil {
			t.Fatalf("Log with IP %q: %v", addr, err)
		}
	}

	got, err := logger.Query(ctx, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != len(addresses) {
		t.Fatalf("got %d events, want %d", len(got), len(addresses))
	}

	// Query returns newest-first, so walk the expected list backwards.
	for i, want := range addresses {
		rec := got[len(got)-1-i]
		if rec.IPAddress != want {
			t.Errorf("event %d IPAddress = %q, want %q", i, rec.IPAddress, want)
		}
		if rec.UserAgent != "skmctl/1.0" {
			t.Errorf("event %d UserAgent = %q", i, rec.UserAgent)
		}
	}

	// The chain must still verify: the hash is computed over the textual form,
	// so any change in how inet round-trips would break it.
	res, err := logger.Verify(ctx, DefaultTenantID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid {
		t.Errorf("chain broken at seq %d: %s", res.BrokenAtSeq, res.Reason)
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	logger, _ := testLogger(t)

	res, err := logger.Verify(context.Background(), DefaultTenantID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid {
		t.Error("an empty chain should verify as valid")
	}
	if res.Checked != 0 {
		t.Errorf("Checked = %d, want 0", res.Checked)
	}
}
