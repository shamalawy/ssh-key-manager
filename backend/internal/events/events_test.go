package events

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestSignRoundTrips(t *testing.T) {
	secret := []byte("a signing secret")
	payload := []byte(`{"type":"key.created"}`)
	timestamp := "1772000000"

	signature := Sign(secret, timestamp, payload)

	if !strings.HasPrefix(signature, "sha256=") {
		t.Errorf("signature = %q, want a sha256= prefix", signature)
	}
	if !Verify(secret, timestamp, signature, payload) {
		t.Error("Verify rejected a signature this package produced")
	}
}

func TestSignatureCoversTheTimestamp(t *testing.T) {
	secret := []byte("a signing secret")
	payload := []byte(`{"type":"key.created"}`)

	signature := Sign(secret, "1772000000", payload)

	// Replaying the same body with a fresh timestamp must not verify, or the
	// timestamp would be decoration rather than replay protection.
	if Verify(secret, "1772009999", signature, payload) {
		t.Error("a signature verified against a different timestamp")
	}
}

func TestSignatureCoversTheBody(t *testing.T) {
	secret := []byte("a signing secret")
	timestamp := "1772000000"

	signature := Sign(secret, timestamp, []byte(`{"type":"key.created"}`))
	if Verify(secret, timestamp, signature, []byte(`{"type":"key.revoked"}`)) {
		t.Error("a signature verified against a different body")
	}
}

func TestSignatureRejectsTheWrongSecret(t *testing.T) {
	payload := []byte(`{"type":"key.created"}`)
	signature := Sign([]byte("the real secret"), "1772000000", payload)

	if Verify([]byte("some other secret"), "1772000000", signature, payload) {
		t.Error("a signature verified under the wrong secret")
	}
}

// The delimiter matters: without it, ("12", "3...") and ("123", "...") would
// hash identically, so a receiver could be fed a body that began with a digit
// and claim a different timestamp.
func TestTimestampAndBodyAreUnambiguous(t *testing.T) {
	secret := []byte("s")

	a := Sign(secret, "12", []byte("3payload"))
	b := Sign(secret, "123", []byte("payload"))

	if a == b {
		t.Error("timestamp and body are concatenated without a delimiter")
	}
}

func TestNewSecretIsLongAndUnique(t *testing.T) {
	first, second := NewSecret(), NewSecret()

	if first == second {
		t.Error("NewSecret returned the same value twice")
	}
	if len(first) < 32 {
		t.Errorf("NewSecret returned %d characters, want at least 32", len(first))
	}
}

func TestBusDeliversToEverySubscriber(t *testing.T) {
	bus := NewBus(quietLogger())

	a := bus.Subscribe(4)
	defer a.Close()
	b := bus.Subscribe(4)
	defer b.Close()

	tenant := uuid.New()
	bus.Publish(Event{ID: uuid.New(), Type: TypeKeyCreated, TenantID: tenant})

	for name, sub := range map[string]*Subscription{"a": a, "b": b} {
		select {
		case ev := <-sub.C:
			if ev.Type != TypeKeyCreated {
				t.Errorf("subscriber %s got %q", name, ev.Type)
			}
		case <-time.After(time.Second):
			t.Errorf("subscriber %s received nothing", name)
		}
	}
}

// A browser tab that stops reading must not be able to stall a rotation. The
// bus drops rather than blocks, and this asserts that it really does.
func TestSlowSubscriberDoesNotBlockThePublisher(t *testing.T) {
	bus := NewBus(quietLogger())

	slow := bus.Subscribe(1)
	defer slow.Close()

	// Several publishers at once, because that is how the server actually
	// behaves: workers and request handlers emit concurrently.
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for p := 0; p < 4; p++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 100; i++ {
					bus.Publish(Event{ID: uuid.New(), Type: TypeKeyDeployed})
				}
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish blocked on a subscriber that stopped reading")
	}

	if bus.Dropped() == 0 {
		t.Error("Dropped() = 0, but a one-slot subscriber cannot have taken 400 events")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	bus := NewBus(quietLogger())
	sub := bus.Subscribe(1)

	sub.Close()
	sub.Close() // must not panic on a double close of the channel

	if bus.Subscribers() != 0 {
		t.Errorf("Subscribers() = %d after close, want 0", bus.Subscribers())
	}
}

func TestSubscribersCount(t *testing.T) {
	bus := NewBus(quietLogger())

	if got := bus.Subscribers(); got != 0 {
		t.Fatalf("Subscribers() = %d on a fresh bus", got)
	}

	first := bus.Subscribe(1)
	second := bus.Subscribe(1)
	if got := bus.Subscribers(); got != 2 {
		t.Errorf("Subscribers() = %d, want 2", got)
	}

	first.Close()
	if got := bus.Subscribers(); got != 1 {
		t.Errorf("Subscribers() = %d after one close, want 1", got)
	}
	second.Close()
}

// recordingSink captures what the publisher hands to durable delivery.
type recordingSink struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingSink) Deliver(ctx context.Context, ev Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingSink) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

func TestPublisherStampsAndFansOut(t *testing.T) {
	bus := NewBus(quietLogger())
	sink := &recordingSink{}
	publisher := NewPublisher(bus, quietLogger(), sink)

	sub := bus.Subscribe(4)
	defer sub.Close()

	tenant := uuid.New()
	resource := uuid.New()
	publisher.Emit(context.Background(), tenant, TypeRotationStarted, "rotation",
		&resource, "web-fleet", map[string]any{"targets": 3})

	recorded := sink.snapshot()
	if len(recorded) != 1 {
		t.Fatalf("the sink got %d events, want 1", len(recorded))
	}

	ev := recorded[0]
	if ev.ID == uuid.Nil {
		t.Error("the publisher did not assign an identifier")
	}
	if ev.OccurredAt.IsZero() {
		t.Error("the publisher did not stamp a time")
	}
	if ev.TenantID != tenant {
		t.Errorf("TenantID = %s, want %s", ev.TenantID, tenant)
	}
	if ev.ResourceName != "web-fleet" {
		t.Errorf("ResourceName = %q", ev.ResourceName)
	}

	select {
	case fromBus := <-sub.C:
		if fromBus.ID != ev.ID {
			t.Error("the bus and the sink received different events")
		}
	case <-time.After(time.Second):
		t.Error("the bus received nothing")
	}
}

func TestAllEventTypesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range All {
		if seen[e] {
			t.Errorf("duplicate event type %q in All", e)
		}
		seen[e] = true
	}
	if len(All) < 10 {
		t.Errorf("All lists %d event types, which looks truncated", len(All))
	}
}
