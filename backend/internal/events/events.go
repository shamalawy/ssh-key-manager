// Package events carries things that happened to whatever wants to know:
// the browser over Server-Sent Events, and configured HTTP endpoints as signed
// webhooks.
//
// The bus is deliberately lossy for slow subscribers. A browser tab that stops
// reading must not be able to stall a rotation, so its channel is bounded and
// events are dropped rather than blocking the publisher. Durability lives in
// the audit log and the webhook delivery table, both of which are unaffected
// by a subscriber falling behind.
package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Event types. These are the strings a webhook subscribes to.
const (
	TypeKeyCreated       = "key.created"
	TypeKeyRevoked       = "key.revoked"
	TypeKeyExpiring      = "key.expiring"
	TypeKeyDeployed      = "key.deployed"
	TypeDeployFailed     = "deploy.failed"
	TypeRotationStarted  = "rotation.started"
	TypeRotationStaged   = "rotation.staged"
	TypeRotationVerified = "rotation.verified"
	TypeRotationSoaking  = "rotation.soaking"
	TypeRotationDone     = "rotation.completed"
	TypeRotationFailed   = "rotation.failed"
	TypeRotationAborted  = "rotation.aborted"
	TypeDriftDetected    = "drift.detected"
	TypeVerifyFailed     = "verification.failed"
	TypeJobFailed        = "job.failed"
	TypeBackupCompleted  = "backup.completed"
	TypeUnmanagedFound   = "discovery.unmanaged_key"
)

// All lists every event type, so the interface can render a subscription
// picker without hard-coding the list a second time.
var All = []string{
	TypeKeyCreated, TypeKeyRevoked, TypeKeyExpiring, TypeKeyDeployed,
	TypeDeployFailed, TypeRotationStarted, TypeRotationStaged,
	TypeRotationVerified, TypeRotationSoaking, TypeRotationDone,
	TypeRotationFailed, TypeRotationAborted, TypeDriftDetected,
	TypeVerifyFailed, TypeJobFailed, TypeBackupCompleted, TypeUnmanagedFound,
}

// Event is one thing that happened.
type Event struct {
	ID           uuid.UUID      `json:"id"`
	Type         string         `json:"type"`
	TenantID     uuid.UUID      `json:"-"`
	ResourceType string         `json:"resource_type,omitempty"`
	ResourceID   *uuid.UUID     `json:"resource_id,omitempty"`
	ResourceName string         `json:"resource_name,omitempty"`
	Data         map[string]any `json:"data,omitempty"`
	OccurredAt   time.Time      `json:"occurred_at"`
}

// JSON encodes an event for transport.
func (e Event) JSON() ([]byte, error) { return json.Marshal(e) }

// Subscription is one consumer's view of the stream.
type Subscription struct {
	// C delivers events. It is closed when the subscription is cancelled.
	C <-chan Event

	id  uuid.UUID
	ch  chan Event
	bus *Bus
}

// Close detaches the subscription. Calling it twice is safe.
func (s *Subscription) Close() {
	if s.bus != nil {
		s.bus.unsubscribe(s.id)
		s.bus = nil
	}
}

// Bus fans events out to in-process subscribers.
type Bus struct {
	mu   sync.RWMutex
	subs map[uuid.UUID]*Subscription
	log  *slog.Logger
	// dropped is atomic because Publish holds only a read lock: two concurrent
	// publishers would otherwise race on it.
	dropped atomic.Int64
}

// NewBus returns an empty bus.
func NewBus(log *slog.Logger) *Bus {
	return &Bus{subs: make(map[uuid.UUID]*Subscription), log: log}
}

// Subscribe attaches a new consumer with a bounded buffer.
func (b *Bus) Subscribe(buffer int) *Subscription {
	if buffer <= 0 {
		buffer = 64
	}

	ch := make(chan Event, buffer)
	sub := &Subscription{C: ch, id: uuid.New(), ch: ch, bus: b}

	b.mu.Lock()
	b.subs[sub.id] = sub
	b.mu.Unlock()

	return sub
}

func (b *Bus) unsubscribe(id uuid.UUID) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if sub, ok := b.subs[id]; ok {
		delete(b.subs, id)
		close(sub.ch)
	}
}

// Publish delivers an event to every subscriber, skipping any whose buffer is
// full rather than waiting for it.
func (b *Bus) Publish(ev Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, sub := range b.subs {
		select {
		case sub.ch <- ev:
		default:
			b.dropped.Add(1)
			// Log at debug: a browser that scrolled away is normal, and this
			// would otherwise be the noisiest line in the log.
			b.log.Debug("dropped an event for a slow subscriber",
				"subscription", sub.id, "type", ev.Type)
		}
	}
}

// Dropped reports how many events were discarded for slow subscribers, so a
// persistently lagging interface is visible rather than merely quiet.
func (b *Bus) Dropped() int64 { return b.dropped.Load() }

// Subscribers returns the current subscriber count, for the status endpoint.
func (b *Bus) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// Sink receives published events for durable delivery. The webhook dispatcher
// implements it; tests substitute a recorder.
type Sink interface {
	Deliver(ctx context.Context, ev Event)
}

// Publisher is the single entry point the rest of the system calls.
type Publisher struct {
	bus   *Bus
	sinks []Sink
	log   *slog.Logger
}

// NewPublisher wires a bus to zero or more durable sinks.
func NewPublisher(bus *Bus, log *slog.Logger, sinks ...Sink) *Publisher {
	return &Publisher{bus: bus, sinks: sinks, log: log}
}

// Bus exposes the in-process bus so the SSE handler can subscribe.
func (p *Publisher) Bus() *Bus { return p.bus }

// Publish stamps an event and hands it to the bus and every sink.
func (p *Publisher) Publish(ctx context.Context, ev Event) {
	if ev.ID == uuid.Nil {
		ev.ID = uuid.New()
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}

	if p.bus != nil {
		p.bus.Publish(ev)
	}
	for _, sink := range p.sinks {
		sink.Deliver(ctx, ev)
	}
}

// Emit is the common case: a type, a resource, and some detail.
func (p *Publisher) Emit(ctx context.Context, tenantID uuid.UUID, evType, resourceType string, resourceID *uuid.UUID, name string, data map[string]any) {
	p.Publish(ctx, Event{
		Type:         evType,
		TenantID:     tenantID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: name,
		Data:         data,
	})
}
