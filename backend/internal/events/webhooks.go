package events

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

// Signature header names. The scheme mirrors what most receivers already
// implement: a timestamp and a hex HMAC over "timestamp.body", so a captured
// request cannot be replayed indefinitely.
const (
	HeaderSignature = "X-SKM-Signature"
	HeaderTimestamp = "X-SKM-Timestamp"
	HeaderEvent     = "X-SKM-Event"
	HeaderDelivery  = "X-SKM-Delivery"
)

// Dispatcher queues events for the webhooks that subscribe to them and delivers
// the queue with retries.
//
// Queueing and sending are separate on purpose: Deliver runs on the publishing
// goroutine and must be cheap and non-blocking, while the actual HTTP call is
// slow, fallible, and needs to survive a restart.
type Dispatcher struct {
	webhooks *store.Webhooks
	vault    *vault.Vault
	client   *http.Client
	log      *slog.Logger

	maxAttempts int
	baseBackoff time.Duration
}

// NewDispatcher builds a webhook dispatcher.
//
// The HTTP client sets an aggressive timeout and disables redirects: a webhook
// endpoint that redirects is either misconfigured or trying to bounce a signed
// SKM request somewhere it was not addressed to.
func NewDispatcher(webhooks *store.Webhooks, v *vault.Vault, log *slog.Logger) *Dispatcher {
	return &Dispatcher{
		webhooks: webhooks,
		vault:    v,
		log:      log,
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				TLSHandshakeTimeout: 5 * time.Second,
				MaxIdleConnsPerHost: 2,
			},
		},
		maxAttempts: 6,
		baseBackoff: 30 * time.Second,
	}
}

// Deliver queues an event for every subscribed webhook.
func (d *Dispatcher) Deliver(ctx context.Context, ev Event) {
	hooks, err := d.webhooks.List(ctx, ev.TenantID)
	if err != nil {
		d.log.Warn("listing webhooks for an event", "type", ev.Type, "error", err)
		return
	}

	payload, err := ev.JSON()
	if err != nil {
		d.log.Warn("encoding event payload", "type", ev.Type, "error", err)
		return
	}

	for i := range hooks {
		hook := &hooks[i]
		if !hook.Matches(ev.Type) {
			continue
		}
		if _, err := d.webhooks.QueueDelivery(ctx, hook.ID, ev.Type, payload); err != nil {
			d.log.Warn("queueing webhook delivery",
				"webhook", hook.Name, "type", ev.Type, "error", err)
		}
	}
}

// Drain sends every delivery that is due, returning how many were attempted.
// The scheduler calls it on a tick.
func (d *Dispatcher) Drain(ctx context.Context, limit int) (int, error) {
	due, err := d.webhooks.DueDeliveries(ctx, limit)
	if err != nil {
		return 0, err
	}

	for i := range due {
		d.attempt(ctx, &due[i])
	}
	return len(due), nil
}

func (d *Dispatcher) attempt(ctx context.Context, delivery *store.WebhookDelivery) {
	hook, err := d.webhooks.Get(ctx, store.DefaultTenantID, delivery.WebhookID)
	if err != nil {
		d.record(ctx, delivery, 0, fmt.Sprintf("loading the webhook: %v", err), false)
		return
	}

	status, body, err := d.send(ctx, hook, delivery)
	if err != nil {
		d.record(ctx, delivery, status, err.Error(), false)
		return
	}

	// 2xx is success; everything else is retried. A 4xx from a receiver that
	// will never accept the event still burns the attempt budget and lands in
	// the delivery log, where an operator can see it.
	ok := status >= 200 && status < 300
	d.record(ctx, delivery, status, body, ok)
}

func (d *Dispatcher) send(ctx context.Context, hook *store.Webhook, delivery *store.WebhookDelivery) (int, string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, hook.URL, bytes.NewReader(delivery.Payload))
	if err != nil {
		return 0, "", fmt.Errorf("events: building the webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "skm-webhook/1")
	req.Header.Set(HeaderEvent, delivery.Event)
	req.Header.Set(HeaderDelivery, delivery.ID.String())

	for k, v := range hook.Headers {
		req.Header.Set(k, v)
	}

	if hook.HasSecret {
		secret, err := d.secret(ctx, hook)
		if err != nil {
			return 0, "", err
		}
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set(HeaderTimestamp, timestamp)
		req.Header.Set(HeaderSignature, Sign(secret, timestamp, delivery.Payload))
		vault.Zero(secret)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("events: delivering to %s: %w", hook.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read a bounded amount: the response is only kept for diagnostics, and a
	// misbehaving endpoint should not be able to stream gigabytes at us.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(body), nil
}

func (d *Dispatcher) secret(ctx context.Context, hook *store.Webhook) ([]byte, error) {
	sealed, err := d.webhooks.LoadSecret(ctx, hook.TenantID, hook.ID)
	if err != nil {
		return nil, fmt.Errorf("events: loading the signing secret for %s: %w", hook.Name, err)
	}
	secret, err := d.vault.Decrypt(sealed, []byte(hook.ID.String()))
	if err != nil {
		return nil, fmt.Errorf("events: decrypting the signing secret for %s: %w", hook.Name, err)
	}
	return secret, nil
}

func (d *Dispatcher) record(ctx context.Context, delivery *store.WebhookDelivery, status int, body string, ok bool) {
	backoff := d.backoff(delivery.Attempts)

	if err := d.webhooks.RecordDeliveryResult(ctx, delivery.ID, status, body, ok, backoff, d.maxAttempts); err != nil {
		d.log.Warn("recording webhook delivery", "delivery", delivery.ID, "error", err)
	}
	if !ok {
		d.log.Warn("webhook delivery failed", "delivery", delivery.ID,
			"event", delivery.Event, "attempt", delivery.Attempts, "status", status)
	}
}

func (d *Dispatcher) backoff(attempt int) time.Duration {
	delay := d.baseBackoff
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay > time.Hour {
			return time.Hour
		}
	}
	return delay
}

// Sign computes the HMAC a receiver should verify.
//
// The timestamp is inside the signed material so that replaying a captured
// request with a stale timestamp fails verification on any receiver that
// checks freshness.
func Sign(secret []byte, timestamp string, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature, in constant time. It exists so the test suite
// proves the scheme round-trips, and so an operator writing a receiver has a
// reference implementation to read.
func Verify(secret []byte, timestamp, signature string, payload []byte) bool {
	expected := Sign(secret, timestamp, payload)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// NewSecret returns a random webhook signing secret.
func NewSecret() string {
	return uuid.New().String() + uuid.New().String()
}
