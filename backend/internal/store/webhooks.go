package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/shamalawy/ssh-key-manager/backend/internal/db"
	"github.com/shamalawy/ssh-key-manager/backend/internal/vault"
)

// Webhook is an outbound notification endpoint.
//
// The signing secret is sealed in the vault like any other secret: a webhook
// secret that leaks lets an attacker forge events into whatever consumes them.
type Webhook struct {
	ID       uuid.UUID         `json:"id"`
	TenantID uuid.UUID         `json:"-"`
	Name     string            `json:"name"`
	URL      string            `json:"url"`
	Events   []string          `json:"events"`
	Enabled  bool              `json:"enabled"`
	Headers  map[string]string `json:"headers"`

	HasSecret bool `json:"has_secret"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Matches reports whether a webhook subscribes to an event. An empty
// subscription list means every event, which is the useful default for the
// first webhook someone configures.
func (w *Webhook) Matches(event string) bool {
	if !w.Enabled {
		return false
	}
	if len(w.Events) == 0 {
		return true
	}
	for _, e := range w.Events {
		if e == event || e == "*" {
			return true
		}
	}
	return false
}

// WebhookDelivery is one attempt to send one event to one endpoint.
type WebhookDelivery struct {
	ID          uuid.UUID       `json:"id"`
	WebhookID   uuid.UUID       `json:"webhook_id"`
	Event       string          `json:"event"`
	Payload     json.RawMessage `json:"payload"`
	State       string          `json:"state"`
	Attempts    int             `json:"attempts"`
	StatusCode  *int            `json:"status_code,omitempty"`
	Response    string          `json:"response,omitempty"`
	NextRetryAt *time.Time      `json:"next_retry_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	DeliveredAt *time.Time      `json:"delivered_at,omitempty"`

	// Joined for display.
	WebhookName string `json:"webhook_name,omitempty"`
}

// Delivery states.
const (
	DeliveryPending   = "pending"
	DeliveryDelivered = "delivered"
	DeliveryFailed    = "failed"
	DeliveryDead      = "dead"
)

// Webhooks is the repository for outbound notifications.
type Webhooks struct{ pool *db.Pool }

// NewWebhooks returns a Webhooks repository.
func NewWebhooks(pool *db.Pool) *Webhooks { return &Webhooks{pool: pool} }

const webhookColumns = `id, tenant_id, name, url, events, enabled, headers,
	(ciphertext IS NOT NULL) AS has_secret, created_at, updated_at`

// Create stores a webhook and seals its signing secret.
func (s *Webhooks) Create(ctx context.Context, w *Webhook, secret *vault.Sealed) (*Webhook, error) {
	if w.ID == uuid.Nil {
		w.ID = uuid.New()
	}
	if w.TenantID == uuid.Nil {
		w.TenantID = DefaultTenantID
	}
	if w.Events == nil {
		w.Events = []string{}
	}
	if w.Headers == nil {
		w.Headers = map[string]string{}
	}

	headers, err := json.Marshal(w.Headers)
	if err != nil {
		return nil, fmt.Errorf("store: encoding webhook headers: %w", err)
	}

	var kekVersion *int
	var wrappedDEK, ciphertext []byte
	if secret != nil {
		kekVersion = &secret.KEKVersion
		wrappedDEK = secret.WrappedDEK
		ciphertext = secret.Ciphertext
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO webhooks (id, tenant_id, name, url, kek_version, wrapped_dek,
			ciphertext, events, enabled, headers)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+webhookColumns,
		w.ID, w.TenantID, w.Name, w.URL, kekVersion, wrappedDEK, ciphertext,
		w.Events, w.Enabled, headers)

	created, err := scanWebhook(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: a webhook named %q already exists", ErrConflict, w.Name)
		}
		return nil, fmt.Errorf("store: inserting webhook: %w", err)
	}
	return created, nil
}

// Get returns one webhook's metadata.
func (s *Webhooks) Get(ctx context.Context, tenantID, id uuid.UUID) (*Webhook, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+webhookColumns+` FROM webhooks WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	w, err := scanWebhook(row)
	if err != nil {
		return nil, fmt.Errorf("store: loading webhook %s: %w", id, err)
	}
	return w, nil
}

// List returns every webhook for a tenant.
func (s *Webhooks) List(ctx context.Context, tenantID uuid.UUID) ([]Webhook, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+webhookColumns+` FROM webhooks WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: listing webhooks: %w", err)
	}
	defer rows.Close()

	out := []Webhook{}
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *w)
	}
	return out, rows.Err()
}

// LoadSecret returns a webhook's sealed signing secret.
func (s *Webhooks) LoadSecret(ctx context.Context, tenantID, id uuid.UUID) (*vault.Sealed, error) {
	var sealed vault.Sealed
	var kekVersion *int
	err := s.pool.QueryRow(ctx,
		`SELECT kek_version, wrapped_dek, ciphertext FROM webhooks WHERE tenant_id = $1 AND id = $2`,
		tenantID, id).Scan(&kekVersion, &sealed.WrappedDEK, &sealed.Ciphertext)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: loading webhook secret: %w", err)
	}
	if kekVersion == nil || len(sealed.Ciphertext) == 0 {
		return nil, ErrNotFound
	}
	sealed.KEKVersion = *kekVersion
	return &sealed, nil
}

// Delete removes a webhook and its delivery history.
func (s *Webhooks) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM webhooks WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: deleting webhook: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetEnabled turns a webhook on or off without losing its configuration.
func (s *Webhooks) SetEnabled(ctx context.Context, tenantID, id uuid.UUID, enabled bool) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE webhooks SET enabled = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, enabled)
	if err != nil {
		return fmt.Errorf("store: updating webhook: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// QueueDelivery records an event to be sent.
func (s *Webhooks) QueueDelivery(ctx context.Context, webhookID uuid.UUID, event string, payload []byte) (*WebhookDelivery, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO webhook_deliveries (webhook_id, event, payload, next_retry_at)
		VALUES ($1,$2,$3, now())
		RETURNING id, webhook_id, event, payload, state, attempts, status_code,
			response, next_retry_at, created_at, delivered_at`,
		webhookID, event, payload)

	d, err := scanDelivery(row)
	if err != nil {
		return nil, fmt.Errorf("store: queueing webhook delivery: %w", err)
	}
	return d, nil
}

// DueDeliveries leases pending deliveries whose retry time has arrived.
func (s *Webhooks) DueDeliveries(ctx context.Context, limit int) ([]WebhookDelivery, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.pool.Query(ctx, `
		UPDATE webhook_deliveries SET attempts = attempts + 1, next_retry_at = NULL
		WHERE id IN (
			SELECT id FROM webhook_deliveries
			WHERE state = 'pending' AND next_retry_at IS NOT NULL AND next_retry_at <= now()
			ORDER BY next_retry_at FOR UPDATE SKIP LOCKED LIMIT $1)
		RETURNING id, webhook_id, event, payload, state, attempts, status_code,
			response, next_retry_at, created_at, delivered_at`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: leasing webhook deliveries: %w", err)
	}
	defer rows.Close()

	out := []WebhookDelivery{}
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// RecordDeliveryResult stores an attempt's outcome, scheduling a retry or
// giving up once the attempt budget is spent.
func (s *Webhooks) RecordDeliveryResult(ctx context.Context, id uuid.UUID, statusCode int, response string, ok bool, retryAfter time.Duration, maxAttempts int) error {
	if ok {
		_, err := s.pool.Exec(ctx, `
			UPDATE webhook_deliveries SET state = 'delivered', status_code = $2,
				response = $3, delivered_at = now(), next_retry_at = NULL
			WHERE id = $1`, id, statusCode, truncate(response, 2000))
		if err != nil {
			return fmt.Errorf("store: recording webhook delivery: %w", err)
		}
		return nil
	}

	_, err := s.pool.Exec(ctx, `
		UPDATE webhook_deliveries SET
			state = CASE WHEN attempts >= $5 THEN 'dead' ELSE 'pending' END,
			status_code = $2, response = $3,
			next_retry_at = CASE WHEN attempts >= $5 THEN NULL ELSE now() + $4::interval END
		WHERE id = $1`, id, nullableInt(statusCode), truncate(response, 2000),
		retryAfter.String(), maxAttempts)
	if err != nil {
		return fmt.Errorf("store: recording webhook failure: %w", err)
	}
	return nil
}

// ReplayDelivery requeues a delivery an operator wants retried by hand.
func (s *Webhooks) ReplayDelivery(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE webhook_deliveries SET state = 'pending', attempts = 0,
			next_retry_at = now(), response = '' WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: replaying webhook delivery: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListDeliveries returns delivery history newest first.
func (s *Webhooks) ListDeliveries(ctx context.Context, tenantID uuid.UUID, webhookID *uuid.UUID, limit int) ([]WebhookDelivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT d.id, d.webhook_id, d.event, d.payload, d.state, d.attempts,
			d.status_code, d.response, d.next_retry_at, d.created_at, d.delivered_at, w.name
		FROM webhook_deliveries d
		JOIN webhooks w ON w.id = d.webhook_id
		WHERE w.tenant_id = $1 AND ($2::uuid IS NULL OR d.webhook_id = $2)
		ORDER BY d.created_at DESC LIMIT $3`, tenantID, webhookID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing webhook deliveries: %w", err)
	}
	defer rows.Close()

	out := []WebhookDelivery{}
	for rows.Next() {
		var d WebhookDelivery
		var payload []byte
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.Event, &payload, &d.State,
			&d.Attempts, &d.StatusCode, &d.Response, &d.NextRetryAt,
			&d.CreatedAt, &d.DeliveredAt, &d.WebhookName); err != nil {
			return nil, fmt.Errorf("store: scanning webhook delivery: %w", err)
		}
		d.Payload = payload
		out = append(out, d)
	}
	return out, rows.Err()
}

func scanWebhook(row interface{ Scan(...any) error }) (*Webhook, error) {
	var w Webhook
	var headers []byte
	err := row.Scan(&w.ID, &w.TenantID, &w.Name, &w.URL, &w.Events, &w.Enabled,
		&headers, &w.HasSecret, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(headers) > 0 {
		if err := json.Unmarshal(headers, &w.Headers); err != nil {
			return nil, fmt.Errorf("store: decoding webhook headers: %w", err)
		}
	}
	return &w, nil
}

func scanDelivery(row interface{ Scan(...any) error }) (*WebhookDelivery, error) {
	var d WebhookDelivery
	var payload []byte
	err := row.Scan(&d.ID, &d.WebhookID, &d.Event, &payload, &d.State, &d.Attempts,
		&d.StatusCode, &d.Response, &d.NextRetryAt, &d.CreatedAt, &d.DeliveredAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	d.Payload = payload
	return &d, nil
}

// nullableInt keeps a zero status code (the connection never completed) out of
// the record as NULL rather than as a misleading HTTP 0.
func nullableInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}
