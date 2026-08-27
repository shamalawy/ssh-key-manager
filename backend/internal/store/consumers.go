package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hamalawy/ssh-key-manager/backend/internal/db"
)

// Consumer is a sink for a *private* key, as opposed to a target, which
// receives the public one.
//
// Modelling only targets is the mistake that breaks rotation in practice: the
// CI job or application that authenticates with the key has to receive the new
// private key before the old public key is removed, or retiring the old key
// takes the service down. Consumers exist so the engine has somewhere to put
// that step.
type Consumer struct {
	ID       uuid.UUID      `json:"id"`
	TenantID uuid.UUID      `json:"-"`
	KeyID    uuid.UUID      `json:"key_id"`
	Name     string         `json:"name"`
	Kind     string         `json:"kind"`
	Config   map[string]any `json:"config"`
	Enabled  bool           `json:"enabled"`

	LastDeliveredAt *time.Time `json:"last_delivered_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Consumer kinds.
const (
	ConsumerVaultKV   = "vault_kv"
	ConsumerK8sSecret = "kubernetes_secret"
	ConsumerFileDrop  = "file_drop"
	ConsumerWebhook   = "webhook"
	ConsumerEnvExport = "env_export"
)

// Consumers is the repository for private-key sinks.
type Consumers struct{ pool *db.Pool }

// NewConsumers returns a Consumers repository.
func NewConsumers(pool *db.Pool) *Consumers { return &Consumers{pool: pool} }

const consumerColumns = `id, tenant_id, key_id, name, kind, config, enabled,
	last_delivered_at, last_error, created_at, updated_at`

// Create stores a consumer.
func (s *Consumers) Create(ctx context.Context, c *Consumer) (*Consumer, error) {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.TenantID == uuid.Nil {
		c.TenantID = DefaultTenantID
	}
	if c.Config == nil {
		c.Config = map[string]any{}
	}

	config, err := json.Marshal(c.Config)
	if err != nil {
		return nil, fmt.Errorf("store: encoding consumer config: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO consumers (id, tenant_id, key_id, name, kind, config, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+consumerColumns,
		c.ID, c.TenantID, c.KeyID, c.Name, c.Kind, config, c.Enabled)

	created, err := scanConsumer(row)
	if err != nil {
		if isForeignKeyViolation(err) {
			return nil, fmt.Errorf("%w: no such key %s", ErrNotFound, c.KeyID)
		}
		return nil, fmt.Errorf("store: inserting consumer: %w", err)
	}
	return created, nil
}

// Get returns one consumer.
func (s *Consumers) Get(ctx context.Context, tenantID, id uuid.UUID) (*Consumer, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+consumerColumns+` FROM consumers WHERE tenant_id = $1 AND id = $2`, tenantID, id)

	c, err := scanConsumer(row)
	if err != nil {
		return nil, fmt.Errorf("store: loading consumer %s: %w", id, err)
	}
	return c, nil
}

// List returns consumers, optionally only those bound to one key.
func (s *Consumers) List(ctx context.Context, tenantID uuid.UUID, keyID *uuid.UUID) ([]Consumer, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+consumerColumns+` FROM consumers
		WHERE tenant_id = $1 AND ($2::uuid IS NULL OR key_id = $2)
		ORDER BY name`, tenantID, keyID)
	if err != nil {
		return nil, fmt.Errorf("store: listing consumers: %w", err)
	}
	defer rows.Close()

	out := []Consumer{}
	for rows.Next() {
		c, err := scanConsumer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// Rebind points a consumer at a different key, which is how a rotation hands
// the new private key to the systems that use it.
func (s *Consumers) Rebind(ctx context.Context, tenantID, id, keyID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE consumers SET key_id = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, keyID)
	if err != nil {
		return fmt.Errorf("store: rebinding consumer: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordDelivery stores the outcome of a delivery attempt.
func (s *Consumers) RecordDelivery(ctx context.Context, id uuid.UUID, cause error) error {
	msg := ""
	var delivered any
	if cause != nil {
		msg = truncate(cause.Error(), 2000)
	} else {
		delivered = time.Now()
	}

	_, err := s.pool.Exec(ctx, `
		UPDATE consumers SET last_error = $2,
			last_delivered_at = COALESCE($3, last_delivered_at), updated_at = now()
		WHERE id = $1`, id, msg, delivered)
	if err != nil {
		return fmt.Errorf("store: recording consumer delivery: %w", err)
	}
	return nil
}

// Delete removes a consumer.
func (s *Consumers) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM consumers WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("store: deleting consumer: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanConsumer(row interface{ Scan(...any) error }) (*Consumer, error) {
	var c Consumer
	var config []byte
	err := row.Scan(&c.ID, &c.TenantID, &c.KeyID, &c.Name, &c.Kind, &config,
		&c.Enabled, &c.LastDeliveredAt, &c.LastError, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &c.Config); err != nil {
			return nil, fmt.Errorf("store: decoding consumer config: %w", err)
		}
	}
	return &c, nil
}
