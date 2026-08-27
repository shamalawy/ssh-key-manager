// Package audit records a tamper-evident log of everything that happens.
//
// Each event commits to its predecessor by hash, so the log forms a chain:
// altering or removing any entry invalidates every hash after it. Combined with
// the database-level append-only trigger on audit_events, that gives two
// independent layers of protection — one that stops casual tampering and one
// that detects tampering by anyone who got past the first.
//
// The chain is per-tenant. Appends are serialised with a PostgreSQL advisory
// lock held for the duration of the transaction, because computing prev_hash
// and inserting must be atomic or two concurrent appends will both chain off
// the same predecessor and fork the chain.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ActorType identifies what kind of principal caused an event.
type ActorType string

const (
	ActorUser      ActorType = "user"
	ActorAPIToken  ActorType = "api_token"
	ActorSystem    ActorType = "system"
	ActorScheduler ActorType = "scheduler"
)

// Outcome records whether the action succeeded.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

// Event is a single audit record. Everything except Action is optional.
type Event struct {
	TenantID uuid.UUID

	ActorType ActorType
	ActorID   *uuid.UUID
	ActorName string

	// Action is a dotted verb such as "key.create" or "key.reveal".
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	ResourceName string

	Outcome Outcome
	// Detail carries action-specific context. It must never contain secret
	// material: the audit log is the most widely readable table in the system.
	Detail map[string]any

	IPAddress string
	UserAgent string
	SessionID *uuid.UUID
}

// Record is a stored event as read back from the database.
type Record struct {
	Seq          int64          `json:"seq"`
	ID           uuid.UUID      `json:"id"`
	TenantID     uuid.UUID      `json:"tenant_id"`
	ActorType    ActorType      `json:"actor_type"`
	ActorID      *uuid.UUID     `json:"actor_id,omitempty"`
	ActorName    string         `json:"actor_name"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   *uuid.UUID     `json:"resource_id,omitempty"`
	ResourceName string         `json:"resource_name"`
	Outcome      Outcome        `json:"outcome"`
	Detail       map[string]any `json:"detail"`
	IPAddress    string         `json:"ip_address,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	SessionID    *uuid.UUID     `json:"session_id,omitempty"`
	PrevHash     string         `json:"prev_hash"`
	Hash         string         `json:"hash"`
	OccurredAt   time.Time      `json:"occurred_at"`
}

// Logger appends events to the audit chain.
type Logger struct {
	pool *pgxpool.Pool
}

// New returns a Logger writing to pool.
func New(pool *pgxpool.Pool) *Logger { return &Logger{pool: pool} }

// Log appends an event and returns the stored record.
//
// The write is deliberately synchronous and its error is returned rather than
// swallowed: for security-relevant actions the caller should fail the operation
// if it cannot be recorded, and it can only make that choice if it is told.
func (l *Logger) Log(ctx context.Context, ev Event) (*Record, error) {
	ev.applyDefaults()
	if ev.Action == "" {
		return nil, fmt.Errorf("audit: Action is required")
	}

	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit: beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	// Serialise appends for this tenant so prev_hash cannot be read twice.
	// The lock is released automatically when the transaction ends.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey(ev.TenantID)); err != nil {
		return nil, fmt.Errorf("audit: acquiring chain lock: %w", err)
	}

	var prevHash string
	err = tx.QueryRow(ctx,
		`SELECT hash FROM audit_events WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`,
		ev.TenantID).Scan(&prevHash)
	if err != nil && err != pgx.ErrNoRows {
		return nil, fmt.Errorf("audit: reading chain head: %w", err)
	}

	rec := &Record{
		ID:           uuid.New(),
		TenantID:     ev.TenantID,
		ActorType:    ev.ActorType,
		ActorID:      ev.ActorID,
		ActorName:    ev.ActorName,
		Action:       ev.Action,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		ResourceName: ev.ResourceName,
		Outcome:      ev.Outcome,
		Detail:       ev.Detail,
		IPAddress:    ev.IPAddress,
		UserAgent:    ev.UserAgent,
		SessionID:    ev.SessionID,
		PrevHash:     prevHash,
		OccurredAt:   time.Now().UTC().Truncate(time.Microsecond),
	}

	detailJSON, err := canonicalJSON(rec.Detail)
	if err != nil {
		return nil, fmt.Errorf("audit: encoding detail: %w", err)
	}
	rec.Hash = computeHash(rec, detailJSON)

	var ip any
	if rec.IPAddress != "" {
		ip = rec.IPAddress
	}

	if err := tx.QueryRow(ctx, `
		INSERT INTO audit_events (
			id, tenant_id, actor_type, actor_id, actor_name,
			action, resource_type, resource_id, resource_name,
			outcome, detail, ip_address, user_agent, session_id,
			prev_hash, hash, occurred_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		RETURNING seq`,
		rec.ID, rec.TenantID, string(rec.ActorType), rec.ActorID, rec.ActorName,
		rec.Action, rec.ResourceType, rec.ResourceID, rec.ResourceName,
		string(rec.Outcome), detailJSON, ip, rec.UserAgent, rec.SessionID,
		rec.PrevHash, rec.Hash, rec.OccurredAt,
	).Scan(&rec.Seq); err != nil {
		return nil, fmt.Errorf("audit: inserting event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("audit: committing event: %w", err)
	}
	return rec, nil
}

func (ev *Event) applyDefaults() {
	if ev.ActorType == "" {
		ev.ActorType = ActorSystem
	}
	if ev.Outcome == "" {
		ev.Outcome = OutcomeSuccess
	}
	if ev.Detail == nil {
		ev.Detail = map[string]any{}
	}
	if ev.TenantID == uuid.Nil {
		ev.TenantID = DefaultTenantID
	}
}

// DefaultTenantID is the tenant every single-tenant install uses. It matches the
// row seeded by the initial migration.
var DefaultTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// computeHash derives an event's hash from its content and its predecessor.
//
// The field order below is part of the on-disk format: changing it invalidates
// every existing chain, so it must only change alongside a migration that
// rewrites and re-verifies history.
func computeHash(r *Record, detailJSON []byte) string {
	h := sha256.New()

	write := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			// A separator prevents ("ab","c") and ("a","bc") hashing alike.
			h.Write([]byte{0x1f})
		}
	}

	write(
		r.PrevHash,
		r.ID.String(),
		r.TenantID.String(),
		string(r.ActorType),
		uuidStr(r.ActorID),
		r.ActorName,
		r.Action,
		r.ResourceType,
		uuidStr(r.ResourceID),
		r.ResourceName,
		string(r.Outcome),
		r.IPAddress,
		r.UserAgent,
		uuidStr(r.SessionID),
		r.OccurredAt.UTC().Format(time.RFC3339Nano),
	)
	h.Write(detailJSON)

	return hex.EncodeToString(h.Sum(nil))
}

// canonicalJSON encodes detail deterministically. Go's encoding/json sorts map
// keys, which is what makes the hash reproducible when the value is read back
// out of JSONB — PostgreSQL does not preserve key order.
func canonicalJSON(m map[string]any) ([]byte, error) {
	if m == nil {
		m = map[string]any{}
	}
	return json.Marshal(m)
}

func uuidStr(u *uuid.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

// lockKey maps a tenant to a stable 64-bit advisory lock key.
func lockKey(tenant uuid.UUID) int64 {
	h := fnv.New64a()
	h.Write([]byte("skm.audit."))
	h.Write(tenant[:])
	return int64(h.Sum64())
}

// Actions used across the system. Keeping them as constants means the set is
// greppable and the GUI's filter list cannot drift from what is actually
// emitted.
const (
	ActionKeyCreate    = "key.create"
	ActionKeyImport    = "key.import"
	ActionKeyReveal    = "key.reveal"
	ActionKeyRevoke    = "key.revoke"
	ActionKeyDestroy   = "key.destroy"
	ActionKeyRotate    = "key.rotate"
	ActionKeyAdopt     = "key.adopt"
	ActionKeyDeploy    = "key.deploy"
	ActionKeyRemove    = "key.remove"
	ActionKeyVerify    = "key.verify"
	ActionTargetCreate = "target.create"
	ActionTargetUpdate = "target.update"
	ActionTargetDelete = "target.delete"
	ActionSnapshotTake = "snapshot.take"
	ActionRollback     = "changeset.rollback"
	ActionBackupCreate = "backup.create"
	ActionBackupRestor = "backup.restore"
	ActionVaultSeal    = "vault.seal"
	ActionVaultUnseal  = "vault.unseal"
	ActionKEKRotate    = "vault.kek_rotate"
	ActionLogin        = "auth.login"
	ActionLogout       = "auth.logout"
	ActionLoginFailed  = "auth.login_failed"
	ActionMFAVerify    = "auth.mfa_verify"
	ActionUserCreate   = "user.create"
	ActionUserUpdate   = "user.update"
	ActionTokenCreate  = "api_token.create"
	ActionTokenRevoke  = "api_token.revoke"
	ActionPermDenied   = "authz.denied"
	ActionBackupVerify = "backup.verify"
	ActionReconcile    = "reconcile.run"
	ActionConsumerAdd  = "consumer.create"
	ActionConsumerSend = "consumer.deliver"
	ActionConsumerBind = "consumer.rebind"
	ActionWebhookAdd   = "webhook.create"
)

// Action namespaces, used by the GUI to group the filter list.
func Namespace(action string) string {
	ns, _, _ := strings.Cut(action, ".")
	return ns
}
