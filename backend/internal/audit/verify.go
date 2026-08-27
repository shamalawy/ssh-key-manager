package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// VerifyResult reports the integrity of an audit chain.
type VerifyResult struct {
	TenantID uuid.UUID `json:"tenant_id"`
	Checked  int64     `json:"checked"`
	Valid    bool      `json:"valid"`

	// BrokenAtSeq is the first event whose hash or linkage does not hold.
	// Everything before it is intact; everything after it is unverifiable.
	BrokenAtSeq int64  `json:"broken_at_seq,omitempty"`
	Reason      string `json:"reason,omitempty"`

	FirstEventAt time.Time     `json:"first_event_at,omitempty"`
	LastEventAt  time.Time     `json:"last_event_at,omitempty"`
	Duration     time.Duration `json:"-"`
}

// Verify walks a tenant's chain from the beginning, recomputing every hash.
//
// It detects three distinct failures: an event whose content no longer matches
// its stored hash (the row was edited), an event whose prev_hash does not match
// its predecessor (a row was removed or reordered), and a chain that does not
// start from the empty hash (the beginning was truncated).
//
// Rows stream in batches so verifying a large log does not need it all in
// memory at once.
func (l *Logger) Verify(ctx context.Context, tenantID uuid.UUID) (*VerifyResult, error) {
	if tenantID == uuid.Nil {
		tenantID = DefaultTenantID
	}

	start := time.Now()
	res := &VerifyResult{TenantID: tenantID, Valid: true}

	rows, err := l.pool.Query(ctx, `
		SELECT seq, id, actor_type, actor_id, actor_name,
		       action, resource_type, resource_id, resource_name,
		       outcome, detail, host(ip_address), user_agent, session_id,
		       prev_hash, hash, occurred_at
		FROM audit_events
		WHERE tenant_id = $1
		ORDER BY seq ASC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("audit: reading chain: %w", err)
	}
	defer rows.Close()

	var expectedPrev string // the empty chain starts from ""

	for rows.Next() {
		rec, detailJSON, err := scanRecord(rows, tenantID)
		if err != nil {
			return nil, err
		}

		if res.Checked == 0 {
			res.FirstEventAt = rec.OccurredAt
		}
		res.Checked++
		res.LastEventAt = rec.OccurredAt

		if rec.PrevHash != expectedPrev {
			res.Valid = false
			res.BrokenAtSeq = rec.Seq
			res.Reason = fmt.Sprintf(
				"event %d links to prev_hash %q but its predecessor hashes to %q; a record was removed, reordered, or inserted",
				rec.Seq, truncate(rec.PrevHash), truncate(expectedPrev))
			break
		}

		if got := computeHash(rec, detailJSON); got != rec.Hash {
			res.Valid = false
			res.BrokenAtSeq = rec.Seq
			res.Reason = fmt.Sprintf(
				"event %d has hash %q but its content hashes to %q; the record was modified",
				rec.Seq, truncate(rec.Hash), truncate(got))
			break
		}

		expectedPrev = rec.Hash
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterating chain: %w", err)
	}

	res.Duration = time.Since(start)
	return res, nil
}

// Filter narrows an audit query. Zero values mean "no constraint".
type Filter struct {
	TenantID     uuid.UUID
	Actions      []string
	ActorID      *uuid.UUID
	ResourceType string
	ResourceID   *uuid.UUID
	Outcome      Outcome
	Since        time.Time
	Until        time.Time
	Limit        int
	BeforeSeq    int64 // keyset pagination: return events older than this
}

// Query returns audit records newest-first, for the GUI and CSV export.
//
// It uses keyset pagination on seq rather than OFFSET: audit logs grow without
// bound and OFFSET degrades linearly, whereas seq is the primary key and stays
// fast at any depth.
func (l *Logger) Query(ctx context.Context, f Filter) ([]Record, error) {
	if f.TenantID == uuid.Nil {
		f.TenantID = DefaultTenantID
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}

	// host() renders inet as text: pgx decodes inet into netip types, and the
	// hash is computed over the textual form anyway.
	q := `SELECT seq, id, actor_type, actor_id, actor_name,
	             action, resource_type, resource_id, resource_name,
	             outcome, detail, host(ip_address), user_agent, session_id,
	             prev_hash, hash, occurred_at
	      FROM audit_events
	      WHERE tenant_id = $1`
	args := []any{f.TenantID}

	add := func(clause string, val any) {
		args = append(args, val)
		q += fmt.Sprintf(clause, len(args))
	}

	if len(f.Actions) > 0 {
		add(" AND action = ANY($%d)", f.Actions)
	}
	if f.ActorID != nil {
		add(" AND actor_id = $%d", *f.ActorID)
	}
	if f.ResourceType != "" {
		add(" AND resource_type = $%d", f.ResourceType)
	}
	if f.ResourceID != nil {
		add(" AND resource_id = $%d", *f.ResourceID)
	}
	if f.Outcome != "" {
		add(" AND outcome = $%d", string(f.Outcome))
	}
	if !f.Since.IsZero() {
		add(" AND occurred_at >= $%d", f.Since)
	}
	if !f.Until.IsZero() {
		add(" AND occurred_at <= $%d", f.Until)
	}
	if f.BeforeSeq > 0 {
		add(" AND seq < $%d", f.BeforeSeq)
	}

	args = append(args, f.Limit)
	q += fmt.Sprintf(" ORDER BY seq DESC LIMIT $%d", len(args))

	rows, err := l.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: querying events: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		rec, _, err := scanRecord(rows, f.TenantID)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

// rowScanner is satisfied by pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanRecord reads one row, returning both the record and the raw detail bytes
// the hash was computed over.
func scanRecord(rows rowScanner, tenantID uuid.UUID) (*Record, []byte, error) {
	var (
		rec       Record
		detailRaw []byte
		actorType string
		outcome   string
		ipAddress *string
	)

	if err := rows.Scan(
		&rec.Seq, &rec.ID, &actorType, &rec.ActorID, &rec.ActorName,
		&rec.Action, &rec.ResourceType, &rec.ResourceID, &rec.ResourceName,
		&outcome, &detailRaw, &ipAddress, &rec.UserAgent, &rec.SessionID,
		&rec.PrevHash, &rec.Hash, &rec.OccurredAt,
	); err != nil {
		return nil, nil, fmt.Errorf("audit: scanning event: %w", err)
	}

	rec.TenantID = tenantID
	rec.ActorType = ActorType(actorType)
	rec.Outcome = Outcome(outcome)
	if ipAddress != nil {
		rec.IPAddress = *ipAddress
	}
	rec.OccurredAt = rec.OccurredAt.UTC()

	// Re-canonicalise: PostgreSQL does not preserve JSONB key order, so the
	// bytes read back differ from what was written. Decoding and re-encoding
	// through a Go map reproduces the canonical form that was hashed.
	detail, err := decodeDetail(detailRaw)
	if err != nil {
		return nil, nil, err
	}
	rec.Detail = detail

	canonical, err := canonicalJSON(detail)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: re-encoding detail: %w", err)
	}

	return &rec, canonical, nil
}

func truncate(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12] + "..."
}
