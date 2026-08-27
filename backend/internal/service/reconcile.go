package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/hamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/events"
	"github.com/hamalawy/ssh-key-manager/backend/internal/keys"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

// ReconcileService compares what SKM believes about a target with what the
// target actually says.
//
// It pays for itself twice. It heals drift — a key someone deleted by hand
// comes back, a key someone added by hand is flagged — and it builds the
// unmanaged-key inventory, which for an estate that has never had key
// management is usually the first genuinely useful screen in the product:
// "who can already log into these machines?" is a question most operators
// cannot answer at all.
type ReconcileService struct {
	targets     *store.Targets
	keys        *store.Keys
	assignments *store.Assignments
	discovery   *store.Discovery
	deploySvc   *DeployService
	keySvc      *KeyService
	audit       *audit.Logger
	publisher   *events.Publisher
	log         *slog.Logger
}

// NewReconcileService wires a ReconcileService.
func NewReconcileService(t *store.Targets, k *store.Keys, a *store.Assignments, d *store.Discovery, deploy *DeployService, keySvc *KeyService, auditLog *audit.Logger, pub *events.Publisher, log *slog.Logger) *ReconcileService {
	return &ReconcileService{
		targets: t, keys: k, assignments: a, discovery: d, deploySvc: deploy,
		keySvc: keySvc, audit: auditLog, publisher: pub, log: log,
	}
}

// PrincipalReport is one principal's reconciliation outcome.
type PrincipalReport struct {
	PrincipalID uuid.UUID `json:"principal_id"`
	Username    string    `json:"username"`

	// Missing are keys SKM expects but the target does not have.
	Missing []string `json:"missing,omitempty"`
	// Unexpected are managed keys present that should not be.
	Unexpected []string `json:"unexpected,omitempty"`
	// Unmanaged are keys on the target that SKM did not put there.
	Unmanaged []string `json:"unmanaged,omitempty"`

	Healed bool   `json:"healed"`
	Error  string `json:"error,omitempty"`
}

// InSync reports whether this principal needed nothing.
//
// Unmanaged keys deliberately do not count. Drift means the target diverged
// from SKM's desired state; a key SKM never claimed is a *finding*, tracked in
// the inventory and surfaced separately. Counting it as drift would leave any
// host carrying one legitimate personal key permanently "drifted", which makes
// the drift signal useless for the thing it exists to catch.
func (r PrincipalReport) InSync() bool {
	return len(r.Missing) == 0 && len(r.Unexpected) == 0 && r.Error == ""
}

// ReconcileResult reports one target's reconciliation.
type ReconcileResult struct {
	TargetID   uuid.UUID         `json:"target_id"`
	TargetName string            `json:"target_name"`
	DriftState string            `json:"drift_state"`
	Mode       string            `json:"reconcile_mode"`
	Principals []PrincipalReport `json:"principals"`
	CheckedAt  time.Time         `json:"checked_at"`
}

// Drifted reports whether anything differed.
func (r *ReconcileResult) Drifted() bool {
	for _, p := range r.Principals {
		if !p.InSync() {
			return true
		}
	}
	return false
}

// Reconcile inspects one target and, when configured to, heals it.
func (s *ReconcileService) Reconcile(ctx context.Context, subject *authz.Subject, targetID uuid.UUID) (*ReconcileResult, error) {
	if err := subject.Require(authz.PermReconcileRun); err != nil {
		return nil, err
	}

	target, err := s.targets.Get(ctx, subject.TenantID, targetID)
	if err != nil {
		return nil, err
	}
	if !subject.InScope(target.Tags) {
		return nil, fmt.Errorf("%w: target %s", authz.ErrOutOfScope, target.Name)
	}
	if target.ReconcileMode == store.ReconcileDisabled {
		return nil, fmt.Errorf("service: reconciliation is disabled for target %q", target.Name)
	}

	conn, err := s.deploySvc.registry.Get(target.Connector)
	if err != nil {
		return nil, err
	}
	if !conn.Capabilities().CanList {
		return nil, fmt.Errorf("service: the %s connector cannot read back its keys, so %q cannot be reconciled",
			target.Connector, target.Name)
	}

	principals, err := s.targets.ListPrincipals(ctx, targetID)
	if err != nil {
		return nil, err
	}

	result := &ReconcileResult{
		TargetID:   targetID,
		TargetName: target.Name,
		Mode:       target.ReconcileMode,
		CheckedAt:  time.Now().UTC(),
		Principals: make([]PrincipalReport, 0, len(principals)),
	}

	managed, err := s.managedByFingerprint(ctx, subject.TenantID)
	if err != nil {
		return nil, err
	}

	for i := range principals {
		report := s.reconcilePrincipal(ctx, subject, target, &principals[i], conn, managed)
		result.Principals = append(result.Principals, report)
	}

	drift := store.DriftInSync
	if result.Drifted() {
		drift = store.DriftDrifted
	}
	result.DriftState = drift

	if err := s.targets.SetDrift(ctx, subject.TenantID, targetID, drift); err != nil {
		s.log.Warn("recording drift state", "target", targetID, "error", err)
	}

	if drift == store.DriftDrifted {
		s.publisher.Emit(ctx, subject.TenantID, events.TypeDriftDetected, "target",
			&targetID, target.Name, map[string]any{"principals": len(result.Principals)})
	}

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionReconcile,
		ResourceType: "target",
		ResourceID:   &targetID,
		ResourceName: target.Name,
		Outcome:      audit.OutcomeSuccess,
		Detail:       map[string]any{"drift": drift, "mode": target.ReconcileMode},
	})

	return result, nil
}

// reconcilePrincipal diffs one principal's actual keys against the desired set.
func (s *ReconcileService) reconcilePrincipal(ctx context.Context, subject *authz.Subject, target *store.Target, principal *store.Principal, conn connectors.Connector, managed map[string]store.Key) PrincipalReport {
	report := PrincipalReport{PrincipalID: principal.ID, Username: principal.Username}

	cred, err := s.deploySvc.credential(ctx, subject.TenantID, target)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	defer vault.Zero(cred.PrivateKey)

	req := connectors.Request{
		Target:     toConnectorTarget(target),
		Principal:  toConnectorPrincipal(principal),
		Credential: cred,
	}

	actual, err := conn.List(ctx, req)
	if err != nil {
		report.Error = err.Error()
		return report
	}

	present := map[string]keys.Entry{}
	seenFingerprints := make([]string, 0, len(actual))
	for _, e := range actual {
		if e.Kind != keys.EntryKey || e.Fingerprint == "" {
			continue
		}
		present[e.Fingerprint] = e
		seenFingerprints = append(seenFingerprints, e.Fingerprint)
	}

	desired, err := s.assignments.ForPrincipal(ctx, subject.TenantID, principal.ID)
	if err != nil {
		report.Error = err.Error()
		return report
	}

	expected := map[string]bool{}
	for _, a := range desired {
		key, err := s.keys.Get(ctx, subject.TenantID, a.KeyID)
		if err != nil {
			continue
		}

		switch a.DesiredState {
		case store.StatePresent:
			expected[key.Fingerprint] = true
			if _, ok := present[key.Fingerprint]; !ok {
				report.Missing = append(report.Missing, key.Fingerprint)
				if e := s.assignments.RecordDeployment(ctx, a.ID, store.StateAbsent,
					"the key is not present on the target"); e != nil {
					s.log.Warn("recording drift on an assignment", "assignment", a.ID, "error", e)
				}
			}
		case store.StateAbsent:
			if _, ok := present[key.Fingerprint]; ok {
				report.Unexpected = append(report.Unexpected, key.Fingerprint)
			}
		}
	}

	// Anything present that SKM manages but did not expect here, plus anything
	// it does not manage at all, goes into the inventory.
	observedAt := time.Now()
	for fingerprint, entry := range present {
		if expected[fingerprint] {
			continue
		}
		if k, isManaged := managed[fingerprint]; isManaged {
			report.Unexpected = append(report.Unexpected, fmt.Sprintf("%s (%s)", fingerprint, k.Name))
			continue
		}

		report.Unmanaged = append(report.Unmanaged, fingerprint)
		if _, err := s.discovery.Observe(ctx, &store.DiscoveredKey{
			TenantID:    subject.TenantID,
			TargetID:    target.ID,
			PrincipalID: principal.ID,
			Fingerprint: fingerprint,
			PublicKey:   publicLine(entry),
			Algorithm:   entry.Type,
			Comment:     entry.Comment,
			Options:     entry.Options,
		}); err != nil {
			s.log.Warn("recording a discovered key", "target", target.Name, "error", err)
		}
	}

	if n, err := s.discovery.MarkAbsent(ctx, target.ID, principal.ID, seenFingerprints, observedAt); err != nil {
		s.log.Warn("marking discovered keys absent", "target", target.Name, "error", err)
	} else if n > 0 {
		s.log.Info("discovered keys are no longer present", "target", target.Name, "count", n)
	}

	if len(report.Unmanaged) > 0 {
		s.publisher.Emit(ctx, subject.TenantID, events.TypeUnmanagedFound, "target",
			&target.ID, target.Name, map[string]any{
				"principal": principal.Username, "count": len(report.Unmanaged),
			})
	}

	// Healing re-runs the ordinary deployment path, so it inherits the
	// snapshot, the lockout guard, and the audit entry rather than having a
	// quieter path of its own.
	if target.ReconcileMode == store.ReconcileAutoHeal && (len(report.Missing) > 0 || len(report.Unexpected) > 0) {
		if _, err := s.deploySvc.Deploy(ctx, subject, target.ID, principal.ID, DeployOptions{
			Prune:      len(report.Unexpected) > 0,
			VerifyAuth: true,
		}); err != nil {
			report.Error = fmt.Sprintf("auto-heal failed: %v", err)
		} else {
			report.Healed = true
		}
	}

	return report
}

// ReconcileAll walks every enabled target, for the scheduled sweep.
func (s *ReconcileService) ReconcileAll(ctx context.Context, subject *authz.Subject) ([]ReconcileResult, error) {
	if err := subject.Require(authz.PermReconcileRun); err != nil {
		return nil, err
	}

	all, err := s.targets.List(ctx, store.TargetFilter{TenantID: subject.TenantID, Limit: 1000})
	if err != nil {
		return nil, err
	}

	out := make([]ReconcileResult, 0, len(all))
	for i := range all {
		t := &all[i]
		if !t.Enabled || t.ReconcileMode == store.ReconcileDisabled {
			continue
		}

		res, err := s.Reconcile(ctx, subject, t.ID)
		if err != nil {
			s.log.Warn("reconciling a target", "target", t.Name, "error", err)
			if e := s.targets.SetDrift(ctx, subject.TenantID, t.ID, store.DriftError); e != nil {
				s.log.Warn("recording reconcile error", "target", t.Name, "error", e)
			}
			continue
		}
		out = append(out, *res)
	}
	return out, nil
}

// Adopt brings a discovered key under management as a public-key-only record.
//
// SKM does not hold the private half, so the key is imported as
// "discovered": it can be tracked, assigned, and removed, but it cannot be
// rotated, because rotating a key nobody holds the private half of is not
// something SKM can carry out.
func (s *ReconcileService) Adopt(ctx context.Context, subject *authz.Subject, discoveredID uuid.UUID, name string) (*store.Key, error) {
	if err := subject.Require(authz.PermKeyAdopt); err != nil {
		return nil, err
	}

	d, err := s.discovery.Get(ctx, subject.TenantID, discoveredID)
	if err != nil {
		return nil, err
	}
	if d.State == store.DiscoveredAdopted {
		return nil, fmt.Errorf("%w: this key has already been adopted", store.ErrConflict)
	}

	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(d.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("service: the discovered key is not a valid public key: %w", err)
	}

	if name == "" {
		name = fmt.Sprintf("adopted-%s", shortFingerprint(d.Fingerprint))
	}

	// Record SKM's own algorithm name where the wire type maps onto one, so an
	// adopted key sorts and filters alongside generated ones. A key whose type
	// SKM will not generate — an old ssh-rsa, say — keeps its wire type and is
	// flagged non-compliant rather than being rejected: you cannot rotate away
	// from a weak key you refused to record.
	algorithm := pub.Type()
	compliant := true
	notes := ""
	if parsed, err := keys.ParseAlgorithm(pub.Type()); err == nil {
		algorithm = string(parsed)
	} else {
		compliant = false
		notes = err.Error()
	}

	key, err := s.keys.Create(ctx, &store.Key{
		TenantID:        subject.TenantID,
		Name:            name,
		Description:     fmt.Sprintf("adopted from %s (%s)", d.TargetName, d.Username),
		Algorithm:       algorithm,
		PublicKey:       d.PublicKey,
		Fingerprint:     d.Fingerprint,
		Comment:         orString(comment, d.Comment),
		Status:          store.KeyStatusActive,
		KeyClass:        store.KeyClassDiscovered,
		HasPrivateKey:   false,
		Compliant:       compliant,
		ComplianceNotes: notes,
		OwnerID:         &subject.UserID,
		Tags:            []string{"adopted"},
	}, nil)
	if err != nil {
		return nil, err
	}

	if _, err := s.assignments.Upsert(ctx, &store.Assignment{
		TenantID:     subject.TenantID,
		KeyID:        key.ID,
		TargetID:     d.TargetID,
		PrincipalID:  d.PrincipalID,
		Options:      d.Options,
		DesiredState: store.StatePresent,
		ActualState:  store.StatePresent,
		CreatedBy:    &subject.UserID,
	}); err != nil {
		return nil, err
	}

	if _, err := s.discovery.SetState(ctx, subject.TenantID, discoveredID, store.DiscoveredAdopted, &key.ID); err != nil {
		return nil, err
	}

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionKeyAdopt,
		ResourceType: "key",
		ResourceID:   &key.ID,
		ResourceName: key.Name,
		Outcome:      audit.OutcomeSuccess,
		Detail: map[string]any{
			"fingerprint": d.Fingerprint, "target": d.TargetName, "principal": d.Username,
			"note": "adopted keys have no private half in the vault and cannot be rotated",
		},
	})

	return key, nil
}

// Ignore marks a discovered key as known and accepted, so it stops appearing
// as an unresolved finding.
func (s *ReconcileService) Ignore(ctx context.Context, subject *authz.Subject, discoveredID uuid.UUID) (*store.DiscoveredKey, error) {
	if err := subject.Require(authz.PermKeyAdopt); err != nil {
		return nil, err
	}
	return s.discovery.SetState(ctx, subject.TenantID, discoveredID, store.DiscoveredIgnored, nil)
}

// ListDiscovered returns the unmanaged-key inventory.
func (s *ReconcileService) ListDiscovered(ctx context.Context, subject *authz.Subject, f store.DiscoveryFilter) ([]store.DiscoveredKey, error) {
	if err := subject.Require(authz.PermTargetRead); err != nil {
		return nil, err
	}
	f.TenantID = subject.TenantID
	return s.discovery.List(ctx, f)
}

// managedByFingerprint indexes every key SKM knows about.
func (s *ReconcileService) managedByFingerprint(ctx context.Context, tenantID uuid.UUID) (map[string]store.Key, error) {
	all, err := s.keys.List(ctx, store.KeyFilter{TenantID: tenantID, Limit: 1000})
	if err != nil {
		return nil, err
	}

	out := make(map[string]store.Key, len(all))
	for _, k := range all {
		out[k.Fingerprint] = k
	}
	return out, nil
}

func (s *ReconcileService) record(ctx context.Context, subject *authz.Subject, ev audit.Event) {
	ev.TenantID = subject.TenantID
	ev.ActorType = audit.ActorUser
	ev.ActorID = &subject.UserID
	ev.ActorName = subject.Username
	if _, err := s.audit.Log(ctx, ev); err != nil {
		s.log.Error("writing audit event", "action", ev.Action, "error", err)
	}
}

// shortFingerprint trims the SHA256: prefix for use in a generated name.
func shortFingerprint(fp string) string {
	trimmed := strings.TrimPrefix(fp, "SHA256:")
	if len(trimmed) > 8 {
		return trimmed[:8]
	}
	return trimmed
}

// publicLine renders a discovered entry back to an authorized_keys line without
// its options, which are stored separately.
func publicLine(e keys.Entry) string {
	if e.PublicKey == nil {
		return e.Raw
	}
	line := string(ssh.MarshalAuthorizedKey(e.PublicKey))
	line = line[:len(line)-1] // drop the trailing newline MarshalAuthorizedKey adds
	if e.Comment != "" {
		line += " " + e.Comment
	}
	return line
}
