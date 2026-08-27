package service

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/events"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

// DeployService converges targets on their desired key state.
//
// Every mutation follows the same shape: snapshot, apply, read back, verify,
// record. The snapshot is taken before anything changes and its identifier is
// recorded as the changeset's inverse operation, so a deployment is undoable
// from the moment it begins rather than only once it completes.
type DeployService struct {
	targets     *store.Targets
	keys        *store.Keys
	assignments *store.Assignments
	snapshots   *store.Snapshots
	changesets  *store.Changesets
	credentials *store.Credentials
	registry    *connectors.Registry
	vault       *vault.Vault
	keySvc      *KeyService
	audit       *audit.Logger
	publisher   *events.Publisher
	log         *slog.Logger
}

// SetPublisher attaches the event publisher, so a deployment made through the
// API announces itself just as one made through the job queue does. Without
// this, a webhook subscribed to key.deployed would fire only for queued work,
// which is the sort of inconsistency nobody discovers until it matters.
func (s *DeployService) SetPublisher(p *events.Publisher) { s.publisher = p }

// DeployServiceDeps bundles the repositories a DeployService needs.
type DeployServiceDeps struct {
	Targets     *store.Targets
	Keys        *store.Keys
	Assignments *store.Assignments
	Snapshots   *store.Snapshots
	Changesets  *store.Changesets
	Credentials *store.Credentials
	Registry    *connectors.Registry
	Vault       *vault.Vault
	KeyService  *KeyService
	Audit       *audit.Logger
	Logger      *slog.Logger
}

// NewDeployService wires a DeployService.
func NewDeployService(d DeployServiceDeps) *DeployService {
	return &DeployService{
		targets: d.Targets, keys: d.Keys, assignments: d.Assignments,
		snapshots: d.Snapshots, changesets: d.Changesets, credentials: d.Credentials,
		registry: d.Registry, vault: d.Vault, keySvc: d.KeyService,
		audit: d.Audit, log: d.Logger,
	}
}

// DeployOptions tunes a single convergence run.
type DeployOptions struct {
	// DryRun computes and returns the diff without writing.
	DryRun bool
	// Prune removes managed keys no longer assigned. Off by default so a
	// deployment only ever adds unless asked otherwise.
	Prune bool
	// VerifyAuth opens a fresh connection with each deployed key to prove it
	// actually authenticates, rather than trusting that the file was written.
	VerifyAuth bool
	// ChangesetID groups this deployment with others, for rotations.
	ChangesetID *uuid.UUID
}

// DeployResult reports what a convergence run did.
type DeployResult struct {
	TargetID    uuid.UUID `json:"target_id"`
	TargetName  string    `json:"target_name"`
	PrincipalID uuid.UUID `json:"principal_id"`
	Username    string    `json:"username"`

	Changed  bool     `json:"changed"`
	DryRun   bool     `json:"dry_run"`
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Diff     string   `json:"diff"`
	KeyCount int      `json:"key_count"`
	Warnings []string `json:"warnings,omitempty"`

	SnapshotID  *uuid.UUID `json:"snapshot_id,omitempty"`
	ChangesetID *uuid.UUID `json:"changeset_id,omitempty"`

	// VerifiedKeys lists fingerprints proven to authenticate.
	VerifiedKeys []string `json:"verified_keys,omitempty"`
	// FailedKeys lists fingerprints deployed but not provably working.
	FailedKeys []string `json:"failed_keys,omitempty"`
	// PromotedKeys lists keys this deployment moved to active.
	PromotedKeys []string `json:"promoted_keys,omitempty"`
}

// Deploy converges one principal on its assigned keys.
func (s *DeployService) Deploy(ctx context.Context, subject *authz.Subject, targetID, principalID uuid.UUID, opts DeployOptions) (*DeployResult, error) {
	perm := authz.PermDeployExecute
	if opts.DryRun {
		perm = authz.PermDeployDryRun
	}
	if err := subject.Require(perm); err != nil {
		return nil, err
	}

	target, principal, cred, conn, err := s.resolve(ctx, subject, targetID, principalID)
	if err != nil {
		return nil, err
	}
	if !subject.InScope(target.Tags) {
		return nil, fmt.Errorf("%w: target %s", authz.ErrOutOfScope, target.Name)
	}

	req := connectors.Request{Target: target, Principal: principal, Credential: cred}
	defer vault.Zero(cred.PrivateKey)

	desired, assignments, err := s.desiredKeys(ctx, subject.TenantID, principalID)
	if err != nil {
		return nil, err
	}

	result := &DeployResult{
		TargetID:    targetID,
		TargetName:  target.Name,
		PrincipalID: principalID,
		Username:    principal.Username,
		DryRun:      opts.DryRun,
		ChangesetID: opts.ChangesetID,
	}

	// Snapshot before touching anything, so rollback is possible even if the
	// apply fails partway.
	var snapshotID *uuid.UUID
	if conn.Capabilities().CanSnapshot && !opts.DryRun {
		snap, err := conn.Snapshot(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("service: capturing snapshot of %s: %w", target.Name, err)
		}
		stored, err := s.snapshots.Create(ctx, &store.Snapshot{
			TenantID:    subject.TenantID,
			TargetID:    targetID,
			PrincipalID: &principalID,
			ChangesetID: opts.ChangesetID,
			Kind:        snap.Kind,
			RawContent:  snap.Content,
			Checksum:    snap.Checksum,
			KeyCount:    snap.KeyCount,
			Existed:     snap.Existed,
		})
		if err != nil {
			return nil, err
		}
		snapshotID = &stored.ID
		result.SnapshotID = snapshotID

		if opts.ChangesetID != nil {
			if err := s.changesets.AppendInverse(ctx, *opts.ChangesetID, map[string]any{
				"op":           "restore_snapshot",
				"snapshot_id":  stored.ID.String(),
				"target_id":    targetID.String(),
				"principal_id": principalID.String(),
			}); err != nil {
				return nil, err
			}
		}
	}

	applyOpts := connectors.DefaultApplyOptions()
	applyOpts.DryRun = opts.DryRun
	applyOpts.Prune = opts.Prune
	applyOpts.ManagedFingerprints = s.managedFingerprints(ctx, subject.TenantID)

	applied, err := conn.Apply(ctx, req, desired, applyOpts)
	if applied != nil {
		result.Changed = applied.Changed
		result.Added = applied.Added
		result.Removed = applied.Removed
		result.Diff = applied.Diff
		result.Warnings = applied.Warnings
		if applied.After != nil {
			result.KeyCount = applied.After.KeyCount
		}
	}
	if err != nil {
		s.recordFailure(ctx, assignments, err)
		s.auditDeploy(ctx, subject, target, principal, result, err)
		if s.publisher != nil {
			s.publisher.Emit(ctx, subject.TenantID, events.TypeDeployFailed, "target",
				&targetID, target.Name, map[string]any{
					"principal": principal.Username, "error": err.Error(),
				})
		}
		return result, err
	}

	if opts.DryRun {
		return result, nil
	}

	// Record each assignment as applied, then — if asked — prove each key can
	// actually authenticate. Presence in a file is not the same as working
	// access, and only the second is worth acting on.
	for _, a := range assignments {
		if err := s.assignments.RecordDeployment(ctx, a.ID, store.StatePresent, ""); err != nil {
			s.log.Warn("recording deployment", "assignment", a.ID, "error", err)
		}
	}

	if opts.VerifyAuth && conn.Capabilities().CanVerify {
		s.verifyAssignments(ctx, subject, req, conn, assignments, result)
	}

	if err := s.targets.SetDrift(ctx, subject.TenantID, targetID, store.DriftInSync); err != nil {
		s.log.Warn("recording drift state", "target", targetID, "error", err)
	}

	s.auditDeploy(ctx, subject, target, principal, result, nil)

	if s.publisher != nil {
		s.publisher.Emit(ctx, subject.TenantID, events.TypeKeyDeployed, "target",
			&targetID, target.Name, map[string]any{
				"principal": principal.Username,
				"added":     result.Added,
				"removed":   result.Removed,
				"verified":  result.VerifiedKeys,
			})
	}
	return result, nil
}

// verifyAssignments proves each deployed key authenticates, recording the
// outcome per assignment.
func (s *DeployService) verifyAssignments(ctx context.Context, subject *authz.Subject, req connectors.Request, conn connectors.Connector, assignments []store.Assignment, result *DeployResult) {
	for _, a := range assignments {
		if a.DesiredState != store.StatePresent {
			continue
		}

		key, err := s.keys.Get(ctx, subject.TenantID, a.KeyID)
		if err != nil || !key.HasPrivateKey {
			continue
		}

		privateKey, err := s.keySvc.PrivateKeyFor(ctx, subject.TenantID, a.KeyID)
		if err != nil {
			result.FailedKeys = append(result.FailedKeys, key.Fingerprint)
			continue
		}

		verifyErr := conn.Verify(ctx, req, privateKey)
		vault.Zero(privateKey)

		if verifyErr != nil {
			result.FailedKeys = append(result.FailedKeys, key.Fingerprint)
			if err := s.assignments.RecordDeployment(ctx, a.ID, store.StateError, verifyErr.Error()); err != nil {
				s.log.Warn("recording verification failure", "assignment", a.ID, "error", err)
			}
			continue
		}

		result.VerifiedKeys = append(result.VerifiedKeys, key.Fingerprint)
		if err := s.assignments.RecordAuthVerified(ctx, a.ID); err != nil {
			s.log.Warn("recording verification", "assignment", a.ID, "error", err)
		}

		// A key that has been deployed and has proven it can authenticate is,
		// by any useful definition, active. Promoting here rather than at
		// creation means "active" always denotes a key that actually works
		// somewhere, which is what makes the dashboard count meaningful.
		if key.Status == store.KeyStatusPending || key.Status == store.KeyStatusStaged {
			if _, err := s.keys.SetStatus(ctx, subject.TenantID, key.ID, store.KeyStatusActive); err != nil {
				s.log.Warn("promoting key to active", "key", key.ID, "error", err)
				continue
			}
			result.PromotedKeys = append(result.PromotedKeys, key.Fingerprint)
		}
	}
}

// Rollback restores a snapshot, returning a target to a previous state.
func (s *DeployService) Rollback(ctx context.Context, subject *authz.Subject, snapshotID uuid.UUID) (*DeployResult, error) {
	if err := subject.RequireFresh(authz.PermRollback, MFAWindow); err != nil {
		return nil, err
	}

	snap, err := s.snapshots.Get(ctx, subject.TenantID, snapshotID)
	if err != nil {
		return nil, err
	}
	if snap.PrincipalID == nil {
		return nil, fmt.Errorf("service: snapshot %s is not bound to a principal and cannot be restored", snapshotID)
	}

	target, principal, cred, conn, err := s.resolve(ctx, subject, snap.TargetID, *snap.PrincipalID)
	if err != nil {
		return nil, err
	}
	defer vault.Zero(cred.PrivateKey)

	if !conn.Capabilities().CanRestore {
		return nil, fmt.Errorf("service: the %s connector cannot restore snapshots", conn.Kind())
	}

	req := connectors.Request{Target: target, Principal: principal, Credential: cred}

	// Snapshot the current state first: a rollback is itself a change, and
	// rolling back a rollback has to be possible.
	if pre, err := conn.Snapshot(ctx, req); err == nil {
		if _, err := s.snapshots.Create(ctx, &store.Snapshot{
			TenantID:    subject.TenantID,
			TargetID:    snap.TargetID,
			PrincipalID: snap.PrincipalID,
			Kind:        pre.Kind,
			RawContent:  pre.Content,
			Checksum:    pre.Checksum,
			KeyCount:    pre.KeyCount,
			Existed:     pre.Existed,
		}); err != nil {
			s.log.Warn("capturing pre-rollback snapshot", "target", snap.TargetID, "error", err)
		}
	}

	if err := conn.Restore(ctx, req, &connectors.Snapshot{
		Kind:     snap.Kind,
		Content:  snap.RawContent,
		Checksum: snap.Checksum,
		KeyCount: snap.KeyCount,
		Existed:  snap.Existed,
	}); err != nil {
		return nil, fmt.Errorf("service: restoring %s: %w", target.Name, err)
	}

	s.log2(ctx, subject, audit.Event{
		Action:       audit.ActionRollback,
		ResourceType: "target",
		ResourceID:   &snap.TargetID,
		ResourceName: target.Name,
		Detail: map[string]any{
			"snapshot_id": snapshotID.String(),
			"checksum":    snap.Checksum,
			"principal":   principal.Username,
		},
	})

	// Observed state is no longer known: the reconciler will re-derive it.
	if err := s.targets.SetDrift(ctx, subject.TenantID, snap.TargetID, store.DriftUnknown); err != nil {
		s.log.Warn("resetting drift state", "target", snap.TargetID, "error", err)
	}

	return &DeployResult{
		TargetID:    snap.TargetID,
		TargetName:  target.Name,
		PrincipalID: *snap.PrincipalID,
		Username:    principal.Username,
		Changed:     true,
		KeyCount:    snap.KeyCount,
		SnapshotID:  &snapshotID,
	}, nil
}

// Probe checks a target's reachability and pins its host key on first contact.
func (s *DeployService) Probe(ctx context.Context, subject *authz.Subject, targetID uuid.UUID) (*connectors.ProbeResult, error) {
	if err := subject.Require(authz.PermTargetRead); err != nil {
		return nil, err
	}

	target, err := s.targets.Get(ctx, subject.TenantID, targetID)
	if err != nil {
		return nil, err
	}

	principals, err := s.targets.ListPrincipals(ctx, targetID)
	if err != nil {
		return nil, err
	}
	if len(principals) == 0 {
		return nil, fmt.Errorf("service: target %s has no managed accounts to probe", target.Name)
	}

	ct, cp, cred, conn, err := s.resolve(ctx, subject, targetID, principals[0].ID)
	if err != nil {
		return nil, err
	}
	defer vault.Zero(cred.PrivateKey)

	res, probeErr := conn.Probe(ctx, connectors.Request{Target: ct, Principal: cp, Credential: cred})

	health, message := store.HealthUnreachable, ""
	if probeErr != nil {
		message = probeErr.Error()
	} else if res != nil && res.Reachable {
		health, message = store.HealthHealthy, res.Message
	}
	if err := s.targets.SetHealth(ctx, subject.TenantID, targetID, health, message); err != nil {
		s.log.Warn("recording target health", "target", targetID, "error", err)
	}

	// Pin the host key the first time it is seen, so every later connection is
	// verified against it.
	if probeErr == nil && res != nil && res.HostKeyIsNew && res.HostKeyPin != "" && target.HostKeyPin == "" {
		if err := s.targets.SetHostKeyPin(ctx, subject.TenantID, targetID, res.HostKeyPin); err != nil {
			s.log.Warn("recording host key pin", "target", targetID, "error", err)
		}
	}

	return res, probeErr
}

// resolve loads everything needed to talk to a target.
func (s *DeployService) resolve(ctx context.Context, subject *authz.Subject, targetID, principalID uuid.UUID) (*connectors.Target, *connectors.Principal, *connectors.Credential, connectors.Connector, error) {
	target, err := s.targets.Get(ctx, subject.TenantID, targetID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if !target.Enabled {
		return nil, nil, nil, nil, fmt.Errorf("service: target %s is disabled", target.Name)
	}

	principal, err := s.targets.GetPrincipal(ctx, principalID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if principal.TargetID != targetID {
		return nil, nil, nil, nil, fmt.Errorf("service: principal %s does not belong to target %s", principalID, target.Name)
	}

	conn, err := s.registry.Get(target.Connector)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cred, err := s.credential(ctx, subject.TenantID, target)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return toConnectorTarget(target), toConnectorPrincipal(principal), cred, conn, nil
}

// credential decrypts the access credential for a target.
func (s *DeployService) credential(ctx context.Context, tenantID uuid.UUID, target *store.Target) (*connectors.Credential, error) {
	if target.CredentialID == nil {
		return nil, fmt.Errorf("service: target %s has no credential; SKM cannot reach it", target.Name)
	}

	meta, err := s.credentials.Get(ctx, tenantID, *target.CredentialID)
	if err != nil {
		return nil, err
	}

	out := &connectors.Credential{Kind: meta.Kind, Username: meta.Username}

	// A credential may reference a managed key rather than storing its own
	// secret, which is how an install moves off passwords onto managed keys.
	if meta.KeyID != nil {
		privateKey, err := s.keySvc.PrivateKeyFor(ctx, tenantID, *meta.KeyID)
		if err != nil {
			return nil, fmt.Errorf("service: loading the key backing credential %q: %w", meta.Name, err)
		}
		out.PrivateKey = privateKey
		return out, nil
	}

	if !meta.HasSecret {
		return nil, fmt.Errorf("service: credential %q holds no secret", meta.Name)
	}

	sealed, err := s.credentials.LoadSecret(ctx, tenantID, meta.ID)
	if err != nil {
		return nil, err
	}
	plaintext, err := s.vault.Decrypt(sealed, []byte(meta.ID.String()))
	if err != nil {
		return nil, fmt.Errorf("service: decrypting credential %q: %w", meta.Name, err)
	}

	switch meta.Kind {
	case store.CredSSHKey:
		out.PrivateKey = plaintext
	case store.CredAPIToken:
		out.Token = string(plaintext)
		vault.Zero(plaintext)
	default:
		out.Password = string(plaintext)
		vault.Zero(plaintext)
	}
	return out, nil
}

// desiredKeys builds the connector's desired set from stored assignments.
func (s *DeployService) desiredKeys(ctx context.Context, tenantID, principalID uuid.UUID) ([]connectors.DesiredKey, []store.Assignment, error) {
	assignments, err := s.assignments.ForPrincipal(ctx, tenantID, principalID)
	if err != nil {
		return nil, nil, err
	}

	var desired []connectors.DesiredKey
	var active []store.Assignment

	for _, a := range assignments {
		if a.DesiredState != store.StatePresent {
			continue
		}

		key, err := s.keys.Get(ctx, tenantID, a.KeyID)
		if err != nil {
			return nil, nil, err
		}
		// Revoked and compromised keys are never deployed, whatever the
		// assignment says.
		switch key.Status {
		case store.KeyStatusRevoked, store.KeyStatusCompromised, store.KeyStatusDestroyed:
			continue
		}

		desired = append(desired, connectors.DesiredKey{
			PublicLine:  key.PublicKey,
			Fingerprint: key.Fingerprint,
			Options:     a.Options,
			Comment:     key.Comment,
		})
		active = append(active, a)
	}

	return desired, active, nil
}

// managedFingerprints lists every fingerprint SKM knows about, so pruning can
// distinguish its own keys from ones an operator added by hand.
func (s *DeployService) managedFingerprints(ctx context.Context, tenantID uuid.UUID) []string {
	// Paged rather than capped. This set decides which keys pruning is allowed
	// to remove: a key missing from it is treated as one SKM did not deploy and
	// is left alone. A silent cap here would therefore not fail loudly — it
	// would quietly stop pruning the keys past the cap, which is exactly the
	// kind of bug that is only noticed long after it matters.
	const page = 500

	var out []string
	for offset := 0; ; offset += page {
		batch, err := s.keys.List(ctx, store.KeyFilter{
			TenantID: tenantID, Limit: page, Offset: offset,
		})
		if err != nil {
			s.log.Warn("listing managed fingerprints", "error", err)
			return nil
		}
		for _, k := range batch {
			out = append(out, k.Fingerprint)
		}
		if len(batch) < page {
			return out
		}
	}
}

func (s *DeployService) recordFailure(ctx context.Context, assignments []store.Assignment, cause error) {
	for _, a := range assignments {
		if err := s.assignments.RecordDeployment(ctx, a.ID, store.StateError, cause.Error()); err != nil {
			s.log.Warn("recording deployment failure", "assignment", a.ID, "error", err)
		}
	}
}

func (s *DeployService) auditDeploy(ctx context.Context, subject *authz.Subject, target *connectors.Target, principal *connectors.Principal, result *DeployResult, cause error) {
	outcome := audit.OutcomeSuccess
	detail := map[string]any{
		"principal": principal.Username,
		"changed":   result.Changed,
		"added":     result.Added,
		"removed":   result.Removed,
		"dry_run":   result.DryRun,
		"key_count": result.KeyCount,
	}
	if len(result.VerifiedKeys) > 0 {
		detail["verified"] = result.VerifiedKeys
	}
	if len(result.FailedKeys) > 0 {
		detail["verification_failed"] = result.FailedKeys
	}
	if cause != nil {
		outcome = audit.OutcomeFailure
		detail["error"] = cause.Error()
	}

	s.log2(ctx, subject, audit.Event{
		Action:       audit.ActionKeyDeploy,
		ResourceType: "target",
		ResourceID:   &target.ID,
		ResourceName: target.Name,
		Outcome:      outcome,
		Detail:       detail,
	})
}

func (s *DeployService) log2(ctx context.Context, subject *authz.Subject, ev audit.Event) {
	ev.TenantID = subject.TenantID
	ev.ActorType = audit.ActorUser
	ev.ActorID = &subject.UserID
	ev.ActorName = subject.Username
	if _, err := s.audit.Log(ctx, ev); err != nil {
		s.log.Error("writing audit event", "action", ev.Action, "error", err)
	}
}

func toConnectorTarget(t *store.Target) *connectors.Target {
	return &connectors.Target{
		ID:         t.ID,
		Name:       t.Name,
		Kind:       t.Kind,
		Connector:  t.Connector,
		Address:    t.Address,
		Port:       t.Port,
		Config:     t.Config,
		HostKeyPin: t.HostKeyPin,
		Tags:       t.Tags,
	}
}

func toConnectorPrincipal(p *store.Principal) *connectors.Principal {
	return &connectors.Principal{
		ID:                 p.ID,
		Username:           p.Username,
		AuthorizedKeysPath: p.AuthorizedKeysPath,
		UseSudo:            p.UseSudo,
	}
}

// TargetCapabilities reports what the connector behind a target can do.
//
// The rotation engine needs this before it plans: on a platform that holds one
// key per login, add-before-remove is not a safer sequence, it is an impossible
// one, and discovering that at apply time means discovering it halfway through
// a fleet.
func (s *DeployService) TargetCapabilities(ctx context.Context, tenantID, targetID uuid.UUID) (connectors.Capabilities, error) {
	target, err := s.targets.Get(ctx, tenantID, targetID)
	if err != nil {
		return connectors.Capabilities{}, err
	}
	connector, err := s.registry.Get(target.Connector)
	if err != nil {
		return connectors.Capabilities{}, err
	}

	if aware, ok := connector.(interface {
		TargetCapabilities(*connectors.Target) connectors.Capabilities
	}); ok {
		return aware.TargetCapabilities(&connectors.Target{
			ID: target.ID, Name: target.Name, Kind: target.Kind,
			Connector: target.Connector, Address: target.Address, Port: target.Port,
			Config: target.Config, HostKeyPin: target.HostKeyPin, Tags: target.Tags,
		}), nil
	}
	return connector.Capabilities(), nil
}
