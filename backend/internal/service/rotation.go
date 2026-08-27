package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/events"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

// RotationService drives the add-before-remove state machine.
//
// Every transition is a database write followed by an enqueued job, never an
// in-memory step. That is what makes a rotation survive the process being
// killed halfway through it: whatever state the rotation reached is on disk,
// and a worker on any instance can pick it up from there.
//
// The invariant the whole design protects: an old key is never removed from a
// target until a *new, independent* SSH connection has authenticated with the
// new key on that same target. Presence of a key in a file proves nothing.
type RotationService struct {
	rotations   *store.Rotations
	keys        *store.Keys
	targets     *store.Targets
	assignments *store.Assignments
	changesets  *store.Changesets
	consumers   *store.Consumers
	users       *store.Users
	jobs        *store.Jobs
	keySvc      *KeyService
	deploySvc   *DeployService
	consumerSvc *ConsumerService
	audit       *audit.Logger
	publisher   *events.Publisher
	log         *slog.Logger
}

// RotationDeps bundles what a RotationService needs.
type RotationDeps struct {
	Rotations   *store.Rotations
	Keys        *store.Keys
	Targets     *store.Targets
	Assignments *store.Assignments
	Changesets  *store.Changesets
	Consumers   *store.Consumers
	Users       *store.Users
	Jobs        *store.Jobs
	KeyService  *KeyService
	Deploy      *DeployService
	ConsumerSvc *ConsumerService
	Audit       *audit.Logger
	Publisher   *events.Publisher
	Logger      *slog.Logger
}

// NewRotationService wires a RotationService.
func NewRotationService(d RotationDeps) *RotationService {
	return &RotationService{
		rotations: d.Rotations, keys: d.Keys, targets: d.Targets,
		assignments: d.Assignments, changesets: d.Changesets, consumers: d.Consumers,
		users: d.Users, jobs: d.Jobs, keySvc: d.KeyService, deploySvc: d.Deploy,
		consumerSvc: d.ConsumerSvc, audit: d.Audit, publisher: d.Publisher, log: d.Logger,
	}
}

// PlanRequest describes a rotation to be planned.
type PlanRequest struct {
	// KeyID is the key being replaced.
	KeyID uuid.UUID
	// PolicyID links the run to the schedule that produced it, when any.
	PolicyID *uuid.UUID
	Trigger  string
	// Algorithm for the successor key; defaults to the old key's algorithm.
	Algorithm string
	// SoakPeriod keeps both keys live after promotion. A nil pointer means
	// "unset, use the policy or the default"; a pointer to zero means the
	// caller genuinely wants no soak, which is a different request.
	SoakPeriod *time.Duration
	// CanaryPercent sizes the first wave.
	CanaryPercent int
	// FailureThreshold is the percentage of targets that may fail before the
	// rotation aborts rather than continuing.
	FailureThreshold int
	// ApprovalRequired holds the rotation before it stages anything.
	ApprovalRequired bool
	// DryRun plans and diffs without mutating any target.
	DryRun bool
}

// RotationPlan is what a rotation would do, before it does any of it.
type RotationPlan struct {
	Rotation *store.Rotation        `json:"rotation"`
	OldKey   *store.Key             `json:"old_key"`
	Targets  []store.RotationTarget `json:"targets"`
	// Waves reports how the target set was split, so an operator can see the
	// canary group before approving.
	Waves map[int]int `json:"waves"`
	// Consumers lists the private-key sinks that will be rebound. A rotation
	// with unlisted consumers is the classic way to break a CI pipeline.
	Consumers []store.Consumer `json:"consumers"`
	Warnings  []string         `json:"warnings,omitempty"`
}

// rotationStepPayload is what the queued job carries.
type rotationStepPayload struct {
	RotationID uuid.UUID `json:"rotation_id"`
	UserID     uuid.UUID `json:"user_id"`
}

// Plan resolves a rotation's target set and splits it into waves without
// changing anything.
func (s *RotationService) Plan(ctx context.Context, subject *authz.Subject, req PlanRequest) (*RotationPlan, error) {
	if err := subject.Require(authz.PermRotationWrite); err != nil {
		return nil, err
	}

	oldKey, err := s.keys.Get(ctx, subject.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	if !subject.InScope(oldKey.Tags) {
		return nil, fmt.Errorf("%w: key %s", authz.ErrOutOfScope, oldKey.Name)
	}
	if oldKey.KeyClass == store.KeyClassBreakGlass {
		return nil, badRotation("break-glass keys are excluded from rotation; they are the path back in when a rotation goes wrong")
	}
	switch oldKey.Status {
	case store.KeyStatusRetired, store.KeyStatusDestroyed:
		return nil, badRotation("key %q is already %s", oldKey.Name, oldKey.Status)
	}

	// The target set is every principal the old key is currently assigned to.
	// Rotating a key means replacing it everywhere it is used; anything less
	// leaves the old key live somewhere and defeats the point.
	current, err := s.assignments.List(ctx, store.AssignmentFilter{
		TenantID: subject.TenantID, KeyID: &req.KeyID,
		DesiredState: store.StatePresent, Limit: 1000,
	})
	if err != nil {
		return nil, err
	}

	plan := &RotationPlan{OldKey: oldKey, Waves: map[int]int{}}
	if len(current) == 0 {
		plan.Warnings = append(plan.Warnings,
			"this key is not assigned to any target; the rotation will generate a successor but deploy nothing")
	}

	rotation, err := s.rotations.CreateRotation(ctx, &store.Rotation{
		TenantID:     subject.TenantID,
		PolicyID:     req.PolicyID,
		OldKeyID:     &req.KeyID,
		State:        store.RotationPlanned,
		Trigger:      orTrigger(req.Trigger),
		DryRun:       req.DryRun,
		TargetsTotal: len(current),
		CreatedBy:    &subject.UserID,
	})
	if err != nil {
		return nil, err
	}

	if req.ApprovalRequired {
		rotation, err = s.rotations.SetRotationState(ctx, rotation.ID,
			[]string{store.RotationPlanned}, store.RotationAwaiting, "")
		if err != nil {
			return nil, err
		}
	}

	// Wave 0 is the canary. Targets explicitly flagged as canaries go first;
	// otherwise the percentage decides, rounded up so a non-zero percentage
	// always yields at least one canary.
	canaries := s.canarySet(ctx, subject.TenantID, current, req.CanaryPercent)

	for _, a := range current {
		wave := 1
		if canaries[a.TargetID] {
			wave = 0
		}

		if err := s.rotations.AddRotationTarget(ctx, &store.RotationTarget{
			RotationID:  rotation.ID,
			TargetID:    a.TargetID,
			PrincipalID: a.PrincipalID,
			Wave:        wave,
			State:       store.RTPending,
		}); err != nil {
			return nil, err
		}
		plan.Waves[wave]++
	}

	// With no canary group everything is one wave; renumber so the machine
	// does not walk an empty wave 0.
	if plan.Waves[0] == 0 && plan.Waves[1] > 0 {
		if _, err := s.rotations.WaveTargets(ctx, rotation.ID, 1, nil); err == nil {
			if err := s.collapseWaves(ctx, rotation.ID); err != nil {
				return nil, err
			}
			plan.Waves = map[int]int{0: len(current)}
		}
	}

	targets, err := s.rotations.ListRotationTargets(ctx, rotation.ID)
	if err != nil {
		return nil, err
	}
	plan.Targets = targets

	sinks, err := s.consumers.List(ctx, subject.TenantID, &req.KeyID)
	if err != nil {
		return nil, err
	}
	plan.Consumers = sinks

	// Warn about anything the machine cannot verify, since a target without
	// the authentication gate is one the rotation has to trust rather than
	// prove.
	plan.Warnings = append(plan.Warnings, s.capabilityWarnings(ctx, subject.TenantID, targets)...)

	plan.Rotation = rotation

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionKeyRotate,
		ResourceType: "rotation",
		ResourceID:   &rotation.ID,
		ResourceName: oldKey.Name,
		Outcome:      audit.OutcomeSuccess,
		Detail: map[string]any{
			"phase": "planned", "targets": len(current), "dry_run": req.DryRun,
			"canary": plan.Waves[0], "trigger": rotation.Trigger,
		},
	})

	// Parameters the machine needs later are carried on the rotation's policy
	// when there is one, and defaulted from the request when there is not.
	s.remember(rotation.ID, rotationParams{
		Algorithm:        orString(req.Algorithm, oldKey.Algorithm),
		SoakPeriod:       req.SoakPeriod,
		FailureThreshold: req.FailureThreshold,
	})

	return plan, nil
}

// collapseWaves moves every target into wave 0 when no canary was selected.
func (s *RotationService) collapseWaves(ctx context.Context, rotationID uuid.UUID) error {
	targets, err := s.rotations.ListRotationTargets(ctx, rotationID)
	if err != nil {
		return err
	}
	for _, t := range targets {
		t.Wave = 0
		if err := s.rotations.AddRotationTarget(ctx, &t); err != nil {
			return err
		}
	}
	return nil
}

// canarySet picks the first wave, preferring targets explicitly marked as
// canaries over an arbitrary slice of the fleet.
func (s *RotationService) canarySet(ctx context.Context, tenantID uuid.UUID, all []store.AssignmentDetail, percent int) map[uuid.UUID]bool {
	out := map[uuid.UUID]bool{}
	if len(all) == 0 {
		return out
	}

	for _, a := range all {
		t, err := s.targets.Get(ctx, tenantID, a.TargetID)
		if err == nil && t.IsCanary {
			out[a.TargetID] = true
		}
	}
	if len(out) > 0 {
		return out
	}

	if percent <= 0 {
		return out
	}
	// Round up: a 10% canary over three hosts should still be one host, not
	// zero, or the canary wave silently does nothing.
	want := (len(all)*percent + 99) / 100
	if want >= len(all) {
		return out
	}

	for i := 0; i < want; i++ {
		out[all[i].TargetID] = true
	}
	return out
}

// capabilityWarnings reports targets whose connector cannot prove a key works.
func (s *RotationService) capabilityWarnings(ctx context.Context, tenantID uuid.UUID, targets []store.RotationTarget) []string {
	var out []string
	seen := map[uuid.UUID]bool{}

	for _, rt := range targets {
		if seen[rt.TargetID] {
			continue
		}
		seen[rt.TargetID] = true

		t, err := s.targets.Get(ctx, tenantID, rt.TargetID)
		if err != nil {
			continue
		}
		conn, err := s.deploySvc.registry.Get(t.Connector)
		if err != nil {
			out = append(out, fmt.Sprintf("%s uses connector %q, which is not registered", t.Name, t.Connector))
			continue
		}
		if !conn.Capabilities().CanVerify {
			out = append(out, fmt.Sprintf(
				"%s uses the %s connector, which cannot authenticate to prove the new key works; "+
					"the old key will be retired on presence alone", t.Name, t.Connector))
		}
	}
	return out
}

// Start puts a planned rotation into the queue.
func (s *RotationService) Start(ctx context.Context, subject *authz.Subject, rotationID uuid.UUID) (*store.Rotation, error) {
	if err := subject.Require(authz.PermRotationExecute); err != nil {
		return nil, err
	}

	r, err := s.rotations.GetRotation(ctx, subject.TenantID, rotationID)
	if err != nil {
		return nil, err
	}
	switch r.State {
	case store.RotationPlanned:
	case store.RotationAwaiting:
		return nil, badRotation("rotation %s is awaiting approval", rotationID)
	default:
		if store.RotationFinished(r.State) {
			return nil, badRotation("rotation %s already finished as %q", rotationID, r.State)
		}
		return nil, badRotation("rotation %s is already running (%s)", rotationID, r.State)
	}

	if err := s.enqueueStep(ctx, r, subject.UserID, 0); err != nil {
		return nil, err
	}

	s.publisher.Emit(ctx, subject.TenantID, events.TypeRotationStarted, "rotation",
		&rotationID, "", map[string]any{"targets": r.TargetsTotal, "trigger": r.Trigger})

	return r, nil
}

// Approve unblocks a rotation held for sign-off.
func (s *RotationService) Approve(ctx context.Context, subject *authz.Subject, rotationID uuid.UUID) (*store.Rotation, error) {
	if err := subject.Require(authz.PermRotationApprove); err != nil {
		return nil, err
	}

	r, err := s.rotations.Approve(ctx, subject.TenantID, rotationID, subject.UserID)
	if err != nil {
		return nil, err
	}

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionKeyRotate,
		ResourceType: "rotation",
		ResourceID:   &rotationID,
		Outcome:      audit.OutcomeSuccess,
		Detail:       map[string]any{"phase": "approved"},
	})

	if err := s.enqueueStep(ctx, r, subject.UserID, 0); err != nil {
		return nil, err
	}
	return r, nil
}

// Abort halts a rotation. Nothing already deployed is removed: leaving the new
// key alongside the old is the safe direction to fail in, and a rollback is a
// separate, explicit action.
func (s *RotationService) Abort(ctx context.Context, subject *authz.Subject, rotationID uuid.UUID, reason string) (*store.Rotation, error) {
	if err := subject.Require(authz.PermRotationAbort); err != nil {
		return nil, err
	}

	r, err := s.rotations.GetRotation(ctx, subject.TenantID, rotationID)
	if err != nil {
		return nil, err
	}
	if store.RotationFinished(r.State) {
		return nil, badRotation("rotation %s already finished as %q", rotationID, r.State)
	}

	updated, err := s.rotations.SetRotationState(ctx, rotationID, nil, store.RotationAborted,
		orString(reason, "aborted by an operator"))
	if err != nil {
		return nil, err
	}

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionKeyRotate,
		ResourceType: "rotation",
		ResourceID:   &rotationID,
		Outcome:      audit.OutcomeSuccess,
		Detail:       map[string]any{"phase": "aborted", "reason": reason},
	})
	s.publisher.Emit(ctx, subject.TenantID, events.TypeRotationAborted, "rotation",
		&rotationID, "", map[string]any{"reason": reason})

	return updated, nil
}

// Step advances a rotation by exactly one transition.
//
// Returning requeue=true means the machine has more to do; the job handler
// enqueues the next step. Splitting it this way keeps every transition
// individually durable and individually retryable.
func (s *RotationService) Step(ctx context.Context, rotationID, userID uuid.UUID, logf func(string, map[string]any)) (requeue bool, delay time.Duration, err error) {
	subject, err := s.systemSubject(ctx, userID)
	if err != nil {
		return false, 0, err
	}

	r, err := s.rotations.GetRotation(ctx, subject.TenantID, rotationID)
	if err != nil {
		return false, 0, err
	}
	if store.RotationFinished(r.State) {
		return false, 0, nil
	}

	logf(fmt.Sprintf("rotation is in state %q (wave %d)", r.State, r.Wave), map[string]any{
		"state": r.State, "wave": r.Wave,
	})

	switch r.State {
	case store.RotationAwaiting:
		// Nothing to do until a human approves; the approval enqueues a step.
		return false, 0, nil

	case store.RotationPlanned:
		return s.stepPlanned(ctx, subject, r, logf)

	case store.RotationStaging:
		return s.stepStaging(ctx, subject, r, logf)

	case store.RotationVerifying:
		return s.stepVerifying(ctx, subject, r, logf)

	case store.RotationStaged, store.RotationVerified:
		return s.stepPromote(ctx, subject, r, logf)

	case store.RotationPromoting:
		return s.stepSoak(ctx, subject, r, logf)

	case store.RotationSoaking:
		return s.stepSoakWait(ctx, subject, r, logf)

	case store.RotationRetiring:
		return s.stepRetire(ctx, subject, r, logf)

	default:
		return false, 0, fmt.Errorf("service: rotation %s is in unexpected state %q", rotationID, r.State)
	}
}

// stepPlanned generates the successor key and opens the changeset.
func (s *RotationService) stepPlanned(ctx context.Context, subject *authz.Subject, r *store.Rotation, logf func(string, map[string]any)) (bool, time.Duration, error) {
	if r.NewKeyID != nil {
		// A retry after a crash between generating the key and advancing the
		// state: do not generate a second one.
		if _, err := s.rotations.SetRotationState(ctx, r.ID, []string{store.RotationPlanned}, store.RotationStaging, ""); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	}

	oldKey, err := s.keys.Get(ctx, subject.TenantID, *r.OldKeyID)
	if err != nil {
		return false, 0, err
	}

	params := s.recall(r.ID)

	changeset, err := s.changesets.Create(ctx, &store.Changeset{
		TenantID:  subject.TenantID,
		Kind:      store.ChangesetRotation,
		Summary:   fmt.Sprintf("rotation of key %q", oldKey.Name),
		CreatedBy: &subject.UserID,
	})
	if err != nil {
		return false, 0, err
	}

	newKey, err := s.keySvc.Generate(ctx, subject, GenerateRequest{
		Name:        successorName(oldKey.Name, oldKey.Generation+1),
		Description: fmt.Sprintf("generation %d successor to %s", oldKey.Generation+1, oldKey.Name),
		Algorithm:   orString(params.Algorithm, oldKey.Algorithm),
		Comment:     oldKey.Comment,
		Tags:        oldKey.Tags,
		KeyClass:    oldKey.KeyClass,
		ParentKeyID: &oldKey.ID,
		Generation:  oldKey.Generation + 1,
	})
	if err != nil {
		return false, 0, err
	}

	logf(fmt.Sprintf("generated %s as generation %d", newKey.Fingerprint, newKey.Generation), map[string]any{
		"key": newKey.ID.String(), "fingerprint": newKey.Fingerprint,
	})

	total, err := s.rotations.ListRotationTargets(ctx, r.ID)
	if err != nil {
		return false, 0, err
	}
	if err := s.rotations.SetRotationKeys(ctx, r.ID, &newKey.ID, &changeset.ID, len(total)); err != nil {
		return false, 0, err
	}

	if r.DryRun {
		// A dry run stops here: it has shown the plan, the wave split, and the
		// successor key without touching a single target.
		if _, err := s.rotations.SetRotationState(ctx, r.ID, nil, store.RotationCompleted, "dry run"); err != nil {
			return false, 0, err
		}
		return false, 0, nil
	}

	if _, err := s.rotations.SetRotationState(ctx, r.ID, []string{store.RotationPlanned}, store.RotationStaging, ""); err != nil {
		return false, 0, err
	}
	return true, 0, nil
}

// stepStaging deploys the new key alongside the old across the current wave.
func (s *RotationService) stepStaging(ctx context.Context, subject *authz.Subject, r *store.Rotation, logf func(string, map[string]any)) (bool, time.Duration, error) {
	if r.NewKeyID == nil {
		return false, 0, fmt.Errorf("service: rotation %s reached staging without a successor key", r.ID)
	}

	pending, err := s.rotations.WaveTargets(ctx, r.ID, r.Wave, []string{store.RTPending})
	if err != nil {
		return false, 0, err
	}

	for _, rt := range pending {
		if err := s.stageOne(ctx, subject, r, rt, logf); err != nil {
			logf(fmt.Sprintf("staging failed on %s (%s): %v", rt.TargetName, rt.Username, err), map[string]any{
				"target": rt.TargetName, "error": err.Error(),
			})
			if e := s.rotations.SetRotationTargetState(ctx, r.ID, rt.TargetID, rt.PrincipalID, store.RTFailed, err.Error()); e != nil {
				return false, 0, e
			}
			continue
		}
		logf(fmt.Sprintf("staged the new key on %s (%s)", rt.TargetName, rt.Username), nil)
		if err := s.rotations.SetRotationTargetState(ctx, r.ID, rt.TargetID, rt.PrincipalID, store.RTStaged, ""); err != nil {
			return false, 0, err
		}
	}

	if abort, err := s.abortOnThreshold(ctx, subject, r, "staging"); err != nil || abort {
		return false, 0, err
	}

	if _, err := s.rotations.SetRotationState(ctx, r.ID, []string{store.RotationStaging}, store.RotationVerifying, ""); err != nil {
		return false, 0, err
	}
	s.publisher.Emit(ctx, subject.TenantID, events.TypeRotationStaged, "rotation", &r.ID, "",
		map[string]any{"wave": r.Wave})
	return true, 0, nil
}

// stageOne binds the new key to one principal and converges that principal
// without pruning, so both keys are live afterwards.
//
// That is the whole safety argument of add-before-remove, and it depends on the
// target being able to hold two keys at once. Where it cannot, the work is
// genuinely different and is handled by replaceOne.
func (s *RotationService) stageOne(ctx context.Context, subject *authz.Subject, r *store.Rotation, rt store.RotationTarget, logf func(string, map[string]any)) error {
	caps, err := s.deploySvc.TargetCapabilities(ctx, subject.TenantID, rt.TargetID)
	if err != nil {
		return err
	}
	if caps.SingleKey {
		return s.replaceOne(ctx, subject, r, rt, caps, logf)
	}

	// Carry the old assignment's options across: a key deployed without its
	// from= or command= restrictions is a quietly widened grant.
	options := s.optionsFor(ctx, subject.TenantID, *r.OldKeyID, rt.PrincipalID)

	if _, err := s.assignments.Upsert(ctx, &store.Assignment{
		TenantID:     subject.TenantID,
		KeyID:        *r.NewKeyID,
		TargetID:     rt.TargetID,
		PrincipalID:  rt.PrincipalID,
		Options:      options,
		DesiredState: store.StatePresent,
		CreatedBy:    &subject.UserID,
	}); err != nil {
		return err
	}

	result, err := s.deploySvc.Deploy(ctx, subject, rt.TargetID, rt.PrincipalID, DeployOptions{
		Prune:       false,
		VerifyAuth:  false,
		ChangesetID: r.ChangesetID,
	})
	if err != nil {
		return err
	}
	if len(result.Warnings) > 0 {
		logf(fmt.Sprintf("%s reported: %v", rt.TargetName, result.Warnings), nil)
	}
	return nil
}

// replaceOne rotates a principal on a platform that holds one key at a time.
//
// Arista EOS is the case that forced this: "username X ssh-key ..." overwrites
// whatever was there, so there is no instant at which both the old and the new
// key authenticate. Staging and verifying cannot be separate phases, because
// between them the old key is already gone.
//
// So the two are fused here. The old key is replaced, the new one is proved
// against a fresh connection immediately, and if that proof fails the old key
// goes straight back from the snapshot the deployment just took. The window in
// which the login is unreachable is the length of one SSH handshake, and it
// closes whichever way the handshake goes.
//
// This is worse than add-before-remove. It is also the best that is available
// on this hardware, and the engine says which one it used rather than letting
// the operator assume the safer sequence ran everywhere.
func (s *RotationService) replaceOne(ctx context.Context, subject *authz.Subject, r *store.Rotation, rt store.RotationTarget, caps connectors.Capabilities, logf func(string, map[string]any)) error {
	if !caps.CanRestore {
		return fmt.Errorf("%w: %s holds one key per login and cannot restore the previous one, "+
			"so a failed replacement would leave %q unreachable; rotate it by hand",
			ErrBadRotation, rt.TargetName, rt.Username)
	}

	logf(fmt.Sprintf("%s holds one key per login: replacing and verifying in a single step", rt.TargetName),
		map[string]any{"target": rt.TargetName, "strategy": "replace"})

	options := s.optionsFor(ctx, subject.TenantID, *r.OldKeyID, rt.PrincipalID)

	if _, err := s.assignments.Upsert(ctx, &store.Assignment{
		TenantID: subject.TenantID, KeyID: *r.NewKeyID,
		TargetID: rt.TargetID, PrincipalID: rt.PrincipalID,
		Options: options, DesiredState: store.StatePresent, CreatedBy: &subject.UserID,
	}); err != nil {
		return err
	}
	if _, err := s.assignments.Upsert(ctx, &store.Assignment{
		TenantID: subject.TenantID, KeyID: *r.OldKeyID,
		TargetID: rt.TargetID, PrincipalID: rt.PrincipalID,
		Options: options, DesiredState: store.StateAbsent, CreatedBy: &subject.UserID,
	}); err != nil {
		return err
	}

	result, err := s.deploySvc.Deploy(ctx, subject, rt.TargetID, rt.PrincipalID, DeployOptions{
		Prune:       true,
		VerifyAuth:  true,
		ChangesetID: r.ChangesetID,
	})
	if err != nil {
		if restoreErr := s.restorePrevious(ctx, subject, r, rt, options); restoreErr != nil {
			// Both failed. This is the state an operator must be paged about,
			// so it is reported in full rather than summarised.
			return fmt.Errorf("replacing the key on %s failed (%v) and restoring the previous one "+
				"also failed (%v); %q may have no working key",
				rt.TargetName, err, restoreErr, rt.Username)
		}
		logf(fmt.Sprintf("%s did not accept the new key; the previous one was put back", rt.TargetName),
			map[string]any{"target": rt.TargetName, "error": err.Error()})
		return err
	}
	if len(result.Warnings) > 0 {
		logf(fmt.Sprintf("%s reported: %v", rt.TargetName, result.Warnings), nil)
	}
	return nil
}

// restorePrevious puts the old key back after a failed replacement.
func (s *RotationService) restorePrevious(ctx context.Context, subject *authz.Subject, r *store.Rotation, rt store.RotationTarget, options []string) error {
	if _, err := s.assignments.Upsert(ctx, &store.Assignment{
		TenantID: subject.TenantID, KeyID: *r.OldKeyID,
		TargetID: rt.TargetID, PrincipalID: rt.PrincipalID,
		Options: options, DesiredState: store.StatePresent, CreatedBy: &subject.UserID,
	}); err != nil {
		return err
	}
	if _, err := s.assignments.Upsert(ctx, &store.Assignment{
		TenantID: subject.TenantID, KeyID: *r.NewKeyID,
		TargetID: rt.TargetID, PrincipalID: rt.PrincipalID,
		Options: options, DesiredState: store.StateAbsent, CreatedBy: &subject.UserID,
	}); err != nil {
		return err
	}

	_, err := s.deploySvc.Deploy(ctx, subject, rt.TargetID, rt.PrincipalID, DeployOptions{
		Prune: true, VerifyAuth: false, ChangesetID: r.ChangesetID,
	})
	return err
}

// stepVerifying proves the new key authenticates on each staged target.
//
// This is the gate. A target that cannot be authenticated to with the new key
// never has its old key removed, whatever the file on disk says.
func (s *RotationService) stepVerifying(ctx context.Context, subject *authz.Subject, r *store.Rotation, logf func(string, map[string]any)) (bool, time.Duration, error) {
	staged, err := s.rotations.WaveTargets(ctx, r.ID, r.Wave, []string{store.RTStaged})
	if err != nil {
		return false, 0, err
	}

	privateKey, err := s.keySvc.PrivateKeyFor(ctx, subject.TenantID, *r.NewKeyID)
	if err != nil {
		return false, 0, err
	}
	defer vault.Zero(privateKey)

	for _, rt := range staged {
		err := s.verifyOne(ctx, subject, rt, privateKey)
		if err != nil {
			logf(fmt.Sprintf("the new key does not authenticate on %s (%s): %v", rt.TargetName, rt.Username, err), map[string]any{
				"target": rt.TargetName, "error": err.Error(),
			})
			s.publisher.Emit(ctx, subject.TenantID, events.TypeVerifyFailed, "target",
				&rt.TargetID, rt.TargetName, map[string]any{"rotation": r.ID.String(), "error": err.Error()})

			if e := s.rotations.SetRotationTargetState(ctx, r.ID, rt.TargetID, rt.PrincipalID, store.RTFailed, err.Error()); e != nil {
				return false, 0, e
			}
			continue
		}

		logf(fmt.Sprintf("the new key authenticated on %s (%s)", rt.TargetName, rt.Username), nil)
		if err := s.rotations.SetRotationTargetState(ctx, r.ID, rt.TargetID, rt.PrincipalID, store.RTVerified, ""); err != nil {
			return false, 0, err
		}
	}

	if abort, err := s.abortOnThreshold(ctx, subject, r, "verification"); err != nil || abort {
		return false, 0, err
	}

	// More waves to run? Move to the next one rather than promoting.
	maxWave, err := s.rotations.MaxWave(ctx, r.ID)
	if err != nil {
		return false, 0, err
	}
	if r.Wave < maxWave {
		if err := s.rotations.SetWave(ctx, r.ID, r.Wave+1); err != nil {
			return false, 0, err
		}
		if _, err := s.rotations.SetRotationState(ctx, r.ID, []string{store.RotationVerifying}, store.RotationStaging, ""); err != nil {
			return false, 0, err
		}
		logf(fmt.Sprintf("canary wave %d verified; proceeding to wave %d", r.Wave, r.Wave+1), nil)
		return true, 0, nil
	}

	if _, err := s.rotations.SetRotationState(ctx, r.ID, []string{store.RotationVerifying}, store.RotationVerified, ""); err != nil {
		return false, 0, err
	}
	s.publisher.Emit(ctx, subject.TenantID, events.TypeRotationVerified, "rotation", &r.ID, "", nil)
	return true, 0, nil
}

// verifyOne opens a fresh connection with the new private key.
func (s *RotationService) verifyOne(ctx context.Context, subject *authz.Subject, rt store.RotationTarget, privateKey []byte) error {
	target, principal, cred, conn, err := s.deploySvc.resolve(ctx, subject, rt.TargetID, rt.PrincipalID)
	if err != nil {
		return err
	}
	defer vault.Zero(cred.PrivateKey)

	if !conn.Capabilities().CanVerify {
		// The connector cannot authenticate. Fall back to confirming presence,
		// and say so, rather than pretending the gate was passed.
		if !conn.Capabilities().CanList {
			return nil
		}
		entries, err := conn.List(ctx, connectors.Request{Target: target, Principal: principal, Credential: cred})
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Fingerprint != "" {
				return nil
			}
		}
		return fmt.Errorf("service: the new key is not present on %s", target.Name)
	}

	return conn.Verify(ctx, connectors.Request{
		Target: target, Principal: principal, Credential: cred,
	}, privateKey)
}

// stepPromote makes the new key active, marks the old one retiring, and hands
// the new private key to every consumer *before* anything is removed.
func (s *RotationService) stepPromote(ctx context.Context, subject *authz.Subject, r *store.Rotation, logf func(string, map[string]any)) (bool, time.Duration, error) {
	if _, err := s.rotations.SetRotationState(ctx, r.ID,
		[]string{store.RotationStaged, store.RotationVerified}, store.RotationPromoting, ""); err != nil {
		return false, 0, err
	}

	if _, err := s.keys.SetStatus(ctx, subject.TenantID, *r.NewKeyID, store.KeyStatusActive); err != nil {
		return false, 0, err
	}
	if _, err := s.keys.SetStatus(ctx, subject.TenantID, *r.OldKeyID, store.KeyStatusRetiring); err != nil {
		return false, 0, err
	}
	logf("promoted the new key to active and marked the old one retiring", nil)

	// Consumers hold the *private* key. They must be updated now, while both
	// keys still work — after retirement is too late, and that is exactly the
	// window most tooling gets wrong.
	sinks, err := s.consumers.List(ctx, subject.TenantID, r.OldKeyID)
	if err != nil {
		return false, 0, err
	}
	for _, c := range sinks {
		if !c.Enabled {
			logf(fmt.Sprintf("consumer %q is disabled; skipping it", c.Name), nil)
			continue
		}
		if err := s.consumerSvc.Rebind(ctx, subject, c.ID, *r.NewKeyID); err != nil {
			logf(fmt.Sprintf("consumer %q could not be updated: %v", c.Name, err), map[string]any{
				"consumer": c.Name, "error": err.Error(),
			})
			// A consumer that cannot take the new key means retiring the old
			// one would break it. Abort rather than proceed.
			if _, e := s.rotations.SetRotationState(ctx, r.ID, nil, store.RotationFailed,
				fmt.Sprintf("consumer %q could not be updated: %v", c.Name, err)); e != nil {
				return false, 0, e
			}
			return false, 0, nil
		}
		logf(fmt.Sprintf("delivered the new private key to consumer %q", c.Name), nil)
	}

	return true, 0, nil
}

// stepSoak opens the window in which both keys stay live.
func (s *RotationService) stepSoak(ctx context.Context, subject *authz.Subject, r *store.Rotation, logf func(string, map[string]any)) (bool, time.Duration, error) {
	soak := s.soakPeriod(ctx, subject.TenantID, r)
	until := time.Now().Add(soak)

	if err := s.rotations.SetSoakUntil(ctx, r.ID, until); err != nil {
		return false, 0, err
	}
	if _, err := s.rotations.SetRotationState(ctx, r.ID, []string{store.RotationPromoting}, store.RotationSoaking, ""); err != nil {
		return false, 0, err
	}

	logf(fmt.Sprintf("soaking until %s; both keys remain valid until then", until.Format(time.RFC3339)), map[string]any{
		"soak_until": until, "soak_seconds": int(soak.Seconds()),
	})
	s.publisher.Emit(ctx, subject.TenantID, events.TypeRotationSoaking, "rotation", &r.ID, "",
		map[string]any{"soak_until": until})

	// Wake up when the window closes rather than polling through it.
	return true, soak, nil
}

// stepSoakWait re-checks the clock; a worker may have picked the job up early.
func (s *RotationService) stepSoakWait(ctx context.Context, subject *authz.Subject, r *store.Rotation, logf func(string, map[string]any)) (bool, time.Duration, error) {
	if r.SoakUntil != nil && time.Now().Before(*r.SoakUntil) {
		remaining := time.Until(*r.SoakUntil)
		logf(fmt.Sprintf("still soaking; %s remaining", remaining.Round(time.Second)), nil)
		return true, remaining, nil
	}

	if _, err := s.rotations.SetRotationState(ctx, r.ID, []string{store.RotationSoaking}, store.RotationRetiring, ""); err != nil {
		return false, 0, err
	}
	return true, 0, nil
}

// stepRetire removes the old key, but only from targets that proved the new one
// works.
func (s *RotationService) stepRetire(ctx context.Context, subject *authz.Subject, r *store.Rotation, logf func(string, map[string]any)) (bool, time.Duration, error) {
	all, err := s.rotations.ListRotationTargets(ctx, r.ID)
	if err != nil {
		return false, 0, err
	}

	var failed int
	for _, rt := range all {
		if rt.State != store.RTVerified {
			if rt.State == store.RTFailed {
				failed++
				logf(fmt.Sprintf("leaving both keys on %s (%s): it never verified", rt.TargetName, rt.Username), nil)
			}
			continue
		}

		if err := s.retireOne(ctx, subject, r, rt); err != nil {
			failed++
			logf(fmt.Sprintf("could not remove the old key from %s (%s): %v", rt.TargetName, rt.Username, err), map[string]any{
				"target": rt.TargetName, "error": err.Error(),
			})
			if e := s.rotations.SetRotationTargetState(ctx, r.ID, rt.TargetID, rt.PrincipalID, store.RTFailed, err.Error()); e != nil {
				return false, 0, e
			}
			continue
		}

		logf(fmt.Sprintf("removed the old key from %s (%s)", rt.TargetName, rt.Username), nil)
		if err := s.rotations.SetRotationTargetState(ctx, r.ID, rt.TargetID, rt.PrincipalID, store.RTRetired, ""); err != nil {
			return false, 0, err
		}
	}

	// The old key is only retired when it is gone everywhere. Any target still
	// holding it keeps the key in "retiring", because a key that still grants
	// access somewhere must not be reported as retired.
	finalState := store.RotationCompleted
	message := ""
	if failed > 0 {
		message = fmt.Sprintf("%d target(s) still hold the old key; it remains in the retiring state", failed)
		logf(message, nil)
	} else {
		if _, err := s.keys.SetStatus(ctx, subject.TenantID, *r.OldKeyID, store.KeyStatusRetired); err != nil {
			return false, 0, err
		}
		logf("the old key is retired; it is no longer authorized anywhere SKM manages", nil)
	}

	if _, err := s.rotations.SetRotationState(ctx, r.ID, []string{store.RotationRetiring}, finalState, message); err != nil {
		return false, 0, err
	}

	if r.ChangesetID != nil {
		if err := s.changesets.SetState(ctx, *r.ChangesetID, store.ChangesetCommitted); err != nil {
			s.log.Warn("closing rotation changeset", "changeset", *r.ChangesetID, "error", err)
		}
	}

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionKeyRotate,
		ResourceType: "rotation",
		ResourceID:   &r.ID,
		Outcome:      audit.OutcomeSuccess,
		Detail:       map[string]any{"phase": "completed", "targets_failed": failed},
	})
	s.publisher.Emit(ctx, subject.TenantID, events.TypeRotationDone, "rotation", &r.ID, "",
		map[string]any{"targets_failed": failed})

	return false, 0, nil
}

// retireOne removes the old key from one principal and confirms it is gone.
func (s *RotationService) retireOne(ctx context.Context, subject *authz.Subject, r *store.Rotation, rt store.RotationTarget) error {
	// Mark the old binding absent, then converge with pruning on. The
	// connector's own lockout guard refuses to empty the file, so even a
	// mistake here cannot lock the principal out.
	existing, err := s.assignments.List(ctx, store.AssignmentFilter{
		TenantID: subject.TenantID, KeyID: r.OldKeyID,
		TargetID: &rt.TargetID, PrincipalID: &rt.PrincipalID, Limit: 10,
	})
	if err != nil {
		return err
	}
	for _, a := range existing {
		if err := s.assignments.Delete(ctx, subject.TenantID, a.ID); err != nil {
			return err
		}
	}

	result, err := s.deploySvc.Deploy(ctx, subject, rt.TargetID, rt.PrincipalID, DeployOptions{
		Prune:       true,
		VerifyAuth:  true,
		ChangesetID: r.ChangesetID,
	})
	if err != nil {
		return err
	}

	// Confirm the new key still authenticates after the removal. Verifying
	// afterwards catches the case where pruning removed more than intended.
	if len(result.FailedKeys) > 0 {
		return fmt.Errorf("service: after removing the old key, %d key(s) no longer authenticate on %s",
			len(result.FailedKeys), rt.TargetName)
	}
	return nil
}

// abortOnThreshold ends a rotation whose failure rate exceeds what the policy
// tolerates.
func (s *RotationService) abortOnThreshold(ctx context.Context, subject *authz.Subject, r *store.Rotation, phase string) (bool, error) {
	current, err := s.rotations.GetRotation(ctx, subject.TenantID, r.ID)
	if err != nil {
		return false, err
	}
	if current.TargetsTotal == 0 || current.TargetsFailed == 0 {
		return false, nil
	}

	threshold := s.recall(r.ID).FailureThreshold
	if threshold <= 0 {
		threshold = s.policyThreshold(ctx, subject.TenantID, r)
	}

	rate := current.TargetsFailed * 100 / current.TargetsTotal
	if rate <= threshold {
		return false, nil
	}

	reason := fmt.Sprintf("%d of %d targets failed during %s (%d%%), above the %d%% threshold",
		current.TargetsFailed, current.TargetsTotal, phase, rate, threshold)

	if _, err := s.rotations.SetRotationState(ctx, r.ID, nil, store.RotationAborted, reason); err != nil {
		return false, err
	}

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionKeyRotate,
		ResourceType: "rotation",
		ResourceID:   &r.ID,
		Outcome:      audit.OutcomeFailure,
		Detail:       map[string]any{"phase": phase, "reason": reason},
	})
	s.publisher.Emit(ctx, subject.TenantID, events.TypeRotationAborted, "rotation", &r.ID, "",
		map[string]any{"reason": reason})

	return true, nil
}

func (s *RotationService) policyThreshold(ctx context.Context, tenantID uuid.UUID, r *store.Rotation) int {
	if r.PolicyID == nil {
		return 0
	}
	p, err := s.rotations.GetPolicy(ctx, tenantID, *r.PolicyID)
	if err != nil {
		return 0
	}
	return p.FailureThreshold
}

func (s *RotationService) soakPeriod(ctx context.Context, tenantID uuid.UUID, r *store.Rotation) time.Duration {
	// An explicitly requested zero is honoured: "rotate this now, no soak" is a
	// real thing to ask for, and silently parking the rotation for a day
	// instead would be the wrong kind of surprise.
	if params := s.recall(r.ID); params.SoakPeriod != nil {
		return *params.SoakPeriod
	}
	if r.PolicyID != nil {
		if p, err := s.rotations.GetPolicy(ctx, tenantID, *r.PolicyID); err == nil {
			return p.SoakPeriod()
		}
	}
	return 24 * time.Hour
}

// optionsFor reads the authorized_keys options attached to the old binding.
func (s *RotationService) optionsFor(ctx context.Context, tenantID, oldKeyID, principalID uuid.UUID) []string {
	existing, err := s.assignments.List(ctx, store.AssignmentFilter{
		TenantID: tenantID, KeyID: &oldKeyID, PrincipalID: &principalID, Limit: 1,
	})
	if err != nil || len(existing) == 0 {
		return nil
	}
	return existing[0].Options
}

// enqueueStep queues the next transition.
func (s *RotationService) enqueueStep(ctx context.Context, r *store.Rotation, userID uuid.UUID, delay time.Duration) error {
	payload, err := json.Marshal(rotationStepPayload{RotationID: r.ID, UserID: userID})
	if err != nil {
		return fmt.Errorf("service: encoding rotation step: %w", err)
	}

	// The idempotency key includes the state, so a step queued twice for the
	// same state collapses into one job while the next state still queues.
	idempotency := fmt.Sprintf("rotation:%s:%s:%d", r.ID, r.State, r.Wave)

	_, err = s.jobs.Enqueue(ctx, &store.Job{
		TenantID:       r.TenantID,
		Type:           store.JobTypeRotationStep,
		Payload:        payload,
		Priority:       50,
		MaxAttempts:    3,
		RunAfter:       time.Now().Add(delay),
		IdempotencyKey: &idempotency,
		RotationID:     &r.ID,
		CreatedBy:      &userID,
	})
	return err
}

// EnqueueNext is called by the job handler after a successful step.
func (s *RotationService) EnqueueNext(ctx context.Context, tenantID, rotationID, userID uuid.UUID, delay time.Duration) error {
	r, err := s.rotations.GetRotation(ctx, tenantID, rotationID)
	if err != nil {
		return err
	}
	if store.RotationFinished(r.State) {
		return nil
	}
	return s.enqueueStep(ctx, r, userID, delay)
}

// Get returns one rotation with its per-target progress.
func (s *RotationService) Get(ctx context.Context, subject *authz.Subject, id uuid.UUID) (*store.Rotation, []store.RotationTarget, error) {
	if err := subject.Require(authz.PermRotationRead); err != nil {
		return nil, nil, err
	}

	r, err := s.rotations.GetRotation(ctx, subject.TenantID, id)
	if err != nil {
		return nil, nil, err
	}
	targets, err := s.rotations.ListRotationTargets(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	return r, targets, nil
}

// List returns rotations.
func (s *RotationService) List(ctx context.Context, subject *authz.Subject, states []string, limit int) ([]store.Rotation, error) {
	if err := subject.Require(authz.PermRotationRead); err != nil {
		return nil, err
	}
	return s.rotations.ListRotations(ctx, subject.TenantID, states, limit)
}

// systemSubject rebuilds the acting subject for a queued step.
//
// A background job runs with the permissions of whoever started the rotation,
// not with implicit superuser rights. If their access was revoked between
// queueing and execution, the rotation stops.
func (s *RotationService) systemSubject(ctx context.Context, userID uuid.UUID) (*authz.Subject, error) {
	subject, err := s.users.LoadSubject(ctx, store.DefaultTenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("service: rebuilding the acting subject for a queued rotation step: %w", err)
	}
	// Steps run unattended, so a step-up requirement cannot be satisfied
	// interactively; the queued work inherits the MFA state it was created
	// with by treating the session as machine-driven.
	subject.MFAVerifiedAt = time.Now()
	return subject, nil
}

func (s *RotationService) record(ctx context.Context, subject *authz.Subject, ev audit.Event) {
	ev.TenantID = subject.TenantID
	ev.ActorType = audit.ActorUser
	ev.ActorID = &subject.UserID
	ev.ActorName = subject.Username
	if _, err := s.audit.Log(ctx, ev); err != nil {
		s.log.Error("writing audit event", "action", ev.Action, "error", err)
	}
}

// rotationParams are the per-run knobs that have no column of their own,
// carried in memory between planning and the first step.
//
// They are a cache, not the source of truth: a step that runs on another
// instance falls back to the policy or to the defaults, which is why every
// reader tolerates a miss.
var (
	rotationParamsMu    sync.RWMutex
	rotationParamsCache = map[uuid.UUID]rotationParams{}
)

type rotationParams struct {
	Algorithm        string
	SoakPeriod       *time.Duration
	FailureThreshold int
}

func (s *RotationService) remember(id uuid.UUID, p rotationParams) {
	rotationParamsMu.Lock()
	defer rotationParamsMu.Unlock()
	rotationParamsCache[id] = p
}

func (s *RotationService) recall(id uuid.UUID) rotationParams {
	rotationParamsMu.RLock()
	defer rotationParamsMu.RUnlock()
	return rotationParamsCache[id]
}

func successorName(name string, generation int) string {
	base := name
	// Strip a trailing generation suffix so names do not accumulate them.
	for i := len(name) - 1; i > 0; i-- {
		if name[i] == '-' {
			if suffix := name[i+1:]; len(suffix) > 1 && suffix[0] == 'g' {
				allDigits := true
				for _, c := range suffix[1:] {
					if c < '0' || c > '9' {
						allDigits = false
						break
					}
				}
				if allDigits {
					base = name[:i]
				}
			}
			break
		}
	}
	return fmt.Sprintf("%s-g%d", base, generation)
}

func orString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orTrigger(v string) string {
	if v == "" {
		return store.TriggerManual
	}
	return v
}

// ErrBadRotation marks a rotation request the machine refuses.
var ErrBadRotation = errors.New("service: invalid rotation request")

func badRotation(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadRotation, fmt.Sprintf(format, args...))
}
