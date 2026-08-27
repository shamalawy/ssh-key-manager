package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/shamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/shamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/shamalawy/ssh-key-manager/backend/internal/cronx"
	"github.com/shamalawy/ssh-key-manager/backend/internal/events"
	"github.com/shamalawy/ssh-key-manager/backend/internal/jobs"
	"github.com/shamalawy/ssh-key-manager/backend/internal/store"
)

// Worker binds the job runner and the scheduler to the services that do the
// actual work.
//
// It is the one place that knows both "what kinds of background work exist"
// and "who performs them", which keeps that coupling out of the services
// themselves and out of main.
type Worker struct {
	jobs      *store.Jobs
	rotations *store.Rotations
	keys      *store.Keys
	targets   *store.Targets
	users     *store.Users

	rotationSvc  *RotationService
	deploySvc    *DeployService
	reconcileSvc *ReconcileService
	backupSvc    *BackupService
	consumerSvc  *ConsumerService
	authSvc      *AuthService

	dispatcher *events.Dispatcher
	publisher  *events.Publisher
	audit      *audit.Logger
	log        *slog.Logger

	// jobRetention bounds how long finished jobs are kept.
	jobRetention time.Duration
	// expiryWarning is how far ahead a key's expiry is announced.
	expiryWarning time.Duration
	// reconcileEvery paces the drift sweep.
	reconcileEvery time.Duration
}

// WorkerDeps bundles what a Worker needs.
type WorkerDeps struct {
	Jobs      *store.Jobs
	Rotations *store.Rotations
	Keys      *store.Keys
	Targets   *store.Targets
	Users     *store.Users

	Rotation  *RotationService
	Deploy    *DeployService
	Reconcile *ReconcileService
	Backup    *BackupService
	Consumers *ConsumerService
	Auth      *AuthService

	Dispatcher *events.Dispatcher
	Publisher  *events.Publisher
	Audit      *audit.Logger
	Logger     *slog.Logger

	JobRetention   time.Duration
	ExpiryWarning  time.Duration
	ReconcileEvery time.Duration
}

// NewWorker wires a Worker.
func NewWorker(d WorkerDeps) *Worker {
	w := &Worker{
		jobs: d.Jobs, rotations: d.Rotations, keys: d.Keys, targets: d.Targets,
		users: d.Users, rotationSvc: d.Rotation, deploySvc: d.Deploy,
		reconcileSvc: d.Reconcile, backupSvc: d.Backup, consumerSvc: d.Consumers,
		authSvc: d.Auth, dispatcher: d.Dispatcher, publisher: d.Publisher,
		audit: d.Audit, log: d.Logger,
		jobRetention:   d.JobRetention,
		expiryWarning:  d.ExpiryWarning,
		reconcileEvery: d.ReconcileEvery,
	}
	if w.jobRetention <= 0 {
		w.jobRetention = 14 * 24 * time.Hour
	}
	if w.expiryWarning <= 0 {
		w.expiryWarning = 14 * 24 * time.Hour
	}
	if w.reconcileEvery <= 0 {
		w.reconcileEvery = time.Hour
	}
	return w
}

// RegisterHandlers binds job types to their implementations.
func (w *Worker) RegisterHandlers(runner *jobs.Runner) {
	runner.Register(store.JobTypeRotationStep, w.handleRotationStep)
	runner.Register(store.JobTypeDeploy, w.handleDeploy)
	runner.Register(store.JobTypeReconcile, w.handleReconcile)
	runner.Register(store.JobTypeConsumer, w.handleConsumerDelivery)
	runner.Register(store.JobTypeBackup, w.handleBackup)
}

// RegisterTasks binds periodic work to the scheduler.
func (w *Worker) RegisterTasks(sched *jobs.Scheduler) {
	sched.Add("rotation.policies", time.Minute, w.tickPolicies)
	sched.Add("rotation.soak", time.Minute, w.tickSoak)
	sched.Add("key.expiry", time.Hour, w.tickExpiry)
	sched.Add("reconcile.sweep", w.reconcileEvery, w.tickReconcile)
	sched.Add("webhook.drain", 15*time.Second, w.tickWebhooks)
	sched.Add("jobs.purge", 6*time.Hour, w.tickPurgeJobs)
	sched.Add("backup.prune", 6*time.Hour, w.tickPruneBackups)
	sched.Add("session.purge", time.Hour, w.tickPurgeSessions)
}

// ------------------------------------------------------------- job handlers ---

// handleRotationStep advances a rotation by one transition and queues the next.
func (w *Worker) handleRotationStep(ctx context.Context, j *store.Job, log *jobs.JobLogger) (any, error) {
	var payload rotationStepPayload
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return nil, jobs.Permanent(fmt.Errorf("service: malformed rotation step payload: %w", err))
	}

	logf := func(msg string, fields map[string]any) { log.Info(ctx, msg, fields) }

	requeue, delay, err := w.rotationSvc.Step(ctx, payload.RotationID, payload.UserID, logf)
	if err != nil {
		// A refused permission or a deleted key will not fix itself.
		if errors.Is(err, authz.ErrDenied) || errors.Is(err, store.ErrNotFound) || errors.Is(err, ErrBadRotation) {
			w.failRotation(ctx, payload.RotationID, err)
			return nil, jobs.Permanent(err)
		}
		return nil, err
	}

	if requeue {
		if err := w.rotationSvc.EnqueueNext(ctx, store.DefaultTenantID, payload.RotationID, payload.UserID, delay); err != nil {
			return nil, err
		}
	}

	return map[string]any{"requeued": requeue, "delay_seconds": int(delay.Seconds())}, nil
}

// failRotation records a terminal failure so a dead job does not leave a
// rotation stuck in a running state forever.
func (w *Worker) failRotation(ctx context.Context, rotationID uuid.UUID, cause error) {
	if _, err := w.rotations.SetRotationState(ctx, rotationID, nil, store.RotationFailed, cause.Error()); err != nil {
		w.log.Warn("marking a rotation failed", "rotation", rotationID, "error", err)
		return
	}
	w.publisher.Emit(ctx, store.DefaultTenantID, events.TypeRotationFailed, "rotation",
		&rotationID, "", map[string]any{"error": cause.Error()})
}

type deployPayload struct {
	TargetID    uuid.UUID `json:"target_id"`
	PrincipalID uuid.UUID `json:"principal_id"`
	UserID      uuid.UUID `json:"user_id"`
	Prune       bool      `json:"prune"`
	VerifyAuth  bool      `json:"verify_auth"`
}

func (w *Worker) handleDeploy(ctx context.Context, j *store.Job, log *jobs.JobLogger) (any, error) {
	var payload deployPayload
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return nil, jobs.Permanent(fmt.Errorf("service: malformed deploy payload: %w", err))
	}

	subject, err := w.subject(ctx, payload.UserID)
	if err != nil {
		return nil, jobs.Permanent(err)
	}

	log.Info(ctx, "converging the target", map[string]any{
		"target": payload.TargetID.String(), "prune": payload.Prune,
	})

	// The deploy service publishes its own key.deployed / deploy.failed events,
	// so this handler does not: emitting here too would deliver every queued
	// deployment to each webhook twice.
	result, err := w.deploySvc.Deploy(ctx, subject, payload.TargetID, payload.PrincipalID, DeployOptions{
		Prune: payload.Prune, VerifyAuth: payload.VerifyAuth,
	})
	if err != nil {
		return nil, err
	}

	log.Info(ctx, fmt.Sprintf("converged: %d added, %d removed", len(result.Added), len(result.Removed)), nil)
	return result, nil
}

type reconcilePayload struct {
	TargetID *uuid.UUID `json:"target_id,omitempty"`
	UserID   uuid.UUID  `json:"user_id"`
}

func (w *Worker) handleReconcile(ctx context.Context, j *store.Job, log *jobs.JobLogger) (any, error) {
	var payload reconcilePayload
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return nil, jobs.Permanent(fmt.Errorf("service: malformed reconcile payload: %w", err))
	}

	subject, err := w.subject(ctx, payload.UserID)
	if err != nil {
		return nil, jobs.Permanent(err)
	}

	if payload.TargetID != nil {
		return w.reconcileSvc.Reconcile(ctx, subject, *payload.TargetID)
	}

	results, err := w.reconcileSvc.ReconcileAll(ctx, subject)
	if err != nil {
		return nil, err
	}

	var drifted int
	for i := range results {
		if results[i].Drifted() {
			drifted++
		}
	}
	log.Info(ctx, fmt.Sprintf("reconciled %d targets; %d drifted", len(results), drifted), nil)

	return map[string]any{"targets": len(results), "drifted": drifted}, nil
}

type consumerPayload struct {
	ConsumerID uuid.UUID `json:"consumer_id"`
	UserID     uuid.UUID `json:"user_id"`
}

func (w *Worker) handleConsumerDelivery(ctx context.Context, j *store.Job, log *jobs.JobLogger) (any, error) {
	var payload consumerPayload
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return nil, jobs.Permanent(fmt.Errorf("service: malformed consumer payload: %w", err))
	}

	subject, err := w.subject(ctx, payload.UserID)
	if err != nil {
		return nil, jobs.Permanent(err)
	}

	if err := w.consumerSvc.Redeliver(ctx, subject, payload.ConsumerID); err != nil {
		return nil, err
	}
	log.Info(ctx, "delivered the private key to the consumer", nil)
	return map[string]any{"consumer": payload.ConsumerID.String()}, nil
}

type backupPayload struct {
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Passphrase string    `json:"passphrase"`
	UserID     uuid.UUID `json:"user_id"`
	RetainDays int       `json:"retain_days"`
}

func (w *Worker) handleBackup(ctx context.Context, j *store.Job, log *jobs.JobLogger) (any, error) {
	var payload backupPayload
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return nil, jobs.Permanent(fmt.Errorf("service: malformed backup payload: %w", err))
	}

	subject, err := w.subject(ctx, payload.UserID)
	if err != nil {
		return nil, jobs.Permanent(err)
	}

	record, err := w.backupSvc.Create(ctx, subject, CreateRequest{
		Name:       payload.Name,
		Kind:       payload.Kind,
		Passphrase: payload.Passphrase,
		RetainFor:  time.Duration(payload.RetainDays) * 24 * time.Hour,
	})
	if err != nil {
		return nil, err
	}

	log.Info(ctx, fmt.Sprintf("wrote %s (%d keys, %d bytes)", record.Location, record.KeyCount, record.SizeBytes), nil)
	return map[string]any{"backup": record.ID.String(), "keys": record.KeyCount}, nil
}

// -------------------------------------------------------- scheduled tasks ---

// tickPolicies fires rotation policies whose schedule has come due.
func (w *Worker) tickPolicies(ctx context.Context) error {
	due, err := w.rotations.DuePolicies(ctx, time.Now())
	if err != nil {
		return err
	}

	for i := range due {
		policy := &due[i]

		// Reschedule first. If planning fails, the policy still moves on
		// rather than firing again every tick.
		next := nextRun(policy.CronExpr, time.Now())
		if err := w.rotations.MarkPolicyRun(ctx, policy.ID, next); err != nil {
			w.log.Warn("recording a policy run", "policy", policy.Name, "error", err)
		}

		if err := w.runPolicy(ctx, policy); err != nil {
			w.log.Warn("running a rotation policy", "policy", policy.Name, "error", err)
		}
	}
	return nil
}

// runPolicy plans and starts a rotation for every key the policy selects.
func (w *Worker) runPolicy(ctx context.Context, policy *store.RotationPolicy) error {
	subject, err := w.policySubject(ctx, policy)
	if err != nil {
		return err
	}

	candidates, err := w.selectKeys(ctx, subject.TenantID, policy)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		w.log.Info("policy matched no keys due for rotation", "policy", policy.Name)
		return nil
	}

	w.log.Info("rotation policy firing", "policy", policy.Name, "keys", len(candidates))

	for _, k := range candidates {
		soak := policy.SoakPeriod()
		plan, err := w.rotationSvc.Plan(ctx, subject, PlanRequest{
			KeyID:            k.ID,
			PolicyID:         &policy.ID,
			Trigger:          store.TriggerSchedule,
			Algorithm:        policy.Algorithm,
			SoakPeriod:       &soak,
			CanaryPercent:    policy.CanaryPercent,
			FailureThreshold: policy.FailureThreshold,
			ApprovalRequired: policy.ApprovalRequired,
		})
		if err != nil {
			w.log.Warn("planning a scheduled rotation", "policy", policy.Name, "key", k.Name, "error", err)
			continue
		}

		if policy.ApprovalRequired {
			w.log.Info("rotation is waiting for approval", "policy", policy.Name,
				"key", k.Name, "rotation", plan.Rotation.ID)
			continue
		}

		if _, err := w.rotationSvc.Start(ctx, subject, plan.Rotation.ID); err != nil {
			w.log.Warn("starting a scheduled rotation", "policy", policy.Name, "key", k.Name, "error", err)
		}
	}
	return nil
}

// selectKeys resolves a policy's selector to the keys actually due.
//
// Being selected is necessary but not sufficient: a key younger than the
// policy's max_age is not rotated just because the cron fired, or a daily
// schedule would rotate everything daily.
func (w *Worker) selectKeys(ctx context.Context, tenantID uuid.UUID, policy *store.RotationPolicy) ([]store.Key, error) {
	filter := store.KeyFilter{
		TenantID: tenantID,
		Tags:     policy.Selector.KeyTags,
		Statuses: []string{store.KeyStatusActive},
		Limit:    500,
	}

	all, err := w.keys.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	maxAge := policy.MaxAge()
	out := make([]store.Key, 0, len(all))

	for _, k := range all {
		// Break-glass keys are the way back in when a rotation goes wrong.
		// They are never rotated on a schedule.
		if k.KeyClass == store.KeyClassBreakGlass {
			continue
		}
		// Adopted keys have no private half in the vault, so SKM cannot
		// generate a successor that anyone could actually use.
		if !k.HasPrivateKey {
			continue
		}
		if policy.Selector.KeyClass != "" && k.KeyClass != policy.Selector.KeyClass {
			continue
		}
		if len(policy.Selector.KeyIDs) > 0 && !containsID(policy.Selector.KeyIDs, k.ID) {
			continue
		}
		if maxAge > 0 && time.Since(k.CreatedAt) < maxAge {
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

// tickSoak wakes rotations whose soak window has closed.
func (w *Worker) tickSoak(ctx context.Context) error {
	expired, err := w.rotations.SoakExpired(ctx, time.Now())
	if err != nil {
		return err
	}

	for i := range expired {
		r := &expired[i]
		actor := uuid.Nil
		if r.CreatedBy != nil {
			actor = *r.CreatedBy
		}
		if err := w.rotationSvc.EnqueueNext(ctx, r.TenantID, r.ID, actor, 0); err != nil {
			w.log.Warn("waking a soaked rotation", "rotation", r.ID, "error", err)
		}
	}
	return nil
}

// tickExpiry announces keys approaching expiry.
func (w *Worker) tickExpiry(ctx context.Context) error {
	all, err := w.keys.List(ctx, store.KeyFilter{
		TenantID: store.DefaultTenantID,
		Statuses: []string{store.KeyStatusActive, store.KeyStatusStaged},
		Limit:    1000,
	})
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(w.expiryWarning)
	for i := range all {
		k := &all[i]
		if k.ExpiresAt == nil || k.ExpiresAt.After(cutoff) {
			continue
		}
		w.publisher.Emit(ctx, k.TenantID, events.TypeKeyExpiring, "key", &k.ID, k.Name,
			map[string]any{
				"expires_at": k.ExpiresAt,
				"days_left":  int(time.Until(*k.ExpiresAt).Hours() / 24),
			})
	}
	return nil
}

// tickReconcile queues a fleet-wide drift sweep.
//
// It enqueues rather than reconciling inline: a sweep across a large fleet is
// slow, and the scheduler tick must stay short so the other tasks are not
// starved behind it.
func (w *Worker) tickReconcile(ctx context.Context) error {
	admin, err := w.anyAdmin(ctx)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(reconcilePayload{UserID: admin})
	if err != nil {
		return err
	}

	idempotency := "reconcile:sweep"
	_, err = w.jobs.Enqueue(ctx, &store.Job{
		TenantID:       store.DefaultTenantID,
		Type:           store.JobTypeReconcile,
		Payload:        payload,
		Priority:       200,
		MaxAttempts:    2,
		IdempotencyKey: &idempotency,
	})
	return err
}

func (w *Worker) tickWebhooks(ctx context.Context) error {
	if w.dispatcher == nil {
		return nil
	}
	_, err := w.dispatcher.Drain(ctx, 25)
	return err
}

func (w *Worker) tickPurgeJobs(ctx context.Context) error {
	n, err := w.jobs.PurgeFinished(ctx, w.jobRetention)
	if err != nil {
		return err
	}
	if n > 0 {
		w.log.Info("purged finished jobs", "count", n)
	}
	return nil
}

func (w *Worker) tickPruneBackups(ctx context.Context) error {
	if w.backupSvc == nil {
		return nil
	}
	n, err := w.backupSvc.PruneExpired(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		w.log.Info("pruned expired backups", "count", n)
	}
	return nil
}

func (w *Worker) tickPurgeSessions(ctx context.Context) error {
	n, err := w.authSvc.PurgeExpiredSessions(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		w.log.Info("purged expired sessions", "count", n)
	}
	return nil
}

// ------------------------------------------------------------------ helpers ---

// EnqueueDeploy queues a deployment for the API to hand off asynchronously.
func (w *Worker) EnqueueDeploy(ctx context.Context, subject *authz.Subject, targetID, principalID uuid.UUID, prune, verify bool) (*store.Job, error) {
	payload, err := json.Marshal(deployPayload{
		TargetID: targetID, PrincipalID: principalID, UserID: subject.UserID,
		Prune: prune, VerifyAuth: verify,
	})
	if err != nil {
		return nil, err
	}

	idempotency := fmt.Sprintf("deploy:%s:%s", targetID, principalID)
	return w.jobs.Enqueue(ctx, &store.Job{
		TenantID:       subject.TenantID,
		Type:           store.JobTypeDeploy,
		Payload:        payload,
		TargetID:       &targetID,
		IdempotencyKey: &idempotency,
		CreatedBy:      &subject.UserID,
	})
}

// EnqueueReconcile queues a drift check for one target or the whole fleet.
func (w *Worker) EnqueueReconcile(ctx context.Context, subject *authz.Subject, targetID *uuid.UUID) (*store.Job, error) {
	payload, err := json.Marshal(reconcilePayload{TargetID: targetID, UserID: subject.UserID})
	if err != nil {
		return nil, err
	}

	scope := "fleet"
	if targetID != nil {
		scope = targetID.String()
	}
	idempotency := "reconcile:" + scope

	return w.jobs.Enqueue(ctx, &store.Job{
		TenantID:       subject.TenantID,
		Type:           store.JobTypeReconcile,
		Payload:        payload,
		TargetID:       targetID,
		IdempotencyKey: &idempotency,
		CreatedBy:      &subject.UserID,
	})
}

// subject rebuilds an acting identity for a queued job.
func (w *Worker) subject(ctx context.Context, userID uuid.UUID) (*authz.Subject, error) {
	if userID == uuid.Nil {
		id, err := w.anyAdmin(ctx)
		if err != nil {
			return nil, err
		}
		userID = id
	}

	subject, err := w.users.LoadSubject(ctx, store.DefaultTenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("service: rebuilding the acting subject for a queued job: %w", err)
	}
	// Queued work cannot present a second factor interactively; it inherits
	// the authority of the account that scheduled it.
	subject.MFAVerifiedAt = time.Now()
	return subject, nil
}

// policySubject resolves who a scheduled rotation acts as.
func (w *Worker) policySubject(ctx context.Context, policy *store.RotationPolicy) (*authz.Subject, error) {
	if policy.CreatedBy != nil {
		if subject, err := w.users.LoadSubject(ctx, policy.TenantID, *policy.CreatedBy); err == nil && subject.Can(authz.PermRotationExecute) {
			subject.MFAVerifiedAt = time.Now()
			return subject, nil
		}
		w.log.Warn("the account that created a policy can no longer rotate; falling back to an administrator",
			"policy", policy.Name)
	}
	return w.subject(ctx, uuid.Nil)
}

// anyAdmin finds an account that can perform unattended work.
func (w *Worker) anyAdmin(ctx context.Context) (uuid.UUID, error) {
	users, err := w.users.List(ctx, store.DefaultTenantID)
	if err != nil {
		return uuid.Nil, err
	}

	for i := range users {
		u := &users[i]
		if !u.Active {
			continue
		}
		subject, err := w.users.LoadSubject(ctx, store.DefaultTenantID, u.ID)
		if err != nil {
			continue
		}
		if subject.Can(authz.PermRotationExecute) && subject.Can(authz.PermDeployExecute) {
			return u.ID, nil
		}
	}
	return uuid.Nil, errors.New("service: no active account holds the permissions unattended work needs")
}

// nextRun computes a policy's next firing time, returning nil when the policy
// has no schedule (age-only policies are evaluated on every tick instead).
func nextRun(expr string, from time.Time) *time.Time {
	if expr == "" {
		// No cron: re-evaluate on the next tick so max_age policies still fire.
		next := from.Add(time.Hour)
		return &next
	}
	next, err := cronx.NextAfter(expr, from)
	if err != nil {
		return nil
	}
	return &next
}

func containsID(list []uuid.UUID, id uuid.UUID) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}
