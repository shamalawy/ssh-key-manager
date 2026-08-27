package service

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/shamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/shamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/shamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/shamalawy/ssh-key-manager/backend/internal/connectors/linux"
	"github.com/shamalawy/ssh-key-manager/backend/internal/consumers"
	"github.com/shamalawy/ssh-key-manager/backend/internal/db"
	"github.com/shamalawy/ssh-key-manager/backend/internal/dbtest"
	"github.com/shamalawy/ssh-key-manager/backend/internal/events"
	"github.com/shamalawy/ssh-key-manager/backend/internal/store"
	"github.com/shamalawy/ssh-key-manager/backend/internal/vault"
)

// rotationHarness runs the whole rotation machine against a real fleet: real
// PostgreSQL, real sshd, real SSH authentication as the verification gate.
//
// The fleet is its own pair of containers. Sharing a host with another test
// package caused exactly the failure this suite is meant to catch — one
// package's restore wiping the other's keys — so the isolation is deliberate.
type rotationHarness struct {
	*harness

	rotationSvc *RotationService
	consumerSvc *ConsumerService
	rotations   *store.Rotations
	jobs        *store.Jobs
	consumers   *store.Consumers
	recorder    *eventRecorder
	pool        *db.Pool
}

// eventRecorder captures published events so a test can assert what an operator
// would have been told.
type eventRecorder struct{ seen []events.Event }

func (r *eventRecorder) Deliver(ctx context.Context, ev events.Event) {
	r.seen = append(r.seen, ev)
}

func (r *eventRecorder) has(evType string) bool {
	for _, ev := range r.seen {
		if ev.Type == evType {
			return true
		}
	}
	return false
}

// durationPtr is the shape PlanRequest wants: a nil soak means "use the
// default", so a test asking for a specific one has to say so explicitly.
func durationPtr(d time.Duration) *time.Duration { return &d }

// fleetAddrs returns the hosts reserved for rotation tests.
func fleetAddrs() []string {
	raw := os.Getenv("SKM_TEST_SSH_FLEET")
	if raw == "" {
		return nil
	}

	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func newRotationHarness(t *testing.T) *rotationHarness {
	t.Helper()

	fleet := fleetAddrs()
	if len(fleet) < 2 {
		t.Skip("SKM_TEST_SSH_FLEET not set to at least two hosts; skipping the rotation fleet test")
	}

	pool := dbtest.New(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	v := vault.New()
	kek := make([]byte, vault.KeyLen)
	for i := range kek {
		kek[i] = byte(i*11 + 3)
	}
	if err := v.Unseal(1, kek); err != nil {
		t.Fatalf("unsealing vault: %v", err)
	}

	registry := connectors.NewRegistry()
	registry.Register(linux.New())

	auditLog := audit.New(pool)
	keyStore := store.NewKeys(pool)
	keySvc := NewKeyService(keyStore, v, auditLog)

	base := &harness{
		keySvc:  keySvc,
		keys:    keyStore,
		targets: store.NewTargets(pool),
		assigns: store.NewAssignments(pool),
		creds:   store.NewCredentials(pool),
		snaps:   store.NewSnapshots(pool),
		users:   store.NewUsers(pool),
		audit:   auditLog,
		vault:   v,
	}
	base.deploySvc = NewDeployService(DeployServiceDeps{
		Targets: base.targets, Keys: keyStore, Assignments: base.assigns,
		Snapshots: base.snaps, Changesets: store.NewChangesets(pool),
		Credentials: base.creds, Registry: registry, Vault: v,
		KeyService: keySvc, Audit: auditLog, Logger: logger,
	})

	if err := base.users.EnsureSystemRoles(context.Background(), store.DefaultTenantID); err != nil {
		t.Fatalf("seeding system roles: %v", err)
	}
	base.subject = base.newSubject(t, "rotation-tester", authz.All)

	// A queued rotation step rebuilds its acting subject from the database
	// rather than trusting whatever was in memory when the rotation was
	// planned, so the test user needs a real role grant — not just an
	// in-memory permission set.
	adminRole, err := base.users.GetRoleByName(context.Background(), store.DefaultTenantID, "admin")
	if err != nil {
		t.Fatalf("loading the admin role: %v", err)
	}
	if err := base.users.GrantRole(context.Background(), base.subject.UserID, adminRole.ID); err != nil {
		t.Fatalf("granting the admin role: %v", err)
	}

	recorder := &eventRecorder{}
	publisher := events.NewPublisher(events.NewBus(logger), logger, recorder)

	consumerStore := store.NewConsumers(pool)
	consumerSvc := NewConsumerService(consumerStore, keyStore, keySvc,
		consumers.NewRegistry(), auditLog, logger)

	rotationStore := store.NewRotations(pool)
	jobStore := store.NewJobs(pool)

	h := &rotationHarness{
		harness:     base,
		rotations:   rotationStore,
		jobs:        jobStore,
		consumers:   consumerStore,
		consumerSvc: consumerSvc,
		recorder:    recorder,
		pool:        pool,
	}

	h.rotationSvc = NewRotationService(RotationDeps{
		Rotations: rotationStore, Keys: keyStore, Targets: base.targets,
		Assignments: base.assigns, Changesets: store.NewChangesets(pool),
		Consumers: consumerStore, Users: base.users, Jobs: jobStore,
		KeyService: keySvc, Deploy: base.deploySvc, ConsumerSvc: consumerSvc,
		Audit: auditLog, Publisher: publisher, Logger: logger,
	})

	return h
}

// provisionAt creates a target pointing at a specific fleet host.
func (h *rotationHarness) provisionAt(t *testing.T, name, addr, username string, canary bool) (*store.Target, *store.Principal) {
	t.Helper()
	ctx := context.Background()

	host, portStr, _ := strings.Cut(addr, ":")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parsing fleet address %q: %v", addr, err)
	}

	credID := uuid.New()
	sealed, err := h.vault.Encrypt([]byte("testpass"), []byte(credID.String()))
	if err != nil {
		t.Fatalf("sealing credential: %v", err)
	}
	cred, err := h.creds.Create(ctx, &store.Credential{
		ID: credID, Name: "fleet-" + name, Kind: store.CredSSHPassword, Username: "skmtest",
	}, sealed)
	if err != nil {
		t.Fatalf("creating credential: %v", err)
	}

	target, err := h.targets.Create(ctx, &store.Target{
		Name: name, Kind: "linux", Connector: linux.Kind,
		Address: host, Port: port, Enabled: true, IsCanary: canary,
		CredentialID: &cred.ID, Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}

	principal, err := h.targets.CreatePrincipal(ctx, &store.Principal{
		TargetID: target.ID, Username: username, Enabled: true,
	})
	if err != nil {
		t.Fatalf("creating principal: %v", err)
	}

	// Each test gets a fresh database, but the containers are shared and keep
	// whatever the previous test left behind. Clearing the file here makes host
	// state as isolated as database state, so the suite is order-independent.
	h.resetHost(t, target, principal)

	return target, principal
}

// resetHost returns a principal's authorized_keys to "no file at all".
//
// It is best-effort: a target that is deliberately unreachable (the failure
// tests point at a closed port) has nothing to reset.
func (h *rotationHarness) resetHost(t *testing.T, target *store.Target, principal *store.Principal) {
	t.Helper()
	ctx := context.Background()

	cred, err := h.deploySvc.credential(ctx, store.DefaultTenantID, target)
	if err != nil {
		return
	}
	defer vault.Zero(cred.PrivateKey)

	err = linux.New().Restore(ctx, connectors.Request{
		Target:     toConnectorTarget(target),
		Principal:  toConnectorPrincipal(principal),
		Credential: cred,
	}, &connectors.Snapshot{Kind: "authorized_keys", Existed: false})
	if err != nil {
		t.Logf("could not reset %s (%s): %v", target.Name, principal.Username, err)
	}
}

// run drives a rotation to completion the way the worker does, without waiting
// on the queue: each step is executed and the next one taken immediately.
//
// Soak delays are honoured only up to a bound, so the test proves the machine
// asks for a delay without spending it.
func (h *rotationHarness) run(t *testing.T, rotationID uuid.UUID, maxSteps int) *store.Rotation {
	t.Helper()
	ctx := context.Background()

	for i := 0; i < maxSteps; i++ {
		requeue, delay, err := h.rotationSvc.Step(ctx, rotationID, h.subject.UserID,
			func(msg string, fields map[string]any) { t.Logf("  rotation: %s", msg) })
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if !requeue {
			break
		}
		if delay > 0 && delay < 5*time.Second {
			time.Sleep(delay)
		}
	}

	r, err := h.rotations.GetRotation(ctx, store.DefaultTenantID, rotationID)
	if err != nil {
		t.Fatalf("reading the rotation back: %v", err)
	}
	return r
}

// The Milestone 3 exit criterion: an unattended staged rotation across a fleet.
// Both keys work during the soak; only the new one afterwards.
func TestStagedRotationAcrossAFleet(t *testing.T) {
	h := newRotationHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	targetA, principalA := h.provisionAt(t, "fleet-a", fleet[0], "skmtest", false)
	targetB, principalB := h.provisionAt(t, "fleet-b", fleet[1], "skmtest", false)

	oldKey, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "fleet-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	for _, pair := range []struct {
		target    *store.Target
		principal *store.Principal
	}{{targetA, principalA}, {targetB, principalB}} {
		if _, err := h.assigns.Upsert(ctx, &store.Assignment{
			KeyID: oldKey.ID, TargetID: pair.target.ID, PrincipalID: pair.principal.ID,
		}); err != nil {
			t.Fatalf("Upsert assignment: %v", err)
		}
		if _, err := h.deploySvc.Deploy(ctx, h.subject, pair.target.ID, pair.principal.ID,
			DeployOptions{VerifyAuth: true}); err != nil {
			t.Fatalf("initial Deploy: %v", err)
		}
	}

	if !h.canAuthenticate(t, targetA, principalA, oldKey.ID) {
		t.Fatal("the original key does not authenticate on host A before the rotation")
	}
	if !h.canAuthenticate(t, targetB, principalB, oldKey.ID) {
		t.Fatal("the original key does not authenticate on host B before the rotation")
	}

	// Plan. Nothing has changed yet.
	plan, err := h.rotationSvc.Plan(ctx, h.subject, PlanRequest{
		KeyID: oldKey.ID, Trigger: store.TriggerManual,
		SoakPeriod: durationPtr(time.Second), // a real window, just a short one
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Targets) != 2 {
		t.Fatalf("the plan covers %d targets, want 2", len(plan.Targets))
	}
	if plan.Rotation.State != store.RotationPlanned {
		t.Errorf("planned rotation state = %q", plan.Rotation.State)
	}
	if h.canAuthenticate(t, targetA, principalA, oldKey.ID) == false {
		t.Fatal("planning changed the fleet")
	}

	// Drive it.
	final := h.run(t, plan.Rotation.ID, 20)

	if final.State != store.RotationCompleted {
		t.Fatalf("rotation ended in %q (%s), want completed", final.State, final.Error)
	}
	if final.NewKeyID == nil {
		t.Fatal("the rotation completed without recording a successor key")
	}
	if final.TargetsVerified != 2 {
		t.Errorf("TargetsVerified = %d, want 2", final.TargetsVerified)
	}
	if final.TargetsRetired != 2 {
		t.Errorf("TargetsRetired = %d, want 2", final.TargetsRetired)
	}

	// The new key works everywhere.
	newKey, err := h.keys.Get(ctx, store.DefaultTenantID, *final.NewKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if newKey.Generation != oldKey.Generation+1 {
		t.Errorf("successor generation = %d, want %d", newKey.Generation, oldKey.Generation+1)
	}
	if newKey.ParentKeyID == nil || *newKey.ParentKeyID != oldKey.ID {
		t.Error("the successor does not record its parent; the lineage is broken")
	}
	if newKey.Status != store.KeyStatusActive {
		t.Errorf("successor status = %q, want active", newKey.Status)
	}

	if !h.canAuthenticate(t, targetA, principalA, newKey.ID) {
		t.Error("the new key does not authenticate on host A")
	}
	if !h.canAuthenticate(t, targetB, principalB, newKey.ID) {
		t.Error("the new key does not authenticate on host B")
	}

	// The old key is gone everywhere. This is the assertion that matters: a
	// rotation that leaves the old key live has not rotated anything.
	if h.canAuthenticate(t, targetA, principalA, oldKey.ID) {
		t.Error("the old key still authenticates on host A after retirement")
	}
	if h.canAuthenticate(t, targetB, principalB, oldKey.ID) {
		t.Error("the old key still authenticates on host B after retirement")
	}

	retired, err := h.keys.Get(ctx, store.DefaultTenantID, oldKey.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retired.Status != store.KeyStatusRetired {
		t.Errorf("old key status = %q, want retired", retired.Status)
	}

	for _, want := range []string{
		events.TypeRotationStaged, events.TypeRotationVerified, events.TypeRotationDone,
	} {
		if !h.recorder.has(want) {
			t.Errorf("no %q event was published", want)
		}
	}
}

// Both keys must work during the soak window. That window is the whole point:
// it is what lets a straggler that has not picked up the new key keep working.
func TestBothKeysAuthenticateDuringSoak(t *testing.T) {
	h := newRotationHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, principal := h.provisionAt(t, "soak-host", fleet[0], "skmtest", false)

	oldKey, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "soak-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: oldKey.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID,
		DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatal(err)
	}

	plan, err := h.rotationSvc.Plan(ctx, h.subject, PlanRequest{
		KeyID: oldKey.ID, SoakPeriod: durationPtr(time.Hour), // long enough that the test stops inside it
	})
	if err != nil {
		t.Fatal(err)
	}

	// Step until the machine is soaking.
	var soaking *store.Rotation
	for i := 0; i < 10; i++ {
		requeue, _, err := h.rotationSvc.Step(ctx, plan.Rotation.ID, h.subject.UserID,
			func(string, map[string]any) {})
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		current, err := h.rotations.GetRotation(ctx, store.DefaultTenantID, plan.Rotation.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.State == store.RotationSoaking {
			soaking = current
			break
		}
		if !requeue {
			t.Fatalf("the rotation stopped in %q before soaking", current.State)
		}
	}
	if soaking == nil {
		t.Fatal("the rotation never reached the soak window")
	}
	if soaking.SoakUntil == nil || !soaking.SoakUntil.After(time.Now()) {
		t.Errorf("SoakUntil = %v, want a time in the future", soaking.SoakUntil)
	}

	// The property the soak window exists for.
	if !h.canAuthenticate(t, target, principal, oldKey.ID) {
		t.Error("the old key stopped working during the soak window")
	}
	if !h.canAuthenticate(t, target, principal, *soaking.NewKeyID) {
		t.Error("the new key does not work during the soak window")
	}

	// Stepping again inside the window must not retire anything.
	if _, _, err := h.rotationSvc.Step(ctx, plan.Rotation.ID, h.subject.UserID,
		func(string, map[string]any) {}); err != nil {
		t.Fatal(err)
	}
	if !h.canAuthenticate(t, target, principal, oldKey.ID) {
		t.Error("the old key was retired before the soak window closed")
	}
}

// A canary wave must be verified before the rest of the fleet is touched.
func TestCanaryWaveIsStagedFirst(t *testing.T) {
	h := newRotationHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	canary, canaryPrincipal := h.provisionAt(t, "canary-host", fleet[0], "skmtest", true)
	rest, restPrincipal := h.provisionAt(t, "rest-host", fleet[1], "skmtest", false)

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "canary-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, pair := range []struct {
		target    *store.Target
		principal *store.Principal
	}{{canary, canaryPrincipal}, {rest, restPrincipal}} {
		if _, err := h.assigns.Upsert(ctx, &store.Assignment{
			KeyID: key.ID, TargetID: pair.target.ID, PrincipalID: pair.principal.ID,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.deploySvc.Deploy(ctx, h.subject, pair.target.ID, pair.principal.ID,
			DeployOptions{VerifyAuth: true}); err != nil {
			t.Fatal(err)
		}
	}

	plan, err := h.rotationSvc.Plan(ctx, h.subject, PlanRequest{
		KeyID: key.ID, SoakPeriod: durationPtr(time.Second), CanaryPercent: 50,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The host flagged as a canary goes in wave 0, alone.
	if plan.Waves[0] != 1 || plan.Waves[1] != 1 {
		t.Fatalf("waves = %v, want one target in each", plan.Waves)
	}
	for _, rt := range plan.Targets {
		if rt.TargetID == canary.ID && rt.Wave != 0 {
			t.Errorf("the canary host is in wave %d, want 0", rt.Wave)
		}
		if rt.TargetID == rest.ID && rt.Wave != 1 {
			t.Errorf("the non-canary host is in wave %d, want 1", rt.Wave)
		}
	}

	final := h.run(t, plan.Rotation.ID, 25)
	if final.State != store.RotationCompleted {
		t.Fatalf("rotation ended in %q (%s)", final.State, final.Error)
	}
	if final.TargetsRetired != 2 {
		t.Errorf("TargetsRetired = %d, want 2", final.TargetsRetired)
	}
}

// A target that cannot be reached must not have its old key removed. Halting
// beats half-applying: the alternative is a host nobody can log into.
func TestUnreachableTargetKeepsBothKeys(t *testing.T) {
	h := newRotationHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	good, goodPrincipal := h.provisionAt(t, "reachable-host", fleet[0], "skmtest", false)

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "partial-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: key.ID, TargetID: good.ID, PrincipalID: goodPrincipal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, good.ID, goodPrincipal.ID,
		DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatal(err)
	}

	// A second target that does not answer. Port 1 is reserved and closed.
	dead, deadPrincipal := h.provisionAt(t, "dead-host", "127.0.0.1:1", "skmtest", false)
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: key.ID, TargetID: dead.ID, PrincipalID: deadPrincipal.ID,
	}); err != nil {
		t.Fatal(err)
	}

	plan, err := h.rotationSvc.Plan(ctx, h.subject, PlanRequest{
		KeyID: key.ID, SoakPeriod: durationPtr(time.Second),
		FailureThreshold: 60, // tolerate the one dead host out of two
	})
	if err != nil {
		t.Fatal(err)
	}

	final := h.run(t, plan.Rotation.ID, 25)

	if final.TargetsFailed == 0 {
		t.Fatal("the unreachable host was not recorded as failed")
	}

	// The reachable host rotated cleanly.
	if !h.canAuthenticate(t, good, goodPrincipal, *final.NewKeyID) {
		t.Error("the new key does not work on the reachable host")
	}
	if h.canAuthenticate(t, good, goodPrincipal, key.ID) {
		t.Error("the old key was left on the reachable host")
	}

	// And the old key is *not* reported as retired, because it is still
	// authorized somewhere SKM could not reach.
	oldKey, err := h.keys.Get(ctx, store.DefaultTenantID, key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if oldKey.Status == store.KeyStatusRetired {
		t.Error("the old key is marked retired even though a target still holds it")
	}
	if oldKey.Status != store.KeyStatusRetiring {
		t.Errorf("old key status = %q, want retiring", oldKey.Status)
	}
}

// Above the tolerated failure rate the machine aborts rather than continuing
// into a fleet it is evidently unable to reach.
func TestRotationAbortsAboveTheFailureThreshold(t *testing.T) {
	h := newRotationHarness(t)
	ctx := context.Background()

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "threshold-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Two unreachable hosts: a 100% failure rate.
	for i, addr := range []string{"127.0.0.1:1", "127.0.0.1:2"} {
		target, principal := h.provisionAt(t, "dead-"+strconv.Itoa(i), addr, "skmtest", false)
		if _, err := h.assigns.Upsert(ctx, &store.Assignment{
			KeyID: key.ID, TargetID: target.ID, PrincipalID: principal.ID,
		}); err != nil {
			t.Fatal(err)
		}
	}

	plan, err := h.rotationSvc.Plan(ctx, h.subject, PlanRequest{
		KeyID: key.ID, SoakPeriod: durationPtr(time.Second), FailureThreshold: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	final := h.run(t, plan.Rotation.ID, 20)

	if final.State != store.RotationAborted {
		t.Fatalf("rotation ended in %q, want aborted", final.State)
	}
	if !strings.Contains(final.Error, "threshold") {
		t.Errorf("the abort reason should name the threshold: %q", final.Error)
	}

	// The old key must be untouched: an aborted rotation changes nothing about
	// what still works.
	oldKey, err := h.keys.Get(ctx, store.DefaultTenantID, key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if oldKey.Status == store.KeyStatusRetired || oldKey.Status == store.KeyStatusRetiring {
		t.Errorf("an aborted rotation moved the old key to %q", oldKey.Status)
	}
	if !h.recorder.has(events.TypeRotationAborted) {
		t.Error("no abort event was published")
	}
}

// Break-glass keys are the way back in when a rotation goes wrong, so the
// machine refuses to rotate them.
func TestBreakGlassKeysAreNotRotated(t *testing.T) {
	h := newRotationHarness(t)
	ctx := context.Background()

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "emergency", Algorithm: "ed25519", KeyClass: store.KeyClassBreakGlass,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.rotationSvc.Plan(ctx, h.subject, PlanRequest{KeyID: key.ID})
	if err == nil {
		t.Fatal("Plan accepted a break-glass key")
	}
	if !strings.Contains(err.Error(), "break-glass") {
		t.Errorf("the refusal should say why: %v", err)
	}
}

// An approval gate must actually hold the rotation, not merely record that one
// was requested.
func TestApprovalGateHoldsTheRotation(t *testing.T) {
	h := newRotationHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, principal := h.provisionAt(t, "approval-host", fleet[0], "skmtest", false)

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "approval-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: key.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID,
		DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatal(err)
	}

	plan, err := h.rotationSvc.Plan(ctx, h.subject, PlanRequest{
		KeyID: key.ID, ApprovalRequired: true, SoakPeriod: durationPtr(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Rotation.State != store.RotationAwaiting {
		t.Fatalf("state = %q, want awaiting_approval", plan.Rotation.State)
	}

	// Starting an unapproved rotation is refused.
	if _, err := h.rotationSvc.Start(ctx, h.subject, plan.Rotation.ID); err == nil {
		t.Error("Start accepted a rotation awaiting approval")
	}

	// Stepping does nothing while it waits.
	requeue, _, err := h.rotationSvc.Step(ctx, plan.Rotation.ID, h.subject.UserID,
		func(string, map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	if requeue {
		t.Error("an unapproved rotation asked to be requeued")
	}
	if !h.canAuthenticate(t, target, principal, key.ID) {
		t.Fatal("the fleet changed while the rotation was awaiting approval")
	}

	// Approving releases it.
	approved, err := h.rotationSvc.Approve(ctx, h.subject, plan.Rotation.ID)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if approved.ApprovedBy == nil || *approved.ApprovedBy != h.subject.UserID {
		t.Error("the approval was not attributed")
	}

	final := h.run(t, plan.Rotation.ID, 20)
	if final.State != store.RotationCompleted {
		t.Fatalf("rotation ended in %q (%s)", final.State, final.Error)
	}
}

// Aborting mid-flight leaves both keys in place: failing towards *more* access
// is the safe direction.
func TestAbortLeavesTheOldKeyWorking(t *testing.T) {
	h := newRotationHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, principal := h.provisionAt(t, "abort-host", fleet[0], "skmtest", false)

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "abort-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: key.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID,
		DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatal(err)
	}

	plan, err := h.rotationSvc.Plan(ctx, h.subject, PlanRequest{
		KeyID: key.ID, SoakPeriod: durationPtr(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Stage and verify, then abort before retirement.
	for i := 0; i < 4; i++ {
		if _, _, err := h.rotationSvc.Step(ctx, plan.Rotation.ID, h.subject.UserID,
			func(string, map[string]any) {}); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}

	aborted, err := h.rotationSvc.Abort(ctx, h.subject, plan.Rotation.ID, "operator changed their mind")
	if err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if aborted.State != store.RotationAborted {
		t.Errorf("state = %q, want aborted", aborted.State)
	}

	if !h.canAuthenticate(t, target, principal, key.ID) {
		t.Error("aborting removed the original key; an abort must never reduce access")
	}

	// Further steps do nothing.
	requeue, _, err := h.rotationSvc.Step(ctx, plan.Rotation.ID, h.subject.UserID,
		func(string, map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	if requeue {
		t.Error("an aborted rotation asked to be requeued")
	}
}

// A consumer holds the private key. It must be handed the new one *before* the
// old key is retired, or retiring it breaks whatever was using it.
func TestConsumerIsUpdatedBeforeTheOldKeyRetires(t *testing.T) {
	h := newRotationHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, principal := h.provisionAt(t, "consumer-host", fleet[0], "skmtest", false)

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "consumer-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: key.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID,
		DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatal(err)
	}

	// A file-drop consumer, so the test can read what was delivered.
	dir := t.TempDir()
	keyPath := dir + "/deploy_key"
	if _, err := h.consumerSvc.Create(ctx, h.subject, &store.Consumer{
		Name: "ci-runner", Kind: store.ConsumerFileDrop, KeyID: key.ID, Enabled: true,
		Config: map[string]any{"path": keyPath},
	}); err != nil {
		t.Fatalf("creating the consumer: %v", err)
	}

	plan, err := h.rotationSvc.Plan(ctx, h.subject, PlanRequest{
		KeyID: key.ID, SoakPeriod: durationPtr(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Consumers) != 1 {
		t.Errorf("the plan lists %d consumers, want 1", len(plan.Consumers))
	}

	final := h.run(t, plan.Rotation.ID, 20)
	if final.State != store.RotationCompleted {
		t.Fatalf("rotation ended in %q (%s)", final.State, final.Error)
	}

	delivered, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("the consumer never received a key: %v", err)
	}

	// It must be the *new* private key, and it must authenticate.
	newPrivate, err := h.keySvc.PrivateKeyFor(ctx, store.DefaultTenantID, *final.NewKeyID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Zero(newPrivate)

	if string(delivered) != string(newPrivate) {
		t.Error("the consumer holds a key other than the rotation's successor")
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the delivered key has mode %o, want 600", perm)
	}

	// And the consumer row now points at the new key.
	sinks, err := h.consumers.List(ctx, store.DefaultTenantID, final.NewKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sinks) != 1 {
		t.Errorf("the consumer was not rebound to the successor key")
	}
}

// A dry run shows the plan and the successor key without touching the fleet.
func TestDryRunChangesNothing(t *testing.T) {
	h := newRotationHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, principal := h.provisionAt(t, "dryrun-host", fleet[0], "skmtest", false)

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "dryrun-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: key.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID,
		DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatal(err)
	}

	plan, err := h.rotationSvc.Plan(ctx, h.subject, PlanRequest{
		KeyID: key.ID, DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	final := h.run(t, plan.Rotation.ID, 10)
	if final.State != store.RotationCompleted {
		t.Fatalf("dry run ended in %q", final.State)
	}

	// The successor exists so an operator can see what would be deployed...
	if final.NewKeyID == nil {
		t.Fatal("the dry run produced no successor key to inspect")
	}
	// ...but it is nowhere near the fleet.
	if h.canAuthenticate(t, target, principal, *final.NewKeyID) {
		t.Error("a dry run deployed the successor key")
	}
	if !h.canAuthenticate(t, target, principal, key.ID) {
		t.Error("a dry run disturbed the existing key")
	}

	oldKey, err := h.keys.Get(ctx, store.DefaultTenantID, key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if oldKey.Status != store.KeyStatusActive {
		t.Errorf("a dry run moved the old key to %q", oldKey.Status)
	}
}
