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

	"github.com/hamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors/linux"
	"github.com/hamalawy/ssh-key-manager/backend/internal/dbtest"
	"github.com/hamalawy/ssh-key-manager/backend/internal/keys"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

// harness wires the whole stack against a live database and a live sshd, so
// these tests exercise the same code paths the server does.
type harness struct {
	keySvc    *KeyService
	deploySvc *DeployService
	keys      *store.Keys
	targets   *store.Targets
	assigns   *store.Assignments
	creds     *store.Credentials
	snaps     *store.Snapshots
	users     *store.Users
	audit     *audit.Logger
	subject   *authz.Subject
	vault     *vault.Vault
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	if sshAddr() == "" {
		t.Skip("SKM_TEST_SSH_ADDR not set; skipping end-to-end test")
	}
	pool := dbtest.New(t)

	v := vault.New()
	kek := make([]byte, vault.KeyLen)
	for i := range kek {
		kek[i] = byte(i * 7)
	}
	if err := v.Unseal(1, kek); err != nil {
		t.Fatalf("unsealing vault: %v", err)
	}

	registry := connectors.NewRegistry()
	registry.Register(linux.New())

	auditLog := audit.New(pool)
	keyStore := store.NewKeys(pool)
	keySvc := NewKeyService(keyStore, v, auditLog)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	h := &harness{
		keySvc:  keySvc,
		keys:    keyStore,
		targets: store.NewTargets(pool),
		assigns: store.NewAssignments(pool),
		creds:   store.NewCredentials(pool),
		snaps:   store.NewSnapshots(pool),
		audit:   auditLog,
		vault:   v,
	}

	h.deploySvc = NewDeployService(DeployServiceDeps{
		Targets: h.targets, Keys: keyStore, Assignments: h.assigns,
		Snapshots: h.snaps, Changesets: store.NewChangesets(pool),
		Credentials: h.creds, Registry: registry, Vault: v,
		KeyService: keySvc, Audit: auditLog, Logger: logger,
	})

	h.users = store.NewUsers(pool)
	if err := h.users.EnsureSystemRoles(context.Background(), store.DefaultTenantID); err != nil {
		t.Fatalf("seeding system roles: %v", err)
	}

	// An administrator with a fresh second factor, so sensitive operations are
	// permitted. The row is real because keys.owner_id references users.
	h.subject = h.newSubject(t, "tester", authz.All)

	return h
}

// newSubject creates a real user row and returns an authorised subject for it.
func (h *harness) newSubject(t *testing.T, username string, perms []authz.Permission) *authz.Subject {
	t.Helper()

	u, err := h.users.Create(context.Background(), &store.User{
		Username: username, DisplayName: username, PasswordHash: "unused-in-tests", Active: true,
	})
	if err != nil {
		t.Fatalf("creating user %q: %v", username, err)
	}

	subject := authz.NewSubject(u.ID, store.DefaultTenantID, username, perms, nil, nil)
	subject.MFAVerifiedAt = time.Now()
	return subject
}

// provision creates the credential, target, and principal pointing at the live
// sshd container.
func (h *harness) provision(t *testing.T, name, username string, useSudo bool) (*store.Target, *store.Principal) {
	t.Helper()
	ctx := context.Background()

	host, portStr, _ := strings.Cut(sshAddr(), ":")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parsing SKM_TEST_SSH_ADDR: %v", err)
	}

	credID := uuid.New()
	sealed, err := h.vault.Encrypt([]byte("testpass"), []byte(credID.String()))
	if err != nil {
		t.Fatalf("sealing credential: %v", err)
	}
	cred, err := h.creds.Create(ctx, &store.Credential{
		ID: credID, Name: "sshd-" + name, Kind: store.CredSSHPassword, Username: "skmtest",
	}, sealed)
	if err != nil {
		t.Fatalf("creating credential: %v", err)
	}

	target, err := h.targets.Create(ctx, &store.Target{
		Name: name, Kind: "linux", Connector: linux.Kind,
		Address: host, Port: port, Enabled: true,
		CredentialID: &cred.ID, Tags: []string{"test"},
	})
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}

	principal, err := h.targets.CreatePrincipal(ctx, &store.Principal{
		TargetID: target.ID, Username: username, UseSudo: useSudo, Enabled: true,
	})
	if err != nil {
		t.Fatalf("creating principal: %v", err)
	}

	return target, principal
}

// canAuthenticate reports whether a key currently works against the target.
func (h *harness) canAuthenticate(t *testing.T, target *store.Target, principal *store.Principal, keyID uuid.UUID) bool {
	t.Helper()
	ctx := context.Background()

	privateKey, err := h.keySvc.PrivateKeyFor(ctx, store.DefaultTenantID, keyID)
	if err != nil {
		t.Fatalf("loading private key: %v", err)
	}
	defer vault.Zero(privateKey)

	err = linux.New().Verify(ctx, connectors.Request{
		Target:     toConnectorTarget(target),
		Principal:  toConnectorPrincipal(principal),
		Credential: &connectors.Credential{},
	}, privateKey)
	return err == nil
}

// The whole vertical slice: generate a key in the vault, assign it, deploy it
// to a real host, and prove the private half authenticates.
func TestEndToEndGenerateAssignDeployVerify(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	target, principal := h.provision(t, "e2e-host", "skmtest", false)

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "e2e-key", Algorithm: "ed25519", Tags: []string{"test"},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if key.Status != store.KeyStatusPending {
		t.Errorf("new key status = %q, want pending", key.Status)
	}
	if !key.HasPrivateKey {
		t.Error("generated key reports no private key")
	}

	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: key.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatalf("Upsert assignment: %v", err)
	}

	// A dry run must not change anything.
	dry, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID, DeployOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run Deploy: %v", err)
	}
	if !dry.Changed {
		t.Error("dry run reported no change for an undeployed key")
	}
	if dry.Diff == "" {
		t.Error("dry run produced no diff")
	}
	if h.canAuthenticate(t, target, principal, key.ID) {
		t.Fatal("the key authenticates after a dry run; it was actually deployed")
	}

	// The real deployment, with verification.
	res, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID, DeployOptions{VerifyAuth: true})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if !res.Changed {
		t.Error("deployment reported no change")
	}
	if res.SnapshotID == nil {
		t.Error("no snapshot was taken before the mutation")
	}
	if len(res.VerifiedKeys) != 1 || res.VerifiedKeys[0] != key.Fingerprint {
		t.Errorf("VerifiedKeys = %v, want [%s]", res.VerifiedKeys, key.Fingerprint)
	}
	if len(res.FailedKeys) != 0 {
		t.Errorf("FailedKeys = %v, want none", res.FailedKeys)
	}
	// A key that deployed and proved it authenticates should now be active:
	// "active" is only meaningful if it means the key actually works somewhere.
	if len(res.PromotedKeys) != 1 {
		t.Errorf("PromotedKeys = %v, want the deployed key", res.PromotedKeys)
	}
	promoted, err := h.keys.Get(ctx, store.DefaultTenantID, key.ID)
	if err != nil {
		t.Fatalf("re-reading key: %v", err)
	}
	if promoted.Status != store.KeyStatusActive {
		t.Errorf("key status after a verified deployment = %q, want active", promoted.Status)
	}
	if promoted.ActivatedAt == nil {
		t.Error("activated_at was not stamped on promotion")
	}

	if !h.canAuthenticate(t, target, principal, key.ID) {
		t.Fatal("the deployed key does not authenticate")
	}

	// The assignment must record both that it deployed and that it was proven.
	assignments, err := h.assigns.List(ctx, store.AssignmentFilter{})
	if err != nil {
		t.Fatalf("listing assignments: %v", err)
	}
	if len(assignments) != 1 {
		t.Fatalf("got %d assignments, want 1", len(assignments))
	}
	a := assignments[0]
	if !a.InSync() {
		t.Errorf("assignment is not in sync: desired %q, actual %q", a.DesiredState, a.ActualState)
	}
	if a.AuthVerifiedAt == nil {
		t.Error("auth_verified_at was not stamped")
	}

	// Every step must be on the audit trail, and the chain must still verify.
	events, err := h.audit.Query(ctx, audit.Filter{})
	if err != nil {
		t.Fatalf("querying audit: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Action] = true
	}
	for _, want := range []string{audit.ActionKeyCreate, audit.ActionKeyDeploy} {
		if !seen[want] {
			t.Errorf("audit trail is missing %q", want)
		}
	}

	chain, err := h.audit.Verify(ctx, store.DefaultTenantID)
	if err != nil {
		t.Fatalf("verifying audit chain: %v", err)
	}
	if !chain.Valid {
		t.Errorf("audit chain is broken at seq %d: %s", chain.BrokenAtSeq, chain.Reason)
	}
}

// The product's central promise, through the real service layer: a rotation
// never interrupts access.
func TestEndToEndStagedRotation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	target, principal := h.provision(t, "rotation-host", "skmtest", false)

	gen1, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{Name: "rotating-key", Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("generating generation 1: %v", err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: gen1.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatalf("assigning generation 1: %v", err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID, DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatalf("deploying generation 1: %v", err)
	}
	if !h.canAuthenticate(t, target, principal, gen1.ID) {
		t.Fatal("generation 1 does not authenticate")
	}

	// Stage generation 2 alongside generation 1.
	gen2, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "rotating-key-gen2", Algorithm: "ed25519",
		ParentKeyID: &gen1.ID, Generation: gen1.Generation + 1,
	})
	if err != nil {
		t.Fatalf("generating generation 2: %v", err)
	}
	if gen2.Generation != 2 || gen2.ParentKeyID == nil || *gen2.ParentKeyID != gen1.ID {
		t.Errorf("rotation lineage not recorded: generation %d, parent %v", gen2.Generation, gen2.ParentKeyID)
	}

	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: gen2.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatalf("assigning generation 2: %v", err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID, DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatalf("staging generation 2: %v", err)
	}

	// Both keys must work during the soak window.
	if !h.canAuthenticate(t, target, principal, gen1.ID) {
		t.Error("generation 1 stopped working while generation 2 was staged")
	}
	if !h.canAuthenticate(t, target, principal, gen2.ID) {
		t.Fatal("generation 2 does not authenticate after staging")
	}

	// Retire generation 1 by withdrawing its assignment and pruning.
	assignments, err := h.assigns.List(ctx, store.AssignmentFilter{KeyID: &gen1.ID})
	if err != nil || len(assignments) != 1 {
		t.Fatalf("locating generation 1's assignment: %v (%d found)", err, len(assignments))
	}
	if err := h.assigns.Delete(ctx, store.DefaultTenantID, assignments[0].ID); err != nil {
		t.Fatalf("withdrawing generation 1: %v", err)
	}

	retired, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID, DeployOptions{
		Prune: true, VerifyAuth: true,
	})
	if err != nil {
		t.Fatalf("retiring generation 1: %v", err)
	}
	if len(retired.Removed) != 1 || retired.Removed[0] != gen1.Fingerprint {
		t.Errorf("Removed = %v, want [%s]", retired.Removed, gen1.Fingerprint)
	}

	if !h.canAuthenticate(t, target, principal, gen2.ID) {
		t.Error("generation 2 stopped working after generation 1 was retired")
	}
	if h.canAuthenticate(t, target, principal, gen1.ID) {
		t.Error("generation 1 still authenticates after retirement")
	}
}

// A rollback must return the target to its exact prior state.
func TestEndToEndRollback(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	target, principal := h.provision(t, "rollback-host", "skmtest", false)

	original, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{Name: "original", Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: original.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID, DeployOptions{}); err != nil {
		t.Fatalf("deploying the original key: %v", err)
	}

	// Deploy a second key, capturing the snapshot taken beforehand.
	mistake, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{Name: "mistake", Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: mistake.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	bad, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID, DeployOptions{})
	if err != nil {
		t.Fatalf("deploying the second key: %v", err)
	}
	if bad.SnapshotID == nil {
		t.Fatal("no snapshot was taken before the second deployment")
	}
	if !h.canAuthenticate(t, target, principal, mistake.ID) {
		t.Fatal("the second key did not deploy")
	}

	// Roll back to the snapshot taken before the mistake.
	if _, err := h.deploySvc.Rollback(ctx, h.subject, *bad.SnapshotID); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	if h.canAuthenticate(t, target, principal, mistake.ID) {
		t.Error("the rolled-back key still authenticates")
	}
	if !h.canAuthenticate(t, target, principal, original.ID) {
		t.Error("the original key stopped working after rollback")
	}
}

// Revoked keys must never be deployed, whatever the assignment says.
func TestRevokedKeyIsNotDeployed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	target, principal := h.provision(t, "revoke-host", "skmtest", false)

	keep, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{Name: "keeper", Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	revoked, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{Name: "revoked", Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	for _, k := range []*store.Key{keep, revoked} {
		if _, err := h.assigns.Upsert(ctx, &store.Assignment{
			KeyID: k.ID, TargetID: target.ID, PrincipalID: principal.ID,
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	if _, err := h.keySvc.Revoke(ctx, h.subject, revoked.ID, true, "key found in a public repository"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID, DeployOptions{}); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	if h.canAuthenticate(t, target, principal, revoked.ID) {
		t.Error("a compromised key was deployed despite being revoked")
	}
	if !h.canAuthenticate(t, target, principal, keep.ID) {
		t.Error("the healthy key was not deployed")
	}
}

// Reveal is the one path that hands private key material to a human, so its
// gates are asserted explicitly.
func TestRevealRequiresPermissionAndFreshMFA(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{Name: "secret", Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// An operator holds no reveal permission at all.
	operator := h.newSubject(t, "operator", systemRolePermissions(t, "operator"))
	if _, err := h.keySvc.Reveal(ctx, operator, key.ID, "curiosity"); err == nil {
		t.Error("an operator revealed a private key")
	}

	// An engineer holds the permission but with a stale second factor.
	stale := h.newSubject(t, "engineer", systemRolePermissions(t, "engineer"))
	stale.MFAVerifiedAt = time.Now().Add(-time.Hour)
	if _, err := h.keySvc.Reveal(ctx, stale, key.ID, "deploying by hand"); err == nil {
		t.Error("a stale second factor was accepted for reveal")
	}

	// With both, the material comes back and is genuinely usable.
	res, err := h.keySvc.Reveal(ctx, h.subject, key.ID, "documented break-glass drill")
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if len(res.PrivatePEM) == 0 {
		t.Fatal("Reveal returned no material")
	}
	line, err := keys.PublicLineFromPrivate(res.PrivatePEM, key.Comment)
	if err != nil {
		t.Fatalf("deriving the public half: %v", err)
	}
	if line != key.PublicKey {
		t.Error("the revealed private key does not match the stored public key")
	}

	// Every reveal, granted or denied, must be on the trail.
	events, err := h.audit.Query(ctx, audit.Filter{Actions: []string{audit.ActionKeyReveal}})
	if err != nil {
		t.Fatalf("querying audit: %v", err)
	}
	var granted, denied int
	for _, e := range events {
		switch e.Outcome {
		case audit.OutcomeSuccess:
			granted++
		case audit.OutcomeDenied:
			denied++
		}
	}
	if granted != 1 {
		t.Errorf("recorded %d successful reveals, want 1", granted)
	}
	if denied != 2 {
		t.Errorf("recorded %d denied reveals, want 2", denied)
	}
}

// KEK rotation must rewrap every key and leave them all decryptable.
func TestKEKRotation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	var created []*store.Key
	for i := 0; i < 3; i++ {
		k, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
			Name: "rewrap-" + strconv.Itoa(i), Algorithm: "ed25519",
		})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		created = append(created, k)
	}

	newKEK := make([]byte, vault.KeyLen)
	for i := range newKEK {
		newKEK[i] = byte(255 - i)
	}
	if err := h.vault.Unseal(2, newKEK); err != nil {
		t.Fatalf("installing KEK version 2: %v", err)
	}

	count, err := h.keySvc.RotateKEK(ctx, h.subject)
	if err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}
	if count != 3 {
		t.Errorf("rewrapped %d keys, want 3", count)
	}

	for _, k := range created {
		material, err := h.keys.LoadMaterial(ctx, k.ID)
		if err != nil {
			t.Fatalf("LoadMaterial: %v", err)
		}
		if material.KEKVersion != 2 {
			t.Errorf("key %s is still at KEK version %d", k.Name, material.KEKVersion)
		}
		if _, err := h.keySvc.PrivateKeyFor(ctx, store.DefaultTenantID, k.ID); err != nil {
			t.Errorf("key %s no longer decrypts after rewrap: %v", k.Name, err)
		}
	}

	// Rotation is resumable, so a second run must be a clean no-op.
	again, err := h.keySvc.RotateKEK(ctx, h.subject)
	if err != nil {
		t.Fatalf("second RotateKEK: %v", err)
	}
	if again != 0 {
		t.Errorf("a second rotation rewrapped %d keys, want 0", again)
	}
}

// The first deployment to a host is the one that matters most: a machine that
// has never been managed has no ~/.ssh/authorized_keys at all. Capturing a
// snapshot of a file that does not exist has to work, or SKM can never onboard
// anything.
func TestFirstDeploymentToUnmanagedHost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	target, principal := h.provision(t, "pristine-host", "deploy", true)

	// Ensure the account genuinely has no key file to start from.
	if err := h.wipeAuthorizedKeys(t, target, principal); err != nil {
		t.Fatalf("clearing authorized_keys: %v", err)
	}

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{Name: "first-key", Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: key.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	res, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID, DeployOptions{VerifyAuth: true})
	if err != nil {
		t.Fatalf("first deployment to a host with no authorized_keys: %v", err)
	}
	if !res.Changed {
		t.Error("first deployment reported no change")
	}
	if res.SnapshotID == nil {
		t.Fatal("no snapshot was taken for a host with no existing file")
	}

	// The snapshot must record that nothing was there, so a rollback removes
	// the file rather than leaving an empty one behind.
	snap, err := h.snaps.Get(ctx, store.DefaultTenantID, *res.SnapshotID)
	if err != nil {
		t.Fatalf("reading the snapshot: %v", err)
	}
	if snap.Existed {
		t.Error("snapshot claims the file existed on a host that had none")
	}
	if snap.KeyCount != 0 {
		t.Errorf("snapshot key count = %d, want 0", snap.KeyCount)
	}

	if !h.canAuthenticate(t, target, principal, key.ID) {
		t.Fatal("the first key deployed to a pristine host does not authenticate")
	}

	// Rolling back should return the host to having no file at all.
	if _, err := h.deploySvc.Rollback(ctx, h.subject, *res.SnapshotID); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if h.canAuthenticate(t, target, principal, key.ID) {
		t.Error("the key still authenticates after rolling back to no-file state")
	}
}

// wipeAuthorizedKeys removes the principal's key file so a test can start from
// a genuinely unmanaged host.
func (h *harness) wipeAuthorizedKeys(t *testing.T, target *store.Target, principal *store.Principal) error {
	t.Helper()

	return linux.New().Restore(context.Background(), connectors.Request{
		Target:    toConnectorTarget(target),
		Principal: toConnectorPrincipal(principal),
		Credential: &connectors.Credential{
			Kind: "ssh_password", Username: "skmtest", Password: "testpass",
		},
	}, &connectors.Snapshot{Kind: "authorized_keys", Existed: false})
}

// sshAddr names the sshd container this package deploys to.
//
// It is deliberately a different container from the one internal/connectors/linux
// uses. Go runs test packages in parallel, and both packages manage the same
// account's authorized_keys file — sharing one host means one package's restore
// silently wipes the other's deployment, which surfaces as a mysterious
// authentication failure rather than an obvious collision.
func sshAddr() string {
	if addr := os.Getenv("SKM_TEST_SSH_ADDR_E2E"); addr != "" {
		return addr
	}
	return os.Getenv("SKM_TEST_SSH_ADDR")
}

func systemRolePermissions(t *testing.T, name string) []authz.Permission {
	t.Helper()
	for _, r := range authz.SystemRoles {
		if r.Name == name {
			return r.Permissions
		}
	}
	t.Fatalf("system role %q not found", name)
	return nil
}
