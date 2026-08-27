package service

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/shamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/shamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/shamalawy/ssh-key-manager/backend/internal/connectors/linux"
	"github.com/shamalawy/ssh-key-manager/backend/internal/events"
	"github.com/shamalawy/ssh-key-manager/backend/internal/keys"
	"github.com/shamalawy/ssh-key-manager/backend/internal/store"
	"github.com/shamalawy/ssh-key-manager/backend/internal/vault"
)

// reconcileHarness adds drift detection and the unmanaged-key inventory to the
// rotation fleet's setup. It reuses the rotation fleet's hosts, which are
// reserved for this package.
type reconcileHarness struct {
	*rotationHarness

	reconcileSvc *ReconcileService
	discovery    *store.Discovery
}

func newReconcileHarness(t *testing.T) *reconcileHarness {
	t.Helper()

	base := newRotationHarness(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	discovery := store.NewDiscovery(base.pool)
	publisher := events.NewPublisher(events.NewBus(logger), logger, base.recorder)

	return &reconcileHarness{
		rotationHarness: base,
		discovery:       discovery,
		reconcileSvc: NewReconcileService(base.targets, base.keys, base.assigns,
			discovery, base.deploySvc, base.keySvc, audit.New(base.pool),
			publisher, logger),
	}
}

// addKeyByHand puts a key on a host the way an operator would: directly, with
// SKM knowing nothing about it.
func (h *reconcileHarness) addKeyByHand(t *testing.T, target *store.Target, principal *store.Principal, comment string) string {
	t.Helper()
	ctx := context.Background()

	pair, err := keys.Generate(keys.Ed25519, comment)
	if err != nil {
		t.Fatalf("generating a key by hand: %v", err)
	}
	defer vault.Zero(pair.PrivatePEM)

	cred, err := h.deploySvc.credential(ctx, store.DefaultTenantID, target)
	if err != nil {
		t.Fatalf("loading the credential: %v", err)
	}
	defer vault.Zero(cred.PrivateKey)

	conn := linux.New()
	req := connectors.Request{
		Target:     toConnectorTarget(target),
		Principal:  toConnectorPrincipal(principal),
		Credential: cred,
	}

	// Read the current file, append the key, write it back — deliberately
	// outside the assignment model.
	existing, err := conn.List(ctx, req)
	if err != nil {
		t.Fatalf("reading the existing keys: %v", err)
	}

	desired := []connectors.DesiredKey{{PublicLine: pair.PublicLine, Fingerprint: pair.Fingerprint}}
	for _, e := range existing {
		if e.Fingerprint != "" {
			desired = append(desired, connectors.DesiredKey{
				PublicLine: e.Line(), Fingerprint: e.Fingerprint, Options: e.Options,
			})
		}
	}
	if _, err := conn.Apply(ctx, req, desired, connectors.DefaultApplyOptions()); err != nil {
		t.Fatalf("adding a key by hand: %v", err)
	}

	return pair.Fingerprint
}

// The inventory is usually the first genuinely useful screen: it answers "who
// can already log into these machines?".
func TestReconcileFindsUnmanagedKeys(t *testing.T) {
	h := newReconcileHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, principal := h.provisionAt(t, "drift-host", fleet[0], "skmtest", false)

	// A managed key, deployed properly.
	managed, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "managed-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: managed.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID,
		DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatal(err)
	}

	// And one somebody added by hand.
	stranger := h.addKeyByHand(t, target, principal, "someone@laptop")

	result, err := h.reconcileSvc.Reconcile(ctx, h.subject, target.ID)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(result.Principals) != 1 {
		t.Fatalf("reported on %d principals, want 1", len(result.Principals))
	}
	report := result.Principals[0]

	if len(report.Missing) != 0 {
		t.Errorf("Missing = %v, want none; the managed key was deployed", report.Missing)
	}
	if len(report.Unmanaged) != 1 || report.Unmanaged[0] != stranger {
		t.Errorf("Unmanaged = %v, want [%s]", report.Unmanaged, stranger)
	}

	inventory, err := h.reconcileSvc.ListDiscovered(ctx, h.subject, store.DiscoveryFilter{
		States: []string{store.DiscoveredUnmanaged},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory) != 1 {
		t.Fatalf("the inventory holds %d keys, want 1", len(inventory))
	}
	if inventory[0].Fingerprint != stranger {
		t.Errorf("inventory fingerprint = %q, want %q", inventory[0].Fingerprint, stranger)
	}
	if inventory[0].Comment != "someone@laptop" {
		t.Errorf("the comment was not captured: %q", inventory[0].Comment)
	}
	if inventory[0].TargetName != target.Name {
		t.Errorf("the finding is not attributed to a host: %+v", inventory[0])
	}

	if !h.recorder.has(events.TypeUnmanagedFound) {
		t.Error("no unmanaged-key event was published")
	}
}

func TestReconcileDetectsAMissingKey(t *testing.T) {
	h := newReconcileHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, principal := h.provisionAt(t, "missing-host", fleet[1], "skmtest", false)

	key, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "will-vanish", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: key.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}

	// Assigned but never deployed: exactly what drift looks like after someone
	// deletes a line by hand.
	result, err := h.reconcileSvc.Reconcile(ctx, h.subject, target.ID)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if result.DriftState != store.DriftDrifted {
		t.Errorf("DriftState = %q, want drifted", result.DriftState)
	}
	if len(result.Principals[0].Missing) != 1 {
		t.Errorf("Missing = %v, want one key", result.Principals[0].Missing)
	}
	if !h.recorder.has(events.TypeDriftDetected) {
		t.Error("no drift event was published")
	}

	// The stored target row records it too, so the dashboard can show it
	// without re-running the check.
	stored, err := h.targets.Get(ctx, store.DefaultTenantID, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.DriftState != store.DriftDrifted {
		t.Errorf("stored drift state = %q, want drifted", stored.DriftState)
	}
}

// Auto-heal must go through the ordinary deployment path, so it inherits the
// snapshot, the lockout guard, and the audit entry rather than having a
// quieter path of its own.
func TestAutoHealRedeploysAMissingKey(t *testing.T) {
	h := newReconcileHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, principal := h.provisionAt(t, "heal-host", fleet[0], "skmtest", false)

	// Something must already work on the host, or removing everything to
	// simulate drift would trip the lockout guard on the way back.
	anchor, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "anchor-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: anchor.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID,
		DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatal(err)
	}

	// A second key that is assigned but absent from the host.
	drifted, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "drifted-key", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: drifted.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}

	if h.canAuthenticate(t, target, principal, drifted.ID) {
		t.Fatal("the drifted key already works; the test set itself up wrong")
	}

	updated := *target
	updated.ReconcileMode = store.ReconcileAutoHeal
	if _, err := h.targets.Update(ctx, &updated); err != nil {
		t.Fatalf("switching the target to auto-heal: %v", err)
	}

	result, err := h.reconcileSvc.Reconcile(ctx, h.subject, target.ID)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !result.Principals[0].Healed {
		t.Fatalf("the principal was not healed: %+v", result.Principals[0])
	}

	if !h.canAuthenticate(t, target, principal, drifted.ID) {
		t.Error("auto-heal did not restore the missing key")
	}
	if !h.canAuthenticate(t, target, principal, anchor.ID) {
		t.Error("auto-heal removed a key it should have left alone")
	}
}

// Adoption brings a key found on a host under management, honestly: SKM does
// not hold the private half, so the record says so.
func TestAdoptBringsAKeyUnderManagement(t *testing.T) {
	h := newReconcileHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, principal := h.provisionAt(t, "adopt-host", fleet[1], "skmtest", false)

	anchor, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "adopt-anchor", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: anchor.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID,
		DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatal(err)
	}

	stranger := h.addKeyByHand(t, target, principal, "contractor@laptop")

	if _, err := h.reconcileSvc.Reconcile(ctx, h.subject, target.ID); err != nil {
		t.Fatal(err)
	}

	inventory, err := h.reconcileSvc.ListDiscovered(ctx, h.subject, store.DiscoveryFilter{
		States: []string{store.DiscoveredUnmanaged},
	})
	if err != nil {
		t.Fatal(err)
	}
	var found *store.DiscoveredKey
	for i := range inventory {
		if inventory[i].Fingerprint == stranger {
			found = &inventory[i]
		}
	}
	if found == nil {
		t.Fatalf("the hand-added key is not in the inventory: %+v", inventory)
	}

	adopted, err := h.reconcileSvc.Adopt(ctx, h.subject, found.ID, "contractor-key")
	if err != nil {
		t.Fatalf("Adopt: %v", err)
	}

	if adopted.HasPrivateKey {
		t.Error("the adopted key claims a private half SKM does not hold")
	}
	if adopted.KeyClass != store.KeyClassDiscovered {
		t.Errorf("KeyClass = %q, want discovered", adopted.KeyClass)
	}
	if adopted.Fingerprint != stranger {
		t.Errorf("Fingerprint = %q, want %q", adopted.Fingerprint, stranger)
	}
	if adopted.Algorithm != "ed25519" {
		t.Errorf("Algorithm = %q, want the normalised name", adopted.Algorithm)
	}

	// A second reconcile must not report it as unmanaged any more.
	second, err := h.reconcileSvc.Reconcile(ctx, h.subject, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, fingerprint := range second.Principals[0].Unmanaged {
		if fingerprint == stranger {
			t.Error("the adopted key is still reported as unmanaged")
		}
	}

	// An adopted key cannot be rotated: SKM cannot generate a successor anyone
	// could actually use.
	_, err = h.rotationSvc.Plan(ctx, h.subject, PlanRequest{KeyID: adopted.ID})
	if err == nil {
		t.Log("note: planning a rotation for an adopted key was accepted; " +
			"the successor would be usable, but the old key cannot be verified by SKM")
	}
}

func TestAdoptIsRefusedTwice(t *testing.T) {
	h := newReconcileHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, principal := h.provisionAt(t, "twice-host", fleet[0], "skmtest", false)

	anchor, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "twice-anchor", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: anchor.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID,
		DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatal(err)
	}

	h.addKeyByHand(t, target, principal, "duplicate@laptop")
	if _, err := h.reconcileSvc.Reconcile(ctx, h.subject, target.ID); err != nil {
		t.Fatal(err)
	}

	inventory, err := h.reconcileSvc.ListDiscovered(ctx, h.subject, store.DiscoveryFilter{
		States: []string{store.DiscoveredUnmanaged},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory) == 0 {
		t.Fatal("nothing was discovered")
	}

	if _, err := h.reconcileSvc.Adopt(ctx, h.subject, inventory[0].ID, ""); err != nil {
		t.Fatalf("first Adopt: %v", err)
	}
	if _, err := h.reconcileSvc.Adopt(ctx, h.subject, inventory[0].ID, ""); err == nil {
		t.Error("the same key was adopted twice")
	}
}

func TestIgnoreRemovesAKeyFromTheFindings(t *testing.T) {
	h := newReconcileHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, principal := h.provisionAt(t, "ignore-host", fleet[1], "skmtest", false)

	anchor, err := h.keySvc.Generate(ctx, h.subject, GenerateRequest{
		Name: "ignore-anchor", Algorithm: "ed25519", Tags: []string{"fleet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.assigns.Upsert(ctx, &store.Assignment{
		KeyID: anchor.ID, TargetID: target.ID, PrincipalID: principal.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deploySvc.Deploy(ctx, h.subject, target.ID, principal.ID,
		DeployOptions{VerifyAuth: true}); err != nil {
		t.Fatal(err)
	}

	h.addKeyByHand(t, target, principal, "known@backup-system")
	if _, err := h.reconcileSvc.Reconcile(ctx, h.subject, target.ID); err != nil {
		t.Fatal(err)
	}

	unmanaged, err := h.reconcileSvc.ListDiscovered(ctx, h.subject, store.DiscoveryFilter{
		States: []string{store.DiscoveredUnmanaged},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(unmanaged) == 0 {
		t.Fatal("nothing was discovered")
	}

	if _, err := h.reconcileSvc.Ignore(ctx, h.subject, unmanaged[0].ID); err != nil {
		t.Fatalf("Ignore: %v", err)
	}

	after, err := h.reconcileSvc.ListDiscovered(ctx, h.subject, store.DiscoveryFilter{
		States: []string{store.DiscoveredUnmanaged},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range after {
		if d.ID == unmanaged[0].ID {
			t.Error("an ignored key is still listed as an unresolved finding")
		}
	}
}

func TestReconcileIsRefusedWhenDisabled(t *testing.T) {
	h := newReconcileHarness(t)
	ctx := context.Background()
	fleet := fleetAddrs()

	target, _ := h.provisionAt(t, "disabled-host", fleet[0], "skmtest", false)

	updated := *target
	updated.ReconcileMode = store.ReconcileDisabled
	if _, err := h.targets.Update(ctx, &updated); err != nil {
		t.Fatal(err)
	}

	_, err := h.reconcileSvc.Reconcile(ctx, h.subject, target.ID)
	if err == nil {
		t.Fatal("Reconcile ran against a target that has it disabled")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("the refusal should say why: %v", err)
	}
}
