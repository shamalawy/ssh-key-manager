package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/dbtest"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

func repos(t *testing.T) (*Keys, *Targets, *Assignments, *Snapshots, *Changesets) {
	t.Helper()
	pool := dbtest.New(t)
	return NewKeys(pool), NewTargets(pool), NewAssignments(pool), NewSnapshots(pool), NewChangesets(pool)
}

func sampleKey(name, fingerprint string) *Key {
	return &Key{
		Name:          name,
		Algorithm:     "ed25519",
		PublicKey:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + fingerprint,
		Fingerprint:   fingerprint,
		Comment:       "skm:test",
		Status:        KeyStatusActive,
		HasPrivateKey: true,
		Compliant:     true,
	}
}

func sampleTarget(name string) *Target {
	return &Target{
		Name:      name,
		Kind:      "linux",
		Connector: "linux",
		Address:   "10.0.0.1",
		Port:      22,
		Enabled:   true,
		Tags:      []string{"prod"},
	}
}

func TestKeyCRUD(t *testing.T) {
	keys, _, _, _, _ := repos(t)
	ctx := context.Background()

	created, err := keys.Create(ctx, sampleKey("web-fleet", "SHA256:aaa"), nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Fatal("created key has no ID")
	}
	if created.Generation != 1 {
		t.Errorf("Generation = %d, want 1", created.Generation)
	}
	if created.TenantID != DefaultTenantID {
		t.Errorf("TenantID = %s, want the default tenant", created.TenantID)
	}

	got, err := keys.Get(ctx, DefaultTenantID, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "web-fleet" {
		t.Errorf("Name = %q, want web-fleet", got.Name)
	}

	byFP, err := keys.GetByFingerprint(ctx, DefaultTenantID, "SHA256:aaa")
	if err != nil {
		t.Fatalf("GetByFingerprint: %v", err)
	}
	if byFP.ID != created.ID {
		t.Error("GetByFingerprint returned a different key")
	}

	expires := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	updated, err := keys.Update(ctx, DefaultTenantID, created.ID, "renamed", "a description", []string{"prod", "web"}, &expires)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "renamed" || len(updated.Tags) != 2 {
		t.Errorf("update did not apply: %+v", updated)
	}

	if err := keys.Delete(ctx, DefaultTenantID, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := keys.Get(ctx, DefaultTenantID, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after delete = %v, want ErrNotFound", err)
	}
}

// A fingerprint uniquely identifies a keypair, so registering one twice is a
// conflict rather than a second key.
func TestDuplicateFingerprintIsRejected(t *testing.T) {
	keys, _, _, _, _ := repos(t)
	ctx := context.Background()

	if _, err := keys.Create(ctx, sampleKey("first", "SHA256:dup"), nil); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := keys.Create(ctx, sampleKey("second", "SHA256:dup"), nil)
	if !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate fingerprint = %v, want ErrConflict", err)
	}
}

// Key material must be written in the same transaction as the key row. A key
// that exists without its private half looks usable but cannot authenticate.
func TestKeyMaterialRoundTrip(t *testing.T) {
	keys, _, _, _, _ := repos(t)
	ctx := context.Background()

	v := vault.New()
	kek := make([]byte, vault.KeyLen)
	for i := range kek {
		kek[i] = byte(i)
	}
	if err := v.Unseal(1, kek); err != nil {
		t.Fatalf("Unseal: %v", err)
	}

	const secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret material\n-----END OPENSSH PRIVATE KEY-----"

	k := sampleKey("with-material", "SHA256:mat")
	k.ID = uuid.New()

	sealed, err := v.Encrypt([]byte(secret), []byte(k.ID.String()))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	created, err := keys.Create(ctx, k, sealed)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	loaded, err := keys.LoadMaterial(ctx, created.ID)
	if err != nil {
		t.Fatalf("LoadMaterial: %v", err)
	}

	plaintext, err := v.Decrypt(loaded, []byte(created.ID.String()))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plaintext) != secret {
		t.Error("decrypted material does not match what was stored")
	}

	// Destroying material must leave the key row and its history behind.
	if err := keys.DestroyMaterial(ctx, DefaultTenantID, created.ID); err != nil {
		t.Fatalf("DestroyMaterial: %v", err)
	}
	if _, err := keys.LoadMaterial(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("LoadMaterial after destroy = %v, want ErrNotFound", err)
	}

	after, err := keys.Get(ctx, DefaultTenantID, created.ID)
	if err != nil {
		t.Fatalf("Get after destroy: %v", err)
	}
	if after.Status != KeyStatusDestroyed {
		t.Errorf("status = %q, want destroyed", after.Status)
	}
	if after.HasPrivateKey {
		t.Error("HasPrivateKey is still true after destroying material")
	}
}

// The AAD binds ciphertext to its key row, so material moved between rows must
// fail to decrypt.
func TestKeyMaterialIsBoundToItsKey(t *testing.T) {
	keys, _, _, _, _ := repos(t)
	ctx := context.Background()

	v := vault.New()
	kek := make([]byte, vault.KeyLen)
	if err := v.Unseal(1, kek); err != nil {
		t.Fatalf("Unseal: %v", err)
	}

	a := sampleKey("key-a", "SHA256:a")
	a.ID = uuid.New()
	sealed, err := v.Encrypt([]byte("private material"), []byte(a.ID.String()))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := keys.Create(ctx, a, sealed); err != nil {
		t.Fatalf("Create: %v", err)
	}

	b := sampleKey("key-b", "SHA256:b")
	b.ID = uuid.New()
	if _, err := keys.Create(ctx, b, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Transplant A's material onto B, as an attacker with write access would.
	stolen, err := keys.LoadMaterial(ctx, a.ID)
	if err != nil {
		t.Fatalf("LoadMaterial: %v", err)
	}
	if err := keys.StoreMaterial(ctx, b.ID, stolen); err != nil {
		t.Fatalf("StoreMaterial: %v", err)
	}

	replanted, err := keys.LoadMaterial(ctx, b.ID)
	if err != nil {
		t.Fatalf("LoadMaterial: %v", err)
	}
	if _, err := v.Decrypt(replanted, []byte(b.ID.String())); err == nil {
		t.Fatal("transplanted key material decrypted under a different key's identity")
	}
}

func TestKeyFiltering(t *testing.T) {
	keys, _, _, _, _ := repos(t)
	ctx := context.Background()

	active := sampleKey("active-key", "SHA256:f1")
	active.Tags = []string{"prod"}
	if _, err := keys.Create(ctx, active, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	retired := sampleKey("retired-key", "SHA256:f2")
	retired.Status = KeyStatusRetired
	retired.Tags = []string{"dev"}
	if _, err := keys.Create(ctx, retired, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	expiring := sampleKey("expiring-key", "SHA256:f3")
	soon := time.Now().Add(24 * time.Hour)
	expiring.ExpiresAt = &soon
	if _, err := keys.Create(ctx, expiring, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	tests := []struct {
		name   string
		filter KeyFilter
		want   int
	}{
		{"all", KeyFilter{}, 3},
		{"by status", KeyFilter{Statuses: []string{KeyStatusActive}}, 2},
		{"by two statuses", KeyFilter{Statuses: []string{KeyStatusActive, KeyStatusRetired}}, 3},
		{"by tag", KeyFilter{Tags: []string{"prod"}}, 1},
		{"by other tag", KeyFilter{Tags: []string{"dev"}}, 1},
		{"by unmatched tag", KeyFilter{Tags: []string{"nope"}}, 0},
		{"expiring within a week", KeyFilter{ExpiringIn: 7 * 24 * time.Hour}, 1},
		{"search by name", KeyFilter{Search: "retired"}, 1},
		{"search by fingerprint", KeyFilter{Search: "f3"}, 1},
		{"limit", KeyFilter{Limit: 2}, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := keys.List(ctx, tc.filter)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("List returned %d keys, want %d", len(got), tc.want)
			}
		})
	}
}

func TestKeyStatusTransitionsStampTimestamps(t *testing.T) {
	keys, _, _, _, _ := repos(t)
	ctx := context.Background()

	created, err := keys.Create(ctx, sampleKey("lifecycle", "SHA256:life"), nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	activated, err := keys.SetStatus(ctx, DefaultTenantID, created.ID, KeyStatusActive)
	if err != nil {
		t.Fatalf("SetStatus(active): %v", err)
	}
	if activated.ActivatedAt == nil {
		t.Error("activated_at was not stamped on activation")
	}

	retired, err := keys.SetStatus(ctx, DefaultTenantID, created.ID, KeyStatusRetired)
	if err != nil {
		t.Fatalf("SetStatus(retired): %v", err)
	}
	if retired.RetiredAt == nil {
		t.Error("retired_at was not stamped on retirement")
	}
	if retired.ActivatedAt == nil {
		t.Error("activated_at was cleared when the key retired")
	}
}

func TestTargetAndPrincipalCRUD(t *testing.T) {
	_, targets, _, _, _ := repos(t)
	ctx := context.Background()

	created, err := targets.Create(ctx, sampleTarget("web-01"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ReconcileMode != ReconcileReportOnly {
		t.Errorf("ReconcileMode = %q, want report_only by default", created.ReconcileMode)
	}
	if created.Health != HealthUnknown {
		t.Errorf("Health = %q, want unknown", created.Health)
	}

	if _, err := targets.Create(ctx, sampleTarget("web-01")); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate target name = %v, want ErrConflict", err)
	}

	if err := targets.SetHostKeyPin(ctx, DefaultTenantID, created.ID, "SHA256:hostkey"); err != nil {
		t.Fatalf("SetHostKeyPin: %v", err)
	}
	if err := targets.SetHealth(ctx, DefaultTenantID, created.ID, HealthHealthy, "reachable"); err != nil {
		t.Fatalf("SetHealth: %v", err)
	}
	if err := targets.SetDrift(ctx, DefaultTenantID, created.ID, DriftInSync); err != nil {
		t.Fatalf("SetDrift: %v", err)
	}

	got, err := targets.Get(ctx, DefaultTenantID, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HostKeyPin != "SHA256:hostkey" {
		t.Errorf("HostKeyPin = %q", got.HostKeyPin)
	}
	if got.Health != HealthHealthy || got.LastSeenAt == nil {
		t.Errorf("health not recorded: %+v", got)
	}
	if got.DriftState != DriftInSync || got.LastReconciledAt == nil {
		t.Errorf("drift not recorded: %+v", got)
	}

	principal, err := targets.CreatePrincipal(ctx, &Principal{
		TargetID: created.ID, Username: "deploy", UseSudo: true, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}

	if _, err := targets.CreatePrincipal(ctx, &Principal{
		TargetID: created.ID, Username: "deploy",
	}); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate principal = %v, want ErrConflict", err)
	}

	list, err := targets.ListPrincipals(ctx, created.ID)
	if err != nil {
		t.Fatalf("ListPrincipals: %v", err)
	}
	if len(list) != 1 || list[0].Username != "deploy" {
		t.Errorf("ListPrincipals = %+v", list)
	}

	// Deleting a target must cascade to its principals.
	if err := targets.Delete(ctx, DefaultTenantID, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := targets.GetPrincipal(ctx, principal.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("principal survived its target's deletion: %v", err)
	}
}

func TestTargetConfigRoundTrip(t *testing.T) {
	_, targets, _, _, _ := repos(t)
	ctx := context.Background()

	tgt := sampleTarget("configured")
	tgt.Config = map[string]any{
		"file_mode":            "640",
		"authorized_keys_path": "/etc/ssh/keys/deploy",
		"vendor":               "cisco_ios",
		"nested":               map[string]any{"a": float64(1)},
	}

	created, err := targets.Create(ctx, tgt)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := targets.Get(ctx, DefaultTenantID, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Config["file_mode"] != "640" {
		t.Errorf("file_mode = %v", got.Config["file_mode"])
	}
	if got.Config["authorized_keys_path"] != "/etc/ssh/keys/deploy" {
		t.Errorf("authorized_keys_path = %v", got.Config["authorized_keys_path"])
	}
}

func TestAssignmentLifecycle(t *testing.T) {
	keys, targets, assignments, _, _ := repos(t)
	ctx := context.Background()

	key, err := keys.Create(ctx, sampleKey("deploy-key", "SHA256:assign"), nil)
	if err != nil {
		t.Fatalf("creating key: %v", err)
	}
	target, err := targets.Create(ctx, sampleTarget("host-01"))
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}
	principal, err := targets.CreatePrincipal(ctx, &Principal{
		TargetID: target.ID, Username: "root", Enabled: true,
	})
	if err != nil {
		t.Fatalf("creating principal: %v", err)
	}

	assignment, err := assignments.Upsert(ctx, &Assignment{
		KeyID:       key.ID,
		TargetID:    target.ID,
		PrincipalID: principal.ID,
		Options:     []string{"no-pty"},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if assignment.DesiredState != StatePresent {
		t.Errorf("DesiredState = %q, want present", assignment.DesiredState)
	}
	if assignment.ActualState != StateUnknown {
		t.Errorf("ActualState = %q, want unknown before deployment", assignment.ActualState)
	}
	if assignment.InSync() {
		t.Error("a never-deployed assignment reported in sync")
	}

	// Upserting again must update rather than duplicate.
	again, err := assignments.Upsert(ctx, &Assignment{
		KeyID: key.ID, TargetID: target.ID, PrincipalID: principal.ID,
		Options: []string{"no-pty", "no-agent-forwarding"},
	})
	if err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if again.ID != assignment.ID {
		t.Error("re-upserting created a duplicate assignment")
	}
	if len(again.Options) != 2 {
		t.Errorf("options not updated: %v", again.Options)
	}

	if err := assignments.RecordDeployment(ctx, assignment.ID, StatePresent, ""); err != nil {
		t.Fatalf("RecordDeployment: %v", err)
	}
	if err := assignments.RecordAuthVerified(ctx, assignment.ID); err != nil {
		t.Fatalf("RecordAuthVerified: %v", err)
	}

	deployed, err := assignments.Get(ctx, DefaultTenantID, assignment.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !deployed.InSync() {
		t.Error("a deployed assignment is not reported in sync")
	}
	if deployed.DeployedAt == nil || deployed.AuthVerifiedAt == nil {
		t.Errorf("deployment timestamps not recorded: %+v", deployed)
	}

	details, err := assignments.List(ctx, AssignmentFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(details) != 1 {
		t.Fatalf("List returned %d assignments, want 1", len(details))
	}
	d := details[0]
	if d.KeyName != "deploy-key" || d.TargetName != "host-01" || d.Username != "root" {
		t.Errorf("joined names are wrong: %+v", d)
	}

	// Drift filtering feeds the reconciler's work list.
	drifted, err := assignments.List(ctx, AssignmentFilter{OnlyDrifted: true})
	if err != nil {
		t.Fatalf("List(drifted): %v", err)
	}
	if len(drifted) != 0 {
		t.Errorf("an in-sync assignment appeared in the drift list")
	}

	if err := assignments.RecordDeployment(ctx, assignment.ID, StateError, "connection refused"); err != nil {
		t.Fatalf("RecordDeployment(error): %v", err)
	}
	drifted, err = assignments.List(ctx, AssignmentFilter{OnlyDrifted: true})
	if err != nil {
		t.Fatalf("List(drifted): %v", err)
	}
	if len(drifted) != 1 {
		t.Errorf("a failed assignment did not appear in the drift list")
	}
}

func TestSnapshotAndChangeset(t *testing.T) {
	_, targets, _, snapshots, changesets := repos(t)
	ctx := context.Background()

	target, err := targets.Create(ctx, sampleTarget("snapshot-host"))
	if err != nil {
		t.Fatalf("creating target: %v", err)
	}

	cs, err := changesets.Create(ctx, &Changeset{
		Kind: ChangesetDeploy, Summary: "deploy web key to snapshot-host",
	})
	if err != nil {
		t.Fatalf("creating changeset: %v", err)
	}
	if cs.State != ChangesetOpen {
		t.Errorf("State = %q, want open", cs.State)
	}

	content := []byte("ssh-ed25519 AAAA original\n")
	snap, err := snapshots.Create(ctx, &Snapshot{
		TargetID:    target.ID,
		ChangesetID: &cs.ID,
		RawContent:  content,
		Checksum:    "abc123",
		KeyCount:    1,
	})
	if err != nil {
		t.Fatalf("creating snapshot: %v", err)
	}

	got, err := snapshots.Get(ctx, DefaultTenantID, snap.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.RawContent) != string(content) {
		t.Errorf("snapshot content changed: %q", got.RawContent)
	}

	// Inverse operations are appended in the database so a crash mid-change
	// still leaves a rollback path.
	if err := changesets.AppendInverse(ctx, cs.ID, map[string]any{
		"op": "restore_snapshot", "snapshot_id": snap.ID.String(),
	}); err != nil {
		t.Fatalf("AppendInverse: %v", err)
	}
	if err := changesets.AppendInverse(ctx, cs.ID, map[string]any{
		"op": "restore_snapshot", "snapshot_id": uuid.New().String(),
	}); err != nil {
		t.Fatalf("AppendInverse: %v", err)
	}

	loaded, err := changesets.Get(ctx, DefaultTenantID, cs.ID)
	if err != nil {
		t.Fatalf("Get changeset: %v", err)
	}
	if len(loaded.InverseOps) != 2 {
		t.Errorf("got %d inverse operations, want 2", len(loaded.InverseOps))
	}

	if err := changesets.SetState(ctx, cs.ID, ChangesetCommitted); err != nil {
		t.Fatalf("SetState: %v", err)
	}
	committed, err := changesets.Get(ctx, DefaultTenantID, cs.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if committed.State != ChangesetCommitted || committed.ClosedAt == nil {
		t.Errorf("changeset not closed: %+v", committed)
	}

	list, err := snapshots.ListForTarget(ctx, DefaultTenantID, target.ID, 10)
	if err != nil {
		t.Fatalf("ListForTarget: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("ListForTarget returned %d snapshots, want 1", len(list))
	}
	// The listing omits content so it stays cheap.
	if len(list[0].RawContent) != 0 {
		t.Error("the snapshot listing included raw content")
	}
}

func TestMaterialNeedingRewrap(t *testing.T) {
	keys, _, _, _, _ := repos(t)
	ctx := context.Background()

	for i, fp := range []string{"SHA256:r1", "SHA256:r2"} {
		k := sampleKey("rewrap-"+fp, fp)
		k.ID = uuid.New()
		sealed := &vault.Sealed{
			KEKVersion: 1,
			WrappedDEK: []byte{byte(i)},
			Ciphertext: []byte{byte(i)},
		}
		if _, err := keys.Create(ctx, k, sealed); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	stale, err := keys.MaterialNeedingRewrap(ctx, 2, 100)
	if err != nil {
		t.Fatalf("MaterialNeedingRewrap: %v", err)
	}
	if len(stale) != 2 {
		t.Errorf("got %d keys needing rewrap, want 2", len(stale))
	}

	none, err := keys.MaterialNeedingRewrap(ctx, 1, 100)
	if err != nil {
		t.Fatalf("MaterialNeedingRewrap: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("got %d keys needing rewrap at the current version, want 0", len(none))
	}
}
