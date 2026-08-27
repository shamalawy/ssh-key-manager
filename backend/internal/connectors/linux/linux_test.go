package linux

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/keys"
	"github.com/hamalawy/ssh-key-manager/backend/internal/sshx"
)

// testHost returns the address and port of the disposable sshd container,
// skipping when it is not running so unit tests still work standalone.
func testHost(t *testing.T) (string, int) {
	t.Helper()

	addr := os.Getenv("SKM_TEST_SSH_ADDR")
	if addr == "" {
		t.Skip("SKM_TEST_SSH_ADDR not set; skipping live sshd integration test")
	}

	host, portStr, found := strings.Cut(addr, ":")
	if !found {
		t.Fatalf("SKM_TEST_SSH_ADDR %q must be host:port", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("SKM_TEST_SSH_ADDR has a non-numeric port: %v", err)
	}
	return host, port
}

// fixture builds a request against the live container. principal names the
// account whose keys are managed; when it differs from the login account the
// sudo path is exercised.
func fixture(t *testing.T, principal string, useSudo bool) (*Connector, connectors.Request) {
	t.Helper()
	host, port := testHost(t)

	req := connectors.Request{
		Target: &connectors.Target{
			ID:      uuid.New(),
			Name:    "test-host",
			Kind:    "linux",
			Address: host,
			Port:    port,
			Config:  map[string]any{},
		},
		Principal: &connectors.Principal{
			ID:       uuid.New(),
			Username: principal,
			UseSudo:  useSudo,
		},
		Credential: &connectors.Credential{
			Kind:     "ssh_password",
			Username: "skmtest",
			Password: "testpass",
		},
	}
	return New(), req
}

// reset clears the principal's authorized_keys so each test starts clean.
func reset(t *testing.T, principal string) {
	t.Helper()
	if os.Getenv("SKM_TEST_SSH_ADDR") == "" {
		return
	}
	container := os.Getenv("SKM_TEST_SSH_CONTAINER")
	if container == "" {
		return
	}
	// Handled by the caller's docker exec in the harness; nothing to do here.
}

func newKey(t *testing.T, comment string) *keys.KeyPair {
	t.Helper()
	kp, err := keys.Generate(keys.Ed25519, comment)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return kp
}

func desired(kp *keys.KeyPair, options ...string) connectors.DesiredKey {
	return connectors.DesiredKey{
		PublicLine:  kp.PublicLine,
		Fingerprint: kp.Fingerprint,
		Options:     options,
	}
}

func TestProbeReachesHost(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()

	res, err := c.Probe(ctx, req)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !res.Reachable {
		t.Fatalf("target reported unreachable: %s", res.Message)
	}
	if !strings.HasPrefix(res.HostKeyPin, "SHA256:") {
		t.Errorf("HostKeyPin = %q, want a SHA256 fingerprint", res.HostKeyPin)
	}
	if !res.HostKeyIsNew {
		t.Error("HostKeyIsNew = false on a first connection with no stored pin")
	}
	if res.Detail["connected_as"] != "skmtest" {
		t.Errorf("connected_as = %q, want skmtest", res.Detail["connected_as"])
	}
}

// A pinned host key that does not match must abort the connection. This is the
// defence against being redirected to an attacker's host.
func TestHostKeyMismatchIsRefused(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()

	req.Target.HostKeyPin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	if _, err := c.Probe(ctx, req); err == nil {
		t.Fatal("Probe succeeded against a mismatched host key pin")
	} else if !strings.Contains(err.Error(), "host key") {
		t.Errorf("error did not mention the host key: %v", err)
	}
}

// The correct pin must be accepted, so pinning does not break normal operation.
func TestCorrectHostKeyPinIsAccepted(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()

	first, err := c.Probe(ctx, req)
	if err != nil {
		t.Fatalf("initial Probe: %v", err)
	}

	req.Target.HostKeyPin = first.HostKeyPin
	second, err := c.Probe(ctx, req)
	if err != nil {
		t.Fatalf("Probe with a correct pin: %v", err)
	}
	if second.HostKeyIsNew {
		t.Error("HostKeyIsNew = true when a matching pin was supplied")
	}
}

// The full deploy path: place a key, confirm it is listed, and — the part that
// actually matters — confirm the private half can authenticate.
func TestDeployThenAuthenticate(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()
	kp := newKey(t, "skm:deploy-test")

	res, err := c.Apply(ctx, req, []connectors.DesiredKey{desired(kp)}, connectors.DefaultApplyOptions())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Changed {
		t.Fatal("Apply reported no change when deploying a new key")
	}
	if len(res.Added) != 1 || res.Added[0] != kp.Fingerprint {
		t.Errorf("Added = %v, want [%s]", res.Added, kp.Fingerprint)
	}
	if res.Diff == "" {
		t.Error("Apply produced no diff")
	}

	listed, err := c.List(ctx, req)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !containsFingerprint(listed, kp.Fingerprint) {
		t.Fatalf("deployed key is not present; got %d keys", len(listed))
	}

	// The verification gate.
	if err := c.Verify(ctx, req, kp.PrivatePEM); err != nil {
		t.Fatalf("Verify with the deployed private key failed: %v", err)
	}
}

// Verify must fail for a key that was never deployed, or the gate is worthless.
func TestVerifyRejectsUndeployedKey(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()

	stranger := newKey(t, "skm:not-deployed")
	if err := c.Verify(ctx, req, stranger.PrivatePEM); err == nil {
		t.Fatal("Verify succeeded with a key that was never deployed")
	}
}

// Applying the same desired state twice must be a no-op, so a converged
// deployment does not rewrite the file, take a snapshot, or emit an audit event.
func TestApplyIsIdempotent(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()
	kp := newKey(t, "skm:idempotent")

	if _, err := c.Apply(ctx, req, []connectors.DesiredKey{desired(kp)}, connectors.DefaultApplyOptions()); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	second, err := c.Apply(ctx, req, []connectors.DesiredKey{desired(kp)}, connectors.DefaultApplyOptions())
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if second.Changed {
		t.Error("re-applying identical state reported a change")
	}
	if second.Diff != "" {
		t.Errorf("re-applying identical state produced a diff:\n%s", second.Diff)
	}
}

// A dry run must compute the change without touching the target.
func TestDryRunDoesNotWrite(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()
	kp := newKey(t, "skm:dry-run")

	before, err := c.Snapshot(ctx, req)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	opts := connectors.DefaultApplyOptions()
	opts.DryRun = true
	res, err := c.Apply(ctx, req, []connectors.DesiredKey{desired(kp)}, opts)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Changed {
		t.Error("dry run reported no change for a new key")
	}
	if !res.DryRun {
		t.Error("result does not record that it was a dry run")
	}

	after, err := c.Snapshot(ctx, req)
	if err != nil {
		t.Fatalf("Snapshot after dry run: %v", err)
	}
	if after.Checksum != before.Checksum {
		t.Error("dry run modified the target")
	}
	if err := c.Verify(ctx, req, kp.PrivatePEM); err == nil {
		t.Error("a dry-run key authenticated; it was actually deployed")
	}
}

// The core promise: content SKM did not put there is preserved exactly.
func TestUnmanagedContentIsPreserved(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()

	handAdded := newKey(t, "operator@laptop")
	managed := newKey(t, "skm:managed")

	// Seed the file with a comment, a hand-added key, and an unparseable line.
	seed := "# added by hand, do not remove\n" +
		handAdded.PublicLine + "\n" +
		"this line is not a valid key\n"
	if err := c.Restore(ctx, req, &connectors.Snapshot{
		Kind: "authorized_keys", Content: []byte(seed), Existed: true,
	}); err != nil {
		t.Fatalf("seeding file: %v", err)
	}

	opts := connectors.DefaultApplyOptions()
	opts.Prune = true
	opts.ManagedFingerprints = []string{managed.Fingerprint}
	if _, err := c.Apply(ctx, req, []connectors.DesiredKey{desired(managed)}, opts); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	after, err := c.Snapshot(ctx, req)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	content := string(after.Content)

	for _, want := range []string{
		"# added by hand, do not remove",
		handAdded.PublicLine,
		"this line is not a valid key",
		managed.PublicLine,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("file lost %q:\n%s", want, content)
		}
	}

	// The hand-added key must still work.
	if err := c.Verify(ctx, req, handAdded.PrivatePEM); err != nil {
		t.Errorf("hand-added key stopped working after a managed deployment: %v", err)
	}
}

// The lockout guard: an Apply that would empty the file is refused outright.
func TestRefusesToRemoveLastKey(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()
	only := newKey(t, "skm:last-key")

	// Start from a file containing exactly one managed key.
	if err := c.Restore(ctx, req, &connectors.Snapshot{
		Kind: "authorized_keys", Content: []byte(only.PublicLine + "\n"), Existed: true,
	}); err != nil {
		t.Fatalf("seeding file: %v", err)
	}

	opts := connectors.DefaultApplyOptions()
	opts.Prune = true
	opts.PreserveUnmanaged = false
	opts.ManagedFingerprints = []string{only.Fingerprint}

	_, err := c.Apply(ctx, req, nil, opts)
	if err == nil {
		t.Fatal("Apply emptied authorized_keys; the lockout guard did not fire")
	}
	if !strings.Contains(err.Error(), "last remaining key") {
		t.Errorf("unexpected error: %v", err)
	}

	// The file must be untouched, and the key must still authenticate.
	if err := c.Verify(ctx, req, only.PrivatePEM); err != nil {
		t.Errorf("the refused Apply still damaged the file: %v", err)
	}
}

// AllowEmpty is the deliberate escape hatch for decommissioning.
func TestAllowEmptyPermitsFullRemoval(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()
	kp := newKey(t, "skm:decommission")

	if err := c.Restore(ctx, req, &connectors.Snapshot{
		Kind: "authorized_keys", Content: []byte(kp.PublicLine + "\n"), Existed: true,
	}); err != nil {
		t.Fatalf("seeding file: %v", err)
	}

	opts := connectors.DefaultApplyOptions()
	opts.Prune = true
	opts.PreserveUnmanaged = false
	opts.AllowEmpty = true
	opts.ManagedFingerprints = []string{kp.Fingerprint}

	if _, err := c.Apply(ctx, req, nil, opts); err != nil {
		t.Fatalf("Apply with AllowEmpty: %v", err)
	}

	listed, err := c.List(ctx, req)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("expected no keys after an AllowEmpty prune, got %d", len(listed))
	}
}

// Snapshot and Restore must reproduce the original bytes exactly, or rollback
// is not really rollback.
func TestSnapshotRestoreIsByteExact(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()

	original := newKey(t, "skm:original")
	seed := "# original state\n" + original.PublicLine + "\n\n# trailing comment\n"

	if err := c.Restore(ctx, req, &connectors.Snapshot{
		Kind: "authorized_keys", Content: []byte(seed), Existed: true,
	}); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	snap, err := c.Snapshot(ctx, req)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if string(snap.Content) != seed {
		t.Fatalf("snapshot does not match what was written:\ngot:  %q\nwant: %q", snap.Content, seed)
	}

	// Mutate, then roll back.
	intruder := newKey(t, "skm:intruder")
	if _, err := c.Apply(ctx, req, []connectors.DesiredKey{desired(intruder)}, connectors.DefaultApplyOptions()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := c.Restore(ctx, req, snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	restored, err := c.Snapshot(ctx, req)
	if err != nil {
		t.Fatalf("Snapshot after restore: %v", err)
	}
	if string(restored.Content) != seed {
		t.Errorf("restore was not byte-exact:\ngot:  %q\nwant: %q", restored.Content, seed)
	}
	if restored.Checksum != snap.Checksum {
		t.Errorf("checksum after restore = %s, want %s", restored.Checksum, snap.Checksum)
	}
	if err := c.Verify(ctx, req, intruder.PrivatePEM); err == nil {
		t.Error("the rolled-back key still authenticates")
	}
}

// A corrupted snapshot must be refused rather than written.
func TestRestoreRejectsCorruptedSnapshot(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()

	err := c.Restore(ctx, req, &connectors.Snapshot{
		Kind:     "authorized_keys",
		Content:  []byte("ssh-ed25519 AAAA corrupted\n"),
		Checksum: "0000000000000000000000000000000000000000000000000000000000000000",
		Existed:  true,
	})
	if err == nil {
		t.Fatal("Restore accepted a snapshot whose checksum does not match its content")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("unexpected error: %v", err)
	}
}

// authorized_keys options must survive deployment, since `from=` and
// `command=` are load-bearing restrictions.
func TestOptionsArePreserved(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()
	kp := newKey(t, "skm:restricted")

	opts := []string{`from="10.0.0.0/8,192.168.0.0/16"`, "no-pty", "no-agent-forwarding"}
	if _, err := c.Apply(ctx, req, []connectors.DesiredKey{desired(kp, opts...)}, connectors.DefaultApplyOptions()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	listed, err := c.List(ctx, req)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	for _, e := range listed {
		if e.Fingerprint != kp.Fingerprint {
			continue
		}
		got := strings.Join(e.Options, ",")
		want := strings.Join(opts, ",")
		if got != want {
			t.Errorf("options = %q, want %q", got, want)
		}
		return
	}
	t.Fatal("deployed key not found in the listing")
}

// Managing another account's keys requires sudo; this exercises that path and
// checks the resulting file is owned by the right user.
func TestSudoManagesAnotherAccount(t *testing.T) {
	c, req := fixture(t, "deploy", true)
	ctx := context.Background()
	kp := newKey(t, "skm:sudo-managed")

	if _, err := c.Apply(ctx, req, []connectors.DesiredKey{desired(kp)}, connectors.DefaultApplyOptions()); err != nil {
		t.Fatalf("Apply via sudo: %v", err)
	}

	// The key must authenticate as the managed account, not the login account.
	if err := c.Verify(ctx, req, kp.PrivatePEM); err != nil {
		t.Fatalf("key deployed via sudo does not authenticate as deploy: %v", err)
	}
}

// The whole point of the product, end to end: stage the new key alongside the
// old, verify it independently, then retire the old one — with both keys valid
// in between.
func TestStagedRotationKeepsAccessThroughout(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()

	oldKey := newKey(t, "skm:gen1")
	newGen := newKey(t, "skm:gen2")

	// Start with generation 1 in place.
	if err := c.Restore(ctx, req, &connectors.Snapshot{
		Kind: "authorized_keys", Content: []byte(oldKey.PublicLine + "\n"), Existed: true,
	}); err != nil {
		t.Fatalf("seeding generation 1: %v", err)
	}
	if err := c.Verify(ctx, req, oldKey.PrivatePEM); err != nil {
		t.Fatalf("generation 1 does not authenticate: %v", err)
	}

	// Stage: add generation 2 without removing generation 1.
	staged, err := c.Apply(ctx, req, []connectors.DesiredKey{
		desired(oldKey), desired(newGen),
	}, connectors.DefaultApplyOptions())
	if err != nil {
		t.Fatalf("staging generation 2: %v", err)
	}
	if !staged.Changed {
		t.Error("staging reported no change")
	}

	// Both must work during the soak window. This is what stops a rotation
	// from breaking anything still holding the old key.
	if err := c.Verify(ctx, req, oldKey.PrivatePEM); err != nil {
		t.Errorf("generation 1 stopped working while staged: %v", err)
	}
	if err := c.Verify(ctx, req, newGen.PrivatePEM); err != nil {
		t.Fatalf("generation 2 does not authenticate after staging: %v", err)
	}

	// Retire: remove generation 1 now that generation 2 is proven.
	opts := connectors.DefaultApplyOptions()
	opts.Prune = true
	opts.ManagedFingerprints = []string{oldKey.Fingerprint, newGen.Fingerprint}
	retired, err := c.Apply(ctx, req, []connectors.DesiredKey{desired(newGen)}, opts)
	if err != nil {
		t.Fatalf("retiring generation 1: %v", err)
	}
	if len(retired.Removed) != 1 || retired.Removed[0] != oldKey.Fingerprint {
		t.Errorf("Removed = %v, want [%s]", retired.Removed, oldKey.Fingerprint)
	}

	if err := c.Verify(ctx, req, newGen.PrivatePEM); err != nil {
		t.Errorf("generation 2 stopped working after retiring generation 1: %v", err)
	}
	if err := c.Verify(ctx, req, oldKey.PrivatePEM); err == nil {
		t.Error("generation 1 still authenticates after being retired")
	}
}

// A key whose material does not match its recorded fingerprint indicates
// database corruption or tampering, and must not be deployed.
func TestFingerprintMismatchIsRefused(t *testing.T) {
	c, req := fixture(t, "skmtest", false)
	ctx := context.Background()
	kp := newKey(t, "skm:mismatch")

	bad := connectors.DesiredKey{
		PublicLine:  kp.PublicLine,
		Fingerprint: "SHA256:thisIsNotTheRealFingerprint",
	}
	if _, err := c.Apply(ctx, req, []connectors.DesiredKey{bad}, connectors.DefaultApplyOptions()); err == nil {
		t.Fatal("Apply accepted a key whose fingerprint does not match its material")
	}
}

func TestValidate(t *testing.T) {
	c := New()
	ctx := context.Background()

	tests := []struct {
		name    string
		target  *connectors.Target
		wantErr bool
	}{
		{"valid", &connectors.Target{Name: "h", Address: "10.0.0.1", Port: 22}, false},
		{"valid with mode", &connectors.Target{Name: "h", Address: "10.0.0.1", Port: 22, Config: map[string]any{"file_mode": "640"}}, false},
		{"nil target", nil, true},
		{"no address", &connectors.Target{Name: "h", Port: 22}, true},
		{"bad port", &connectors.Target{Name: "h", Address: "10.0.0.1", Port: 99999}, true},
		{"bad file mode", &connectors.Target{Name: "h", Address: "10.0.0.1", Config: map[string]any{"file_mode": "notoctal"}}, true},
		{"bad file mode digits", &connectors.Target{Name: "h", Address: "10.0.0.1", Config: map[string]any{"file_mode": "899"}}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Validate(ctx, tc.target)
			if tc.wantErr && err == nil {
				t.Error("expected an error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestCapabilitiesAreComplete(t *testing.T) {
	caps := New().Capabilities()
	if !caps.CanList || !caps.CanSnapshot || !caps.CanRestore || !caps.CanVerify || !caps.SupportsOptions {
		t.Errorf("the linux connector should declare every capability, got %+v", caps)
	}
}

func TestRequestValidation(t *testing.T) {
	c := New()
	ctx := context.Background()

	if _, err := c.List(ctx, connectors.Request{}); err == nil {
		t.Error("List accepted an empty request")
	}
	if _, err := c.Apply(ctx, connectors.Request{Target: &connectors.Target{}}, nil, connectors.DefaultApplyOptions()); err == nil {
		t.Error("Apply accepted a request with no principal")
	}
}

// quote is a security boundary: every remote command embeds operator-supplied
// strings.
func TestQuote(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"simple", `'simple'`},
		{"/home/user/.ssh/authorized_keys", `'/home/user/.ssh/authorized_keys'`},
		{"has space", `'has space'`},
		{`it's`, `'it'\''s'`},
		{`; rm -rf /`, `'; rm -rf /'`},
		{`$(whoami)`, `'$(whoami)'`},
		{"`id`", "'`id`'"},
		{`a'; touch /tmp/pwned; '`, `'a'\''; touch /tmp/pwned; '\'''`},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := quote(tc.in); got != tc.want {
				t.Errorf("quote(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDecodeBase64ToleratesWrapping(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "aGVsbG8=", "hello"},
		{"newline wrapped", "aGVs\nbG8=", "hello"},
		{"crlf wrapped", "aGVs\r\nbG8=", "hello"},
		{"spaces", "aGVs bG8=", "hello"},
		{"empty", "", ""},
		{"only whitespace", "\n\n", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeBase64(tc.in)
			if err != nil {
				t.Fatalf("decodeBase64(%q): %v", tc.in, err)
			}
			if string(got) != tc.want {
				t.Errorf("decodeBase64(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestWrapAddsSudo(t *testing.T) {
	if got := wrap("echo hi", false); strings.Contains(got, "sudo") {
		t.Errorf("wrap without sudo included sudo: %q", got)
	}
	got := wrap("echo hi", true)
	if !strings.HasPrefix(got, "sudo -n ") {
		t.Errorf("wrap with sudo = %q, want a 'sudo -n ' prefix", got)
	}
}

// Compile-time proof that Connector satisfies the interface.
var _ connectors.Connector = (*Connector)(nil)

// Ensure the injectable dial hook has the shape sshx.Dial provides.
var _ DialFunc = sshx.Dial

func containsFingerprint(entries []keys.Entry, fingerprint string) bool {
	for _, e := range entries {
		if e.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}
