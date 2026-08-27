package execc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/keys"
)

// writeScript drops an executable shell script into dir and returns its path.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func request(t *testing.T, script string) connectors.Request {
	t.Helper()

	return connectors.Request{
		Target: &connectors.Target{
			ID: uuid.New(), Name: "appliance-01", Kind: "appliance",
			Connector: Kind, Address: "10.0.0.9", Port: 22,
			Config: map[string]any{"script": script},
		},
		Principal:  &connectors.Principal{ID: uuid.New(), Username: "admin"},
		Credential: &connectors.Credential{Kind: "ssh_password", Username: "admin", Password: "hunter2"},
	}
}

// The connector runs code as the SKM server. Being off by default is the only
// safe posture for that.
func TestDisabledWhenNoDirectoriesAreAllowed(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "connector.sh", `echo '{"ok":true}'`)

	c := New(nil)
	err := c.Validate(t.Context(), request(t, script).Target)

	if err == nil {
		t.Fatal("Validate succeeded with no allowed directories")
	}
	if !strings.Contains(err.Error(), "SKM_EXEC_DIRS") {
		t.Errorf("the error should say how to enable it: %v", err)
	}
}

func TestScriptOutsideTheAllowListIsRefused(t *testing.T) {
	allowed := t.TempDir()
	elsewhere := t.TempDir()
	script := writeScript(t, elsewhere, "connector.sh", `echo '{"ok":true}'`)

	c := New([]string{allowed})
	if err := c.Validate(t.Context(), request(t, script).Target); err == nil {
		t.Fatal("Validate accepted a script outside the permitted directories")
	}
}

// A relative path with .. must not walk out of the allowed directory.
func TestTraversalOutOfTheAllowListIsRefused(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	if err := os.Mkdir(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := writeScript(t, root, "evil.sh", `echo '{"ok":true}'`)

	c := New([]string{allowed})
	target := request(t, filepath.Join(allowed, "..", filepath.Base(outside))).Target

	if err := c.Validate(t.Context(), target); err == nil {
		t.Fatal("Validate accepted a path that traverses out of the allowed directory")
	}
}

// A symlink inside an allowed directory pointing at /bin/sh would otherwise
// turn the allow-list into a formality.
func TestSymlinkOutOfTheAllowListIsRefused(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	if err := os.Mkdir(allowed, 0o700); err != nil {
		t.Fatal(err)
	}

	real := writeScript(t, root, "real.sh", `echo '{"ok":true}'`)
	link := filepath.Join(allowed, "innocent.sh")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("this filesystem does not support symlinks: %v", err)
	}

	c := New([]string{allowed})
	if err := c.Validate(t.Context(), request(t, link).Target); err == nil {
		t.Fatal("Validate followed a symlink out of the allowed directory")
	}
}

// A script anyone can rewrite is a script anyone can use to run code as SKM.
func TestWorldWritableScriptIsRefused(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "connector.sh", `echo '{"ok":true}'`)
	if err := os.Chmod(script, 0o777); err != nil {
		t.Fatal(err)
	}

	c := New([]string{dir})
	err := c.Validate(t.Context(), request(t, script).Target)

	if err == nil {
		t.Fatal("Validate accepted a world-writable script")
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Errorf("the error should say why: %v", err)
	}
}

func TestNonExecutableScriptIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "connector.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho '{\"ok\":true}'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := New([]string{dir})
	if err := c.Validate(t.Context(), request(t, path).Target); err == nil {
		t.Fatal("Validate accepted a script that is not executable")
	}
}

func TestValidateAcceptsAPermittedScript(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "connector.sh", `echo '{"ok":true}'`)

	c := New([]string{dir})
	if err := c.Validate(t.Context(), request(t, script).Target); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// The contract is a JSON request on stdin. This script echoes it back so the
// test can assert exactly what a connector author receives.
func TestRequestContractOnStdin(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "request.json")
	script := writeScript(t, dir, "connector.sh",
		"cat > "+capture+"\necho '{\"ok\":true,\"reachable\":true,\"detail\":{\"model\":\"X100\"}}'\n")

	c := New([]string{dir})
	req := request(t, script)

	result, err := c.Probe(t.Context(), req)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !result.Reachable || result.Detail["model"] != "X100" {
		t.Errorf("probe result = %+v", result)
	}

	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatalf("the script did not receive a request: %v", err)
	}

	var received Request
	if err := json.Unmarshal(raw, &received); err != nil {
		t.Fatalf("the request was not valid JSON: %v", err)
	}

	if received.Operation != OpProbe {
		t.Errorf("Operation = %q, want %q", received.Operation, OpProbe)
	}
	if received.Target.Name != "appliance-01" || received.Target.Address != "10.0.0.9" {
		t.Errorf("target = %+v", received.Target)
	}
	if received.Principal.Username != "admin" {
		t.Errorf("principal = %+v", received.Principal)
	}
	if received.Credential.Password != "hunter2" {
		t.Error("the credential did not reach the script")
	}
}

// Credentials go on stdin, never in argv: /proc/<pid>/cmdline is readable by
// other users on the host.
func TestCredentialsAreNotPassedInArgv(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "argv.txt")
	script := writeScript(t, dir, "connector.sh",
		"cat > /dev/null\necho \"$@\" > "+capture+"\necho '{\"ok\":true,\"reachable\":true}'\n")

	c := New([]string{dir})
	if _, err := c.Probe(t.Context(), request(t, script)); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	argv, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(argv), "hunter2") {
		t.Errorf("the password appeared in argv: %q", argv)
	}
}

func TestListParsesReturnedKeys(t *testing.T) {
	pair, err := keys.Generate(keys.Ed25519, "skm@appliance")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	body := `cat > /dev/null
cat <<'JSON'
{"ok":true,"keys":["` + pair.PublicLine + `"]}
JSON
`
	script := writeScript(t, dir, "connector.sh", body)

	c := New([]string{dir})
	entries, err := c.List(t.Context(), request(t, script))
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Fingerprint != pair.Fingerprint {
		t.Errorf("fingerprint = %q, want %q", entries[0].Fingerprint, pair.Fingerprint)
	}
}

func TestFailureIsReportedWithTheScriptsReason(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "connector.sh",
		"cat > /dev/null\necho '{\"ok\":false,\"error\":\"the appliance rejected the key\"}'\n")

	c := New([]string{dir})
	_, err := c.Probe(t.Context(), request(t, script))

	if err == nil {
		t.Fatal("Probe succeeded even though the script reported failure")
	}
	if !strings.Contains(err.Error(), "the appliance rejected the key") {
		t.Errorf("the script's reason should reach the operator: %v", err)
	}
}

func TestNonZeroExitIsAFailure(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "connector.sh",
		"cat > /dev/null\necho 'something broke' >&2\nexit 3\n")

	c := New([]string{dir})
	_, err := c.Probe(t.Context(), request(t, script))

	if err == nil {
		t.Fatal("Probe succeeded despite a non-zero exit")
	}
	if !strings.Contains(err.Error(), "something broke") {
		t.Errorf("stderr should reach the operator: %v", err)
	}
}

func TestNonJSONOutputIsAClearError(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "connector.sh", "cat > /dev/null\necho 'not json at all'\n")

	c := New([]string{dir})
	_, err := c.Probe(t.Context(), request(t, script))

	if err == nil {
		t.Fatal("Probe accepted output that is not JSON")
	}
	if !strings.Contains(err.Error(), "not JSON") {
		t.Errorf("the error should name the problem: %v", err)
	}
}

// The lockout guard is not something a connector opts into.
func TestApplyRefusesToLeaveNoKeys(t *testing.T) {
	dir := t.TempDir()
	// Snapshot always reports an empty state, so the apply "succeeded" into a
	// target with nothing authorized.
	script := writeScript(t, dir, "connector.sh",
		"cat > /dev/null\necho '{\"ok\":true,\"changed\":true,\"snapshot\":{\"kind\":\"exec_state\",\"content\":\"\",\"existed\":true}}'\n")

	c := New([]string{dir})
	req := request(t, script)

	_, err := c.Apply(t.Context(), req, nil, connectors.DefaultApplyOptions())
	if err == nil {
		t.Fatal("Apply succeeded having left no keys on the target")
	}
	if !strings.Contains(err.Error(), "last remaining key") && !strings.Contains(err.Error(), "no authorized keys") {
		t.Errorf("the refusal should be the lockout guard: %v", err)
	}
}

func TestSnapshotRoundTripsThroughTheScript(t *testing.T) {
	pair, err := keys.Generate(keys.Ed25519, "skm@appliance")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	body := `cat > /dev/null
cat <<'JSON'
{"ok":true,"snapshot":{"kind":"exec_state","content":"` + pair.PublicLine + `\n","existed":true}}
JSON
`
	script := writeScript(t, dir, "connector.sh", body)

	c := New([]string{dir})
	snap, err := c.Snapshot(t.Context(), request(t, script))
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	if snap.KeyCount != 1 {
		t.Errorf("KeyCount = %d, want 1", snap.KeyCount)
	}
	if !snap.Existed {
		t.Error("Existed = false; the script said the state was there")
	}
	if snap.Checksum == "" {
		t.Error("no checksum was computed")
	}
}
