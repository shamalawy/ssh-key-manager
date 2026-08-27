// Package execc runs an operator-supplied program to manage keys on anything
// SKM has no first-party connector for.
//
// This is what makes "anything that depends on SSH keys" a true statement
// rather than an aspiration. A first-party connector is better when one exists;
// this exists so that waiting for one is never the blocker.
//
// The contract is a documented JSON object on stdin and a JSON object on
// stdout, one invocation per operation. Anything the script writes to stderr is
// surfaced as the operation's message, which is where a script should explain
// itself.
//
// Safety notes worth stating plainly. The script runs as the SKM server
// process, so a target configured with an exec connector can run code with the
// server's privileges — the connector is therefore gated behind an allow-list
// of directories rather than accepting an arbitrary path from the database.
// Credentials are passed on stdin, never in argv, because argv is world-
// readable in /proc.
package execc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/diff"
	"github.com/hamalawy/ssh-key-manager/backend/internal/keys"
)

// Kind is the connector's registered identifier.
const Kind = "exec"

// Operations the script is asked to perform.
const (
	OpProbe    = "probe"
	OpList     = "list"
	OpApply    = "apply"
	OpSnapshot = "snapshot"
	OpRestore  = "restore"
	OpVerify   = "verify"
)

// Connector shells out to an operator-supplied program.
type Connector struct {
	// AllowedDirs restricts which directories a script may live in. An empty
	// list disables the connector entirely, which is the correct default for
	// an install that has not opted in.
	AllowedDirs []string
	// Timeout bounds a single invocation.
	Timeout time.Duration
}

// New returns a connector permitted to run scripts from the given directories.
func New(allowedDirs []string) *Connector {
	return &Connector{AllowedDirs: allowedDirs, Timeout: 5 * time.Minute}
}

func (c *Connector) Kind() string { return Kind }

// Capabilities are declared per target, because what a script can do depends on
// the script. The connector-level answer is the optimistic one; Validate and
// each operation still refuse anything the target has not opted into.
func (c *Connector) Capabilities() connectors.Capabilities {
	return connectors.Capabilities{
		CanList:         true,
		CanSnapshot:     true,
		CanRestore:      true,
		CanVerify:       true,
		SupportsOptions: true,
	}
}

// Request is the JSON object written to the script's stdin.
type Request struct {
	Operation string `json:"operation"`
	Target    struct {
		ID         string         `json:"id"`
		Name       string         `json:"name"`
		Kind       string         `json:"kind"`
		Address    string         `json:"address"`
		Port       int            `json:"port"`
		Config     map[string]any `json:"config,omitempty"`
		HostKeyPin string         `json:"host_key_pin,omitempty"`
		Tags       []string       `json:"tags,omitempty"`
	} `json:"target"`
	Principal struct {
		Username string `json:"username"`
	} `json:"principal"`
	Credential struct {
		Kind     string `json:"kind"`
		Username string `json:"username,omitempty"`
		Password string `json:"password,omitempty"`
		Token    string `json:"token,omitempty"`
		// PrivateKey is the management credential, not a managed key.
		PrivateKey string `json:"private_key,omitempty"`
	} `json:"credential"`

	// Desired is set for apply.
	Desired []DesiredKey `json:"desired,omitempty"`
	Options struct {
		DryRun     bool `json:"dry_run"`
		Prune      bool `json:"prune"`
		AllowEmpty bool `json:"allow_empty"`
	} `json:"options,omitempty"`

	// Snapshot is set for restore.
	Snapshot *SnapshotBody `json:"snapshot,omitempty"`
	// VerifyKey is the private key to authenticate with, set for verify.
	VerifyKey string `json:"verify_key,omitempty"`
}

// DesiredKey is one key the script should ensure is present.
type DesiredKey struct {
	PublicKey   string   `json:"public_key"`
	Fingerprint string   `json:"fingerprint"`
	Options     []string `json:"options,omitempty"`
	Comment     string   `json:"comment,omitempty"`
}

// SnapshotBody is a captured state, passed back to the script on restore.
type SnapshotBody struct {
	Kind    string `json:"kind"`
	Content string `json:"content"`
	Existed bool   `json:"existed"`
}

// Response is the JSON object the script must write to stdout.
type Response struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`

	// Keys is returned by list: authorized_keys-style lines.
	Keys []string `json:"keys,omitempty"`

	// Apply results.
	Changed bool     `json:"changed,omitempty"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`

	// Snapshot is returned by snapshot.
	Snapshot *SnapshotBody `json:"snapshot,omitempty"`

	// Probe results.
	Reachable bool              `json:"reachable,omitempty"`
	Detail    map[string]string `json:"detail,omitempty"`
}

// Validate checks a target's script path against the allow-list.
func (c *Connector) Validate(ctx context.Context, t *connectors.Target) error {
	_, err := c.script(t)
	return err
}

// script resolves and authorises the program for a target.
func (c *Connector) script(t *connectors.Target) (string, error) {
	if t == nil {
		return "", fmt.Errorf("exec: target is nil")
	}
	if len(c.AllowedDirs) == 0 {
		return "", fmt.Errorf("exec: the exec connector is not enabled on this install; " +
			"set SKM_EXEC_DIRS to the directory holding your connector scripts")
	}

	raw := t.ConfigString("script", "")
	if raw == "" {
		return "", fmt.Errorf("exec: target %q has no \"script\" setting", t.Name)
	}

	resolved, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("exec: resolving %q: %w", raw, err)
	}
	// Resolve symlinks before the prefix check: a symlink inside an allowed
	// directory pointing at /bin/sh would otherwise pass.
	if real, err := filepath.EvalSymlinks(resolved); err == nil {
		resolved = real
	}

	for _, dir := range c.AllowedDirs {
		base, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		if real, err := filepath.EvalSymlinks(base); err == nil {
			base = real
		}
		rel, err := filepath.Rel(base, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}

		info, err := os.Stat(resolved)
		if err != nil {
			return "", fmt.Errorf("exec: %s: %w", resolved, err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("exec: %s is a directory", resolved)
		}
		if info.Mode()&0o111 == 0 {
			return "", fmt.Errorf("exec: %s is not executable", resolved)
		}
		// A script anyone can rewrite is a script anyone can use to run code
		// as the SKM server.
		if info.Mode()&0o022 != 0 {
			return "", fmt.Errorf("exec: %s is group- or world-writable (mode %o); refusing to run it", resolved, info.Mode().Perm())
		}
		return resolved, nil
	}

	return "", fmt.Errorf("exec: %s is not inside any permitted directory (%s)",
		resolved, strings.Join(c.AllowedDirs, ", "))
}

// Probe asks the script whether the target is reachable.
func (c *Connector) Probe(ctx context.Context, req connectors.Request) (*connectors.ProbeResult, error) {
	resp, err := c.invoke(ctx, OpProbe, req, func(*Request) {})
	if err != nil {
		return &connectors.ProbeResult{Reachable: false, Message: err.Error()}, err
	}
	return &connectors.ProbeResult{
		Reachable: resp.Reachable || resp.OK,
		Message:   orMessage(resp.Message, "reachable"),
		Detail:    resp.Detail,
	}, nil
}

// List asks the script for the currently authorized keys.
func (c *Connector) List(ctx context.Context, req connectors.Request) ([]keys.Entry, error) {
	resp, err := c.invoke(ctx, OpList, req, func(*Request) {})
	if err != nil {
		return nil, err
	}

	parsed := keys.ParseAuthorizedKeys([]byte(strings.Join(resp.Keys, "\n")))
	return parsed.Keys(), nil
}

// Apply asks the script to converge the target.
func (c *Connector) Apply(ctx context.Context, req connectors.Request, desired []connectors.DesiredKey, opts connectors.ApplyOptions) (*connectors.ApplyResult, error) {
	before, err := c.Snapshot(ctx, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.invoke(ctx, OpApply, req, func(r *Request) {
		for _, d := range desired {
			r.Desired = append(r.Desired, DesiredKey{
				PublicKey: d.PublicLine, Fingerprint: d.Fingerprint,
				Options: d.Options, Comment: d.Comment,
			})
		}
		r.Options.DryRun = opts.DryRun
		r.Options.Prune = opts.Prune
		r.Options.AllowEmpty = opts.AllowEmpty
	})
	if err != nil {
		return nil, err
	}

	result := &connectors.ApplyResult{
		Changed: resp.Changed,
		Added:   resp.Added,
		Removed: resp.Removed,
		Before:  before,
		DryRun:  opts.DryRun,
	}
	if resp.Message != "" {
		result.Warnings = append(result.Warnings, resp.Message)
	}

	after, err := c.Snapshot(ctx, req)
	if err != nil {
		return result, err
	}
	result.After = after
	result.Diff = diff.Unified(string(before.Content), string(after.Content),
		req.Target.Name+" (before)", req.Target.Name+" (after)", 3)

	// The lockout guard applies to exec targets too. A script that reports
	// success having removed everything is exactly the case this exists for.
	if !opts.DryRun && after.KeyCount == 0 && !opts.AllowEmpty {
		return result, fmt.Errorf("%w: the script left no authorized keys on %s as %s",
			connectors.ErrWouldLockOut, req.Target.Name, req.Principal.Username)
	}

	return result, nil
}

// Snapshot asks the script to capture the current state.
func (c *Connector) Snapshot(ctx context.Context, req connectors.Request) (*connectors.Snapshot, error) {
	resp, err := c.invoke(ctx, OpSnapshot, req, func(*Request) {})
	if err != nil {
		return nil, err
	}
	if resp.Snapshot == nil {
		return nil, fmt.Errorf("exec: the script returned no snapshot for %s", req.Target.Name)
	}

	content := []byte(resp.Snapshot.Content)
	parsed := keys.ParseAuthorizedKeys(content)
	sum := sha256.Sum256(content)

	return &connectors.Snapshot{
		Kind:     orMessage(resp.Snapshot.Kind, "exec_state"),
		Content:  content,
		Checksum: hex.EncodeToString(sum[:]),
		KeyCount: parsed.Count(),
		Existed:  resp.Snapshot.Existed,
	}, nil
}

// Restore hands a snapshot back to the script.
func (c *Connector) Restore(ctx context.Context, req connectors.Request, snap *connectors.Snapshot) error {
	if snap == nil {
		return fmt.Errorf("exec: no snapshot to restore")
	}
	_, err := c.invoke(ctx, OpRestore, req, func(r *Request) {
		r.Snapshot = &SnapshotBody{
			Kind: snap.Kind, Content: string(snap.Content), Existed: snap.Existed,
		}
	})
	return err
}

// Verify asks the script to prove the key authenticates.
func (c *Connector) Verify(ctx context.Context, req connectors.Request, privateKeyPEM []byte) error {
	if !req.Target.ConfigBool("can_verify", true) {
		return connectors.ErrUnsupported
	}
	_, err := c.invoke(ctx, OpVerify, req, func(r *Request) {
		r.VerifyKey = string(privateKeyPEM)
	})
	return err
}

// invoke runs the script for one operation.
func (c *Connector) invoke(ctx context.Context, op string, req connectors.Request, customise func(*Request)) (*Response, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	script, err := c.script(req.Target)
	if err != nil {
		return nil, err
	}

	payload := &Request{Operation: op}
	payload.Target.ID = req.Target.ID.String()
	payload.Target.Name = req.Target.Name
	payload.Target.Kind = req.Target.Kind
	payload.Target.Address = req.Target.Address
	payload.Target.Port = req.Target.Port
	payload.Target.Config = req.Target.Config
	payload.Target.HostKeyPin = req.Target.HostKeyPin
	payload.Target.Tags = req.Target.Tags
	payload.Principal.Username = req.Principal.Username
	payload.Credential.Kind = req.Credential.Kind
	payload.Credential.Username = req.Credential.Username
	payload.Credential.Password = req.Credential.Password
	payload.Credential.Token = req.Credential.Token
	payload.Credential.PrivateKey = string(req.Credential.PrivateKey)
	customise(payload)

	stdin, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("exec: encoding the request: %w", err)
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, script)
	cmd.Stdin = bytes.NewReader(stdin)
	// A minimal environment: the script gets the operation and nothing
	// inherited from the server that it has no business seeing.
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"SKM_OPERATION=" + op,
		"SKM_TARGET=" + req.Target.Name,
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	stderrText := strings.TrimSpace(stderr.String())

	if runCtx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("exec: %s timed out after %s during %s", filepath.Base(script), timeout, op)
	}

	var resp Response
	if out := bytes.TrimSpace(stdout.Bytes()); len(out) > 0 {
		if err := json.Unmarshal(out, &resp); err != nil {
			return nil, fmt.Errorf("exec: %s returned output that is not JSON during %s: %w (stderr: %s)",
				filepath.Base(script), op, err, clip(stderrText))
		}
	} else if runErr == nil {
		return nil, fmt.Errorf("exec: %s produced no output during %s (stderr: %s)",
			filepath.Base(script), op, clip(stderrText))
	}

	if runErr != nil {
		detail := resp.Error
		if detail == "" {
			detail = stderrText
		}
		return nil, fmt.Errorf("exec: %s failed during %s: %v: %s",
			filepath.Base(script), op, runErr, clip(detail))
	}
	if !resp.OK {
		detail := resp.Error
		if detail == "" {
			detail = orMessage(resp.Message, stderrText)
		}
		return nil, fmt.Errorf("exec: %s reported failure during %s: %s",
			filepath.Base(script), op, clip(detail))
	}

	return &resp, nil
}

func orMessage(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// clip bounds text taken from a script's output before it lands in an error or
// the audit log.
func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 1000 {
		return s
	}
	return s[:1000] + "… (truncated)"
}
