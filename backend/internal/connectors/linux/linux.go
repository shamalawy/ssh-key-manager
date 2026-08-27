// Package linux manages authorized_keys files on Linux and Unix hosts over SSH.
//
// It is the reference connector: it declares every capability, and the rotation
// engine's guarantees are strongest against targets like these. Two design
// choices are worth stating outright.
//
// Writes are atomic. The file is staged in the destination directory, given its
// permissions and ownership before it is moved, and then renamed over the
// original. A crash or a dropped connection at any point leaves either the old
// file or the new one, never a truncated one — which for authorized_keys is the
// difference between a working host and an unreachable one.
//
// Unmanaged content is preserved byte for byte. Keys an operator added by hand,
// comments, and even lines SKM cannot parse survive a rewrite untouched. SKM
// only ever adds or removes its own entries.
package linux

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/diff"
	"github.com/hamalawy/ssh-key-manager/backend/internal/keys"
	"github.com/hamalawy/ssh-key-manager/backend/internal/sshx"
)

// Kind is the connector's registered identifier.
const Kind = "linux"

// DialFunc opens an SSH connection. It is a field on Connector so tests can
// substitute a fake transport without a live host.
type DialFunc func(ctx context.Context, opts sshx.DialOptions) (*sshx.Client, error)

// Connector implements connectors.Connector for Unix-like hosts.
type Connector struct {
	Dial DialFunc
}

// New returns a Connector using real SSH.
func New() *Connector {
	return &Connector{Dial: sshx.Dial}
}

func (c *Connector) Kind() string { return Kind }

// Capabilities reports full support: a Unix host can do everything SKM asks.
func (c *Connector) Capabilities() connectors.Capabilities {
	return connectors.Capabilities{
		CanList:         true,
		CanSnapshot:     true,
		CanRestore:      true,
		CanVerify:       true,
		SupportsOptions: true,
	}
}

// Validate checks configuration without connecting.
func (c *Connector) Validate(ctx context.Context, t *connectors.Target) error {
	if t == nil {
		return fmt.Errorf("linux: target is nil")
	}
	if strings.TrimSpace(t.Address) == "" {
		return fmt.Errorf("linux: target %q has no address", t.Name)
	}
	if t.Port < 0 || t.Port > 65535 {
		return fmt.Errorf("linux: target %q has an invalid port %d", t.Name, t.Port)
	}
	if mode := t.ConfigString("file_mode", "600"); !validMode(mode) {
		return fmt.Errorf("linux: target %q has an invalid file_mode %q (expected octal such as 600)", t.Name, mode)
	}
	return nil
}

// Probe connects and reports reachability plus the observed host key.
func (c *Connector) Probe(ctx context.Context, req connectors.Request) (*connectors.ProbeResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client, err := c.connect(ctx, req)
	if err != nil {
		return &connectors.ProbeResult{Reachable: false, Message: err.Error()}, err
	}
	defer client.Close()

	res := &connectors.ProbeResult{
		Reachable:    true,
		HostKeyPin:   client.HostKeyPin,
		HostKeyIsNew: client.HostKeyIsNew,
		Detail:       map[string]string{},
	}

	// Best-effort identification; failure here does not make the target
	// unreachable.
	if out, err := client.Run(ctx, "uname -sr 2>/dev/null || true"); err == nil {
		res.Detail["uname"] = strings.TrimSpace(out.Stdout)
	}
	if out, err := client.Run(ctx, "id -un 2>/dev/null || true"); err == nil {
		res.Detail["connected_as"] = strings.TrimSpace(out.Stdout)
	}
	res.Message = "reachable"
	return res, nil
}

// List reads the keys currently authorized for the principal.
func (c *Connector) List(ctx context.Context, req connectors.Request) ([]keys.Entry, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client, err := c.connect(ctx, req)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	snap, err := c.read(ctx, client, req)
	if err != nil {
		return nil, err
	}
	return keys.ParseAuthorizedKeys(snap.Content).Keys(), nil
}

// Snapshot captures the current file byte for byte.
func (c *Connector) Snapshot(ctx context.Context, req connectors.Request) (*connectors.Snapshot, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client, err := c.connect(ctx, req)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	return c.read(ctx, client, req)
}

// Restore writes a snapshot back verbatim.
//
// A snapshot taken when no file existed restores to no file, rather than to an
// empty file — the two differ to sshd only in edge cases, but a rollback that
// does not reproduce the original state exactly is not a rollback.
func (c *Connector) Restore(ctx context.Context, req connectors.Request, snap *connectors.Snapshot) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if snap == nil {
		return fmt.Errorf("linux: snapshot is nil")
	}
	if got := checksum(snap.Content); snap.Checksum != "" && got != snap.Checksum {
		return fmt.Errorf("linux: snapshot checksum mismatch (stored %s, computed %s); refusing to restore corrupted content",
			snap.Checksum, got)
	}

	client, err := c.connect(ctx, req)
	if err != nil {
		return err
	}
	defer client.Close()

	keyPath, err := c.resolvePath(ctx, client, req)
	if err != nil {
		return err
	}

	if !snap.Existed {
		out, err := client.Run(ctx, wrap(removeScript(keyPath), req.Principal.UseSudo))
		if err != nil {
			return fmt.Errorf("linux: removing %s: %w", keyPath, err)
		}
		if out.ExitCode != 0 {
			return fmt.Errorf("linux: removing %s failed (exit %d): %s", keyPath, out.ExitCode, strings.TrimSpace(out.Stderr))
		}
		return nil
	}

	return c.write(ctx, client, req, keyPath, snap.Content)
}

// Verify proves a private key authenticates as the principal.
//
// The connection is deliberately new and independent: reusing the management
// session would prove only that the management credential still works, which is
// exactly the thing a rotation must not assume.
func (c *Connector) Verify(ctx context.Context, req connectors.Request, privateKeyPEM []byte) error {
	if err := req.Validate(); err != nil {
		return err
	}
	if len(privateKeyPEM) == 0 {
		return fmt.Errorf("linux: no private key supplied to verify")
	}

	dial := c.Dial
	if dial == nil {
		dial = sshx.Dial
	}

	opts := sshx.DialOptions{
		Address:    req.Target.Address,
		Port:       req.Target.Port,
		Username:   req.Principal.Username,
		PrivateKey: privateKeyPEM,
		HostKeyPin: req.Target.HostKeyPin,
	}

	client, err := dial(ctx, opts)
	if err != nil {
		return fmt.Errorf("linux: verifying key against %s as %s: %w", req.Target.Name, req.Principal.Username, err)
	}
	defer client.Close()

	// Opening a session proves the login is genuinely usable, not merely that
	// the handshake completed — a shell-less or expired account fails here.
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("linux: key authenticated to %s but no session could be opened: %w", req.Target.Name, err)
	}
	session.Close()
	return nil
}

// Apply converges the target's authorized_keys on the desired set.
func (c *Connector) Apply(ctx context.Context, req connectors.Request, desired []connectors.DesiredKey, opts connectors.ApplyOptions) (*connectors.ApplyResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client, err := c.connect(ctx, req)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	keyPath, err := c.resolvePath(ctx, client, req)
	if err != nil {
		return nil, err
	}

	before, err := c.readPath(ctx, client, req, keyPath)
	if err != nil {
		return nil, err
	}

	file := keys.ParseAuthorizedKeys(before.Content)
	result := &connectors.ApplyResult{Before: before, DryRun: opts.DryRun}

	// Add or update every desired key.
	for _, d := range desired {
		entry, err := keys.NewEntry(d.PublicLine, d.Options)
		if err != nil {
			return nil, fmt.Errorf("linux: preparing key %s: %w", d.Fingerprint, err)
		}
		if d.Fingerprint != "" && entry.Fingerprint != d.Fingerprint {
			return nil, fmt.Errorf("linux: key material does not match its recorded fingerprint (expected %s, computed %s)",
				d.Fingerprint, entry.Fingerprint)
		}
		if file.Upsert(entry) {
			result.Added = append(result.Added, entry.Fingerprint)
		}
	}

	// Prune managed keys that are no longer desired, never touching entries SKM
	// did not deploy.
	if opts.Prune {
		wanted := make(map[string]bool, len(desired))
		for _, d := range desired {
			wanted[d.Fingerprint] = true
		}
		managed := make(map[string]bool, len(opts.ManagedFingerprints))
		for _, fp := range opts.ManagedFingerprints {
			managed[fp] = true
		}

		for _, entry := range file.Keys() {
			if wanted[entry.Fingerprint] {
				continue
			}
			if opts.PreserveUnmanaged && !managed[entry.Fingerprint] {
				continue
			}
			if file.Remove(entry.Fingerprint) {
				result.Removed = append(result.Removed, entry.Fingerprint)
			}
		}
	}

	after := file.Bytes()
	result.Changed = !bytesEqual(before.Content, after)
	result.Diff = diff.Unified(string(before.Content), string(after), keyPath+" (before)", keyPath+" (after)", 3)
	result.After = &connectors.Snapshot{
		Kind:     "authorized_keys",
		Content:  after,
		Checksum: checksum(after),
		KeyCount: file.Count(),
		Existed:  true,
	}

	// The lockout guard. Emptying an authorized_keys file is how a fleet
	// becomes unreachable, so it is refused outright rather than warned about.
	if file.Count() == 0 && !opts.AllowEmpty {
		return result, fmt.Errorf("%w: applying to %s as %s would leave no authorized keys",
			connectors.ErrWouldLockOut, req.Target.Name, req.Principal.Username)
	}

	if !result.Changed {
		return result, nil
	}
	if opts.DryRun {
		return result, nil
	}

	if err := c.write(ctx, client, req, keyPath, after); err != nil {
		return result, err
	}

	// Read back and compare. A write that reported success but did not land —
	// a full disk, a read-only mount, a quota — must not be recorded as a
	// successful deployment.
	verify, err := c.readPath(ctx, client, req, keyPath)
	if err != nil {
		return result, fmt.Errorf("linux: reading back %s after write: %w", keyPath, err)
	}
	if verify.Checksum != result.After.Checksum {
		return result, fmt.Errorf("linux: %s does not match what was written (expected checksum %s, found %s); the change may be partially applied",
			keyPath, result.After.Checksum, verify.Checksum)
	}

	return result, nil
}

// connect opens the management connection using the target's credential.
func (c *Connector) connect(ctx context.Context, req connectors.Request) (*sshx.Client, error) {
	dial := c.Dial
	if dial == nil {
		dial = sshx.Dial
	}

	username := req.Credential.Username
	if username == "" {
		username = req.Principal.Username
	}

	client, err := dial(ctx, sshx.DialOptions{
		Address:    req.Target.Address,
		Port:       req.Target.Port,
		Username:   username,
		Password:   req.Credential.Password,
		PrivateKey: req.Credential.PrivateKey,
		HostKeyPin: req.Target.HostKeyPin,
	})
	if err != nil {
		return nil, fmt.Errorf("linux: connecting to %s: %w", req.Target.Name, err)
	}
	return client, nil
}

// resolvePath determines the authorized_keys path for the principal.
func (c *Connector) resolvePath(ctx context.Context, client *sshx.Client, req connectors.Request) (string, error) {
	if p := strings.TrimSpace(req.Principal.AuthorizedKeysPath); p != "" {
		return p, nil
	}
	if p := req.Target.ConfigString("authorized_keys_path", ""); p != "" {
		return p, nil
	}

	out, err := client.Run(ctx, wrap(homeScript(req.Principal.Username), req.Principal.UseSudo))
	if err != nil {
		return "", fmt.Errorf("linux: resolving home directory for %s: %w", req.Principal.Username, err)
	}
	if out.ExitCode != 0 {
		return "", fmt.Errorf("linux: cannot resolve home directory for %s on %s (exit %d): %s",
			req.Principal.Username, req.Target.Name, out.ExitCode, strings.TrimSpace(out.Stderr))
	}

	home := strings.TrimSpace(out.Stdout)
	if home == "" {
		return "", fmt.Errorf("linux: user %s has no home directory on %s", req.Principal.Username, req.Target.Name)
	}
	return path.Join(home, ".ssh", "authorized_keys"), nil
}

func (c *Connector) read(ctx context.Context, client *sshx.Client, req connectors.Request) (*connectors.Snapshot, error) {
	keyPath, err := c.resolvePath(ctx, client, req)
	if err != nil {
		return nil, err
	}
	return c.readPath(ctx, client, req, keyPath)
}

// readPath fetches a file as base64 and decodes it, so binary or unusual bytes
// survive the round trip intact.
func (c *Connector) readPath(ctx context.Context, client *sshx.Client, req connectors.Request, keyPath string) (*connectors.Snapshot, error) {
	out, err := client.Run(ctx, wrap(readScript(keyPath), req.Principal.UseSudo))
	if err != nil {
		return nil, fmt.Errorf("linux: reading %s: %w", keyPath, err)
	}
	if out.ExitCode != 0 {
		return nil, fmt.Errorf("linux: reading %s failed (exit %d): %s",
			keyPath, out.ExitCode, strings.TrimSpace(out.Stderr))
	}

	marker, body, _ := strings.Cut(out.Stdout, "\n")
	switch strings.TrimSpace(marker) {
	case markerMissing:
		return &connectors.Snapshot{
			Kind:     "authorized_keys",
			Content:  nil,
			Checksum: checksum(nil),
			Existed:  false,
		}, nil
	case markerExists:
		// fall through
	default:
		return nil, fmt.Errorf("linux: unexpected response reading %s: %q", keyPath, truncate(out.Stdout))
	}

	content, err := decodeBase64(body)
	if err != nil {
		return nil, fmt.Errorf("linux: decoding %s: %w", keyPath, err)
	}

	return &connectors.Snapshot{
		Kind:     "authorized_keys",
		Content:  content,
		Checksum: checksum(content),
		KeyCount: keys.ParseAuthorizedKeys(content).Count(),
		Existed:  true,
	}, nil
}

func (c *Connector) write(ctx context.Context, client *sshx.Client, req connectors.Request, keyPath string, content []byte) error {
	mode := req.Target.ConfigString("file_mode", "600")
	encoded := []byte(base64.StdEncoding.EncodeToString(content))

	out, err := client.RunInput(ctx,
		wrap(writeScript(keyPath, req.Principal.Username, mode), req.Principal.UseSudo),
		encoded)
	if err != nil {
		return fmt.Errorf("linux: writing %s: %w", keyPath, err)
	}

	if strings.Contains(out.Stderr, markerNoBase64) {
		return fmt.Errorf("linux: %s has no usable base64 decoder (tried base64 and openssl)", req.Target.Name)
	}
	if out.ExitCode != 0 {
		return fmt.Errorf("linux: writing %s failed (exit %d): %s",
			keyPath, out.ExitCode, strings.TrimSpace(out.Stderr))
	}
	if !strings.Contains(out.Stdout, markerOK) {
		return fmt.Errorf("linux: writing %s did not confirm success: %q", keyPath, truncate(out.Stdout))
	}
	return nil
}

// decodeBase64 tolerates the line wrapping every base64 implementation adds.
func decodeBase64(s string) ([]byte, error) {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\n', '\r', ' ', '\t':
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(b.String())
}

func checksum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validMode(mode string) bool {
	if len(mode) < 3 || len(mode) > 4 {
		return false
	}
	for _, r := range mode {
		if r < '0' || r > '7' {
			return false
		}
	}
	return true
}

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 120 {
		return s
	}
	return s[:120] + "..."
}

// Settings describes what a linux target can have configured. Both keys are
// optional: the defaults are right for a stock OpenSSH host, which is most of
// them.
func (c *Connector) Settings() []connectors.Setting {
	return []connectors.Setting{
		{
			Key: "authorized_keys_path", Label: "authorized_keys path", Type: "string",
			Description: "Override the per-principal default. Needed when sshd's " +
				"AuthorizedKeysFile has been moved out of the home directory.",
		},
		{
			Key: "file_mode", Label: "File mode", Type: "string", Default: "0600",
			Description: "Octal permissions for the written file. sshd ignores a key " +
				"file that is group or world writable, so this rarely wants changing.",
		},
	}
}
