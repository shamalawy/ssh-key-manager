package netdev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/shamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/shamalawy/ssh-key-manager/backend/internal/diff"
	"github.com/shamalawy/ssh-key-manager/backend/internal/keys"
	"github.com/shamalawy/ssh-key-manager/backend/internal/sshx"
)

// Kind is the connector's registered identifier.
const Kind = "netdev"

// DialFunc opens an SSH connection; a field so tests can substitute a
// scripted device without hardware.
type DialFunc func(ctx context.Context, opts sshx.DialOptions) (*sshx.Client, error)

// Connector manages keys on network devices.
type Connector struct {
	Dial DialFunc
}

// New returns a Connector using real SSH.
func New() *Connector { return &Connector{Dial: sshx.Dial} }

func (c *Connector) Kind() string { return Kind }

// Capabilities are the conservative intersection across the built-in profiles.
// Per-target answers come from TargetCapabilities.
func (c *Connector) Capabilities() connectors.Capabilities {
	return connectors.Capabilities{
		CanList:         true,
		CanSnapshot:     true,
		CanRestore:      false,
		CanVerify:       true,
		SupportsOptions: false,
	}
}

// TargetCapabilities reports what a specific target's profile supports.
func (c *Connector) TargetCapabilities(t *connectors.Target) connectors.Capabilities {
	profile, err := c.profileFor(t)
	if err != nil {
		return connectors.Capabilities{}
	}
	return connectors.Capabilities{
		CanList:     profile.ShowKeys != "",
		CanSnapshot: profile.ShowConfig != "",
		CanRestore:  profile.CanRestore,
		CanVerify:   true,
		SingleKey:   profile.SingleKey,
	}
}

// Validate checks that a target names a usable profile.
func (c *Connector) Validate(ctx context.Context, t *connectors.Target) error {
	if t == nil {
		return fmt.Errorf("netdev: target is nil")
	}
	if strings.TrimSpace(t.Address) == "" {
		return fmt.Errorf("netdev: target %q has no address", t.Name)
	}

	profile, err := c.profileFor(t)
	if err != nil {
		return err
	}
	if len(profile.AddKey) == 0 {
		return fmt.Errorf("netdev: profile %q defines no add-key commands; "+
			"supply add_key/remove_key in the target's config or choose another profile", profile.Name)
	}
	return nil
}

// profileFor resolves a target's profile, applying any per-target overrides.
//
// Overrides exist because vendors change syntax between releases, and an
// operator should be able to fix one command without waiting for a new SKM
// build.
func (c *Connector) profileFor(t *connectors.Target) (Profile, error) {
	name := t.ConfigString("profile", "")
	if name == "" {
		return Profile{}, fmt.Errorf("netdev: target %q has no \"profile\" setting (known: %s)",
			t.Name, strings.Join(ProfileNames(), ", "))
	}

	profile, err := Lookup(name)
	if err != nil {
		return Profile{}, err
	}

	if v := configLines(t, "setup"); v != nil {
		profile.Setup = v
	}
	if v := configLines(t, "enter_config"); v != nil {
		profile.EnterConfig = v
	}
	if v := configLines(t, "exit_config"); v != nil {
		profile.ExitConfig = v
	}
	if v := configLines(t, "add_key"); v != nil {
		profile.AddKey = v
	}
	if v := configLines(t, "remove_key"); v != nil {
		profile.RemoveKey = v
	}
	if v := configLines(t, "commit"); v != nil {
		profile.Commit = v
	}
	if v := t.ConfigString("show_keys", ""); v != "" {
		profile.ShowKeys = v
	}
	if v := t.ConfigString("show_config", ""); v != "" {
		profile.ShowConfig = v
	}
	if v := t.ConfigString("key_format", ""); v != "" {
		profile.KeyFormat = KeyFormat(v)
	}
	return profile, nil
}

// configLines reads a list-of-strings setting from the target config.
func configLines(t *connectors.Target, key string) []string {
	if t.Config == nil {
		return nil
	}
	raw, ok := t.Config[key]
	if !ok {
		return nil
	}

	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return strings.Split(v, "\n")
	}
	return nil
}

// Probe connects and identifies the device.
func (c *Connector) Probe(ctx context.Context, req connectors.Request) (*connectors.ProbeResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client, err := c.connect(ctx, req)
	if err != nil {
		return &connectors.ProbeResult{Reachable: false, Message: err.Error()}, err
	}
	defer client.Close()

	profile, err := c.profileFor(req.Target)
	if err != nil {
		return nil, err
	}

	res := &connectors.ProbeResult{
		Reachable:    true,
		HostKeyPin:   client.HostKeyPin,
		HostKeyIsNew: client.HostKeyIsNew,
		Message:      "reachable",
		Detail:       map[string]string{"profile": profile.Name},
	}

	if v := req.Target.ConfigString("show_version", "show version"); v != "" {
		if out, err := client.Run(ctx, v); err == nil {
			res.Detail["version"] = firstLine(out.Stdout)
		}
	}
	return res, nil
}

// List reads the keys currently configured for the principal.
func (c *Connector) List(ctx context.Context, req connectors.Request) ([]keys.Entry, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	profile, err := c.profileFor(req.Target)
	if err != nil {
		return nil, err
	}
	if profile.ShowKeys == "" {
		return nil, fmt.Errorf("%w: profile %q cannot read back its keys", connectors.ErrUnsupported, profile.Name)
	}

	client, err := c.connect(ctx, req)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err := c.runAll(ctx, client, profile, profile.Setup, substitutions{}); err != nil {
		return nil, err
	}

	cmd := render(profile.ShowKeys, substitutions{Username: req.Principal.Username})
	out, err := client.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("netdev: reading keys from %s: %w", req.Target.Name, err)
	}

	return extractKeys(out.Stdout), nil
}

// Apply converges the device on the desired key set.
func (c *Connector) Apply(ctx context.Context, req connectors.Request, desired []connectors.DesiredKey, opts connectors.ApplyOptions) (*connectors.ApplyResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	profile, err := c.profileFor(req.Target)
	if err != nil {
		return nil, err
	}

	// On a single-key platform the add command overwrites. Issuing two of them
	// would leave one key installed while reporting two, which is the precise
	// failure this product exists to prevent: an operator believing access is
	// in place when it is not.
	if profile.SingleKey && len(desired) > 1 {
		return nil, fmt.Errorf("%w: %s holds one ssh-key per username, and %d were requested for %q — "+
			"rotate this target on its own so it can be replaced and verified, or manage a second username",
			connectors.ErrUnsupported, profile.Description, len(desired), req.Principal.Username)
	}

	client, err := c.connect(ctx, req)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err := c.runAll(ctx, client, profile, profile.Setup, substitutions{}); err != nil {
		return nil, err
	}

	before, err := c.capture(ctx, client, req, profile)
	if err != nil {
		return nil, err
	}

	present := map[string]bool{}
	if profile.ShowKeys != "" {
		existing, err := c.listWith(ctx, client, req, profile)
		if err != nil {
			return nil, err
		}
		for _, e := range existing {
			present[e.Fingerprint] = true
		}
	}

	result := &connectors.ApplyResult{Before: before, DryRun: opts.DryRun}

	var commands []string
	for _, d := range desired {
		if present[d.Fingerprint] {
			continue
		}
		subs, err := substitutionsFor(req.Principal.Username, d, profile)
		if err != nil {
			return nil, err
		}
		for _, tmpl := range profile.AddKey {
			commands = append(commands, render(tmpl, subs))
		}
		result.Added = append(result.Added, d.Fingerprint)

		// The add overwrote whatever was there. Say what was lost rather than
		// letting the caller infer it from a diff nobody reads.
		if profile.SingleKey {
			for fingerprint := range present {
				if fingerprint != d.Fingerprint {
					result.Removed = append(result.Removed, fingerprint)
					result.Warnings = append(result.Warnings, fmt.Sprintf(
						"%s replaced the existing key for %q; this platform holds only one",
						profile.Description, req.Principal.Username))
				}
			}
		}
	}

	// On a single-key platform the add already replaced whatever was there, so
	// there is nothing left to prune — and issuing the removal anyway deletes
	// the key just installed, because the vendor's remove command names the
	// username, not the key. Arista EOS: "no username mo ssh-key". Found by
	// running a rotation against a real switch, which staged the new key,
	// pruned the old one, and thereby removed both.
	pruning := opts.Prune && profile.ShowKeys != "" && len(profile.RemoveKey) > 0
	if profile.SingleKey && len(result.Added) > 0 {
		pruning = false
	}

	if pruning {
		wanted := map[string]bool{}
		for _, d := range desired {
			wanted[d.Fingerprint] = true
		}
		managed := map[string]bool{}
		for _, fp := range opts.ManagedFingerprints {
			managed[fp] = true
		}

		existing, err := c.listWith(ctx, client, req, profile)
		if err != nil {
			return nil, err
		}
		for _, e := range existing {
			if wanted[e.Fingerprint] {
				continue
			}
			if opts.PreserveUnmanaged && !managed[e.Fingerprint] {
				continue
			}
			subs, err := substitutionsFor(req.Principal.Username, connectors.DesiredKey{
				PublicLine: e.Line(), Fingerprint: e.Fingerprint,
			}, profile)
			if err != nil {
				continue
			}
			for _, tmpl := range profile.RemoveKey {
				commands = append(commands, render(tmpl, subs))
			}
			result.Removed = append(result.Removed, e.Fingerprint)
		}
	}

	result.Changed = len(commands) > 0

	// The lockout guard, in the form the platform allows. Where the device can
	// be listed, removing everything is refused outright, as on a Unix host.
	if profile.ShowKeys != "" && !opts.AllowEmpty && len(desired) == 0 && len(result.Removed) > 0 {
		return result, fmt.Errorf("%w: applying to %s as %s would leave no keys configured",
			connectors.ErrWouldLockOut, req.Target.Name, req.Principal.Username)
	}

	if opts.DryRun || !result.Changed {
		result.Diff = previewDiff(req.Target.Name, commands)
		return result, nil
	}

	sequence := append([]string{}, profile.EnterConfig...)
	sequence = append(sequence, commands...)
	sequence = append(sequence, profile.ExitConfig...)
	sequence = append(sequence, profile.Commit...)

	if err := c.runAll(ctx, client, profile, sequence, substitutions{}); err != nil {
		return result, err
	}

	after, err := c.capture(ctx, client, req, profile)
	if err != nil {
		return result, err
	}
	result.After = after
	result.Diff = diff.Unified(string(before.Content), string(after.Content),
		req.Target.Name+" (before)", req.Target.Name+" (after)", 3)

	// Confirm the device actually took the configuration, rather than trusting
	// that it echoed the commands back without complaint.
	if profile.ShowKeys != "" {
		final, err := c.listWith(ctx, client, req, profile)
		if err != nil {
			return result, err
		}
		got := map[string]bool{}
		for _, e := range final {
			got[e.Fingerprint] = true
		}
		for _, d := range desired {
			if !got[d.Fingerprint] {
				return result, fmt.Errorf("netdev: %s accepted the commands but %s is not in its configuration",
					req.Target.Name, d.Fingerprint)
			}
		}
	} else {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"profile %q cannot read back its keys, so this change was not confirmed on the device",
			profile.Name))
	}

	return result, nil
}

// Snapshot captures the relevant section of the running configuration.
func (c *Connector) Snapshot(ctx context.Context, req connectors.Request) (*connectors.Snapshot, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	profile, err := c.profileFor(req.Target)
	if err != nil {
		return nil, err
	}
	if profile.ShowConfig == "" {
		return nil, fmt.Errorf("%w: profile %q cannot capture a snapshot", connectors.ErrUnsupported, profile.Name)
	}

	client, err := c.connect(ctx, req)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err := c.runAll(ctx, client, profile, profile.Setup, substitutions{}); err != nil {
		return nil, err
	}
	return c.capture(ctx, client, req, profile)
}

// Restore writes a snapshot back, where that is a bounded operation.
//
// For a multi-key platform it is not offered, and the package comment says why:
// replaying a captured running configuration onto a device is a larger and
// riskier operation than the change it would undo.
//
// A single-key platform is the exception. There the snapshot contains exactly
// one key for the principal, and putting it back is one add command — the same
// command the connector already issues. That narrow case is worth supporting,
// because it is what lets a failed replacement on such a device be undone
// immediately instead of leaving the account unreachable.
func (c *Connector) Restore(ctx context.Context, req connectors.Request, snap *connectors.Snapshot) error {
	if err := req.Validate(); err != nil {
		return err
	}

	profile, err := c.profileFor(req.Target)
	if err != nil {
		return err
	}
	if !profile.CanRestore || !profile.SingleKey {
		return fmt.Errorf("%w: restoring a device configuration is not automated; "+
			"the snapshot is stored so an operator can review and apply it deliberately",
			connectors.ErrUnsupported)
	}
	if snap == nil {
		return fmt.Errorf("%w: no snapshot to restore", connectors.ErrUnsupported)
	}

	entry, ok := keyInSnapshot(string(snap.Content))
	if !ok {
		// An empty capture is a real state: the principal had no key. Removing
		// whatever is there now is the faithful restoration of that.
		return c.removeAll(ctx, req, profile)
	}

	_, err = c.Apply(ctx, req, []connectors.DesiredKey{{
		PublicLine:  entry.Line(),
		Fingerprint: entry.Fingerprint,
	}}, connectors.ApplyOptions{})
	return err
}

// keyInSnapshot pulls the first authorized key out of a captured configuration.
func keyInSnapshot(raw string) (keys.Entry, bool) {
	for _, line := range strings.Split(raw, "\n") {
		if entry, ok := keyFromLine(line); ok {
			return entry, true
		}
	}
	return keys.Entry{}, false
}

// removeAll issues the profile's removal command, which on a single-key
// platform clears the principal's only key.
func (c *Connector) removeAll(ctx context.Context, req connectors.Request, profile Profile) error {
	if len(profile.RemoveKey) == 0 {
		return fmt.Errorf("%w: profile %q cannot remove keys", connectors.ErrUnsupported, profile.Name)
	}

	client, err := c.connect(ctx, req)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := c.runAll(ctx, client, profile, profile.Setup, substitutions{}); err != nil {
		return err
	}

	subs := substitutions{Username: req.Principal.Username}
	commands := append([]string{}, profile.EnterConfig...)
	for _, tmpl := range profile.RemoveKey {
		commands = append(commands, render(tmpl, subs))
	}
	commands = append(commands, profile.ExitConfig...)
	commands = append(commands, profile.Commit...)

	return c.runAll(ctx, client, profile, commands, subs)
}

func (c *Connector) Verify(ctx context.Context, req connectors.Request, privateKeyPEM []byte) error {
	if err := req.Validate(); err != nil {
		return err
	}

	err := sshx.CheckAuth(ctx, sshx.DialOptions{
		Address:    req.Target.Address,
		Port:       req.Target.Port,
		Username:   req.Principal.Username,
		PrivateKey: privateKeyPEM,
		HostKeyPin: req.Target.HostKeyPin,
	})
	if err != nil {
		return fmt.Errorf("netdev: the key does not authenticate as %s on %s: %w",
			req.Principal.Username, req.Target.Name, err)
	}
	return nil
}

// ------------------------------------------------------------------ internals ---

func (c *Connector) connect(ctx context.Context, req connectors.Request) (*sshx.Client, error) {
	dial := c.Dial
	if dial == nil {
		dial = sshx.Dial
	}

	return dial(ctx, sshx.DialOptions{
		Address:    req.Target.Address,
		Port:       req.Target.Port,
		Username:   req.Credential.Username,
		Password:   req.Credential.Password,
		PrivateKey: req.Credential.PrivateKey,
		HostKeyPin: req.Target.HostKeyPin,
	})
}

// listWith reads back the keys currently authorized for the principal.
//
// Known limitation: the profile's Setup commands — "terminal length 0" and its
// equivalents — apply to the session that ran them, and this opens its own. On
// a platform that paginates a non-interactive session, a long configuration
// could come back truncated at a "--More--" prompt. It does not happen on the
// one platform this has been run against (Arista EOS answers exec commands
// unpaginated when stdin is not a terminal), and fixing it blind — by folding
// setup and the show command into one shell session and then stripping the
// echoed setup output — would change the bytes every snapshot is checksummed
// over, on profiles nobody here can test. Left as it is, and written down.
func (c *Connector) listWith(ctx context.Context, client *sshx.Client, req connectors.Request, profile Profile) ([]keys.Entry, error) {
	cmd := render(profile.ShowKeys, substitutions{Username: req.Principal.Username})
	out, err := client.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("netdev: reading keys from %s: %w", req.Target.Name, err)
	}
	return extractKeys(out.Stdout), nil
}

func (c *Connector) capture(ctx context.Context, client *sshx.Client, req connectors.Request, profile Profile) (*connectors.Snapshot, error) {
	if profile.ShowConfig == "" {
		// Without a capture command there is nothing to snapshot, but an empty
		// snapshot is still better than failing the whole operation: the
		// deployment path only needs it for the diff.
		return &connectors.Snapshot{Kind: "device_config", Content: []byte{}, Existed: false}, nil
	}

	cmd := render(profile.ShowConfig, substitutions{Username: req.Principal.Username})
	out, err := client.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("netdev: capturing configuration from %s: %w", req.Target.Name, err)
	}

	content := []byte(out.Stdout)
	sum := sha256.Sum256(content)

	return &connectors.Snapshot{
		Kind:     "device_config",
		Content:  content,
		Checksum: hex.EncodeToString(sum[:]),
		KeyCount: len(extractKeys(out.Stdout)),
		Existed:  len(content) > 0,
	}, nil
}

// runAll executes a command sequence, treating vendor error text as failure.
func (c *Connector) runAll(ctx context.Context, client *sshx.Client, profile Profile, commands []string, subs substitutions) error {
	var script []string
	for _, cmd := range commands {
		cmd = strings.TrimSpace(render(cmd, subs))
		if cmd != "" {
			script = append(script, cmd)
		}
	}
	if len(script) == 0 {
		return nil
	}

	// One session for the whole batch, not one per command.
	//
	// This is the difference between a change that applies and a change that is
	// rejected: "configure terminal" puts the *session* into configuration
	// mode, so a following command sent down a fresh session runs in exec mode,
	// where "username x ssh-key ..." is not a command at all. Confirmed against
	// Arista EOS 4.26.9M, which answered "% Invalid input" to every
	// configuration command until the batch was sent as one script.
	out, err := client.RunScript(ctx, script)
	if err != nil {
		return fmt.Errorf("netdev: running %d command(s): %w", len(script), err)
	}
	if marker := findMarker(out.Stdout+out.Stderr, profile.ErrorMarkers); marker != "" {
		return fmt.Errorf("%w: %s rejected the change: %s",
			connectors.ErrDeviceRejected, profile.Description, marker)
	}
	return nil
}

// substitutionsFor prepares the template values for one key.
func substitutionsFor(username string, d connectors.DesiredKey, profile Profile) (substitutions, error) {
	keyType, blob, comment := splitPublicLine(d.PublicLine)
	if keyType == "" || blob == "" {
		return substitutions{}, fmt.Errorf("netdev: %q is not a usable public key line", d.PublicLine)
	}
	if comment == "" {
		comment = d.Comment
	}
	// Device CLIs are whitespace-delimited; a comment with spaces would be
	// parsed as extra arguments.
	comment = strings.ReplaceAll(comment, " ", "_")

	return substitutions{
		Username:    username,
		Key:         strings.TrimSpace(d.PublicLine),
		Type:        keyType,
		Blob:        blob,
		Comment:     comment,
		Fingerprint: d.Fingerprint,
		ChunkWidth:  profile.ChunkWidth,
	}, nil
}

// extractKeys finds authorized-key lines in arbitrary CLI output.
//
// Device output interleaves configuration with prompts, banners, and vendor
// prefixes, and some platforms quote the key inside a command that itself
// names the key type — Junos writes:
//
//	set ... authentication ssh-ed25519 "ssh-ed25519 AAAA... comment"
//
// so "find the first key type and take the rest of the line" gets it wrong.
// Scanning tokens and keeping whichever candidate actually parses is the only
// approach that survives all of them.
func extractKeys(output string) []keys.Entry {
	var found []keys.Entry

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}

		if entry, ok := keyFromLine(line); ok {
			found = append(found, entry)
		}
	}
	return found
}

// keyFromLine pulls the public key out of one line of device output.
func keyFromLine(line string) (keys.Entry, bool) {
	// Quotes are delimiters here, not content.
	fields := strings.Fields(strings.ReplaceAll(line, `"`, " "))

	for i, field := range fields {
		if !isKeyType(field) {
			continue
		}
		if i+1 >= len(fields) {
			continue
		}

		candidate := field + " " + fields[i+1]
		if i+2 < len(fields) {
			candidate += " " + fields[i+2]
		}

		parsed := keys.ParseAuthorizedKeys([]byte(candidate))
		for _, e := range parsed.Keys() {
			if e.Fingerprint != "" {
				return e, true
			}
		}
	}
	return keys.Entry{}, false
}

// keyTypes are the token values that begin a public key.
var keyTypes = map[string]bool{
	"ssh-ed25519": true, "ssh-rsa": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

func isKeyType(s string) bool { return keyTypes[s] }

func findMarker(output string, markers []string) string {
	lower := strings.ToLower(output)
	for _, m := range markers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return strings.TrimSpace(m)
		}
	}
	return ""
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(line)
}

// previewDiff renders the commands a dry run would send, since a device's
// before/after configuration is not knowable without applying them.
func previewDiff(name string, commands []string) string {
	if len(commands) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s (no change)\n+++ %s (would run)\n", name, name)
	for _, cmd := range commands {
		for _, line := range strings.Split(cmd, "\n") {
			fmt.Fprintf(&b, "+%s\n", line)
		}
	}
	return b.String()
}

// Settings describes what a netdev target needs configured.
func (c *Connector) Settings() []connectors.Setting {
	return []connectors.Setting{
		{
			Key: "profile", Label: "Vendor profile", Type: "choice",
			Choices: ProfileNames(), Required: true, Default: "generic",
			Description: "The command vocabulary for this platform. Profiles are written " +
				"from published vendor syntax; check the first deployment to an " +
				"unfamiliar platform by hand.",
		},
		{
			Key: "show_keys", Label: "Override the show-keys command", Type: "string",
			Description: "Leave empty to use the profile's own. Setting this on a " +
				"profile that has none does not make the platform listable.",
		},
		{
			Key: "show_config", Label: "Override the snapshot command", Type: "string",
			Description: "Leave empty to use the profile's own.",
		},
		{
			Key: "show_version", Label: "Override the probe command", Type: "string",
			Description: "Run on probe to confirm the device answers. Leave empty for the default.",
		},
		{
			Key: "key_format", Label: "Key format", Type: "choice",
			Choices:     []string{"", "openssh", "type_blob", "chunked"},
			Description: "How the key is presented in the add command. Leave empty to use the profile's.",
		},
	}
}
