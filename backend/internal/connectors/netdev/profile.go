// Package netdev manages SSH keys on network devices through their CLI.
//
// Network devices are the case that breaks most key managers. They have no
// authorized_keys file, no shell, a pager that blocks output, a configuration
// mode that must be entered and left, and a commit step that decides whether
// anything happened at all. What they do have is a per-vendor command sequence,
// which is what a profile encodes.
//
// The honest capability position: most profiles can list and verify, and can
// capture the running configuration as a snapshot, but cannot restore one. A
// blind push of a whole running configuration is a far more dangerous operation
// than the one being undone, so this connector declines to offer it and reports
// CanRestore=false rather than pretending.
package netdev

import (
	"fmt"
	"sort"
	"strings"
)

// KeyFormat describes how a device wants the public key presented.
type KeyFormat string

const (
	// FormatOpenSSH is the whole "ssh-ed25519 AAAA... comment" line.
	FormatOpenSSH KeyFormat = "openssh"
	// FormatTypeAndBlob splits the type and the base64 blob into separate
	// substitutions, which is what most vendors' single-line syntax wants.
	FormatTypeAndBlob KeyFormat = "type_blob"
	// FormatChunked emits the base64 blob wrapped to a fixed width across
	// several lines, as Cisco IOS's key-string block requires.
	FormatChunked KeyFormat = "chunked"
)

// Profile is one vendor's command vocabulary.
//
// Every command is a template over {{username}}, {{key}}, {{type}}, {{blob}},
// {{comment}} and {{fingerprint}}. Keeping them as data rather than code means
// supporting a new platform is a table entry, not a new Go file.
type Profile struct {
	Name        string
	Description string

	// Setup runs first, typically to disable the pager.
	Setup []string
	// EnterConfig and ExitConfig bracket the mutating commands.
	EnterConfig []string
	ExitConfig  []string
	// AddKey and RemoveKey are the per-key command sequences.
	AddKey    []string
	RemoveKey []string
	// Commit persists the running configuration.
	Commit []string

	// ShowKeys reads back the authorized keys for a user. Empty means the
	// platform cannot be listed, and the connector reports CanList=false.
	ShowKeys string
	// ShowConfig captures a snapshot. Empty means no snapshot capability.
	ShowConfig string

	KeyFormat  KeyFormat
	ChunkWidth int

	// ErrorMarkers are substrings that mean the device rejected a command even
	// though the session itself succeeded. Network CLIs almost never set a
	// non-zero exit status, so this is the only reliable failure signal.
	ErrorMarkers []string

	// CanRestore is false for every multi-key profile; see the package comment.
	// Single-key platforms are the exception: there, restoring a snapshot means
	// re-issuing one AddKey, which is a bounded operation rather than a blind
	// push of a whole running configuration.
	CanRestore bool

	// SingleKey marks a platform that holds one key per username.
	//
	// Confirmed against Arista EOS 4.26.9M: issuing a second
	// "username X ssh-key ..." replaces the first, with no error and no
	// indication that anything was lost. The indexed form other releases
	// accept — "username X ssh-key 1 ..." — is rejected outright there.
	SingleKey bool
}

// DefaultErrorMarkers are the phrases common CLIs use to reject input.
var DefaultErrorMarkers = []string{
	"% Invalid input", "% Incomplete command", "% Unknown command",
	"% Bad IP address", "% Error", "Invalid input detected",
	"syntax error", "unknown command", "error: ", "^ (unknown command)",
	"Permission denied", "% Authorization failed",
}

// Profiles is the built-in vendor table.
//
// These are written from published vendor syntax, not from devices in this
// repository's test fleet: SKM's integration suite covers the Linux connector
// against real sshd containers, and a scripted device emulator for the netdev
// path. Treat an unlisted platform as a candidate for the exec connector rather
// than assuming an approximate profile will work.
var Profiles = map[string]Profile{
	"arista_eos": {
		Name:        "arista_eos",
		Description: "Arista EOS",
		Setup:       []string{"terminal length 0"},
		EnterConfig: []string{"configure terminal"},
		ExitConfig:  []string{"end"},
		AddKey:      []string{"username {{username}} ssh-key {{type}} {{blob}} {{comment}}"},
		RemoveKey:   []string{"no username {{username}} ssh-key"},
		Commit:      []string{"write memory"},
		ShowKeys:    "show running-config section username {{username}}",
		ShowConfig:  "show running-config section username",
		KeyFormat:   FormatTypeAndBlob,
		SingleKey:   true,
		CanRestore:  true,
	},
	"juniper_junos": {
		Name:        "juniper_junos",
		Description: "Juniper Junos",
		Setup:       []string{"set cli screen-length 0"},
		EnterConfig: []string{"configure"},
		ExitConfig:  []string{"exit"},
		AddKey: []string{
			`set system login user {{username}} authentication {{type}} "{{key}}"`,
		},
		RemoveKey: []string{
			`delete system login user {{username}} authentication {{type}} "{{key}}"`,
		},
		Commit:     []string{"commit and-quit"},
		ShowKeys:   "show configuration system login user {{username}} authentication | display set",
		ShowConfig: "show configuration system login | display set",
		KeyFormat:  FormatOpenSSH,
		ErrorMarkers: append([]string{
			"error: statement not found", "commit failed",
		}, DefaultErrorMarkers...),
	},
	"cisco_iosxe": {
		Name:        "cisco_iosxe",
		Description: "Cisco IOS / IOS-XE",
		Setup:       []string{"terminal length 0"},
		EnterConfig: []string{"configure terminal"},
		ExitConfig:  []string{"end"},
		AddKey: []string{
			"ip ssh pubkey-chain",
			"username {{username}}",
			"key-string",
			"{{blob_chunks}}",
			"exit",
			"exit",
			"exit",
		},
		RemoveKey: []string{
			"ip ssh pubkey-chain",
			"no username {{username}}",
			"exit",
		},
		Commit:     []string{"write memory"},
		ShowKeys:   "show running-config | section ip ssh pubkey-chain",
		ShowConfig: "show running-config | section ip ssh pubkey-chain",
		KeyFormat:  FormatChunked,
		ChunkWidth: 72,
	},
	"cisco_nxos": {
		Name:        "cisco_nxos",
		Description: "Cisco NX-OS",
		Setup:       []string{"terminal length 0"},
		EnterConfig: []string{"configure terminal"},
		ExitConfig:  []string{"end"},
		AddKey:      []string{`username {{username}} sshkey {{type}} {{blob}}`},
		RemoveKey:   []string{"no username {{username}} sshkey"},
		Commit:      []string{"copy running-config startup-config"},
		ShowKeys:    "show running-config | include \"username {{username}} sshkey\"",
		ShowConfig:  "show running-config | include sshkey",
		KeyFormat:   FormatTypeAndBlob,
	},
	"generic": {
		Name:        "generic",
		Description: "A device whose commands are supplied per target",
		KeyFormat:   FormatOpenSSH,
	},
}

// ProfileNames lists the built-in profiles in a stable order.
//
// Sorted, because map iteration is not: an unsorted list shuffles the choices
// in the interface on every request and reorders the names in the "known
// profiles" error message, which makes the same error look like a different
// one each time it is read.
func ProfileNames() []string {
	out := make([]string, 0, len(Profiles))
	for name := range Profiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Lookup returns a profile by name.
func Lookup(name string) (Profile, error) {
	p, ok := Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("netdev: no profile named %q (known: %s)",
			name, strings.Join(ProfileNames(), ", "))
	}
	if len(p.ErrorMarkers) == 0 {
		p.ErrorMarkers = DefaultErrorMarkers
	}
	if p.ChunkWidth == 0 {
		p.ChunkWidth = 72
	}
	return p, nil
}

// substitutions are the values a command template can reference.
type substitutions struct {
	Username    string
	Key         string
	Type        string
	Blob        string
	Comment     string
	Fingerprint string
	ChunkWidth  int
}

// render expands a command template.
func render(tmpl string, s substitutions) string {
	replacements := []string{
		"{{username}}", s.Username,
		"{{key}}", s.Key,
		"{{type}}", s.Type,
		"{{blob}}", s.Blob,
		"{{comment}}", s.Comment,
		"{{fingerprint}}", s.Fingerprint,
	}
	out := strings.NewReplacer(replacements...).Replace(tmpl)

	// The chunked substitution expands to several lines, so it is handled
	// after the single-value replacements.
	if strings.Contains(out, "{{blob_chunks}}") {
		out = strings.ReplaceAll(out, "{{blob_chunks}}", chunk(s.Blob, s.ChunkWidth))
	}
	return out
}

// chunk wraps a base64 blob to the width a device's key-string block expects.
func chunk(blob string, width int) string {
	if width <= 0 {
		width = 72
	}

	var lines []string
	for len(blob) > width {
		lines = append(lines, blob[:width])
		blob = blob[width:]
	}
	if blob != "" {
		lines = append(lines, blob)
	}
	return strings.Join(lines, "\n")
}

// splitPublicLine breaks "ssh-ed25519 AAAA... comment" into its parts.
func splitPublicLine(line string) (keyType, blob, comment string) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return "", "", ""
	}
	keyType, blob = fields[0], fields[1]
	if len(fields) > 2 {
		comment = strings.Join(fields[2:], " ")
	}
	return keyType, blob, comment
}
