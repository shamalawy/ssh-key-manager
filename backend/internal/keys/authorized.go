package keys

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// EntryKind classifies a line in an authorized_keys file.
type EntryKind int

const (
	// EntryKey is a parseable public key line.
	EntryKey EntryKind = iota
	// EntryComment is a line starting with '#'.
	EntryComment
	// EntryBlank is an empty or whitespace-only line.
	EntryBlank
	// EntryInvalid is a non-empty line that failed to parse. SKM preserves
	// these verbatim rather than dropping them: a line it cannot read is
	// exactly the sort of thing that must survive a rewrite untouched.
	EntryInvalid
)

func (k EntryKind) String() string {
	switch k {
	case EntryKey:
		return "key"
	case EntryComment:
		return "comment"
	case EntryBlank:
		return "blank"
	default:
		return "invalid"
	}
}

// Entry is one line of an authorized_keys file.
type Entry struct {
	Kind EntryKind
	// Raw is the line exactly as read. It is re-emitted verbatim unless the
	// entry has been modified, which is what keeps unmanaged content byte-identical
	// across a rewrite.
	Raw string

	// The fields below are populated only for EntryKey.
	Options     []string
	Type        string
	PublicKey   ssh.PublicKey
	Comment     string
	Fingerprint string

	// dirty marks an entry as constructed or modified by SKM, so rendering
	// re-derives the line instead of echoing Raw.
	dirty bool
}

// AuthorizedKeys is a parsed authorized_keys file.
type AuthorizedKeys struct {
	Entries []Entry
	// TrailingNewline records whether the source ended with a newline, so a
	// rewrite does not silently add or drop one.
	TrailingNewline bool
}

// ParseAuthorizedKeys reads an authorized_keys file.
//
// It never fails. Anything unparseable is retained as EntryInvalid so that a
// subsequent write preserves it; refusing to parse the whole file because one
// line is malformed would be the wrong trade when the file guards login access.
func ParseAuthorizedKeys(data []byte) *AuthorizedKeys {
	ak := &AuthorizedKeys{TrailingNewline: len(data) > 0 && data[len(data)-1] == '\n'}

	body := strings.TrimSuffix(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if len(data) == 0 {
		return ak
	}

	for _, line := range strings.Split(body, "\n") {
		ak.Entries = append(ak.Entries, parseLine(line))
	}
	return ak
}

func parseLine(line string) Entry {
	trimmed := strings.TrimSpace(line)

	switch {
	case trimmed == "":
		return Entry{Kind: EntryBlank, Raw: line}
	case strings.HasPrefix(trimmed, "#"):
		return Entry{Kind: EntryComment, Raw: line}
	}

	pub, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return Entry{Kind: EntryInvalid, Raw: line}
	}

	return Entry{
		Kind:        EntryKey,
		Raw:         line,
		Options:     options,
		Type:        pub.Type(),
		PublicKey:   pub,
		Comment:     comment,
		Fingerprint: ssh.FingerprintSHA256(pub),
	}
}

// NewEntry builds a key entry from an authorized_keys line plus optional
// prefixed options such as `from="10.0.0.0/8"` or `no-pty`.
func NewEntry(publicLine string, options []string) (Entry, error) {
	pub, comment, inlineOpts, _, err := ssh.ParseAuthorizedKey([]byte(publicLine))
	if err != nil {
		return Entry{}, fmt.Errorf("keys: parsing public key line: %w", err)
	}

	// Options supplied by the caller win over any embedded in the line.
	if len(options) == 0 {
		options = inlineOpts
	}

	e := Entry{
		Kind:        EntryKey,
		Options:     options,
		Type:        pub.Type(),
		PublicKey:   pub,
		Comment:     comment,
		Fingerprint: ssh.FingerprintSHA256(pub),
		dirty:       true,
	}
	e.Raw = e.render()
	return e, nil
}

// render rebuilds the textual line for an entry from its fields.
func (e Entry) render() string {
	if e.Kind != EntryKey {
		return e.Raw
	}

	var b strings.Builder
	if len(e.Options) > 0 {
		b.WriteString(strings.Join(e.Options, ","))
		b.WriteByte(' ')
	}
	b.WriteString(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e.PublicKey))))
	if c := strings.TrimSpace(e.Comment); c != "" {
		b.WriteByte(' ')
		b.WriteString(c)
	}
	return b.String()
}

// Line returns the entry as it will be written.
func (e Entry) Line() string {
	if e.dirty {
		return e.render()
	}
	return e.Raw
}

// Bytes renders the file for writing back to the target.
func (ak *AuthorizedKeys) Bytes() []byte {
	var b bytes.Buffer
	for i, e := range ak.Entries {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(e.Line())
	}
	if len(ak.Entries) > 0 && ak.TrailingNewline {
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// Keys returns just the key entries, in file order.
func (ak *AuthorizedKeys) Keys() []Entry {
	out := make([]Entry, 0, len(ak.Entries))
	for _, e := range ak.Entries {
		if e.Kind == EntryKey {
			out = append(out, e)
		}
	}
	return out
}

// Fingerprints returns the SHA256 fingerprint of every key present.
func (ak *AuthorizedKeys) Fingerprints() []string {
	out := make([]string, 0, len(ak.Entries))
	for _, e := range ak.Entries {
		if e.Kind == EntryKey {
			out = append(out, e.Fingerprint)
		}
	}
	return out
}

// IndexOf returns the position of the key with the given fingerprint, or -1.
func (ak *AuthorizedKeys) IndexOf(fingerprint string) int {
	for i, e := range ak.Entries {
		if e.Kind == EntryKey && e.Fingerprint == fingerprint {
			return i
		}
	}
	return -1
}

// Has reports whether the fingerprint is present.
func (ak *AuthorizedKeys) Has(fingerprint string) bool { return ak.IndexOf(fingerprint) >= 0 }

// Upsert adds an entry, or updates the options and comment of an existing key
// with the same fingerprint. It reports whether the file changed, which lets
// callers skip a write — and therefore skip a snapshot and an audit entry —
// when a deployment is already in the desired state.
func (ak *AuthorizedKeys) Upsert(e Entry) bool {
	if e.Kind != EntryKey {
		return false
	}

	i := ak.IndexOf(e.Fingerprint)
	if i < 0 {
		e.dirty = true
		ak.Entries = append(ak.Entries, e)
		ak.TrailingNewline = true
		return true
	}

	existing := ak.Entries[i]
	if equalOptions(existing.Options, e.Options) && existing.Comment == e.Comment {
		return false
	}

	e.dirty = true
	ak.Entries[i] = e
	return true
}

// Remove deletes the key with the given fingerprint, reporting whether it was
// present.
func (ak *AuthorizedKeys) Remove(fingerprint string) bool {
	i := ak.IndexOf(fingerprint)
	if i < 0 {
		return false
	}
	ak.Entries = append(ak.Entries[:i], ak.Entries[i+1:]...)
	return true
}

// Count returns the number of key entries.
func (ak *AuthorizedKeys) Count() int { return len(ak.Keys()) }

func equalOptions(a, b []string) bool {
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
