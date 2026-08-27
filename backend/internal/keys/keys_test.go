package keys

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name    string
		alg     Algorithm
		sshType string
		slow    bool
	}{
		{"ed25519", Ed25519, "ssh-ed25519", false},
		{"ecdsa p256", ECDSAP256, "ecdsa-sha2-nistp256", false},
		{"ecdsa p384", ECDSAP384, "ecdsa-sha2-nistp384", false},
		{"ecdsa p521", ECDSAP521, "ecdsa-sha2-nistp521", false},
		{"rsa 3072", RSA3072, "ssh-rsa", true},
		{"rsa 4096", RSA4096, "ssh-rsa", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.slow && testing.Short() {
				t.Skip("RSA generation is slow; skipped under -short")
			}

			kp, err := Generate(tc.alg, "skm-test@example.com")
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}

			if kp.Algorithm != tc.alg {
				t.Errorf("Algorithm = %q, want %q", kp.Algorithm, tc.alg)
			}
			if !strings.HasPrefix(kp.PublicLine, tc.sshType+" ") {
				t.Errorf("PublicLine = %q, want prefix %q", kp.PublicLine, tc.sshType)
			}
			if !strings.HasSuffix(kp.PublicLine, " skm-test@example.com") {
				t.Errorf("PublicLine missing comment: %q", kp.PublicLine)
			}
			if !strings.HasPrefix(kp.Fingerprint, "SHA256:") {
				t.Errorf("Fingerprint = %q, want SHA256: prefix", kp.Fingerprint)
			}
			if !bytes.Contains(kp.PrivatePEM, []byte("OPENSSH PRIVATE KEY")) {
				t.Error("PrivatePEM is not in OpenSSH format")
			}

			// The private key must actually work as a signer, and its public
			// half must match the line we published.
			signer, err := Signer(kp.PrivatePEM)
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			if got := ssh.FingerprintSHA256(signer.PublicKey()); got != kp.Fingerprint {
				t.Errorf("signer fingerprint = %q, want %q", got, kp.Fingerprint)
			}

			// The published line must parse as an authorized_keys entry.
			if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(kp.PublicLine)); err != nil {
				t.Errorf("PublicLine does not parse as an authorized_keys entry: %v", err)
			}
		})
	}
}

func TestGenerateRejectsUnknownAlgorithm(t *testing.T) {
	for _, alg := range []Algorithm{"", "dsa", "rsa-1024", "nonsense"} {
		if _, err := Generate(alg, "c"); err == nil {
			t.Errorf("Generate(%q) succeeded; want an error", alg)
		}
	}
}

func TestGenerateIsUnique(t *testing.T) {
	a, err := Generate(Ed25519, "c")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := Generate(Ed25519, "c")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if a.Fingerprint == b.Fingerprint {
		t.Error("two generated keys share a fingerprint")
	}
}

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		in      string
		want    Algorithm
		wantErr bool
	}{
		{"ed25519", Ed25519, false},
		{"ED25519", Ed25519, false},
		{"ssh-ed25519", Ed25519, false},
		{"", DefaultAlgorithm, false},
		{"default", DefaultAlgorithm, false},
		{"ecdsa", ECDSAP256, false},
		{"nistp384", ECDSAP384, false},
		{"ecdsa_p521", ECDSAP521, false},
		{"rsa", RSA3072, false},
		{"rsa4096", RSA4096, false},
		{"  rsa-4096  ", RSA4096, false},
		{"dsa", "", true},
		{"rsa-1024", "", true},
		{"rsa-2048", "", true},
		{"blowfish", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseAlgorithm(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseAlgorithm(%q) = %q, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAlgorithm(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseAlgorithm(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestImportPrivateKeyRoundTrip(t *testing.T) {
	orig, err := Generate(Ed25519, "original@host")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	imported, err := ImportPrivateKey(orig.PrivatePEM, "")
	if err != nil {
		t.Fatalf("ImportPrivateKey: %v", err)
	}

	if imported.Fingerprint != orig.Fingerprint {
		t.Errorf("imported fingerprint = %q, want %q", imported.Fingerprint, orig.Fingerprint)
	}
	if imported.Algorithm != Ed25519 {
		t.Errorf("imported algorithm = %q, want ed25519", imported.Algorithm)
	}
}

func TestImportRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "not a key", "-----BEGIN OPENSSH PRIVATE KEY-----\ngarbage\n-----END OPENSSH PRIVATE KEY-----"} {
		if _, err := ImportPrivateKey([]byte(in), ""); err == nil {
			t.Errorf("ImportPrivateKey(%q) succeeded; want an error", in)
		}
	}
}

// A file SKM has not modified must be re-emitted byte for byte. Anything less
// means a deployment silently rewrites content it does not own.
func TestAuthorizedKeysRoundTripIsByteExact(t *testing.T) {
	kp, err := Generate(Ed25519, "user@host")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"single key", kp.PublicLine + "\n"},
		{"no trailing newline", kp.PublicLine},
		{"comments and blanks", "# managed by hand\n\n" + kp.PublicLine + "\n\n# trailing note\n"},
		{"with options", `from="10.0.0.0/8",no-pty ` + kp.PublicLine + "\n"},
		{"invalid line preserved", "this is not a key\n" + kp.PublicLine + "\n"},
		{"leading whitespace", "  # indented comment\n" + kp.PublicLine + "\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseAuthorizedKeys([]byte(tc.in)).Bytes()
			if string(got) != tc.in {
				t.Errorf("round trip changed the file:\n got: %q\nwant: %q", got, tc.in)
			}
		})
	}
}

func TestAuthorizedKeysParsing(t *testing.T) {
	kp, err := Generate(Ed25519, "user@host")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	src := "# header\n\n" +
		`from="10.0.0.0/8",no-pty ` + kp.PublicLine + "\n" +
		"garbage line\n"

	ak := ParseAuthorizedKeys([]byte(src))

	if got, want := len(ak.Entries), 4; got != want {
		t.Fatalf("entries = %d, want %d", got, want)
	}
	wantKinds := []EntryKind{EntryComment, EntryBlank, EntryKey, EntryInvalid}
	for i, want := range wantKinds {
		if got := ak.Entries[i].Kind; got != want {
			t.Errorf("entry %d kind = %v, want %v", i, got, want)
		}
	}

	if got := ak.Count(); got != 1 {
		t.Errorf("Count() = %d, want 1", got)
	}

	key := ak.Keys()[0]
	if key.Fingerprint != kp.Fingerprint {
		t.Errorf("fingerprint = %q, want %q", key.Fingerprint, kp.Fingerprint)
	}
	if got, want := strings.Join(key.Options, ","), `from="10.0.0.0/8",no-pty`; got != want {
		t.Errorf("options = %q, want %q", got, want)
	}
	if key.Comment != "user@host" {
		t.Errorf("comment = %q, want user@host", key.Comment)
	}
	if !ak.Has(kp.Fingerprint) {
		t.Error("Has() = false for a key that is present")
	}
}

func TestUpsertAndRemove(t *testing.T) {
	existing, err := Generate(Ed25519, "existing@host")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	incoming, err := Generate(Ed25519, "incoming@host")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ak := ParseAuthorizedKeys([]byte("# keep me\n" + existing.PublicLine + "\n"))

	entry, err := NewEntry(incoming.PublicLine, []string{`from="192.168.0.0/16"`})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}

	if changed := ak.Upsert(entry); !changed {
		t.Error("Upsert of a new key reported no change")
	}
	if got := ak.Count(); got != 2 {
		t.Fatalf("Count() = %d after upsert, want 2", got)
	}

	// Upserting an identical entry must be a no-op, so an already-converged
	// deployment does not rewrite the file.
	if changed := ak.Upsert(entry); changed {
		t.Error("Upsert of an identical key reported a change")
	}

	// Changing options must register as a change.
	updated, err := NewEntry(incoming.PublicLine, []string{"no-pty"})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	if changed := ak.Upsert(updated); !changed {
		t.Error("Upsert with different options reported no change")
	}
	if got := ak.Count(); got != 2 {
		t.Errorf("Count() = %d after option change, want 2", got)
	}

	out := string(ak.Bytes())
	if !strings.Contains(out, "# keep me") {
		t.Error("unmanaged comment was lost")
	}
	if !strings.Contains(out, "no-pty") {
		t.Error("updated options were not written")
	}

	if removed := ak.Remove(incoming.Fingerprint); !removed {
		t.Error("Remove reported the key was absent")
	}
	if ak.Has(incoming.Fingerprint) {
		t.Error("key still present after Remove")
	}
	if removed := ak.Remove(incoming.Fingerprint); removed {
		t.Error("Remove of an absent key reported success")
	}
	if got := ak.Count(); got != 1 {
		t.Errorf("Count() = %d after remove, want 1", got)
	}
	if !strings.Contains(string(ak.Bytes()), existing.PublicLine) {
		t.Error("the untouched key was lost during remove")
	}
}

func TestSupportedAlgorithmsIsStable(t *testing.T) {
	a, b := SupportedAlgorithms(), SupportedAlgorithms()
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Error("SupportedAlgorithms() is not stably ordered")
	}
	if len(a) == 0 {
		t.Fatal("SupportedAlgorithms() is empty")
	}
	for _, name := range a {
		if !Algorithm(name).Valid() {
			t.Errorf("SupportedAlgorithms() lists %q but Valid() is false", name)
		}
	}
}
