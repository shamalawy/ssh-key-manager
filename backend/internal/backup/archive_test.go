package backup

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// Argon2 at production cost takes about a second per derivation, which would
// make this file slow enough that nobody runs it. The tests below exercise the
// format, not the cost parameters, so they use a cheap KDF and one test asserts
// the production defaults separately.
func cheapWrite(t *testing.T, passphrase string, payload *Payload) []byte {
	t.Helper()

	original := newKDF
	newKDF = func() KDFParams {
		return KDFParams{Algorithm: "argon2id", Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	}
	t.Cleanup(func() { newKDF = original })

	var buf bytes.Buffer
	if _, _, err := Write(&buf, passphrase, "full", "test", payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.Bytes()
}

func samplePayload() *Payload {
	return &Payload{
		ExportedAt: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		Keys: []KeyRecord{
			{
				ID: "11111111-1111-1111-1111-111111111111", Name: "web-fleet",
				Algorithm: "ed25519", Fingerprint: "SHA256:aaaa",
				PublicKey: "ssh-ed25519 AAAA web", PrivatePEM: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
				Status: "active", KeyClass: "standard", Generation: 2, Tags: []string{"prod"},
			},
			{
				ID: "22222222-2222-2222-2222-222222222222", Name: "adopted-one",
				Algorithm: "ssh-rsa", Fingerprint: "SHA256:bbbb",
				PublicKey: "ssh-rsa AAAA legacy", Status: "active", KeyClass: "discovered",
			},
		},
		Targets: []TargetRecord{
			{ID: "33333333-3333-3333-3333-333333333333", Name: "web-01",
				Connector: "linux", Address: "10.0.0.1", Port: 22, Tags: []string{"prod"}},
		},
	}
}

func TestRoundTrip(t *testing.T) {
	payload := samplePayload()
	archive := cheapWrite(t, "correct horse battery staple", payload)

	header, decoded, err := Read(bytes.NewReader(archive), "correct horse battery staple")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if header.KeyCount != 2 {
		t.Errorf("header.KeyCount = %d, want 2", header.KeyCount)
	}
	if len(decoded.Keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(decoded.Keys))
	}
	if decoded.Keys[0].PrivatePEM != payload.Keys[0].PrivatePEM {
		t.Error("the private key did not survive the round trip")
	}
	if len(decoded.Targets) != 1 || decoded.Targets[0].Name != "web-01" {
		t.Error("targets did not survive the round trip")
	}
}

func TestWrongPassphraseIsRefused(t *testing.T) {
	archive := cheapWrite(t, "the right passphrase", samplePayload())

	_, _, err := Read(bytes.NewReader(archive), "the wrong passphrase")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Read with a wrong passphrase = %v, want ErrWrongPassphrase", err)
	}
}

func TestPassphraseIsRequired(t *testing.T) {
	var buf bytes.Buffer
	_, _, err := Write(&buf, "", "full", "test", samplePayload())
	if err == nil {
		t.Fatal("Write accepted an empty passphrase; an unencrypted export of every private key must be refused")
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("the error should say why: %v", err)
	}
}

// The archive is exactly as valuable as the vault. A tampered ciphertext must
// fail loudly rather than decrypt to something plausible.
func TestTamperedCiphertextIsDetected(t *testing.T) {
	archive := cheapWrite(t, "correct horse battery staple", samplePayload())

	// Flip a bit well past the header, inside the AEAD-protected body.
	tampered := append([]byte(nil), archive...)
	tampered[len(tampered)-20] ^= 0x01

	if _, _, err := Read(bytes.NewReader(tampered), "correct horse battery staple"); err == nil {
		t.Fatal("Read accepted a tampered archive")
	}
}

// The header is authenticated as additional data, so an attacker cannot swap
// the derivation parameters for cheaper ones and attack the file offline.
func TestTamperedHeaderIsDetected(t *testing.T) {
	archive := cheapWrite(t, "correct horse battery staple", samplePayload())

	// The header is JSON in the clear; change the recorded key count.
	tampered := bytes.Replace(archive, []byte(`"key_count":2`), []byte(`"key_count":9`), 1)
	if bytes.Equal(tampered, archive) {
		t.Fatal("the test could not find the field it meant to alter")
	}

	if _, _, err := Read(bytes.NewReader(tampered), "correct horse battery staple"); err == nil {
		t.Fatal("Read accepted an archive whose header had been altered")
	}
}

func TestNonArchiveIsRejectedClearly(t *testing.T) {
	_, _, err := Read(strings.NewReader("this is just a text file\n"), "whatever")
	if !errors.Is(err, ErrNotAnArchive) {
		t.Fatalf("Read of a non-archive = %v, want ErrNotAnArchive", err)
	}
}

// ReadHeader must work without the passphrase: listing archives and checking
// what a file is should not require handing over the key to every private key.
func TestHeaderIsReadableWithoutThePassphrase(t *testing.T) {
	archive := cheapWrite(t, "correct horse battery staple", samplePayload())

	header, _, err := ReadHeader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if header.Kind != "full" || header.KeyCount != 2 {
		t.Errorf("header = %+v, want kind=full key_count=2", header)
	}
	if header.Version != FormatVersion {
		t.Errorf("header.Version = %d, want %d", header.Version, FormatVersion)
	}
}

func TestHeaderCarriesNoSecrets(t *testing.T) {
	payload := samplePayload()
	archive := cheapWrite(t, "correct horse battery staple", payload)

	_, headerJSON, err := ReadHeader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

	// Neither the private key nor the passphrase may appear in the plaintext
	// preamble.
	if bytes.Contains(headerJSON, []byte("BEGIN PRIVATE KEY")) {
		t.Error("the header contains private key material")
	}
	if bytes.Contains(headerJSON, []byte("correct horse")) {
		t.Error("the header contains the passphrase")
	}
	// Nor may they appear anywhere in the archive as plaintext.
	if bytes.Contains(archive, []byte("BEGIN PRIVATE KEY")) {
		t.Error("the archive contains unencrypted private key material")
	}
}

func TestNewerVersionIsRefused(t *testing.T) {
	archive := cheapWrite(t, "correct horse battery staple", samplePayload())
	tampered := bytes.Replace(archive, []byte(`"version":1`), []byte(`"version":9`), 1)

	_, _, err := ReadHeader(bytes.NewReader(tampered))
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("ReadHeader of a future version = %v, want ErrUnsupportedVersion", err)
	}
}

// The production cost is deliberately higher than the login parameters: a
// backup passphrase is attacked offline, for as long as an attacker likes.
func TestDefaultKDFIsExpensive(t *testing.T) {
	kdf := DefaultKDF()

	if kdf.Algorithm != "argon2id" {
		t.Errorf("Algorithm = %q, want argon2id", kdf.Algorithm)
	}
	if kdf.MemoryKiB < 128*1024 {
		t.Errorf("MemoryKiB = %d, want at least 131072 (128 MiB)", kdf.MemoryKiB)
	}
	if kdf.Time < 3 {
		t.Errorf("Time = %d, want at least 3", kdf.Time)
	}
}

func TestSaltDiffersBetweenArchives(t *testing.T) {
	first := cheapWrite(t, "correct horse battery staple", samplePayload())
	second := cheapWrite(t, "correct horse battery staple", samplePayload())

	h1, _, err := ReadHeader(bytes.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	h2, _, err := ReadHeader(bytes.NewReader(second))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(h1.KDF.Salt, h2.KDF.Salt) {
		t.Error("two archives share a salt; the same passphrase would derive the same key")
	}
	if bytes.Equal(h1.Nonce, h2.Nonce) {
		t.Error("two archives share a nonce")
	}
}
