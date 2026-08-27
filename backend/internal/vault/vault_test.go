package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// testKEK returns a deterministic-length random key.
func testKEK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return k
}

// unsealed returns a vault holding version 1.
func unsealed(t *testing.T) *Vault {
	t.Helper()
	v := New()
	if err := v.Unseal(1, testKEK(t)); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	return v
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{"empty plaintext", []byte{}, []byte("key:1")},
		{"short", []byte("hunter2"), []byte("key:1")},
		{"nil aad", []byte("secret"), nil},
		{"binary", []byte{0x00, 0xff, 0x7f, 0x80, 0x00}, []byte("key:2")},
		{"large", bytes.Repeat([]byte("A"), 64*1024), []byte("key:3")},
	}

	v := unsealed(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sealed, err := v.Encrypt(tc.plaintext, tc.aad)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			got, err := v.Decrypt(sealed, tc.aad)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, tc.plaintext) {
				t.Errorf("round trip mismatch: got %q want %q", got, tc.plaintext)
			}
		})
	}
}

// The ciphertext must never equal the plaintext, and repeated encryption of the
// same input must differ — a fresh DEK and nonce every time.
func TestEncryptIsNondeterministic(t *testing.T) {
	v := unsealed(t)
	pt, aad := []byte("same plaintext"), []byte("key:1")

	a, err := v.Encrypt(pt, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := v.Encrypt(pt, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Error("two encryptions of the same plaintext produced identical ciphertext")
	}
	if bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Error("two encryptions produced identical wrapped DEKs")
	}
	if bytes.Contains(a.Ciphertext, pt) {
		t.Error("plaintext appears verbatim in ciphertext")
	}
}

// AAD binding is what stops an attacker with database write access from moving
// one row's ciphertext onto another row.
func TestAADMismatchFails(t *testing.T) {
	v := unsealed(t)
	sealed, err := v.Encrypt([]byte("secret"), []byte("key:aaa"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := v.Decrypt(sealed, []byte("key:bbb")); err == nil {
		t.Fatal("decrypt with wrong AAD succeeded; ciphertext is not bound to its owner")
	}
	if _, err := v.Decrypt(sealed, nil); err == nil {
		t.Fatal("decrypt with nil AAD succeeded against non-nil AAD ciphertext")
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	v := unsealed(t)
	aad := []byte("key:1")
	sealed, err := v.Encrypt([]byte("secret value"), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(s *Sealed)
	}{
		{"flip ciphertext bit", func(s *Sealed) { s.Ciphertext[len(s.Ciphertext)-1] ^= 0x01 }},
		{"flip nonce bit", func(s *Sealed) { s.Ciphertext[0] ^= 0x01 }},
		{"flip wrapped DEK bit", func(s *Sealed) { s.WrappedDEK[len(s.WrappedDEK)-1] ^= 0x01 }},
		{"truncate ciphertext", func(s *Sealed) { s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1] }},
		{"empty ciphertext", func(s *Sealed) { s.Ciphertext = nil }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := &Sealed{
				KEKVersion: sealed.KEKVersion,
				WrappedDEK: append([]byte(nil), sealed.WrappedDEK...),
				Ciphertext: append([]byte(nil), sealed.Ciphertext...),
			}
			tc.mutate(cp)
			if _, err := v.Decrypt(cp, aad); err == nil {
				t.Error("decrypt of tampered value succeeded")
			}
		})
	}
}

func TestSealedVaultRefusesOperations(t *testing.T) {
	v := unsealed(t)
	sealed, err := v.Encrypt([]byte("secret"), []byte("key:1"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	v.Seal()

	if !v.IsSealed() {
		t.Error("IsSealed() = false after Seal()")
	}
	if got := v.CurrentVersion(); got != 0 {
		t.Errorf("CurrentVersion() = %d after Seal(), want 0", got)
	}
	if _, err := v.Encrypt([]byte("x"), nil); !errors.Is(err, ErrSealed) {
		t.Errorf("Encrypt on sealed vault: got %v, want ErrSealed", err)
	}
	if _, err := v.Decrypt(sealed, []byte("key:1")); !errors.Is(err, ErrSealed) {
		t.Errorf("Decrypt on sealed vault: got %v, want ErrSealed", err)
	}
	if _, err := v.Rewrap(sealed, []byte("key:1")); !errors.Is(err, ErrSealed) {
		t.Errorf("Rewrap on sealed vault: got %v, want ErrSealed", err)
	}
}

// The core KEK-rotation property: the secret ciphertext is untouched, only the
// wrapped DEK changes, and the plaintext still decrypts.
func TestRewrapRotatesKEKWithoutRewritingCiphertext(t *testing.T) {
	v := New()
	if err := v.Unseal(1, testKEK(t)); err != nil {
		t.Fatalf("Unseal v1: %v", err)
	}

	plaintext, aad := []byte("private key material"), []byte("key:42")
	old, err := v.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if err := v.Unseal(2, testKEK(t)); err != nil {
		t.Fatalf("Unseal v2: %v", err)
	}
	if got := v.CurrentVersion(); got != 2 {
		t.Fatalf("CurrentVersion() = %d after unsealing v2, want 2", got)
	}

	fresh, err := v.Rewrap(old, aad)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	if fresh.KEKVersion != 2 {
		t.Errorf("rewrapped KEKVersion = %d, want 2", fresh.KEKVersion)
	}
	if !bytes.Equal(fresh.Ciphertext, old.Ciphertext) {
		t.Error("Rewrap rewrote the secret ciphertext; it must only rewrap the DEK")
	}
	if bytes.Equal(fresh.WrappedDEK, old.WrappedDEK) {
		t.Error("Rewrap left the wrapped DEK unchanged")
	}

	got, err := v.Decrypt(fresh, aad)
	if err != nil {
		t.Fatalf("Decrypt after rewrap: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext after rewrap = %q, want %q", got, plaintext)
	}

	// Old-version rows must stay readable until they are rewrapped.
	if _, err := v.Decrypt(old, aad); err != nil {
		t.Errorf("pre-rotation value no longer decrypts: %v", err)
	}
}

// A partially completed rotation gets retried, so rewrapping twice must be safe.
func TestRewrapIsIdempotent(t *testing.T) {
	v := unsealed(t)
	aad := []byte("key:1")
	sealed, err := v.Encrypt([]byte("secret"), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	again, err := v.Rewrap(sealed, aad)
	if err != nil {
		t.Fatalf("Rewrap at current version: %v", err)
	}
	if again != sealed {
		t.Error("Rewrap at the current version should return the value unchanged")
	}
}

// Restoring a backup under the wrong master key must fail loudly, not silently
// produce garbage.
func TestUnknownKEKVersion(t *testing.T) {
	v := unsealed(t)
	sealed, err := v.Encrypt([]byte("secret"), []byte("key:1"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	sealed.KEKVersion = 99

	if _, err := v.Decrypt(sealed, []byte("key:1")); !errors.Is(err, ErrUnknownKEK) {
		t.Errorf("Decrypt with unknown KEK version: got %v, want ErrUnknownKEK", err)
	}
}

func TestWrongKEKFails(t *testing.T) {
	a := unsealed(t)
	sealed, err := a.Encrypt([]byte("secret"), []byte("key:1"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// A different vault at the same version — i.e. the wrong master key.
	b := unsealed(t)
	if _, err := b.Decrypt(sealed, []byte("key:1")); err == nil {
		t.Fatal("decrypt succeeded under a different KEK")
	}
}

func TestUnsealValidation(t *testing.T) {
	tests := []struct {
		name    string
		version int
		keyLen  int
		wantErr error
	}{
		{"valid", 1, KeyLen, nil},
		{"short key", 1, KeyLen - 1, ErrBadKeyLen},
		{"long key", 1, KeyLen + 1, ErrBadKeyLen},
		{"empty key", 1, 0, ErrBadKeyLen},
		{"zero version", 0, KeyLen, nil}, // non-nil error, checked below
		{"negative version", -1, KeyLen, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := New()
			err := v.Unseal(tc.version, make([]byte, tc.keyLen))
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("got %v, want %v", err, tc.wantErr)
				}
			case tc.version < 1:
				if err == nil {
					t.Error("expected an error for a version below 1")
				}
			default:
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("b[%d] = %d after Zero, want 0", i, v)
		}
	}
}

// Concurrent use is the normal case: many workers encrypt while an operator
// rotates the KEK. Run with -race.
func TestConcurrentUse(t *testing.T) {
	v := unsealed(t)
	const goroutines = 16

	done := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			aad := []byte("key:concurrent")
			s, err := v.Encrypt([]byte("secret"), aad)
			if err != nil {
				done <- err
				return
			}
			_, err = v.Decrypt(s, aad)
			done <- err
		}()
	}
	// Rotate underneath the readers.
	if err := v.Unseal(2, testKEK(t)); err != nil {
		t.Fatalf("Unseal v2: %v", err)
	}

	for i := 0; i < goroutines; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent operation failed: %v", err)
		}
	}
}
