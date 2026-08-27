// Package vault provides envelope encryption for private key material.
//
// Every secret is encrypted under its own randomly generated data encryption
// key (DEK); the DEK is then wrapped by a key encryption key (KEK) held in
// memory. Two properties follow, and both matter operationally:
//
//   - Rotating the KEK only requires rewrapping DEKs, not re-encrypting
//     secrets. Rewrapping millions of small wrapped-DEK blobs is cheap;
//     re-encrypting the secrets themselves would not be.
//   - The KEK never touches secret plaintext, so a KEK compromise without
//     database access yields nothing.
//
// All encryption is AES-256-GCM. Callers must supply additional authenticated
// data (AAD) binding the ciphertext to its logical owner — normally the row's
// primary key. This is what prevents an attacker with write access to the
// database from swapping one row's ciphertext into another row and having it
// decrypt successfully.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// KeyLen is the required KEK and DEK length: AES-256.
const KeyLen = 32

var (
	// ErrSealed is returned by every operation that needs the KEK while the
	// vault is sealed.
	ErrSealed = errors.New("vault: sealed")
	// ErrUnknownKEK means a Sealed value references a KEK version this vault
	// has not been given. Usually a restore against the wrong master key.
	ErrUnknownKEK = errors.New("vault: unknown KEK version")
	// ErrBadKeyLen means a supplied key was not KeyLen bytes.
	ErrBadKeyLen = errors.New("vault: key must be 32 bytes")
)

// Sealed is an encrypted secret together with everything needed to decrypt it
// given the right KEK. It is safe to persist verbatim.
type Sealed struct {
	// KEKVersion identifies which KEK wrapped the DEK.
	KEKVersion int
	// WrappedDEK is nonce||ciphertext||tag of the DEK under the KEK.
	WrappedDEK []byte
	// Ciphertext is nonce||ciphertext||tag of the secret under the DEK.
	Ciphertext []byte
}

// Vault holds KEKs in memory and performs envelope encryption.
//
// A Vault may hold several KEK versions at once: during a rotation the new
// version becomes current for writes while older versions remain available so
// existing rows stay readable until they are rewrapped.
type Vault struct {
	mu      sync.RWMutex
	keks    map[int][]byte
	current int
}

// New returns a sealed vault holding no keys.
func New() *Vault {
	return &Vault{keks: make(map[int][]byte)}
}

// Unseal installs a KEK version and makes it current if it is the highest
// version seen. The supplied key is copied; the caller may zero its own buffer.
func (v *Vault) Unseal(version int, kek []byte) error {
	if len(kek) != KeyLen {
		return ErrBadKeyLen
	}
	if version < 1 {
		return fmt.Errorf("vault: KEK version must be >= 1, got %d", version)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	cp := make([]byte, KeyLen)
	copy(cp, kek)
	v.keks[version] = cp
	if version > v.current {
		v.current = version
	}
	return nil
}

// Seal drops every KEK, zeroing the key material first. Subsequent operations
// fail with ErrSealed until the vault is unsealed again.
func (v *Vault) Seal() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for ver, k := range v.keks {
		Zero(k)
		delete(v.keks, ver)
	}
	v.current = 0
}

// IsSealed reports whether the vault currently holds no usable KEK.
func (v *Vault) IsSealed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.current == 0
}

// CurrentVersion returns the KEK version new secrets are wrapped under, or 0
// when sealed.
func (v *Vault) CurrentVersion() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.current
}

// Versions returns the KEK versions this vault can decrypt with, unordered.
func (v *Vault) Versions() []int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]int, 0, len(v.keks))
	for ver := range v.keks {
		out = append(out, ver)
	}
	return out
}

// Encrypt seals plaintext under a fresh DEK wrapped by the current KEK.
//
// aad binds the result to its logical owner and must be supplied identically to
// Decrypt. Passing nil is allowed but strongly discouraged for stored secrets.
func (v *Vault) Encrypt(plaintext, aad []byte) (*Sealed, error) {
	v.mu.RLock()
	current := v.current
	kek := v.keks[current]
	v.mu.RUnlock()

	if current == 0 || kek == nil {
		return nil, ErrSealed
	}

	dek := make([]byte, KeyLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("vault: generating DEK: %w", err)
	}
	defer Zero(dek)

	ciphertext, err := aeadSeal(dek, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("vault: encrypting secret: %w", err)
	}

	// The wrapped DEK is bound to the same AAD, so a wrapped DEK cannot be
	// moved between rows either.
	wrapped, err := aeadSeal(kek, dek, aad)
	if err != nil {
		return nil, fmt.Errorf("vault: wrapping DEK: %w", err)
	}

	return &Sealed{KEKVersion: current, WrappedDEK: wrapped, Ciphertext: ciphertext}, nil
}

// Decrypt opens a Sealed value. aad must match what was supplied to Encrypt.
//
// The returned slice is caller-owned; zero it with Zero when finished.
func (v *Vault) Decrypt(s *Sealed, aad []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("vault: nil sealed value")
	}

	v.mu.RLock()
	kek := v.keks[s.KEKVersion]
	sealed := v.current == 0
	v.mu.RUnlock()

	if sealed {
		return nil, ErrSealed
	}
	if kek == nil {
		return nil, fmt.Errorf("%w: %d", ErrUnknownKEK, s.KEKVersion)
	}

	dek, err := aeadOpen(kek, s.WrappedDEK, aad)
	if err != nil {
		return nil, fmt.Errorf("vault: unwrapping DEK: %w", err)
	}
	defer Zero(dek)

	plaintext, err := aeadOpen(dek, s.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypting secret: %w", err)
	}
	return plaintext, nil
}

// Rewrap re-encrypts a Sealed value's DEK under the current KEK, leaving the
// secret ciphertext untouched. This is the whole point of envelope encryption:
// KEK rotation never has to read or rewrite the secrets themselves.
//
// Rewrapping a value already at the current version returns it unchanged, so
// the operation is idempotent and safe to retry across a partially completed
// rotation.
func (v *Vault) Rewrap(s *Sealed, aad []byte) (*Sealed, error) {
	if s == nil {
		return nil, errors.New("vault: nil sealed value")
	}

	v.mu.RLock()
	current := v.current
	newKEK := v.keks[current]
	oldKEK := v.keks[s.KEKVersion]
	v.mu.RUnlock()

	if current == 0 || newKEK == nil {
		return nil, ErrSealed
	}
	if s.KEKVersion == current {
		return s, nil
	}
	if oldKEK == nil {
		return nil, fmt.Errorf("%w: %d", ErrUnknownKEK, s.KEKVersion)
	}

	dek, err := aeadOpen(oldKEK, s.WrappedDEK, aad)
	if err != nil {
		return nil, fmt.Errorf("vault: unwrapping DEK for rewrap: %w", err)
	}
	defer Zero(dek)

	wrapped, err := aeadSeal(newKEK, dek, aad)
	if err != nil {
		return nil, fmt.Errorf("vault: rewrapping DEK: %w", err)
	}

	return &Sealed{KEKVersion: current, WrappedDEK: wrapped, Ciphertext: s.Ciphertext}, nil
}

// aeadSeal encrypts with AES-256-GCM, returning nonce||ciphertext||tag.
func aeadSeal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	// Seal appends to nonce, so the nonce prefixes the result in one allocation.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// aeadOpen reverses aeadSeal.
func aeadOpen(key, blob, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, body := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	out, err := gcm.Open(nil, nonce, body, aad)
	if err != nil {
		// Deliberately opaque: distinguishing "wrong key" from "tampered data"
		// tells an attacker which of the two they achieved.
		return nil, errors.New("authentication failed")
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, ErrBadKeyLen
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Zero overwrites b. Go's garbage collector may already have copied the buffer
// elsewhere, so this reduces rather than eliminates exposure — it is still
// worth doing for long-lived key material.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
