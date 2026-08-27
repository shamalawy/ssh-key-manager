// Package backup produces and restores encrypted exports of the vault.
//
// The archive is deliberately independent of the running instance's master
// key. An export decrypts each private key with the live vault and re-encrypts
// the whole payload under a *separate* backup passphrase, so the archive can be
// restored into a fresh install whose master key is different — which is the
// only kind of restore that helps in a disaster.
//
// That also means the archive is exactly as valuable as the vault itself. The
// passphrase is never stored, never logged, and never derivable from anything
// SKM holds.
package backup

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
)

// Magic identifies an SKM archive, so a wrong file is rejected with a clear
// message rather than a decryption failure.
var Magic = [8]byte{'S', 'K', 'M', 'B', 'A', 'K', 0x01, 0x00}

// FormatVersion is bumped when the on-disk layout changes.
const FormatVersion = 1

var (
	// ErrNotAnArchive means the file is not an SKM backup.
	ErrNotAnArchive = errors.New("backup: not an SKM archive")
	// ErrWrongPassphrase means authentication failed during decryption.
	// It is deliberately indistinguishable from a corrupted archive: AES-GCM
	// cannot tell them apart, and pretending otherwise would be a guess.
	ErrWrongPassphrase = errors.New("backup: the passphrase is wrong, or the archive is corrupt")
	// ErrUnsupportedVersion means the archive was written by a newer SKM.
	ErrUnsupportedVersion = errors.New("backup: unsupported archive version")
)

// KDFParams records how the archive key was derived, so a future SKM can raise
// the cost without being unable to read old archives.
type KDFParams struct {
	Algorithm string `json:"algorithm"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Salt      []byte `json:"salt"`
}

// DefaultKDF returns the current derivation cost.
//
// It is deliberately heavier than the login parameters: a backup passphrase is
// typed once in an emergency, not on every sign-in, and the archive may be
// attacked offline for as long as an attacker likes.
func DefaultKDF() KDFParams {
	return KDFParams{
		Algorithm: "argon2id",
		Time:      4,
		MemoryKiB: 256 * 1024,
		Threads:   4,
	}
}

// newKDF returns the parameters a fresh archive is written with. It is a
// variable so the test suite can drop the cost: these tests exercise the
// format, and a second of Argon2 per case is a second nobody spends.
var newKDF = DefaultKDF

// Header is the plaintext preamble. It carries only what is needed to decrypt
// and to identify the archive; nothing in it is secret.
type Header struct {
	Version   int       `json:"version"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
	Instance  string    `json:"instance,omitempty"`
	KeyCount  int       `json:"key_count"`
	KDF       KDFParams `json:"kdf"`
	Nonce     []byte    `json:"nonce"`
	// PayloadSHA256 covers the *plaintext* payload, so a successful restore can
	// be checked against it independently of the AEAD tag.
	PayloadSHA256 string `json:"payload_sha256"`
}

// Payload is the archive contents.
type Payload struct {
	Keys        []KeyRecord        `json:"keys"`
	Targets     []TargetRecord     `json:"targets,omitempty"`
	Assignments []AssignmentRecord `json:"assignments,omitempty"`
	Consumers   []ConsumerRecord   `json:"consumers,omitempty"`
	Policies    []PolicyRecord     `json:"policies,omitempty"`
	ExportedAt  time.Time          `json:"exported_at"`
}

// KeyRecord is one key, with its private half in plaintext *inside the
// encrypted payload*. It is never written unencrypted to disk.
type KeyRecord struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Algorithm   string   `json:"algorithm"`
	PublicKey   string   `json:"public_key"`
	Fingerprint string   `json:"fingerprint"`
	Comment     string   `json:"comment"`
	Status      string   `json:"status"`
	KeyClass    string   `json:"key_class"`
	Generation  int      `json:"generation"`
	ParentKeyID string   `json:"parent_key_id,omitempty"`
	Tags        []string `json:"tags"`
	PrivatePEM  string   `json:"private_pem,omitempty"`
	CreatedAt   string   `json:"created_at"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
}

// TargetRecord is a target's configuration. Credentials are deliberately
// excluded: a backup that also carries the passwords to every host in the
// estate turns one lost archive into total compromise.
type TargetRecord struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	Connector  string         `json:"connector"`
	Address    string         `json:"address"`
	Port       int            `json:"port"`
	Config     map[string]any `json:"config,omitempty"`
	HostKeyPin string         `json:"host_key_pin,omitempty"`
	Tags       []string       `json:"tags"`
	Principals []string       `json:"principals,omitempty"`
}

// AssignmentRecord binds a key to a principal by fingerprint and name, rather
// than by identifier, so a restore into a fresh instance can re-link them.
type AssignmentRecord struct {
	KeyFingerprint string   `json:"key_fingerprint"`
	TargetName     string   `json:"target_name"`
	Username       string   `json:"username"`
	Options        []string `json:"options,omitempty"`
	DesiredState   string   `json:"desired_state"`
}

// ConsumerRecord is a private-key sink's configuration.
type ConsumerRecord struct {
	Name           string         `json:"name"`
	Kind           string         `json:"kind"`
	KeyFingerprint string         `json:"key_fingerprint"`
	Config         map[string]any `json:"config,omitempty"`
	Enabled        bool           `json:"enabled"`
}

// PolicyRecord is a rotation schedule.
type PolicyRecord struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	CronExpr         string   `json:"cron_expr"`
	MaxAgeSeconds    int64    `json:"max_age_seconds"`
	Algorithm        string   `json:"algorithm"`
	SoakSeconds      int64    `json:"soak_seconds"`
	CanaryPercent    int      `json:"canary_percent"`
	FailureThreshold int      `json:"failure_threshold"`
	ApprovalRequired bool     `json:"approval_required"`
	KeyTags          []string `json:"key_tags,omitempty"`
	TargetTags       []string `json:"target_tags,omitempty"`
	KeyClass         string   `json:"key_class,omitempty"`
}

// Write encrypts a payload under a passphrase and writes the archive.
//
// Layout: magic, a four-byte big-endian header length, the JSON header, then
// the AES-256-GCM ciphertext of the gzipped payload. The header is
// authenticated as additional data, so an attacker cannot swap the KDF
// parameters for cheaper ones and re-attack the file.
func Write(w io.Writer, passphrase string, kind string, instance string, payload *Payload) (checksum string, written int64, err error) {
	if passphrase == "" {
		return "", 0, errors.New("backup: a passphrase is required; an unencrypted export of every private key is not an option SKM offers")
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", 0, fmt.Errorf("backup: encoding the payload: %w", err)
	}

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(plaintext); err != nil {
		return "", 0, fmt.Errorf("backup: compressing the payload: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", 0, fmt.Errorf("backup: finishing compression: %w", err)
	}

	sum := sha256.Sum256(plaintext)

	kdf := newKDF()
	kdf.Salt = make([]byte, 16)
	if _, err := rand.Read(kdf.Salt); err != nil {
		return "", 0, fmt.Errorf("backup: generating a salt: %w", err)
	}

	header := Header{
		Version:       FormatVersion,
		Kind:          kind,
		CreatedAt:     time.Now().UTC(),
		Instance:      instance,
		KeyCount:      len(payload.Keys),
		KDF:           kdf,
		PayloadSHA256: hex.EncodeToString(sum[:]),
	}

	gcm, err := aeadFor(passphrase, kdf)
	if err != nil {
		return "", 0, err
	}

	header.Nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(header.Nonce); err != nil {
		return "", 0, fmt.Errorf("backup: generating a nonce: %w", err)
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", 0, fmt.Errorf("backup: encoding the header: %w", err)
	}

	ciphertext := gcm.Seal(nil, header.Nonce, compressed.Bytes(), headerJSON)

	var n int64
	write := func(b []byte) error {
		c, err := w.Write(b)
		n += int64(c)
		return err
	}

	if err := write(Magic[:]); err != nil {
		return "", n, fmt.Errorf("backup: writing the archive: %w", err)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(headerJSON)))
	if err := write(length[:]); err != nil {
		return "", n, fmt.Errorf("backup: writing the archive: %w", err)
	}
	if err := write(headerJSON); err != nil {
		return "", n, fmt.Errorf("backup: writing the archive: %w", err)
	}
	if err := write(ciphertext); err != nil {
		return "", n, fmt.Errorf("backup: writing the archive: %w", err)
	}

	return header.PayloadSHA256, n, nil
}

// ReadHeader parses the plaintext preamble without needing the passphrase.
//
// This is what makes "list my backups" and "is this file an SKM archive?"
// answerable without handing over the passphrase to a listing operation.
func ReadHeader(r io.Reader) (*Header, []byte, error) {
	var magic [8]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, nil, ErrNotAnArchive
	}
	if magic != Magic {
		return nil, nil, ErrNotAnArchive
	}

	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, nil, ErrNotAnArchive
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > 1<<20 {
		return nil, nil, fmt.Errorf("%w: the header length is implausible (%d bytes)", ErrNotAnArchive, size)
	}

	headerJSON := make([]byte, size)
	if _, err := io.ReadFull(r, headerJSON); err != nil {
		return nil, nil, fmt.Errorf("backup: reading the header: %w", err)
	}

	var h Header
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return nil, nil, fmt.Errorf("backup: decoding the header: %w", err)
	}
	if h.Version > FormatVersion {
		return nil, nil, fmt.Errorf("%w: the archive is version %d, this build reads up to %d",
			ErrUnsupportedVersion, h.Version, FormatVersion)
	}

	return &h, headerJSON, nil
}

// Read decrypts an archive.
func Read(r io.Reader, passphrase string) (*Header, *Payload, error) {
	header, headerJSON, err := ReadHeader(r)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("backup: reading the archive body: %w", err)
	}

	gcm, err := aeadFor(passphrase, header.KDF)
	if err != nil {
		return nil, nil, err
	}

	compressed, err := gcm.Open(nil, header.Nonce, ciphertext, headerJSON)
	if err != nil {
		return nil, nil, ErrWrongPassphrase
	}

	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, nil, fmt.Errorf("backup: decompressing the payload: %w", err)
	}
	defer func() { _ = gz.Close() }()

	plaintext, err := io.ReadAll(gz)
	if err != nil {
		return nil, nil, fmt.Errorf("backup: reading the payload: %w", err)
	}

	// Check the plaintext digest as well as the AEAD tag. The tag proves the
	// ciphertext was not altered; this proves the decompressed result is what
	// was exported, which is the claim a restore actually depends on.
	sum := sha256.Sum256(plaintext)
	if got := hex.EncodeToString(sum[:]); got != header.PayloadSHA256 {
		return nil, nil, fmt.Errorf("backup: the payload digest does not match the header (%s vs %s)",
			got, header.PayloadSHA256)
	}

	var payload Payload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, nil, fmt.Errorf("backup: decoding the payload: %w", err)
	}

	return header, &payload, nil
}

// aeadFor derives the archive key and returns its AEAD.
func aeadFor(passphrase string, kdf KDFParams) (cipher.AEAD, error) {
	if kdf.Algorithm != "" && kdf.Algorithm != "argon2id" {
		return nil, fmt.Errorf("backup: unsupported key derivation %q", kdf.Algorithm)
	}
	if len(kdf.Salt) < 8 {
		return nil, errors.New("backup: the archive's salt is missing or too short")
	}

	key := argon2.IDKey([]byte(passphrase), kdf.Salt, kdf.Time, kdf.MemoryKiB, kdf.Threads, 32)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backup: creating the cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backup: creating the AEAD: %w", err)
	}
	return gcm, nil
}
