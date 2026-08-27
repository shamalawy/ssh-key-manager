// Package auth handles user credentials, second factors, and sessions.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2 parameters. These are the interactive-use defaults from RFC 9106,
// tuned so a login costs roughly 50ms on modern server hardware. They are
// encoded into every hash, so raising them later does not invalidate existing
// passwords — old hashes keep verifying with their original parameters and are
// upgraded on next login.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	saltLen             = 16
)

// ErrInvalidHash means a stored hash is not in the expected format.
var ErrInvalidHash = errors.New("auth: password hash is malformed")

// Params are the cost parameters used for a single hash.
type Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// DefaultParams returns the current cost settings.
func DefaultParams() Params {
	return Params{Time: argonTime, Memory: argonMemory, Threads: argonThreads}
}

// HashPassword derives an Argon2id hash in the standard PHC string format:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
//
// Storing the parameters alongside the digest is what makes cost upgrades
// possible without a flag day.
func HashPassword(password string, p Params) (string, error) {
	if password == "" {
		return "", errors.New("auth: password is empty")
	}
	if p.Time == 0 || p.Memory == 0 || p.Threads == 0 {
		p = DefaultParams()
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generating salt: %w", err)
	}

	digest := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

// VerifyPassword reports whether password matches encoded, and whether the hash
// was produced with weaker parameters than current policy and should be
// upgraded.
//
// The comparison is constant-time. The needsRehash return is what lets an
// install raise its Argon2 cost over time without ever asking users to reset.
func VerifyPassword(password, encoded string, current Params) (ok bool, needsRehash bool, err error) {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}

	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}

	if current.Time == 0 {
		current = DefaultParams()
	}
	weaker := p.Time < current.Time || p.Memory < current.Memory || p.Threads < current.Threads
	return true, weaker, nil
}

func decodeHash(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return Params{}, nil, nil, fmt.Errorf("auth: unsupported argon2 version %d", version)
	}

	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	digest, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}

	return p, salt, digest, nil
}

// DummyVerify performs a hash computation against a throwaway value.
//
// It is called when a login names a user that does not exist, so that the
// response takes the same time as a real failed login. Without it, response
// timing reveals which usernames are valid.
func DummyVerify(password string) {
	_, _, _ = VerifyPassword(password,
		"$argon2id$v=19$m=65536,t=3,p=4$YWJjZGVmZ2hpamtsbW5vcA$"+
			"cnfCJ0dOZlYyH1qXQF2gJqYnFbBqbf4pBiUEZBEIRuU",
		DefaultParams())
}
