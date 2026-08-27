// Package keys generates, parses, and formats SSH keys and authorized_keys
// entries.
//
// It is deliberately strict about algorithms: SKM will not generate anything it
// would flag as non-compliant, and it refuses outright to produce DSA or
// undersized RSA keys. Existing weak keys can still be imported and inspected —
// you cannot fix what you cannot see — but they are reported as non-compliant so
// they show up in the dashboard and can be rotated onto something modern.
package keys

import (
	"fmt"
	"sort"
	"strings"
)

// Algorithm identifies a keypair type SKM can generate.
type Algorithm string

const (
	Ed25519   Algorithm = "ed25519"
	ECDSAP256 Algorithm = "ecdsa-p256"
	ECDSAP384 Algorithm = "ecdsa-p384"
	ECDSAP521 Algorithm = "ecdsa-p521"
	RSA3072   Algorithm = "rsa-3072"
	RSA4096   Algorithm = "rsa-4096"
)

// DefaultAlgorithm is what SKM generates when the caller expresses no
// preference. Ed25519 is small, fast, has no parameter choices to get wrong, and
// is supported by every OpenSSH release since 6.5 (2014).
const DefaultAlgorithm = Ed25519

// MinRSABits is the smallest RSA modulus considered compliant.
const MinRSABits = 3072

type algorithmInfo struct {
	bits      int    // RSA modulus size, or curve size for ECDSA
	curve     string // ECDSA curve name, empty otherwise
	sshType   string // the wire type prefix in authorized_keys
	generable bool
}

var algorithms = map[Algorithm]algorithmInfo{
	Ed25519:   {bits: 256, sshType: "ssh-ed25519", generable: true},
	ECDSAP256: {bits: 256, curve: "P-256", sshType: "ecdsa-sha2-nistp256", generable: true},
	ECDSAP384: {bits: 384, curve: "P-384", sshType: "ecdsa-sha2-nistp384", generable: true},
	ECDSAP521: {bits: 521, curve: "P-521", sshType: "ecdsa-sha2-nistp521", generable: true},
	RSA3072:   {bits: 3072, sshType: "ssh-rsa", generable: true},
	RSA4096:   {bits: 4096, sshType: "ssh-rsa", generable: true},
}

// Valid reports whether a is an algorithm SKM knows how to generate.
func (a Algorithm) Valid() bool {
	info, ok := algorithms[a]
	return ok && info.generable
}

// Bits returns the key size in bits.
func (a Algorithm) Bits() int { return algorithms[a].bits }

// SSHType returns the authorized_keys wire type for a.
func (a Algorithm) SSHType() string { return algorithms[a].sshType }

func (a Algorithm) String() string { return string(a) }

// ParseAlgorithm resolves a user-supplied algorithm name, accepting a few
// common spellings so the API and CLI are forgiving about input that clearly
// means one thing.
func ParseAlgorithm(s string) (Algorithm, error) {
	norm := strings.ToLower(strings.TrimSpace(s))
	norm = strings.ReplaceAll(norm, "_", "-")

	switch norm {
	case "", "default":
		return DefaultAlgorithm, nil
	case "ed25519", "ssh-ed25519":
		return Ed25519, nil
	case "ecdsa", "ecdsa-p256", "ecdsa-256", "nistp256", "ecdsa-sha2-nistp256":
		return ECDSAP256, nil
	case "ecdsa-p384", "ecdsa-384", "nistp384", "ecdsa-sha2-nistp384":
		return ECDSAP384, nil
	case "ecdsa-p521", "ecdsa-521", "nistp521", "ecdsa-sha2-nistp521":
		return ECDSAP521, nil
	case "rsa", "rsa-3072", "rsa3072":
		return RSA3072, nil
	case "rsa-4096", "rsa4096":
		return RSA4096, nil
	case "rsa-1024", "rsa-2048", "dsa", "ssh-dss":
		return "", fmt.Errorf("keys: %q is below SKM's security floor and will not be generated (use ed25519, or rsa-3072 and above)", s)
	}
	return "", fmt.Errorf("keys: unknown algorithm %q (supported: %s)", s, strings.Join(SupportedAlgorithms(), ", "))
}

// SupportedAlgorithms lists every generable algorithm, sorted for stable output
// in help text and API responses.
func SupportedAlgorithms() []string {
	out := make([]string, 0, len(algorithms))
	for a, info := range algorithms {
		if info.generable {
			out = append(out, string(a))
		}
	}
	sort.Strings(out)
	return out
}
