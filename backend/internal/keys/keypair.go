package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyPair is a freshly generated or imported keypair.
//
// PrivatePEM is sensitive: it must go straight into the vault and must never be
// logged, returned from a list endpoint, or written to disk unencrypted.
type KeyPair struct {
	Algorithm     Algorithm
	PrivatePEM    []byte // OpenSSH format ("BEGIN OPENSSH PRIVATE KEY")
	PublicLine    string // authorized_keys format, no options, no trailing newline
	Fingerprint   string // "SHA256:..."
	Comment       string
	EncryptedPriv bool // true when PrivatePEM is passphrase-protected
}

// Generate creates a new keypair of the given algorithm.
//
// The comment is embedded in both the private key and the public line; it is
// cosmetic but it is what an operator sees at the end of an authorized_keys
// entry, so it is worth setting to something identifying.
func Generate(alg Algorithm, comment string) (*KeyPair, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("keys: cannot generate algorithm %q (supported: %s)", alg, strings.Join(SupportedAlgorithms(), ", "))
	}

	var priv crypto.PrivateKey
	var err error

	switch alg {
	case Ed25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case ECDSAP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case ECDSAP521:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case RSA3072:
		priv, err = rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("keys: unhandled algorithm %q", alg)
	}
	if err != nil {
		return nil, fmt.Errorf("keys: generating %s: %w", alg, err)
	}

	return fromPrivate(priv, alg, comment)
}

// fromPrivate builds a KeyPair from an in-memory private key.
func fromPrivate(priv crypto.PrivateKey, alg Algorithm, comment string) (*KeyPair, error) {
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("keys: marshalling private key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("keys: deriving public key: %w", err)
	}
	pub := signer.PublicKey()

	return &KeyPair{
		Algorithm:   alg,
		PrivatePEM:  pem.EncodeToMemory(block),
		PublicLine:  publicLine(pub, comment),
		Fingerprint: ssh.FingerprintSHA256(pub),
		Comment:     comment,
	}, nil
}

// publicLine renders a public key as a single authorized_keys line.
func publicLine(pub ssh.PublicKey, comment string) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment = strings.TrimSpace(comment); comment != "" {
		line += " " + comment
	}
	return line
}

// ImportPrivateKey parses an existing private key in any format x/crypto/ssh
// understands (OpenSSH, PKCS#1, PKCS#8, SEC1), optionally passphrase-protected.
//
// The result is normalised to unencrypted OpenSSH format for storage: the vault
// provides encryption at rest, so keeping a second passphrase layer would mean
// SKM could not actually use the key for automated rotation.
func ImportPrivateKey(pemBytes []byte, passphrase string) (*KeyPair, error) {
	var raw any
	var err error

	if passphrase != "" {
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	} else {
		raw, err = ssh.ParseRawPrivateKey(pemBytes)
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, fmt.Errorf("keys: private key is passphrase-protected; supply the passphrase to import it")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("keys: parsing private key: %w", err)
	}

	// ParseRawPrivateKey hands back pointers for some types and values for
	// others; normalise so ssh.NewSignerFromKey always gets something it can use.
	if ed, ok := raw.(ed25519.PrivateKey); ok {
		raw = &ed
	}

	alg, err := algorithmOf(raw)
	if err != nil {
		return nil, err
	}

	comment := commentFromPEM(pemBytes)
	return fromPrivate(raw, alg, comment)
}

// algorithmOf classifies an imported private key, rejecting nothing — an
// undersized RSA key still gets an Algorithm so it can be imported and then
// reported as non-compliant.
func algorithmOf(priv any) (Algorithm, error) {
	switch k := priv.(type) {
	case *ed25519.PrivateKey, ed25519.PrivateKey:
		return Ed25519, nil
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return ECDSAP256, nil
		case 384:
			return ECDSAP384, nil
		case 521:
			return ECDSAP521, nil
		default:
			return "", fmt.Errorf("keys: unsupported ECDSA curve %s", k.Curve.Params().Name)
		}
	case *rsa.PrivateKey:
		// Preserve the real size so compliance reporting is honest, snapping
		// only to the labels we know.
		switch bits := k.N.BitLen(); {
		case bits >= 4096:
			return RSA4096, nil
		default:
			return Algorithm(fmt.Sprintf("rsa-%d", bits)), nil
		}
	default:
		return "", fmt.Errorf("keys: unsupported private key type %T", priv)
	}
}

// commentFromPEM recovers the comment OpenSSH stores alongside a private key.
// A missing comment is not an error; it is simply blank.
func commentFromPEM(pemBytes []byte) string {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return ""
	}
	if c, ok := block.Headers["Comment"]; ok {
		return strings.Trim(strings.TrimSpace(c), `"`)
	}
	return ""
}

// Signer turns stored private key material back into something that can
// authenticate an SSH connection. This is the only path by which a private key
// leaves the vault during normal operation.
func Signer(privatePEM []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(privatePEM)
	if err != nil {
		return nil, fmt.Errorf("keys: loading signer: %w", err)
	}
	return signer, nil
}

// PublicLineFromPrivate derives the authorized_keys line for stored private key
// material, used to verify that a stored public key still matches its private
// half.
func PublicLineFromPrivate(privatePEM []byte, comment string) (string, error) {
	signer, err := Signer(privatePEM)
	if err != nil {
		return "", err
	}
	return publicLine(signer.PublicKey(), comment), nil
}
