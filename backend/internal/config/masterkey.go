package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// MasterKeyLen is the required length of the raw key-encryption key.
const MasterKeyLen = 32

// decodeMasterKey accepts the master key as hex, standard base64, or raw bytes
// and returns exactly MasterKeyLen bytes.
//
// It deliberately refuses anything shorter rather than stretching it: a short
// master key is an operator mistake, and silently padding it would hide the
// fact that the vault is weaker than it looks.
func decodeMasterKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)

	if b, err := hex.DecodeString(s); err == nil && len(b) == MasterKeyLen {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == MasterKeyLen {
			return b, nil
		}
	}
	if len(s) == MasterKeyLen {
		return []byte(s), nil
	}

	return nil, fmt.Errorf(
		"config: SKM_MASTER_KEY must decode to %d bytes (got %d chars; supply %d-byte hex, base64, or raw). "+
			"Generate one with: openssl rand -hex %d",
		MasterKeyLen, len(s), MasterKeyLen, MasterKeyLen)
}
