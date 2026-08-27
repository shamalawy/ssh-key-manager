package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP implements RFC 6238 time-based one-time passwords, compatible with
// Google Authenticator, Authy, 1Password, and every other standard app.
//
// Implemented directly rather than pulled in as a dependency: it is thirty
// lines of well-specified HMAC, and this way the second factor guarding private
// key reveal has no third-party code in its path.

const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// totpSkew allows one step either side, tolerating clock drift between the
	// server and the user's phone without meaningfully widening the window.
	totpSkew = 1
)

// GenerateTOTPSecret returns a new base32-encoded shared secret.
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, 20) // 160 bits, the RFC 4226 recommendation
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generating TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// TOTPURI builds the otpauth:// URI that enrolment QR codes encode.
func TOTPURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(int(totpPeriod.Seconds())))

	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// TOTPCode computes the code for a given secret and instant.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("auth: decoding TOTP secret: %w", err)
	}

	counter := uint64(t.Unix()) / uint64(totpPeriod.Seconds())
	return hotp(key, counter), nil
}

// VerifyTOTP checks a submitted code, accepting one step either side of now.
//
// The comparison is constant-time so a submitted code cannot be recovered
// digit by digit through timing.
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return false
	}

	counter := uint64(now.Unix()) / uint64(totpPeriod.Seconds())
	for delta := -totpSkew; delta <= totpSkew; delta++ {
		candidate := hotp(key, uint64(int64(counter)+int64(delta)))
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// hotp is the RFC 4226 counter-based algorithm TOTP is built on.
func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation: the low nibble of the last byte selects the offset.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod)
}

// GenerateRecoveryCodes returns n single-use codes for when the second-factor
// device is lost. They are shown once and stored hashed.
func GenerateRecoveryCodes(n int) ([]string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no look-alike characters

	codes := make([]string, n)
	for i := range codes {
		buf := make([]byte, 10)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("auth: generating recovery code: %w", err)
		}
		var b strings.Builder
		for j, v := range buf {
			if j == 5 {
				b.WriteByte('-')
			}
			b.WriteByte(alphabet[int(v)%len(alphabet)])
		}
		codes[i] = b.String()
	}
	return codes, nil
}
