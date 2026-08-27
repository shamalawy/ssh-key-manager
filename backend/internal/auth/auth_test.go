package auth

import (
	"strings"
	"testing"
	"time"
)

func TestHashAndVerifyPassword(t *testing.T) {
	const password = "correct horse battery staple"

	hash, err := HashPassword(password, DefaultParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("hash is not in PHC format: %q", hash)
	}
	if strings.Contains(hash, password) {
		t.Fatal("the hash contains the password verbatim")
	}

	ok, rehash, err := VerifyPassword(password, hash, DefaultParams())
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("the correct password did not verify")
	}
	if rehash {
		t.Error("a hash created with current parameters was flagged for rehash")
	}

	ok, _, err = VerifyPassword("wrong password", hash, DefaultParams())
	if err != nil {
		t.Fatalf("VerifyPassword with a wrong password: %v", err)
	}
	if ok {
		t.Error("an incorrect password verified")
	}
}

// Two hashes of the same password must differ, or the salt is not doing its job.
func TestHashIsSalted(t *testing.T) {
	a, err := HashPassword("same", DefaultParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := HashPassword("same", DefaultParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a == b {
		t.Error("hashing the same password twice produced identical output")
	}
}

func TestHashRejectsEmptyPassword(t *testing.T) {
	if _, err := HashPassword("", DefaultParams()); err == nil {
		t.Error("HashPassword accepted an empty password")
	}
}

// Raising cost parameters must flag old hashes for upgrade rather than break
// them.
func TestNeedsRehashOnParameterIncrease(t *testing.T) {
	weak := Params{Time: 1, Memory: 8 * 1024, Threads: 1}

	hash, err := HashPassword("password", weak)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, rehash, err := VerifyPassword("password", hash, DefaultParams())
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("a password hashed with weaker parameters no longer verifies")
	}
	if !rehash {
		t.Error("a weaker hash was not flagged for rehash")
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	tests := []string{
		"",
		"not-a-hash",
		"$argon2id$",
		"$bcrypt$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=99$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=19$badparams$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=4$!!!notbase64!!!$aGFzaA",
	}

	for _, tc := range tests {
		t.Run(tc, func(t *testing.T) {
			ok, _, err := VerifyPassword("password", tc, DefaultParams())
			if ok {
				t.Error("a malformed hash verified successfully")
			}
			if err == nil {
				t.Error("expected an error for a malformed hash")
			}
		})
	}
}

func TestDummyVerifyDoesNotPanic(t *testing.T) {
	// Guards the timing-equalisation path for unknown usernames: its built-in
	// hash must stay parseable.
	DummyVerify("anything")
}

func TestTOTPRoundTrip(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}

	now := time.Now()
	code, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	if len(code) != totpDigits {
		t.Errorf("code %q has %d digits, want %d", code, len(code), totpDigits)
	}
	if !VerifyTOTP(secret, code, now) {
		t.Error("a freshly generated code did not verify")
	}
}

// Clock drift of one step either way must be tolerated; beyond that, rejected.
func TestTOTPSkewWindow(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Now()

	tests := []struct {
		name   string
		offset time.Duration
		want   bool
	}{
		{"current step", 0, true},
		{"one step early", -totpPeriod, true},
		{"one step late", totpPeriod, true},
		{"two steps early", -2 * totpPeriod, false},
		{"two steps late", 2 * totpPeriod, false},
		{"an hour off", time.Hour, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, err := TOTPCode(secret, now.Add(tc.offset))
			if err != nil {
				t.Fatalf("TOTPCode: %v", err)
			}
			if got := VerifyTOTP(secret, code, now); got != tc.want {
				t.Errorf("VerifyTOTP for a code %v away = %v, want %v", tc.offset, got, tc.want)
			}
		})
	}
}

func TestTOTPRejectsBadInput(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Now()

	tests := []struct {
		name   string
		secret string
		code   string
	}{
		{"empty code", secret, ""},
		{"too short", secret, "12345"},
		{"too long", secret, "1234567"},
		{"non-numeric", secret, "abcdef"},
		{"wrong code", secret, "000000"},
		{"invalid secret", "!!!not-base32!!!", "123456"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// "000000" is a legitimate code roughly one time in a million;
			// tolerate that rather than making the test flaky.
			if VerifyTOTP(tc.secret, tc.code, now) && tc.code != "000000" {
				t.Errorf("VerifyTOTP accepted %q", tc.code)
			}
		})
	}
}

// Verified against the RFC 6238 test vectors so the implementation is provably
// interoperable with standard authenticator apps.
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	// The RFC's SHA1 key is the ASCII "12345678901234567890".
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	tests := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}

	for _, tc := range tests {
		got, err := TOTPCode(secret, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatalf("TOTPCode at %d: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("TOTPCode at %d = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestTOTPSecretsAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		s, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("GenerateTOTPSecret: %v", err)
		}
		if seen[s] {
			t.Fatal("GenerateTOTPSecret returned a duplicate")
		}
		seen[s] = true
	}
}

func TestTOTPURI(t *testing.T) {
	uri := TOTPURI("SKM", "alice@example.com", "ABCDEF")

	for _, want := range []string{
		"otpauth://totp/",
		"secret=ABCDEF",
		"issuer=SKM",
		"digits=6",
		"period=30",
		"algorithm=SHA1",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI missing %q: %s", want, uri)
		}
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("got %d codes, want 10", len(codes))
	}

	seen := make(map[string]bool)
	for _, c := range codes {
		if seen[c] {
			t.Errorf("duplicate recovery code %q", c)
		}
		seen[c] = true

		if !strings.Contains(c, "-") {
			t.Errorf("code %q is not grouped for readability", c)
		}
		// Look-alike characters are excluded so codes can be read aloud or
		// copied from paper without ambiguity.
		for _, bad := range []string{"0", "1", "l", "i", "o"} {
			if strings.Contains(c, bad) {
				t.Errorf("code %q contains the ambiguous character %q", c, bad)
			}
		}
	}
}
