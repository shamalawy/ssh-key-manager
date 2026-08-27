package qr

import (
	"bytes"
	"image/png"
	"strings"
	"testing"
)

// The published standard supplies these answers, so they check the encoder
// against the specification rather than against itself. Everything downstream
// is worthless if these are wrong.

func TestReedSolomonMatchesPublishedVector(t *testing.T) {
	// "HELLO WORLD" at version 1-M: the data codewords and the ten error
	// correction codewords the specification's worked example produces.
	data := []byte{32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17}
	want := []byte{196, 35, 39, 119, 235, 215, 231, 226, 93, 23}

	got := reedSolomon(data, 10)
	if !bytes.Equal(got, want) {
		t.Fatalf("error correction codewords\n got %v\nwant %v", got, want)
	}
}

func TestFormatInfoMatchesPublishedTable(t *testing.T) {
	// The mask-0 row of the standard's format information table.
	for _, tc := range []struct {
		level Level
		want  int
	}{
		{LevelL, 0b111011111000100},
		{LevelM, 0b101010000010010},
		{LevelQ, 0b011010101011111},
		{LevelH, 0b001011010001001},
	} {
		if got := formatInfo(tc.level, 0); got != tc.want {
			t.Errorf("formatInfo(%d, 0) = %015b, want %015b", tc.level, got, tc.want)
		}
	}

	// The remaining 28 entries are checked by their defining property rather
	// than by a transcribed table: strip the 0x5412 mask and what is left must
	// be a multiple of the BCH generator, and its top five bits must be the
	// level and mask that went in. Transcribing 32 constants by hand is how a
	// table like this acquires a typo.
	for level := LevelL; level <= LevelH; level++ {
		for mask := 0; mask < 8; mask++ {
			raw := formatInfo(level, mask) ^ 0x5412
			if bch(raw>>10, 0x537, 10) != raw {
				t.Errorf("level %d mask %d: not a valid BCH codeword", level, mask)
			}
			if got := raw >> 13 & 0b11; got != formatBits[level] {
				t.Errorf("level %d mask %d: level bits %02b, want %02b", level, mask, got, formatBits[level])
			}
			if got := raw >> 10 & 0b111; got != mask {
				t.Errorf("level %d mask %d: mask bits %03b", level, mask, got)
			}
		}
	}
}

func TestVersionInfoMatchesPublishedTable(t *testing.T) {
	want := map[int]int{7: 0x07C94, 8: 0x085BC, 9: 0x09A99, 10: 0x0A4D3}
	for version, expected := range want {
		if got := versionInfo(version); got != expected {
			t.Errorf("versionInfo(%d) = %#05x, want %#05x", version, got, expected)
		}
	}
}

func TestCodewordCountsMatchTheSpecification(t *testing.T) {
	// Total codewords per version, from the standard's capacity table. A typo
	// in the block table would produce a symbol of the right size whose
	// codewords do not fill it, which is invisible until a scanner fails.
	totals := []int{0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346}

	for version := 1; version <= 10; version++ {
		for level := LevelL; level <= LevelH; level++ {
			s := specs[version][level]
			got := s.dataCodewords() + (s.group1+s.group2)*s.ecPerBlock
			if got != totals[version] {
				t.Errorf("version %d level %d: %d codewords, want %d",
					version, level, got, totals[version])
			}
		}
	}
}

// Round trip: encode, then read the symbol back with a reader written from the
// specification's traversal rules. This does not prove the code scans on a
// phone, but it does prove the format field, the mask, the interleaving and the
// zigzag placement all agree with each other and with the standard's layout.

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		level Level
	}{
		{"short", "hello", LevelM},
		{"otpauth", "otpauth://totp/SKM:admin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=SKM&algorithm=SHA1&digits=6&period=30", LevelM},
		{"low ec", strings.Repeat("x", 200), LevelL},
		{"high ec", "break glass", LevelH},
		{"binary", string([]byte{0, 1, 2, 250, 255, 128}), LevelQ},
		{"version boundary", strings.Repeat("a", 154), LevelM},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, err := Encode([]byte(tc.text), tc.level)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if code.Size != code.Version*4+17 {
				t.Fatalf("size %d does not match version %d", code.Size, code.Version)
			}

			got, level, err := decode(code)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got != tc.text {
				t.Fatalf("round trip\n got %q\nwant %q", got, tc.text)
			}
			if level != tc.level {
				t.Fatalf("level %d, want %d", level, tc.level)
			}
		})
	}
}

func TestStructuralInvariants(t *testing.T) {
	code, err := Encode([]byte("structure"), LevelM)
	if err != nil {
		t.Fatal(err)
	}
	size := code.Size

	// Three finder patterns, each a dark ring around a dark 3x3 core.
	for _, corner := range [][2]int{{0, 0}, {size - 7, 0}, {0, size - 7}} {
		ox, oy := corner[0], corner[1]
		if !code.At(ox+3, oy+3) {
			t.Errorf("finder at (%d,%d) has a light core", ox, oy)
		}
		if code.At(ox+1, oy+1) {
			t.Errorf("finder at (%d,%d) has a dark inner ring", ox, oy)
		}
		if !code.At(ox, oy) || !code.At(ox+6, oy+6) {
			t.Errorf("finder at (%d,%d) has a broken outer ring", ox, oy)
		}
	}

	// Timing patterns alternate, starting dark next to the finders.
	for i := 8; i < size-8; i++ {
		if code.At(i, 6) != (i%2 == 0) {
			t.Fatalf("horizontal timing pattern breaks at %d", i)
		}
		if code.At(6, i) != (i%2 == 0) {
			t.Fatalf("vertical timing pattern breaks at %d", i)
		}
	}

	if !code.At(8, size-8) {
		t.Error("the always-dark module is light")
	}
}

func TestRejectsOversizedPayload(t *testing.T) {
	if _, err := Encode(bytes.Repeat([]byte("x"), 400), LevelM); err == nil {
		t.Fatal("expected an error for a payload past version 10")
	}
}

func TestPNGRenders(t *testing.T) {
	uri, err := DataURI("otpauth://totp/SKM:admin?secret=JBSWY3DPEHPK3PXP&issuer=SKM", 6)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "data:image/png;base64,") {
		t.Fatalf("unexpected prefix: %.40s", uri)
	}

	code, err := Encode([]byte("render"), LevelM)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := PNG(code, 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the encoder produced something that is not a PNG: %v", err)
	}

	wantSide := (code.Size + 8) * 4
	if b := img.Bounds(); b.Dx() != wantSide || b.Dy() != wantSide {
		t.Fatalf("image is %dx%d, want %dx%d", b.Dx(), b.Dy(), wantSide, wantSide)
	}
	// The quiet zone must be light all the way round, or a scanner has nothing
	// to separate the symbol from whatever it is printed on.
	for x := 0; x < wantSide; x++ {
		if r, _, _, _ := img.At(x, 2).RGBA(); r == 0 {
			t.Fatalf("dark module in the quiet zone at x=%d", x)
		}
	}
}
