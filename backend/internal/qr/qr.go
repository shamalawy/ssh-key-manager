// Package qr encodes short byte strings as QR codes.
//
// This exists because enrolling a second factor by typing a 32-character
// base32 secret into a phone is the kind of friction that makes people skip
// the second factor. A camera-readable code removes it.
//
// The scope is deliberately narrow: byte mode, versions 1 through 10, which
// covers an otpauth:// URI several times over with room to spare. Anything
// longer than that returns an error rather than silently producing a code that
// will not scan. No numeric, alphanumeric, or kanji modes; no ECI; no
// structured append. A general QR library is a much larger thing than this
// product needs, and every branch not written is a branch that cannot be wrong.
package qr

import (
	"errors"
	"fmt"
)

// Level is the error-correction level.
type Level int

const (
	LevelL Level = iota // ~7% recovery
	LevelM              // ~15% recovery
	LevelQ              // ~25% recovery
	LevelH              // ~30% recovery
)

// formatBits is the two-bit level indicator baked into the format information.
// The order is not L,M,Q,H — the specification assigns M=00, L=01, H=10, Q=11.
var formatBits = map[Level]int{LevelL: 0b01, LevelM: 0b00, LevelQ: 0b11, LevelH: 0b10}

// ErrTooLong means the payload does not fit in a version-10 symbol.
var ErrTooLong = errors.New("qr: payload too long")

// Code is a rendered QR symbol: a square grid where true is a dark module.
type Code struct {
	Size    int
	Modules [][]bool
	Version int
	Level   Level
}

// At reports whether the module at (x, y) is dark. Out-of-range is light, so
// callers rendering a quiet zone do not need bounds checks.
func (c *Code) At(x, y int) bool {
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return false
	}
	return c.Modules[y][x]
}

// blockSpec describes how one version-and-level's codewords are grouped.
//
// QR splits data across blocks of two possible sizes so that a large symbol
// degrades gracefully: damage concentrated in one region only destroys the
// blocks that region carries. Each block gets its own error-correction
// codewords, then the blocks are interleaved.
type blockSpec struct {
	ecPerBlock int
	group1     int // number of blocks
	data1      int // data codewords in each
	group2     int
	data2      int
}

func (b blockSpec) dataCodewords() int { return b.group1*b.data1 + b.group2*b.data2 }

// specs is indexed [version][level]. Versions 1-10 only; index 0 is unused so
// that specs[v] reads as "version v".
var specs = [11][4]blockSpec{
	{}, // version 0 does not exist
	/*  1 */ {{7, 1, 19, 0, 0}, {10, 1, 16, 0, 0}, {13, 1, 13, 0, 0}, {17, 1, 9, 0, 0}},
	/*  2 */ {{10, 1, 34, 0, 0}, {16, 1, 28, 0, 0}, {22, 1, 22, 0, 0}, {28, 1, 16, 0, 0}},
	/*  3 */ {{15, 1, 55, 0, 0}, {26, 1, 44, 0, 0}, {18, 2, 17, 0, 0}, {22, 2, 13, 0, 0}},
	/*  4 */ {{20, 1, 80, 0, 0}, {18, 2, 32, 0, 0}, {26, 2, 24, 0, 0}, {16, 4, 9, 0, 0}},
	/*  5 */ {{26, 1, 108, 0, 0}, {24, 2, 43, 0, 0}, {18, 2, 15, 2, 16}, {22, 2, 11, 2, 12}},
	/*  6 */ {{18, 2, 68, 0, 0}, {16, 4, 27, 0, 0}, {24, 4, 19, 0, 0}, {28, 4, 15, 0, 0}},
	/*  7 */ {{20, 2, 78, 0, 0}, {18, 4, 31, 0, 0}, {18, 2, 14, 4, 15}, {26, 4, 13, 1, 14}},
	/*  8 */ {{24, 2, 97, 0, 0}, {22, 2, 38, 2, 39}, {22, 4, 18, 2, 19}, {26, 4, 14, 2, 15}},
	/*  9 */ {{30, 2, 116, 0, 0}, {22, 3, 36, 2, 37}, {20, 4, 16, 4, 17}, {24, 4, 12, 4, 13}},
	/* 10 */ {{18, 2, 68, 2, 69}, {26, 4, 43, 1, 44}, {24, 6, 19, 2, 20}, {28, 6, 15, 2, 16}},
}

// alignmentCentres[v] lists the row/column coordinates of alignment pattern
// centres. A pattern is placed at every pairing except the three that would
// collide with a finder pattern.
var alignmentCentres = [11][]int{
	nil, nil,
	{6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34},
	{6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50},
}

// Encode renders data as the smallest version-1-to-10 symbol that holds it.
func Encode(data []byte, level Level) (*Code, error) {
	version, err := chooseVersion(len(data), level)
	if err != nil {
		return nil, err
	}

	spec := specs[version][level]
	codewords := encodeData(data, version, spec)
	final := interleave(codewords, spec)

	// Every mask is tried and the least penalised wins. Picking a fixed mask
	// would still produce a valid symbol, but a bad pairing of mask and payload
	// can leave large blank regions that confuse a camera trying to lock on.
	var best *Code
	bestPenalty := -1
	for mask := 0; mask < 8; mask++ {
		c := buildMatrix(version, level, final, mask)
		p := penalty(c)
		if bestPenalty < 0 || p < bestPenalty {
			best, bestPenalty = c, p
		}
	}
	return best, nil
}

func chooseVersion(n int, level Level) (int, error) {
	for v := 1; v <= 10; v++ {
		need := 4 + countBits(v) + 8*n
		if need <= specs[v][level].dataCodewords()*8 {
			return v, nil
		}
	}
	return 0, fmt.Errorf("%w: %d bytes exceeds version 10", ErrTooLong, n)
}

// countBits is the width of the character-count field, which widens at
// version 10 for byte mode.
func countBits(version int) int {
	if version < 10 {
		return 8
	}
	return 16
}

// encodeData produces the data codewords: header, payload, terminator, and
// the alternating pad bytes the specification mandates.
func encodeData(data []byte, version int, spec blockSpec) []byte {
	var bits bitBuffer
	bits.append(0b0100, 4) // byte mode
	bits.append(len(data), countBits(version))
	for _, b := range data {
		bits.append(int(b), 8)
	}

	capacity := spec.dataCodewords() * 8
	// Terminator: up to four zero bits, fewer if the symbol is nearly full.
	if rem := capacity - bits.len(); rem > 0 {
		bits.append(0, min(4, rem))
	}
	for bits.len()%8 != 0 {
		bits.append(0, 1)
	}

	out := bits.bytes()
	for i := 0; len(out) < spec.dataCodewords(); i++ {
		if i%2 == 0 {
			out = append(out, 0xEC)
		} else {
			out = append(out, 0x11)
		}
	}
	return out
}

// interleave splits the data into blocks, computes each block's
// error-correction codewords, and reads them back column-wise.
func interleave(data []byte, spec blockSpec) []byte {
	type block struct{ data, ec []byte }

	blocks := make([]block, 0, spec.group1+spec.group2)
	pos := 0
	add := func(count, size int) {
		for i := 0; i < count; i++ {
			d := data[pos : pos+size]
			pos += size
			blocks = append(blocks, block{data: d, ec: reedSolomon(d, spec.ecPerBlock)})
		}
	}
	add(spec.group1, spec.data1)
	add(spec.group2, spec.data2)

	var out []byte
	maxData := max(spec.data1, spec.data2)
	for i := 0; i < maxData; i++ {
		for _, b := range blocks {
			if i < len(b.data) {
				out = append(out, b.data[i])
			}
		}
	}
	for i := 0; i < spec.ecPerBlock; i++ {
		for _, b := range blocks {
			out = append(out, b.ec[i])
		}
	}
	return out
}

// bitBuffer accumulates a big-endian bit stream.
type bitBuffer struct {
	bits []bool
}

func (b *bitBuffer) append(value, width int) {
	for i := width - 1; i >= 0; i-- {
		b.bits = append(b.bits, value>>uint(i)&1 == 1)
	}
}

func (b *bitBuffer) len() int { return len(b.bits) }

func (b *bitBuffer) bytes() []byte {
	out := make([]byte, len(b.bits)/8)
	for i, bit := range b.bits {
		if bit {
			out[i/8] |= 1 << uint(7-i%8)
		}
	}
	return out
}
