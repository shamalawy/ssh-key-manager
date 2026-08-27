package qr

import (
	"errors"
	"fmt"
)

// A reader for the test suite only.
//
// It is written from the specification's layout rules rather than by reusing
// the encoder's placement code, so that a mistake in the encoder shows up as a
// failed round trip instead of being mirrored. Error correction is ignored —
// nothing here is damaged — so it reads the data codewords and stops.

func decode(c *Code) (string, Level, error) {
	version := (c.Size - 17) / 4
	if version < 1 || version > 10 {
		return "", 0, fmt.Errorf("unsupported size %d", c.Size)
	}

	level, mask, err := readFormat(c)
	if err != nil {
		return "", 0, err
	}

	reserved := functionModules(version)
	bits := readData(c, reserved, mask)
	codewords := deinterleave(bits, specs[version][level])

	text, err := parsePayload(codewords, version)
	return text, level, err
}

func readFormat(c *Code) (Level, int, error) {
	raw := 0
	for i := 0; i < 15; i++ {
		x, y := formatPos1(i)
		if c.At(x, y) {
			raw |= 1 << uint(i)
		}
	}
	raw ^= 0x5412

	if bch(raw>>10, 0x537, 10) != raw {
		return 0, 0, errors.New("format information failed its BCH check")
	}

	levelBits, mask := raw>>13&0b11, raw>>10&0b111
	for level, bits := range formatBits {
		if bits == levelBits {
			return level, mask, nil
		}
	}
	return 0, 0, fmt.Errorf("unknown level bits %02b", levelBits)
}

// functionModules marks every module the data stream must skip: finders and
// their separators, timing patterns, alignment patterns, the format and
// version fields, and the always-dark module.
func functionModules(version int) [][]bool {
	size := version*4 + 17
	m := make([][]bool, size)
	for i := range m {
		m[i] = make([]bool, size)
	}
	mark := func(x, y int) {
		if x >= 0 && y >= 0 && x < size && y < size {
			m[y][x] = true
		}
	}

	// Finder patterns with separators: an 8x8 block in three corners.
	for dy := 0; dy < 8; dy++ {
		for dx := 0; dx < 8; dx++ {
			mark(dx, dy)
			mark(size-1-dx, dy)
			mark(dx, size-1-dy)
		}
	}

	for i := 0; i < size; i++ {
		mark(i, 6)
		mark(6, i)
	}

	centres := alignmentCentres[version]
	for _, cy := range centres {
		for _, cx := range centres {
			if (cx == 6 && cy == 6) || (cx == 6 && cy == size-7) || (cx == size-7 && cy == 6) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					mark(cx+dx, cy+dy)
				}
			}
		}
	}

	for i := 0; i < 15; i++ {
		x1, y1 := formatPos1(i)
		mark(x1, y1)
		x2, y2 := formatPos2(i, size)
		mark(x2, y2)
	}
	mark(8, size-8)

	if version >= 7 {
		for i := 0; i < 18; i++ {
			a, b := size-11+i%3, i/3
			mark(a, b)
			mark(b, a)
		}
	}
	return m
}

func readData(c *Code, reserved [][]bool, mask int) []byte {
	size := c.Size
	var out []byte
	acc, n := byte(0), 0

	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		upward := (right+1)&2 == 0
		for vert := 0; vert < size; vert++ {
			for dx := 0; dx < 2; dx++ {
				x := right - dx
				y := vert
				if upward {
					y = size - 1 - vert
				}
				if reserved[y][x] {
					continue
				}
				bit := c.Modules[y][x]
				if maskAt(mask, x, y) {
					bit = !bit
				}
				acc <<= 1
				if bit {
					acc |= 1
				}
				if n++; n == 8 {
					out = append(out, acc)
					acc, n = 0, 0
				}
			}
		}
	}
	return out
}

// deinterleave undoes the column-wise read that interleave performed, keeping
// only the data half.
func deinterleave(stream []byte, spec blockSpec) []byte {
	sizes := make([]int, 0, spec.group1+spec.group2)
	for i := 0; i < spec.group1; i++ {
		sizes = append(sizes, spec.data1)
	}
	for i := 0; i < spec.group2; i++ {
		sizes = append(sizes, spec.data2)
	}

	blocks := make([][]byte, len(sizes))
	pos := 0
	maxData := max(spec.data1, spec.data2)
	for i := 0; i < maxData; i++ {
		for b, size := range sizes {
			if i < size {
				blocks[b] = append(blocks[b], stream[pos])
				pos++
			}
		}
	}

	var out []byte
	for _, b := range blocks {
		out = append(out, b...)
	}
	return out
}

func parsePayload(codewords []byte, version int) (string, error) {
	var bits []bool
	for _, b := range codewords {
		for i := 7; i >= 0; i-- {
			bits = append(bits, b>>uint(i)&1 == 1)
		}
	}
	read := func(pos, width int) int {
		v := 0
		for i := 0; i < width; i++ {
			v <<= 1
			if bits[pos+i] {
				v |= 1
			}
		}
		return v
	}

	if mode := read(0, 4); mode != 0b0100 {
		return "", fmt.Errorf("mode %04b is not byte mode", mode)
	}
	cb := countBits(version)
	length := read(4, cb)

	if 4+cb+8*length > len(bits) {
		return "", fmt.Errorf("declared length %d overruns the symbol", length)
	}
	out := make([]byte, length)
	for i := range out {
		out[i] = byte(read(4+cb+8*i, 8))
	}
	return string(out), nil
}
