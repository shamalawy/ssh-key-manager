package qr

// Symbol layout: function patterns, data placement, masking, and the penalty
// score that decides which mask is used.

// buildMatrix lays out one complete symbol under the given mask.
func buildMatrix(version int, level Level, codewords []byte, mask int) *Code {
	size := version*4 + 17
	c := &Code{Size: size, Version: version, Level: level}
	c.Modules = make([][]bool, size)
	reserved := make([][]bool, size)
	for i := range c.Modules {
		c.Modules[i] = make([]bool, size)
		reserved[i] = make([]bool, size)
	}

	set := func(x, y int, dark bool) {
		c.Modules[y][x] = dark
		reserved[y][x] = true
	}

	// Three finder patterns with their separators.
	for _, p := range [][2]int{{0, 0}, {size - 7, 0}, {0, size - 7}} {
		drawFinder(set, p[0], p[1], size)
	}

	// Timing patterns run between the finders on row 6 and column 6.
	for i := 8; i < size-8; i++ {
		dark := i%2 == 0
		set(i, 6, dark)
		set(6, i, dark)
	}

	// Alignment patterns, except where they would overlap a finder.
	centres := alignmentCentres[version]
	for _, y := range centres {
		for _, x := range centres {
			if (x == 6 && y == 6) || (x == 6 && y == size-7) || (x == size-7 && y == 6) {
				continue
			}
			drawAlignment(set, x, y)
		}
	}

	// The module above the lower-left finder's separator is always dark.
	set(8, size-8, true)

	// Format information occupies fixed positions near all three finders and
	// is written twice so it survives damage to any one corner.
	format := formatInfo(level, mask)
	for i := 0; i < 15; i++ {
		dark := format>>uint(i)&1 == 1
		x1, y1 := formatPos1(i)
		set(x1, y1, dark)
		x2, y2 := formatPos2(i, size)
		set(x2, y2, dark)
	}

	// Version information, versions 7 and up.
	if version >= 7 {
		info := versionInfo(version)
		for i := 0; i < 18; i++ {
			dark := info>>uint(i)&1 == 1
			x, y := i/3, size-11+i%3
			set(x, y, dark)
			set(y, x, dark)
		}
	}

	placeData(c, reserved, codewords, mask)
	return c
}

func drawFinder(set func(x, y int, dark bool), ox, oy, size int) {
	// The 7x7 pattern plus a one-module light separator on the inner sides.
	for dy := -1; dy <= 7; dy++ {
		for dx := -1; dx <= 7; dx++ {
			x, y := ox+dx, oy+dy
			if x < 0 || y < 0 || x >= size || y >= size {
				continue
			}
			inner := dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4
			edge := dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6 &&
				(dx == 0 || dx == 6 || dy == 0 || dy == 6)
			set(x, y, inner || edge)
		}
	}
}

func drawAlignment(set func(x, y int, dark bool), cx, cy int) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			ring := max(abs(dx), abs(dy))
			set(cx+dx, cy+dy, ring != 1)
		}
	}
}

// formatPos1 and formatPos2 map the fifteen format bits onto the two runs of
// modules that carry them. The mapping is irregular — it steps around the
// timing patterns — so it is written out rather than computed, because an
// off-by-one here yields a symbol no scanner will read and no test short of
// decoding one would catch.
func formatPos1(i int) (x, y int) {
	switch {
	case i < 6:
		return 8, i
	case i == 6:
		return 8, 7
	case i == 7:
		return 8, 8
	case i == 8:
		return 7, 8
	default:
		return 14 - i, 8
	}
}

func formatPos2(i, size int) (x, y int) {
	if i < 8 {
		return size - 1 - i, 8
	}
	return 8, size - 15 + i
}

// placeData walks the two-module-wide columns from the bottom right, upward
// then downward, skipping the vertical timing column, and writes each bit into
// the first unreserved module it meets.
func placeData(c *Code, reserved [][]bool, codewords []byte, mask int) {
	size := c.Size
	bit := 0

	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			// Column 6 is the vertical timing pattern; the pair shifts left.
			right = 5
		}
		// Direction alternates per column pair. Deriving it from the column
		// rather than toggling a flag keeps the skip at column 6 from
		// silently inverting every pair after it.
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
				dark := false
				if idx := bit / 8; idx < len(codewords) {
					dark = codewords[idx]>>uint(7-bit%8)&1 == 1
				}
				if maskAt(mask, x, y) {
					dark = !dark
				}
				c.Modules[y][x] = dark
				bit++
			}
		}
	}
}

func maskAt(mask, x, y int) bool {
	switch mask {
	case 0:
		return (y+x)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (y+x)%3 == 0
	case 4:
		return (y/2+x/3)%2 == 0
	case 5:
		return (y*x)%2+(y*x)%3 == 0
	case 6:
		return ((y*x)%2+(y*x)%3)%2 == 0
	default:
		return ((y+x)%2+(y*x)%3)%2 == 0
	}
}

// penalty scores a masked symbol by the four rules in the specification.
// Lower is better; the rules punish anything that looks like a finder pattern
// or that leaves the camera without local contrast to lock onto.
func penalty(c *Code) int {
	size := c.Size
	total := 0

	// Rule 1: runs of five or more identical modules.
	runScore := func(get func(i int) bool) int {
		score, run := 0, 1
		for i := 1; i < size; i++ {
			if get(i) == get(i-1) {
				run++
				continue
			}
			if run >= 5 {
				score += 3 + run - 5
			}
			run = 1
		}
		if run >= 5 {
			score += 3 + run - 5
		}
		return score
	}
	for i := 0; i < size; i++ {
		total += runScore(func(j int) bool { return c.Modules[i][j] })
		total += runScore(func(j int) bool { return c.Modules[j][i] })
	}

	// Rule 2: every 2x2 block of one colour.
	for y := 0; y < size-1; y++ {
		for x := 0; x < size-1; x++ {
			v := c.Modules[y][x]
			if c.Modules[y][x+1] == v && c.Modules[y+1][x] == v && c.Modules[y+1][x+1] == v {
				total += 3
			}
		}
	}

	// Rule 3: the 1:1:3:1:1 finder-like pattern with four light modules
	// on either side, in any row or column.
	patterns := [][]bool{
		{true, false, true, true, true, false, true, false, false, false, false},
		{false, false, false, false, true, false, true, true, true, false, true},
	}
	matches := func(get func(i int) bool, start int, want []bool) bool {
		for k, w := range want {
			if get(start+k) != w {
				return false
			}
		}
		return true
	}
	for i := 0; i < size; i++ {
		row := func(j int) bool { return c.Modules[i][j] }
		col := func(j int) bool { return c.Modules[j][i] }
		for start := 0; start+11 <= size; start++ {
			for _, p := range patterns {
				if matches(row, start, p) {
					total += 40
				}
				if matches(col, start, p) {
					total += 40
				}
			}
		}
	}

	// Rule 4: deviation from an even balance of dark and light.
	dark := 0
	for _, row := range c.Modules {
		for _, m := range row {
			if m {
				dark++
			}
		}
	}
	percent := dark * 100 / (size * size)
	deviation := abs(percent - 50)
	total += deviation / 5 * 10

	return total
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
