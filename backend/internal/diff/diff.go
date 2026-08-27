// Package diff produces unified diffs of text files.
//
// SKM shows a diff before every mutating operation. An operator approving a
// change to authorized_keys should see the exact lines being added and removed,
// not a summary — "3 keys added, 1 removed" hides which key was removed, and
// that is precisely the detail that matters when the change is wrong.
package diff

import (
	"fmt"
	"strings"
)

// Unified renders a unified diff of old against new.
//
// context is the number of unchanged lines shown around each change. Returns an
// empty string when the inputs are identical, which callers use to skip writes.
func Unified(oldText, newText, oldLabel, newLabel string, context int) string {
	if oldText == newText {
		return ""
	}
	if context < 0 {
		context = 0
	}

	oldLines := splitLines(oldText)
	newLines := splitLines(newText)
	ops := lcsOps(oldLines, newLines)
	hunks := group(ops, context)
	if len(hunks) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s\n", oldLabel, newLabel)

	for _, h := range hunks {
		oldCount, newCount := 0, 0
		for _, op := range h {
			switch op.kind {
			case opEqual:
				oldCount++
				newCount++
			case opDelete:
				oldCount++
			case opInsert:
				newCount++
			}
		}

		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n",
			h[0].oldLine+1, oldCount, h[0].newLine+1, newCount)

		for _, op := range h {
			switch op.kind {
			case opEqual:
				fmt.Fprintf(&b, " %s\n", op.text)
			case opDelete:
				fmt.Fprintf(&b, "-%s\n", op.text)
			case opInsert:
				fmt.Fprintf(&b, "+%s\n", op.text)
			}
		}
	}

	return b.String()
}

type opKind int

const (
	opEqual opKind = iota
	opDelete
	opInsert
)

type op struct {
	kind    opKind
	text    string
	oldLine int
	newLine int
}

// lcsOps computes an edit script via the classic longest-common-subsequence
// dynamic program.
//
// The table is O(n*m); authorized_keys files are tens of lines, so this is
// comfortably cheap and produces minimal, readable diffs. If SKM ever diffs
// whole device configurations this should become Myers.
func lcsOps(a, b []string) []op {
	n, m := len(a), len(b)

	table := make([][]int, n+1)
	for i := range table {
		table[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
			} else if table[i+1][j] >= table[i][j+1] {
				table[i][j] = table[i+1][j]
			} else {
				table[i][j] = table[i][j+1]
			}
		}
	}

	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, op{opEqual, a[i], i, j})
			i++
			j++
		case table[i+1][j] >= table[i][j+1]:
			ops = append(ops, op{opDelete, a[i], i, j})
			i++
		default:
			ops = append(ops, op{opInsert, b[j], i, j})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{opDelete, a[i], i, j})
	}
	for ; j < m; j++ {
		ops = append(ops, op{opInsert, b[j], i, j})
	}
	return ops
}

// group splits an edit script into hunks, keeping `context` equal lines around
// each run of changes and dropping the rest.
func group(ops []op, context int) [][]op {
	changed := make([]bool, len(ops))
	any := false
	for i, o := range ops {
		if o.kind != opEqual {
			changed[i] = true
			any = true
		}
	}
	if !any {
		return nil
	}

	keep := make([]bool, len(ops))
	for i, isChange := range changed {
		if !isChange {
			continue
		}
		lo := max(0, i-context)
		hi := min(len(ops)-1, i+context)
		for j := lo; j <= hi; j++ {
			keep[j] = true
		}
	}

	var hunks [][]op
	var current []op
	for i, k := range keep {
		if k {
			current = append(current, ops[i])
			continue
		}
		if len(current) > 0 {
			hunks = append(hunks, current)
			current = nil
		}
	}
	if len(current) > 0 {
		hunks = append(hunks, current)
	}
	return hunks
}

// splitLines splits text into lines, dropping the empty element a trailing
// newline would otherwise produce.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// Stat summarises a diff for compact display.
type Stat struct {
	Added   int
	Removed int
}

// Summarise counts added and removed lines without rendering the diff.
func Summarise(oldText, newText string) Stat {
	var st Stat
	for _, o := range lcsOps(splitLines(oldText), splitLines(newText)) {
		switch o.kind {
		case opInsert:
			st.Added++
		case opDelete:
			st.Removed++
		}
	}
	return st
}
