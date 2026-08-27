package diff

import (
	"strings"
	"testing"
)

func TestUnified(t *testing.T) {
	tests := []struct {
		name        string
		old, new    string
		wantEmpty   bool
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:      "identical",
			old:       "a\nb\n",
			new:       "a\nb\n",
			wantEmpty: true,
		},
		{
			name:        "single addition",
			old:         "a\n",
			new:         "a\nb\n",
			wantContain: []string{"+b", " a"},
		},
		{
			name:        "single removal",
			old:         "a\nb\n",
			new:         "a\n",
			wantContain: []string{"-b", " a"},
		},
		{
			name:        "replacement shows both sides",
			old:         "key-old\n",
			new:         "key-new\n",
			wantContain: []string{"-key-old", "+key-new"},
		},
		{
			name:        "from empty",
			old:         "",
			new:         "a\n",
			wantContain: []string{"+a"},
		},
		{
			name:        "to empty",
			old:         "a\n",
			new:         "",
			wantContain: []string{"-a"},
		},
		{
			name:        "unchanged lines outside context are omitted",
			old:         strings.Repeat("pad\n", 20) + "target\n",
			new:         strings.Repeat("pad\n", 20) + "changed\n",
			wantContain: []string{"-target", "+changed"},
			wantAbsent:  []string{"@@ -1,"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Unified(tc.old, tc.new, "before", "after", 3)

			if tc.wantEmpty {
				if got != "" {
					t.Errorf("expected an empty diff, got:\n%s", got)
				}
				return
			}
			if got == "" {
				t.Fatal("expected a diff, got empty")
			}
			if !strings.HasPrefix(got, "--- before\n+++ after\n") {
				t.Errorf("missing header:\n%s", got)
			}
			for _, want := range tc.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("diff missing %q:\n%s", want, got)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("diff unexpectedly contains %q:\n%s", absent, got)
				}
			}
		})
	}
}

func TestSummarise(t *testing.T) {
	tests := []struct {
		name              string
		old, new          string
		wantAdd, wantDrop int
	}{
		{"no change", "a\nb\n", "a\nb\n", 0, 0},
		{"one added", "a\n", "a\nb\n", 1, 0},
		{"one removed", "a\nb\n", "a\n", 0, 1},
		{"replacement", "a\n", "b\n", 1, 1},
		{"rotation shape", "old\n", "old\nnew\n", 1, 0},
		{"retire shape", "old\nnew\n", "new\n", 0, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Summarise(tc.old, tc.new)
			if got.Added != tc.wantAdd || got.Removed != tc.wantDrop {
				t.Errorf("Summarise = +%d/-%d, want +%d/-%d",
					got.Added, got.Removed, tc.wantAdd, tc.wantDrop)
			}
		})
	}
}

// The two-phase rotation shape: add the new key, keep the old, then remove the
// old. Each step must produce a diff that touches exactly one line.
func TestRotationDiffsAreMinimal(t *testing.T) {
	const (
		unmanaged = `ssh-ed25519 AAAAunmanaged operator@laptop`
		oldKey    = `ssh-ed25519 AAAAold skm:web:gen1`
		newKey    = `ssh-ed25519 AAAAnew skm:web:gen2`
	)

	before := unmanaged + "\n" + oldKey + "\n"
	staged := before + newKey + "\n"
	retired := unmanaged + "\n" + newKey + "\n"

	if st := Summarise(before, staged); st.Added != 1 || st.Removed != 0 {
		t.Errorf("staging changed +%d/-%d, want +1/-0", st.Added, st.Removed)
	}
	if st := Summarise(staged, retired); st.Added != 0 || st.Removed != 1 {
		t.Errorf("retiring changed +%d/-%d, want +0/-1", st.Added, st.Removed)
	}

	// The unmanaged key must survive both phases untouched.
	for name, text := range map[string]string{"staged": staged, "retired": retired} {
		if !strings.Contains(text, unmanaged) {
			t.Errorf("%s state lost the unmanaged key", name)
		}
	}
}
