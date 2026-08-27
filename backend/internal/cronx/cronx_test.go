package cronx

import (
	"testing"
	"time"
)

func mustParse(t *testing.T, expr string) *Schedule {
	t.Helper()
	s, err := Parse(expr)
	if err != nil {
		t.Fatalf("Parse(%q) = %v", expr, err)
	}
	return s
}

func at(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parsing %q: %v", value, err)
	}
	return parsed
}

func TestNext(t *testing.T) {
	tests := []struct {
		name string
		expr string
		from string
		want string
	}{
		{"every minute", "* * * * *", "2026-03-01T10:00:30Z", "2026-03-01T10:01:00Z"},
		{"top of the hour", "0 * * * *", "2026-03-01T10:00:30Z", "2026-03-01T11:00:00Z"},
		{"daily at 03:30", "30 3 * * *", "2026-03-01T10:00:00Z", "2026-03-02T03:30:00Z"},
		{"daily, earlier today", "30 3 * * *", "2026-03-01T01:00:00Z", "2026-03-01T03:30:00Z"},
		{"every 15 minutes", "*/15 * * * *", "2026-03-01T10:07:00Z", "2026-03-01T10:15:00Z"},
		{"weekday range", "0 9 * * 1-5", "2026-03-07T12:00:00Z", "2026-03-09T09:00:00Z"},
		{"first of the month", "0 0 1 * *", "2026-03-15T00:00:00Z", "2026-04-01T00:00:00Z"},
		{"list of hours", "0 2,14 * * *", "2026-03-01T03:00:00Z", "2026-03-01T14:00:00Z"},
		{"named month", "0 0 1 jan *", "2026-03-01T00:00:00Z", "2027-01-01T00:00:00Z"},
		{"named day", "0 6 * * sun", "2026-03-03T00:00:00Z", "2026-03-08T06:00:00Z"},
		{"step from a value", "0 9/6 * * *", "2026-03-01T00:00:00Z", "2026-03-01T09:00:00Z"},

		{"macro hourly", "@hourly", "2026-03-01T10:30:00Z", "2026-03-01T11:00:00Z"},
		{"macro daily", "@daily", "2026-03-01T10:30:00Z", "2026-03-02T00:00:00Z"},
		{"macro weekly", "@weekly", "2026-03-03T10:30:00Z", "2026-03-08T00:00:00Z"},
		{"macro monthly", "@monthly", "2026-03-03T10:30:00Z", "2026-04-01T00:00:00Z"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mustParse(t, tc.expr).Next(at(t, tc.from))
			want := at(t, tc.want)
			if !got.Equal(want) {
				t.Errorf("Next(%q, %s) = %s, want %s", tc.expr, tc.from,
					got.Format(time.RFC3339), want.Format(time.RFC3339))
			}
		})
	}
}

// The either-or day rule is cron's least intuitive behaviour and the one most
// likely to fire a rotation on a day nobody expected.
func TestDayFieldsAreOredWhenBothAreRestricted(t *testing.T) {
	// The 15th of March 2026 is a Sunday; the 2nd is a Monday.
	s := mustParse(t, "0 0 15 * mon")

	// From the 1st, the next Monday (the 2nd) matches even though it is not
	// the 15th.
	got := s.Next(at(t, "2026-03-01T00:00:00Z"))
	if want := at(t, "2026-03-02T00:00:00Z"); !got.Equal(want) {
		t.Errorf("with both day fields set, got %s, want %s (either should match)",
			got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestDayOfMonthOnlyIgnoresWeekday(t *testing.T) {
	s := mustParse(t, "0 0 15 * *")
	got := s.Next(at(t, "2026-03-01T00:00:00Z"))
	if want := at(t, "2026-03-15T00:00:00Z"); !got.Equal(want) {
		t.Errorf("got %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestSundayIsSevenOrZero(t *testing.T) {
	zero := mustParse(t, "0 0 * * 0").Next(at(t, "2026-03-03T00:00:00Z"))
	seven := mustParse(t, "0 0 * * 7").Next(at(t, "2026-03-03T00:00:00Z"))

	if !zero.Equal(seven) {
		t.Errorf("0 and 7 should both mean Sunday: %s vs %s",
			zero.Format(time.RFC3339), seven.Format(time.RFC3339))
	}
}

func TestEveryMacro(t *testing.T) {
	s := mustParse(t, "@every 90m")
	from := at(t, "2026-03-01T10:00:00Z")

	got := s.Next(from)
	if want := from.Add(90 * time.Minute); !got.Equal(want) {
		t.Errorf("got %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestNextIsAlwaysStrictlyAfter(t *testing.T) {
	// An expression that matches "now" exactly must return the *following*
	// occurrence, or a scheduler that stores next_run_at and re-reads it would
	// fire the same policy forever.
	s := mustParse(t, "0 * * * *")
	exact := at(t, "2026-03-01T10:00:00Z")

	got := s.Next(exact)
	if !got.After(exact) {
		t.Fatalf("Next(%s) = %s, which is not strictly after", exact, got)
	}
	if want := at(t, "2026-03-01T11:00:00Z"); !got.Equal(want) {
		t.Errorf("got %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestUnsatisfiableExpressionReportsRatherThanSpinning(t *testing.T) {
	// The 30th of February never arrives.
	s := mustParse(t, "0 0 30 2 *")

	got := s.Next(at(t, "2026-03-01T00:00:00Z"))
	if !got.IsZero() {
		t.Errorf("Next returned %s for an unsatisfiable expression; want the zero time", got)
	}

	if err := Validate("0 0 30 2 *"); err == nil {
		t.Error("Validate accepted an expression that never fires")
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	bad := []string{
		"",
		"* * * *",
		"* * * * * *",
		"60 * * * *",
		"* 24 * * *",
		"* * 0 * *",
		"* * * 13 *",
		"* * * * 8",
		"5-1 * * * *",
		"*/0 * * * *",
		"a * * * *",
		"@nonsense",
		"@every 30s",
		"@every banana",
	}

	for _, expr := range bad {
		t.Run(expr, func(t *testing.T) {
			if _, err := Parse(expr); err == nil {
				t.Errorf("Parse(%q) accepted an invalid expression", expr)
			}
		})
	}
}

func TestParsePreservesTheOriginalExpression(t *testing.T) {
	s := mustParse(t, "@daily")
	if s.String() != "@daily" {
		t.Errorf("String() = %q, want the macro back", s.String())
	}
}

func TestChunkedStepsCoverTheWholeRange(t *testing.T) {
	s := mustParse(t, "0 */6 * * *")

	// 00:00, 06:00, 12:00, 18:00, then the next day.
	want := []string{
		"2026-03-01T06:00:00Z",
		"2026-03-01T12:00:00Z",
		"2026-03-01T18:00:00Z",
		"2026-03-02T00:00:00Z",
	}

	current := at(t, "2026-03-01T00:00:00Z")
	for _, expected := range want {
		current = s.Next(current)
		if got, wantTime := current, at(t, expected); !got.Equal(wantTime) {
			t.Fatalf("got %s, want %s", got.Format(time.RFC3339), wantTime.Format(time.RFC3339))
		}
	}
}
