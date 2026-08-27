// Package cronx parses cron expressions and computes the next firing time.
//
// It exists rather than a dependency because SKM needs one narrow thing —
// "when does this policy next run?" — and the rest of the codebase already
// takes the same position on stdlib-first (no ORM, no test framework, no HTTP
// router). A scheduler is also exactly the kind of component where reading the
// implementation matters: a policy that fires at the wrong hour rotates keys
// during a change freeze.
//
// Supported syntax is the standard five-field form:
//
//	minute hour day-of-month month day-of-week
//
// Each field accepts `*`, a value, a `a-b` range, a `a-b/n` or `*/n` step, and
// comma-separated lists of those. Day-of-week accepts 0-6 with 0 = Sunday, and
// 7 as a synonym for Sunday. Three-letter month and day names are accepted.
//
// The macros @hourly, @daily/@midnight, @weekly, @monthly, @yearly/@annually
// and @every <duration> are also understood.
package cronx

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule computes successive activation times.
type Schedule struct {
	// Each field is a bitmask over its legal range.
	minute  uint64
	hour    uint64
	dom     uint64
	month   uint64
	dow     uint64
	starDOM bool
	starDOW bool

	// every is set by the @every macro, which is a fixed interval rather than
	// a wall-clock pattern.
	every time.Duration

	expr string
}

// String returns the expression the schedule was parsed from.
func (s *Schedule) String() string { return s.expr }

type fieldSpec struct {
	name    string
	min     int
	max     int
	aliases map[string]int
}

var (
	minuteSpec = fieldSpec{name: "minute", min: 0, max: 59}
	hourSpec   = fieldSpec{name: "hour", min: 0, max: 23}
	domSpec    = fieldSpec{name: "day of month", min: 1, max: 31}
	monthSpec  = fieldSpec{name: "month", min: 1, max: 12, aliases: map[string]int{
		"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
		"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
	}}
	dowSpec = fieldSpec{name: "day of week", min: 0, max: 6, aliases: map[string]int{
		"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
	}}
)

// Parse compiles a cron expression.
func Parse(expr string) (*Schedule, error) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return nil, fmt.Errorf("cronx: the expression is empty")
	}

	if strings.HasPrefix(trimmed, "@") {
		return parseMacro(trimmed)
	}

	fields := strings.Fields(trimmed)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cronx: %q has %d fields; a cron expression has 5 "+
			"(minute hour day-of-month month day-of-week)", expr, len(fields))
	}

	s := &Schedule{expr: trimmed}
	var err error

	if s.minute, err = parseField(fields[0], minuteSpec); err != nil {
		return nil, err
	}
	if s.hour, err = parseField(fields[1], hourSpec); err != nil {
		return nil, err
	}
	if s.dom, err = parseField(fields[2], domSpec); err != nil {
		return nil, err
	}
	if s.month, err = parseField(fields[3], monthSpec); err != nil {
		return nil, err
	}
	if s.dow, err = parseField(fields[4], dowSpec); err != nil {
		return nil, err
	}

	// Cron's one genuinely surprising rule: when both day fields are
	// restricted, a day matching *either* fires. When only one is restricted,
	// only that one applies. Recording which were stars is the only way to
	// tell the two cases apart later.
	s.starDOM = isStar(fields[2])
	s.starDOW = isStar(fields[4])

	return s, nil
}

func isStar(field string) bool {
	return field == "*" || field == "?"
}

func parseMacro(expr string) (*Schedule, error) {
	if after, found := strings.CutPrefix(expr, "@every "); found {
		d, err := time.ParseDuration(strings.TrimSpace(after))
		if err != nil {
			return nil, fmt.Errorf("cronx: %q is not a valid duration: %w", after, err)
		}
		if d < time.Minute {
			return nil, fmt.Errorf("cronx: @every intervals shorter than a minute are refused (got %s)", d)
		}
		return &Schedule{every: d, expr: expr}, nil
	}

	var equivalent string
	switch expr {
	case "@hourly":
		equivalent = "0 * * * *"
	case "@daily", "@midnight":
		equivalent = "0 0 * * *"
	case "@weekly":
		equivalent = "0 0 * * 0"
	case "@monthly":
		equivalent = "0 0 1 * *"
	case "@yearly", "@annually":
		equivalent = "0 0 1 1 *"
	default:
		return nil, fmt.Errorf("cronx: unknown macro %q", expr)
	}

	s, err := Parse(equivalent)
	if err != nil {
		return nil, err
	}
	s.expr = expr
	return s, nil
}

// parseField compiles one comma-separated field into a bitmask.
func parseField(field string, spec fieldSpec) (uint64, error) {
	var bits uint64

	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return 0, fmt.Errorf("cronx: empty entry in the %s field", spec.name)
		}

		step := 1
		if base, stepStr, found := strings.Cut(part, "/"); found {
			n, err := strconv.Atoi(strings.TrimSpace(stepStr))
			if err != nil || n <= 0 {
				return 0, fmt.Errorf("cronx: %q is not a valid step in the %s field", stepStr, spec.name)
			}
			step = n
			part = strings.TrimSpace(base)
		}

		lo, hi := spec.min, spec.max
		switch {
		case part == "*" || part == "?":
			// Full range, already set.
		case strings.Contains(part, "-"):
			loStr, hiStr, _ := strings.Cut(part, "-")
			var err error
			if lo, err = parseValue(loStr, spec); err != nil {
				return 0, err
			}
			if hi, err = parseValue(hiStr, spec); err != nil {
				return 0, err
			}
			if lo > hi {
				return 0, fmt.Errorf("cronx: %q is a descending range in the %s field", part, spec.name)
			}
		default:
			v, err := parseValue(part, spec)
			if err != nil {
				return 0, err
			}
			lo, hi = v, v
			// A bare value with a step means "from here to the end".
			if step > 1 {
				hi = spec.max
			}
		}

		for v := lo; v <= hi; v += step {
			bits |= 1 << uint(v)
		}
	}

	if bits == 0 {
		return 0, fmt.Errorf("cronx: the %s field %q matches nothing", spec.name, field)
	}
	return bits, nil
}

func parseValue(s string, spec fieldSpec) (int, error) {
	s = strings.TrimSpace(s)

	if spec.aliases != nil {
		if v, ok := spec.aliases[strings.ToLower(s)]; ok {
			return v, nil
		}
	}

	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("cronx: %q is not a valid %s value", s, spec.name)
	}

	// Sunday is conventionally writable as either 0 or 7.
	if spec.name == dowSpec.name && v == 7 {
		v = 0
	}
	if v < spec.min || v > spec.max {
		return 0, fmt.Errorf("cronx: %s value %d is outside %d-%d", spec.name, v, spec.min, spec.max)
	}
	return v, nil
}

// Next returns the first activation strictly after t.
//
// The search is bounded at five years: an expression like "0 0 30 2 *" (the
// 30th of February) never matches, and a scheduler must report that rather
// than spin.
func (s *Schedule) Next(t time.Time) time.Time {
	if s.every > 0 {
		return t.Add(s.every).Truncate(time.Second)
	}

	// Start at the next whole minute; cron has minute resolution.
	t = t.Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(5, 0, 0)

	for t.Before(limit) {
		if s.month&(1<<uint(t.Month())) == 0 {
			// Skip to the first of the next month.
			t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location()).AddDate(0, 1, 0)
			continue
		}
		if !s.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()).AddDate(0, 0, 1)
			continue
		}
		if s.hour&(1<<uint(t.Hour())) == 0 {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location()).Add(time.Hour)
			continue
		}
		if s.minute&(1<<uint(t.Minute())) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}

	// No match within the horizon. A zero time is the caller's signal that the
	// expression is unsatisfiable, which is better than a wrong answer.
	return time.Time{}
}

// dayMatches applies cron's day-field rule: when both day fields are
// restricted, either matching is enough.
func (s *Schedule) dayMatches(t time.Time) bool {
	domHit := s.dom&(1<<uint(t.Day())) != 0
	dowHit := s.dow&(1<<uint(t.Weekday())) != 0

	switch {
	case s.starDOM && s.starDOW:
		return true
	case s.starDOM:
		return dowHit
	case s.starDOW:
		return domHit
	default:
		return domHit || dowHit
	}
}

// NextAfter is a convenience for callers holding an expression rather than a
// compiled schedule.
func NextAfter(expr string, t time.Time) (time.Time, error) {
	s, err := Parse(expr)
	if err != nil {
		return time.Time{}, err
	}
	next := s.Next(t)
	if next.IsZero() {
		return time.Time{}, fmt.Errorf("cronx: %q never fires", expr)
	}
	return next, nil
}

// Validate reports whether an expression parses and can actually fire.
func Validate(expr string) error {
	_, err := NextAfter(expr, time.Now())
	return err
}
