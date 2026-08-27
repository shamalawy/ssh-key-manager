package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func subject(t *testing.T, granted, allow, deny []Permission) *Subject {
	t.Helper()
	return NewSubject(uuid.New(), uuid.New(), "tester", granted, allow, deny)
}

func TestCan(t *testing.T) {
	tests := []struct {
		name    string
		granted []Permission
		allow   []Permission
		deny    []Permission
		check   Permission
		want    bool
	}{
		{"granted by role", []Permission{PermKeyRead}, nil, nil, PermKeyRead, true},
		{"not granted", []Permission{PermKeyRead}, nil, nil, PermKeyWrite, false},
		{"granted by override", nil, []Permission{PermKeyReveal}, nil, PermKeyReveal, true},
		{"deny beats role grant", []Permission{PermKeyReveal}, nil, []Permission{PermKeyReveal}, PermKeyReveal, false},
		{"deny beats allow override", nil, []Permission{PermKeyReveal}, []Permission{PermKeyReveal}, PermKeyReveal, false},
		{"nothing granted", nil, nil, nil, PermKeyRead, false},
		// Permissions must not imply one another.
		{"write does not imply read", []Permission{PermKeyWrite}, nil, nil, PermKeyRead, false},
		{"read does not imply reveal", []Permission{PermKeyRead}, nil, nil, PermKeyReveal, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := subject(t, tc.granted, tc.allow, tc.deny)
			if got := s.Can(tc.check); got != tc.want {
				t.Errorf("Can(%s) = %v, want %v", tc.check, got, tc.want)
			}
		})
	}
}

func TestNilSubjectDeniesEverything(t *testing.T) {
	var s *Subject
	for _, p := range All {
		if s.Can(p) {
			t.Fatalf("nil subject granted %s", p)
		}
	}
	if s.InScope(nil) {
		t.Error("nil subject reported in scope")
	}
}

func TestRequire(t *testing.T) {
	s := subject(t, []Permission{PermKeyRead}, nil, nil)

	if err := s.Require(PermKeyRead); err != nil {
		t.Errorf("Require(key.read): %v", err)
	}
	err := s.Require(PermKeyWrite)
	if !errors.Is(err, ErrDenied) {
		t.Errorf("Require(key.write) = %v, want ErrDenied", err)
	}
}

func TestRequireFresh(t *testing.T) {
	const window = 5 * time.Minute

	tests := []struct {
		name    string
		perm    Permission
		mfaAge  time.Duration
		mfaSet  bool
		wantErr error
	}{
		{"non-sensitive needs no MFA", PermKeyRead, 0, false, nil},
		{"sensitive with fresh MFA", PermKeyReveal, time.Minute, true, nil},
		{"sensitive with stale MFA", PermKeyReveal, time.Hour, true, ErrMFARequired},
		{"sensitive with no MFA", PermKeyReveal, 0, false, ErrMFARequired},
		{"backup restore is sensitive", PermBackupRestore, time.Hour, true, ErrMFARequired},
		{"vault unseal is sensitive", PermVaultUnseal, 0, false, ErrMFARequired},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := subject(t, All, nil, nil)
			if tc.mfaSet {
				s.MFAVerifiedAt = time.Now().Add(-tc.mfaAge)
			}

			err := s.RequireFresh(tc.perm, window)
			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("RequireFresh(%s): %v", tc.perm, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("RequireFresh(%s) = %v, want %v", tc.perm, err, tc.wantErr)
			}
		})
	}
}

// A denied permission must stay denied even with fresh MFA — step-up is an
// additional gate, never a substitute for holding the permission.
func TestRequireFreshStillChecksPermission(t *testing.T) {
	s := subject(t, []Permission{PermKeyRead}, nil, nil)
	s.MFAVerifiedAt = time.Now()

	if err := s.RequireFresh(PermKeyReveal, time.Hour); !errors.Is(err, ErrDenied) {
		t.Errorf("RequireFresh on an ungranted permission = %v, want ErrDenied", err)
	}
}

func TestScopes(t *testing.T) {
	tests := []struct {
		name         string
		scopes       []string
		resourceTags []string
		want         bool
	}{
		{"unscoped sees everything", nil, []string{"prod"}, true},
		{"unscoped sees untagged", nil, nil, true},
		{"matching tag", []string{"prod"}, []string{"prod", "eu"}, true},
		{"no matching tag", []string{"prod"}, []string{"dev"}, false},
		{"scoped subject cannot see untagged", []string{"prod"}, nil, false},
		{"any of several scopes", []string{"prod", "staging"}, []string{"staging"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := subject(t, All, nil, nil)
			s.Scopes = tc.scopes
			if got := s.InScope(tc.resourceTags); got != tc.want {
				t.Errorf("InScope(%v) with scopes %v = %v, want %v", tc.resourceTags, tc.scopes, got, tc.want)
			}
		})
	}
}

func TestRequireScoped(t *testing.T) {
	s := subject(t, []Permission{PermTargetRead}, nil, nil)
	s.Scopes = []string{"prod"}

	if err := s.RequireScoped(PermTargetRead, []string{"prod"}); err != nil {
		t.Errorf("in-scope check failed: %v", err)
	}
	if err := s.RequireScoped(PermTargetRead, []string{"dev"}); !errors.Is(err, ErrOutOfScope) {
		t.Errorf("out-of-scope check = %v, want ErrOutOfScope", err)
	}
	if err := s.RequireScoped(PermTargetWrite, []string{"prod"}); !errors.Is(err, ErrDenied) {
		t.Errorf("ungranted permission = %v, want ErrDenied", err)
	}
}

func TestSystemRolesAreWellFormed(t *testing.T) {
	seen := make(map[string]bool)

	for _, role := range SystemRoles {
		t.Run(role.Name, func(t *testing.T) {
			if seen[role.Name] {
				t.Fatalf("duplicate system role %q", role.Name)
			}
			seen[role.Name] = true

			if role.Description == "" {
				t.Error("role has no description")
			}
			if len(role.Permissions) == 0 {
				t.Error("role grants nothing")
			}
			for _, p := range role.Permissions {
				if !Valid(p) {
					t.Errorf("role grants unknown permission %q", p)
				}
			}
		})
	}

	for _, want := range []string{"admin", "engineer", "operator", "auditor", "viewer"} {
		if !seen[want] {
			t.Errorf("missing system role %q", want)
		}
	}
}

// The operator role exists precisely so day-to-day work does not require access
// to private key material. If that ever changes it should be a deliberate,
// visible decision rather than a quiet edit.
func TestOperatorAndViewerCannotRevealKeys(t *testing.T) {
	for _, name := range []string{"operator", "viewer", "auditor"} {
		role := systemRole(t, name)
		s := subject(t, role.Permissions, nil, nil)

		for _, p := range []Permission{PermKeyReveal, PermKeyRevealBreakGlass, PermCredentialReveal} {
			if s.Can(p) {
				t.Errorf("role %q grants %s", name, p)
			}
		}
		if s.Can(PermBackupRestore) {
			t.Errorf("role %q grants backup.restore", name)
		}
		if s.Can(PermVaultUnseal) {
			t.Errorf("role %q grants vault.unseal", name)
		}
	}
}

func TestViewerAndAuditorAreReadOnly(t *testing.T) {
	writePerms := []Permission{
		PermKeyWrite, PermKeyDelete, PermKeyRotate, PermTargetWrite, PermTargetDelete,
		PermDeployExecute, PermRotationExecute, PermRollback, PermUserWrite,
	}

	for _, name := range []string{"viewer", "auditor"} {
		s := subject(t, systemRole(t, name).Permissions, nil, nil)
		for _, p := range writePerms {
			if s.Can(p) {
				t.Errorf("read-only role %q grants %s", name, p)
			}
		}
	}
}

func TestAdminHoldsEverything(t *testing.T) {
	s := subject(t, systemRole(t, "admin").Permissions, nil, nil)
	for _, p := range All {
		if !s.Can(p) {
			t.Errorf("admin lacks %s", p)
		}
	}
	if !s.IsAdmin() {
		t.Error("IsAdmin() = false for the admin role")
	}
}

func TestPermissionsListIsCompleteAndUnique(t *testing.T) {
	seen := make(map[Permission]bool, len(All))
	for _, p := range All {
		if seen[p] {
			t.Errorf("duplicate permission %q in All", p)
		}
		seen[p] = true
		if p.Namespace() == "" {
			t.Errorf("permission %q has no namespace", p)
		}
	}

	if _, err := ParsePermission("key.read"); err != nil {
		t.Errorf("ParsePermission(key.read): %v", err)
	}
	if _, err := ParsePermission("key.definitely-not-real"); err == nil {
		t.Error("ParsePermission accepted an unknown permission")
	}
}

func TestPermissionsAreSortedAndFilterDenies(t *testing.T) {
	s := subject(t, []Permission{PermTargetRead, PermKeyRead, PermKeyWrite}, nil, []Permission{PermKeyWrite})

	got := s.Permissions()
	want := []string{"key.read", "target.read"}
	if len(got) != len(want) {
		t.Fatalf("Permissions() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Permissions()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func systemRole(t *testing.T, name string) SystemRole {
	t.Helper()
	for _, r := range SystemRoles {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("system role %q not found", name)
	return SystemRole{}
}
