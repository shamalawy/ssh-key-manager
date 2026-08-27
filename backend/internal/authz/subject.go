package authz

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrDenied is returned when a subject lacks a permission.
	ErrDenied = errors.New("authz: permission denied")
	// ErrMFARequired means the permission is sensitive and the subject's MFA
	// verification is stale or absent.
	ErrMFARequired = errors.New("authz: step-up authentication required")
	// ErrOutOfScope means the subject holds the permission but not for this
	// resource's tags.
	ErrOutOfScope = errors.New("authz: resource is outside your assigned scope")
)

// Subject is the resolved identity behind a request, with its effective
// permissions already flattened. Resolution happens once per request; every
// subsequent check is a map lookup.
type Subject struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Username string

	// Set when the request authenticated with an API token rather than a
	// session, so token-only restrictions can be applied.
	TokenID *uuid.UUID

	// Scopes restricts the subject to resources carrying at least one of these
	// tags. Empty means unrestricted.
	Scopes []string

	// MFAVerifiedAt is when the subject last completed a second factor. Zero
	// means never.
	MFAVerifiedAt time.Time

	// MustChangePassword is set when the account's password was chosen by
	// someone else. Until the user picks their own, a session may do nothing
	// but change it.
	MustChangePassword bool

	granted map[Permission]bool
	denied  map[Permission]bool
}

// NewSubject flattens roles and overrides into an effective permission set.
func NewSubject(userID, tenantID uuid.UUID, username string, rolePerms []Permission, allowOverrides, denyOverrides []Permission) *Subject {
	s := &Subject{
		UserID:   userID,
		TenantID: tenantID,
		Username: username,
		granted:  make(map[Permission]bool, len(rolePerms)),
		denied:   make(map[Permission]bool, len(denyOverrides)),
	}
	for _, p := range rolePerms {
		s.granted[p] = true
	}
	for _, p := range allowOverrides {
		s.granted[p] = true
	}
	for _, p := range denyOverrides {
		s.denied[p] = true
	}
	return s
}

// Can reports whether the subject holds a permission. Deny overrides win.
func (s *Subject) Can(p Permission) bool {
	if s == nil {
		return false
	}
	if s.denied[p] {
		return false
	}
	return s.granted[p]
}

// Require returns ErrDenied unless the subject holds the permission.
func (s *Subject) Require(p Permission) error {
	if !s.Can(p) {
		return fmt.Errorf("%w: %s", ErrDenied, p)
	}
	return nil
}

// RequireFresh checks a permission and, for sensitive ones, that the subject
// completed MFA within window.
//
// This is the step-up gate in front of revealing private keys, restoring
// backups, and unsealing the vault: holding the permission is not enough if the
// session has been open, and possibly unattended, for hours.
func (s *Subject) RequireFresh(p Permission, window time.Duration) error {
	if err := s.Require(p); err != nil {
		return err
	}
	if !p.Sensitive() {
		return nil
	}
	if s.MFAVerifiedAt.IsZero() || time.Since(s.MFAVerifiedAt) > window {
		return fmt.Errorf("%w: %s requires re-authentication within %s", ErrMFARequired, p, window)
	}
	return nil
}

// InScope reports whether a resource carrying the given tags is within the
// subject's scope. An unscoped subject sees everything.
func (s *Subject) InScope(resourceTags []string) bool {
	if s == nil {
		return false
	}
	if len(s.Scopes) == 0 {
		return true
	}
	for _, scope := range s.Scopes {
		for _, tag := range resourceTags {
			if scope == tag {
				return true
			}
		}
	}
	return false
}

// RequireScoped checks both the permission and that the resource is in scope.
func (s *Subject) RequireScoped(p Permission, resourceTags []string) error {
	if err := s.Require(p); err != nil {
		return err
	}
	if !s.InScope(resourceTags) {
		return fmt.Errorf("%w: %v", ErrOutOfScope, resourceTags)
	}
	return nil
}

// Permissions returns the effective permission set, sorted, for the /me
// endpoint so the GUI can hide controls the user cannot use.
func (s *Subject) Permissions() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.granted))
	for p := range s.granted {
		if !s.denied[p] {
			out = append(out, string(p))
		}
	}
	sort.Strings(out)
	return out
}

// IsAdmin reports whether the subject holds every permission. Used only for
// display; enforcement always checks the specific permission.
func (s *Subject) IsAdmin() bool {
	for _, p := range All {
		if !s.Can(p) {
			return false
		}
	}
	return true
}

// Restrict narrows a subject to the intersection of what it already holds and
// the permissions listed.
//
// This is what makes an API token safe to hand to a CI job: the token names the
// three things that job does, and even though it authenticates as an account
// that could do everything, it cannot. Permissions the account does not hold
// are not added — a token can only ever subtract.
func (s *Subject) Restrict(allowed []Permission) {
	if s == nil || len(allowed) == 0 {
		return
	}
	narrowed := make(map[Permission]bool, len(allowed))
	for _, p := range allowed {
		if s.granted[p] {
			narrowed[p] = true
		}
	}
	s.granted = narrowed
}
