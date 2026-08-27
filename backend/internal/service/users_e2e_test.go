package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/dbtest"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
)

// Account administration against a real database.
//
// The guards here are the console's version of the lockout guards the rest of
// the product applies to hosts: the ways an administrator can accidentally
// remove their own or everyone's access.

func TestCreateRejectsAnUnknownRoleWithoutLeavingAnAccount(t *testing.T) {
	// A rejected create used to insert the account, then fail on the role
	// grant, leaving a user nobody had a password for sitting in the table.
	h := newUserHarness(t)

	before := h.count(t)
	_, err := h.svc.Create(t.Context(), h.admin, CreateUserRequest{
		Username: "ghost", Password: "a-perfectly-long-password", Roles: []string{"wizard"},
	})
	if err == nil {
		t.Fatal("Create accepted a role that does not exist")
	}
	if !strings.Contains(err.Error(), "wizard") {
		t.Errorf("the error should name the role: %v", err)
	}

	if after := h.count(t); after != before {
		t.Errorf("a rejected create left %d account(s) behind", after-before)
	}
}

func TestCreateRejectsAShortPassword(t *testing.T) {
	h := newUserHarness(t)

	_, err := h.svc.Create(t.Context(), h.admin, CreateUserRequest{
		Username: "brief", Password: "short",
	})
	if err == nil {
		t.Fatal("Create accepted a five-character password")
	}
	if h.exists(t, "brief") {
		t.Error("a rejected create left the account behind")
	}
}

func TestTheLastAdministratorCannotBeRemoved(t *testing.T) {
	// Reaching this guard needs an actor who can edit users without being an
	// administrator, which is what a per-user permission override produces. The
	// self-checks catch the ordinary cases first, so without an override the
	// guard is unreachable — and that is precisely why it is worth a test: the
	// day someone grants user.write to a custom role, it is the only thing
	// standing between a tidy-up and an install nobody can administer.
	h := newUserHarness(t)

	deputy, err := h.svc.Create(t.Context(), h.admin, CreateUserRequest{
		Username: "deputy", Password: "a-sufficiently-long-password",
		Roles: []string{authz.RoleOperator},
	})
	if err != nil {
		t.Fatal(err)
	}

	subject := authz.NewSubject(deputy.ID, store.DefaultTenantID, "deputy",
		[]authz.Permission{authz.PermUserRead, authz.PermUserWrite}, nil, nil)
	subject.MFAVerifiedAt = time.Now()

	// Demoting the only administrator.
	_, err = h.svc.Update(t.Context(), subject, h.admin.UserID, UpdateUserRequest{
		Roles: &[]string{authz.RoleViewer},
	})
	if err == nil {
		t.Fatal("the only administrator was demoted, locking everyone out of administration")
	}
	if !strings.Contains(err.Error(), "only active administrator") {
		t.Errorf("the refusal should explain itself: %v", err)
	}

	// Deactivating and deleting are the same hole by another route.
	inactive := false
	if _, err := h.svc.Update(t.Context(), subject, h.admin.UserID, UpdateUserRequest{
		Active: &inactive,
	}); err == nil {
		t.Error("the only administrator was deactivated")
	}
	if err := h.svc.Delete(t.Context(), subject, h.admin.UserID); err == nil {
		t.Error("the only administrator was deleted")
	}

	// With a second administrator in place, the same call is allowed.
	second, err := h.svc.Create(t.Context(), h.admin, CreateUserRequest{
		Username: "second-admin", Password: "another-long-password",
		Roles: []string{authz.RoleAdmin},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Update(t.Context(), subject, second.ID, UpdateUserRequest{
		Roles: &[]string{authz.RoleViewer},
	}); err != nil {
		t.Fatalf("demoting one of two administrators should be allowed: %v", err)
	}
}

func TestYouCannotDemoteOrDeactivateYourself(t *testing.T) {
	h := newUserHarness(t)

	if _, err := h.svc.Update(t.Context(), h.admin, h.admin.UserID, UpdateUserRequest{
		Roles: &[]string{authz.RoleViewer},
	}); err == nil {
		t.Error("an administrator demoted themselves")
	}

	inactive := false
	if _, err := h.svc.Update(t.Context(), h.admin, h.admin.UserID, UpdateUserRequest{
		Active: &inactive,
	}); err == nil {
		t.Error("an administrator deactivated themselves")
	}

	if err := h.svc.Delete(t.Context(), h.admin, h.admin.UserID); err == nil {
		t.Error("an administrator deleted themselves")
	}
}

func TestATokenCannotExceedItsOwnersRights(t *testing.T) {
	h := newUserHarness(t)

	viewer, err := h.svc.Create(t.Context(), h.admin, CreateUserRequest{
		Username: "read-only", Password: "yet-another-long-password",
		Roles: []string{authz.RoleViewer},
	})
	if err != nil {
		t.Fatal(err)
	}
	subject := h.subjectFor(t, viewer.ID)

	// A viewer can mint nothing, so the admin mints on their behalf — and the
	// permission the viewer does not hold is refused rather than trimmed.
	_, _, err = h.svc.CreateToken(t.Context(), h.admin, CreateTokenRequest{
		Name: "escalation", UserID: viewer.ID.String(),
		Permissions: []string{string(authz.PermKeyReveal)},
	})
	if err == nil {
		t.Fatal("a token was minted carrying a permission its owner does not hold")
	}
	if !strings.Contains(err.Error(), "key.reveal") {
		t.Errorf("the refusal should name the permission: %v", err)
	}

	// A permission the owner does hold is fine.
	_, secret, err := h.svc.CreateToken(t.Context(), h.admin, CreateTokenRequest{
		Name: "reading", UserID: viewer.ID.String(),
		Permissions: []string{string(authz.PermKeyRead)},
	})
	if err != nil {
		t.Fatalf("minting a token within the owner's rights: %v", err)
	}
	if !strings.HasPrefix(secret, TokenPrefix) {
		t.Errorf("token %q does not carry the recognisable prefix", secret[:8])
	}
	_ = subject
}

func TestResetTOTPRefusesYourOwnAccount(t *testing.T) {
	// Clearing a second factor is the one administrative action that reduces
	// security outright, so it always involves a second person.
	h := newUserHarness(t)

	if err := h.svc.ResetTOTP(t.Context(), h.admin, h.admin.UserID); err == nil {
		t.Fatal("an administrator cleared their own second factor through the admin path")
	}
}

// ------------------------------------------------------------- harness ---

type userHarness struct {
	svc   *UserService
	users *store.Users
	admin *authz.Subject
}

// newUserHarness wires account administration against a live database. No sshd
// is involved: none of this touches a host.
func newUserHarness(t *testing.T) *userHarness {
	t.Helper()
	pool := dbtest.New(t)

	users := store.NewUsers(pool)
	if err := users.EnsureSystemRoles(context.Background(), store.DefaultTenantID); err != nil {
		t.Fatalf("seeding system roles: %v", err)
	}

	h := &userHarness{
		svc:   NewUserService(users, store.NewTokens(pool), audit.New(pool)),
		users: users,
	}

	// A real administrator row with a real role grant, because the guards under
	// test work by counting administrators.
	admin, err := users.Create(context.Background(), &store.User{
		Username: "root-admin", DisplayName: "Root", PasswordHash: "unused-in-tests", Active: true,
	})
	if err != nil {
		t.Fatalf("creating the administrator: %v", err)
	}
	role, err := users.GetRoleByName(context.Background(), store.DefaultTenantID, authz.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.GrantRole(context.Background(), admin.ID, role.ID); err != nil {
		t.Fatal(err)
	}

	h.admin = h.subjectFor(t, admin.ID)
	return h
}

// subjectFor loads a subject the way a request would, so the permissions under
// test are the ones the server would actually resolve.
func (h *userHarness) subjectFor(t *testing.T, id uuid.UUID) *authz.Subject {
	t.Helper()

	subject, err := h.users.LoadSubject(context.Background(), store.DefaultTenantID, id)
	if err != nil {
		t.Fatalf("loading subject: %v", err)
	}
	subject.MFAVerifiedAt = time.Now()
	return subject
}

func (h *userHarness) count(t *testing.T) int {
	t.Helper()
	users, err := h.users.List(t.Context(), store.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	return len(users)
}

func (h *userHarness) exists(t *testing.T, username string) bool {
	t.Helper()
	users, err := h.users.List(t.Context(), store.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Username == username {
			return true
		}
	}
	return false
}
