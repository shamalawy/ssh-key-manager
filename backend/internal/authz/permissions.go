// Package authz defines SKM's permission model and evaluates access decisions.
//
// The model is deliberately flat: a permission is a dotted string, a role is a
// set of permissions, and a user holds roles plus optional per-user overrides.
// There is no inheritance and no hierarchy, because permission systems that
// support both are systems where nobody can answer "can this person do that?"
// by reading the configuration.
//
// Two rules make the model predictable:
//
//   - Deny always wins. An explicit deny override beats every role grant.
//   - Nothing is implied. Holding key.write does not imply key.read; roles list
//     everything they grant. Verbose, but auditable.
package authz

import (
	"fmt"
	"sort"
	"strings"
)

// Permission is a dotted capability string.
type Permission string

// The complete permission set. Anything not listed here cannot be granted,
// which means a typo in a role definition fails loudly instead of silently
// granting nothing.
const (
	// Keys
	PermKeyRead   Permission = "key.read"
	PermKeyWrite  Permission = "key.write"
	PermKeyDelete Permission = "key.delete"
	PermKeyRotate Permission = "key.rotate"
	PermKeyRevoke Permission = "key.revoke"
	PermKeyImport Permission = "key.import"
	PermKeyAdopt  Permission = "key.adopt"
	// Separately gated: this is the one that hands over private key material.
	PermKeyReveal Permission = "key.reveal"
	// Break-glass keys are the emergency access path and are gated apart from
	// ordinary reveals so the two can be audited and alerted on differently.
	PermKeyRevealBreakGlass Permission = "key.reveal_break_glass"

	// Targets and deployment
	PermTargetRead    Permission = "target.read"
	PermTargetWrite   Permission = "target.write"
	PermTargetDelete  Permission = "target.delete"
	PermDeployExecute Permission = "deploy.execute"
	PermDeployDryRun  Permission = "deploy.dry_run"
	PermReconcileRun  Permission = "reconcile.run"

	// Credentials used to reach targets
	PermCredentialRead   Permission = "credential.read"
	PermCredentialWrite  Permission = "credential.write"
	PermCredentialReveal Permission = "credential.reveal"

	// Rotation
	PermRotationRead    Permission = "rotation.read"
	PermRotationWrite   Permission = "rotation.write"
	PermRotationExecute Permission = "rotation.execute"
	PermRotationApprove Permission = "rotation.approve"
	PermRotationAbort   Permission = "rotation.abort"

	// Backup and rollback
	PermBackupRead    Permission = "backup.read"
	PermBackupCreate  Permission = "backup.create"
	PermBackupRestore Permission = "backup.restore"
	PermRollback      Permission = "changeset.rollback"

	// Jobs
	PermJobRead   Permission = "job.read"
	PermJobWrite  Permission = "job.write"
	PermJobCancel Permission = "job.cancel"

	// Audit
	PermAuditRead   Permission = "audit.read"
	PermAuditVerify Permission = "audit.verify"
	PermAuditExport Permission = "audit.export"

	// Vault lifecycle
	PermVaultStatus Permission = "vault.status"
	PermVaultSeal   Permission = "vault.seal"
	PermVaultUnseal Permission = "vault.unseal"
	PermVaultRotate Permission = "vault.rotate_kek"

	// Administration
	PermUserRead      Permission = "user.read"
	PermUserWrite     Permission = "user.write"
	PermRoleRead      Permission = "role.read"
	PermRoleWrite     Permission = "role.write"
	PermTokenRead     Permission = "api_token.read"
	PermTokenWrite    Permission = "api_token.write"
	PermWebhookRead   Permission = "webhook.read"
	PermWebhookWrite  Permission = "webhook.write"
	PermSettingsRead  Permission = "settings.read"
	PermSettingsWrite Permission = "settings.write"
)

// All lists every valid permission.
var All = []Permission{
	PermKeyRead, PermKeyWrite, PermKeyDelete, PermKeyRotate, PermKeyRevoke,
	PermKeyImport, PermKeyAdopt, PermKeyReveal, PermKeyRevealBreakGlass,
	PermTargetRead, PermTargetWrite, PermTargetDelete,
	PermDeployExecute, PermDeployDryRun, PermReconcileRun,
	PermCredentialRead, PermCredentialWrite, PermCredentialReveal,
	PermRotationRead, PermRotationWrite, PermRotationExecute,
	PermRotationApprove, PermRotationAbort,
	PermBackupRead, PermBackupCreate, PermBackupRestore, PermRollback,
	PermJobRead, PermJobWrite, PermJobCancel,
	PermAuditRead, PermAuditVerify, PermAuditExport,
	PermVaultStatus, PermVaultSeal, PermVaultUnseal, PermVaultRotate,
	PermUserRead, PermUserWrite, PermRoleRead, PermRoleWrite,
	PermTokenRead, PermTokenWrite, PermWebhookRead, PermWebhookWrite,
	PermSettingsRead, PermSettingsWrite,
}

var allSet = func() map[Permission]bool {
	m := make(map[Permission]bool, len(All))
	for _, p := range All {
		m[p] = true
	}
	return m
}()

// Valid reports whether p is a known permission.
func Valid(p Permission) bool { return allSet[p] }

// ParsePermission validates a permission string.
func ParsePermission(s string) (Permission, error) {
	p := Permission(strings.TrimSpace(s))
	if !Valid(p) {
		return "", fmt.Errorf("authz: unknown permission %q", s)
	}
	return p, nil
}

// Namespace returns the part before the first dot, used to group the admin UI.
func (p Permission) Namespace() string {
	ns, _, _ := strings.Cut(string(p), ".")
	return ns
}

func (p Permission) String() string { return string(p) }

// Sensitive reports whether a permission hands over secret material or can
// cause irreversible change. The API requires a recent MFA verification for
// these, and they are surfaced separately in the audit UI.
func (p Permission) Sensitive() bool {
	switch p {
	case PermKeyReveal, PermKeyRevealBreakGlass, PermCredentialReveal,
		PermKeyDelete, PermBackupRestore, PermRollback,
		PermVaultSeal, PermVaultUnseal, PermVaultRotate:
		return true
	}
	return false
}

// SystemRole is a built-in role that cannot be edited or deleted.
type SystemRole struct {
	Name        string
	Description string
	Permissions []Permission
}

// The seeded role names. Code that has to reason about a specific role — the
// "do not remove the last administrator" guard, for instance — refers to these
// rather than to a bare string.
const (
	RoleAdmin    = "admin"
	RoleEngineer = "engineer"
	RoleOperator = "operator"
	RoleAuditor  = "auditor"
	RoleViewer   = "viewer"
)

// SystemRoles are seeded on first boot.
//
// The split that matters is operator vs. engineer: an operator can run
// rotations and deployments that were already defined, but cannot reveal
// private keys or restore backups. That covers day-to-day work without handing
// out the crown jewels.
var SystemRoles = []SystemRole{
	{
		Name:        "admin",
		Description: "Full control, including private key reveal and vault administration.",
		Permissions: All,
	},
	{
		Name:        "engineer",
		Description: "Manage keys, targets, and rotations, including revealing private keys.",
		Permissions: []Permission{
			PermKeyRead, PermKeyWrite, PermKeyRotate, PermKeyRevoke, PermKeyImport,
			PermKeyAdopt, PermKeyReveal,
			PermTargetRead, PermTargetWrite,
			PermDeployExecute, PermDeployDryRun, PermReconcileRun,
			PermCredentialRead, PermCredentialWrite,
			PermRotationRead, PermRotationWrite, PermRotationExecute, PermRotationAbort,
			PermBackupRead, PermBackupCreate, PermRollback,
			PermJobRead, PermJobWrite, PermJobCancel,
			PermAuditRead, PermVaultStatus,
			PermTokenRead, PermTokenWrite, PermWebhookRead,
		},
	},
	{
		Name:        "operator",
		Description: "Run deployments and rotations that already exist; no access to private key material.",
		Permissions: []Permission{
			PermKeyRead, PermTargetRead,
			PermDeployExecute, PermDeployDryRun, PermReconcileRun,
			PermRotationRead, PermRotationExecute, PermRotationAbort,
			PermJobRead, PermJobWrite, PermJobCancel,
			PermBackupRead, PermAuditRead, PermVaultStatus,
		},
	},
	{
		Name:        "auditor",
		Description: "Read everything including the audit trail, and verify its integrity. Change nothing.",
		Permissions: []Permission{
			PermKeyRead, PermTargetRead, PermRotationRead, PermJobRead,
			PermBackupRead, PermCredentialRead,
			PermAuditRead, PermAuditVerify, PermAuditExport,
			PermVaultStatus, PermUserRead, PermRoleRead, PermTokenRead, PermWebhookRead,
			PermSettingsRead,
		},
	},
	{
		Name:        "viewer",
		Description: "Read-only view of keys, targets, and rotations.",
		Permissions: []Permission{
			PermKeyRead, PermTargetRead, PermRotationRead, PermJobRead, PermVaultStatus,
		},
	},
}

// PermissionStrings converts a permission slice for storage in a TEXT[] column.
func PermissionStrings(ps []Permission) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	sort.Strings(out)
	return out
}

// Permissions converts stored strings back into Permission values, dropping
// any that are not recognised.
//
// Dropping rather than erroring is the right behaviour here: an API token
// stored before a permission was renamed should lose that one capability, not
// stop authenticating altogether.
func Permissions(names []string) []Permission {
	out := make([]Permission, 0, len(names))
	for _, n := range names {
		p := Permission(n)
		if IsKnown(p) {
			out = append(out, p)
		}
	}
	return out
}

// knownPermissions indexes All for lookup.
var knownPermissions = func() map[Permission]bool {
	m := make(map[Permission]bool, len(All))
	for _, p := range All {
		m[p] = true
	}
	return m
}()

// IsKnown reports whether a permission string is one this build defines.
func IsKnown(p Permission) bool { return knownPermissions[p] }

// Group returns the resource a permission acts on, which is the part before
// the dot. The token editor uses it to lay the list out in sections instead of
// as one alphabetical wall.
func Group(p Permission) string {
	name := string(p)
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			return name[:i]
		}
	}
	return name
}
