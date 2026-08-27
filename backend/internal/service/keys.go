// Package service holds the application logic that coordinates the vault, the
// repositories, the connectors, and the audit log.
//
// Handlers stay thin: they parse, authorise, and call into here. Anything that
// touches private key material lives in this package so there is one place to
// review when asking "where can a private key escape?".
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/events"
	"github.com/hamalawy/ssh-key-manager/backend/internal/keys"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

// MFAWindow is how recently a subject must have completed a second factor
// before a sensitive operation is allowed.
const MFAWindow = 5 * time.Minute

// KeyService manages the lifecycle of managed keypairs.
type KeyService struct {
	keys        *store.Keys
	assignments *store.Assignments
	vault       *vault.Vault
	audit       *audit.Logger
	publisher   *events.Publisher
}

// SetPublisher attaches the event publisher.
//
// It is set after construction rather than passed in because the publisher's
// webhook sink needs the vault, and the vault is already a KeyService
// dependency — a constructor argument would make the wiring circular.
func (s *KeyService) SetPublisher(p *events.Publisher) { s.publisher = p }

// NewKeyService wires a KeyService.

// emit publishes an event when a publisher is attached. Every declared event
// type must actually be emitted somewhere, or a webhook subscribing to it
// silently never fires.
func (s *KeyService) emit(ctx context.Context, tenantID uuid.UUID, evType string, k *store.Key, data map[string]any) {
	if s.publisher == nil {
		return
	}
	s.publisher.Emit(ctx, tenantID, evType, "key", &k.ID, k.Name, data)
}

// NewKeyService wires a KeyService.
func NewKeyService(k *store.Keys, v *vault.Vault, a *audit.Logger) *KeyService {
	return &KeyService{keys: k, vault: v, audit: a}
}

// GenerateRequest describes a key to create.
type GenerateRequest struct {
	Name        string
	Description string
	Algorithm   string
	Comment     string
	Tags        []string
	KeyClass    string
	ValidFor    time.Duration
	// ParentKeyID and Generation are set by the rotation engine when creating a
	// successor key; left zero for a first-generation key.
	ParentKeyID *uuid.UUID
	Generation  int
}

// Generate creates a keypair, sealing the private half into the vault.
//
// The plaintext private key exists only inside this function and is zeroed
// before returning. It is never logged, never returned, and never written
// anywhere but the encrypted column.
func (s *KeyService) Generate(ctx context.Context, subject *authz.Subject, req GenerateRequest) (*store.Key, error) {
	if err := subject.Require(authz.PermKeyWrite); err != nil {
		s.denied(ctx, subject, audit.ActionKeyCreate, req.Name, err)
		return nil, err
	}
	if req.Name == "" {
		return nil, fmt.Errorf("service: a key name is required")
	}

	alg, err := keys.ParseAlgorithm(req.Algorithm)
	if err != nil {
		return nil, err
	}

	comment := req.Comment
	if comment == "" {
		comment = fmt.Sprintf("skm:%s", req.Name)
	}

	pair, err := keys.Generate(alg, comment)
	if err != nil {
		return nil, err
	}
	// The plaintext must not outlive this call.
	defer vault.Zero(pair.PrivatePEM)

	id := uuid.New()

	// The AAD binds the ciphertext to this key's identity, so material cannot
	// be transplanted onto another row and still decrypt.
	sealed, err := s.vault.Encrypt(pair.PrivatePEM, []byte(id.String()))
	if err != nil {
		return nil, fmt.Errorf("service: sealing private key: %w", err)
	}

	k := &store.Key{
		ID:            id,
		TenantID:      subject.TenantID,
		Name:          req.Name,
		Description:   req.Description,
		Algorithm:     string(alg),
		PublicKey:     pair.PublicLine,
		Fingerprint:   pair.Fingerprint,
		Comment:       comment,
		Status:        store.KeyStatusPending,
		KeyClass:      keyClassOrDefault(req.KeyClass),
		Generation:    max(req.Generation, 1),
		ParentKeyID:   req.ParentKeyID,
		OwnerID:       &subject.UserID,
		Tags:          req.Tags,
		HasPrivateKey: true,
		Compliant:     true,
		CreatedBy:     &subject.UserID,
	}
	if req.ValidFor > 0 {
		expires := time.Now().Add(req.ValidFor)
		k.ExpiresAt = &expires
	}

	created, err := s.keys.Create(ctx, k, sealed)
	if err != nil {
		return nil, err
	}

	s.log(ctx, subject, audit.Event{
		Action:       audit.ActionKeyCreate,
		ResourceType: "key",
		ResourceID:   &created.ID,
		ResourceName: created.Name,
		Detail: map[string]any{
			"algorithm":   created.Algorithm,
			"fingerprint": created.Fingerprint,
			"key_class":   created.KeyClass,
			"generation":  created.Generation,
		},
	})
	s.emit(ctx, subject.TenantID, events.TypeKeyCreated, created, map[string]any{
		"algorithm":   created.Algorithm,
		"fingerprint": created.Fingerprint,
		"generation":  created.Generation,
	})

	return created, nil
}

// Import registers an existing keypair.
func (s *KeyService) Import(ctx context.Context, subject *authz.Subject, name string, privatePEM []byte, passphrase string, tags []string) (*store.Key, error) {
	if err := subject.Require(authz.PermKeyImport); err != nil {
		s.denied(ctx, subject, audit.ActionKeyImport, name, err)
		return nil, err
	}

	pair, err := keys.ImportPrivateKey(privatePEM, passphrase)
	if err != nil {
		return nil, err
	}
	defer vault.Zero(pair.PrivatePEM)

	id := uuid.New()
	sealed, err := s.vault.Encrypt(pair.PrivatePEM, []byte(id.String()))
	if err != nil {
		return nil, fmt.Errorf("service: sealing imported key: %w", err)
	}

	// Imported keys are reported honestly: an undersized RSA key is registered
	// so it can be seen and rotated, but flagged as non-compliant.
	compliant, notes := assessCompliance(pair.Algorithm)

	k := &store.Key{
		ID:              id,
		TenantID:        subject.TenantID,
		Name:            name,
		Algorithm:       string(pair.Algorithm),
		PublicKey:       pair.PublicLine,
		Fingerprint:     pair.Fingerprint,
		Comment:         pair.Comment,
		Status:          store.KeyStatusActive,
		KeyClass:        store.KeyClassImported,
		Generation:      1,
		OwnerID:         &subject.UserID,
		Tags:            tags,
		HasPrivateKey:   true,
		Compliant:       compliant,
		ComplianceNotes: notes,
		CreatedBy:       &subject.UserID,
	}

	created, err := s.keys.Create(ctx, k, sealed)
	if err != nil {
		return nil, err
	}

	s.log(ctx, subject, audit.Event{
		Action:       audit.ActionKeyImport,
		ResourceType: "key",
		ResourceID:   &created.ID,
		ResourceName: created.Name,
		Detail: map[string]any{
			"algorithm":   created.Algorithm,
			"fingerprint": created.Fingerprint,
			"compliant":   compliant,
		},
	})
	s.emit(ctx, subject.TenantID, events.TypeKeyCreated, created, map[string]any{
		"algorithm":   created.Algorithm,
		"fingerprint": created.Fingerprint,
		"imported":    true,
		"compliant":   compliant,
	})
	return created, nil
}

// RevealResult carries private key material out of the vault.
type RevealResult struct {
	Key        *store.Key
	PrivatePEM []byte
}

// Reveal decrypts and returns a private key.
//
// This is the most sensitive operation in the product, and it is gated
// accordingly: a dedicated permission, a recent second factor, and an audit
// entry written before the material is returned. Break-glass keys need a
// further permission again, because they are the emergency access path.
//
// The audit entry is written first deliberately. If the log cannot be written
// the reveal does not happen, so there is no path by which key material leaves
// the vault unrecorded.
func (s *KeyService) Reveal(ctx context.Context, subject *authz.Subject, keyID uuid.UUID, reason string) (*RevealResult, error) {
	k, err := s.keys.Get(ctx, subject.TenantID, keyID)
	if err != nil {
		return nil, err
	}

	perm := authz.PermKeyReveal
	if k.KeyClass == store.KeyClassBreakGlass {
		perm = authz.PermKeyRevealBreakGlass
	}

	if err := subject.RequireFresh(perm, MFAWindow); err != nil {
		s.denied(ctx, subject, audit.ActionKeyReveal, k.Name, err)
		return nil, err
	}
	if !k.HasPrivateKey {
		return nil, fmt.Errorf("service: key %s has no stored private key", k.Name)
	}

	if _, err := s.audit.Log(ctx, audit.Event{
		TenantID:     subject.TenantID,
		ActorType:    audit.ActorUser,
		ActorID:      &subject.UserID,
		ActorName:    subject.Username,
		Action:       audit.ActionKeyReveal,
		ResourceType: "key",
		ResourceID:   &k.ID,
		ResourceName: k.Name,
		Detail: map[string]any{
			"fingerprint": k.Fingerprint,
			"key_class":   k.KeyClass,
			"reason":      reason,
		},
	}); err != nil {
		return nil, fmt.Errorf("service: refusing to reveal a key that cannot be audited: %w", err)
	}

	sealed, err := s.keys.LoadMaterial(ctx, k.ID)
	if err != nil {
		return nil, err
	}

	privatePEM, err := s.vault.Decrypt(sealed, []byte(k.ID.String()))
	if err != nil {
		return nil, fmt.Errorf("service: decrypting private key: %w", err)
	}

	return &RevealResult{Key: k, PrivatePEM: privatePEM}, nil
}

// PrivateKeyFor loads private key material for internal use — deploying,
// verifying, rotating — without the reveal permission or the MFA gate.
//
// This is not a back door around Reveal: the material never leaves the process,
// and the operations that call it write their own audit entries. Reveal exists
// for handing a key to a human, which is a different act entirely.
func (s *KeyService) PrivateKeyFor(ctx context.Context, tenantID, keyID uuid.UUID) ([]byte, error) {
	sealed, err := s.keys.LoadMaterial(ctx, keyID)
	if err != nil {
		return nil, err
	}
	plaintext, err := s.vault.Decrypt(sealed, []byte(keyID.String()))
	if err != nil {
		return nil, fmt.Errorf("service: decrypting private key: %w", err)
	}
	return plaintext, nil
}

// Revoke marks a key unusable and schedules its material for destruction.
//
// Revocation does not remove the key from targets: that requires reaching every
// one of them, which may fail. The key is marked so nothing new uses it, and
// the reconciler removes it as targets become reachable.
func (s *KeyService) Revoke(ctx context.Context, subject *authz.Subject, keyID uuid.UUID, compromised bool, reason string) (*store.Key, error) {
	if err := subject.Require(authz.PermKeyRevoke); err != nil {
		s.denied(ctx, subject, audit.ActionKeyRevoke, keyID.String(), err)
		return nil, err
	}

	k, err := s.keys.Get(ctx, subject.TenantID, keyID)
	if err != nil {
		return nil, err
	}

	status := store.KeyStatusRevoked
	if compromised {
		status = store.KeyStatusCompromised
	}

	updated, err := s.keys.SetStatus(ctx, subject.TenantID, keyID, status)
	if err != nil {
		return nil, err
	}

	s.log(ctx, subject, audit.Event{
		Action:       audit.ActionKeyRevoke,
		ResourceType: "key",
		ResourceID:   &k.ID,
		ResourceName: k.Name,
		Detail: map[string]any{
			"fingerprint": k.Fingerprint,
			"compromised": compromised,
			"reason":      reason,
		},
	})
	s.emit(ctx, subject.TenantID, events.TypeKeyRevoked, updated, map[string]any{
		"fingerprint": k.Fingerprint,
		"compromised": compromised,
		"reason":      reason,
	})
	return updated, nil
}

// Get returns a key, checking read permission.
func (s *KeyService) Get(ctx context.Context, subject *authz.Subject, id uuid.UUID) (*store.Key, error) {
	if err := subject.Require(authz.PermKeyRead); err != nil {
		return nil, err
	}
	return s.keys.Get(ctx, subject.TenantID, id)
}

// List returns keys matching a filter, checking read permission.
func (s *KeyService) List(ctx context.Context, subject *authz.Subject, f store.KeyFilter) ([]store.Key, error) {
	if err := subject.Require(authz.PermKeyRead); err != nil {
		return nil, err
	}
	f.TenantID = subject.TenantID
	return s.keys.List(ctx, f)
}

// Update changes a key's metadata.
func (s *KeyService) Update(ctx context.Context, subject *authz.Subject, id uuid.UUID, name, description string, tags []string, expiresAt *time.Time) (*store.Key, error) {
	if err := subject.Require(authz.PermKeyWrite); err != nil {
		return nil, err
	}
	return s.keys.Update(ctx, subject.TenantID, id, name, description, tags, expiresAt)
}

// SetStatus moves a key through its lifecycle.
func (s *KeyService) SetStatus(ctx context.Context, subject *authz.Subject, id uuid.UUID, status string) (*store.Key, error) {
	if err := subject.Require(authz.PermKeyWrite); err != nil {
		return nil, err
	}
	return s.keys.SetStatus(ctx, subject.TenantID, id, status)
}

// RotateKEK rewraps every key's data encryption key under the current KEK.
//
// The secret ciphertexts are never touched, so this is cheap regardless of how
// much material is stored. It is resumable: rewrapping is idempotent, so a run
// interrupted halfway can simply be started again.
func (s *KeyService) RotateKEK(ctx context.Context, subject *authz.Subject) (int, error) {
	if err := subject.RequireFresh(authz.PermVaultRotate, MFAWindow); err != nil {
		s.denied(ctx, subject, audit.ActionKEKRotate, "vault", err)
		return 0, err
	}

	current := s.vault.CurrentVersion()
	if current == 0 {
		return 0, vault.ErrSealed
	}

	var rewrapped int
	for {
		batch, err := s.keys.MaterialNeedingRewrap(ctx, current, 100)
		if err != nil {
			return rewrapped, err
		}
		if len(batch) == 0 {
			break
		}

		for _, keyID := range batch {
			sealed, err := s.keys.LoadMaterial(ctx, keyID)
			if err != nil {
				return rewrapped, err
			}
			fresh, err := s.vault.Rewrap(sealed, []byte(keyID.String()))
			if err != nil {
				return rewrapped, fmt.Errorf("service: rewrapping key %s: %w", keyID, err)
			}
			if err := s.keys.StoreMaterial(ctx, keyID, fresh); err != nil {
				return rewrapped, err
			}
			rewrapped++
		}
	}

	s.log(ctx, subject, audit.Event{
		Action:       audit.ActionKEKRotate,
		ResourceType: "vault",
		ResourceName: "vault",
		Detail:       map[string]any{"kek_version": current, "keys_rewrapped": rewrapped},
	})
	return rewrapped, nil
}

// log writes an audit event, defaulting the actor from the subject.
//
// Failures are swallowed here because these are informational records written
// after the fact. Where the audit entry is itself the control — Reveal — the
// error is checked explicitly instead.
func (s *KeyService) log(ctx context.Context, subject *authz.Subject, ev audit.Event) {
	ev.TenantID = subject.TenantID
	ev.ActorType = audit.ActorUser
	ev.ActorID = &subject.UserID
	ev.ActorName = subject.Username
	_, _ = s.audit.Log(ctx, ev)
}

// denied records a rejected authorisation attempt.
func (s *KeyService) denied(ctx context.Context, subject *authz.Subject, action, resource string, reason error) {
	if subject == nil {
		return
	}
	_, _ = s.audit.Log(ctx, audit.Event{
		TenantID:     subject.TenantID,
		ActorType:    audit.ActorUser,
		ActorID:      &subject.UserID,
		ActorName:    subject.Username,
		Action:       action,
		ResourceName: resource,
		Outcome:      audit.OutcomeDenied,
		Detail:       map[string]any{"reason": reason.Error()},
	})
}

func keyClassOrDefault(class string) string {
	switch class {
	case store.KeyClassBreakGlass, store.KeyClassDiscovered, store.KeyClassImported:
		return class
	default:
		return store.KeyClassStandard
	}
}

// assessCompliance reports whether an algorithm meets current policy.
func assessCompliance(alg keys.Algorithm) (bool, string) {
	if alg.Valid() {
		return true, ""
	}
	// Anything not generable reached the system by import: undersized RSA and
	// legacy types land here.
	return false, fmt.Sprintf("%s is below the current security floor; rotate onto ed25519 or rsa-3072 and above", alg)
}

// ErrSealed is re-exported so handlers can map it to a 503 without importing
// the vault package.
var ErrSealed = vault.ErrSealed

// IsNotFound reports whether an error means a row was missing.
func IsNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }

// IsConflict reports whether an error means a uniqueness constraint failed.
func IsConflict(err error) bool { return errors.Is(err, store.ErrConflict) }

// ErrKeyDeployed refuses a destructive key operation while the key is still
// assigned somewhere. It is a 409, not a 500: the caller can fix it.
var ErrKeyDeployed = errors.New("service: key is still deployed")

// SetAssignments lets the service see where a key is deployed.
//
// Only Delete needs it, and only to refuse: without it the service would have
// to accept "delete this key" on faith and discover the deployments through a
// foreign-key error, by which point the private key is already gone.
func (s *KeyService) SetAssignments(a *store.Assignments) { s.assignments = a }

// Delete removes a key and shreds its private material.
//
// This is irreversible in the strongest sense the product offers: the private
// half is destroyed, so the key cannot be redeployed, cannot be rotated, and
// cannot authenticate anywhere it is still installed. It is therefore refused
// while any assignment still points at the key. Revoke first, retire the
// deployments, then delete — the same order a careful operator would use
// anyway, made mandatory so that a hurried one gets it too.
func (s *KeyService) Delete(ctx context.Context, subject *authz.Subject, id uuid.UUID) error {
	if err := subject.Require(authz.PermKeyDelete); err != nil {
		s.denied(ctx, subject, audit.ActionKeyDestroy, id.String(), err)
		return err
	}

	key, err := s.keys.Get(ctx, subject.TenantID, id)
	if err != nil {
		return err
	}
	if err := subject.RequireScoped(authz.PermKeyDelete, key.Tags); err != nil {
		return err
	}

	if s.assignments != nil {
		existing, err := s.assignments.List(ctx, store.AssignmentFilter{
			TenantID: subject.TenantID, KeyID: &id,
		})
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			where := make([]string, 0, len(existing))
			for _, a := range existing {
				where = append(where, a.TargetName+":"+a.Username)
			}
			return fmt.Errorf("%w: still assigned to %d place(s): %v — remove the assignments first",
				ErrKeyDeployed, len(existing), where)
		}
	}

	if err := s.keys.DestroyMaterial(ctx, subject.TenantID, id); err != nil {
		return err
	}
	if err := s.keys.Delete(ctx, subject.TenantID, id); err != nil {
		return err
	}

	s.log(ctx, subject, audit.Event{
		TenantID: subject.TenantID, Action: audit.ActionKeyDestroy,
		ResourceType: "key", ResourceID: &id, ResourceName: key.Name,
		Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"fingerprint": key.Fingerprint, "status": key.Status,
		},
	})
	s.emit(ctx, subject.TenantID, events.TypeKeyRevoked, key,
		map[string]any{"event": "deleted"})
	return nil
}
