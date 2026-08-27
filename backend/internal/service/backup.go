package service

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/backup"
	"github.com/hamalawy/ssh-key-manager/backend/internal/events"
	"github.com/hamalawy/ssh-key-manager/backend/internal/keys"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

// BackupService exports and restores the vault.
//
// The export is the only bulk path by which private key material leaves the
// system, so it is gated like a reveal and audited like one. It is also the
// only path that has to keep working when everything else has failed, which is
// why the archive format is self-describing and independent of this instance's
// master key.
type BackupService struct {
	backups     *store.Backups
	keys        *store.Keys
	targets     *store.Targets
	assignments *store.Assignments
	consumers   *store.Consumers
	rotations   *store.Rotations
	keySvc      *KeyService
	vault       *vault.Vault
	audit       *audit.Logger
	publisher   *events.Publisher
	log         *slog.Logger

	// dir is where archives are written. Everything is confined to it, so a
	// crafted name cannot write outside the backup directory.
	dir string
}

// BackupDeps bundles what a BackupService needs.
type BackupDeps struct {
	Backups     *store.Backups
	Keys        *store.Keys
	Targets     *store.Targets
	Assignments *store.Assignments
	Consumers   *store.Consumers
	Rotations   *store.Rotations
	KeyService  *KeyService
	Vault       *vault.Vault
	Audit       *audit.Logger
	Publisher   *events.Publisher
	Logger      *slog.Logger
	Directory   string
}

// NewBackupService wires a BackupService.
func NewBackupService(d BackupDeps) *BackupService {
	dir := d.Directory
	if dir == "" {
		dir = "/var/lib/skm/backups"
	}
	return &BackupService{
		backups: d.Backups, keys: d.Keys, targets: d.Targets,
		assignments: d.Assignments, consumers: d.Consumers, rotations: d.Rotations,
		keySvc: d.KeyService, vault: d.Vault, audit: d.Audit,
		publisher: d.Publisher, log: d.Logger, dir: dir,
	}
}

// CreateRequest describes an export.
type CreateRequest struct {
	Name string
	Kind string
	// Passphrase encrypts the archive. It is never stored.
	Passphrase string
	// RetainFor sets the archive's expiry, after which the pruning job
	// removes it.
	RetainFor time.Duration
}

// BackupMFAWindow is how recently a second factor must have been verified to
// export or restore an archive.
//
// Longer than the reveal window on purpose. Revealing a key is one click;
// taking a backup means choosing a name, a kind, a retention, and typing a
// passphrase twice, and a window that expires mid-form teaches people to
// verify, fail, verify again — which is worse for security than the extra ten
// minutes, because it makes the prompt something to click through rather than
// something to think about.
const BackupMFAWindow = 15 * time.Minute

// Create exports the vault to an encrypted archive.
func (s *BackupService) Create(ctx context.Context, subject *authz.Subject, req CreateRequest) (*store.Backup, error) {
	if err := subject.Require(authz.PermBackupCreate); err != nil {
		return nil, err
	}
	// An export of every private key is a reveal of every private key. Gating
	// it on the backup permission alone would be a way around the reveal gate.
	if req.Kind != store.BackupMetadata {
		if err := subject.RequireFresh(authz.PermKeyReveal, BackupMFAWindow); err != nil {
			s.recordDenied(ctx, subject, req.Name, err)
			// The bare gate names key.reveal, which reads as a non sequitur to
			// someone who asked for a backup. Say what is actually happening.
			return nil, fmt.Errorf("%w — this archive contains every private key, "+
				"so it is gated like revealing one. Verify your second factor, "+
				"then try again", err)
		}
	}
	if len(req.Passphrase) < 12 {
		return nil, fmt.Errorf("service: the backup passphrase must be at least 12 characters; " +
			"this archive holds every private key SKM manages")
	}

	name := req.Name
	if name == "" {
		name = "skm-" + time.Now().UTC().Format("20060102-150405")
	}
	safe := safeFilename(name)
	if safe == "" {
		return nil, fmt.Errorf("service: %q is not a usable backup name", name)
	}

	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("service: preparing the backup directory: %w", err)
	}

	path := filepath.Join(s.dir, safe+".skmbak")

	var expires *time.Time
	if req.RetainFor > 0 {
		t := time.Now().Add(req.RetainFor)
		expires = &t
	}

	record, err := s.backups.Create(ctx, &store.Backup{
		TenantID:  subject.TenantID,
		Name:      name,
		Kind:      orString(req.Kind, store.BackupFull),
		Location:  path,
		State:     store.BackupRunning,
		ExpiresAt: expires,
		CreatedBy: &subject.UserID,
	})
	if err != nil {
		return nil, err
	}

	payload, err := s.buildPayload(ctx, subject, record.Kind)
	if err != nil {
		_ = s.backups.Fail(ctx, record.ID, err)
		return nil, err
	}
	defer zeroPayload(payload)

	checksum, size, err := s.writeArchive(path, req.Passphrase, record.Kind, payload)
	if err != nil {
		_ = s.backups.Fail(ctx, record.ID, err)
		return nil, err
	}

	if err := s.backups.Complete(ctx, record.ID, size, checksum, len(payload.Keys)); err != nil {
		return nil, err
	}

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionBackupCreate,
		ResourceType: "backup",
		ResourceID:   &record.ID,
		ResourceName: name,
		Outcome:      audit.OutcomeSuccess,
		Detail: map[string]any{
			"kind": record.Kind, "keys": len(payload.Keys),
			"size_bytes": size, "location": path,
		},
	})
	s.publisher.Emit(ctx, subject.TenantID, events.TypeBackupCompleted, "backup",
		&record.ID, name, map[string]any{"keys": len(payload.Keys), "size_bytes": size})

	return s.backups.Get(ctx, subject.TenantID, record.ID)
}

// writeArchive writes to a temporary file and renames, so a crash never leaves
// a truncated archive that looks restorable.
func (s *BackupService) writeArchive(path, passphrase, kind string, payload *backup.Payload) (string, int64, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".skmbak-*")
	if err != nil {
		return "", 0, fmt.Errorf("service: creating the archive: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return "", 0, fmt.Errorf("service: restricting permissions on the archive: %w", err)
	}

	checksum, size, err := backup.Write(tmp, passphrase, kind, "skm", payload)
	if err != nil {
		return "", 0, err
	}
	if err := tmp.Sync(); err != nil {
		return "", 0, fmt.Errorf("service: flushing the archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", 0, fmt.Errorf("service: closing the archive: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", 0, fmt.Errorf("service: moving the archive into place: %w", err)
	}

	return checksum, size, nil
}

// buildPayload gathers everything the archive carries.
func (s *BackupService) buildPayload(ctx context.Context, subject *authz.Subject, kind string) (*backup.Payload, error) {
	payload := &backup.Payload{ExportedAt: time.Now().UTC()}

	allKeys, err := s.keys.List(ctx, store.KeyFilter{TenantID: subject.TenantID, Limit: 5000})
	if err != nil {
		return nil, err
	}

	for i := range allKeys {
		k := &allKeys[i]
		rec := backup.KeyRecord{
			ID: k.ID.String(), Name: k.Name, Description: k.Description,
			Algorithm: k.Algorithm, PublicKey: k.PublicKey, Fingerprint: k.Fingerprint,
			Comment: k.Comment, Status: k.Status, KeyClass: k.KeyClass,
			Generation: k.Generation, Tags: k.Tags,
			CreatedAt: k.CreatedAt.Format(time.RFC3339),
		}
		if k.ParentKeyID != nil {
			rec.ParentKeyID = k.ParentKeyID.String()
		}
		if k.ExpiresAt != nil {
			rec.ExpiresAt = k.ExpiresAt.Format(time.RFC3339)
		}

		if kind != store.BackupMetadata && k.HasPrivateKey {
			private, err := s.keySvc.PrivateKeyFor(ctx, subject.TenantID, k.ID)
			if err != nil {
				return nil, fmt.Errorf("service: reading the private half of %q for export: %w", k.Name, err)
			}
			rec.PrivatePEM = string(private)
			vault.Zero(private)
		}

		payload.Keys = append(payload.Keys, rec)
	}

	if kind == store.BackupKeysOnly {
		return payload, nil
	}

	targets, err := s.targets.List(ctx, store.TargetFilter{TenantID: subject.TenantID, Limit: 5000})
	if err != nil {
		return nil, err
	}
	for i := range targets {
		t := &targets[i]
		rec := backup.TargetRecord{
			ID: t.ID.String(), Name: t.Name, Kind: t.Kind, Connector: t.Connector,
			Address: t.Address, Port: t.Port, Config: t.Config,
			HostKeyPin: t.HostKeyPin, Tags: t.Tags,
		}
		principals, err := s.targets.ListPrincipals(ctx, t.ID)
		if err == nil {
			for _, p := range principals {
				rec.Principals = append(rec.Principals, p.Username)
			}
		}
		payload.Targets = append(payload.Targets, rec)
	}

	assignments, err := s.assignments.List(ctx, store.AssignmentFilter{
		TenantID: subject.TenantID, Limit: 5000,
	})
	if err != nil {
		return nil, err
	}
	for _, a := range assignments {
		payload.Assignments = append(payload.Assignments, backup.AssignmentRecord{
			KeyFingerprint: a.KeyFingerprint, TargetName: a.TargetName,
			Username: a.Username, Options: a.Options, DesiredState: a.DesiredState,
		})
	}

	sinks, err := s.consumers.List(ctx, subject.TenantID, nil)
	if err != nil {
		return nil, err
	}
	byID := map[uuid.UUID]string{}
	for i := range allKeys {
		byID[allKeys[i].ID] = allKeys[i].Fingerprint
	}
	for _, c := range sinks {
		payload.Consumers = append(payload.Consumers, backup.ConsumerRecord{
			Name: c.Name, Kind: c.Kind, KeyFingerprint: byID[c.KeyID],
			Config: c.Config, Enabled: c.Enabled,
		})
	}

	policies, err := s.rotations.ListPolicies(ctx, subject.TenantID)
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		payload.Policies = append(payload.Policies, backup.PolicyRecord{
			Name: p.Name, Enabled: p.Enabled, CronExpr: p.CronExpr,
			MaxAgeSeconds: p.MaxAgeSec, Algorithm: p.Algorithm,
			SoakSeconds: p.SoakPeriodSec, CanaryPercent: p.CanaryPercent,
			FailureThreshold: p.FailureThreshold, ApprovalRequired: p.ApprovalRequired,
			KeyTags: p.Selector.KeyTags, TargetTags: p.Selector.TargetTags,
			KeyClass: p.Selector.KeyClass,
		})
	}

	return payload, nil
}

// VerifyResult reports what an archive contains and whether it is readable.
type VerifyResult struct {
	Location    string    `json:"location"`
	Kind        string    `json:"kind"`
	CreatedAt   time.Time `json:"created_at"`
	KeyCount    int       `json:"key_count"`
	TargetCount int       `json:"target_count"`
	// KeysDecrypted counts private keys that parsed back into usable keypairs.
	KeysDecrypted int      `json:"keys_decrypted"`
	Problems      []string `json:"problems,omitempty"`
	Valid         bool     `json:"valid"`
}

// Verify proves an archive is restorable without restoring it.
//
// "The backup ran" and "the backup can be restored" are different claims, and
// only the second one matters at 3am. This decrypts the archive and re-parses
// every private key, then throws the result away.
func (s *BackupService) Verify(ctx context.Context, subject *authz.Subject, backupID uuid.UUID, passphrase string) (*VerifyResult, error) {
	if err := subject.Require(authz.PermBackupRead); err != nil {
		return nil, err
	}

	record, err := s.backups.Get(ctx, subject.TenantID, backupID)
	if err != nil {
		return nil, err
	}

	result, err := s.VerifyFile(ctx, record.Location, passphrase)
	if err != nil {
		return nil, err
	}

	if result.Valid {
		if err := s.backups.MarkVerified(ctx, backupID); err != nil {
			s.log.Warn("marking a backup verified", "backup", backupID, "error", err)
		}
	}

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionBackupVerify,
		ResourceType: "backup",
		ResourceID:   &backupID,
		ResourceName: record.Name,
		Outcome:      outcomeFor(result.Valid),
		Detail: map[string]any{
			"keys": result.KeyCount, "keys_decrypted": result.KeysDecrypted,
			"problems": result.Problems,
		},
	})

	return result, nil
}

// VerifyFile checks an archive on disk.
func (s *BackupService) VerifyFile(ctx context.Context, path, passphrase string) (*VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("service: opening the archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	header, payload, err := backup.Read(f, passphrase)
	if err != nil {
		return nil, err
	}

	result := &VerifyResult{
		Location:    path,
		Kind:        header.Kind,
		CreatedAt:   header.CreatedAt,
		KeyCount:    len(payload.Keys),
		TargetCount: len(payload.Targets),
	}

	for i := range payload.Keys {
		rec := &payload.Keys[i]
		if rec.PrivatePEM == "" {
			if header.Kind != store.BackupMetadata {
				result.Problems = append(result.Problems,
					fmt.Sprintf("%s has no private key in the archive", rec.Name))
			}
			continue
		}

		pair, err := keys.ImportPrivateKey([]byte(rec.PrivatePEM), "")
		if err != nil {
			result.Problems = append(result.Problems,
				fmt.Sprintf("%s: the private key does not parse: %v", rec.Name, err))
			continue
		}
		if pair.Fingerprint != rec.Fingerprint {
			result.Problems = append(result.Problems, fmt.Sprintf(
				"%s: the private key does not match the recorded fingerprint (%s vs %s)",
				rec.Name, pair.Fingerprint, rec.Fingerprint))
			continue
		}
		result.KeysDecrypted++
	}

	zeroPayload(payload)
	result.Valid = len(result.Problems) == 0
	return result, nil
}

// RestoreResult reports what a restore did.
type RestoreResult struct {
	KeysRestored int      `json:"keys_restored"`
	KeysSkipped  int      `json:"keys_skipped"`
	Problems     []string `json:"problems,omitempty"`
}

// Restore imports an archive into this instance.
//
// Keys are re-sealed under *this* instance's master key, which is what makes
// restoring into a fresh install work. Existing keys are skipped rather than
// overwritten: a restore that silently replaced a live key with an older copy
// of itself would be a way to reintroduce a revoked key.
func (s *BackupService) Restore(ctx context.Context, subject *authz.Subject, path, passphrase string) (*RestoreResult, error) {
	if err := subject.Require(authz.PermBackupRestore); err != nil {
		return nil, err
	}
	if err := subject.RequireFresh(authz.PermKeyReveal, BackupMFAWindow); err != nil {
		s.recordDenied(ctx, subject, path, err)
		return nil, fmt.Errorf("%w — restoring writes private keys back into this "+
			"install, so it is gated like revealing one. Verify your second factor, "+
			"then try again", err)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("service: opening the archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	header, payload, err := backup.Read(f, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroPayload(payload)

	result := &RestoreResult{}

	for i := range payload.Keys {
		rec := &payload.Keys[i]

		if existing, err := s.keys.GetByFingerprint(ctx, subject.TenantID, rec.Fingerprint); err == nil {
			result.KeysSkipped++
			s.log.Info("skipping a key already present", "name", existing.Name,
				"fingerprint", rec.Fingerprint)
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}

		id := uuid.New()
		var sealed *vault.Sealed

		if rec.PrivatePEM != "" {
			private := []byte(rec.PrivatePEM)
			sealed, err = s.vault.Encrypt(private, []byte(id.String()))
			vault.Zero(private)
			if err != nil {
				result.Problems = append(result.Problems,
					fmt.Sprintf("%s: could not be sealed: %v", rec.Name, err))
				continue
			}
		}

		k := &store.Key{
			ID: id, TenantID: subject.TenantID,
			Name:        uniqueName(ctx, s.keys, subject.TenantID, rec.Name),
			Description: rec.Description, Algorithm: rec.Algorithm,
			PublicKey: rec.PublicKey, Fingerprint: rec.Fingerprint,
			Comment: rec.Comment, Status: rec.Status, KeyClass: rec.KeyClass,
			Generation: max(rec.Generation, 1), Tags: rec.Tags,
			HasPrivateKey: sealed != nil, Compliant: true,
			OwnerID: &subject.UserID, CreatedBy: &subject.UserID,
		}

		if _, err := s.keys.Create(ctx, k, sealed); err != nil {
			result.Problems = append(result.Problems, fmt.Sprintf("%s: %v", rec.Name, err))
			continue
		}
		result.KeysRestored++
	}

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionBackupRestor,
		ResourceType: "backup",
		ResourceName: filepath.Base(path),
		Outcome:      outcomeFor(len(result.Problems) == 0),
		Detail: map[string]any{
			"archive_created_at": header.CreatedAt,
			"keys_restored":      result.KeysRestored,
			"keys_skipped":       result.KeysSkipped,
			"problems":           result.Problems,
		},
	})

	return result, nil
}

// List returns backup records.
func (s *BackupService) List(ctx context.Context, subject *authz.Subject, limit int) ([]store.Backup, error) {
	if err := subject.Require(authz.PermBackupRead); err != nil {
		return nil, err
	}
	return s.backups.List(ctx, subject.TenantID, limit)
}

// Delete removes an archive and its record.
func (s *BackupService) Delete(ctx context.Context, subject *authz.Subject, id uuid.UUID) error {
	if err := subject.Require(authz.PermBackupCreate); err != nil {
		return err
	}

	record, err := s.backups.Get(ctx, subject.TenantID, id)
	if err != nil {
		return err
	}
	// Only remove files this service wrote; the location column is not a
	// general-purpose delete instruction.
	if strings.HasPrefix(record.Location, s.dir) {
		if err := os.Remove(record.Location); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("service: removing the archive: %w", err)
		}
	}
	return s.backups.Delete(ctx, subject.TenantID, id)
}

// PruneExpired removes archives past their retention date.
func (s *BackupService) PruneExpired(ctx context.Context) (int, error) {
	expired, err := s.backups.Expired(ctx, time.Now())
	if err != nil {
		return 0, err
	}

	var removed int
	for _, b := range expired {
		if strings.HasPrefix(b.Location, s.dir) {
			if err := os.Remove(b.Location); err != nil && !os.IsNotExist(err) {
				s.log.Warn("removing an expired archive", "backup", b.Name, "error", err)
				continue
			}
		}
		if err := s.backups.Delete(ctx, b.TenantID, b.ID); err != nil {
			s.log.Warn("deleting an expired backup record", "backup", b.Name, "error", err)
			continue
		}
		removed++
	}
	return removed, nil
}

// Directory reports where archives are written.
func (s *BackupService) Directory() string { return s.dir }

func (s *BackupService) record(ctx context.Context, subject *authz.Subject, ev audit.Event) {
	ev.TenantID = subject.TenantID
	ev.ActorType = audit.ActorUser
	ev.ActorID = &subject.UserID
	ev.ActorName = subject.Username
	if _, err := s.audit.Log(ctx, ev); err != nil {
		s.log.Error("writing audit event", "action", ev.Action, "error", err)
	}
}

func (s *BackupService) recordDenied(ctx context.Context, subject *authz.Subject, name string, cause error) {
	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionPermDenied,
		ResourceType: "backup",
		ResourceName: name,
		Outcome:      audit.OutcomeDenied,
		Detail:       map[string]any{"reason": cause.Error()},
	})
}

func outcomeFor(ok bool) audit.Outcome {
	if ok {
		return audit.OutcomeSuccess
	}
	return audit.OutcomeFailure
}

// zeroPayload wipes private key material from a decoded payload.
//
// Go strings are immutable, so this cannot scrub the original bytes; it clears
// the references so the material is collectable rather than pinned for the life
// of the request. The genuinely sensitive buffers — the ones handed to the
// vault — are []byte and are zeroed properly.
func zeroPayload(p *backup.Payload) {
	if p == nil {
		return
	}
	for i := range p.Keys {
		p.Keys[i].PrivatePEM = ""
	}
}

// safeFilename reduces a name to something that cannot escape the backup
// directory or collide with a dotfile.
func safeFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), ".-")
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

// uniqueName avoids a name collision on restore without silently merging two
// different keys under one name.
func uniqueName(ctx context.Context, keyStore *store.Keys, tenantID uuid.UUID, name string) string {
	candidate := name
	for i := 1; i < 100; i++ {
		found, err := keyStore.List(ctx, store.KeyFilter{TenantID: tenantID, Search: candidate, Limit: 50})
		if err != nil {
			return candidate
		}
		clash := false
		for _, k := range found {
			if k.Name == candidate {
				clash = true
				break
			}
		}
		if !clash {
			return candidate
		}
		candidate = fmt.Sprintf("%s-restored-%d", name, i)
	}
	return name + "-restored-" + hex.EncodeToString([]byte(uuid.New().String()[:4]))
}
