package service

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/shamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/shamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/shamalawy/ssh-key-manager/backend/internal/consumers"
	"github.com/shamalawy/ssh-key-manager/backend/internal/store"
	"github.com/shamalawy/ssh-key-manager/backend/internal/vault"
)

// ConsumerService hands private keys to the systems that use them.
//
// It is the only path other than an explicit reveal by which private key
// material leaves the vault, so it carries the same discipline: the plaintext
// exists for the length of one delivery, is zeroed afterwards, and every
// delivery is audited whether it succeeded or not.
type ConsumerService struct {
	consumers *store.Consumers
	keys      *store.Keys
	keySvc    *KeyService
	registry  *consumers.Registry
	audit     *audit.Logger
	log       *slog.Logger

	// Set when this build can deliver to a machine over SSH. Optional so a
	// ConsumerService can still be wired without the target side of the world.
	targets     *store.Targets
	credentials *store.Credentials
	vault       *vault.Vault
}

// NewConsumerService wires a ConsumerService.
func NewConsumerService(c *store.Consumers, k *store.Keys, keySvc *KeyService, reg *consumers.Registry, a *audit.Logger, log *slog.Logger) *ConsumerService {
	return &ConsumerService{consumers: c, keys: k, keySvc: keySvc, registry: reg, audit: a, log: log}
}

// WithRemoteDelivery lets consumers deliver to machines SKM already knows.
//
// It is separate from the constructor because delivering to a host needs the
// target and credential stores, and a ConsumerService that only writes to Vault
// or a local path has no business holding them.
func (s *ConsumerService) WithRemoteDelivery(t *store.Targets, c *store.Credentials, v *vault.Vault) *ConsumerService {
	s.targets, s.credentials, s.vault = t, c, v
	return s
}

// remoteFor resolves the machine a consumer delivers to.
//
// Returns nil when the consumer names no target, which is the normal case: only
// the ssh_file sink needs one, and it reports its own error if it is missing.
func (s *ConsumerService) remoteFor(ctx context.Context, tenantID uuid.UUID, c *store.Consumer) (*consumers.RemoteHost, error) {
	raw, _ := c.Config["target_id"].(string)
	if raw == "" {
		return nil, nil
	}
	if s.targets == nil || s.credentials == nil || s.vault == nil {
		return nil, fmt.Errorf("service: this build cannot deliver to a machine")
	}

	targetID, err := uuid.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("service: consumer %q has an unreadable target_id: %w", c.Name, err)
	}
	target, err := s.targets.Get(ctx, tenantID, targetID)
	if err != nil {
		return nil, err
	}

	remote := &consumers.RemoteHost{
		Address:    target.Address,
		Port:       target.Port,
		HostKeyPin: target.HostKeyPin,
	}
	if u, ok := c.Config["username"].(string); ok && u != "" {
		remote.Username = u
	}
	if sudo, ok := c.Config["use_sudo"].(bool); ok {
		remote.UseSudo = sudo
	}

	if target.CredentialID == nil {
		return nil, fmt.Errorf("service: %s has no credential, so SKM cannot sign in to write the key", target.Name)
	}
	meta, err := s.credentials.Get(ctx, tenantID, *target.CredentialID)
	if err != nil {
		return nil, err
	}
	if remote.Username == "" {
		remote.Username = meta.Username
	}

	// A credential may point at a managed key rather than holding a secret.
	if meta.KeyID != nil {
		priv, err := s.keySvc.PrivateKeyFor(ctx, tenantID, *meta.KeyID)
		if err != nil {
			return nil, fmt.Errorf("service: loading the key behind credential %q: %w", meta.Name, err)
		}
		remote.PrivateKey = priv
		return remote, nil
	}
	if !meta.HasSecret {
		return nil, fmt.Errorf("service: credential %q holds no secret", meta.Name)
	}

	sealed, err := s.credentials.LoadSecret(ctx, tenantID, meta.ID)
	if err != nil {
		return nil, err
	}
	plaintext, err := s.vault.Decrypt(sealed, []byte(meta.ID.String()))
	if err != nil {
		return nil, fmt.Errorf("service: decrypting credential %q: %w", meta.Name, err)
	}
	if meta.Kind == store.CredSSHKey {
		remote.PrivateKey = plaintext
	} else {
		remote.Password = string(plaintext)
		vault.Zero(plaintext)
	}
	return remote, nil
}

// Create registers a private-key sink.
func (s *ConsumerService) Create(ctx context.Context, subject *authz.Subject, c *store.Consumer) (*store.Consumer, error) {
	// Writing a consumer is effectively arranging for a private key to be
	// copied somewhere, so it is gated on the reveal permission rather than on
	// a weaker "config" one.
	if err := subject.Require(authz.PermKeyReveal); err != nil {
		return nil, err
	}
	if _, err := s.registry.Get(c.Kind); err != nil {
		return nil, err
	}

	key, err := s.keys.Get(ctx, subject.TenantID, c.KeyID)
	if err != nil {
		return nil, err
	}
	if !subject.InScope(key.Tags) {
		return nil, fmt.Errorf("%w: key %s", authz.ErrOutOfScope, key.Name)
	}

	c.TenantID = subject.TenantID
	created, err := s.consumers.Create(ctx, c)
	if err != nil {
		return nil, err
	}

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionConsumerAdd,
		ResourceType: "consumer",
		ResourceID:   &created.ID,
		ResourceName: created.Name,
		Outcome:      audit.OutcomeSuccess,
		Detail:       map[string]any{"kind": created.Kind, "key": key.Name},
	})
	return created, nil
}

// List returns the configured sinks.
func (s *ConsumerService) List(ctx context.Context, subject *authz.Subject, keyID *uuid.UUID) ([]store.Consumer, error) {
	if err := subject.Require(authz.PermKeyRead); err != nil {
		return nil, err
	}
	return s.consumers.List(ctx, subject.TenantID, keyID)
}

// Delete removes a sink.
func (s *ConsumerService) Delete(ctx context.Context, subject *authz.Subject, id uuid.UUID) error {
	if err := subject.Require(authz.PermKeyReveal); err != nil {
		return err
	}
	return s.consumers.Delete(ctx, subject.TenantID, id)
}

// Rebind points a consumer at a new key and delivers it.
//
// The order matters: deliver first, record second. A consumer recorded as
// holding a key it never received would let a rotation retire the old one and
// break it.
func (s *ConsumerService) Rebind(ctx context.Context, subject *authz.Subject, consumerID, keyID uuid.UUID) error {
	c, err := s.consumers.Get(ctx, subject.TenantID, consumerID)
	if err != nil {
		return err
	}

	if err := s.deliver(ctx, subject, c, keyID); err != nil {
		if e := s.consumers.RecordDelivery(ctx, c.ID, err); e != nil {
			s.log.Warn("recording consumer delivery failure", "consumer", c.Name, "error", e)
		}
		return err
	}

	if err := s.consumers.Rebind(ctx, subject.TenantID, consumerID, keyID); err != nil {
		return err
	}
	return s.consumers.RecordDelivery(ctx, c.ID, nil)
}

// Redeliver re-sends a consumer's current key, for recovering a sink that was
// unreachable when the rotation ran.
func (s *ConsumerService) Redeliver(ctx context.Context, subject *authz.Subject, consumerID uuid.UUID) error {
	if err := subject.Require(authz.PermKeyReveal); err != nil {
		return err
	}

	c, err := s.consumers.Get(ctx, subject.TenantID, consumerID)
	if err != nil {
		return err
	}

	err = s.deliver(ctx, subject, c, c.KeyID)
	if e := s.consumers.RecordDelivery(ctx, c.ID, err); e != nil {
		s.log.Warn("recording consumer delivery", "consumer", c.Name, "error", e)
	}
	return err
}

// deliver decrypts the key and hands it to the sink.
func (s *ConsumerService) deliver(ctx context.Context, subject *authz.Subject, c *store.Consumer, keyID uuid.UUID) error {
	sink, err := s.registry.Get(c.Kind)
	if err != nil {
		return err
	}

	key, err := s.keys.Get(ctx, subject.TenantID, keyID)
	if err != nil {
		return err
	}

	if sink.Pull() {
		// Nothing to push. Record the audit entry anyway: the consumer is now
		// entitled to a different key, which is a change worth a trail.
		s.record(ctx, subject, audit.Event{
			Action:       audit.ActionConsumerBind,
			ResourceType: "consumer",
			ResourceID:   &c.ID,
			ResourceName: c.Name,
			Outcome:      audit.OutcomeSuccess,
			Detail:       map[string]any{"kind": c.Kind, "key": key.Name, "mode": "pull"},
		})
		return nil
	}

	privatePEM, err := s.keySvc.PrivateKeyFor(ctx, subject.TenantID, keyID)
	if err != nil {
		return err
	}
	defer vault.Zero(privatePEM)

	remote, err := s.remoteFor(ctx, subject.TenantID, c)
	if err != nil {
		return err
	}
	if remote != nil {
		defer vault.Zero(remote.PrivateKey)
	}

	deliverErr := sink.Deliver(ctx, consumers.Delivery{
		ConsumerName: c.Name,
		KeyName:      key.Name,
		Fingerprint:  key.Fingerprint,
		PublicKey:    key.PublicKey,
		PrivatePEM:   privatePEM,
		Config:       c.Config,
		Remote:       remote,
	})

	outcome := audit.OutcomeSuccess
	detail := map[string]any{"kind": c.Kind, "key": key.Name, "fingerprint": key.Fingerprint}
	if deliverErr != nil {
		outcome = audit.OutcomeFailure
		detail["error"] = deliverErr.Error()
	}

	s.record(ctx, subject, audit.Event{
		Action:       audit.ActionConsumerSend,
		ResourceType: "consumer",
		ResourceID:   &c.ID,
		ResourceName: c.Name,
		Outcome:      outcome,
		Detail:       detail,
	})

	return deliverErr
}

// Kinds lists the sink kinds this build supports.
func (s *ConsumerService) Kinds() []string { return s.registry.Kinds() }

func (s *ConsumerService) record(ctx context.Context, subject *authz.Subject, ev audit.Event) {
	ev.TenantID = subject.TenantID
	ev.ActorType = audit.ActorUser
	ev.ActorID = &subject.UserID
	ev.ActorName = subject.Username
	if _, err := s.audit.Log(ctx, ev); err != nil {
		s.log.Error("writing audit event", "action", ev.Action, "error", err)
	}
}
