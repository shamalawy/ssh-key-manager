// Package connectors defines how SKM reaches the things it manages keys on.
//
// The interface is the product's extension point: "anything that depends on SSH
// keys" is only achievable if adding a new kind of target means implementing one
// interface rather than editing the rotation engine.
//
// Capabilities are declared rather than assumed. A Linux host can list, snapshot,
// restore, and verify; a switch often cannot list its keys in a machine-readable
// way, and a git provider has no notion of authenticating a session at all. The
// engine adapts its behaviour to what a connector actually supports instead of
// failing on the ones that do less.
package connectors

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/hamalawy/ssh-key-manager/backend/internal/keys"
)

var (
	// ErrUnsupported is returned by a connector for a capability it does not
	// declare. Callers should check Capabilities first; this is the backstop.
	ErrUnsupported = errors.New("connectors: operation not supported by this connector")
	// ErrWouldLockOut is returned when an Apply would leave a principal with no
	// usable keys. It is a hard refusal, not a warning.
	ErrWouldLockOut = errors.New("connectors: refusing to remove the last remaining key")
	// ErrNotFound means the target exists but the principal or key file does not.
	ErrNotFound = errors.New("connectors: not found")
)

// Capabilities describes what a connector can do.
type Capabilities struct {
	// CanList: the current set of authorized keys can be read back.
	CanList bool `json:"can_list"`
	// CanSnapshot: a byte-exact capture can be taken before mutation.
	CanSnapshot bool `json:"can_snapshot"`
	// CanRestore: a snapshot can be written back verbatim.
	CanRestore bool `json:"can_restore"`
	// CanVerify: SKM can prove a private key authenticates against the target.
	// Without this, a rotation cannot use the authentication gate and must fall
	// back to confirming the key is present.
	CanVerify bool `json:"can_verify"`
	// SupportsOptions: authorized_keys options (from=, command=, no-pty) are
	// honoured. Most non-Linux targets ignore them.
	SupportsOptions bool `json:"supports_options"`
	// SingleKey: the platform holds exactly one key per principal, so a second
	// one replaces the first rather than joining it.
	//
	// This is not a rare corner. Arista EOS through at least 4.26 accepts
	// "username <name> ssh-key <key>" and silently overwrites whatever was
	// there, and several other vendor CLIs behave the same way. It matters
	// because add-before-remove — the sequence the whole rotation engine is
	// built on — is simply impossible here: there is no moment when both keys
	// are valid. A connector that declares this gets a replace-and-verify
	// rotation with an immediate rollback instead, and one that does not
	// declare it would report two keys installed where one is.
	SingleKey bool `json:"single_key"`
}

// Target is a place public keys are authorized.
type Target struct {
	ID         uuid.UUID
	Name       string
	Kind       string
	Connector  string
	Address    string
	Port       int
	Config     map[string]any
	HostKeyPin string
	Tags       []string
}

// ConfigString reads a string setting from the target's connector config.
func (t *Target) ConfigString(key, def string) string {
	if t.Config == nil {
		return def
	}
	if v, ok := t.Config[key].(string); ok && v != "" {
		return v
	}
	return def
}

// ConfigBool reads a boolean setting from the target's connector config.
func (t *Target) ConfigBool(key string, def bool) bool {
	if t.Config == nil {
		return def
	}
	if v, ok := t.Config[key].(bool); ok {
		return v
	}
	return def
}

// Principal is the account on the target whose authorized keys are managed.
type Principal struct {
	ID       uuid.UUID
	Username string
	// AuthorizedKeysPath overrides the connector default when non-empty.
	AuthorizedKeysPath string
	UseSudo            bool
}

// Credential is how SKM authenticates to the target in order to manage it.
// This is the bootstrap problem: some existing access is needed before keys can
// be installed.
type Credential struct {
	Kind     string // ssh_password | ssh_key | api_token
	Username string
	Password string
	// PrivateKey is unencrypted PEM, held only for the life of the operation.
	PrivateKey []byte
	Token      string
}

// Request bundles the three things every connector operation needs.
type Request struct {
	Target     *Target
	Principal  *Principal
	Credential *Credential
}

// Validate checks a request is internally complete.
func (r Request) Validate() error {
	switch {
	case r.Target == nil:
		return errors.New("connectors: request has no target")
	case r.Principal == nil:
		return errors.New("connectors: request has no principal")
	case r.Credential == nil:
		return errors.New("connectors: request has no credential")
	}
	return nil
}

// DesiredKey is one entry SKM wants present on a target.
type DesiredKey struct {
	PublicLine  string
	Fingerprint string
	Options     []string
	Comment     string
}

// Snapshot is a byte-exact capture of a target's key state before mutation.
type Snapshot struct {
	Kind     string // authorized_keys | device_config | api_state
	Content  []byte
	Checksum string
	KeyCount int
	// Existed records whether there was anything there at all, so a restore can
	// correctly return the target to "no file" rather than "empty file".
	Existed bool
}

// ApplyOptions tunes a single Apply call.
type ApplyOptions struct {
	// DryRun computes the diff and returns it without writing anything.
	DryRun bool
	// Prune removes managed keys that are not in the desired set. When false,
	// Apply only adds — the safe default for staging a rotation.
	Prune bool
	// AllowEmpty permits an Apply that would leave zero keys. Off by default;
	// this is the lockout guard.
	AllowEmpty bool
	// PreserveUnmanaged keeps keys SKM did not deploy. Almost always true:
	// removing a key an operator added by hand is how you lose a fleet.
	PreserveUnmanaged bool
	// ManagedFingerprints identifies which keys SKM considers its own, so
	// pruning can distinguish them from unmanaged entries.
	ManagedFingerprints []string
}

// DefaultApplyOptions are the conservative settings: add only, keep everything
// else, refuse to empty the file.
func DefaultApplyOptions() ApplyOptions {
	return ApplyOptions{PreserveUnmanaged: true}
}

// ApplyResult reports what an Apply did, or would do in a dry run.
type ApplyResult struct {
	Changed bool
	// Added and Removed hold fingerprints.
	Added   []string
	Removed []string
	// Diff is a human-readable unified diff, shown in the GUI before an
	// operator approves a change.
	Diff     string
	Before   *Snapshot
	After    *Snapshot
	DryRun   bool
	Warnings []string
}

// Connector manages keys on one class of target.
type Connector interface {
	// Kind is the stable identifier stored in targets.connector.
	Kind() string
	Capabilities() Capabilities

	// Validate checks a target's configuration without connecting.
	Validate(ctx context.Context, t *Target) error
	// Probe connects and reports reachability, returning the observed host key.
	Probe(ctx context.Context, req Request) (*ProbeResult, error)

	// List reads the keys currently authorized for the principal.
	List(ctx context.Context, req Request) ([]keys.Entry, error)
	// Apply converges the target on the desired key set.
	Apply(ctx context.Context, req Request, desired []DesiredKey, opts ApplyOptions) (*ApplyResult, error)

	// Snapshot captures current state for rollback.
	Snapshot(ctx context.Context, req Request) (*Snapshot, error)
	// Restore writes a snapshot back verbatim.
	Restore(ctx context.Context, req Request, snap *Snapshot) error

	// Verify proves that privateKeyPEM authenticates as the principal. This is
	// the gate a rotation must pass before promoting a new key.
	Verify(ctx context.Context, req Request, privateKeyPEM []byte) error
}

// ProbeResult reports target reachability.
//
// The JSON tags matter: this crosses the API like everything else, and an
// endpoint that answers in Go field names while its neighbours answer in
// snake_case makes every client special-case it.
type ProbeResult struct {
	Reachable    bool   `json:"reachable"`
	HostKeyPin   string `json:"host_key_pin,omitempty"`
	HostKeyIsNew bool   `json:"host_key_is_new"`
	Message      string `json:"message,omitempty"`
	// Detail carries connector-specific facts (OS version, device model) for
	// display.
	Detail map[string]string `json:"detail,omitempty"`
}

// Registry maps connector kinds to implementations.
type Registry struct {
	mu         sync.RWMutex
	connectors map[string]Connector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{connectors: make(map[string]Connector)}
}

// Register adds a connector, panicking on a duplicate kind because that is a
// programming error discoverable at startup.
func (r *Registry) Register(c Connector) {
	r.mu.Lock()
	defer r.mu.Unlock()

	kind := c.Kind()
	if _, exists := r.connectors[kind]; exists {
		panic(fmt.Sprintf("connectors: duplicate registration for kind %q", kind))
	}
	r.connectors[kind] = c
}

// Get returns the connector for a kind.
func (r *Registry) Get(kind string) (Connector, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	c, ok := r.connectors[kind]
	if !ok {
		return nil, fmt.Errorf("connectors: no connector registered for kind %q", kind)
	}
	return c, nil
}

// Kinds lists every registered connector kind.
func (r *Registry) Kinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]string, 0, len(r.connectors))
	for k := range r.connectors {
		out = append(out, k)
	}
	return out
}

// Setting documents one connector-specific configuration key.
//
// It exists so the interface can offer a real form for "which vendor profile"
// or "which git provider" instead of a JSON text box. A JSON text box is not a
// user interface; it is a request that the operator already know the answer.
type Setting struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Type        string   `json:"type"` // string, secret, bool, int, choice
	Choices     []string `json:"choices,omitempty"`
	Default     string   `json:"default,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Description string   `json:"description"`
}

// Documented is implemented by connectors that describe their configuration.
// A connector that does not is still usable; its settings are just not offered
// as a form.
type Documented interface {
	Settings() []Setting
}

// ErrDeviceRejected means the target refused a command it received.
//
// It is separated from a transport failure because the two need different
// responses: a rejection is a problem with the configuration or the profile
// and the operator can act on the device's own words, while a transport failure
// is worth retrying. Reporting a rejection as an internal error — which is what
// happens without a sentinel like this — hides the device's explanation behind
// "an internal error occurred", and the explanation is the entire useful part.
var ErrDeviceRejected = errors.New("connectors: the target rejected the change")
