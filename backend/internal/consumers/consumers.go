// Package consumers delivers *private* keys to the systems that authenticate
// with them.
//
// Targets and consumers are the two halves of a rotation. A target receives the
// public key and can be converged at any time; a consumer receives the private
// key and must be updated during the window when both keys still work. Tools
// that model only targets appear to rotate successfully and then break the CI
// job that was using the key.
//
// Every sink here handles material that must never be logged. The contract is
// that a Sink receives the PEM, uses it, and returns — it does not retain it,
// print it, or include it in an error.
package consumers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	// ErrUnsupported means no sink is registered for a consumer kind.
	ErrUnsupported = errors.New("consumers: unsupported consumer kind")
	// ErrConfig means the consumer's configuration is incomplete.
	ErrConfig = errors.New("consumers: invalid consumer configuration")
	// ErrDelivery means the destination was reached and would not take the key
	// — a path that cannot be written, a rejected token, a full disk. The
	// server did its job; the answer was no, and the message says why.
	ErrDelivery = errors.New("consumers: the destination refused the key")
)

// Delivery is one private key being handed to one sink.
type Delivery struct {
	ConsumerName string
	KeyName      string
	Fingerprint  string
	PublicKey    string
	// PrivatePEM is live key material. Sinks must not retain or log it.
	PrivatePEM []byte
	Config     map[string]any

	// Remote is set when the consumer names a machine to deliver to, resolved
	// by the service layer from the target and its credential.
	Remote *RemoteHost
}

// ConfigString reads a required string setting.
func (d Delivery) ConfigString(key string) (string, error) {
	v, _ := d.Config[key].(string)
	if strings.TrimSpace(v) == "" {
		return "", fmt.Errorf("%w: %q needs a %q setting", ErrConfig, d.ConsumerName, key)
	}
	return v, nil
}

// ConfigOr reads an optional string setting.
func (d Delivery) ConfigOr(key, def string) string {
	if v, ok := d.Config[key].(string); ok && v != "" {
		return v
	}
	return def
}

// Sink writes a private key somewhere.
type Sink interface {
	Kind() string
	// Pull reports that the consumer fetches from SKM rather than being
	// pushed to, so a rotation records readiness instead of delivering.
	Pull() bool
	Deliver(ctx context.Context, d Delivery) error
}

// Registry maps consumer kinds to sinks.
type Registry struct{ sinks map[string]Sink }

// NewRegistry returns a registry with the built-in sinks.
func NewRegistry() *Registry {
	r := &Registry{sinks: map[string]Sink{}}
	for _, s := range []Sink{
		&FileDrop{}, &WebhookSink{client: defaultClient()},
		&VaultKV{client: defaultClient()}, &KubernetesSecret{client: defaultClient()},
		&EnvExport{}, &SSHFile{},
	} {
		r.sinks[s.Kind()] = s
	}
	return r
}

// Get returns the sink for a kind.
func (r *Registry) Get(kind string) (Sink, error) {
	s, ok := r.sinks[kind]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupported, kind)
	}
	return s, nil
}

// Kinds lists the registered sink kinds.
func (r *Registry) Kinds() []string {
	out := make([]string, 0, len(r.sinks))
	for k := range r.sinks {
		out = append(out, k)
	}
	return out
}

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
}

// ---------------------------------------------------------------- file drop ---

// FileDrop writes the key to a path on the SKM host, for sidecar and
// shared-volume patterns.
type FileDrop struct{}

// Kind identifies the sink.
func (FileDrop) Kind() string { return "file_drop" }

// Pull reports that this sink is pushed to.
func (FileDrop) Pull() bool { return false }

// Deliver writes the private key with restrictive permissions.
//
// The write is atomic — temp file, chmod, rename — so a reader never observes a
// half-written key, and the mode is set before any content exists rather than
// after.
func (FileDrop) Deliver(ctx context.Context, d Delivery) error {
	path, err := d.ConfigString("path")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %q needs an absolute path", ErrConfig, d.ConsumerName)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("consumers: creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".skm-key-*")
	if err != nil {
		return fmt.Errorf("consumers: creating a temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("consumers: restricting permissions on %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(d.PrivatePEM); err != nil {
		return fmt.Errorf("consumers: writing the key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("consumers: flushing the key to disk: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("consumers: closing the temporary file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("consumers: moving the key into place at %s: %w", path, err)
	}

	// The public half is written alongside when asked for, because most
	// consumers of a private key also want the matching .pub.
	if d.ConfigOr("write_public", "") == "true" && d.PublicKey != "" {
		pub := path + ".pub"
		if err := os.WriteFile(pub, []byte(d.PublicKey+"\n"), 0o644); err != nil {
			return fmt.Errorf("consumers: writing the public key to %s: %w", pub, err)
		}
	}
	return nil
}

// ------------------------------------------------------------------ webhook ---

// WebhookSink POSTs the key to an endpoint that stores it.
type WebhookSink struct{ client *http.Client }

// Kind identifies the sink.
func (*WebhookSink) Kind() string { return "webhook" }

// Pull reports that this sink is pushed to.
func (*WebhookSink) Pull() bool { return false }

// Deliver posts the key as JSON.
func (s *WebhookSink) Deliver(ctx context.Context, d Delivery) error {
	url, err := d.ConfigString("url")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(url, "https://") && d.ConfigOr("allow_insecure", "") != "true" {
		return fmt.Errorf("%w: %q posts a private key, so its URL must be https "+
			"(set allow_insecure to override)", ErrConfig, d.ConsumerName)
	}

	body, err := json.Marshal(map[string]any{
		"key_name":    d.KeyName,
		"fingerprint": d.Fingerprint,
		"public_key":  d.PublicKey,
		"private_key": string(d.PrivatePEM),
	})
	if err != nil {
		return fmt.Errorf("consumers: encoding the delivery: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("consumers: building the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token := d.ConfigOr("token", ""); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return s.do(req, d.ConsumerName)
}

func (s *WebhookSink) do(req *http.Request, name string) error {
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("consumers: delivering to %s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	// The response may echo the request; read a bounded amount and never
	// include it verbatim, since the request contained a private key.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("consumers: %s returned HTTP %d", name, resp.StatusCode)
}

// ----------------------------------------------------------------- Vault KV ---

// VaultKV writes the key into a HashiCorp Vault KV v2 mount.
type VaultKV struct{ client *http.Client }

// Kind identifies the sink.
func (*VaultKV) Kind() string { return "vault_kv" }

// Pull reports that this sink is pushed to.
func (*VaultKV) Pull() bool { return false }

// Deliver writes a secret version.
func (s *VaultKV) Deliver(ctx context.Context, d Delivery) error {
	addr, err := d.ConfigString("address")
	if err != nil {
		return err
	}
	path, err := d.ConfigString("path")
	if err != nil {
		return err
	}
	token, err := d.ConfigString("token")
	if err != nil {
		return err
	}
	mount := d.ConfigOr("mount", "secret")

	payload, err := json.Marshal(map[string]any{
		"data": map[string]any{
			d.ConfigOr("private_key_field", "private_key"): string(d.PrivatePEM),
			d.ConfigOr("public_key_field", "public_key"):   d.PublicKey,
			"fingerprint": d.Fingerprint,
		},
	})
	if err != nil {
		return fmt.Errorf("consumers: encoding the Vault payload: %w", err)
	}

	url := fmt.Sprintf("%s/v1/%s/data/%s",
		strings.TrimRight(addr, "/"), strings.Trim(mount, "/"), strings.TrimLeft(path, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("consumers: building the Vault request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("consumers: writing to Vault for %s: %w", d.ConsumerName, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("consumers: Vault returned HTTP %d for %s: %s",
		resp.StatusCode, d.ConsumerName, strings.TrimSpace(string(body)))
}

// ---------------------------------------------------------- Kubernetes Secret ---

// KubernetesSecret writes the key into a Secret via the API server.
type KubernetesSecret struct{ client *http.Client }

// Kind identifies the sink.
func (*KubernetesSecret) Kind() string { return "kubernetes_secret" }

// Pull reports that this sink is pushed to.
func (*KubernetesSecret) Pull() bool { return false }

// Deliver applies a strategic merge patch to the Secret's data.
//
// A merge patch rather than a replace: a Secret often carries other keys the
// application needs, and replacing it would delete them.
func (s *KubernetesSecret) Deliver(ctx context.Context, d Delivery) error {
	apiServer, err := d.ConfigString("api_server")
	if err != nil {
		return err
	}
	namespace, err := d.ConfigString("namespace")
	if err != nil {
		return err
	}
	name, err := d.ConfigString("secret_name")
	if err != nil {
		return err
	}
	token, err := d.ConfigString("token")
	if err != nil {
		return err
	}

	data := map[string]string{
		d.ConfigOr("private_key_field", "ssh-privatekey"): base64.StdEncoding.EncodeToString(d.PrivatePEM),
	}
	if d.PublicKey != "" {
		data[d.ConfigOr("public_key_field", "ssh-publickey")] =
			base64.StdEncoding.EncodeToString([]byte(d.PublicKey + "\n"))
	}

	patch, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		return fmt.Errorf("consumers: encoding the Secret patch: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s",
		strings.TrimRight(apiServer, "/"), namespace, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(patch))
	if err != nil {
		return fmt.Errorf("consumers: building the Kubernetes request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("consumers: patching the Secret for %s: %w", d.ConsumerName, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("consumers: the Kubernetes API returned HTTP %d for %s: %s",
		resp.StatusCode, d.ConsumerName, strings.TrimSpace(string(body)))
}

// --------------------------------------------------------------- env export ---

// EnvExport is a pull-based consumer: nothing is pushed, and the consuming
// system fetches the key from SKM's API when it needs it.
//
// It exists so a rotation can still track that the consumer must be updated,
// and report it as a dependency in the plan, without SKM holding credentials
// for a system it cannot reach.
type EnvExport struct{}

// Kind identifies the sink.
func (EnvExport) Kind() string { return "env_export" }

// Pull reports that this consumer fetches rather than being pushed to.
func (EnvExport) Pull() bool { return true }

// Deliver is a no-op: rebinding the consumer is the whole delivery.
func (EnvExport) Deliver(ctx context.Context, d Delivery) error { return nil }
