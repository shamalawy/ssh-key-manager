// Package git manages deploy keys and account keys on git hosting providers.
//
// A git provider is a target in SKM's sense — it holds the public half — but it
// differs from a host in two ways that shape this connector. Keys are addressed
// by an opaque provider-assigned identifier rather than by position in a file,
// and a key's *title* is the only field an operator sees, so SKM stamps its own
// fingerprint into the title to make its keys identifiable later.
//
// Verification is genuine: authenticating to the provider's SSH endpoint with
// the new private key proves the key works, exactly as it does for a host.
package git

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/shamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/shamalawy/ssh-key-manager/backend/internal/diff"
	"github.com/shamalawy/ssh-key-manager/backend/internal/keys"
	"github.com/shamalawy/ssh-key-manager/backend/internal/sshx"
)

// Kind is the connector's registered identifier.
const Kind = "git"

// Providers understood by this connector.
const (
	ProviderGitHub    = "github"
	ProviderGitLab    = "gitlab"
	ProviderBitbucket = "bitbucket"
)

// Connector manages keys on git hosting providers.
type Connector struct {
	Client *http.Client
	// Dial is used for verification, and is a field so tests can substitute it.
	Dial func(ctx context.Context, opts sshx.DialOptions) (*sshx.Client, error)
}

// New returns a Connector using real HTTP and SSH.
func New() *Connector {
	return &Connector{
		Client: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				TLSHandshakeTimeout: 5 * time.Second,
			},
		},
		Dial: sshx.Dial,
	}
}

func (c *Connector) Kind() string { return Kind }

// Capabilities: a provider can be listed and snapshotted, its keys can be
// re-added from a snapshot, and a key can be proven to authenticate.
// Options (from=, command=) have no meaning here.
func (c *Connector) Capabilities() connectors.Capabilities {
	return connectors.Capabilities{
		CanList:         true,
		CanSnapshot:     true,
		CanRestore:      true,
		CanVerify:       true,
		SupportsOptions: false,
	}
}

// Validate checks a target's provider configuration.
func (c *Connector) Validate(ctx context.Context, t *connectors.Target) error {
	if t == nil {
		return fmt.Errorf("git: target is nil")
	}

	provider := t.ConfigString("provider", ProviderGitHub)
	switch provider {
	case ProviderGitHub, ProviderGitLab, ProviderBitbucket:
	default:
		return fmt.Errorf("git: unknown provider %q (expected github, gitlab, or bitbucket)", provider)
	}

	scope := t.ConfigString("scope", "repository")
	switch scope {
	case "repository":
		if t.ConfigString("repository", "") == "" {
			return fmt.Errorf("git: target %q is repository-scoped but has no \"repository\" setting "+
				"(owner/name for GitHub and Bitbucket, project id or path for GitLab)", t.Name)
		}
	case "account":
		if provider != ProviderGitHub && provider != ProviderGitLab {
			return fmt.Errorf("git: account-scoped keys are only supported for GitHub and GitLab")
		}
	default:
		return fmt.Errorf("git: unknown scope %q (expected repository or account)", scope)
	}
	return nil
}

// providerKey is one key as the provider reports it.
type providerKey struct {
	ID          json.Number `json:"id"`
	Title       string      `json:"title"`
	Key         string      `json:"key"`
	Fingerprint string      `json:"-"`
	ReadOnly    bool        `json:"read_only"`
}

// Probe confirms the credential works and the target exists.
func (c *Connector) Probe(ctx context.Context, req connectors.Request) (*connectors.ProbeResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	existing, err := c.list(ctx, req)
	if err != nil {
		return &connectors.ProbeResult{Reachable: false, Message: err.Error()}, err
	}

	return &connectors.ProbeResult{
		Reachable: true,
		Message:   "reachable",
		Detail: map[string]string{
			"provider": req.Target.ConfigString("provider", ProviderGitHub),
			"scope":    req.Target.ConfigString("scope", "repository"),
			"keys":     fmt.Sprint(len(existing)),
		},
	}, nil
}

// List returns the keys currently registered on the target.
func (c *Connector) List(ctx context.Context, req connectors.Request) ([]keys.Entry, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	existing, err := c.list(ctx, req)
	if err != nil {
		return nil, err
	}

	var out []keys.Entry
	for _, pk := range existing {
		parsed := keys.ParseAuthorizedKeys([]byte(pk.Key))
		for _, e := range parsed.Keys() {
			if e.Fingerprint != "" {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// Apply adds the desired keys and, when pruning, removes SKM's own keys that
// are no longer wanted.
func (c *Connector) Apply(ctx context.Context, req connectors.Request, desired []connectors.DesiredKey, opts connectors.ApplyOptions) (*connectors.ApplyResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	before, err := c.Snapshot(ctx, req)
	if err != nil {
		return nil, err
	}

	existing, err := c.list(ctx, req)
	if err != nil {
		return nil, err
	}

	byFingerprint := map[string]providerKey{}
	for _, pk := range existing {
		if pk.Fingerprint != "" {
			byFingerprint[pk.Fingerprint] = pk
		}
	}

	result := &connectors.ApplyResult{Before: before, DryRun: opts.DryRun}

	var toAdd []connectors.DesiredKey
	for _, d := range desired {
		if _, ok := byFingerprint[d.Fingerprint]; ok {
			continue
		}
		toAdd = append(toAdd, d)
		result.Added = append(result.Added, d.Fingerprint)
	}

	var toRemove []providerKey
	if opts.Prune {
		wanted := map[string]bool{}
		for _, d := range desired {
			wanted[d.Fingerprint] = true
		}
		managed := map[string]bool{}
		for _, fp := range opts.ManagedFingerprints {
			managed[fp] = true
		}

		for fingerprint, pk := range byFingerprint {
			if wanted[fingerprint] {
				continue
			}
			if opts.PreserveUnmanaged && !managed[fingerprint] {
				continue
			}
			toRemove = append(toRemove, pk)
			result.Removed = append(result.Removed, fingerprint)
		}
	}

	result.Changed = len(toAdd) > 0 || len(toRemove) > 0

	// The lockout guard. Removing the last deploy key breaks every clone and
	// pull that uses it, which is this connector's equivalent of emptying an
	// authorized_keys file.
	if !opts.AllowEmpty && len(byFingerprint)+len(toAdd)-len(toRemove) <= 0 && len(toRemove) > 0 {
		return result, fmt.Errorf("%w: applying to %s would leave no keys registered",
			connectors.ErrWouldLockOut, req.Target.Name)
	}

	if opts.DryRun || !result.Changed {
		result.Diff = previewDiff(req.Target.Name, toAdd, toRemove)
		return result, nil
	}

	for _, d := range toAdd {
		if err := c.add(ctx, req, d); err != nil {
			return result, err
		}
	}
	// Additions run before removals so the target is never briefly keyless.
	for _, pk := range toRemove {
		if err := c.remove(ctx, req, pk); err != nil {
			return result, err
		}
	}

	after, err := c.Snapshot(ctx, req)
	if err != nil {
		return result, err
	}
	result.After = after
	result.Diff = diff.Unified(string(before.Content), string(after.Content),
		req.Target.Name+" (before)", req.Target.Name+" (after)", 3)

	// Read back rather than trusting the create call's response.
	final, err := c.list(ctx, req)
	if err != nil {
		return result, err
	}
	got := map[string]bool{}
	for _, pk := range final {
		got[pk.Fingerprint] = true
	}
	for _, d := range desired {
		if !got[d.Fingerprint] {
			return result, fmt.Errorf("git: %s accepted the key but %s is not listed on the target",
				req.Target.Name, d.Fingerprint)
		}
	}

	return result, nil
}

// Snapshot records the current key set as canonical text.
func (c *Connector) Snapshot(ctx context.Context, req connectors.Request) (*connectors.Snapshot, error) {
	existing, err := c.list(ctx, req)
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	for _, pk := range existing {
		fmt.Fprintf(&b, "%s\t%s\t%s\n", pk.ID.String(), pk.Title, strings.TrimSpace(pk.Key))
	}

	content := []byte(b.String())
	sum := sha256.Sum256(content)

	return &connectors.Snapshot{
		Kind:     "git_keys",
		Content:  content,
		Checksum: hex.EncodeToString(sum[:]),
		KeyCount: len(existing),
		Existed:  true,
	}, nil
}

// Restore re-adds keys from a snapshot that are no longer present.
//
// It deliberately only adds. Provider key identifiers are assigned on creation
// and cannot be reused, so an exact restore is impossible; adding back what is
// missing restores *access*, which is what a rollback is for.
func (c *Connector) Restore(ctx context.Context, req connectors.Request, snap *connectors.Snapshot) error {
	if snap == nil {
		return fmt.Errorf("git: no snapshot to restore")
	}

	existing, err := c.list(ctx, req)
	if err != nil {
		return err
	}
	present := map[string]bool{}
	for _, pk := range existing {
		present[pk.Fingerprint] = true
	}

	for _, line := range strings.Split(string(snap.Content), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), "\t", 3)
		if len(fields) < 3 {
			continue
		}
		title, publicLine := fields[1], fields[2]

		parsed := keys.ParseAuthorizedKeys([]byte(publicLine))
		entries := parsed.Keys()
		if len(entries) == 0 {
			continue
		}
		if present[entries[0].Fingerprint] {
			continue
		}

		if err := c.add(ctx, req, connectors.DesiredKey{
			PublicLine:  publicLine,
			Fingerprint: entries[0].Fingerprint,
			Comment:     title,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Verify authenticates to the provider's SSH endpoint with the key.
func (c *Connector) Verify(ctx context.Context, req connectors.Request, privateKeyPEM []byte) error {
	host := req.Target.ConfigString("ssh_host", defaultSSHHost(req.Target.ConfigString("provider", ProviderGitHub)))
	if host == "" {
		return fmt.Errorf("%w: no ssh_host configured for %s", connectors.ErrUnsupported, req.Target.Name)
	}

	port := req.Target.Port
	if port == 0 {
		port = 22
	}

	dial := c.Dial
	if dial == nil {
		dial = sshx.Dial
	}

	// Providers accept the connection, print a greeting, and close it without
	// granting a shell, so a successful handshake is the whole proof. Opening
	// a session would fail on a key that works perfectly well.
	client, err := dial(ctx, sshx.DialOptions{
		Address:    host,
		Port:       port,
		Username:   "git",
		PrivateKey: privateKeyPEM,
		HostKeyPin: req.Target.HostKeyPin,
	})
	if err != nil {
		return fmt.Errorf("git: the key does not authenticate to %s: %w", host, err)
	}
	client.Close()
	return nil
}

func defaultSSHHost(provider string) string {
	switch provider {
	case ProviderGitHub:
		return "github.com"
	case ProviderGitLab:
		return "gitlab.com"
	case ProviderBitbucket:
		return "bitbucket.org"
	}
	return ""
}

// ------------------------------------------------------------ provider APIs ---

func (c *Connector) list(ctx context.Context, req connectors.Request) ([]providerKey, error) {
	endpoint, err := c.endpoint(req)
	if err != nil {
		return nil, err
	}

	body, err := c.do(ctx, req, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var raw []providerKey
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("git: decoding the key list from %s: %w", req.Target.Name, err)
	}

	for i := range raw {
		parsed := keys.ParseAuthorizedKeys([]byte(raw[i].Key))
		if entries := parsed.Keys(); len(entries) > 0 {
			raw[i].Fingerprint = entries[0].Fingerprint
		}
	}
	return raw, nil
}

func (c *Connector) add(ctx context.Context, req connectors.Request, d connectors.DesiredKey) error {
	endpoint, err := c.endpoint(req)
	if err != nil {
		return err
	}

	provider := req.Target.ConfigString("provider", ProviderGitHub)
	readOnly := req.Target.ConfigBool("read_only", true)

	// The title carries the fingerprint so SKM's keys are identifiable in the
	// provider's own interface, where the key body is truncated.
	title := d.Comment
	if title == "" {
		title = "skm"
	}
	title = fmt.Sprintf("%s (%s)", title, shortFingerprint(d.Fingerprint))

	var payload map[string]any
	switch provider {
	case ProviderGitLab:
		payload = map[string]any{"title": title, "key": d.PublicLine, "can_push": !readOnly}
	case ProviderBitbucket:
		payload = map[string]any{"label": title, "key": d.PublicLine}
	default:
		payload = map[string]any{"title": title, "key": d.PublicLine, "read_only": readOnly}
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("git: encoding the key: %w", err)
	}

	_, err = c.do(ctx, req, http.MethodPost, endpoint, encoded)
	return err
}

func (c *Connector) remove(ctx context.Context, req connectors.Request, pk providerKey) error {
	endpoint, err := c.endpoint(req)
	if err != nil {
		return err
	}

	_, err = c.do(ctx, req, http.MethodDelete, endpoint+"/"+pk.ID.String(), nil)
	return err
}

// endpoint builds the collection URL for a target.
func (c *Connector) endpoint(req connectors.Request) (string, error) {
	t := req.Target
	provider := t.ConfigString("provider", ProviderGitHub)
	scope := t.ConfigString("scope", "repository")
	repo := t.ConfigString("repository", "")

	base := t.ConfigString("api_base", "")
	if base == "" {
		switch provider {
		case ProviderGitHub:
			base = "https://api.github.com"
		case ProviderGitLab:
			base = "https://gitlab.com"
		case ProviderBitbucket:
			base = "https://api.bitbucket.org"
		}
	}
	base = strings.TrimRight(base, "/")

	switch provider {
	case ProviderGitHub:
		if scope == "account" {
			return base + "/user/keys", nil
		}
		return fmt.Sprintf("%s/repos/%s/keys", base, repo), nil
	case ProviderGitLab:
		if scope == "account" {
			return base + "/api/v4/user/keys", nil
		}
		return fmt.Sprintf("%s/api/v4/projects/%s/deploy_keys", base, pathEscape(repo)), nil
	case ProviderBitbucket:
		return fmt.Sprintf("%s/2.0/repositories/%s/deploy-keys", base, repo), nil
	}
	return "", fmt.Errorf("git: unknown provider %q", provider)
}

func (c *Connector) do(ctx context.Context, req connectors.Request, method, url string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("git: building the request: %w", err)
	}

	token := req.Credential.Token
	if token == "" {
		return nil, fmt.Errorf("git: target %q needs an api_token credential", req.Target.Name)
	}

	provider := req.Target.ConfigString("provider", ProviderGitHub)
	switch provider {
	case ProviderGitLab:
		httpReq.Header.Set("PRIVATE-TOKEN", token)
	default:
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if provider == ProviderGitHub {
		httpReq.Header.Set("Accept", "application/vnd.github+json")
		httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}

	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("git: calling %s: %w", req.Target.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return payload, nil
	}

	// The provider's own message is the most useful diagnostic here, and it
	// never contains key material — only titles and identifiers.
	return nil, fmt.Errorf("git: %s returned HTTP %d: %s",
		req.Target.Name, resp.StatusCode, clip(string(payload)))
}

func pathEscape(s string) string {
	// GitLab accepts a URL-encoded "group/project" path in place of a numeric
	// identifier, which is friendlier to configure.
	return strings.ReplaceAll(s, "/", "%2F")
}

func shortFingerprint(fp string) string {
	trimmed := strings.TrimPrefix(fp, "SHA256:")
	if len(trimmed) > 12 {
		return trimmed[:12]
	}
	return trimmed
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 500 {
		return s
	}
	return s[:500] + "… (truncated)"
}

func previewDiff(name string, toAdd []connectors.DesiredKey, toRemove []providerKey) string {
	if len(toAdd) == 0 && len(toRemove) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s (current)\n+++ %s (desired)\n", name, name)
	for _, pk := range toRemove {
		fmt.Fprintf(&b, "-%s\t%s\n", pk.Title, pk.Fingerprint)
	}
	for _, d := range toAdd {
		fmt.Fprintf(&b, "+%s\t%s\n", d.Comment, d.Fingerprint)
	}
	return b.String()
}
