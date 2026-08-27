// Command skmctl is the SKM command-line client.
//
// Everything the web interface can do is reachable here, so deployments and
// rotations can run from CI without a browser. It talks to the same REST API,
// which keeps the two surfaces from drifting apart.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// client talks to an SKM server.
type client struct {
	baseURL string
	token   string
	http    *http.Client
}

func newClient(baseURL, token string) *client {
	return &client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 120 * time.Second},
	}
}

// do performs a request and decodes the response.
func (c *client) do(method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("contacting %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if err := json.Unmarshal(payload, &apiErr); err == nil && apiErr.Error != "" {
			return fmt.Errorf("%s (%s)", apiErr.Error, apiErr.Code)
		}
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

// tokenPath is where a successful login stores its session token.
func tokenPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "skm", "token")
	}
	return filepath.Join(os.TempDir(), ".skm-token")
}

func savedToken() string {
	if t := os.Getenv("SKM_TOKEN"); t != "" {
		return t
	}
	b, err := os.ReadFile(tokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func saveToken(token string) error {
	path := tokenPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// The token is a bearer credential: readable only by its owner.
	return os.WriteFile(path, []byte(token), 0o600)
}

func main() {
	var (
		serverURL string
		asJSON    bool
	)

	root := &cobra.Command{
		Use:   "skmctl",
		Short: "Manage SSH keys, targets, and rotations",
		Long: "skmctl is the command-line client for SKM.\n\n" +
			"Every operation available in the web interface is available here, so\n" +
			"deployments and rotations can run unattended from CI.",
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&serverURL, "server", envOr("SKM_SERVER", "http://localhost:8080"),
		"SKM server URL")
	root.PersistentFlags().BoolVar(&asJSON, "json", false, "emit raw JSON instead of a table")

	newClientFn := func() *client { return newClient(serverURL, savedToken()) }

	root.AddCommand(
		healthCmd(&serverURL),
		loginCmd(&serverURL),
		logoutCmd(newClientFn),
		keysCmd(newClientFn, &asJSON),
		targetsCmd(newClientFn, &asJSON),
		deployCmd(newClientFn, &asJSON),
		rotateCmd(newClientFn, &asJSON),
		reconcileCmd(newClientFn, &asJSON),
		backupCmd(newClientFn, &asJSON),
		jobsCmd(newClientFn, &asJSON),
		auditCmd(newClientFn, &asJSON),
		vaultCmd(newClientFn, &asJSON),
		usersCmd(newClientFn, &asJSON),
		tokensCmd(newClientFn, &asJSON),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// healthCmd backs the container health check, so the image needs no curl.
func healthCmd(serverURL *string) *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Check that the server is responding",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClient(*serverURL, "")
			c.http.Timeout = 5 * time.Second

			var out map[string]any
			if err := c.do(http.MethodGet, "/healthz", nil, &out); err != nil {
				return err
			}
			fmt.Println("ok")
			return nil
		},
	}
}

func loginCmd(serverURL *string) *cobra.Command {
	var username, password, totp string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in and store a session token",
		RunE: func(cmd *cobra.Command, args []string) error {
			if password == "" {
				password = os.Getenv("SKM_PASSWORD")
			}
			if username == "" || password == "" {
				return errors.New("both --username and --password (or SKM_PASSWORD) are required")
			}

			var session struct {
				Token       string   `json:"token"`
				Permissions []string `json:"permissions"`
				User        struct {
					Username           string `json:"username"`
					MustChangePassword bool   `json:"must_change_password"`
				} `json:"user"`
			}

			c := newClient(*serverURL, "")
			if err := c.do(http.MethodPost, "/api/v1/auth/login", map[string]string{
				"username": username, "password": password, "totp_code": totp,
			}, &session); err != nil {
				return err
			}
			if err := saveToken(session.Token); err != nil {
				return fmt.Errorf("saving the session token: %w", err)
			}

			fmt.Printf("signed in as %s (%d permissions)\n", session.User.Username, len(session.Permissions))
			if session.User.MustChangePassword {
				fmt.Println("note: this account must change its password before doing anything else")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "username")
	cmd.Flags().StringVarP(&password, "password", "p", "", "password (or set SKM_PASSWORD)")
	cmd.Flags().StringVar(&totp, "totp", "", "current second-factor code")
	return cmd
}

func logoutCmd(newClientFn func() *client) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke the stored session",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClientFn().do(http.MethodPost, "/api/v1/auth/logout", nil, nil); err != nil {
				return err
			}
			_ = os.Remove(tokenPath())
			fmt.Println("signed out")
			return nil
		},
	}
}

func keysCmd(newClientFn func() *client, asJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "keys", Short: "Manage keys"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Items []map[string]any `json:"items"`
			}
			if err := newClientFn().do(http.MethodGet, "/api/v1/keys?limit=200", nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out.Items)
			}
			printTable(out.Items,
				[]string{"name", "algorithm", "status", "fingerprint_sha256"},
				[]string{"NAME", "ALGORITHM", "STATUS", "FINGERPRINT"})
			return nil
		},
	}

	var (
		algorithm string
		comment   string
		validDays int
		tags      []string
	)
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Generate a new keypair",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var key map[string]any
			if err := newClientFn().do(http.MethodPost, "/api/v1/keys", map[string]any{
				"name": args[0], "algorithm": algorithm, "comment": comment,
				"valid_days": validDays, "tags": tags,
			}, &key); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(key)
			}
			fmt.Printf("created %s\n  algorithm:   %v\n  fingerprint: %v\n  public key:  %v\n",
				key["name"], key["algorithm"], key["fingerprint_sha256"], key["public_key"])
			return nil
		},
	}
	create.Flags().StringVarP(&algorithm, "algorithm", "a", "ed25519", "key algorithm")
	create.Flags().StringVar(&comment, "comment", "", "key comment")
	create.Flags().IntVar(&validDays, "valid-days", 0, "days until the key should be rotated")
	create.Flags().StringSliceVar(&tags, "tag", nil, "tags (repeatable)")

	var reason string
	reveal := &cobra.Command{
		Use:   "reveal <key-id>",
		Short: "Print a private key (requires permission and a recent second factor)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if reason == "" {
				return errors.New("--reason is required: it is recorded on the audit trail")
			}
			var out struct {
				PrivateKey string `json:"private_key"`
			}
			if err := newClientFn().do(http.MethodPost, "/api/v1/keys/"+args[0]+"/reveal",
				map[string]string{"reason": reason}, &out); err != nil {
				return err
			}
			fmt.Print(out.PrivateKey)
			return nil
		},
	}
	reveal.Flags().StringVar(&reason, "reason", "", "why the key is being revealed (recorded in the audit log)")

	var (
		importFile       string
		importPassphrase string
		importTags       []string
	)
	importKey := &cobra.Command{
		Use:   "import <name>",
		Short: "Bring an existing private key under management",
		Long: "Reads a private key from --file, or from stdin when no file is given,\n" +
			"and stores it encrypted. The public half is derived from the private\n" +
			"key, so a .pub file is not needed — which is what makes this the way\n" +
			"to adopt a key another system generated, such as an AWS .pem.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				pem []byte
				err error
			)
			if importFile == "" || importFile == "-" {
				pem, err = io.ReadAll(cmd.InOrStdin())
			} else {
				pem, err = os.ReadFile(importFile)
			}
			if err != nil {
				return err
			}
			if len(bytes.TrimSpace(pem)) == 0 {
				return errors.New("no key material: pass --file, or pipe the key on stdin")
			}

			var key map[string]any
			if err := newClientFn().do(http.MethodPost, "/api/v1/keys/import", map[string]any{
				"name": args[0], "private_key": string(pem),
				"passphrase": importPassphrase, "tags": importTags,
			}, &key); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(key)
			}
			fmt.Printf("imported %s\n  algorithm:   %v\n  fingerprint: %v\n  public key:  %v\n",
				key["name"], key["algorithm"], key["fingerprint_sha256"], key["public_key"])
			return nil
		},
	}
	importKey.Flags().StringVarP(&importFile, "file", "f", "", "private key file (default: stdin)")
	importKey.Flags().StringVar(&importPassphrase, "passphrase", "", "passphrase, if the key is encrypted")
	importKey.Flags().StringSliceVar(&importTags, "tag", nil, "tags (repeatable)")

	cmd.AddCommand(list, create, importKey, reveal)
	return cmd
}

func targetsCmd(newClientFn func() *client, asJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "targets", Short: "Manage targets"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List targets",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Items []map[string]any `json:"items"`
			}
			if err := newClientFn().do(http.MethodGet, "/api/v1/targets?limit=500", nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out.Items)
			}
			printTable(out.Items,
				[]string{"name", "kind", "address", "health", "drift_state"},
				[]string{"NAME", "KIND", "ADDRESS", "HEALTH", "DRIFT"})
			return nil
		},
	}

	probe := &cobra.Command{
		Use:   "probe <target-id>",
		Short: "Check whether a target is reachable",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]any
			if err := newClientFn().do(http.MethodPost, "/api/v1/targets/"+args[0]+"/probe", nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	}

	cmd.AddCommand(list, probe)
	return cmd
}

func deployCmd(newClientFn func() *client, asJSON *bool) *cobra.Command {
	var (
		targetID    string
		principalID string
		dryRun      bool
		prune       bool
		verify      bool
	)

	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Converge a target on its assigned keys",
		Long: "Deploy applies the desired key set to one principal on one target.\n\n" +
			"Use --dry-run first: it prints the exact diff without changing anything.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetID == "" || principalID == "" {
				return errors.New("both --target and --principal are required")
			}

			var res struct {
				Changed      bool     `json:"changed"`
				DryRun       bool     `json:"dry_run"`
				Added        []string `json:"added"`
				Removed      []string `json:"removed"`
				Diff         string   `json:"diff"`
				VerifiedKeys []string `json:"verified_keys"`
				FailedKeys   []string `json:"failed_keys"`
				TargetName   string   `json:"target_name"`
				Username     string   `json:"username"`
			}
			if err := newClientFn().do(http.MethodPost, "/api/v1/deploy", map[string]any{
				"target_id": targetID, "principal_id": principalID,
				"dry_run": dryRun, "prune": prune, "verify_auth": verify,
			}, &res); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(res)
			}

			label := "applied"
			if res.DryRun {
				label = "would apply"
			}
			if !res.Changed {
				fmt.Printf("%s/%s is already in the desired state\n", res.TargetName, res.Username)
				return nil
			}

			fmt.Printf("%s to %s/%s: +%d -%d\n", label, res.TargetName, res.Username,
				len(res.Added), len(res.Removed))
			if res.Diff != "" {
				fmt.Println()
				fmt.Print(res.Diff)
			}
			if len(res.VerifiedKeys) > 0 {
				fmt.Printf("\nverified %d key(s) can authenticate\n", len(res.VerifiedKeys))
			}
			if len(res.FailedKeys) > 0 {
				fmt.Printf("\nWARNING: %d key(s) deployed but could not authenticate: %v\n",
					len(res.FailedKeys), res.FailedKeys)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&targetID, "target", "", "target ID")
	cmd.Flags().StringVar(&principalID, "principal", "", "principal ID")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the diff without applying it")
	cmd.Flags().BoolVar(&prune, "prune", false, "remove managed keys that are no longer assigned")
	cmd.Flags().BoolVar(&verify, "verify", true, "prove each deployed key can authenticate")
	return cmd
}

func auditCmd(newClientFn func() *client, asJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Inspect the audit trail"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List recent audit events",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Items []map[string]any `json:"items"`
			}
			if err := newClientFn().do(http.MethodGet, "/api/v1/audit?limit=50", nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out.Items)
			}
			printTable(out.Items,
				[]string{"occurred_at", "actor_name", "action", "resource_name", "outcome"},
				[]string{"WHEN", "ACTOR", "ACTION", "RESOURCE", "OUTCOME"})
			return nil
		},
	}

	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit chain has not been tampered with",
		RunE: func(cmd *cobra.Command, args []string) error {
			var res struct {
				Valid       bool   `json:"valid"`
				Checked     int64  `json:"checked"`
				BrokenAtSeq int64  `json:"broken_at_seq"`
				Reason      string `json:"reason"`
			}
			if err := newClientFn().do(http.MethodGet, "/api/v1/audit/verify", nil, &res); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(res)
			}

			if res.Valid {
				fmt.Printf("audit chain intact: %d events verified\n", res.Checked)
				return nil
			}
			// A broken chain is a finding, not a client error: report it and
			// exit non-zero so CI notices.
			fmt.Printf("AUDIT CHAIN BROKEN at event %d\n  %s\n", res.BrokenAtSeq, res.Reason)
			os.Exit(2)
			return nil
		},
	}

	cmd.AddCommand(list, verify)
	return cmd
}

func vaultCmd(newClientFn func() *client, asJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "vault", Short: "Inspect and maintain the vault"}

	status := &cobra.Command{
		Use:   "status",
		Short: "Show whether the vault is sealed",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]any
			if err := newClientFn().do(http.MethodGet, "/api/v1/vault/status", nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	}

	rotate := &cobra.Command{
		Use:   "rotate-kek",
		Short: "Rewrap every key under the current key-encryption key",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]any
			if err := newClientFn().do(http.MethodPost, "/api/v1/vault/rotate-kek", nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	}

	cmd.AddCommand(status, rotate)
	return cmd
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// printTable renders rows as aligned columns.
func printTable(rows []map[string]any, fields, headers []string) {
	if len(rows) == 0 {
		fmt.Println("(none)")
		return
	}

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}

	cells := make([][]string, len(rows))
	for r, row := range rows {
		cells[r] = make([]string, len(fields))
		for c, f := range fields {
			text := format(row[f])
			cells[r][c] = text
			if len(text) > widths[c] {
				widths[c] = len(text)
			}
		}
	}

	for i, h := range headers {
		fmt.Printf("%-*s  ", widths[i], h)
	}
	fmt.Println()

	for _, row := range cells {
		for i, cell := range row {
			fmt.Printf("%-*s  ", widths[i], cell)
		}
		fmt.Println()
	}
}

func format(v any) string {
	switch t := v.(type) {
	case nil:
		return "-"
	case string:
		// Timestamps are easier to scan without sub-second precision.
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			return parsed.Local().Format("2006-01-02 15:04:05")
		}
		return t
	case bool:
		if t {
			return "yes"
		}
		return "no"
	case float64:
		return fmt.Sprintf("%g", t)
	default:
		return fmt.Sprint(t)
	}
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
