package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// Account and token administration from the command line.
//
// These exist so an install can be set up without the web interface at all —
// the first thing an automated deployment needs is a token, and needing to
// click through a browser to get one makes the whole API surface awkward to
// adopt.

func usersCmd(newClientFn func() *client, asJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "users", Short: "Manage accounts and roles"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List accounts",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Items []map[string]any `json:"items"`
			}
			if err := newClientFn().do(http.MethodGet, "/api/v1/users", nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out.Items)
			}
			for i := range out.Items {
				out.Items[i]["roles"] = joinAny(out.Items[i]["role_names"])
			}
			printTable(out.Items,
				[]string{"username", "display_name", "roles", "active", "totp_enrolled"},
				[]string{"USERNAME", "NAME", "ROLES", "ACTIVE", "2FA"})
			return nil
		},
	}

	var (
		email      string
		display    string
		roles      []string
		noPWChange bool
	)
	add := &cobra.Command{
		Use:   "add <username>",
		Short: "Create an account",
		Long: "The password is read from SKM_NEW_PASSWORD or prompted for. It is never " +
			"taken as a flag, because flags end up in shell history and process listings.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := newPassword()
			if err != nil {
				return err
			}

			var user map[string]any
			if err := newClientFn().do(http.MethodPost, "/api/v1/users", map[string]any{
				"username": args[0], "password": password, "email": email,
				"display_name": display, "roles": roles,
				"must_change_password": !noPWChange,
			}, &user); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(user)
			}
			fmt.Printf("created %v with role(s) %v\n", user["username"], joinAny(user["role_names"]))
			return nil
		},
	}
	add.Flags().StringVar(&email, "email", "", "contact address")
	add.Flags().StringVar(&display, "name", "", "display name")
	add.Flags().StringSliceVar(&roles, "role", []string{"viewer"}, "roles to grant (repeatable)")
	add.Flags().BoolVar(&noPWChange, "no-password-change", false,
		"do not force a password change at first sign-in")

	var (
		setRoles  []string
		activate  bool
		deactvate bool
		unlock    bool
	)
	edit := &cobra.Command{
		Use:   "edit <user-id>",
		Short: "Change an account's roles or state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if cmd.Flags().Changed("role") {
				body["roles"] = setRoles
			}
			if activate && deactvate {
				return errors.New("--activate and --deactivate contradict each other")
			}
			if activate {
				body["active"] = true
			}
			if deactvate {
				body["active"] = false
			}
			if unlock {
				body["unlock"] = true
			}
			if len(body) == 0 {
				return errors.New("nothing to change; pass --role, --activate, --deactivate, or --unlock")
			}

			var user map[string]any
			if err := newClientFn().do(http.MethodPatch, "/api/v1/users/"+args[0], body, &user); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(user)
			}
			fmt.Printf("updated %v: role(s) %v, active %v\n",
				user["username"], joinAny(user["role_names"]), user["active"])
			return nil
		},
	}
	edit.Flags().StringSliceVar(&setRoles, "role", nil, "replace the role set (repeatable)")
	edit.Flags().BoolVar(&activate, "activate", false, "allow sign-in")
	edit.Flags().BoolVar(&deactvate, "deactivate", false, "prevent sign-in")
	edit.Flags().BoolVar(&unlock, "unlock", false, "clear a failed-login lockout")

	password := &cobra.Command{
		Use:   "password <user-id>",
		Short: "Reset an account's password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			value, err := newPassword()
			if err != nil {
				return err
			}
			if err := newClientFn().do(http.MethodPost, "/api/v1/users/"+args[0]+"/password",
				map[string]any{"password": value, "must_change_password": true}, nil); err != nil {
				return err
			}
			fmt.Println("password reset; they will be asked to change it at next sign-in")
			return nil
		},
	}

	resetTOTP := &cobra.Command{
		Use:   "reset-totp <user-id>",
		Short: "Clear an account's second factor so it can be enrolled again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClientFn().do(http.MethodPost,
				"/api/v1/users/"+args[0]+"/reset-totp", map[string]any{}, nil); err != nil {
				return err
			}
			fmt.Println("second factor cleared; confirm who you spoke to, because this " +
				"turned a two-factor account into a one-factor one")
			return nil
		},
	}

	remove := &cobra.Command{
		Use:   "delete <user-id>",
		Short: "Delete an account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClientFn().do(http.MethodDelete, "/api/v1/users/"+args[0], nil, nil); err != nil {
				return err
			}
			fmt.Println("deleted; the account's audit history is retained")
			return nil
		},
	}

	rolesCmd := &cobra.Command{
		Use:   "roles",
		Short: "List roles and their permissions",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Items []map[string]any `json:"items"`
			}
			if err := newClientFn().do(http.MethodGet, "/api/v1/roles", nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out.Items)
			}
			for _, role := range out.Items {
				fmt.Printf("%v\n  %v\n  %v\n\n", role["name"], role["description"],
					joinAny(role["permissions"]))
			}
			return nil
		},
	}

	cmd.AddCommand(list, add, edit, password, resetTOTP, remove, rolesCmd)
	return cmd
}

func tokensCmd(newClientFn func() *client, asJSON *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tokens",
		Short: "Manage API tokens",
		Long: "A token authenticates as the account behind it and can be narrowed below " +
			"that account's rights, never above them. Tokens carry no second factor, so " +
			"revealing a private key and restoring a backup stay closed to them.",
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Items []map[string]any `json:"items"`
			}
			if err := newClientFn().do(http.MethodGet, "/api/v1/api-tokens", nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out.Items)
			}
			printTable(out.Items,
				[]string{"name", "prefix", "username", "status", "last_used_at"},
				[]string{"NAME", "PREFIX", "OWNER", "STATUS", "LAST USED"})
			return nil
		},
	}

	var (
		permissions []string
		scopes      []string
		expiresIn   string
	)
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Mint a token and print it once",
		Long: "The secret is written to stdout and nowhere else. It cannot be retrieved " +
			"afterwards, so capture it in the same command that creates it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Secret string         `json:"secret"`
				Token  map[string]any `json:"token"`
			}
			if err := newClientFn().do(http.MethodPost, "/api/v1/api-tokens", map[string]any{
				"name": args[0], "permissions": permissions,
				"scopes": scopes, "expires_in": expiresIn,
			}, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out)
			}
			// Only the secret goes to stdout, so `skmctl tokens create ci > f`
			// captures the token and nothing else.
			fmt.Fprintf(cmd.ErrOrStderr(),
				"created %v; this is the only time the secret is shown\n", out.Token["name"])
			fmt.Println(out.Secret)
			return nil
		},
	}
	create.Flags().StringSliceVar(&permissions, "permission", nil,
		"narrow the token to these permissions (repeatable); empty inherits the account's")
	create.Flags().StringSliceVar(&scopes, "scope", nil, "restrict to resources carrying these tags")
	create.Flags().StringVar(&expiresIn, "expires-in", "720h", "a Go duration, or empty for no expiry")

	revoke := &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "Stop a token working, keeping its history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newClientFn().do(http.MethodPost,
				"/api/v1/api-tokens/"+args[0]+"/revoke", map[string]any{}, nil); err != nil {
				return err
			}
			fmt.Println("revoked")
			return nil
		},
	}

	cmd.AddCommand(list, create, revoke)
	return cmd
}

// newPassword reads a password from the environment or the terminal. It is
// never a flag: flags land in shell history and in every process listing on
// the machine.
func newPassword() (string, error) {
	if value := envOr("SKM_NEW_PASSWORD", ""); value != "" {
		return value, nil
	}

	fmt.Fprint(os.Stderr, "New password: ")
	value, err := readSecret()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}

	fmt.Fprint(os.Stderr, "Confirm: ")
	again, err := readSecret()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if value != again {
		return "", errors.New("the passwords do not match")
	}
	return value, nil
}

// joinAny renders a JSON array of strings for a table cell.
func joinAny(v any) string {
	items, ok := v.([]any)
	if !ok || len(items) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprint(item))
	}
	return strings.Join(parts, ",")
}
