package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// rotateCmd drives the rotation machine from the command line.
//
// This is the CI path: "rotate the production key, wait for it, fail the build
// if it did not complete" has to be expressible in one command with an exit
// status, or automation ends up polling the API by hand.
func rotateCmd(newClientFn func() *client, asJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "rotate", Short: "Plan, run, and inspect rotations"}

	var (
		soakHours        int
		canaryPercent    int
		failureThreshold int
		algorithm        string
		approval         bool
		dryRun           bool
		wait             bool
		waitTimeout      time.Duration
	)

	start := &cobra.Command{
		Use:   "start <key-id>",
		Short: "Rotate a key across every target it is deployed to",
		Long: "Adds a successor key alongside the old one, proves it authenticates on\n" +
			"each target, soaks with both live, then removes the old key.\n\n" +
			"With --wait the command blocks until the rotation finishes and exits\n" +
			"non-zero if it did not complete, which is what CI wants.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClientFn()

			var plan struct {
				Rotation map[string]any   `json:"rotation"`
				Targets  []map[string]any `json:"targets"`
				Warnings []string         `json:"warnings"`
			}
			body := map[string]any{
				"key_id":            args[0],
				"soak_hours":        soakHours,
				"canary_percent":    canaryPercent,
				"failure_threshold": failureThreshold,
				"algorithm":         algorithm,
				"approval_required": approval,
				"dry_run":           dryRun,
				"start":             !approval,
			}
			if err := c.do(http.MethodPost, "/api/v1/rotations", body, &plan); err != nil {
				return err
			}

			for _, w := range plan.Warnings {
				fmt.Fprintf(os.Stderr, "warning: %s\n", w)
			}

			id := format(plan.Rotation["id"])
			if *asJSON && !wait {
				return printJSON(plan)
			}

			fmt.Printf("rotation %s covering %d target(s)\n", id, len(plan.Targets))
			if approval {
				fmt.Println("held for approval; run `skmctl rotate approve " + id + "` to release it")
				return nil
			}
			if !wait {
				fmt.Println("running in the background; follow it with `skmctl rotate show " + id + "`")
				return nil
			}

			return waitForRotation(c, id, waitTimeout, *asJSON)
		},
	}
	start.Flags().IntVar(&soakHours, "soak-hours", 24, "how long both keys stay live after promotion")
	start.Flags().IntVar(&canaryPercent, "canary-percent", 10, "portion of targets to rotate first")
	start.Flags().IntVar(&failureThreshold, "failure-threshold", 10, "percentage of targets that may fail before aborting")
	start.Flags().StringVar(&algorithm, "algorithm", "", "algorithm for the successor key (defaults to the old key's)")
	start.Flags().BoolVar(&approval, "require-approval", false, "hold the rotation until someone approves it")
	start.Flags().BoolVar(&dryRun, "dry-run", false, "plan and diff without changing any target")
	start.Flags().BoolVar(&wait, "wait", false, "block until the rotation finishes")
	start.Flags().DurationVar(&waitTimeout, "wait-timeout", 30*time.Minute, "how long to wait with --wait")

	list := &cobra.Command{
		Use:   "list",
		Short: "List rotations",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Items []map[string]any `json:"items"`
			}
			if err := newClientFn().do(http.MethodGet, "/api/v1/rotations", nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out.Items)
			}
			printTable(out.Items,
				[]string{"id", "state", "trigger", "targets_total", "targets_retired", "targets_failed"},
				[]string{"ID", "STATE", "TRIGGER", "TARGETS", "RETIRED", "FAILED"})
			return nil
		},
	}

	show := &cobra.Command{
		Use:   "show <rotation-id>",
		Short: "Show one rotation and its per-target progress",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Rotation map[string]any   `json:"rotation"`
				Targets  []map[string]any `json:"targets"`
			}
			if err := newClientFn().do(http.MethodGet, "/api/v1/rotations/"+args[0], nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out)
			}

			fmt.Printf("state:   %s\n", format(out.Rotation["state"]))
			fmt.Printf("wave:    %s\n", format(out.Rotation["wave"]))
			if msg := format(out.Rotation["error"]); msg != "" {
				fmt.Printf("note:    %s\n", msg)
			}
			if soak := format(out.Rotation["soak_until"]); soak != "" {
				fmt.Printf("soak:    both keys valid until %s\n", soak)
			}
			fmt.Println()

			printTable(out.Targets,
				[]string{"wave", "target_name", "username", "state", "error"},
				[]string{"WAVE", "TARGET", "PRINCIPAL", "STATE", "DETAIL"})
			return nil
		},
	}

	approve := &cobra.Command{
		Use:   "approve <rotation-id>",
		Short: "Release a rotation that is waiting for sign-off",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]any
			if err := newClientFn().do(http.MethodPost,
				"/api/v1/rotations/"+args[0]+"/approve", map[string]any{}, &out); err != nil {
				return err
			}
			fmt.Println("approved; the rotation is now running")
			return nil
		},
	}

	var abortReason string
	abort := &cobra.Command{
		Use:   "abort <rotation-id>",
		Short: "Halt a rotation, leaving both keys in place",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]any
			if err := newClientFn().do(http.MethodPost, "/api/v1/rotations/"+args[0]+"/abort",
				map[string]any{"reason": abortReason}, &out); err != nil {
				return err
			}
			fmt.Println("aborted; nothing already deployed was removed")
			return nil
		},
	}
	abort.Flags().StringVar(&abortReason, "reason", "aborted from the command line", "why the rotation is being stopped")

	policies := &cobra.Command{
		Use:   "policies",
		Short: "List rotation schedules",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Items []map[string]any `json:"items"`
			}
			if err := newClientFn().do(http.MethodGet, "/api/v1/rotation-policies", nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out.Items)
			}
			printTable(out.Items,
				[]string{"name", "enabled", "cron_expr", "next_run_at"},
				[]string{"NAME", "ENABLED", "SCHEDULE", "NEXT RUN"})
			return nil
		},
	}

	cmd.AddCommand(start, list, show, approve, abort, policies)
	return cmd
}

// waitForRotation polls until the machine reaches a terminal state.
func waitForRotation(c *client, id string, timeout time.Duration, asJSON bool) error {
	deadline := time.Now().Add(timeout)
	lastState := ""

	for time.Now().Before(deadline) {
		var out struct {
			Rotation map[string]any   `json:"rotation"`
			Targets  []map[string]any `json:"targets"`
		}
		if err := c.do(http.MethodGet, "/api/v1/rotations/"+id, nil, &out); err != nil {
			return err
		}

		state := format(out.Rotation["state"])
		if state != lastState {
			fmt.Printf("  %s\n", state)
			lastState = state
		}

		switch state {
		case "completed":
			if asJSON {
				return printJSON(out)
			}
			failed := format(out.Rotation["targets_failed"])
			if failed != "0" && failed != "" {
				fmt.Printf("completed with %s target(s) still holding the old key\n", failed)
			} else {
				fmt.Println("completed; the old key is no longer authorized anywhere SKM manages")
			}
			return nil

		case "aborted", "failed", "rolled_back":
			reason := format(out.Rotation["error"])
			return fmt.Errorf("rotation %s: %s", state, orDash(reason))

		case "awaiting_approval":
			return fmt.Errorf("rotation is waiting for approval; run `skmctl rotate approve %s`", id)
		}

		time.Sleep(3 * time.Second)
	}

	return fmt.Errorf("rotation %s did not finish within %s; it is still running", id, timeout)
}

// reconcileCmd runs drift detection and the unmanaged-key inventory.
func reconcileCmd(newClientFn func() *client, asJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "drift", Short: "Detect drift and inspect unmanaged keys"}

	var targetID string
	scan := &cobra.Command{
		Use:   "scan",
		Short: "Read the fleet's actual keys and compare them with what SKM expects",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]any
			body := map[string]any{"target_id": targetID, "async": targetID == ""}
			if err := newClientFn().do(http.MethodPost, "/api/v1/reconcile", body, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out)
			}

			// A fleet-wide sweep comes back as a queued job rather than a report.
			if _, queued := out["type"]; queued {
				fmt.Printf("queued a fleet-wide scan as job %s\n", format(out["id"]))
				return nil
			}

			fmt.Printf("%s: %s\n", format(out["target_name"]), format(out["drift_state"]))
			return nil
		},
	}
	scan.Flags().StringVar(&targetID, "target", "", "scan one target instead of the whole fleet")

	var state string
	list := &cobra.Command{
		Use:   "list",
		Short: "List keys found on targets that SKM did not deploy",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Items []map[string]any `json:"items"`
			}
			path := "/api/v1/discovered-keys"
			if state != "" {
				path += "?state=" + state
			}
			if err := newClientFn().do(http.MethodGet, path, nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out.Items)
			}
			printTable(out.Items,
				[]string{"fingerprint_sha256", "comment", "target_name", "username", "state"},
				[]string{"FINGERPRINT", "COMMENT", "TARGET", "PRINCIPAL", "STATE"})
			return nil
		},
	}
	list.Flags().StringVar(&state, "state", "unmanaged", "unmanaged, adopted, ignored, or empty for all")

	var adoptName string
	adopt := &cobra.Command{
		Use:   "adopt <discovered-key-id>",
		Short: "Bring a discovered key under management",
		Long: "SKM does not hold the private half of an adopted key, so it can be\n" +
			"tracked, assigned, and removed, but not rotated.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var key map[string]any
			if err := newClientFn().do(http.MethodPost, "/api/v1/discovered-keys/"+args[0]+"/adopt",
				map[string]any{"name": adoptName}, &key); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(key)
			}
			fmt.Printf("adopted as %q (%s)\n", format(key["name"]), format(key["fingerprint_sha256"]))
			return nil
		},
	}
	adopt.Flags().StringVar(&adoptName, "name", "", "name for the adopted key")

	cmd.AddCommand(scan, list, adopt)
	return cmd
}

// backupCmd exports, verifies, and restores the vault.
func backupCmd(newClientFn func() *client, asJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "backup", Short: "Export, verify, and restore the vault"}

	var (
		name       string
		kind       string
		retainDays int
	)
	create := &cobra.Command{
		Use:   "create",
		Short: "Write an encrypted archive of the vault",
		Long: "The archive is encrypted under its own passphrase, not the server's\n" +
			"master key, so it can be restored into a fresh install. The passphrase\n" +
			"is read from SKM_BACKUP_PASSPHRASE or prompted for; it is never stored\n" +
			"and cannot be recovered.",
		RunE: func(cmd *cobra.Command, args []string) error {
			passphrase, err := backupPassphrase("Backup passphrase: ")
			if err != nil {
				return err
			}

			var out map[string]any
			if err := newClientFn().do(http.MethodPost, "/api/v1/backups", map[string]any{
				"name": name, "kind": kind, "passphrase": passphrase, "retain_days": retainDays,
			}, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out)
			}
			fmt.Printf("wrote %s key(s) to %s\n", format(out["key_count"]), format(out["location"]))
			return nil
		},
	}
	create.Flags().StringVar(&name, "name", "", "archive name (defaults to a timestamp)")
	create.Flags().StringVar(&kind, "kind", "full", "full, keys_only, or metadata")
	create.Flags().IntVar(&retainDays, "retain-days", 0, "delete the archive after this many days (0 keeps it)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List archives",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Items []map[string]any `json:"items"`
			}
			if err := newClientFn().do(http.MethodGet, "/api/v1/backups", nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out.Items)
			}
			printTable(out.Items,
				[]string{"name", "kind", "state", "key_count", "size_bytes", "created_at"},
				[]string{"NAME", "KIND", "STATE", "KEYS", "BYTES", "CREATED"})
			return nil
		},
	}

	verify := &cobra.Command{
		Use:   "verify <backup-id>",
		Short: "Prove an archive is restorable without restoring it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			passphrase, err := backupPassphrase("Backup passphrase: ")
			if err != nil {
				return err
			}

			var out struct {
				KeyCount      int      `json:"key_count"`
				KeysDecrypted int      `json:"keys_decrypted"`
				Problems      []string `json:"problems"`
				Valid         bool     `json:"valid"`
			}
			if err := newClientFn().do(http.MethodPost, "/api/v1/backups/"+args[0]+"/verify",
				map[string]any{"passphrase": passphrase}, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out)
			}

			fmt.Printf("%d of %d private keys decrypted and matched their fingerprints\n",
				out.KeysDecrypted, out.KeyCount)
			for _, p := range out.Problems {
				fmt.Fprintf(os.Stderr, "problem: %s\n", p)
			}
			if !out.Valid {
				return fmt.Errorf("the archive is not restorable as it stands")
			}
			return nil
		},
	}

	var restorePath string
	restore := &cobra.Command{
		Use:   "restore [backup-id]",
		Short: "Import an archive into this instance",
		Long: "Keys already present are skipped rather than overwritten: a restore\n" +
			"that replaced a live key with an older copy would be a way to bring a\n" +
			"revoked key back.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && restorePath == "" {
				return fmt.Errorf("give a backup id or --path")
			}

			passphrase, err := backupPassphrase("Backup passphrase: ")
			if err != nil {
				return err
			}

			body := map[string]any{"passphrase": passphrase, "path": restorePath}
			if len(args) == 1 {
				body["backup_id"] = args[0]
			}

			var out struct {
				KeysRestored int      `json:"keys_restored"`
				KeysSkipped  int      `json:"keys_skipped"`
				Problems     []string `json:"problems"`
			}
			if err := newClientFn().do(http.MethodPost, "/api/v1/restore", body, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out)
			}

			fmt.Printf("restored %d key(s); skipped %d already present\n", out.KeysRestored, out.KeysSkipped)
			for _, p := range out.Problems {
				fmt.Fprintf(os.Stderr, "problem: %s\n", p)
			}
			return nil
		},
	}
	restore.Flags().StringVar(&restorePath, "path", "", "restore an archive file copied in from elsewhere")

	cmd.AddCommand(create, list, verify, restore)
	return cmd
}

// jobsCmd inspects background work.
func jobsCmd(newClientFn func() *client, asJSON *bool) *cobra.Command {
	cmd := &cobra.Command{Use: "jobs", Short: "Inspect background work"}

	var state string
	list := &cobra.Command{
		Use:   "list",
		Short: "List jobs",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct {
				Items []map[string]any `json:"items"`
			}
			path := "/api/v1/jobs"
			if state != "" {
				path += "?state=" + state
			}
			if err := newClientFn().do(http.MethodGet, path, nil, &out); err != nil {
				return err
			}
			if *asJSON {
				return printJSON(out.Items)
			}
			printTable(out.Items,
				[]string{"id", "type", "state", "attempts", "last_error"},
				[]string{"ID", "TYPE", "STATE", "TRIES", "ERROR"})
			return nil
		},
	}
	list.Flags().StringVar(&state, "state", "", "queued, running, succeeded, dead, or empty for all")

	var follow bool
	logs := &cobra.Command{
		Use:   "logs <job-id>",
		Short: "Show a job's progress lines",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := newClientFn()
			cursor := int64(0)

			for {
				var out struct {
					Items []struct {
						ID       int64     `json:"id"`
						Level    string    `json:"level"`
						Message  string    `json:"message"`
						LoggedAt time.Time `json:"logged_at"`
					} `json:"items"`
					Cursor int64 `json:"cursor"`
				}
				path := fmt.Sprintf("/api/v1/jobs/%s/logs?after=%d", args[0], cursor)
				if err := c.do(http.MethodGet, path, nil, &out); err != nil {
					return err
				}

				for _, l := range out.Items {
					fmt.Printf("%s  %s\n", l.LoggedAt.Format("15:04:05"), l.Message)
				}
				cursor = out.Cursor

				if !follow {
					return nil
				}

				// Stop following once the job is no longer going to write.
				var job struct {
					State string `json:"state"`
				}
				if err := c.do(http.MethodGet, "/api/v1/jobs/"+args[0], nil, &job); err != nil {
					return err
				}
				switch job.State {
				case "succeeded", "cancelled", "dead":
					return nil
				}

				time.Sleep(2 * time.Second)
			}
		},
	}
	logs.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing until the job finishes")

	cmd.AddCommand(list, logs)
	return cmd
}

// backupPassphrase reads the archive passphrase from the environment, falling
// back to a prompt.
//
// It is never accepted as a flag: flags land in shell history and in
// /proc/<pid>/cmdline, where any user on the host can read them.
func backupPassphrase(prompt string) (string, error) {
	if v := os.Getenv("SKM_BACKUP_PASSPHRASE"); v != "" {
		return v, nil
	}

	fmt.Fprint(os.Stderr, prompt)
	passphrase, err := readSecret()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(passphrase) == "" {
		return "", fmt.Errorf("a passphrase is required")
	}
	return passphrase, nil
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "no reason recorded"
	}
	return s
}

// readSecret reads a line from the terminal with echo disabled.
//
// It falls back to a plain read when stdin is not a terminal, which is what
// makes `echo "$PASS" | skmctl backup create` work in a pipeline — though
// SKM_BACKUP_PASSPHRASE is the better path there.
func readSecret() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		raw, err := term.ReadPassword(fd)
		return string(raw), err
	}

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
