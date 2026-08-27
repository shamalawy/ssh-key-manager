package consumers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/hamalawy/ssh-key-manager/backend/internal/sshx"
)

// RemoteHost is a machine a sink can reach over SSH.
//
// It is filled in by the service layer, which owns targets, credentials, and
// the vault. Keeping it a plain struct is what lets this package deliver to a
// host without depending on any of them.
type RemoteHost struct {
	Address    string
	Port       int
	Username   string
	HostKeyPin string
	UseSudo    bool

	Password string
	// PrivateKey authenticates the *connection*. It is not the key being
	// delivered, and the two are never the same thing by accident: this one
	// comes from the target's credential.
	PrivateKey []byte
}

// SSHFile writes the private key to a path on another machine.
//
// This is the sink for a host that has to authenticate outwards — a jump box, a
// CI runner, a backup job that rsyncs over SSH. Those machines need the private
// half, which is why they are consumers rather than targets: a target receives
// the public key and can be converged whenever, a consumer holds the secret and
// has to be updated inside the rotation window.
type SSHFile struct{}

// Kind identifies the sink.
func (SSHFile) Kind() string { return "ssh_file" }

// Pull reports that this sink is pushed to.
func (SSHFile) Pull() bool { return false }

// Deliver writes the key atomically on the remote host.
//
// Same discipline as a local file drop: a temporary file with the mode set
// before any content exists, then a rename. A reader on the far side never sees
// a half-written key, and there is no window where the key is on disk
// world-readable.
func (SSHFile) Deliver(ctx context.Context, d Delivery) error {
	if d.Remote == nil {
		return fmt.Errorf("%w: %q needs a machine to deliver to — set target_id",
			ErrConfig, d.ConsumerName)
	}
	path, err := d.ConfigString("path")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("%w: %q needs an absolute path, got %q",
			ErrConfig, d.ConsumerName, path)
	}

	mode := d.ConfigOr("mode", "600")
	owner := d.ConfigOr("owner", d.Remote.Username)

	client, err := sshx.Dial(ctx, sshx.DialOptions{
		Address:    d.Remote.Address,
		Port:       d.Remote.Port,
		Username:   d.Remote.Username,
		Password:   d.Remote.Password,
		PrivateKey: d.Remote.PrivateKey,
		HostKeyPin: d.Remote.HostKeyPin,
		Timeout:    10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("%w: connecting to %s: %s", ErrDelivery, d.Remote.Address, err)
	}
	defer client.Close()

	if err := writeRemote(ctx, client, path, owner, mode, d.PrivatePEM, d.Remote.UseSudo); err != nil {
		return err
	}

	// The matching .pub alongside, when asked for. Anything using the private
	// key for SSH generally wants it, and deriving it on the far side means
	// installing tooling there.
	if d.ConfigOr("write_public", "") == "true" && d.PublicKey != "" {
		if err := writeRemote(ctx, client, path+".pub", owner, "644",
			[]byte(d.PublicKey+"\n"), d.Remote.UseSudo); err != nil {
			return err
		}
	}
	return nil
}

// writeRemote places content at path atomically.
func writeRemote(ctx context.Context, client *sshx.Client, path, owner, mode string, content []byte, useSudo bool) error {
	script := fmt.Sprintf(`set -eu
P=%s
U=%s
D=$(dirname "$P")
[ -d "$D" ] || { mkdir -p "$D"; chmod 700 "$D"; chown "$U" "$D" 2>/dev/null || true; }
T=$(mktemp "$D/.skm-XXXXXX")
B="$T.b64"
trap 'rm -f "$T" "$B"' EXIT INT TERM HUP
cat > "$B"
if base64 -d < "$B" > "$T" 2>/dev/null; then :
elif base64 -D < "$B" > "$T" 2>/dev/null; then :
elif base64 --decode < "$B" > "$T" 2>/dev/null; then :
elif openssl base64 -d -in "$B" -out "$T" 2>/dev/null; then :
else printf 'SKM_NO_BASE64\n' >&2; exit 3; fi
rm -f "$B"
chmod %s "$T"
chown "$U" "$T" 2>/dev/null || true
mv -f "$T" "$P"
trap - EXIT
# Read back rather than trusting the write. A rename that reported success but
# did not land — a full disk, a read-only mount, a quota — must not be recorded
# as a delivered key.
if command -v sha256sum >/dev/null 2>&1; then H=$(sha256sum < "$P" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then H=$(shasum -a 256 < "$P" | cut -d' ' -f1)
else H=skipped; fi
printf 'SKM_OK %%s\n' "$H"`, shellQuote(path), shellQuote(owner), shellQuote(mode))

	if useSudo {
		script = "sudo -n sh -c " + shellQuote(script)
	}

	out, err := client.RunInput(ctx, script,
		[]byte(base64.StdEncoding.EncodeToString(content)))
	if err != nil {
		return fmt.Errorf("%w: writing %s: %s", ErrDelivery, path, err)
	}
	if strings.Contains(out.Stderr, "SKM_NO_BASE64") {
		return fmt.Errorf("%w: the machine has no usable base64 decoder, so %s cannot be written", ErrDelivery, path)
	}
	if out.ExitCode != 0 {
		return fmt.Errorf("%w: writing %s failed (exit %d): %s",
			ErrDelivery, path, out.ExitCode, strings.TrimSpace(out.Stderr))
	}
	if !strings.Contains(out.Stdout, "SKM_OK") {
		return fmt.Errorf("%w: writing %s did not confirm success", ErrDelivery, path)
	}

	// Compare what the host now holds against what was sent. "skipped" means the
	// host had no sha256 tool, in which case the rename's success is all there
	// is to go on.
	got := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out.Stdout), "SKM_OK"))
	if got != "" && got != "skipped" {
		want := fmt.Sprintf("%x", sha256.Sum256(content))
		if got != want {
			return fmt.Errorf("%w: %s does not match what was sent (wrote %s, host has %s)",
				ErrDelivery, path, want[:12], got[:min(12, len(got))])
		}
	}
	return nil
}

// shellQuote renders s as a single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
