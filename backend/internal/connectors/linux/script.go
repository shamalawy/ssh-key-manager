package linux

import (
	"fmt"
	"strings"
)

// quote renders s as a single-quoted POSIX shell word.
//
// Every remote command is built from operator-supplied data — usernames, file
// paths, key comments — so quoting is a security boundary, not a convenience.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// wrap prepares a script for execution, optionally under sudo.
//
// sudo runs with -n so a host that would prompt for a password fails
// immediately with a clear error instead of hanging until the session times out.
func wrap(script string, useSudo bool) string {
	inner := "sh -c " + quote(script)
	if useSudo {
		return "sudo -n " + inner
	}
	return inner
}

// Sentinels the remote scripts print so Go can tell outcomes apart without
// relying on exit codes alone, which some restricted shells mangle.
const (
	markerExists   = "SKM_EXISTS"
	markerMissing  = "SKM_MISSING"
	markerOK       = "SKM_OK"
	markerNoBase64 = "SKM_NO_BASE64"
)

// readScript emits a marker line and then the base64-encoded file contents.
func readScript(path string) string {
	return fmt.Sprintf(`set -eu
P=%s
if [ -e "$P" ]; then
  printf '%s\n'
  base64 < "$P"
else
  printf '%s\n'
fi`, quote(path), markerExists, markerMissing)
}

// homeScript resolves a user's home directory.
func homeScript(username string) string {
	return fmt.Sprintf(`set -eu
U=%s
H=$(getent passwd "$U" 2>/dev/null | cut -d: -f6 || true)
if [ -z "$H" ]; then H=$(eval echo "~$U" 2>/dev/null || true); fi
if [ -z "$H" ] || [ "$H" = "~$U" ]; then exit 4; fi
printf '%%s\n' "$H"`, quote(username))
}

// writeScript replaces a file atomically, reading base64 content from stdin.
//
// The sequence matters. The temporary file is created in the destination
// directory so the final rename is same-filesystem and therefore atomic; it is
// chmod'ed before it holds content; ownership and SELinux context are copied
// from the file being replaced so a sudo-driven write does not leave a file the
// principal cannot read. A trap removes the temporary file if anything fails,
// so a partial write never lands next to the real one.
func writeScript(path, username string, mode string) string {
	return fmt.Sprintf(`set -eu
P=%s
U=%s
D=$(dirname "$P")

if [ ! -d "$D" ]; then
  mkdir -p "$D"
  chmod 700 "$D"
  chown "$U" "$D" 2>/dev/null || true
fi

T=$(mktemp "$D/.skm-XXXXXX")
B="$T.b64"
trap 'rm -f "$T" "$B"' EXIT INT TERM HUP

cat > "$B"
if base64 -d < "$B" > "$T" 2>/dev/null; then :
elif base64 -D < "$B" > "$T" 2>/dev/null; then :
elif base64 --decode < "$B" > "$T" 2>/dev/null; then :
elif openssl base64 -d -in "$B" -out "$T" 2>/dev/null; then :
else
  printf '%s\n' >&2
  exit 3
fi
rm -f "$B"

chmod %s "$T"
if [ -e "$P" ]; then
  chown --reference="$P" "$T" 2>/dev/null || chown "$U" "$T" 2>/dev/null || true
  if command -v chcon >/dev/null 2>&1; then chcon --reference="$P" "$T" 2>/dev/null || true; fi
else
  chown "$U" "$T" 2>/dev/null || true
fi

mv -f "$T" "$P"
trap - EXIT INT TERM HUP
if command -v sync >/dev/null 2>&1; then sync || true; fi
printf '%s\n'`,
		quote(path), quote(username), markerNoBase64, mode, markerOK)
}

// removeScript deletes the key file, used only when restoring a snapshot that
// captured a target with no file at all.
func removeScript(path string) string {
	return fmt.Sprintf(`set -eu
P=%s
rm -f "$P"
printf '%s\n'`, quote(path), markerOK)
}
