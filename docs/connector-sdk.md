# Writing a connector

"Anything that depends on SSH keys" is only true if adding a new kind of target
means implementing one interface rather than editing the rotation engine. This
is that interface.

There are two ways in. A **first-party connector** is Go code implementing
`connectors.Connector`; it is the right answer when the target class is common
enough to be worth maintaining. The **exec connector** runs a program you
supply against a JSON contract; it is the right answer when you need something
working today.

---

## The interface

```go
type Connector interface {
    Kind() string
    Capabilities() Capabilities

    Validate(ctx context.Context, t *Target) error
    Probe(ctx context.Context, req Request) (*ProbeResult, error)

    List(ctx context.Context, req Request) ([]keys.Entry, error)
    Apply(ctx context.Context, req Request, desired []DesiredKey, opts ApplyOptions) (*ApplyResult, error)

    Snapshot(ctx context.Context, req Request) (*Snapshot, error)
    Restore(ctx context.Context, req Request, snap *Snapshot) error

    Verify(ctx context.Context, req Request, privateKeyPEM []byte) error
}
```

### Capabilities are declared, not assumed

```go
type Capabilities struct {
    CanList         bool
    CanSnapshot     bool
    CanRestore      bool
    CanVerify       bool
    SupportsOptions bool
}
```

Be honest here. The engine adapts to what a connector actually supports instead
of failing on the ones that do less — but only if the declaration is true. A
connector that claims `CanVerify` and does not really verify turns the
rotation's safety gate into a formality, which is the single worst thing a
connector can do.

The built-in connectors, for reference:

| Connector | List | Snapshot | Restore | Verify | Options |
|---|---|---|---|---|---|
| `linux` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `netdev` | per profile | per profile | ✗ | ✓ | ✗ |
| `git` | ✓ | ✓ | add-back only | ✓ | ✗ |
| `exec` | your script | your script | your script | your script | your script |

`netdev` declines `Restore` deliberately: replaying a captured running
configuration onto a device is a larger and riskier operation than the change it
would undo. The snapshot is stored for a human to review and apply.

---

## The five rules

**1. `Verify` must open a fresh, independent connection.** It is handed the
private key and must prove *that key* authenticates as *that principal*. Reusing
the management connection, or checking that the key is present in a file, defeats
the rotation gate. If your target genuinely cannot be authenticated to, report
`CanVerify: false` and let the engine warn the operator.

**2. Never empty the key set.** `Apply` must return
`connectors.ErrWouldLockOut` rather than leave a principal with no usable keys,
unless `ApplyOptions.AllowEmpty` is set. This is a hard refusal, not a warning.
A key manager that removes the wrong key from 500 devices is worse than no key
manager.

**3. Preserve what you did not deploy.** When `PreserveUnmanaged` is set —
which is almost always — keys SKM did not put there stay. Comments, blank lines,
and lines you cannot parse survive verbatim. Removing a key an operator added by
hand is how you lose a fleet.

**4. Read back after writing.** A write that reported success but did not land —
a full disk, a read-only mount, a quota, a device that echoed the command and
ignored it — must not be recorded as a successful deployment. Compare a checksum
or list the keys again.

**5. Never log key material.** Not private keys, obviously; but also not
credentials, and not response bodies from a request that carried one.
`make audit-source` greps for this in CI and will fail the build.

---

## A minimal connector

```go
package myvendor

import (
    "context"
    "fmt"

    "github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
    "github.com/hamalawy/ssh-key-manager/backend/internal/keys"
)

const Kind = "myvendor"

type Connector struct{}

func New() *Connector { return &Connector{} }

func (c *Connector) Kind() string { return Kind }

func (c *Connector) Capabilities() connectors.Capabilities {
    return connectors.Capabilities{CanList: true, CanVerify: true}
}

func (c *Connector) Validate(ctx context.Context, t *connectors.Target) error {
    if t.ConfigString("endpoint", "") == "" {
        return fmt.Errorf("myvendor: target %q has no \"endpoint\" setting", t.Name)
    }
    return nil
}

func (c *Connector) Apply(ctx context.Context, req connectors.Request,
    desired []connectors.DesiredKey, opts connectors.ApplyOptions) (*connectors.ApplyResult, error) {

    before, err := c.List(ctx, req)
    if err != nil {
        return nil, err
    }

    result := &connectors.ApplyResult{DryRun: opts.DryRun}
    // ... work out what to add and remove ...

    if len(desired) == 0 && !opts.AllowEmpty {
        return result, fmt.Errorf("%w: applying to %s would leave no keys",
            connectors.ErrWouldLockOut, req.Target.Name)
    }
    if opts.DryRun {
        return result, nil
    }

    // ... apply, then read back and confirm ...
    _ = before
    return result, nil
}

// Snapshot, Restore, List, Probe, Verify follow the same shape.
```

Register it in `cmd/skm-server/main.go`:

```go
registry.Register(myvendor.New())
```

Test it against something real. The suite in `internal/connectors/linux` runs
against live `sshd` containers rather than mocks, and every bug worth catching
in that connector was caught by doing so.

---

## The exec connector

For anything you do not want to write Go for. SKM invokes a program once per
operation with a JSON object on stdin and expects a JSON object on stdout.

### Enabling it

The connector runs code as the SKM server process, so it is off unless you
opt in:

```sh
SKM_EXEC_DIRS=/etc/skm/connectors
```

Scripts must live inside an allowed directory, be executable, and must not be
group- or world-writable. Symlinks are resolved before the check, so a link
inside an allowed directory pointing elsewhere is refused.

### Configuring a target

```json
{
  "connector": "exec",
  "config": {
    "script": "/etc/skm/connectors/appliance.sh",
    "can_verify": true
  }
}
```

### The contract

Request on stdin:

```json
{
  "operation": "apply",
  "target":    {"id": "...", "name": "appliance-01", "address": "10.0.0.9", "port": 22,
                "config": {}, "host_key_pin": "SHA256:...", "tags": []},
  "principal": {"username": "admin"},
  "credential": {"kind": "ssh_password", "username": "admin", "password": "..."},
  "desired":   [{"public_key": "ssh-ed25519 AAAA... skm", "fingerprint": "SHA256:...",
                 "options": [], "comment": "skm"}],
  "options":   {"dry_run": false, "prune": true, "allow_empty": false}
}
```

`operation` is one of `probe`, `list`, `apply`, `snapshot`, `restore`, `verify`.
`restore` also carries `snapshot`; `verify` also carries `verify_key`, the
private key to authenticate with.

Response on stdout:

```json
{
  "ok": true,
  "message": "3 keys authorized",
  "keys": ["ssh-ed25519 AAAA... someone@laptop"],
  "changed": true,
  "added": ["SHA256:..."],
  "removed": [],
  "snapshot": {"kind": "appliance_state", "content": "...", "existed": true},
  "reachable": true,
  "detail": {"model": "X100"}
}
```

Set `"ok": false` with an `"error"` to report failure; a non-zero exit status
also counts, and stderr reaches the operator either way. Anything the script
prints to stdout that is not JSON is an error, not a warning — SKM will not
guess.

### Notes for script authors

- **Credentials arrive on stdin, never in argv.** `/proc/<pid>/cmdline` is
  readable by other users on the host. Do not pass them onwards in argv either.
- **The environment is minimal**: `PATH`, `SKM_OPERATION`, and `SKM_TARGET`.
  Nothing is inherited from the server.
- **`snapshot` should return the same content shape for `restore`.** SKM stores
  it verbatim and hands it straight back.
- **The lockout guard still applies.** SKM takes a snapshot after your `apply`
  and refuses the operation if it left no keys, whatever your script reported.
  It is a backstop, not a substitute for your own check.
- **Default to 5 minutes.** A script that has not answered by then is killed.

A worked example lives in `internal/connectors/execc/exec_test.go`, where the
scripts are small enough to read in full.
