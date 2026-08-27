# SKM — SSH Key Manager

[![CI](https://github.com/shamalawy/ssh-key-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/shamalawy/ssh-key-manager/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Full-custody lifecycle management for SSH keys: generate, distribute, verify,
rotate, roll back. A Go server with an embedded Angular interface, a REST API,
and a CLI, deployed as two containers.

```
make secrets && make up      # http://localhost:8090
```

---

## The problem it solves

Rotating an SSH key across a fleet is easy to do and catastrophic to do wrong.
Remove the wrong line from `authorized_keys` on 500 hosts and you have 500
machines you cannot log in to. Every design decision here follows from that.

**Nothing is removed until its replacement is proven.** A rotation adds the new
key, opens a *fresh, independent SSH connection using the new private key*, and
only then retires the old one. Presence of a line in a file is not evidence that
a key works; a successful authentication is.

**Nothing is written without a way back.** Every mutation is preceded by a
byte-exact snapshot with a checksum. Rollback restores the original file
verbatim — including the case where there was no file at all.

**Nothing SKM did not put there is touched.** Hand-added keys, comments, and even
lines SKM cannot parse survive a rewrite unchanged.

**The engine refuses to lock you out.** Emptying an `authorized_keys` file is a
hard error, not a warning. Overriding it takes an explicit flag.

---

## Status

Working and tested end to end against real PostgreSQL and real `sshd`:

| Area | State |
|---|---|
| Encrypted vault, envelope encryption, KEK rotation | complete |
| Key generation (6 algorithms), import, `authorized_keys` editing | complete |
| Linux/Unix connector — deploy, verify, snapshot, restore, sudo | complete |
| Deployment engine with dry-run diffs, lockout guards, rollback | complete |
| Authentication: Argon2id, TOTP, sessions, step-up MFA | complete |
| RBAC: 47 permissions, 5 system roles, tag scoping | complete |
| Hash-chained, tamper-evident audit log | complete |
| REST API + CLI (`skmctl`) | complete |
| Rotation engine: staged, verified, soaked, canary waves, approval gates | complete |
| Job queue (PostgreSQL `SKIP LOCKED`) and leader-elected scheduler | complete |
| Policy-driven rotation scheduling with a stdlib cron parser | complete |
| Drift detection, auto-heal, and the unmanaged-key inventory | complete |
| Connectors: `linux`, `netdev`, `git`, `exec` | complete |
| Consumers: file drop, Vault KV, Kubernetes Secret, webhook, pull | complete |
| Signed webhooks with retries, and an SSE event stream | complete |
| Encrypted vault export, verify, and restore | complete |
| User administration, roles, and scoped API tokens | complete |
| Second factor with a scannable QR code and recovery codes | complete |
| OpenAPI 3.1 document and a browsable API reference | complete |
| Web interface: seven screens | complete |
| Ansible and Nornir integrations | complete |
| Docker Compose deployment | complete |

**Not built**, and worth naming rather than leaving as a gap:

- **Cloud and Kubernetes connectors** (AWS/GCP/Azure key pairs, OS Login).
  Kubernetes is covered as a *consumer*; as a target it is not. The `exec`
  connector covers all of these today at the cost of writing a script.
- **A Terraform provider.** It needs `terraform-plugin-framework`, which is not
  available in this build environment. [The API is ready for
  one](integrations/terraform/README.md).
- **Vendor-tested `netdev` profiles beyond Arista.** The `arista_eos` profile
  has been exercised against a real switch — generate, deploy, authenticate,
  rotate, retire — on EOS 4.26.9M. The Juniper and Cisco profiles are written
  from published syntax and unit-tested against captured output, but no device
  was available. Treat those two as a starting point and check the first
  deployment by hand.

---

## Getting started

### Run it

```bash
make secrets     # generates the master key, database password, admin password
make up          # builds and starts skm_server + skm_postgres
```

`make secrets` prints the generated admin password. Sign in as `admin` at
<http://localhost:8090>; the account must change its password on first use.

If port 8090 is taken, `SKM_HTTP_PORT=8081 make up` moves it.

### Develop

```bash
make test-up         # PostgreSQL + three sshd containers
make dev             # server on :8080 against the test database
make dev-frontend    # Angular dev server on :4200, proxying /api
```

### Test

```bash
make test              # unit tests only, no Docker needed
make test-all          # everything, with the race detector
make check             # lint + security invariants + unit tests
```

The integration suite deploys real keys to real `sshd` containers and
authenticates with them. It is not mocked.

---

## Architecture

One Go binary runs the API and serves the Angular build embedded via
`//go:embed`. PostgreSQL is the only stateful dependency — no Redis, no broker.

```
Angular 21 SPA ──HTTP──> Go API ──> PostgreSQL
                            │
                            ├── vault (envelope encryption)
                            └── connector registry ──SSH──> managed hosts
```

### Envelope encryption

Each private key is encrypted under its own random data encryption key (DEK);
the DEK is wrapped by a key encryption key (KEK) held in memory. Rotating the
KEK rewraps DEKs only — the key material itself is never re-encrypted, so
rotation is cheap regardless of how much is stored.

Every ciphertext is bound to its own row by additional authenticated data. An
attacker with database write access cannot move one key's material onto another
key's row and have it decrypt. There is a test that proves this.

### Rotation

```
planned → [approved] → staging → verifying → verified
        → promoting → soaking → retiring → completed
                    ↘ aborted / failed
```

Every transition is a database write followed by an enqueued job, never an
in-memory step. Kill the server mid-rotation and a worker on any instance picks
it up from where it stopped — that is the property the whole design exists for,
and it is what rules out an in-memory queue.

Two things the machine will not do. It never removes an old key from a target
that did not verify the new one, so a partial failure leaves *more* access
rather than less. And when any target still holds the old key, that key stays in
`retiring` rather than `retired` — a key that still grants access somewhere must
not be reported as gone.

Waves come first: targets flagged as canaries (or a configured percentage) are
staged and verified alone before the rest of the fleet is touched. Past the
configured failure tolerance the rotation aborts rather than continuing into a
fleet it evidently cannot reach.

### Background work

The job queue is PostgreSQL, not a broker — SKM already depends on PostgreSQL
for correctness-critical state, and a second stateful system is a second way to
lose it. `FOR UPDATE SKIP LOCKED` gives competing workers exactly-once-at-a-time
delivery; a heartbeat keeps a slow job's lease alive, and a reaper requeues the
work of a process that died holding one.

Workers run on every instance. Scheduled work runs on exactly one, chosen by a
PostgreSQL advisory lock, so scaling out multiplies throughput without firing
every rotation policy twice.

### Targets and consumers

A **target** receives the *public* key — an `authorized_keys` file, a switch's
user config, a GitHub deploy key. A **consumer** receives the *private* key — a
Vault path, a Kubernetes Secret, a CI secret. Rotation has to update consumers
*before* retiring the old key, or automation breaks silently. Most tools model
only the first half.

### The connector interface

Adding support for a new kind of target means implementing one interface.
Capabilities are declared rather than assumed, because a switch generally cannot
list its keys the way a Linux host can, and the engine adapts instead of failing.

```go
type Connector interface {
    Kind() string
    Capabilities() Capabilities
    Validate(ctx, *Target) error
    Probe(ctx, Request) (*ProbeResult, error)
    List(ctx, Request) ([]keys.Entry, error)
    Apply(ctx, Request, []DesiredKey, ApplyOptions) (*ApplyResult, error)
    Snapshot(ctx, Request) (*Snapshot, error)
    Restore(ctx, Request, *Snapshot) error
    Verify(ctx, Request, privateKeyPEM []byte) error
}
```

---

## Platforms that hold one key per login

Some network platforms accept exactly one SSH key per username. Arista EOS is
one: `username mo ssh-key <key>` overwrites whatever was there, with no error
and no indication that anything was lost, and the indexed form other releases
accept is rejected outright.

This matters more than it sounds. Add-before-remove — the sequence the entire
rotation engine is built on — is not merely awkward here, it is impossible:
there is no instant at which both the old and the new key authenticate.

SKM handles it explicitly rather than quietly getting it wrong:

- The connector **declares** the limitation (`single_key` in its capabilities)
  and **refuses** to be handed two keys for one login, rather than issuing two
  commands and reporting two keys installed where one is.
- Rotation switches to **replace-and-verify**: the old key is replaced, the new
  one is proved against a fresh SSH connection immediately, and if that proof
  fails the old key goes straight back from the snapshot the deployment just
  took. The window in which the login is unreachable is one SSH handshake long,
  and it closes whichever way the handshake goes.
- The job log **says which sequence it used**, so nobody assumes the safer one
  ran everywhere.

This is worse than add-before-remove. It is also the best available on the
hardware, and being told which one you got is the difference between a managed
risk and a surprise.

---

## Security posture

- **Host key verification is mandatory.** `InsecureIgnoreHostKey` appears nowhere,
  and `make audit-source` fails the build if it ever does. A target's host key is
  pinned on first contact; a mismatch aborts.
- **Private key material leaves the vault through exactly one endpoint**, which
  requires a dedicated permission, a second factor verified within five minutes,
  and a stated reason. The audit entry is written *before* the material is
  returned — if the log cannot be written, the reveal does not happen.
- **Break-glass keys are gated separately** from ordinary keys, so emergency
  access can be alerted on differently.
- **The audit log is append-only at the database level** (a trigger rejects
  UPDATE and DELETE) *and* hash-chained, so tampering by anyone who gets past
  the first layer is still detectable. `skmctl audit verify` walks the chain.
- **Passwords use Argon2id** with parameters stored per-hash, so cost can be
  raised later without a reset. Unknown usernames still cost a full verification
  so response timing does not reveal which accounts exist.
- **Sessions are opaque tokens stored hashed** — revocable the instant an
  account is disabled, which a self-contained token would not be.
- **The container runs as non-root on distroless**, read-only, with all
  capabilities dropped and no shell.

### The web interface

Seven places to be, all built on the same REST API — there is no privileged
path the interface uses and the API does not have. The interface uses plain
words; the API keeps its own nouns (in brackets). The model is one sentence:
**a key's public half is deployed to servers; its private half is deployed to
clients** — and both are done in bulk with checkboxes.

| Screen | What it is for |
|---|---|
| Overview | A get-started checklist, expiring keys, deploys out of sync, unreachable servers, failed jobs |
| Servers | Servers [targets] and their logins [principals]; saved connections [credentials]; fleet health: out-of-sync checks, "fix automatically", and keys SKM did not deploy [discovered keys] |
| Clients | Anything that needs the private key [consumers]: a CI secret store, a Vault path, a Kubernetes Secret, a file on a host |
| Keys | Generate, import, reveal (gated), revoke, delete; break-glass keys |
| Deploy | Pick a key, then: public key → tick servers/logins, check the diff, apply, roll back in place [assignments + deploy + rollback]; private key → tick clients, deploy [consumer rebind/deliver] |
| Rotation | Rotate a key with five visible phases (planned, staging, verifying, soaking, retiring); schedules [rotation policies] |
| Settings | Account and second factor, users and API tokens, backups, jobs, audit trail, notifications [webhooks], API reference, vault |

An account flagged to change its password can do nothing else until it has:
the interface sends it to a change-password page and the API answers
`403 password_change_required` to every other call. Actions that need a
fresh second factor ask for the code where you are instead of sending you to
Settings.

Connector settings are a real form rather than a JSON box: a connector
describes its own configuration keys — which vendor profile, which git
provider — and the interface renders them. A JSON text box is not a user
interface; it is a request that the operator already know the answer.

---

## The API

The full surface is documented from the route table the router itself is built
from, so the documentation cannot describe an endpoint that does not exist or
miss one that does. Two forms, both unauthenticated because documentation you
have to sign in to read is documentation nobody reads:

- **<http://localhost:8090/api/v1/docs>** — a browsable reference, server-rendered
  and entirely self-contained. No CDN, no fonts, no script from anywhere else.
- **<http://localhost:8090/api/v1/openapi.json>** — an OpenAPI 3.1 document for
  generating clients.

The same reference is in the web interface under **API**, with a filter and
copyable `curl` examples.

A test asserts that every documented request body matches the fields the
handler actually decodes. It found eight endpoints whose documentation had
drifted the first time it ran, which is roughly the rate at which hand-written
API documentation goes wrong.

### API tokens

For automation, mint a token rather than storing a password:

```bash
curl -sS -X POST "$SKM_URL/api/v1/api-tokens" \
  -H "Authorization: Bearer $SESSION" -H 'Content-Type: application/json' \
  -d '{"name":"ci-rotate","permissions":["key.read","rotation.execute"],"expires_in":"720h"}'
```

The secret is returned exactly once and begins `skmt_`. A token authenticates
as the account behind it and can be narrowed below that account's rights, never
above them — asking for more is rejected rather than silently trimmed.

Tokens carry no second factor, so revealing a private key, taking a backup,
restoring one, and rotating the master key stay closed to them **even when the
token holds every permission**. That is deliberate: step-up exists so a person
confirms a dangerous action in the moment, and a value sitting in a CI variable
confirms nothing.

---

## Configuration

Every secret-bearing variable also accepts a `_FILE` companion pointing at a
file, for Docker and Kubernetes secrets.

| Variable | Default | Purpose |
|---|---|---|
| `SKM_DATABASE_URL` | — | PostgreSQL connection string (required) |
| `SKM_MASTER_KEY` | — | 32-byte KEK, hex or base64. Absent means the vault boots sealed |
| `SKM_LISTEN_ADDR` | `:8080` | Listen address |
| `SKM_BOOTSTRAP_USER` / `_PASSWORD` | — | Creates the first admin, only when no users exist |
| `SKM_SESSION_TTL` | `12h` | Session lifetime |
| `SKM_LOG_LEVEL` / `SKM_LOG_FORMAT` | `info` / `json` | Logging |
| `SKM_TLS_CERT_FILE` / `_KEY_FILE` | — | Serve HTTPS directly |
| `SKM_MIGRATE_ON_START` | `true` | Apply migrations at boot |
| `SKM_HTTP_PORT` | `8090` | Host port Compose publishes (not read by the binary) |
| `SKM_SCHEDULER_ENABLED` | `true` | Contend for the scheduler lock and run policies |
| `SKM_WORKER_CONCURRENCY` | `10` | Jobs processed at once by this instance |
| `SKM_BACKUP_DIR` | `/var/lib/skm/backups` | Where encrypted archives are written |
| `SKM_EXEC_DIRS` | — | Colon-separated directories the `exec` connector may run scripts from. Empty disables it |
| `SKM_RECONCILE_INTERVAL` | `1h` | How often the fleet-wide drift sweep runs |
| `SKM_EXPIRY_WARNING` | `336h` | How far ahead an approaching key expiry is announced |
| `SKM_JOB_RETENTION` | `336h` | How long finished jobs are kept for inspection |

Generate a master key with `openssl rand -hex 32`. **Losing it means losing every
stored private key** — there is no recovery path, by design.

---

## CLI

```bash
skmctl login -u admin
skmctl keys create web-fleet --algorithm ed25519 --valid-days 90
skmctl targets list
skmctl deploy --target <id> --principal <id> --dry-run   # shows the diff
skmctl deploy --target <id> --principal <id>             # applies and verifies
skmctl audit verify                                       # exits 2 if the chain is broken
```

Rotation, from CI — `--wait` blocks and exits non-zero if it did not complete:

```bash
skmctl rotate start <key-id> --soak-hours 24 --canary-percent 10 --wait
skmctl rotate show <rotation-id>          # per-target progress
skmctl rotate approve <rotation-id>       # release one held for sign-off
skmctl rotate abort <rotation-id> --reason "change freeze"
```

Accounts and tokens, so an install can be set up without opening a browser:

```bash
skmctl users list
skmctl users add jordan --role operator --name "Jordan Ops"
skmctl users password <user-id>            # prompts; never a flag
skmctl users reset-totp <user-id>          # the lost-phone path
skmctl users roles                         # what each role can do

skmctl tokens create ci --permission key.read --permission rotation.execute > token
skmctl tokens list
skmctl tokens revoke <token-id>
```

`tokens create` writes the secret to stdout and everything else to stderr, so
`skmctl tokens create ci > token` captures the token and nothing else.
Passwords are read from the terminal or from `SKM_NEW_PASSWORD`, never from a
flag — flags end up in shell history and in every process listing on the
machine.

Drift and the inventory:

```bash
skmctl drift scan                          # queue a fleet-wide sweep
skmctl drift list                          # keys SKM did not deploy
skmctl drift adopt <id> --name contractor  # bring one under management
```

Backup — the passphrase comes from `SKM_BACKUP_PASSPHRASE` or a prompt, never a
flag, because flags land in shell history and `/proc/<pid>/cmdline`:

```bash
skmctl backup create --kind full --retain-days 90
skmctl backup verify <backup-id>     # proves it is restorable, then discards it
skmctl backup restore <backup-id>
```

Jobs:

```bash
skmctl jobs list --state dead
skmctl jobs logs <job-id> --follow
```

`--json` on any command emits raw JSON for scripting.

---

## Repository layout

```
backend/
  cmd/{skm-server,skmctl}/
  internal/
    api/          HTTP handlers, middleware, error mapping
    audit/        hash-chained event log and verifier
    auth/         Argon2id, TOTP, recovery codes
    authz/        permissions, system roles, scoping
    backup/       encrypted archive format (Argon2id + AES-256-GCM)
    connectors/   the extension point; linux/ is the reference implementation
                  execc/ is the escape hatch, netdev/ is vendor-profile driven
    consumers/    private-key sinks
    cronx/        cron parsing, so the scheduler has no dependency
    db/           pool and embedded migrations
    diff/         unified diffs for the approval view
    events/       SSE bus and signed webhook delivery
    jobs/         worker pool and leader-elected scheduler
    keys/         generation, import, authorized_keys parsing
    service/      key, deploy, rotation, reconcile, backup, and auth services
    store/        SQL repositories
    sshx/         SSH with mandatory host key verification
    vault/        envelope encryption
frontend/         Angular 21, standalone, zoneless, signals
integrations/     Ansible and Nornir plugins
docs/             connector SDK
deploy/           Dockerfile, compose files, test fleet
```

See [docs/connector-sdk.md](docs/connector-sdk.md) to add support for a target
class SKM does not cover, and [integrations/](integrations/README.md) for
Ansible and Nornir.

---

## Verification

The test suite runs against real dependencies, not mocks. Notable cases:

- A key is generated, deployed, and then used to **actually open an SSH session**.
- A staged rotation keeps **both keys working** through the soak window, then
  retires the old one and confirms it no longer authenticates.
- The engine **refuses** to remove the last remaining key.
- A dry run is proven read-only by checksum comparison.
- Snapshot and restore are **byte-exact**, including the no-file case.
- Transplanting one key's encrypted material onto another key's row **fails to
  decrypt**.
- Tampering with the audit log — modifying a row, deleting one, truncating the
  start — is **detected**, with the triggers deliberately disabled to simulate an
  attacker with direct database access.
- TOTP is checked against the **RFC 6238 test vectors**.
- A **staged rotation across a two-host fleet** runs end to end: successor
  generated, staged, authenticated on both hosts, soaked, old key removed and
  confirmed non-authenticating.
- A **canary wave** is verified alone before the rest of the fleet is staged.
- An **unreachable target** keeps both keys, and the old key is *not* marked
  retired while it still grants access somewhere.
- Past the failure threshold a rotation **aborts** and leaves the old key
  untouched.
- A **consumer receives the new private key before the old one is retired**, at
  mode `0600`, and is rebound to the successor.
- A key added to a host **by hand is discovered**, appears in the inventory, and
  can be adopted — as a public-key-only record, since SKM does not hold its
  private half.
- **Auto-heal** redeploys a missing key through the ordinary deployment path, so
  it inherits the snapshot and the lockout guard.
- Two workers on one queue **never run the same job twice**; a panicking handler
  does not take the pool down; a killed worker's lease is **reaped and requeued**.
- Two schedulers **never both hold leadership**, and leadership **passes on**
  when the leader stops.
- A backup archive **round-trips**; a wrong passphrase, a flipped ciphertext
  bit, and an edited header are all **rejected**.
- Cron expressions are checked against a table of expected firing times,
  including the day-of-month/day-of-week rule and an expression that **never
  fires**.
- The `exec` connector **refuses** a script outside its allow-list, one reached
  by traversal, one reached by symlink, and one that is world-writable — and
  never passes credentials in argv.

---

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build, test, and send a change.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability privately.
- [LICENSE](LICENSE) — MIT.
