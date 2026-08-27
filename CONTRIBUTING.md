# Contributing

## Before you start

- For anything larger than a bug fix, open an issue first so the shape of the
  change is agreed before the code exists.
- Security problems go through [SECURITY.md](SECURITY.md), not the issue
  tracker.

## Building and testing

You need Go 1.26, Node 20, and Docker.

```bash
make check       # gofmt, go vet, security invariants, unit tests
make test-all    # everything, against real PostgreSQL and sshd containers
make test-down   # stop the test fleet when you are done
```

`make check` must pass before a pull request is opened. `make test-all` is
what CI runs; run it locally for any change that touches connectors,
deployment, rotation, or the store.

## What a change should look like

- **Nothing removed until its replacement is proven.** A change that weakens
  the verify-before-retire rule, the lockout guard, or the snapshot-before-write
  rule will not be merged, regardless of how it is justified.
- `make audit-source` encodes invariants that must never regress. If your
  change trips one, the change is wrong, not the check.
- Tests run against real dependencies. Add a test that proves the behaviour,
  not one that proves the mock was called.
- New connectors follow [docs/connector-sdk.md](docs/connector-sdk.md).
- Keep the interface vocabulary: servers get the public key, clients get the
  private key.

## Commits and pull requests

- One logical change per commit, formatted Go (`make fmt`).
- The subject line is a plain sentence saying what the change does, in the
  imperative. The body says why.
- No generated-by or co-authored-by trailers from tools.
- A pull request describes what the reviewer should look at and what you
  tested it against.
