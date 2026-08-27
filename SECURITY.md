# Security policy

SKM holds private keys and can write to `authorized_keys` on every host it
manages. Please report weaknesses privately so a fix can ship before the
details are public.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on this
repository. Do not open a public issue for anything that could be exploited.

Include what you can of:

- The version or commit you tested.
- Steps to reproduce, or a proof of concept.
- What an attacker gains — key material, host access, audit tampering, lockout.

You will get an acknowledgement within a few days. Once a fix is released the
report is credited to you unless you ask otherwise.

## In scope

- Anything that reveals private key material to someone without the
  `key:reveal` permission, or without the audit entry it should leave.
- Bypassing authentication, step-up MFA, RBAC, or tag scoping.
- Removing a key from a host without a verified replacement, or emptying an
  `authorized_keys` file.
- Tampering with the audit log without detection.
- Disabling SSH host key verification, or making SKM connect to a host it has
  not pinned.
- Weaknesses in the vault, backup archive, or webhook signing.

## Out of scope

- Reports that need a compromised database server or a leaked master key as
  the starting point; both are documented as fatal.
- Findings in dependencies with no reachable path through SKM.
- Missing hardening headers or best-practice notes without a demonstrated
  impact.

## Supported versions

Only the latest release on `main` receives security fixes.
