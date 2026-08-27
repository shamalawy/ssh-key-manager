# Integrations

SKM exposes its fleet and its keys over the REST API; these are the adapters
that make that usable from tools people already run.

| Integration | Status | What it does |
|---|---|---|
| [Ansible inventory](ansible/plugins/inventory/skm.py) | Built | Dynamic inventory from `/api/v1/inventory/ansible`. Target tags become groups. |
| [Ansible lookup](ansible/plugins/lookup/skm_key.py) | Built | Reads public keys and rendered `authorized_keys` content. |
| [Nornir inventory](nornir/skm_inventory.py) | Built | Hosts, groups, and platforms from `/api/v1/inventory/nornir`. |
| [Terraform provider](terraform/README.md) | **Not built** | See the note below. |

## Authentication

Every adapter reads `SKM_TOKEN` from the environment, and `SKM_SERVER` for the
base URL. Each also accepts the token as a config option, but the environment
variable is the right place for it: inventory and config files are usually
committed, and a token in version control is a credential in version control.

Create a scoped token from the API rather than reusing an operator's session:

```sh
skmctl login -u ci-bot
# then mint a token with only the permissions the integration needs
```

## Ansible

Put the plugins on Ansible's search path — `ansible.cfg`:

```ini
[defaults]
inventory_plugins = ./integrations/ansible/plugins/inventory
lookup_plugins    = ./integrations/ansible/plugins/lookup
```

`skm.yml`:

```yaml
plugin: skm
server: https://skm.internal
tag:
  - production
```

```sh
export SKM_TOKEN=...
ansible-inventory -i skm.yml --graph
```

Each host arrives with `skm_target_id`, `skm_connector`, `skm_drift_state` and
`skm_health`, so a playbook can act on what SKM knows — skipping hosts SKM
already reports as unreachable, for instance.

### A note on deploying keys from Ansible

The lookup plugin can render a principal's `authorized_keys` content, and it is
tempting to pipe that into `ansible.builtin.authorized_key`. That gets you
SKM's answer about *content* without any of its guarantees about *safety*: no
snapshot is taken, nothing refuses to empty the file, and nothing checks
afterwards that the key can actually authenticate.

Deploy through SKM and let Ansible orchestrate:

```yaml
- name: Converge this host through SKM
  ansible.builtin.command:
    cmd: "skmctl deploy --target {{ skm_target_id }} --principal deploy --verify"
  delegate_to: localhost
  changed_when: "'changed' in skm_result.stdout"
  register: skm_result
```

## Nornir

```python
from nornir import InitNornir
from skm_inventory import SKMInventory  # noqa: F401 — registers on import

nr = InitNornir(inventory={
    "plugin": "SKMInventory",
    "options": {"server": "https://skm.internal", "tags": ["production"]},
})
```

Platform comes from the netdev profile where a target has one, and from the
connector kind otherwise — so NAPALM and Netmiko dispatch correctly without a
second mapping to maintain.

## Terraform

Not built. The reason is worth stating rather than leaving as a gap in a table:
a Terraform provider is a separate Go module built on
`hashicorp/terraform-plugin-framework`, and that dependency is not available in
this build environment. Writing a provider that does not compile against the
real framework would be worse than not writing one.

What a provider would cover, if you want to pick it up:
`skm_key`, `skm_target`, `skm_assignment`, and `skm_rotation_policy` as
resources, with `skm_key` and `skm_targets` as data sources. The API is
complete enough for all of them today — `POST /api/v1/keys`,
`/api/v1/targets`, `/api/v1/assignments`, `/api/v1/rotation-policies`.

In the meantime, `skmctl --json` covers Terraform's `external` data source and
`null_resource` provisioners well enough for most of what a provider would do.
