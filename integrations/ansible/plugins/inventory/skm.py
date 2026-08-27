#!/usr/bin/env python3
"""SKM dynamic inventory for Ansible.

Reads the fleet from a running SKM instance so Ansible and SKM cannot disagree
about what exists. Target tags become Ansible groups, which means an existing
tag scheme is usable immediately rather than being maintained twice.

Usage — put this file on your inventory plugin path and add ``skm.yml``:

    plugin: skm
    server: https://skm.internal
    tag: production        # optional, repeatable

Authentication uses ``SKM_TOKEN`` from the environment, or ``token`` in the
config file. Prefer the environment: an inventory file is usually in version
control, and a token in version control is a credential in version control.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.inventory import BaseInventoryPlugin, Cacheable, Constructable

DOCUMENTATION = r"""
    name: skm
    short_description: SSH Key Manager inventory
    description:
      - Reads hosts from an SKM instance's dynamic inventory endpoint.
      - Target tags become groups; the connector kind becomes a
        C(connector_<kind>) group.
      - Each host carries C(skm_target_id), C(skm_drift_state), and
        C(skm_health) so playbooks can act on what SKM knows.
    options:
      plugin:
        description: Must be C(skm).
        required: true
        choices: ['skm']
      server:
        description: Base URL of the SKM server.
        required: true
        type: str
        env:
          - name: SKM_SERVER
      token:
        description:
          - API token or session token.
          - Prefer the C(SKM_TOKEN) environment variable; an inventory file is
            usually committed, and a token in version control is a credential
            in version control.
        required: false
        type: str
        env:
          - name: SKM_TOKEN
      tag:
        description: Only include targets carrying these tags.
        required: false
        type: list
        elements: str
      validate_certs:
        description: Verify the server's TLS certificate.
        required: false
        type: bool
        default: true
    extends_documentation_fragment:
      - constructed
      - inventory_cache
"""

EXAMPLES = r"""
# skm.yml
plugin: skm
server: https://skm.internal
tag:
  - production

# Only hosts SKM believes are in sync:
compose:
  ansible_host: skm_target_id
keyed_groups:
  - key: skm_drift_state
    prefix: drift
"""


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    NAME = "skm"

    def verify_file(self, path: str) -> bool:
        if not super().verify_file(path):
            return False
        return path.endswith(("skm.yml", "skm.yaml", "skm_inventory.yml"))

    def parse(self, inventory, loader, path, cache=True):
        super().parse(inventory, loader, path, cache)
        self._read_config_data(path)

        server = (self.get_option("server") or "").rstrip("/")
        if not server:
            raise AnsibleParserError("skm: 'server' is required")

        token = self.get_option("token") or os.environ.get("SKM_TOKEN", "")
        if not token:
            raise AnsibleParserError(
                "skm: no token. Set SKM_TOKEN, or 'token' in the inventory file "
                "(the environment variable is the better place for it)."
            )

        cache_key = self.get_cache_key(path)
        data = self._fetch_cached(server, token, cache, cache_key)

        self._populate(data)
        self._apply_constructed_options(data)

    def _fetch_cached(self, server, token, cache, cache_key):
        """Reads from Ansible's inventory cache when allowed, otherwise fetches."""
        use_cache = self.get_option("cache") and cache
        if use_cache:
            try:
                return self._cache[cache_key]
            except KeyError:
                pass

        data = self._fetch(server, token)
        if self.get_option("cache"):
            self._cache[cache_key] = data
        return data

    def _fetch(self, server: str, token: str) -> dict:
        params = []
        for tag in self.get_option("tag") or []:
            params.append(("tag", tag))

        url = f"{server}/api/v1/inventory/ansible"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        request = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })

        context = None
        if not self.get_option("validate_certs"):
            import ssl

            context = ssl._create_unverified_context()

        try:
            with urllib.request.urlopen(request, timeout=30, context=context) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:500]
            raise AnsibleError(f"skm: the server returned HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise AnsibleError(f"skm: cannot reach {server}: {exc.reason}") from exc

    def _populate(self, data: dict) -> None:
        hostvars = data.get("_meta", {}).get("hostvars", {})

        for group, contents in data.items():
            if group == "_meta":
                continue

            self.inventory.add_group(group)
            for host in contents.get("hosts", []):
                self.inventory.add_host(host, group=group)
                for name, value in hostvars.get(host, {}).items():
                    self.inventory.set_variable(host, name, value)

    def _apply_constructed_options(self, data: dict) -> None:
        """Applies compose/groups/keyed_groups from the inventory file."""
        strict = self.get_option("strict")
        hostvars = data.get("_meta", {}).get("hostvars", {})

        for host, variables in hostvars.items():
            self._set_composite_vars(self.get_option("compose"), variables, host, strict)
            self._add_host_to_composed_groups(self.get_option("groups"), variables, host, strict)
            self._add_host_to_keyed_groups(self.get_option("keyed_groups"), variables, host, strict)
