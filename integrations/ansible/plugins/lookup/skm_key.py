#!/usr/bin/env python3
"""SKM lookup plugin: fetch a public key, or a principal's authorized_keys.

The public-key form is the one to reach for. Rendering an ``authorized_keys``
file from SKM's desired state gives you SKM's guarantees about *content*
without its guarantees about *safety*: Ansible's ``authorized_key`` module has
no lockout guard, takes no snapshot, and does not verify that the key it wrote
can actually authenticate. Prefer ``skmctl deploy`` for the deployment itself
and use this plugin for templating and for reading.

Private keys are deliberately not reachable here. A lookup result lands in
Ansible's fact cache, in ``-vvv`` output, and in any task that echoes it — none
of which are places private key material belongs. Use a consumer, or an
explicit ``skmctl keys reveal``, both of which are audited.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()

DOCUMENTATION = r"""
    name: skm_key
    author: SKM
    short_description: Read public keys and authorized_keys content from SKM
    description:
      - With C(name=), returns the public key line for a managed key.
      - With C(target=) and C(principal=), returns the full C(authorized_keys)
        content SKM believes that principal should have.
      - Private keys are not available through this plugin by design; a lookup
        result reaches the fact cache and verbose output.
    options:
      _terms:
        description: Key names to look up, when using the C(name) form.
        required: false
      server:
        description: Base URL of the SKM server.
        type: str
        env:
          - name: SKM_SERVER
        default: http://localhost:8080
      token:
        description: API or session token.
        type: str
        env:
          - name: SKM_TOKEN
      target:
        description: Target id, for the authorized_keys form.
        type: str
      principal:
        description: Username on the target, for the authorized_keys form.
        type: str
      validate_certs:
        description: Verify the server's TLS certificate.
        type: bool
        default: true
"""

EXAMPLES = r"""
- name: Template a public key into a config file
  ansible.builtin.copy:
    content: "{{ lookup('skm_key', 'production-deploy') }}"
    dest: /etc/myapp/deploy.pub
    mode: '0644'

- name: Read what SKM believes this host's authorized_keys should contain
  ansible.builtin.debug:
    msg: "{{ lookup('skm_key', target=skm_target_id, principal='deploy') }}"

# Deploying is better done through SKM itself, which snapshots first, refuses
# to empty the file, and proves the key authenticates afterwards:
- name: Converge the host through SKM
  ansible.builtin.command:
    cmd: "skmctl deploy --target {{ skm_target_id }} --principal deploy --verify"
  delegate_to: localhost
"""

RETURN = r"""
  _raw:
    description: The public key line, or the authorized_keys content.
    type: list
    elements: str
"""


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        server = (self.get_option("server") or "").rstrip("/")
        token = self.get_option("token") or os.environ.get("SKM_TOKEN", "")
        if not token:
            raise AnsibleError("skm_key: set SKM_TOKEN or pass token=")

        target = self.get_option("target")
        principal = self.get_option("principal")

        if target and principal:
            path = f"/api/v1/targets/{urllib.parse.quote(target)}/authorized-keys/{urllib.parse.quote(principal)}"
            return [self._get(server, token, path, as_json=False)]

        if not terms:
            raise AnsibleError(
                "skm_key: give one or more key names, or both target= and principal="
            )

        results = []
        for name in terms:
            results.append(self._public_key(server, token, str(name)))
        return results

    def _public_key(self, server: str, token: str, name: str) -> str:
        query = urllib.parse.urlencode({"q": name, "limit": "50"})
        payload = self._get(server, token, f"/api/v1/keys?{query}", as_json=True)

        for key in payload.get("items", []):
            if key.get("name") == name:
                if key.get("status") in ("revoked", "compromised", "destroyed"):
                    raise AnsibleError(
                        f"skm_key: key {name!r} is {key['status']}; refusing to hand it out"
                    )
                return key["public_key"]

        raise AnsibleError(f"skm_key: no key named {name!r}")

    def _get(self, server: str, token: str, path: str, as_json: bool):
        request = urllib.request.Request(server + path, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json" if as_json else "text/plain",
        })

        context = None
        if not self.get_option("validate_certs"):
            import ssl

            context = ssl._create_unverified_context()

        try:
            with urllib.request.urlopen(request, timeout=30, context=context) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise AnsibleError(f"skm_key: the server returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise AnsibleError(f"skm_key: cannot reach {server}: {exc.reason}") from exc

        return json.loads(body) if as_json else body
